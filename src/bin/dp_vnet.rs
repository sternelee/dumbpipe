//! dp-vnet: Virtual network daemon using iroh P2P + TUN
//!
//! Protocol: single QUIC bidi stream per peer, length-prefixed frames.
//!
//! Frame format: [4B type_be] [4B len_be] [payload]
//!   type=0: control (JSON)
//!   type=1: data (raw IP packet)
//!
//! Usage:
//!   # First node (coordinator)
//!   sudo dp-vnet daemon --ip 100.64.0.1
//!
//!   # Join
//!   sudo dp-vnet daemon --peer <coordinator_ticket>
//!
//!   # Test
//!   ping 100.64.0.1

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    process::Stdio,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use dumbpipe::EndpointTicket;
use iroh::{endpoint::presets, Endpoint, SecretKey};
use n0_error::{Result, StdResultExt};
use noq::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, Mutex},
    time::{sleep, timeout},
};

const ONLINE_TIMEOUT: Duration = Duration::from_secs(5);
const ALPN: &[u8] = b"DPVNETV0";
const IP_PREFIX: u32 = 0x6440_0000;
const IP_MASK: u32 = 0xFFC0_0000;
const CTRL_TYPE: u32 = 0;
const DATA_TYPE: u32 = 1;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Daemon(DaemonArgs),
}

#[derive(Parser, Debug)]
pub struct DaemonArgs {
    #[clap(long)]
    pub ip: Option<String>,

    #[clap(long)]
    pub peer: Option<EndpointTicket>,

    #[clap(long, default_value = "utun5")]
    pub tun: String,
}

pub fn derive_ip(pubkey: &iroh::PublicKey) -> Ipv4Addr {
    let bytes = pubkey.as_bytes();
    let hash = xxhash_rust::xxh3::xxh3_64(bytes);
    let host = (hash as u32) & 0x003F_FFFF;
    let addr = IP_PREFIX | host;
    Ipv4Addr::from(addr.to_be_bytes())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub ip: String,
    pub pubkey: String,
    pub ticket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum VnetMsg {
    Hello { ip: String },
    PeerList { peers: Vec<PeerInfo> },
}

fn get_or_create_secret() -> Result<SecretKey> {
    // IROH_SECRET env takes precedence
    if let Ok(secret) = std::env::var("IROH_SECRET") {
        return SecretKey::from_str(&secret).std_context("invalid IROH_SECRET");
    }

    let secret_file = dirs::config_dir()
        .unwrap_or_else(|| std::env::temp_dir())
        .join("dumbpipe")
        .join("dp-vnet.secret");

    // Try loading from file
    if let Ok(hex) = std::fs::read_to_string(&secret_file) {
        if let Ok(key) = SecretKey::from_str(hex.trim()) {
            return Ok(key);
        }
    }

    // Generate new secret
    let key = SecretKey::generate();
    let hex = data_encoding::HEXLOWER.encode(&key.to_bytes());

    // Ensure directory exists and save
    if let Some(parent) = secret_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&secret_file, &hex) {
        eprintln!("warning: failed to save secret to {}: {}", secret_file.display(), e);
    } else {
        eprintln!("secret saved to {}", secret_file.display());
    }

    eprintln!("secret key: {}", hex);
    Ok(key)
}

async fn create_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    let builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()]);
    builder.bind().await.anyerr()
}

fn dst_ip(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    let dst = &packet[16..20];
    Some(Ipv4Addr::new(dst[0], dst[1], dst[2], dst[3]))
}

fn is_vnet_ip(ip: Ipv4Addr) -> bool {
    let u = u32::from_be_bytes(ip.octets());
    (u & IP_MASK) == IP_PREFIX
}

/// Write a length-prefixed frame to a stream.
async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, typ: u32, payload: &[u8]) -> Result<()> {
    let mut hdr = [0u8; 8];
    hdr[0..4].copy_from_slice(&typ.to_be_bytes());
    hdr[4..8].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&hdr).await.anyerr()?;
    w.write_all(payload).await.anyerr()?;
    w.flush().await.anyerr()?;
    Ok(())
}

/// Read a length-prefixed frame from a stream.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u32, Vec<u8>)> {
    let mut hdr = [0u8; 8];
    r.read_exact(&mut hdr)
        .await
        .std_context("read frame header")?;
    let typ = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let len = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)
        .await
        .std_context("read frame payload")?;
    Ok((typ, payload))
}

struct PeerConn {
    send: Arc<Mutex<SendStream>>,
    last_used: Instant,
}

struct PeerPool {
    peers: HashMap<Ipv4Addr, PeerConn>,
}

impl PeerPool {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Lookup and return a clone of the send handle, updating last_used.
    fn get_send(&mut self, ip: Ipv4Addr) -> Option<Arc<Mutex<SendStream>>> {
        self.peers.get_mut(&ip).map(|p| {
            p.last_used = Instant::now();
            p.send.clone()
        })
    }

    fn insert(&mut self, ip: Ipv4Addr, send: SendStream) {
        self.peers.insert(
            ip,
            PeerConn {
                send: Arc::new(Mutex::new(send)),
                last_used: Instant::now(),
            },
        );
    }

    fn list_peers(&self) -> Vec<PeerInfo> {
        self.peers
            .keys()
            .map(|&ip| PeerInfo {
                ip: ip.to_string(),
                pubkey: String::new(),
                ticket: String::new(),
            })
            .collect()
    }

    fn cleanup(&mut self, max_idle: Duration) {
        let now = Instant::now();
        self.peers.retain(|ip, p| {
            let keep = now.duration_since(p.last_used) < max_idle;
            if !keep {
                tracing::info!("dropping idle peer {}", ip);
            }
            keep
        });
    }
}

fn net_ip(ip: Ipv4Addr) -> (u8, u8, u8, u8) {
    let o = ip.octets();
    (o[0], o[1], o[2], o[3])
}

#[cfg(target_os = "macos")]
async fn create_tun(name: &str, ip: Ipv4Addr) -> Result<tun::AsyncDevice> {
    let mut config = tun::Configuration::default();
    config.tun_name(name);
    config.address(ip);
    config.netmask((255, 192, 0, 0));
    config.up();
    let dev = tun::create_as_async(&config).std_context("failed to create TUN")?;
    let (a, b, _c, _) = net_ip(ip);
    let _ = tokio::process::Command::new("route")
        .args([
            "add",
            "-net",
            &format!("{}.{}.0.0", a, b),
            &format!("{}", ip),
            "255.192.0.0",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    Ok(dev)
}

#[cfg(target_os = "linux")]
async fn create_tun(name: &str, ip: Ipv4Addr) -> Result<tun::AsyncDevice> {
    let mut config = tun::Configuration::default();
    config.tun_name(name);
    config.address(ip);
    config.netmask((255, 192, 0, 0));
    config.up();
    let dev = tun::create_as_async(&config).std_context("failed to create TUN")?;
    let _ = tokio::process::Command::new("ip")
        .args(["route", "add", "100.64.0.0/10", "dev", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
    Ok(dev)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
async fn create_tun(_name: &str, _ip: Ipv4Addr) -> Result<tun::AsyncDevice> {
    n0_error::bail_any!("TUN not supported on this platform")
}

/// Spawn a background task that reads frames from a peer's recv stream
/// and forwards data packets to the TUN writer channel.
fn spawn_peer_reader(mut recv: RecvStream, tun_tx: mpsc::Sender<Vec<u8>>, remote_ip: Ipv4Addr) {
    tokio::spawn(async move {
        loop {
            match read_frame(&mut recv).await {
                Ok((CTRL_TYPE, _)) => {
                    // Control frame after handshake — ignore
                }
                Ok((DATA_TYPE, payload)) => {
                    if tun_tx.try_send(payload).is_err() {
                        break;
                    }
                }
                Ok((_, _)) => continue,
                Err(_) => break,
            }
        }
        tracing::debug!("peer {} reader done", remote_ip);
    });
}

/// Connect to a peer and add it to the pool.
async fn connect_peer(
    endpoint: &Endpoint,
    pool: &Arc<Mutex<PeerPool>>,
    info: &PeerInfo,
    self_ip: Ipv4Addr,
    tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let remote_ip = Ipv4Addr::from_str(&info.ip).std_context("invalid peer IP")?;
    let ticket = EndpointTicket::from_str(&info.ticket).std_context("invalid peer ticket")?;
    let addr = ticket.endpoint_addr();

    let conn = endpoint
        .connect(addr.clone(), ALPN)
        .await
        .std_context(format!("connect to {}", remote_ip))?;

    // Open a single bidi stream for both control + data
    let (mut send, mut recv) = conn.open_bi().await.std_context("open bi")?;

    // Send Hello
    let hello = VnetMsg::Hello {
        ip: self_ip.to_string(),
    };
    let json = serde_json::to_vec(&hello).anyerr()?;
    write_frame(&mut send, CTRL_TYPE, &json).await?;

    // Read PeerList (optional, we just skip it here)
    let _ = read_frame(&mut recv).await?;

    // Store the send half in the pool; spawn reader for recv half
    pool.lock().await.insert(remote_ip, send);
    spawn_peer_reader(recv, tun_tx, remote_ip);

    Ok(())
}

async fn run_daemon(args: DaemonArgs) -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let pubkey = secret_key.public();

    let self_ip = match &args.ip {
        Some(ip_str) => Ipv4Addr::from_str(ip_str).std_context("invalid IP")?,
        None => derive_ip(&pubkey),
    };

    eprintln!("dp-vnet daemon");
    eprintln!("virtual IP: {}", self_ip);

    #[cfg(unix)]
    if unsafe { libc::getuid() } != 0 {
        eprintln!("WARNING: TUN requires root. Run with sudo.");
    }

    let mut tun = create_tun(&args.tun, self_ip).await?;
    eprintln!("TUN {} created", args.tun);

    let endpoint = create_endpoint(secret_key).await?;

    if timeout(ONLINE_TIMEOUT, endpoint.online()).await.is_err() {
        eprintln!("Warning: Failed to connect to home relay");
    }

    let ticket = EndpointTicket::new(endpoint.addr());
    eprintln!("ticket: {ticket}");

    let pool = Arc::new(Mutex::new(PeerPool::new()));
    let pool_clone = pool.clone();

    // Channel for peer readers to send packets back to the TUN device
    let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(1024);

    // Join existing network via coordinator
    if let Some(peer_ticket) = args.peer {
        eprintln!("joining peer...");
        let addr = peer_ticket.endpoint_addr();
        let conn = endpoint
            .connect(addr.clone(), ALPN)
            .await
            .std_context("connect to peer")?;

        let (mut send, mut recv) = conn.open_bi().await.std_context("open bi")?;

        let hello = VnetMsg::Hello {
            ip: self_ip.to_string(),
        };
        let json = serde_json::to_vec(&hello).anyerr()?;
        write_frame(&mut send, CTRL_TYPE, &json).await?;

        let (_, payload) = read_frame(&mut recv).await?;
        let msg: VnetMsg = serde_json::from_slice(&payload).std_context("invalid PeerList")?;

        match msg {
            VnetMsg::PeerList { peers } => {
                eprintln!("received {} peers", peers.len());
                for info in &peers {
                    eprintln!("  -> {}", info.ip);
                    if let Err(e) =
                        connect_peer(&endpoint, &pool, info, self_ip, tun_tx.clone()).await
                    {
                        eprintln!("  failed {}: {}", info.ip, e);
                    }
                }
            }
            _ => eprintln!("unexpected response"),
        }

        // Also keep a data stream to the coordinator itself
        pool.lock().await.insert(self_ip, send);
        spawn_peer_reader(recv, tun_tx.clone(), self_ip);
    }

    // Cleanup task
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60)).await;
            pool_clone.lock().await.cleanup(Duration::from_secs(300));
        }
    });

    let mut buf = vec![0u8; 65535];
    let endpoint = endpoint;
    eprintln!("running...");

    loop {
        tokio::select! {
            // Read from TUN, route to peers
            result = tun.read(&mut buf) => {
                let n = match result {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!("TUN read error: {}", e);
                        continue;
                    }
                };

                let packet = &buf[..n];
                let dst = match dst_ip(packet) {
                    Some(ip) => ip,
                    None => continue,
                };

                if !is_vnet_ip(dst) || dst == self_ip {
                    continue;
                }

                let send_handle = {
                    let mut pool = pool.lock().await;
                    pool.get_send(dst)
                };

                if let Some(send) = send_handle {
                    let mut guard = send.lock().await;
                    if let Err(e) = write_frame(&mut *guard, DATA_TYPE, packet).await {
                        tracing::warn!("send to {}: {}", dst, e);
                    }
                } else {
                    tracing::trace!("no route to {}", dst);
                }
            }

            // Write packets from peer readers into TUN
            Some(packet) = tun_rx.recv() => {
                if let Err(e) = tun.write_all(&packet).await {
                    tracing::warn!("TUN write error: {}", e);
                }
            }

            // Accept incoming peer connections
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let Ok(connecting) = incoming.accept() else { continue };
                let Ok(conn) = connecting.await else { continue };
                let remote_id = conn.remote_id();
                tracing::info!("incoming connection from {}", remote_id);

                let pool = pool.clone();
                let tun_tx = tun_tx.clone();

                tokio::spawn(async move {
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(sr) => sr,
                        Err(e) => {
                            tracing::warn!("accept_bi failed: {}", e);
                            return;
                        }
                    };

                    // Read Hello control frame
                    let remote_ip = match read_frame(&mut recv).await {
                        Ok((CTRL_TYPE, payload)) => {
                            match serde_json::from_slice::<VnetMsg>(&payload) {
                                Ok(VnetMsg::Hello { ip }) => {
                                    Ipv4Addr::from_str(&ip).unwrap_or(Ipv4Addr::new(0, 0, 0, 0))
                                }
                                _ => return,
                            }
                        }
                        _ => return,
                    };

                    if remote_ip == Ipv4Addr::new(0, 0, 0, 0) {
                        return;
                    }

                    // Send PeerList
                    let peers = pool.lock().await.list_peers();
                    let resp = VnetMsg::PeerList { peers };
                    let json = serde_json::to_vec(&resp).anyerr().unwrap_or_default();
                    if write_frame(&mut send, CTRL_TYPE, &json).await.is_err() {
                        return;
                    }

                    // Store send half, spawn reader for recv half
                    pool.lock().await.insert(remote_ip, send);
                    spawn_peer_reader(recv, tun_tx, remote_ip);
                });
            }

            _ = tokio::signal::ctrl_c() => {
                eprintln!("shutting down...");
                break;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let result = match args.command {
        Commands::Daemon(args) => run_daemon(args).await,
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
