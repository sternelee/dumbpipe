//! dp-mesh: Dynamic service discovery gateway over iroh P2P
//!
//! Host side: scans local listening ports, exposes them via iroh P2P
//! Gateway side: connects to host, dynamically binds ports for clients
//!
//! Usage:
//!   # Host machine
//!   export IROH_SECRET=$(cat ~/.dp-mesh-secret)
//!   dp-mesh host
//!
//!   # Gateway machine
//!   dp-mesh gateway --ticket <ticket> --bind-ip 192.168.33.0
//!
//!   # Client
//!   curl http://192.168.33.0:3000

use std::{
    collections::{HashMap, HashSet},
    io,
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
    time::Duration,
};

use clap::{Parser, Subcommand};
use dumbpipe::EndpointTicket;
use iroh::{endpoint::presets, Endpoint, SecretKey};
use n0_error::{ensure_any, Result, StdResultExt};
use noq::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    sync::broadcast,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const ONLINE_TIMEOUT: Duration = Duration::from_secs(5);
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(3);
const ALPN: &[u8] = b"DPMESHV0";
const CONTROL_PORT: u16 = 0;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run as host: scan local ports and expose via iroh P2P
    Host(HostArgs),
    /// Run as gateway: connect to host, expose services on bind-ip
    Gateway(GatewayArgs),
}

#[derive(Parser, Debug)]
pub struct HostArgs {}

#[derive(Parser, Debug)]
pub struct GatewayArgs {
    #[clap(long)]
    pub ticket: EndpointTicket,
    #[clap(long, default_value = "0.0.0.0")]
    pub bind_ip: String,
}

/// Service info discovered on host
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceInfo {
    pub port: u16,
    #[serde(default)]
    pub cmd: String,
}

/// Host → Gateway messages on control stream
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HostMsg {
    Services { services: Vec<ServiceInfo> },
}

/// Gateway → Host messages on control stream
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GatewayMsg {
    Subscribe,
}

// ─────────────────────────────────────────────────────────────────────────────
// Port Discovery
// ─────────────────────────────────────────────────────────────────────────────

async fn discover_ports() -> Result<Vec<ServiceInfo>> {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("lsof")
            .args(["-nP", "-iTCP", "-sTCP:LISTEN"])
            .output()
            .std_context("failed to run lsof")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut services = Vec::new();

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // lsof columns: 0=COMMAND 7=TYPE 8=ADDR:PORT 9=(LISTEN)
            if parts.len() < 9 {
                continue;
            }
            // Filter non-TCP
            if parts[7] != "TCP" {
                continue;
            }
            let cmd = parts[0].to_string();
            // parts[8] is e.g. *:PORT, 127.0.0.1:PORT, [::1]:PORT
            let addr = parts[8];
            let port: u16 = match addr.rsplit(':').next().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };
            services.push(ServiceInfo { port, cmd });
        }
        services.sort_by_key(|s| s.port);
        services.dedup_by(|a, b| a.port == b.port);
        Ok(services)
    }

    #[cfg(target_os = "linux")]
    {
        let output = std::process::Command::new("ss")
            .args(["-tlnp", "--no-header"])
            .output()
            .std_context("failed to run ss")?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut services = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let local_addr = parts[3];
            let port_str = local_addr
                .strip_prefix("*:")
                .or_else(|| local_addr.strip_prefix("0.0.0.0:"));

            let port = match port_str.and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };

            let cmd = parts
                .iter()
                .find(|p| p.starts_with("users:"))
                .and_then(|u| u.split("(\"").nth(1))
                .and_then(|s| s.split('"').next())
                .unwrap_or("unknown")
                .to_string();

            services.push(ServiceInfo { port, cmd });
        }
        services.sort_by_key(|s| s.port);
        services.dedup_by(|a, b| a.port == b.port);
        Ok(services)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Ok(Vec::new())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

fn get_or_create_secret() -> Result<SecretKey> {
    // IROH_SECRET env takes precedence
    if let Ok(secret) = std::env::var("IROH_SECRET") {
        return SecretKey::from_str(&secret).std_context("invalid IROH_SECRET");
    }

    let secret_file = dirs::config_dir()
        .unwrap_or_else(|| std::env::temp_dir())
        .join("dumbpipe")
        .join("dp-mesh.secret");

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

    eprintln!("using secret key {}", hex);
    Ok(key)
}

async fn create_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    let builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()]);
    builder.bind().await.anyerr()
}

fn cancel_token<T>(token: CancellationToken) -> impl Fn(T) -> T {
    move |x| {
        token.cancel();
        x
    }
}

async fn copy_to_noq(
    mut from: impl AsyncRead + Unpin,
    mut send: SendStream,
    token: CancellationToken,
) -> io::Result<u64> {
    tokio::select! {
        res = tokio::io::copy(&mut from, &mut send) => {
            let size = res?;
            send.finish()?;
            Ok(size)
        }
        _ = token.cancelled() => {
            send.reset(0u8.into()).ok();
            Err(io::Error::other("cancelled"))
        }
    }
}

async fn copy_from_noq(
    mut recv: RecvStream,
    mut to: impl AsyncWrite + Unpin,
    token: CancellationToken,
) -> io::Result<u64> {
    tokio::select! {
        res = tokio::io::copy(&mut recv, &mut to) => Ok(res?),
        _ = token.cancelled() => {
            recv.stop(0u8.into()).ok();
            Err(io::Error::other("cancelled"))
        }
    }
}

async fn forward_bidi(
    from1: impl AsyncRead + Send + Sync + Unpin + 'static,
    to1: impl AsyncWrite + Send + Sync + Unpin + 'static,
    from2: RecvStream,
    to2: SendStream,
) -> Result<()> {
    let token1 = CancellationToken::new();
    let token2 = token1.clone();
    let token3 = token1.clone();
    let a2b = tokio::spawn(async move {
        copy_to_noq(from1, to2, token1.clone())
            .await
            .map_err(cancel_token(token1))
    });
    let b2a = tokio::spawn(async move {
        copy_from_noq(from2, to1, token2.clone())
            .await
            .map_err(cancel_token(token2))
    });
    let _ctrl_c = tokio::spawn(async move {
        tokio::signal::ctrl_c().await?;
        token3.cancel();
        io::Result::Ok(())
    });
    b2a.await.anyerr()?.anyerr()?;
    a2b.await.anyerr()?.anyerr()?;
    Ok(())
}

/// Read a newline-delimited line from a RecvStream
async fn read_line(recv: &mut RecvStream) -> io::Result<String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1];
    loop {
        let n = recv.read(&mut tmp).await?;
        match n {
            Some(0) => return Err(io::Error::other("stream closed")),
            Some(_) => {
                if tmp[0] == b'\n' {
                    break;
                }
                buf.push(tmp[0]);
            }
            None => return Err(io::Error::other("stream closed")),
        }
    }
    String::from_utf8(buf).map_err(|e| io::Error::other(e))
}

// ─────────────────────────────────────────────────────────────────────────────
// Host side
// ─────────────────────────────────────────────────────────────────────────────

/// Handle a single data stream: read 2B port, connect localhost, forward
async fn handle_data_stream(mut recv: RecvStream, send: SendStream) -> Result<()> {
    let mut port_bytes = [0u8; 2];
    recv.read_exact(&mut port_bytes)
        .await
        .std_context("failed to read port header")?;
    let port = u16::from_be_bytes(port_bytes);

    if port == CONTROL_PORT {
        return Ok(());
    }

    tracing::info!("data stream for port {}", port);
    let conn = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .std_context(format!("failed to connect localhost:{}", port))?;
    let (tcp_recv, tcp_send) = conn.into_split();
    forward_bidi(tcp_recv, tcp_send, recv, send).await
}

/// Periodic port scanner
async fn port_watcher(tx: broadcast::Sender<Vec<ServiceInfo>>) {
    let mut last: Vec<ServiceInfo> = Vec::new();
    loop {
        sleep(DISCOVERY_INTERVAL).await;
        let current = match discover_ports().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("port discovery error: {}", e);
                continue;
            }
        };
        if current != last {
            let _ = tx.send(current.clone());
            last = current;
        }
    }
}

/// Handle one gateway peer connection
async fn handle_peer(
    conn: iroh::endpoint::Connection,
    mut port_rx: broadcast::Receiver<Vec<ServiceInfo>>,
) -> Result<()> {
    let remote_id = conn.remote_id();
    tracing::info!("peer connected: {}", remote_id);

    // Accept first control stream
    let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await.std_context("accept bi")?;

    // Read subscribe
    let msg = read_line(&mut ctrl_recv)
        .await
        .std_context("read subscribe")?;
    let gw_msg: GatewayMsg = serde_json::from_str(&msg).std_context("invalid subscribe")?;
    ensure_any!(
        matches!(gw_msg, GatewayMsg::Subscribe),
        "expected subscribe"
    );

    // Send initial services
    let services = port_rx.try_recv().unwrap_or_default();
    let json = serde_json::to_string(&HostMsg::Services {
        services: services.clone(),
    })
    .anyerr()?;
    tracing::info!("sending {} services", services.len());
    ctrl_send.write_all(json.as_bytes()).await.anyerr()?;
    ctrl_send.write_u8(b'\n').await.anyerr()?;
    ctrl_send.finish().anyerr()?;

    // Spawn update sender
    let update_conn = conn.clone();
    let mut update_rx = port_rx.resubscribe();
    tokio::spawn(async move {
        loop {
            let current = match update_rx.recv().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let json = match serde_json::to_string(&HostMsg::Services { services: current }) {
                Ok(j) => j,
                Err(_) => break,
            };
            let (mut s, _r) = match update_conn.open_bi().await {
                Ok(sr) => sr,
                Err(e) => {
                    tracing::warn!("open update stream: {}", e);
                    break;
                }
            };
            // Write control port header
            if s.write_all(&CONTROL_PORT.to_be_bytes()).await.is_err() {
                break;
            }
            if s.write_all(json.as_bytes()).await.is_err() {
                break;
            }
            if s.write_u8(b'\n').await.is_err() {
                break;
            }
            let _ = s.finish();
        }
    });

    // Accept data streams
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(sr) => sr,
            Err(e) => {
                tracing::warn!("accept_bi: {}", e);
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(e) = handle_data_stream(recv, send).await {
                tracing::warn!("data stream error: {}", e);
            }
        });
    }
}

async fn run_host(_args: HostArgs) -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key).await?;

    if timeout(ONLINE_TIMEOUT, endpoint.online()).await.is_err() {
        eprintln!("Warning: Failed to connect to home relay");
    }

    let addr = endpoint.addr();
    let ticket = EndpointTicket::new(addr);
    eprintln!("dp-mesh host ready");
    eprintln!("ticket: {ticket}");

    let initial = discover_ports().await.unwrap_or_default();
    eprintln!("discovered {} services:", initial.len());
    for svc in &initial {
        eprintln!("  {} ({})", svc.port, svc.cmd);
    }

    let (tx, _) = broadcast::channel::<Vec<ServiceInfo>>(16);
    let _ = tx.send(initial);
    tokio::spawn(port_watcher(tx.clone()));

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(connecting) = incoming else { break };
                let conn = match connecting.await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!("accept error: {}", e);
                        continue;
                    }
                };
                let rx = tx.subscribe();
                tokio::spawn(async move {
                    if let Err(e) = handle_peer(conn, rx).await {
                        tracing::warn!("peer error: {}", e);
                    }
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

// ─────────────────────────────────────────────────────────────────────────────
// Gateway side
// ─────────────────────────────────────────────────────────────────────────────

/// Handle one TCP connection: open QUIC stream, write port, forward
async fn handle_tcp_accept(
    tcp_stream: TcpStream,
    port: u16,
    conn: iroh::endpoint::Connection,
) -> Result<()> {
    let (tcp_recv, tcp_send) = tcp_stream.into_split();
    let (mut s, r) = conn.open_bi().await.std_context("open bi")?;
    s.write_all(&port.to_be_bytes()).await.anyerr()?;
    forward_bidi(tcp_recv, tcp_send, r, s).await
}

/// Bind TCP listener for one port, forward connections to P2P
async fn spawn_port_listener(port: u16, bind_ip: SocketAddr, conn: iroh::endpoint::Connection) {
    let listener = match TcpListener::bind(bind_ip).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("! {} failed to bind {}:{}: {}", port, bind_ip.ip(), port, e);
            return;
        }
    };
    eprintln!("+ {} on {}:{}", port, bind_ip.ip(), port);

    loop {
        match listener.accept().await {
            Ok((tcp_stream, tcp_addr)) => {
                tracing::info!("tcp {} -> port {}", tcp_addr, port);
                let conn = conn.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_accept(tcp_stream, port, conn).await {
                        tracing::warn!("forward {}: {}", port, e);
                    }
                });
            }
            Err(e) => {
                tracing::warn!("listener {}: {}", port, e);
            }
        }
    }
}

/// Read control updates, manage port listeners
async fn manage_ports(
    mut ctrl_recv: RecvStream,
    bind_ip: SocketAddr,
    conn: iroh::endpoint::Connection,
) -> Result<()> {
    let mut active: HashMap<u16, tokio::task::JoinHandle<()>> = HashMap::new();

    // Read initial services
    let line = read_line(&mut ctrl_recv)
        .await
        .std_context("read first response")?;

    if let Ok(HostMsg::Services { services }) = serde_json::from_str(&line) {
        for svc in &services {
            let bind = SocketAddr::new(bind_ip.ip(), svc.port);
            let h = tokio::spawn(spawn_port_listener(svc.port, bind, conn.clone()));
            active.insert(svc.port, h);
        }
    }

    // Read subsequent updates on new streams
    loop {
        let mut control_recv = select! {
            bi = conn.accept_bi() => {
                let (stream, recv) = match bi {
                    Ok(sr) => sr,
                    Err(_) => break,
                };

                // Check control port header
                let mut hdr = [0u8; 2];
                let mut recv2 = recv;
                recv2.read_exact(&mut hdr).await.ok();
                let p = u16::from_be_bytes(hdr);

                if p != CONTROL_PORT {
                    // Data stream — handle as data
                    tokio::spawn(async move {
                        if let Err(e) = handle_data_stream(recv2, stream).await {
                            tracing::warn!("gateway data stream: {}", e);
                        }
                    });
                    continue;
                }

                recv2
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        };

        let line = match read_line(&mut control_recv).await {
            Ok(l) => l,
            Err(_) => break,
        };

        if let Ok(HostMsg::Services { services }) = serde_json::from_str(&line) {
            let new_ports: HashSet<u16> = services.iter().map(|s| s.port).collect();
            let old_ports: std::collections::HashSet<_> = active.keys().cloned().collect();

            for port in old_ports.difference(&new_ports) {
                if let Some(h) = active.remove(port) {
                    eprintln!("- {} (removed)", port);
                    h.abort();
                }
            }
            for port in new_ports.difference(&old_ports) {
                let bind = SocketAddr::new(bind_ip.ip(), *port);
                let h = tokio::spawn(spawn_port_listener(*port, bind, conn.clone()));
                active.insert(*port, h);
            }
        }
    }

    for (_, h) in active.drain() {
        h.abort();
    }
    Ok(())
}

async fn run_gateway(args: GatewayArgs) -> Result<()> {
    let secret_key = get_or_create_secret()?;
    let endpoint = create_endpoint(secret_key).await?;

    if timeout(ONLINE_TIMEOUT, endpoint.online()).await.is_err() {
        eprintln!("Warning: Failed to connect to home relay");
    }

    let addr = args.ticket.endpoint_addr();
    let conn = endpoint
        .connect(addr.clone(), ALPN)
        .await
        .std_context("connect to host")?;
    tracing::info!("connected to {}", addr.id);

    // Open control stream with subscribe
    let (mut send, recv) = conn.open_bi().await.std_context("open control bi")?;
    let msg = serde_json::to_string(&GatewayMsg::Subscribe).anyerr()?;
    send.write_all(msg.as_bytes()).await.anyerr()?;
    send.write_u8(b'\n').await.anyerr()?;
    send.finish().anyerr()?;

    // Parse bind IP
    let bind_str = format!("{}:0", args.bind_ip);
    let bind_addr: SocketAddr = bind_str
        .to_socket_addrs()
        .std_context("invalid bind-ip")?
        .next()
        .std_context("no address resolved")?;

    eprintln!("dp-mesh gateway connected");
    eprintln!("bind-ip: {}", args.bind_ip);

    manage_ports(recv, bind_addr, conn).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let result = match args.command {
        Commands::Host(args) => run_host(args).await,
        Commands::Gateway(args) => run_gateway(args).await,
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

