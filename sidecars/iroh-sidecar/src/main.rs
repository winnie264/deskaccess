#![cfg_attr(windows, windows_subsystem = "windows")]

use anyhow::{anyhow, bail, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, TransportAddr};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    fs::File,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::Instant,
};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, RwLock},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt::MakeWriter;

const DEFAULT_LISTEN: &str = "127.0.0.1:17389";
const PAIRING_ALPN: &str = "DeskAccess/pairing/iroh/1";
const TUNNEL_ALPN: &str = "DeskAccess/tunnel/iroh/1";
const TICKET_PREFIX: &str = "iroh-sidecar-v1:";

#[derive(Clone)]
struct AppState {
    endpoint: Endpoint,
    handlers: Arc<RwLock<Handlers>>,
    local_streams: Arc<Mutex<HashMap<u64, JoinHandle<()>>>>,
    next_stream_id: Arc<AtomicU64>,
    shutting_down: Arc<AtomicBool>,
}

#[derive(Clone, Debug, Default)]
struct Handlers {
    pairing_addr: Option<String>,
    tunnel_addr: Option<String>,
    pairing_alpn: String,
    tunnel_alpn: String,
}

#[derive(Debug, Deserialize)]
struct HandlersRequest {
    pairing_addr: String,
    tunnel_addr: String,
    pairing_alpn: String,
    tunnel_alpn: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    running: bool,
    ready: bool,
    endpoint_id: String,
    relay_urls: usize,
    direct_addrs: usize,
    last_error: String,
}

#[derive(Debug, Serialize)]
struct TicketResponse {
    ticket: String,
    endpoint_id: String,
}

#[derive(Debug, Deserialize)]
struct OpenRequest {
    kind: String,
    ticket: String,
}

#[derive(Debug, Serialize)]
struct OpenResponse {
    addr: String,
    path: String,
    remote_addr: String,
}

#[derive(Debug, Deserialize)]
struct CloseTunnelRequest {
    peer_id: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct CloseTunnelResponse {
    closed: usize,
}

#[derive(Debug, Serialize)]
struct HandlerResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
struct CallbackMeta {
    peer_id: String,
    path: String,
    remote_addr: String,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        error!(err = ?err, "deskaccess iroh sidecar exiting with error");
        #[cfg(not(windows))]
        eprintln!("deskaccess iroh sidecar exiting with error: {err:?}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let log_path = init_logging()?;

    let opts = parse_options()?;
    let endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![
            PAIRING_ALPN.as_bytes().to_vec(),
            TUNNEL_ALPN.as_bytes().to_vec(),
        ])
        .bind()
        .await
        .context("bind iroh endpoint")?;

    let endpoint_id = endpoint.id().to_string();
    info!(listen = %opts.listen, %endpoint_id, log_file = ?log_path, "deskaccess iroh sidecar starting");
    let online_endpoint = endpoint.clone();
    tokio::spawn(async move {
        let started = Instant::now();
        online_endpoint.online().await;
        info!(
            endpoint_id = %online_endpoint.id(),
            elapsed_ms = started.elapsed().as_millis(),
            "iroh endpoint online"
        );
    });

    let state = AppState {
        endpoint: endpoint.clone(),
        handlers: Arc::new(RwLock::new(Handlers {
            pairing_alpn: PAIRING_ALPN.to_string(),
            tunnel_alpn: TUNNEL_ALPN.to_string(),
            ..Handlers::default()
        })),
        local_streams: Arc::new(Mutex::new(HashMap::new())),
        next_stream_id: Arc::new(AtomicU64::new(1)),
        shutting_down: Arc::new(AtomicBool::new(false)),
    };

    tokio::spawn(accept_loop(state.clone()));

    let app = Router::new()
        .route("/status", get(status))
        .route("/handlers", post(register_handlers))
        .route("/ticket", post(ticket))
        .route("/open", post(open_stream))
        .route("/close_tunnel", post(close_tunnel))
        .route("/shutdown", post(shutdown))
        .with_state(state);

    let listener = TcpListener::bind(opts.listen)
        .await
        .with_context(|| format!("bind control listener {}", opts.listen))?;
    let control_addr = listener
        .local_addr()
        .context("read control listener addr")?;
    if let Some(path) = opts.ready_file {
        write_ready_file(path, control_addr, &endpoint)?;
    }
    axum::serve(listener, app)
        .await
        .context("serve control api")?;
    Ok(())
}

#[derive(Clone)]
struct SharedLogFile {
    file: Arc<StdMutex<File>>,
}

struct SharedLogGuard {
    file: Arc<StdMutex<File>>,
}

impl<'a> MakeWriter<'a> for SharedLogFile {
    type Writer = SharedLogGuard;

    fn make_writer(&'a self) -> Self::Writer {
        SharedLogGuard {
            file: self.file.clone(),
        }
    }
}

impl Write for SharedLogGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.file.lock() {
            Ok(mut file) => file.write(buf),
            Err(_) => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.lock() {
            Ok(mut file) => file.flush(),
            Err(_) => Ok(()),
        }
    }
}

fn init_logging() -> Result<Option<PathBuf>> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        "deskaccess_iroh_sidecar=info,iroh=warn,noq_udp=error,noq_proto=error".into()
    });

    if let Some(path) = sidecar_log_path() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create sidecar log directory {}", parent.display()))?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open sidecar log file {}", path.display()))?;
        let writer = SharedLogFile {
            file: Arc::new(StdMutex::new(file)),
        };
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .with_ansi(false)
            .init();
        return Ok(Some(path));
    }

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .init();
    Ok(None)
}

fn sidecar_log_path() -> Option<PathBuf> {
    if let Some(path) = env::var_os("DESKACCESS_IROH_SIDECAR_LOG") {
        return Some(PathBuf::from(path));
    }
    if let Some(dir) = env::var_os("DESKACCESS_LOG_DIR") {
        return Some(PathBuf::from(dir).join("deskaccess-iroh-sidecar.log"));
    }
    #[cfg(windows)]
    {
        if let Some(dir) = env::var_os("APPDATA") {
            return Some(
                PathBuf::from(dir)
                    .join("DeskAccess")
                    .join("deskaccess-iroh-sidecar.log"),
            );
        }
        if let Some(dir) = env::var_os("LOCALAPPDATA") {
            return Some(
                PathBuf::from(dir)
                    .join("DeskAccess")
                    .join("deskaccess-iroh-sidecar.log"),
            );
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(dir) = env::var_os("XDG_STATE_HOME") {
            return Some(
                PathBuf::from(dir)
                    .join("DeskAccess")
                    .join("deskaccess-iroh-sidecar.log"),
            );
        }
        if let Some(home) = env::var_os("HOME") {
            return Some(
                PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("DeskAccess")
                    .join("deskaccess-iroh-sidecar.log"),
            );
        }
    }
    env::current_dir()
        .ok()
        .map(|dir| dir.join("deskaccess-iroh-sidecar.log"))
}

#[derive(Debug)]
struct Options {
    listen: SocketAddr,
    ready_file: Option<PathBuf>,
}

fn parse_options() -> Result<Options> {
    let mut listen =
        env::var("DESKACCESS_IROH_SIDECAR_LISTEN").unwrap_or_else(|_| DEFAULT_LISTEN.to_string());
    let mut ready_file = env::var_os("DESKACCESS_IROH_SIDECAR_READY_FILE").map(PathBuf::from);
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen = args.next().context("--listen requires an address")?;
            }
            "--ready-file" => {
                ready_file = Some(PathBuf::from(
                    args.next().context("--ready-file requires a path")?,
                ));
            }
            "--help" | "-h" => {
                #[cfg(not(windows))]
                println!("deskaccess-iroh-sidecar [--listen 127.0.0.1:17389] [--ready-file path]");
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    Ok(Options {
        listen: listen
            .parse()
            .with_context(|| format!("parse listen address {listen}"))?,
        ready_file,
    })
}

fn write_ready_file(path: PathBuf, addr: SocketAddr, endpoint: &Endpoint) -> Result<()> {
    #[derive(Serialize)]
    struct ReadyFile {
        url: String,
        addr: String,
        endpoint_id: String,
    }

    let ready = ReadyFile {
        url: format!("http://{}", addr),
        addr: addr.to_string(),
        endpoint_id: endpoint.id().to_string(),
    };
    let data = serde_json::to_vec(&ready)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&path, data).with_context(|| format!("write ready file {}", path.display()))
}

async fn status(State(state): State<AppState>) -> Result<Json<StatusResponse>, AppError> {
    let addr = state.endpoint.addr();
    Ok(Json(StatusResponse {
        running: true,
        ready: true,
        endpoint_id: state.endpoint.id().to_string(),
        relay_urls: addr.relay_urls().count(),
        direct_addrs: addr.ip_addrs().count(),
        last_error: String::new(),
    }))
}

async fn register_handlers(
    State(state): State<AppState>,
    Json(req): Json<HandlersRequest>,
) -> Result<Json<HandlerResponse>, AppError> {
    let mut handlers = state.handlers.write().await;
    handlers.pairing_addr = Some(req.pairing_addr);
    handlers.tunnel_addr = Some(req.tunnel_addr);
    handlers.pairing_alpn = req.pairing_alpn;
    handlers.tunnel_alpn = req.tunnel_alpn;
    info!(
        pairing_addr = ?handlers.pairing_addr,
        tunnel_addr = ?handlers.tunnel_addr,
        "registered deskaccess callback handlers"
    );
    Ok(Json(HandlerResponse { ok: true }))
}

async fn ticket(State(state): State<AppState>) -> Result<Json<TicketResponse>, AppError> {
    state.endpoint.online().await;
    let addr = sanitize_endpoint_addr(&state.endpoint.addr());
    info!(
        endpoint_id = %addr.id,
        routes = ?route_summary(&addr),
        "iroh ticket prepared"
    );
    let data = serde_json::to_vec(&addr)?;
    Ok(Json(TicketResponse {
        ticket: format!("{}{}", TICKET_PREFIX, URL_SAFE_NO_PAD.encode(data)),
        endpoint_id: state.endpoint.id().to_string(),
    }))
}

async fn open_stream(
    State(state): State<AppState>,
    Json(req): Json<OpenRequest>,
) -> Result<Json<OpenResponse>, AppError> {
    let alpn = match req.kind.as_str() {
        "pairing" => PAIRING_ALPN,
        "tunnel" => TUNNEL_ALPN,
        other => return Err(AppError(anyhow!("unknown stream kind {other}"))),
    };
    let target = decode_ticket(&req.ticket)?;
    let started = Instant::now();
    let route_summary = route_summary(&target);
    let attempts = connect_attempts(&target);
    let route_count = attempts.len();
    info!(
        kind = %req.kind,
        remote_peer = %target.id,
        routes = ?route_summary,
        route_count,
        "iroh open requested"
    );
    let mut connect_tasks = JoinSet::new();
    for (index, (route, route_target)) in attempts.into_iter().enumerate() {
        info!(
            kind = %req.kind,
            remote_peer = %route_target.id,
            route_index = index + 1,
            route_count,
            route = %route,
            "iroh route connect attempt"
        );
        let endpoint = state.endpoint.clone();
        let alpn = alpn.as_bytes().to_vec();
        connect_tasks.spawn(async move {
            let route_started = Instant::now();
            let result = endpoint
                .connect(route_target, &alpn)
                .await
                .map_err(|err| format!("{err:?}"));
            (
                index + 1,
                route_count,
                route,
                route_started.elapsed(),
                result,
            )
        });
    }
    let mut last_err: Option<String> = None;
    let conn = loop {
        let Some(joined) = connect_tasks.join_next().await else {
            break match connect_full_ticket_fallback(
                &state.endpoint,
                &target,
                alpn,
                &req.kind,
                started,
                route_count + 1,
            )
            .await
            {
                Ok(conn) => conn,
                Err(err) => {
                    let err = format!(
                        "{err}; previous={}",
                        last_err.unwrap_or_else(|| "none".to_string())
                    );
                    warn!(
                        kind = %req.kind,
                        elapsed_ms = started.elapsed().as_millis(),
                        err = %err,
                        "iroh open connect failed"
                    );
                    return Err(AppError(anyhow!(
                        "connect iroh stream kind {}: {err}",
                        req.kind
                    )));
                }
            };
        };
        match joined {
            Ok((route_index, route_count, route, route_elapsed, Ok(conn))) => {
                connect_tasks.abort_all();
                connect_tasks.detach_all();
                info!(
                    kind = %req.kind,
                    remote_peer = %conn.remote_id(),
                    route_index,
                    route_count,
                    route = %route,
                    route_elapsed_ms = route_elapsed.as_millis(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "iroh route connect won"
                );
                break conn;
            }
            Ok((route_index, route_count, route, route_elapsed, Err(err))) => {
                warn!(
                    kind = %req.kind,
                    route_index,
                    route_count,
                    route = %route,
                    route_elapsed_ms = route_elapsed.as_millis(),
                    elapsed_ms = started.elapsed().as_millis(),
                    err = %err,
                    "iroh route connect failed"
                );
                last_err = Some(err);
            }
            Err(err) => {
                warn!(
                    kind = %req.kind,
                    elapsed_ms = started.elapsed().as_millis(),
                    ?err,
                    "iroh route connect task failed"
                );
                last_err = Some(format!("route task failed: {err:?}"));
            }
        }
    };
    info!(
        kind = %req.kind,
        remote_peer = %conn.remote_id(),
        elapsed_ms = started.elapsed().as_millis(),
        "iroh open connected"
    );
    let remote_peer = conn.remote_id().to_string();
    let (send, recv) = match conn.open_bi().await {
        Ok(streams) => {
            info!(
                kind = %req.kind,
                remote_peer = %remote_peer,
                elapsed_ms = started.elapsed().as_millis(),
                "iroh outgoing stream opened"
            );
            streams
        }
        Err(err) => {
            warn!(
                kind = %req.kind,
                remote_peer = %remote_peer,
                elapsed_ms = started.elapsed().as_millis(),
                ?err,
                "iroh outgoing stream open failed"
            );
            return Err(AppError(anyhow!("open outgoing bi stream: {err:?}")));
        }
    };

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind temporary local stream")?;
    let addr = listener.local_addr()?.to_string();
    let path = connection_path(&conn).await;
    let remote_addr = connection_remote_addr(&conn).await;
    let stream_id = state.next_stream_id.fetch_add(1, Ordering::Relaxed);
    info!(
        kind = %req.kind,
        remote_peer = %remote_peer,
        %stream_id,
        %addr,
        %path,
        %remote_addr,
        elapsed_ms = started.elapsed().as_millis(),
        "iroh open response ready"
    );
    let handle = tokio::spawn(async move {
        match listener.accept().await {
            Ok((tcp, local_addr)) => {
                info!(%remote_peer, %stream_id, %local_addr, "local sidecar stream accepted");
                if let Err(err) = bridge_tcp_to_quic(tcp, send, recv).await {
                    warn!(%remote_peer, %stream_id, ?err, "local sidecar stream bridge failed");
                }
            }
            Err(err) => warn!(%remote_peer, %stream_id, ?err, "local sidecar stream accept failed"),
        }
    });
    state.local_streams.lock().await.insert(stream_id, handle);

    Ok(Json(OpenResponse {
        addr,
        path,
        remote_addr,
    }))
}

async fn close_tunnel(
    State(state): State<AppState>,
    Json(req): Json<CloseTunnelRequest>,
) -> Result<Json<CloseTunnelResponse>, AppError> {
    debug!(peer_id = %req.peer_id, reason = %req.reason, "close_tunnel requested");
    let mut streams = state.local_streams.lock().await;
    let finished: Vec<u64> = streams
        .iter()
        .filter_map(|(id, handle)| handle.is_finished().then_some(*id))
        .collect();
    let closed = finished.len();
    for id in finished {
        streams.remove(&id);
    }
    Ok(Json(CloseTunnelResponse { closed }))
}

async fn shutdown(State(state): State<AppState>) -> Result<Json<HandlerResponse>, AppError> {
    state.shutting_down.store(true, Ordering::Relaxed);
    state.endpoint.close().await;
    Ok(Json(HandlerResponse { ok: true }))
}

async fn accept_loop(state: AppState) {
    while !state.shutting_down.load(Ordering::Relaxed) {
        let Some(incoming) = state.endpoint.accept().await else {
            break;
        };
        let state = state.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(err) => {
                    warn!(?err, "incoming iroh connection failed");
                    return;
                }
            };
            let alpn_string = String::from_utf8_lossy(conn.alpn()).to_string();
            let peer_id = conn.remote_id().to_string();
            info!(%peer_id, alpn = %alpn_string, "incoming iroh connection accepted");
            loop {
                match conn.accept_bi().await {
                    Ok((send, recv)) => {
                        let state = state.clone();
                        let alpn_string = alpn_string.clone();
                        let peer_id = peer_id.clone();
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            if let Err(err) = handle_incoming_stream(
                                state,
                                conn,
                                alpn_string,
                                peer_id,
                                send,
                                recv,
                            )
                            .await
                            {
                                warn!(?err, "incoming iroh stream bridge failed");
                            }
                        });
                    }
                    Err(err) => {
                        debug!(%peer_id, ?err, "incoming iroh bi stream accept ended");
                        return;
                    }
                }
            }
        });
    }
    info!("incoming iroh accept loop ended");
}

async fn handle_incoming_stream(
    state: AppState,
    conn: iroh::endpoint::Connection,
    alpn: String,
    peer_id: String,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
) -> Result<()> {
    let handlers = state.handlers.read().await.clone();
    let callback_addr = if alpn == handlers.pairing_alpn {
        handlers.pairing_addr
    } else if alpn == handlers.tunnel_alpn {
        handlers.tunnel_addr
    } else {
        None
    }
    .with_context(|| format!("no callback registered for alpn {alpn}"))?;

    let mut tcp = TcpStream::connect(&callback_addr)
        .await
        .with_context(|| format!("connect callback {callback_addr}"))?;
    let meta = CallbackMeta {
        peer_id,
        path: connection_path(&conn).await,
        remote_addr: connection_remote_addr(&conn).await,
    };
    let mut line = serde_json::to_vec(&meta)?;
    line.push(b'\n');
    tcp.write_all(&line)
        .await
        .context("write callback metadata")?;
    bridge_tcp_to_quic(tcp, send, recv).await
}

async fn bridge_tcp_to_quic(
    tcp: TcpStream,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let to_quic = async {
        let copied = io::copy(&mut tcp_read, &mut send).await?;
        send.finish()?;
        Result::<u64>::Ok(copied)
    };
    let from_quic = async {
        let copied = io::copy(&mut recv, &mut tcp_write).await?;
        tcp_write.shutdown().await?;
        Result::<u64>::Ok(copied)
    };

    tokio::select! {
        result = to_quic => {
            let bytes = result.context("copy tcp to iroh")?;
            debug!(bytes, "tcp to iroh copy ended");
        }
        result = from_quic => {
            let bytes = result.context("copy iroh to tcp")?;
            debug!(bytes, "iroh to tcp copy ended");
        }
    }
    Ok(())
}

async fn connect_full_ticket_fallback(
    endpoint: &Endpoint,
    target: &EndpointAddr,
    alpn: &str,
    kind: &str,
    started: Instant,
    route_index: usize,
) -> Result<iroh::endpoint::Connection> {
    let fallback = sanitize_endpoint_addr(target);
    let route = "full-ticket-fallback";
    info!(
        kind = %kind,
        remote_peer = %fallback.id,
        route_index,
        route_count = route_index,
        route,
        routes = ?route_summary(&fallback),
        "iroh route connect attempt"
    );
    let route_started = Instant::now();
    match endpoint.connect(fallback, alpn.as_bytes()).await {
        Ok(conn) => {
            info!(
                kind = %kind,
                remote_peer = %conn.remote_id(),
                route_index,
                route_count = route_index,
                route,
                route_elapsed_ms = route_started.elapsed().as_millis(),
                elapsed_ms = started.elapsed().as_millis(),
                "iroh route connect won"
            );
            Ok(conn)
        }
        Err(err) => {
            warn!(
                kind = %kind,
                route_index,
                route_count = route_index,
                route,
                route_elapsed_ms = route_started.elapsed().as_millis(),
                elapsed_ms = started.elapsed().as_millis(),
                ?err,
                "iroh route connect failed"
            );
            Err(anyhow!("full-ticket fallback failed: {err:?}"))
        }
    }
}

fn decode_ticket(ticket: &str) -> Result<EndpointAddr, AppError> {
    let ticket = ticket.strip_prefix(TICKET_PREFIX).unwrap_or(ticket);
    let data = URL_SAFE_NO_PAD
        .decode(ticket.as_bytes())
        .context("decode endpoint ticket")?;
    serde_json::from_slice(&data)
        .map_err(|err| anyhow!("parse endpoint ticket: {err}"))
        .map_err(AppError)
}

fn route_summary(target: &EndpointAddr) -> Vec<String> {
    target.addrs.iter().map(|addr| addr.to_string()).collect()
}

fn connect_attempts(target: &EndpointAddr) -> Vec<(String, EndpointAddr)> {
    let mut attempts = Vec::new();
    for addr in target.ip_addrs().filter(|addr| is_private_ipv4(addr)) {
        attempts.push(ip_attempt(target, addr));
    }
    for relay in target.relay_urls() {
        attempts.push((
            format!("relay:{relay}"),
            EndpointAddr::from_parts(target.id, [TransportAddr::Relay(relay.clone())]),
        ));
    }
    for addr in target
        .ip_addrs()
        .filter(|addr| !is_private_ipv4(addr) && !addr.ip().is_ipv6())
    {
        attempts.push(ip_attempt(target, addr));
    }
    if ipv6_enabled() {
        for addr in target.ip_addrs().filter(|addr| addr.ip().is_ipv6()) {
            attempts.push(ip_attempt(target, addr));
        }
    }
    if attempts.is_empty() {
        attempts.push(("lookup".to_string(), EndpointAddr::new(target.id)));
    }
    attempts
}

fn sanitize_endpoint_addr(target: &EndpointAddr) -> EndpointAddr {
    EndpointAddr::from_parts(
        target.id,
        target.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Relay(relay) => Some(TransportAddr::Relay(relay.clone())),
            TransportAddr::Ip(addr) if !addr.ip().is_ipv6() || ipv6_enabled() => {
                Some(TransportAddr::Ip(*addr))
            }
            TransportAddr::Custom(custom) => Some(TransportAddr::Custom(custom.clone())),
            _ => None,
        }),
    )
}

fn ipv6_enabled() -> bool {
    matches!(
        env::var("DESKACCESS_IROH_ENABLE_IPV6")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn ip_attempt(target: &EndpointAddr, addr: &SocketAddr) -> (String, EndpointAddr) {
    (
        format!("ip:{addr}"),
        EndpointAddr::from_parts(target.id, [TransportAddr::Ip(*addr)]),
    )
}

fn is_private_ipv4(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => is_private_or_local_ipv4(ip),
        IpAddr::V6(_) => false,
    }
}

fn is_private_or_local_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

async fn connection_path(conn: &iroh::endpoint::Connection) -> String {
    let paths = conn.paths();
    if paths.iter().any(|path| path.is_selected() && path.is_ip()) {
        "direct".to_string()
    } else if paths
        .iter()
        .any(|path| path.is_selected() && path.is_relay())
    {
        "relay".to_string()
    } else if paths.iter().any(|path| path.is_ip()) {
        "direct".to_string()
    } else if paths.iter().any(|path| path.is_relay()) {
        "relay".to_string()
    } else {
        "unknown".to_string()
    }
}

async fn connection_remote_addr(conn: &iroh::endpoint::Connection) -> String {
    let paths = conn.paths();
    if let Some(path) = paths.iter().find(|path| path.is_selected()) {
        return path.remote_addr().to_string();
    }
    paths
        .iter()
        .next()
        .map(|path| path.remote_addr().to_string())
        .unwrap_or_default()
}

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        error!(err = ?self.0, "sidecar request failed");
        (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        AppError(err.into())
    }
}
