//! Concurrent eD2k-server and Kad discovery with incremental, bounded source
//! events. This module never owns a database connection or downloads file data.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::kad_session::{self, KadLookupCfg, KadLookupResult};
use aidm_core::ed2k::{
    kad::KadNode,
    peer::{Packet, Protocol},
    server::{self, op, FoundSources, IdChange, LoginTag},
};

#[derive(Debug, Clone)]
pub struct SourceDiscoveryCfg {
    pub file_hash: [u8; 16],
    pub file_size: u64,
    pub user_hash: [u8; 16],
    pub listen_port: u16,
    pub nickname: String,
    pub servers: Vec<SocketAddr>,
    /// An empty list disables Kad, without opening a UDP socket.
    pub kad_seeds: Vec<KadNode>,
    pub kad_cfg: KadLookupCfg,
    pub total_budget: Duration,
    pub server_budget: Duration,
    pub per_server_budget: Duration,
    pub connect_timeout: Duration,
    pub server_parallelism: usize,
    pub max_sources: usize,
    /// For explicit local mocks; production rejects private peer addresses.
    pub allow_private_addresses: bool,
}

impl Default for SourceDiscoveryCfg {
    fn default() -> Self {
        Self {
            file_hash: [0; 16],
            file_size: 0,
            user_hash: [0; 16],
            listen_port: 0,
            nickname: "AIDM".into(),
            servers: Vec::new(),
            kad_seeds: Vec::new(),
            kad_cfg: KadLookupCfg::default(),
            total_budget: Duration::from_secs(45),
            server_budget: Duration::from_secs(10),
            per_server_budget: Duration::from_secs(6),
            connect_timeout: Duration::from_millis(500),
            server_parallelism: 3,
            max_sources: 512,
            allow_private_addresses: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Server(SocketAddr),
    Kad,
}

#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    Source {
        addr: SocketAddr,
        kind: SourceKind,
        user_hash: Option<[u8; 16]>,
    },
    ServerFinished {
        addr: SocketAddr,
        result: Result<ServerDiscoveryResult, String>,
    },
    KadFinished {
        result: Result<KadLookupResult, String>,
    },
    Finished(SourceDiscoverySummary),
}

#[derive(Debug, Clone, Default)]
pub struct ServerDiscoveryResult {
    pub logged_in: bool,
    pub client_id: Option<u32>,
    pub source_batches: usize,
    pub usable_sources: usize,
    pub low_id_sources: usize,
    pub invalid_sources: usize,
    pub cancelled: bool,
    pub elapsed: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct SourceDiscoverySummary {
    pub unique_sources: usize,
    pub server_sources: usize,
    pub kad_sources: usize,
    pub servers_completed: usize,
    pub server_errors: usize,
    pub cancelled: bool,
    pub elapsed: Duration,
}

/// Owns every discovery thread. `cancel`, `join` and Drop are safe while the
/// consumer is no longer reading events: channel sends are never blocking.
pub struct SourceDiscoveryHandle {
    pub events: mpsc::Receiver<DiscoveryEvent>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<SourceDiscoverySummary>>,
}

impl SourceDiscoveryHandle {
    pub fn cancel(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
    /// Request cancellation, then join the coordinator and all its children.
    pub fn join(mut self) -> Result<SourceDiscoverySummary, String> {
        self.cancel();
        self.thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| "ed2k_discovery_thread_panicked".into())
    }
}

impl Drop for SourceDiscoveryHandle {
    fn drop(&mut self) {
        self.cancel();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// Start both discovery channels immediately. The stop predicate may be called
/// from several threads and must be cheap; capture only shared task control.
pub fn start(
    cfg: SourceDiscoveryCfg,
    should_stop: impl Fn() -> bool + Send + Sync + 'static,
) -> SourceDiscoveryHandle {
    let (tx, events) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let inner_stop = stop.clone();
    let handle = thread::spawn(move || run(cfg, should_stop, inner_stop, tx));
    SourceDiscoveryHandle {
        events,
        stop,
        thread: Some(handle),
    }
}

struct EventSink {
    tx: mpsc::Sender<DiscoveryEvent>,
    stop: Arc<AtomicBool>,
    seen: Mutex<HashSet<SocketAddr>>,
    max_sources: usize,
    server_sources: AtomicUsize,
    kad_sources: AtomicUsize,
}

impl EventSink {
    fn event(&self, event: DiscoveryEvent) {
        if self.tx.send(event).is_err() {
            self.stop.store(true, Ordering::Release);
        }
    }
    fn source(&self, addr: SocketAddr, kind: SourceKind, user_hash: Option<[u8; 16]>) {
        let Ok(mut seen) = self.seen.lock() else {
            self.stop.store(true, Ordering::Release);
            return;
        };
        if seen.len() >= self.max_sources || !seen.insert(addr) {
            return;
        }
        match kind {
            SourceKind::Server(_) => {
                self.server_sources.fetch_add(1, Ordering::Relaxed);
            }
            SourceKind::Kad => {
                self.kad_sources.fetch_add(1, Ordering::Relaxed);
            }
        }
        // No callback or database operation while holding the dedup lock.
        drop(seen);
        self.event(DiscoveryEvent::Source {
            addr,
            kind,
            user_hash,
        });
    }
}

fn run(
    cfg: SourceDiscoveryCfg,
    external_stop: impl Fn() -> bool + Send + Sync,
    stop: Arc<AtomicBool>,
    tx: mpsc::Sender<DiscoveryEvent>,
) -> SourceDiscoverySummary {
    let started = Instant::now();
    let deadline = started + cfg.total_budget.min(Duration::from_secs(60));
    let server_deadline = deadline.min(started + cfg.server_budget.min(Duration::from_secs(15)));
    let sink = EventSink {
        tx,
        stop: stop.clone(),
        seen: Mutex::new(HashSet::new()),
        max_sources: cfg.max_sources.clamp(1, 1024),
        server_sources: AtomicUsize::new(0),
        kad_sources: AtomicUsize::new(0),
    };
    let should_stop =
        || stop.load(Ordering::Acquire) || external_stop() || Instant::now() >= deadline;
    let next_server = AtomicUsize::new(0);
    let completed = AtomicUsize::new(0);
    let errors = AtomicUsize::new(0);
    thread::scope(|scope| {
        if !cfg.kad_seeds.is_empty() && !should_stop() {
            let sink = &sink;
            let cfg = &cfg;
            let should_stop = &should_stop;
            scope.spawn(move || {
                let mut kad_cfg = cfg.kad_cfg.clone();
                kad_cfg.timeout = kad_cfg
                    .timeout
                    .min(deadline.saturating_duration_since(Instant::now()));
                let result = kad_session::lookup_sources_streaming(
                    &cfg.file_hash,
                    cfg.file_size,
                    &cfg.kad_seeds,
                    &kad_cfg,
                    should_stop,
                    |source| {
                        sink.source(
                            SocketAddr::from((source.ip, source.port)),
                            SourceKind::Kad,
                            Some(source.user_hash),
                        )
                    },
                );
                sink.event(DiscoveryEvent::KadFinished { result });
            });
        }
        for _ in 0..cfg
            .server_parallelism
            .clamp(1, 8)
            .min(cfg.servers.len().min(32))
        {
            let sink = &sink;
            let cfg = &cfg;
            let should_stop = &should_stop;
            let next_server = &next_server;
            let completed = &completed;
            let errors = &errors;
            scope.spawn(move || {
                while !should_stop() && Instant::now() < server_deadline {
                    let index = next_server.fetch_add(1, Ordering::Relaxed);
                    let Some(&addr) = cfg.servers.get(index).filter(|_| index < 32) else {
                        break;
                    };
                    let result = query_server(addr, cfg, server_deadline, should_stop, |peer| {
                        sink.source(peer, SourceKind::Server(addr), None)
                    });
                    completed.fetch_add(1, Ordering::Relaxed);
                    if result.is_err() {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                    sink.event(DiscoveryEvent::ServerFinished { addr, result });
                }
            });
        }
    }); // scoped children are always joined before Finished or return.
    let summary = SourceDiscoverySummary {
        unique_sources: sink.seen.lock().map(|s| s.len()).unwrap_or(0),
        server_sources: sink.server_sources.load(Ordering::Relaxed),
        kad_sources: sink.kad_sources.load(Ordering::Relaxed),
        servers_completed: completed.load(Ordering::Relaxed),
        server_errors: errors.load(Ordering::Relaxed),
        cancelled: stop.load(Ordering::Acquire) || external_stop(),
        elapsed: started.elapsed(),
    };
    sink.event(DiscoveryEvent::Finished(summary.clone()));
    summary
}

/// 源地址合法性：与查源通道同规则（回环/私网只在明确允许本地测试时放行）。
pub(crate) fn allowed_peer(ip: Ipv4Addr, allow_private: bool) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && ip.octets()[0] != 0
        && ip.octets()[0] < 240
        && (allow_private
            || !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_documentation()))
}

/// The existing blocking server session remains available to other callers.
/// Discovery uses incremental nonblocking framing so a half frame, MOTD flood,
/// or silent server cannot defeat cancellation or the batch-wide time budget.
fn query_server(
    addr: SocketAddr,
    cfg: &SourceDiscoveryCfg,
    global_deadline: Instant,
    should_stop: &impl Fn() -> bool,
    mut on_source: impl FnMut(SocketAddr),
) -> Result<ServerDiscoveryResult, String> {
    let started = Instant::now();
    let deadline =
        global_deadline.min(started + cfg.per_server_budget.min(Duration::from_secs(10)));
    let mut result = ServerDiscoveryResult::default();
    if should_stop() || Instant::now() >= deadline {
        result.cancelled = should_stop();
        return Ok(result);
    }
    let connect_wait = cfg
        .connect_timeout
        .clamp(Duration::from_millis(1), Duration::from_millis(500))
        .min(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        );
    let mut stream = TcpStream::connect_timeout(&addr, connect_wait)
        .map_err(|e| format!("ed2k_discovery_connect: {e}"))?;
    stream
        .set_nonblocking(true)
        .map_err(|e| format!("ed2k_discovery_nonblocking: {e}"))?;
    stream.set_nodelay(true).ok();
    use server::tcp_flags;
    let flags =
        tcp_flags::NEWTAGS | tcp_flags::UNICODE | tcp_flags::INTTAGS | tcp_flags::LARGEFILES;
    let tags = [
        LoginTag::Str(1, cfg.nickname.clone()),
        LoginTag::Uint(0x11, 0x3c),
        LoginTag::Uint(0x20, flags),
        LoginTag::Uint(0xfb, 0x0064_0000),
    ];
    let mut outgoing = server::packet(
        op::LOGINREQUEST,
        server::encode_login(&cfg.user_hash, 0, cfg.listen_port, &tags),
    )
    .encode();
    let mut written = 0;
    let mut incoming = Vec::<u8>::new();
    let mut chunk = [0; 16_384];
    let mut last_batch = None::<Instant>;
    const MAX_FRAME: usize = 1_048_576;
    while Instant::now() < deadline {
        if should_stop() {
            result.cancelled = true;
            break;
        }
        if written < outgoing.len() {
            match stream.write(&outgoing[written..]) {
                Ok(0) => return Err("ed2k_discovery_write_eof".into()),
                Ok(n) => written += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(format!("ed2k_discovery_write: {e}")),
            }
        }
        let mut eof = false;
        match stream.read(&mut chunk) {
            Ok(0) => eof = true,
            Ok(n) => incoming.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(format!("ed2k_discovery_read: {e}")),
        }
        if incoming.len() > MAX_FRAME + chunk.len() {
            return Err("ed2k_discovery_frame_limit".into());
        }
        let mut consumed = 0;
        while incoming.len() - consumed >= 6 {
            if should_stop() || Instant::now() >= deadline {
                break;
            }
            let header: &[u8; 6] = incoming[consumed..consumed + 6].try_into().unwrap();
            let (protocol, len, opcode) =
                Packet::header(header).map_err(|e| format!("ed2k_discovery_header: {e}"))?;
            if len > MAX_FRAME {
                return Err("ed2k_discovery_frame_limit".into());
            }
            if incoming.len() - consumed < 6 + len {
                break;
            }
            let payload = &incoming[consumed + 6..consumed + 6 + len];
            if protocol == Protocol::Edonkey {
                match opcode {
                    op::REJECT => return Err("ed2k_discovery_login_rejected".into()),
                    op::IDCHANGE if !result.logged_in => {
                        let login = IdChange::decode(payload)
                            .map_err(|e| format!("ed2k_discovery_idchange: {e}"))?;
                        result.logged_in = true;
                        result.client_id = Some(login.client_id);
                        // Login has already been consumed by the remote before
                        // this reply, so it is safe to replace the send buffer.
                        outgoing = server::packet(
                            op::GETSOURCES,
                            server::encode_get_sources(&cfg.file_hash, cfg.file_size),
                        )
                        .encode();
                        written = 0;
                    }
                    op::FOUNDSOURCES if result.logged_in => {
                        let found = FoundSources::decode(payload)
                            .map_err(|e| format!("ed2k_discovery_foundsources: {e}"))?;
                        if found.file_hash == cfg.file_hash {
                            result.source_batches += 1;
                            last_batch = Some(Instant::now());
                            for source in found.sources {
                                if server::is_low_id(u32::from_le_bytes(source.ip.octets())) {
                                    result.low_id_sources += 1;
                                    continue;
                                }
                                if source.port == 0
                                    || !allowed_peer(source.ip, cfg.allow_private_addresses)
                                {
                                    result.invalid_sources += 1;
                                    continue;
                                }
                                result.usable_sources += 1;
                                on_source(SocketAddr::from((source.ip, source.port)));
                            }
                        }
                    }
                    _ => {} // MOTD/status/unknown framed packets do not delay dispatch.
                }
            }
            consumed += 6 + len;
        }
        if consumed > 0 {
            incoming.drain(..consumed);
        }
        if eof {
            if !incoming.is_empty() {
                return Err("ed2k_discovery_truncated_frame".into());
            }
            if !result.logged_in {
                return Err("ed2k_discovery_login_eof".into());
            }
            break;
        }
        if last_batch.is_some_and(|last| last.elapsed() >= Duration::from_millis(300)) {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    result.elapsed = started.elapsed();
    if !result.logged_in && !result.cancelled {
        return Err("ed2k_discovery_login_timeout".into());
    }
    Ok(result)
}
