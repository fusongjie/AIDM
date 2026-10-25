//! 真 TCP 多源验收：不同地址同时传输、不重叠分片、断线重派和硬并发许可。
mod common;

use aidm_core::ed2k::peer::{
    ed2k, emule, FileStatus, HelloInfo, Packet, Protocol, QueueRanking, RequestParts, SendingPart,
    EMBLOCKSIZE, PARTSIZE,
};
use aidm_core::ed2k::{
    hash::{hash_reader, Ed2kDigest},
    Flavor,
};
use aidm_engine::ed2k::multi_source::{
    download_from_sources, MultiDownload, MultiSourceCfg, PeerEvent, PoolProgress, TransferHooks,
};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    mpsc, Arc, Condvar, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[test]
fn manager_streams_from_two_peers_while_a_third_hello_is_silent_and_reports_real_counts() {
    let target = Target::new();
    let root = target.path.parent().unwrap();
    let db = aidm_core::open_db(&root.join("db.sqlite")).unwrap();
    aidm_core::settings::ensure_defaults(&db).unwrap();
    let manager =
        aidm_engine::DownloadManager::new(Arc::new(Mutex::new(db)), root.join("downloads"));
    for (key, value) in [
        ("ed2k.servers", ""),
        ("ed2k.kad_enabled", "false"),
        ("conn.global_conn_cap", "3"),
    ] {
        manager.settings_set(key, value).unwrap();
    }
    let data = payload(2);
    let barrier = Arc::new(Started::default());
    let a = server(data.clone(), Some(barrier.clone()), None, false);
    let b = server(data.clone(), Some(barrier), None, false);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let silent = listener.local_addr().unwrap();
    let silent_handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let _ = stream.read_to_end(&mut Vec::new());
    });
    let link = format!(
        "ed2k://|file|pool.bin|{}|{}|/|sources,{silent},{},{}|/",
        data.bytes.len(),
        data.digest.file_hex(),
        a.addr,
        b.addr
    );
    let started = Instant::now();
    let id = manager.add(&link, None, None, None, 0).unwrap();
    let mut first_byte = None;
    let mut peak = 0;
    let mut saw_p2p = false;
    loop {
        let task = manager.status(id).unwrap().unwrap();
        assert_eq!(task.mode.as_deref(), Some("ed2k"));
        if let Some(ref p) = task.p2p {
            saw_p2p = true;
            assert_eq!(p.max_connections, 3);
            assert!(p.active_peers <= 3);
        }
        let stats = manager.stats_snapshot();
        peak = peak.max(stats.active_conns);
        assert!(stats.active_conns <= 3);
        if task.done > 0 && first_byte.is_none() {
            first_byte = Some(started.elapsed());
        }
        if task.state == "done" {
            break;
        }
        assert_ne!(task.state, "error", "{task:?}");
        assert!(started.elapsed() < Duration::from_secs(15), "{task:?}");
        thread::sleep(Duration::from_millis(2));
    }
    silent_handle.join().unwrap();
    let (a, b) = (a.finish(), b.finish());
    assert!(saw_p2p && peak >= 2, "actual global peak={peak}");
    assert!(
        first_byte.unwrap() < Duration::from_secs(3),
        "silent HELLO must not block useful peers"
    );
    assert!(
        a.parts.len() > 0 && b.parts.len() > 0,
        "both peers must actually serve content"
    );
    assert!(
        a.parts.iter().all(|p| !b.parts.contains(p)),
        "a part must have a unique owner"
    );
    assert_eq!(
        std::fs::read(root.join("downloads/pool.bin")).unwrap(),
        data.bytes
    );
    let conn = aidm_core::open_db(&root.join("db.sqlite")).unwrap();
    let sources = aidm_core::model::list_ed2k_sources(&conn, id, 8).unwrap();
    assert_eq!(
        sources.iter().filter(|s| s.tries > s.fails).count(),
        2,
        "both useful peers become preferred resume sources"
    );
    println!(
        "worker_first_byte_ms={} complete_ms={} actual_connection_peak={peak} serving_peers=2",
        first_byte.unwrap().as_millis(),
        started.elapsed().as_millis()
    );
}

struct Target {
    path: PathBuf,
    /// 持有 tempdir：Drop 时自动删除整个目录。
    _tmp: tempfile::TempDir,
}
impl Target {
    fn new() -> Self {
        let tmp = common::tempdir("multipeer");
        let path = tmp.path().join("payload.part");
        Self { path, _tmp: tmp }
    }
}
impl Drop for Target {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
    }
}

struct Hooks {
    limit: usize,
    denied: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    bytes: AtomicU64,
}
impl Hooks {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            denied: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            bytes: AtomicU64::new(0),
        }
    }
}
impl TransferHooks for Hooks {
    fn try_acquire_connection(&self) -> bool {
        if self
            .denied
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return false;
        }
        let mut n = self.active.load(Ordering::SeqCst);
        loop {
            if n >= self.limit {
                return false;
            }
            match self
                .active
                .compare_exchange(n, n + 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => {
                    self.peak.fetch_max(n + 1, Ordering::SeqCst);
                    return true;
                }
                Err(now) => n = now,
            }
        }
    }
    fn release_connection(&self) {
        assert!(self.active.fetch_sub(1, Ordering::SeqCst) > 0);
    }
    fn received(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::SeqCst);
    }
}

struct Payload {
    bytes: Vec<u8>,
    digest: Ed2kDigest,
}
fn payload(parts: usize) -> Arc<Payload> {
    let bytes: Vec<u8> = (0..PARTSIZE as usize * parts + 12345)
        .map(|i| (i.wrapping_mul(29) ^ i / 257) as u8)
        .collect();
    let digest = hash_reader(Flavor::Official, &bytes[..]).unwrap();
    Arc::new(Payload { bytes, digest })
}
fn recv(stream: &mut TcpStream) -> Option<Packet> {
    let mut h = [0; 6];
    stream.read_exact(&mut h).ok()?;
    let (protocol, len, opcode) = Packet::header(&h).unwrap();
    let mut b = vec![0; len];
    stream.read_exact(&mut b).ok()?;
    Some(Packet::new(protocol, opcode, b))
}
fn send(stream: &mut TcpStream, opcode: u8, body: Vec<u8>) -> bool {
    stream
        .write_all(&Packet::new(Protocol::Edonkey, opcode, body).encode())
        .is_ok()
}

#[derive(Default)]
struct Started {
    addresses: Mutex<Vec<SocketAddr>>,
    changed: Condvar,
}
impl Started {
    fn wait_for_two(&self, addr: SocketAddr) {
        let mut s = self.addresses.lock().unwrap();
        if !s.contains(&addr) {
            s.push(addr);
            self.changed.notify_all();
        }
        let deadline = Instant::now() + Duration::from_secs(4);
        while s.len() < 2 {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "two distinct peers must receive requests before either transfers"
            );
            s = self.changed.wait_timeout(s, left).unwrap().0;
        }
    }
}
#[derive(Default)]
struct Report {
    parts: Vec<usize>,
    connections: usize,
}
struct Server {
    addr: SocketAddr,
    handle: JoinHandle<Report>,
    stop: Arc<AtomicBool>,
}
impl Server {
    fn finish(self) -> Report {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.join().unwrap()
    }
}
fn server(
    data: Arc<Payload>,
    simultaneous: Option<Arc<Started>>,
    first_request: Option<mpsc::Sender<()>>,
    disconnect_first: bool,
) -> Server {
    server_mode_full(data, simultaneous, first_request, disconnect_first, false, None)
}

/// 可指定 `queued` 的变体（不主动断开）。
fn server_mode(
    data: Arc<Payload>,
    simultaneous: Option<Arc<Started>>,
    first_request: Option<mpsc::Sender<()>>,
    disconnect_first: bool,
    queued: bool,
) -> Server {
    server_mode_full(data, simultaneous, first_request, disconnect_first, queued, None)
}

fn server_mode_full(
    data: Arc<Payload>,
    simultaneous: Option<Arc<Started>>,
    first_request: Option<mpsc::Sender<()>>,
    disconnect_first: bool,
    queued: bool,
    // 收到信号后，在下一个块发完就断开（用于“IPC 已观察旧归属”后再释放）。
    break_rx: Option<mpsc::Receiver<()>>,
) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let end = stop.clone();
    let handle = thread::spawn(move || {
        let mut report = Report::default();
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut stream = loop {
            if end.load(Ordering::SeqCst) {
                return report;
            }
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("{e}"),
            }
            assert!(Instant::now() < deadline, "peer was not connected");
            thread::sleep(Duration::from_millis(2));
        };
        report.connections += 1;
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let mut first = first_request;
        let mut entered = false;
        while let Some(p) = recv(&mut stream) {
            match p.opcode {
                ed2k::HELLO => {
                    let hello = HelloInfo::decode(ed2k::HELLO, &p.payload).unwrap();
                    if !send(&mut stream, ed2k::HELLOANSWER, hello.encode(true)) {
                        break;
                    }
                }
                ed2k::REQUESTFILENAME => {
                    let mut b = data.digest.file.to_vec();
                    b.extend_from_slice(&8u16.to_le_bytes());
                    b.extend_from_slice(b"pool.bin");
                    if !send(&mut stream, ed2k::REQFILENAMEANSWER, b) {
                        break;
                    }
                }
                ed2k::SETREQFILEID => {
                    if !send(
                        &mut stream,
                        ed2k::FILESTATUS,
                        FileStatus::complete(data.digest.file, data.bytes.len() as u64).encode(),
                    ) {
                        break;
                    }
                }
                ed2k::HASHSETREQUEST => {
                    let mut b = data.digest.file.to_vec();
                    b.extend_from_slice(&(data.digest.parts.len() as u16).to_le_bytes());
                    for h in &data.digest.parts {
                        b.extend_from_slice(h);
                    }
                    if !send(&mut stream, ed2k::HASHSETANSWER, b) {
                        break;
                    }
                }
                ed2k::STARTUPLOADREQ => {
                    if queued {
                        let packet = Packet::new(
                            Protocol::Emule,
                            emule::QUEUERANKING,
                            QueueRanking { rank: 42 }.encode(),
                        );
                        if stream.write_all(&packet.encode()).is_err() {
                            break;
                        }
                        continue;
                    }
                    if !send(&mut stream, ed2k::ACCEPTUPLOADREQ, vec![]) {
                        break;
                    }
                }
                ed2k::REQUESTPARTS => {
                    let req = RequestParts::decode(p.opcode, &p.payload).unwrap();
                    assert!(req.ranges.len() <= 3);
                    assert_eq!(req.file_hash, data.digest.file);
                    if !entered {
                        entered = true;
                        if let Some(tx) = first.take() {
                            let _ = tx.send(());
                        }
                        if let Some(gate) = &simultaneous {
                            gate.wait_for_two(addr);
                        }
                    }
                    for r in req.ranges {
                        assert!(r.len() <= EMBLOCKSIZE);
                        assert_eq!(r.start / PARTSIZE, (r.end - 1) / PARTSIZE);
                        report.parts.push((r.start / PARTSIZE) as usize);
                        let part = SendingPart {
                            file_hash: data.digest.file,
                            start: r.start,
                            end: r.end,
                            data: data.bytes[r.start as usize..r.end as usize].to_vec(),
                        };
                        let (op, b) = part.encode();
                        if !send(&mut stream, op, b) {
                            return report;
                        }
                        if disconnect_first {
                            return report;
                        }
                        if let Some(rx) = &break_rx {
                            if rx.try_recv().is_ok() {
                                return report;
                            }
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                }
                ed2k::END_OF_DOWNLOAD => break,
                emule::REQUESTSOURCES2 => {
                    // 源交换请求合法但本用例无新增源：回空应答（注意协议字节是 0xC5），保持严格 mock。
                    let mut v = vec![1u8];
                    v.extend_from_slice(&data.digest.file);
                    v.extend_from_slice(&0u16.to_le_bytes());
                    let packet = Packet::new(Protocol::Emule, emule::ANSWERSOURCES2, v);
                    if stream.write_all(&packet.encode()).is_err() {
                        break;
                    }
                }
                _ => panic!("unexpected opcode {}", p.opcode),
            }
        }
        report
    });
    Server { addr, handle, stop }
}

fn run(
    data: &Payload,
    target: &Target,
    rx: mpsc::Receiver<SocketAddr>,
    max: usize,
    hooks: &Hooks,
    stop: &AtomicBool,
    events: &Mutex<Vec<PeerEvent>>,
    progress: &mut Vec<PoolProgress>,
) -> MultiDownload {
    download_from_sources(
        &MultiSourceCfg {
            user_hash: aidm_engine::ed2k::peer_session::client_hash(),
            file_hash: data.digest.file,
            file_size: data.bytes.len() as u64,
            target: &target.path,
            max_connections: max,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            discovery_timeout: Duration::from_secs(5),
            stop: &|| stop.load(Ordering::SeqCst),
            hooks,
            on_event: &|e| {
                if matches!(&e, PeerEvent::Finished { error: Some(_), .. }) {
                    eprintln!("{e:?}");
                }
                events.lock().unwrap().push(e)
            },
            xs_sources: None,
            feed_done: None,
            aich_root: None,
            part_filter: None,
            expansion: None,
            on_ownership: None,
            claim_base: 1,
            claim_reserve: 4096,
            claim_refill: None,
        },
        rx,
        |p| progress.push(p),
    )
    .unwrap()
}

#[test]
fn distinct_peers_transfer_concurrently_from_incremental_discovery_and_reuse_verified_prefix() {
    let data = payload(3);
    let target = Target::new();
    std::fs::write(&target.path, &data.bytes[..PARTSIZE as usize]).unwrap();
    let gate = Arc::new(Started::default());
    let (started_tx, started_rx) = mpsc::channel();
    let a = server(data.clone(), Some(gate.clone()), Some(started_tx), false);
    let b = server(data.clone(), Some(gate), None, false);
    let (tx, rx) = mpsc::channel();
    tx.send(a.addr).unwrap();
    tx.send(a.addr).unwrap();
    let b_addr = b.addr;
    let discovery = thread::spawn(move || {
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        tx.send(b_addr).unwrap();
    });
    let hooks = Hooks::new(8);
    let events = Mutex::new(vec![]);
    let mut progress = vec![];
    let out = run(
        &data,
        &target,
        rx,
        2,
        &hooks,
        &AtomicBool::new(false),
        &events,
        &mut progress,
    );
    discovery.join().unwrap();
    let ar = a.finish();
    let br = b.finish();
    assert!(out.is_complete());
    assert_eq!(out.written, data.bytes.len() as u64);
    assert_eq!(std::fs::read(&target.path).unwrap(), data.bytes);
    assert_eq!(hooks.peak.load(Ordering::SeqCst), 2);
    assert_eq!(hooks.active.load(Ordering::SeqCst), 0);
    assert_eq!(
        hooks.bytes.load(Ordering::SeqCst),
        data.bytes.len() as u64 - PARTSIZE
    );
    assert_eq!((ar.connections, br.connections), (1, 1));
    assert!(!ar.parts.is_empty() && !br.parts.is_empty());
    assert!(
        ar.parts.iter().all(|i| !br.parts.contains(i)),
        "live peers must own distinct verification parts"
    );
    assert!(progress
        .iter()
        .any(|p| p.verified_parts == 1 && p.done == PARTSIZE));
    assert!(progress.iter().any(|p| p.transferring_peers == 2));
    assert!(progress
        .iter()
        .all(|p| p.active_peers <= 2 && p.done <= data.bytes.len() as u64));
    assert!(progress.iter().any(|p| p.verifying));
    assert!(!progress.last().unwrap().verifying);
}

#[test]
fn completing_peer_closes_another_peer_still_silently_queued() {
    let data = payload(1);
    let target = Target::new();
    let queued = server_mode(data.clone(), None, None, false, true);
    let active = server(data.clone(), None, None, false);
    let queued_addr = queued.addr;
    let active_addr = active.addr;
    let (tx, rx) = mpsc::channel();
    tx.send(queued_addr).unwrap();
    let discovery = Mutex::new(Some(tx));
    let events = Mutex::new(Vec::new());
    let hooks = Hooks::new(2);
    let start = Instant::now();
    let out = download_from_sources(
        &MultiSourceCfg {
            user_hash: aidm_engine::ed2k::peer_session::client_hash(),
            file_hash: data.digest.file,
            file_size: data.bytes.len() as u64,
            target: &target.path,
            max_connections: 2,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            discovery_timeout: Duration::from_secs(5),
            stop: &|| false,
            hooks: &hooks,
            on_event: &|event| {
                if matches!(event, PeerEvent::Queued { rank: Some(42), .. }) {
                    if let Some(tx) = discovery.lock().unwrap().take() {
                        tx.send(active_addr).unwrap();
                    }
                }
                events.lock().unwrap().push(event);
            },
            xs_sources: None,
            feed_done: None,
            aich_root: None,
            part_filter: None,
            expansion: None,
            on_ownership: None,
            claim_base: 1,
            claim_reserve: 4096,
            claim_refill: None,
        },
        rx,
        |_| {},
    )
    .unwrap();
    assert!(out.is_complete() && !out.stopped);
    // 断言意图是"完成会打断 120 秒的排队等待"，不是"4 秒内必须跑完"：整仓并行跑测试
    // （几百 MB 传输 + 哈希）时 4 秒会被别的测试挤爆。15 秒仍远小于 120 秒，能证明同一件事。
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "completion must interrupt the 120-second queue wait"
    );
    queued.finish();
    active.finish();
    assert!(events.lock().unwrap().iter().any(
        |e| matches!(e,PeerEvent::Finished {addr,network_bytes:0,error:None} if *addr==queued_addr)
    ));
    assert_eq!(hooks.active.load(Ordering::SeqCst), 0);
}

#[test]
fn pause_when_whole_file_verification_starts_does_not_report_completion() {
    let data = payload(0);
    let target = Target::new();
    let source = server(data.clone(), None, None, false);
    let (tx, rx) = mpsc::channel();
    tx.send(source.addr).unwrap();
    drop(tx);
    let stop = AtomicBool::new(false);
    let hooks = Hooks::new(1);
    let mut progress = Vec::new();
    let out = download_from_sources(
        &MultiSourceCfg {
            user_hash: aidm_engine::ed2k::peer_session::client_hash(),
            file_hash: data.digest.file,
            file_size: data.bytes.len() as u64,
            target: &target.path,
            max_connections: 1,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            discovery_timeout: Duration::from_secs(5),
            stop: &|| stop.load(Ordering::SeqCst),
            hooks: &hooks,
            on_event: &|_| {},
            xs_sources: None,
            feed_done: None,
            aich_root: None,
            part_filter: None,
            expansion: None,
            on_ownership: None,
            claim_base: 1,
            claim_reserve: 4096,
            claim_refill: None,
        },
        rx,
        |p| {
            if p.verifying {
                stop.store(true, Ordering::SeqCst);
            }
            progress.push(p);
        },
    )
    .unwrap();
    source.finish();
    assert!(out.stopped && !out.is_complete());
    assert!(progress.iter().any(|p| p.verifying));
    assert!(!progress.last().unwrap().verifying);
    assert_eq!(hooks.active.load(Ordering::SeqCst), 0);
}

#[test]
fn disconnected_owner_is_reassigned_to_another_existing_connection() {
    let data = payload(2);
    let target = Target::new();
    let gate = Arc::new(Started::default());
    let a = server(data.clone(), Some(gate.clone()), None, true);
    let b = server(data.clone(), Some(gate), None, false);
    let (tx, rx) = mpsc::channel();
    tx.send(a.addr).unwrap();
    tx.send(b.addr).unwrap();
    drop(tx);
    let hooks = Hooks::new(2);
    let events = Mutex::new(vec![]);
    let mut progress = vec![];
    let out = run(
        &data,
        &target,
        rx,
        2,
        &hooks,
        &AtomicBool::new(false),
        &events,
        &mut progress,
    );
    let ar = a.finish();
    let br = b.finish();
    assert!(out.is_complete());
    assert_eq!(std::fs::read(&target.path).unwrap(), data.bytes);
    assert!(br.parts.contains(&ar.parts[0]));
    assert_eq!(
        br.connections, 1,
        "survivor must keep its original TCP session"
    );
    assert!(events
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(e, PeerEvent::Finished { error: Some(_), .. })));
    assert!(
        hooks.bytes.load(Ordering::SeqCst) > data.bytes.len() as u64,
        "replayed bytes are traffic, not completed coverage"
    );
}

#[test]
fn task_cap_and_temporarily_denied_global_permit_are_hard_limits() {
    let data = payload(1);
    let target = Target::new();
    let a = server(data.clone(), None, None, false);
    let b = server(data.clone(), None, None, false);
    let (tx, rx) = mpsc::channel();
    tx.send(a.addr).unwrap();
    tx.send(b.addr).unwrap();
    drop(tx);
    let hooks = Hooks::new(1);
    hooks.denied.store(5, Ordering::SeqCst);
    let events = Mutex::new(vec![]);
    let mut progress = vec![];
    let out = run(
        &data,
        &target,
        rx,
        1,
        &hooks,
        &AtomicBool::new(false),
        &events,
        &mut progress,
    );
    let ar = a.finish();
    let br = b.finish();
    assert!(out.is_complete());
    assert_eq!(hooks.peak.load(Ordering::SeqCst), 1);
    assert_eq!(ar.connections + br.connections, 1);
    assert!(progress.iter().all(|p| p.active_peers <= 1));
    assert_eq!(hooks.bytes.load(Ordering::SeqCst), data.bytes.len() as u64);
    assert_eq!(hooks.active.load(Ordering::SeqCst), 0);
}

#[test]
fn pause_interrupts_all_peer_reads_and_partial_data_is_safe_to_resume() {
    let data = payload(2);
    let target = Target::new();
    let gate = Arc::new(Started::default());
    let a = server(data.clone(), Some(gate.clone()), None, false);
    let b = server(data.clone(), Some(gate), None, false);
    let (tx, rx) = mpsc::channel();
    tx.send(a.addr).unwrap();
    tx.send(b.addr).unwrap();
    drop(tx);
    let stop = AtomicBool::new(false);
    let hooks = Hooks::new(2);
    let started = Instant::now();
    let out = download_from_sources(
        &MultiSourceCfg {
            user_hash: aidm_engine::ed2k::peer_session::client_hash(),
            file_hash: data.digest.file,
            file_size: data.bytes.len() as u64,
            target: &target.path,
            max_connections: 2,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            discovery_timeout: Duration::from_secs(5),
            stop: &|| stop.load(Ordering::SeqCst),
            hooks: &hooks,
            on_event: &|e| {
                if matches!(e, PeerEvent::Receiving { .. }) {
                    stop.store(true, Ordering::SeqCst);
                }
            },
            xs_sources: None,
            feed_done: None,
            aich_root: None,
            part_filter: None,
            expansion: None,
            on_ownership: None,
            claim_base: 1,
            claim_reserve: 4096,
            claim_refill: None,
        },
        rx,
        |_| {},
    )
    .unwrap();
    a.finish();
    b.finish();
    assert!(out.stopped && !out.is_complete());
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(hooks.active.load(Ordering::SeqCst), 0);
    assert!(out.written < data.bytes.len() as u64);
    let a = server(data.clone(), None, None, false);
    let (tx, rx) = mpsc::channel();
    tx.send(a.addr).unwrap();
    drop(tx);
    let events = Mutex::new(vec![]);
    let mut progress = vec![];
    let out = run(
        &data,
        &target,
        rx,
        1,
        &hooks,
        &AtomicBool::new(false),
        &events,
        &mut progress,
    );
    a.finish();
    assert!(out.is_complete());
    assert_eq!(std::fs::read(&target.path).unwrap(), data.bytes);
}

#[test]
fn index_hashset_reuses_existing_parts_without_peer_and_rejects_wrong_identity() {
    use aidm_engine::ed2k::multi_source::download_from_sources_with_hashsets;
    let data = payload(1);
    let target = Target::new();
    std::fs::write(&target.path, &data.bytes).unwrap();
    let hooks = Hooks::new(1);
    for valid in [false, true] {
        let mut hashes = data.digest.parts.clone();
        if !valid {
            hashes[0][0] ^= 1;
        }
        let (hash_tx, hash_rx) = mpsc::channel();
        hash_tx.send(hashes).unwrap();
        drop(hash_tx);
        let (source_tx, source_rx) = mpsc::channel();
        drop(source_tx);
        let out = download_from_sources_with_hashsets(
            &MultiSourceCfg {
                user_hash: aidm_engine::ed2k::peer_session::client_hash(),
                file_hash: data.digest.file,
                file_size: data.bytes.len() as u64,
                target: &target.path,
                max_connections: 1,
                connect_timeout: Duration::from_millis(50),
                read_timeout: Duration::from_millis(50),
                discovery_timeout: Duration::from_millis(50),
                stop: &|| false,
                hooks: &hooks,
                on_event: &|_| panic!("no network peer is configured"),
                xs_sources: None,
                feed_done: None,
                aich_root: None,
                part_filter: None,
                expansion: None,
                on_ownership: None,
                claim_base: 1,
                claim_reserve: 4096,
                claim_refill: None,
            },
            source_rx,
            Some(hash_rx),
            |_| {},
        )
        .unwrap();
        assert_eq!(out.is_complete(), valid);
        assert_eq!(out.written, if valid { data.bytes.len() as u64 } else { 0 });
        assert_eq!(
            hooks.bytes.load(Ordering::SeqCst),
            0,
            "reused disk data is not traffic"
        );
    }
    assert_eq!(std::fs::read(&target.path).unwrap(), data.bytes);
}

/// 恢复下载：盘上已有分片 + 活跃源 + 校验片**稍后**才到。
///
/// 源必须在"读回校验已落盘分片"之前就连上并开始传；同时已落盘的那片
/// 不能被重下，也不能因为它在后台校验就被当成未完成。
#[test]
fn resume_connects_sources_before_existing_parts_are_read_back() {
    use aidm_engine::ed2k::multi_source::download_from_sources_with_hashsets;
    let data = payload(3);
    let target = Target::new();
    std::fs::write(&target.path, &data.bytes[..PARTSIZE as usize]).unwrap();
    let (req_tx, req_rx) = mpsc::channel();
    let srv = server(data.clone(), None, Some(req_tx), false);
    let (hash_tx, hash_rx) = mpsc::channel();
    let (source_tx, source_rx) = mpsc::channel();
    source_tx.send(srv.addr).unwrap();
    drop(source_tx);
    let hashes = data.digest.parts.clone();
    let feeder = thread::spawn(move || {
        req_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("源必须在读回校验完成之前连上并开始请求分片");
        hash_tx.send(hashes).unwrap();
    });
    let hooks = Hooks::new(1);
    let events = Mutex::new(vec![]);
    let out = download_from_sources_with_hashsets(
        &MultiSourceCfg {
            user_hash: aidm_engine::ed2k::peer_session::client_hash(),
            file_hash: data.digest.file,
            file_size: data.bytes.len() as u64,
            target: &target.path,
            max_connections: 1,
            connect_timeout: Duration::from_secs(2),
            read_timeout: Duration::from_secs(5),
            discovery_timeout: Duration::from_secs(5),
            stop: &|| false,
            hooks: &hooks,
            on_event: &|e| events.lock().unwrap().push(e),
            xs_sources: None,
            feed_done: None,
            aich_root: None,
            part_filter: None,
            expansion: None,
            on_ownership: None,
            claim_base: 1,
            claim_reserve: 4096,
            claim_refill: None,
        },
        source_rx,
        Some(hash_rx),
        |_| {},
    )
    .unwrap();
    feeder.join().unwrap();
    let report = srv.finish();
    assert!(out.is_complete());
    assert_eq!(std::fs::read(&target.path).unwrap(), data.bytes);
    assert!(
        report.parts.iter().all(|p| *p != 0),
        "已落盘的分片不得被重新下载：{:?}",
        report.parts
    );
    assert_eq!(
        hooks.bytes.load(Ordering::SeqCst),
        data.bytes.len() as u64 - PARTSIZE,
        "复用磁盘数据不算流量"
    );
}

/// 端到端：真实双对端 eD2k 下载 → 统一快照（**经回环 IPC 服务**）→ 落盘与事件关联。
///
/// 这条用例补齐的是此前“分段验证”缺的那一环：池产出的真实归属是否真的
/// 走进了 IPC 客户端能读到的快照。断言刻意只用 IPC 契约（不读内部结构），
/// 所以快照层一旦绕过统一转换就会红。
#[test]
fn unified_snapshot_sees_real_multi_source_ownership_end_to_end() {
    use aidm_ipc::UnifiedSnapshotItem;
    use std::collections::HashSet;

    let target = Target::new();
    let root = target.path.parent().unwrap().to_path_buf();
    let db = aidm_core::open_db(&root.join("db.sqlite")).unwrap();
    aidm_core::settings::ensure_defaults(&db).unwrap();
    let manager = Arc::new(aidm_engine::DownloadManager::new(
        Arc::new(Mutex::new(db)),
        root.join("downloads"),
    ));
    for (key, value) in [
        ("ed2k.servers", ""),
        ("ed2k.kad_enabled", "false"),
        ("conn.global_conn_cap", "3"),
    ] {
        manager.settings_set(key, value).unwrap();
    }

    // 4 个原生 part：足够让两个对端同时各持一个，观测窗口不会被瞬间关闭。
    let data = payload(4);
    let file_len = data.bytes.len() as u64;
    let barrier = Arc::new(Started::default());
    let a = server(data.clone(), Some(barrier.clone()), None, false);
    let b = server(data.clone(), Some(barrier), None, false);
    let link = format!(
        "ed2k://|file|pool.bin|{}|{}|/|sources,{},{}|/",
        file_len,
        data.digest.file_hex(),
        a.addr,
        b.addr
    );

    let port = aidm_engine::server::serve_ephemeral(manager.clone()).expect("serve ipc");
    let id = manager.add(&link, None, None, None, 0).unwrap();

    let mut seen_part_counts: u32 = 0;
    let mut max_assignments: usize = 0;
    let mut saw_two_sources_at_once = false;
    let mut saw_real_range = false;

    let deadline = Instant::now() + Duration::from_secs(30);
    // `tick()` 才会跑影子解释器；按 100ms 节流，避免每 2ms 都做一次调度查库。
    let mut last_tick = Instant::now() - Duration::from_secs(1);
    loop {
        if last_tick.elapsed() >= Duration::from_millis(100) {
            manager.tick();
            last_tick = Instant::now();
        }
        // 只用 IPC 契约层查询，不碰内部结构。
        let resp = aidm_ipc::engine_roundtrip(
            port,
            &aidm_ipc::EngineRequest::TaskSnapshot {
                id: id as u64,
                section: Some("assignments".into()),
                cursor: None,
                limit: Some(256),
            },
            Duration::from_secs(2),
        );
        if let Ok(resp) = resp {
            if let Some(snap) = resp.snapshot {
                seen_part_counts = seen_part_counts.max(snap.total_count);
                if let Some(items) = snap.items {
                    max_assignments = max_assignments.max(items.len());
                    let mut sources: HashSet<String> = HashSet::new();
                    for item in &items {
                        if let UnifiedSnapshotItem::Assignment(a) = item {
                            sources.insert(a.source_id.clone());
                            // 真实范围：起点 < 终点，且落在文件内。
                            let start: u64 = a.range.start.parse().unwrap_or(0);
                            let end: u64 = a
                                .range
                                .end_exclusive
                                .as_deref()
                                .and_then(|s| s.parse().ok())
                                .unwrap_or(0);
                            if start < end && end <= file_len {
                                saw_real_range = true;
                            }
                        }
                    }
                    if sources.len() >= 2 {
                        saw_two_sources_at_once = true;
                    }
                }
            }
        }

        let task = manager.status(id).unwrap().unwrap();
        if task.state == "done" {
            break;
        }
        assert_ne!(task.state, "error", "下载失败：{task:?}");
        assert!(Instant::now() < deadline, "端到端下载超时：{task:?}");
        thread::sleep(Duration::from_millis(2));
    }
    let (a, b) = (a.finish(), b.finish());
    assert!(
        !a.parts.is_empty() && !b.parts.is_empty(),
        "两个对端都必须真的提供过内容"
    );

    // 1) 落盘内容正确（链路真的走完）。
    assert_eq!(
        std::fs::read(root.join("downloads/pool.bin")).unwrap(),
        data.bytes,
        "最终文件必须与源一致"
    );

    // 2) 真实归属确实经 IPC 出现过：part 数非零、范围真实。
    assert!(
        seen_part_counts > 0,
        "下载过程中必须能经 IPC 读到原生 part（实际一直是 0）"
    );
    assert!(
        saw_real_range,
        "通路必须带真实非空范围，不能是空壳（max_assignments={max_assignments}, part_counts={seen_part_counts}）"
    );
    assert!(
        saw_two_sources_at_once,
        "片内多源必须能被观测到（两个不同 source_id 同时在册）"
    );

    // 3) 完成状态与快照一致。
    let resp = manager
        .unified_snapshot(id, None, None, None)
        .expect("summary");
    let view = resp.summary.expect("summary");
    assert_eq!(view.status, "done");
    assert!(
        view.slices.iter().all(|s| s.state == "done"),
        "完成后所有切片应为 done"
    );
    assert_eq!(
        view.progress.verified_unique_bytes,
        file_len.to_string(),
        "eD2k 任务完成的判定依据是原生块校验覆盖"
    );

    // 4) 事件关联：影子事件必须带 event_id 与 state_revision，能被串起来。
    let conn = aidm_core::open_db(&root.join("db.sqlite")).unwrap();
    let mut stmt = conn
        .prepare("SELECT detail FROM events WHERE download_id = ?1 AND kind LIKE 'unified_%'")
        .unwrap();
    let details: Vec<String> = stmt
        .query_map([id], |r| r.get::<_, Option<String>>(0))
        .unwrap()
        .filter_map(|r| r.unwrap())
        .collect();
    assert!(
        !details.is_empty(),
        "真实任务必须产出统一事件；库中实际 kind：{:?}",
        {
            let conn2 = aidm_core::open_db(&root.join("db.sqlite")).unwrap();
            let mut s = conn2
                .prepare("SELECT kind FROM events WHERE download_id = ?1 ORDER BY id")
                .unwrap();
            s.query_map([id], |r| r.get::<_, String>(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect::<Vec<_>>()
        }
    );
    for d in &details {
        assert!(d.contains("event_id="), "事件必须带 event_id：{d}");
        assert!(d.contains("rev="), "事件必须带 state_revision：{d}");
    }
    assert!(
        details
            .iter()
            .any(|d| d.contains("event=download.state_changed")),
        "至少一条状态变化事件：{details:?}"
    );
    // 终态事件由影子节流（5 秒）决定是否赶得上；这里不断言“一定有 to=done”，
    // 终态埋点本身由 `manager::shadow_tests` 单独覆盖。
}
/// 从 `assignment_id` 里取 part 序号（形如 `task-{id}-part-{part}-c{seq}`）。
///
/// 归属 ID 里编码了 part 与领取生命周期；这里只取 part，用来跟踪
/// “同一片是否换过负责方”。
fn parse_assignment_part(assignment_id: &str) -> Option<String> {
    assignment_id
        .split("-part-")
        .nth(1)
        .and_then(|rest| rest.split('-').next())
        .map(str::to_owned)
}

/// 经 IPC 拉一次 assignments 分页，返回 `(part, assignment_id)` 列表。
fn poll_assignments(port: u16, task_id: i64) -> Vec<(String, String)> {
    use aidm_ipc::UnifiedSnapshotItem;

    let Ok(resp) = aidm_ipc::engine_roundtrip(
        port,
        &aidm_ipc::EngineRequest::TaskSnapshot {
            id: task_id as u64,
            section: Some("assignments".into()),
            cursor: None,
            limit: Some(256),
        },
        Duration::from_secs(2),
    ) else {
        return Vec::new();
    };
    let Some(snap) = resp.snapshot else {
        return Vec::new();
    };
    let Some(items) = snap.items else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(|item| match item {
            UnifiedSnapshotItem::Assignment(a) => {
                parse_assignment_part(&a.assignment_id).map(|part| (part, a.assignment_id))
            }
            _ => None,
        })
        .collect()
}

/// 端到端：某个 part 先由一个对端承担，断开后由另一个对端接管。
///
/// 上一版失败的原因与对应措施：
/// 1. 固定盯 part 0——但谁先 claim 哪片由调度决定。改为**跟踪实际出现的 part**；
/// 2. 断开时机不确定——可能早于 IPC 观测。改为**同步屏障**：等 IPC 真正看到
///    归属之后，才发信号允许断开；
/// 3. 只断言“看到接管后的 ID”——改为断言**同一 part 出现两个不同 ID**。
#[test]
fn releasing_and_reassigning_a_part_changes_assignment_identity_end_to_end() {
    use std::collections::{HashMap, HashSet};

    let target = Target::new();
    let root = target.path.parent().unwrap().to_path_buf();
    let db = aidm_core::open_db(&root.join("db.sqlite")).unwrap();
    aidm_core::settings::ensure_defaults(&db).unwrap();
    let manager = Arc::new(aidm_engine::DownloadManager::new(
        Arc::new(Mutex::new(db)),
        root.join("downloads"),
    ));
    for (key, value) in [
        ("ed2k.servers", ""),
        ("ed2k.kad_enabled", "false"),
        ("conn.global_conn_cap", "2"),
    ] {
        manager.settings_set(key, value).unwrap();
    }

    let data = payload(4);
    let file_len = data.bytes.len() as u64;
    // 两个对端同步起来，保证都会拿到分片；A 收到信号后才断。
    let gate = Arc::new(Started::default());
    let (break_tx, break_rx) = mpsc::channel();
    let a = server_mode_full(
        data.clone(),
        Some(gate.clone()),
        None,
        false,
        false,
        Some(break_rx),
    );
    let b = server_mode_full(data.clone(), Some(gate), None, false, false, None);
    let link = format!(
        "ed2k://|file|pool.bin|{}|{}|/|sources,{},{}|/",
        file_len,
        data.digest.file_hex(),
        a.addr,
        b.addr
    );

    let port = aidm_engine::server::serve_ephemeral(manager.clone()).expect("serve ipc");
    let id = manager.add(&link, None, None, None, 0).unwrap();

    // part → 出现过的 assignment_id 集合。
    let mut by_part: HashMap<String, HashSet<String>> = HashMap::new();
    let mut collect = |by_part: &mut HashMap<String, HashSet<String>>| {
        for (part, aid) in poll_assignments(port, id) {
            by_part.entry(part).or_default().insert(aid);
        }
    };

    let deadline = Instant::now() + Duration::from_secs(40);
    let mut last_tick = Instant::now() - Duration::from_secs(1);

    // 阶段 1：等**两个对端都拿到分片**。只等第一个归属就放行是不够的：
    // 那个刚出现的通路可能属于 B，A 还没领到任何片，断开就没效果。
    while Instant::now() < deadline {
        if last_tick.elapsed() >= Duration::from_millis(50) {
            manager.tick();
            last_tick = Instant::now();
        }
        collect(&mut by_part);
        if by_part.len() >= 2 {
            break;
        }
        let task = manager.status(id).unwrap().unwrap();
        assert_ne!(task.state, "error", "下载失败：{task:?}");
        thread::sleep(Duration::from_millis(2));
    }
    assert!(
        by_part.len() >= 2,
        "两个对端应各自领到分片；实际只看到 {by_part:?}"
    );

    // 阶段 2：同步屏障——IPC 已经看到旧归属，现在允许 A 在下一个块后断开。
    let _ = break_tx.send(());

    // 阶段 3：等某一片出现第二个不同 ID（核心断言）。
    let mut saw_new_identity = false;
    while Instant::now() < deadline {
        if last_tick.elapsed() >= Duration::from_millis(50) {
            manager.tick();
            last_tick = Instant::now();
        }
        collect(&mut by_part);
        if by_part.values().any(|ids| ids.len() >= 2) {
            saw_new_identity = true;
            break;
        }
        let task = manager.status(id).unwrap().unwrap();
        if task.state == "done" || task.state == "error" {
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }

    // 阶段 4：继续等到任务真正完成。eD2k 下载完还要做整文件 MD4 校验与提交，
    // 中间会停在 `verifying`，此时最终文件还不存在。
    while Instant::now() < deadline {
        if last_tick.elapsed() >= Duration::from_millis(50) {
            manager.tick();
            last_tick = Instant::now();
        }
        collect(&mut by_part);
        let task = manager.status(id).unwrap().unwrap();
        if task.state == "done" {
            break;
        }
        assert_ne!(task.state, "error", "下载失败：{task:?}");
        thread::sleep(Duration::from_millis(2));
    }

    let ra = a.finish();
    let rb = b.finish();
    let final_state = manager.status(id).unwrap().unwrap().state.clone();
    let path = root.join("downloads/pool.bin");
    let written = std::fs::read(&path);
    assert!(
        written.is_ok(),
        "最终文件缺失（state={final_state}, by_part={by_part:?}, a_parts={:?}, b_parts={:?}）",
        ra.parts,
        rb.parts
    );
    assert_eq!(
        written.unwrap(),
        data.bytes,
        "换源后最终文件仍必须与源一致"
    );
    assert!(
        saw_new_identity,
        "某一片被释放重领后必须出现新的分配 ID；观察到：{by_part:?} a_parts={:?} b_parts={:?}",
        ra.parts, rb.parts
    );
}
