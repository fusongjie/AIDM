//! eD2k 入站上传服务（L6）：TCP 监听 + 应答下载请求 + 上传槽 + 信用记账。
//!
//! ## 为什么默认关
//!
//! 开启后本机在 `ed2k.listen_port` 上监听并对外提供**已完成的 eD2k 任务**。
//! 这与 eMule 默认开启不同：AIDM 把"对外监听"当作需要用户明确选择的能力
//! （防火墙、公司网络、共享范围都是用户的判断），因此 `ed2k.upload_enabled`
//! 默认 false，开启前不绑定任何端口。
//!
//! ## 协议路径（应答侧，与 `peer_session.rs` 的请求侧对称）
//!
//! ```text
//! 收 HELLO         → 回 HELLOANSWER
//! 收 REQUESTFILENAME → 共享且有这个哈希 → REQFILENAMEANSWER，否则 FILEREQANSNOFIL
//! 收 SETREQFILEID   → FILESTATUS（我们是完整源）
//! 收 HASHSETREQUEST → HASHSETANSWER（分片哈希集，落库缓存）
//! 收 STARTUPLOADREQ → 入队；排到就 ACCEPTUPLOADREQ，否则 QUEUERANKING 后继续等
//! 收 REQUESTPARTS   → 逐块校验 + 限速 + SENDINGPART（只有已占上传槽才服务）
//! 收 END_OF_DOWNLOAD / CANCELTRANSFER → 释放上传槽
//! ```
//!
//! ## 明确不做（不要读成已实现）
//!
//! - **LowID 回连**（`OP_CALLBACK`/UDP 回连）：我们只接受直连，不做 NAT 打洞。
//! - **混淆/加密层**：`SupportsCryptLayer` 保持 false。
//! - **压缩传输**（`OP_COMPRESSEDPART`）：只发未压缩块。
//! - **AICH 应答**（入站 `OP_AICHREQUEST`）：需要共享文件的 AICH 树，`aich_version`
//!   仍声明 0，避免"声明支持却不回"。
//! - **入站源交换请求**（0x83）：暂不回答（与请求侧说明一致）。
//! - **上传信用用于我方排队**：信用已记账（`ed2k_credits.uploaded_bytes`），
//!   但"用上传换取对方给的队列优先"要等对方客户端按我们的哈希记账。

use std::io::{Read, Seek, SeekFrom};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aidm_core::ed2k::peer::{
    ed2k, emule, pack_emule_version, part_count, FileStatus, HelloInfo, MiscOptions1, MiscOptions2,
    Packet, Protocol, RequestParts, SendingPart, Tag, TagValue, EDONKEYVERSION,
};
use aidm_core::ed2k::{
    credits,
    share::{self, SharedFile},
};
use aidm_core::settings as kv;
use rusqlite::Connection;

use super::upload_queue::UploadQueue;
use super::wire::Conn;
use crate::limiter::TokenBucket;

pub const KEY_ENABLED: &str = "ed2k.upload_enabled";
pub const KEY_PORT: &str = "ed2k.listen_port";
pub const KEY_SLOTS: &str = "ed2k.upload_slots";
pub const KEY_MAX_WAITING: &str = "ed2k.upload_max_waiting";
pub const KEY_UPLOAD_KBPS: &str = "ed2k.upload_rate_kbps";

/// 每次 `REQUESTPARTS` 后把已发字节写进信用表；上限防止一次请求过长。
const CREDIT_FLUSH_BYTES: u64 = 4 * 1024 * 1024;
/// 单条连接的读超时：对端在排队期间会周期性重发请求，长时间静默视为掉线。
const SESSION_READ_TIMEOUT: Duration = Duration::from_secs(120);
/// 还没握手完就沉默的连接（扫描/半开）很快回收。
const HANDSHAKE_IDLE_LIMIT: Duration = Duration::from_secs(60);
/// 已在排队/传输的会话：eMule 的队列本来可以等很久，给足时间。
const QUEUED_IDLE_LIMIT: Duration = Duration::from_secs(30 * 60);
/// 排队期间重新推送排名的间隔（eMule 也是周期性推送）。
const RANK_REFRESH: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSettings {
    pub enabled: bool,
    pub port: u16,
    pub slots: usize,
    pub max_waiting: usize,
    pub upload_kbps: u64,
}

impl Default for InboundSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            port: 4662,
            slots: 3,
            max_waiting: 50,
            upload_kbps: 0,
        }
    }
}

impl InboundSettings {
    /// 从设置读取。
    ///
    /// 解析失败回落到默认值；**能解析但越界则夹取到区间**（设置写入时 `setting_spec`
    /// 已经拒过一次越界，这里再防一次手改数据库的情况；夹取比"静默用默认值"更可预期）。
    pub fn load(conn: &Connection) -> Self {
        let default = Self::default();
        let raw = |key: &str| kv::get(conn, key).ok().flatten();
        let uint = |key: &str, fallback: u64, min: u64, max: u64| -> u64 {
            let parsed = raw(key)
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(fallback);
            parsed.clamp(min, max)
        };
        Self {
            enabled: matches!(
                raw(KEY_ENABLED).as_deref().map(str::trim),
                Some("true") | Some("1")
            ),
            port: uint(KEY_PORT, u64::from(default.port), 0, u64::from(u16::MAX)) as u16,
            slots: uint(KEY_SLOTS, default.slots as u64, 1, 16) as usize,
            max_waiting: uint(KEY_MAX_WAITING, default.max_waiting as u64, 1, 500) as usize,
            upload_kbps: uint(KEY_UPLOAD_KBPS, 0, 0, 1024 * 1024),
        }
    }
}

/// 对外可查的上传状态（IPC `UploadStatus` 与日志共用同一份数字）。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InboundStats {
    pub enabled: bool,
    /// 实际监听到的端口（`ed2k.listen_port = 0` 时是系统分配的端口）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening_port: Option<u16>,
    /// 已占上传槽的会话数。
    pub active_sessions: u32,
    /// 排队等待上传槽的会话数。
    pub queued_sessions: u32,
    /// 正在处理的入站连接数（含排队与已结束握手的空闲连接）。
    pub connections: u32,
    pub uploaded_bytes: u64,
    pub served_blocks: u64,
    /// 因越界/超长/未占槽而被拒绝的块请求数。
    pub rejected_blocks: u64,
    /// 共享文件数（已完成且记录上有 eD2k 哈希的任务）。
    pub shared_files: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

pub type SharedStats = Arc<Mutex<InboundStats>>;

/// 入站服务句柄。
pub struct Inbound {
    stats: SharedStats,
    stop: Arc<AtomicBool>,
    upload: Arc<TokenBucket>,
    queue: Arc<Mutex<UploadQueue>>,
    file_priority: u8,
}

impl Inbound {
    /// 启动常驻监督线程并立即返回句柄。
    ///
    /// 监督线程每 2 秒重读设置：开关、端口、槽数、限速都即时生效；
    /// 关掉时立刻解绑端口（不再接受新连接），已在传输的会话自然结束。
    pub fn spawn(db: Arc<Mutex<Connection>>, identity: [u8; 16]) -> Arc<Self> {
        let inbound = Arc::new(Self {
            stats: Arc::new(Mutex::new(InboundStats::default())),
            stop: Arc::new(AtomicBool::new(false)),
            upload: TokenBucket::new(0),
            queue: Arc::new(Mutex::new(UploadQueue::new(50, 3))),
            // 本机所有共享文件的优先级一致：我们不做"按文件插队"。
            file_priority: 7,
        });
        let worker = inbound.clone();
        let _ = std::thread::Builder::new()
            .name("ed2k-inbound".into())
            .spawn(move || supervise(worker, db, identity));
        inbound
    }

    pub fn stats(&self) -> InboundStats {
        self.stats.lock().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    fn patch(&self, f: impl FnOnce(&mut InboundStats)) {
        if let Ok(mut stats) = self.stats.lock() {
            f(&mut stats);
        }
    }
}

/// 当前会话数上限：上传槽之外还要留排队与短连接的位置。
fn session_cap(settings: &InboundSettings) -> usize {
    settings.slots * 4 + 16
}

fn supervise(inbound: Arc<Inbound>, db: Arc<Mutex<Connection>>, identity: [u8; 16]) {
    let mut listener: Option<TcpListener> = None;
    let mut bound_port: u16 = 0;
    let mut settings = InboundSettings::default();
    let mut last_settings_check = std::time::Instant::now() - Duration::from_secs(60);

    loop {
        if inbound.stop.load(Ordering::SeqCst) {
            break;
        }
        if last_settings_check.elapsed() >= Duration::from_secs(2) {
            last_settings_check = std::time::Instant::now();
            let loaded = db.lock().map(|conn| InboundSettings::load(&conn));
            match loaded {
                Ok(next) => {
                    // 限速/槽数即时生效（不驱逐已占槽会话）
                    inbound.upload.set_limit_kbps(next.upload_kbps);
                    if let Ok(mut queue) = inbound.queue.lock() {
                        queue.set_limits(next.max_waiting, next.slots);
                    }
                    let shared = db
                        .lock()
                        .ok()
                        .and_then(|conn| share::shared_files(&conn).ok())
                        .map(|files| files.len() as u32);
                    inbound.patch(|stats| {
                        stats.enabled = next.enabled;
                        if let Some(n) = shared {
                            stats.shared_files = n;
                        }
                    });
                    if !next.enabled {
                        listener = None;
                        bound_port = 0;
                        inbound.patch(|stats| {
                            stats.listening_port = None;
                            stats.last_error = None;
                        });
                    } else if listener.is_none() || bound_port != next.port {
                        match bind(next.port) {
                            Ok((l, port)) => {
                                listener = Some(l);
                                bound_port = port;
                                log::info!("ed2k inbound listening on port {port}");
                                inbound.patch(|stats| {
                                    stats.listening_port = Some(port);
                                    stats.last_error = None;
                                });
                            }
                            Err(e) => {
                                log::warn!("ed2k inbound bind failed on port {}: {e}", next.port);
                                listener = None;
                                bound_port = 0;
                                inbound.patch(|stats| {
                                    stats.listening_port = None;
                                    stats.last_error = Some(format!("bind: {e}"));
                                });
                            }
                        }
                    }
                    settings = next;
                }
                Err(_) => {
                    // 数据库锁被毒化：保持上一轮配置继续跑，不因为一次读失败就停服务。
                }
            }
        }

        let Some(l) = listener.as_ref() else {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        };
        match l.accept() {
            Ok((stream, peer)) => {
                let current = inbound
                    .stats
                    .lock()
                    .map(|s| s.connections)
                    .unwrap_or_default();
                if current as usize >= session_cap(&settings) {
                    inbound.patch(|s| {
                        s.last_error = Some("session_cap".into());
                    });
                    drop(stream);
                    continue;
                }
                let worker = inbound.clone();
                let db = db.clone();
                let _ = std::thread::Builder::new()
                    .name("ed2k-upload".into())
                    .spawn(move || {
                        worker.patch(|s| s.connections += 1);
                        log::debug!("ed2k inbound connection from {peer}");
                        serve_conn(worker.clone(), db, identity, stream, peer);
                        worker.patch(|s| {
                            s.connections = s.connections.saturating_sub(1);
                        });
                    });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                inbound.patch(|s| s.last_error = Some(format!("accept: {e}")));
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    log::info!("ed2k inbound service stopped");
}

/// 绑定监听端口。`port = 0` 让系统分配（状态里会显示真实端口）。
fn bind(port: u16) -> Result<(TcpListener, u16), String> {
    let listener =
        TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let actual = listener.local_addr().map_err(|e| e.to_string())?.port();
    Ok((listener, actual))
}

/// 一个入站会话的协议状态。
struct Session {
    user_hash: Option<[u8; 16]>,
    file: Option<SharedFile>,
    /// 已占上传槽（只有占槽后才发数据）。
    active: bool,
    /// 尚未写进信用表的字节。
    pending_credits: u64,
}

fn serve_conn(
    inbound: Arc<Inbound>,
    db: Arc<Mutex<Connection>>,
    identity: [u8; 16],
    stream: TcpStream,
    _peer: SocketAddr,
) {
    let mut conn = match Conn::from_stream(stream, SESSION_READ_TIMEOUT) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut session = Session {
        user_hash: None,
        file: None,
        active: false,
        pending_credits: 0,
    };
    // 排队等待期间用较短读超时轮询，才能周期推送排名/发现对端掉线。
    let poll = RANK_REFRESH.min(Duration::from_secs(5));
    let _ = conn.set_read_timeout(poll);
    let mut last_seen = std::time::Instant::now();

    loop {
        if inbound.stop.load(Ordering::SeqCst) {
            break;
        }
        // 空闲上限：排队的对端可以等很久（eMule 的队列本来就是小时级），
        // 但没握手/没入队却占着连接的要尽快回收。
        let idle_limit = if session.user_hash.is_some() {
            QUEUED_IDLE_LIMIT
        } else {
            HANDSHAKE_IDLE_LIMIT
        };
        if last_seen.elapsed() > idle_limit {
            log::debug!("ed2k inbound session idle timeout");
            break;
        }
        let packet = match conn.recv_idle() {
            Ok(Some(p)) => p,
            // 帧边界无数据：排队中的会话在这里推排名；已占槽的会话继续等。
            Ok(None) => {
                if !session.active {
                    push_rank(&inbound, &mut conn, &mut session);
                }
                continue;
            }
            Err(e) => {
                log::debug!("ed2k inbound read ended: {e}");
                break;
            }
        };
        last_seen = std::time::Instant::now();
        if let Err(e) = dispatch(&mut conn, &inbound, &db, identity, &mut session, packet) {
            log::debug!("ed2k inbound dispatch ended: {e}");
            break;
        }
    }
    // 收尾：释放上传槽 + 把剩余字节写进信用表。
    flush_credits(&db, &mut session);
    if session.active {
        if let Some(hash) = session.user_hash {
            if let Ok(mut queue) = inbound.queue.lock() {
                queue.release(&hash);
            }
        }
    }
    if let Ok(queue) = inbound.queue.lock() {
        inbound.patch(|s| {
            s.active_sessions = queue.active() as u32;
            s.queued_sessions = queue.waiting() as u32;
        });
    }
}

fn dispatch(
    conn: &mut Conn,
    inbound: &Arc<Inbound>,
    db: &Arc<Mutex<Connection>>,
    identity: [u8; 16],
    session: &mut Session,
    packet: Packet,
) -> Result<(), String> {
    match (packet.protocol, packet.opcode) {
        (Protocol::Edonkey, ed2k::HELLO) => {
            let hello = HelloInfo::decode(ed2k::HELLO, &packet.payload)
                .map_err(|e| format!("hello: {e}"))?;
            session.user_hash = Some(hello.user_hash);
            let port = inbound
                .stats
                .lock()
                .ok()
                .and_then(|s| s.listening_port)
                .unwrap_or(0);
            conn.send(
                Protocol::Edonkey,
                ed2k::HELLOANSWER,
                &hello_answer(identity, port),
            )?;
            Ok(())
        }
        (Protocol::Edonkey, ed2k::REQUESTFILENAME) => {
            let Some(want) = hash16(&packet.payload) else {
                return Ok(()); // 载荷长度不对：忽略这条，不断连接
            };
            match lookup(db, &want) {
                Some(file) => {
                    let name = file.name.as_bytes();
                    let len = u16::try_from(name.len()).unwrap_or(u16::MAX);
                    let mut body = want.to_vec();
                    body.extend_from_slice(&len.to_le_bytes());
                    body.extend_from_slice(&name[..len as usize]);
                    session.file = Some(file);
                    conn.send(Protocol::Edonkey, ed2k::REQFILENAMEANSWER, &body)?;
                }
                None => {
                    session.file = None;
                    send_no_file(conn, &want)?;
                }
            }
            Ok(())
        }
        (Protocol::Edonkey, ed2k::SETREQFILEID) => {
            let Some(want) = hash16(&packet.payload) else {
                return Ok(());
            };
            match session
                .file
                .clone()
                .filter(|f| f.md4 == want)
                .or_else(|| lookup(db, &want))
            {
                Some(file) => {
                    let status = FileStatus::complete(want, file.size);
                    session.file = Some(file);
                    conn.send(Protocol::Edonkey, ed2k::FILESTATUS, &status.encode())?;
                }
                None => {
                    session.file = None;
                    send_no_file(conn, &want)?;
                }
            }
            Ok(())
        }
        (Protocol::Edonkey, ed2k::HASHSETREQUEST) => {
            let Some(want) = hash16(&packet.payload) else {
                return Ok(());
            };
            let Some(file) = session
                .file
                .clone()
                .filter(|f| f.md4 == want)
                .or_else(|| lookup(db, &want))
            else {
                send_no_file(conn, &want)?;
                return Ok(());
            };
            match part_hashes(db, &file) {
                Some(parts) => {
                    let mut body = want.to_vec();
                    let count = u16::try_from(parts.len()).unwrap_or(u16::MAX);
                    body.extend_from_slice(&count.to_le_bytes());
                    for p in parts.iter().take(count as usize) {
                        body.extend_from_slice(p);
                    }
                    session.file = Some(file);
                    conn.send(Protocol::Edonkey, ed2k::HASHSETANSWER, &body)?;
                }
                None => {
                    // 文件读不了（被删/被替换成别的长度）：如实回答"没有"。
                    send_no_file(conn, &want)?;
                }
            }
            Ok(())
        }
        (Protocol::Edonkey, ed2k::STARTUPLOADREQ) => {
            let Some(want) = hash16(&packet.payload) else {
                return Ok(());
            };
            let Some(file) = session
                .file
                .clone()
                .filter(|f| f.md4 == want)
                .or_else(|| lookup(db, &want))
            else {
                send_no_file(conn, &want)?;
                return Ok(());
            };
            session.file = Some(file);
            let Some(user_hash) = session.user_hash else {
                return Ok(()); // 没握手就要求上传：忽略
            };
            let ratio = credit_ratio(db, &user_hash);
            // 首次入队（等待时长从 0 开始）；已在队列里的不重置等待时间。
            // `enqueue` 返回 None = 队列满 → 不假装接受，直接结束这个会话。
            let queued = inbound.queue.lock().ok().and_then(|mut queue| {
                if queue.is_waiting(&user_hash) || queue.is_active(&user_hash) {
                    Some(())
                } else {
                    queue
                        .enqueue(user_hash, 0, ratio, inbound.file_priority)
                        .map(|_| ())
                }
            });
            match queued {
                // 入队成功后统一交给 push_rank 决定"立刻接受"还是"报排名等"。
                Some(()) => {
                    push_rank(inbound, conn, session);
                    Ok(())
                }
                None => Err("ed2k_upload_queue_full".into()),
            }
        }
        (Protocol::Edonkey, ed2k::REQUESTPARTS) | (Protocol::Emule, emule::REQUESTPARTS_I64) => {
            if !session.active {
                inbound.patch(|s| s.rejected_blocks += 1);
                return Ok(());
            }
            let Some(file) = session.file.clone() else {
                return Ok(());
            };
            let request = RequestParts::decode(packet.opcode, &packet.payload)
                .map_err(|e| format!("requestparts: {e}"))?;
            if request.file_hash != file.md4 {
                return Ok(());
            }
            for range in request.ranges {
                let Some((start, end)) = share::request_range(range.start, range.end, file.size)
                else {
                    inbound.patch(|s| s.rejected_blocks += 1);
                    continue;
                };
                let Ok(mut handle) = std::fs::File::open(&file.path) else {
                    inbound.patch(|s| s.rejected_blocks += 1);
                    continue;
                };
                let len = end - start;
                if !inbound
                    .upload
                    .take_until(len, || inbound.stop.load(Ordering::SeqCst))
                {
                    return Ok(());
                }
                let mut data = vec![0u8; len as usize];
                handle
                    .seek(SeekFrom::Start(start))
                    .map_err(|e| format!("seek: {e}"))?;
                handle
                    .read_exact(&mut data)
                    .map_err(|e| format!("read: {e}"))?;
                let part = SendingPart {
                    file_hash: file.md4,
                    start,
                    end,
                    data,
                };
                let (opcode, body) = part.encode();
                conn.send(Protocol::Edonkey, opcode, &body)?;
                session.pending_credits += len;
                inbound.patch(|s| {
                    s.uploaded_bytes += len;
                    s.served_blocks += 1;
                });
                if session.pending_credits >= CREDIT_FLUSH_BYTES {
                    flush_credits(db, session);
                }
            }
            Ok(())
        }
        (Protocol::Edonkey, ed2k::END_OF_DOWNLOAD) | (Protocol::Edonkey, ed2k::CANCELTRANSFER) => {
            flush_credits(db, session);
            if session.active {
                if let Some(hash) = session.user_hash {
                    if let Ok(mut queue) = inbound.queue.lock() {
                        queue.release(&hash);
                    }
                }
                session.active = false;
                inbound.patch(|s| s.active_sessions = s.active_sessions.saturating_sub(1));
            }
            Err("session finished".into()) // 结束这个会话线程
        }
        _ => Ok(()), // 不认识的报文一律跳过（协议要求容忍）
    }
}

fn hash16(payload: &[u8]) -> Option<[u8; 16]> {
    (payload.len() >= 16).then(|| payload[..16].try_into().unwrap())
}

fn send_no_file(conn: &mut Conn, want: &[u8; 16]) -> Result<(), String> {
    conn.send(Protocol::Edonkey, ed2k::FILEREQANSNOFIL, want)
}

/// 共享文件存在性 + 磁盘可读性（长度不符视为不可提供）。
fn lookup(db: &Arc<Mutex<Connection>>, want: &[u8; 16]) -> Option<SharedFile> {
    let conn = db.lock().ok()?;
    let file = share::find(&conn, want).ok().flatten()?;
    share::readable(&file)?;
    Some(file)
}

/// 分片哈希集：先查缓存，未命中就算一次并落库。
fn part_hashes(db: &Arc<Mutex<Connection>>, file: &SharedFile) -> Option<Vec<[u8; 16]>> {
    if let Ok(conn) = db.lock() {
        if let Some(parts) = share::cached_part_hashes(&conn, &file.md4, file.size)
            .ok()
            .flatten()
        {
            return Some(parts);
        }
    }
    // 算哈希要整读文件，不能持锁做（否则数据库在几秒到几十秒内不可用）。
    let (computed_hash, parts) = share::compute_part_hashes(&file.path).ok()?;
    if computed_hash != file.md4 {
        // 文件名对了但内容不是这个哈希：绝不能冒充（这正是"以另一个文件应答"）。
        log::warn!(
            "shared file {} hash mismatch: expected {}, got {}",
            file.path.display(),
            hex(&file.md4),
            hex(&computed_hash)
        );
        return None;
    }
    if parts.len() != part_count(file.size) {
        return None;
    }
    if let Ok(conn) = db.lock() {
        let _ = share::store_part_hashes(&conn, &file.md4, file.size, &parts);
    }
    Some(parts)
}

fn credit_ratio(db: &Arc<Mutex<Connection>>, user_hash: &[u8; 16]) -> f64 {
    let conn = match db.lock() {
        Ok(c) => c,
        Err(_) => return 1.0,
    };
    match credits::load(&conn, user_hash) {
        Ok(Some(record)) => credits::score_ratio(
            record.uploaded_bytes,
            record.downloaded_bytes,
            record.identified,
            false,
        ),
        _ => 1.0,
    }
}

fn flush_credits(db: &Arc<Mutex<Connection>>, session: &mut Session) {
    let bytes = std::mem::take(&mut session.pending_credits);
    if bytes == 0 {
        return;
    }
    let Some(user_hash) = session.user_hash else {
        return;
    };
    if let Ok(conn) = db.lock() {
        if let Err(e) = credits::add_transfer(&conn, &user_hash, bytes, 0) {
            log::warn!("ed2k credit record failed: {e}");
        }
    }
}

fn push_rank(inbound: &Arc<Inbound>, conn: &mut Conn, session: &mut Session) {
    let Some(user_hash) = session.user_hash else {
        return;
    };
    let Ok(mut queue) = inbound.queue.lock() else {
        return;
    };
    // 别的会话的轮询可能已经放行了我：先认这个事实，再发接受。
    if queue.is_active(&user_hash) {
        drop(queue);
        if conn
            .send(Protocol::Edonkey, ed2k::ACCEPTUPLOADREQ, &[])
            .is_ok()
        {
            session.active = true;
            inbound.patch(|s| s.active_sessions += 1);
        }
        return;
    }
    // 只有排在第一且有空槽时才由本会话自己占槽；`grant_next` 返回的一定是我，
    // 否则（排第一的是别人）就把槽留给它的会话去认领。
    if queue.rank(&user_hash) == Some(1) && queue.grant_next() == Some(user_hash) {
        drop(queue);
        if conn
            .send(Protocol::Edonkey, ed2k::ACCEPTUPLOADREQ, &[])
            .is_ok()
        {
            session.active = true;
            inbound.patch(|s| s.active_sessions += 1);
        }
        return;
    }
    if let Some(packet) = queue.ranking_packet(&user_hash) {
        drop(queue);
        let _ = conn.send_packet(&packet);
    }
}

fn hello_answer(identity: [u8; 16], tcp_port: u16) -> Vec<u8> {
    let misc1 = MiscOptions1 {
        // 入站 AICH 应答未实现 → 如实声明 0，避免"声明支持却不回"。
        aich_version: 0,
        unicode: true,
        udp_version: 0,
        data_compression: 0,
        sec_ident: 0,
        source_exchange: 1,
        ext_requests: 0,
        comments: 0,
        peer_cache: false,
        no_view_shared: false,
        multi_packet: false,
        preview: false,
    };
    let misc2 = MiscOptions2 {
        file_ident: false,
        direct_udp_callback: false,
        captcha: false,
        source_exchange2: true,
        requires_crypt: false,
        requests_crypt: false,
        supports_crypt: false,
        ext_multipacket: false,
        large_files: true,
        kad_version: 0,
    };
    let info = HelloInfo {
        user_hash: identity,
        // 我们不知道自己的公网地址（不做 LowID 回连），如实给 0。
        client_id: 0,
        tcp_port,
        tags: vec![
            Tag::short(0x01, TagValue::Str("AIDM".into())),
            Tag::short(0x11, TagValue::Uint(EDONKEYVERSION as u64)),
            Tag::short(0xF9, TagValue::Uint(0)),
            Tag::short(0xFA, TagValue::Uint(misc1.to_u32() as u64)),
            Tag::short(0xFE, TagValue::Uint(misc2.to_u32() as u64)),
            Tag::short(
                0xFB,
                TagValue::Uint(pack_emule_version(0, 1, 0, 0, 0) as u64),
            ),
        ],
        server_ip: 0,
        server_port: 0,
    };
    info.encode(true)
}

fn hex(hash: &[u8; 16]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn_with(kv_pairs: &[(&str, &str)]) -> Connection {
        let conn = aidm_core::open_db(std::path::Path::new(":memory:")).unwrap();
        for (k, v) in kv_pairs {
            kv::set(&conn, k, v).unwrap();
        }
        conn
    }

    #[test]
    fn settings_default_disabled_and_clamp_bad_values() {
        let conn = conn_with(&[]);
        assert_eq!(InboundSettings::load(&conn), InboundSettings::default());
        assert!(!InboundSettings::load(&conn).enabled);
        let conn = conn_with(&[
            (KEY_ENABLED, "true"),
            (KEY_PORT, "0"),
            (KEY_SLOTS, "999"),
            (KEY_MAX_WAITING, "0"),
            (KEY_UPLOAD_KBPS, "abc"),
        ]);
        let loaded = InboundSettings::load(&conn);
        assert!(loaded.enabled);
        assert_eq!(loaded.port, 0);
        assert_eq!(loaded.slots, 16, "槽数上限 16");
        assert_eq!(loaded.max_waiting, 1, "排队下限 1");
        assert_eq!(loaded.upload_kbps, 0, "坏值回落不限速");
    }

    #[test]
    fn hello_answer_declares_port_and_no_aich() {
        let payload = hello_answer([3; 16], 4662);
        let info = HelloInfo::decode(ed2k::HELLOANSWER, &payload).unwrap();
        assert_eq!(info.user_hash, [3; 16]);
        assert_eq!(info.tcp_port, 4662);
        let caps = MiscOptions1::from_u32(info.tag(0xFA).unwrap().as_u64().unwrap() as u32);
        assert_eq!(caps.aich_version, 0, "不能声明未实现的 AICH 应答");
        assert_eq!(caps.data_compression, 0);
    }

    #[test]
    fn session_cap_scales_with_slots() {
        let settings = InboundSettings {
            slots: 1,
            ..InboundSettings::default()
        };
        assert_eq!(session_cap(&settings), 20);
        let settings = InboundSettings {
            slots: 16,
            ..InboundSettings::default()
        };
        assert_eq!(session_cap(&settings), 80);
    }
}
