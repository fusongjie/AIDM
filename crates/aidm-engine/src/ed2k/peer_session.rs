//! eMule 对等 TCP 会话：从一个源下载一个文件（L4）。
//!
//! 按 `docs/emule-peer-protocol-spec.md` §9 的"最小可用子集"实现，并补上
//! **hashset（分片哈希集）**用于逐片校验：
//!
//! ```text
//! connect → OP_HELLO → 收 OP_HELLOANSWER
//!         → OP_REQUESTFILENAME → 收 OP_REQFILENAMEANSWER（文件名）
//!         → OP_HASHSETREQUEST(0x51) → 收 OP_HASHSETANSWER(0x52)（分片哈希集）
//!         → （分片数 > 1 时）OP_SETREQFILEID → 收 OP_FILESTATUS（分片位图）
//!         → OP_STARTUPLOADREQ → 收 OP_QUEUERANKING* → 收 OP_ACCEPTUPLOADREQ
//!         → 循环 OP_REQUESTPARTS / 收 OP_SENDINGPART
//!         → OP_END_OF_DOWNLOAD
//! ```
//!
//! ## 校验策略
//!
//! 1. **hashset 自洽**：拿到分片哈希后先验证 `MD4(各分片哈希拼接) == 文件哈希`，
//!    不自洽说明对端给的哈希集是假的 → 直接放弃这个源。
//! 2. **逐片校验**：每片收满即用其哈希集条目校验，失败就清空该片重下（规范做法）。
//! 3. **整文件兜底**：收尾统一确认尺寸并用整文件 eD2k 哈希校验；
//!    不一致则报错，不做"假装成功"。
//!
//! 进度、暂停/取消、写盘定位与 HTTP 路径保持一致；差别是 eD2k 的完整性单位是**分片**
//! （9,728,000 字节）而不是字节区间。

use std::io::{Read, Seek, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

use aidm_core::ed2k::peer::{
    self, decode_answer_sources2, ed2k, emule, pack_emule_version, part_count, AichAnswer,
    AichRequest, FileStatus, HelloInfo, MiscOptions1, MiscOptions2, PartRange, Protocol,
    QueueRanking, RequestParts, SendingPart, Tag, TagValue, EDONKEYVERSION, EMBLOCKSIZE, PARTSIZE,
};
use aidm_core::ed2k::{self as ed2k_core, Flavor};

use super::wire::Conn;

/// 会话参数。
pub struct PeerSessionCfg<'a> {
    /// 与服务器登录共用、在配置目录内持久化的客户端身份。
    pub user_hash: [u8; 16],
    /// 源地址。
    pub addr: SocketAddr,
    /// 目标文件的 eD2k 哈希。
    pub file_hash: [u8; 16],
    /// 文件总长（来自链接或服务器）。
    pub file_size: u64,
    /// 落盘路径（已有完整片经过哈希校验后复用）。
    pub target: &'a Path,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    /// 上层停止条件（暂停/取消）。
    pub stop: &'a dyn Fn() -> bool,
    /// **可信的** AICH 根哈希（来自 `ed2k://…|h=BASE32|/` 链接）。
    ///
    /// `None` 就没有 AICH：没有可信根时恢复树无法验证，而"用对端自己给的根去验证
    /// 对端自己的数据"等于自我确认。eMule 在这种情况下靠多个来源互相印证
    /// （`CAICHUntrustedHash::AddSigningIP` 的签名 IP 计数）来建立信任，
    /// 本实现尚未做那一层，因此宁可不做块级恢复（退回整片重下的既有行为）。
    pub aich_root: Option<[u8; 20]>,
}

/// 会话结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDownload {
    /// 已验证续传片与本次收到的不重叠字节数，不等于稀疏文件的长度。
    pub written: u64,
    /// 完成了的分片数。
    pub parts_done: usize,
    /// 总分片数。
    pub parts_total: usize,
    /// 因校验失败重下的分片次数。
    pub corrupt_parts: usize,
    /// 对端给的文件名（可能为空）。
    pub peer_file_name: Option<String>,
    /// 对端给的队列排名（最后一条 QUEUERANKING）。
    pub queue_rank: Option<u16>,
    /// 是否拿到了分片哈希集（决定校验层级）。
    pub has_hashset: bool,
    /// 通过 AICH 块级恢复重下的 180 KiB 块数（0 表示没走到这条路）。
    pub aich_recovered_blocks: usize,
    /// 是否被上层要求停止。
    pub stopped: bool,
}

impl PeerDownload {
    /// 是否整份下完（按分片计）。
    pub fn is_complete(&self) -> bool {
        self.parts_total > 0 && self.parts_done == self.parts_total
    }
}

/// eMule 每次最多接受三个 180 KiB 请求块；分片仅用于完整性校验。
const MAX_PARALLEL_BLOCKS: usize = 3;
const MAX_CORRUPT_RETRIES: usize = 3;
/// 同一个分片最多做几次 AICH 块级恢复；用不上就退回整片重下。
const MAX_AICH_RETRIES: usize = 2;
/// 入队等待上限：超过就放弃这个源，让上层换源。
const QUEUE_WAIT_LIMIT: Duration = Duration::from_secs(120);
/// 已经供数的源可能暂时停发；帧边界无数据不等于连接已经断开。
const TRANSFER_IDLE_LIMIT: Duration = Duration::from_secs(60);

pub(super) struct ReadyPeer {
    pub conn: Conn,
    pub part_hashes: Option<Vec<[u8; 16]>>,
    pub parts_available: Vec<bool>,
    pub peer_file_name: Option<String>,
    pub queue_rank: Option<u16>,
    /// 对端声明支持 AICH（`CT_EMULE_MISCOOPTIONS1` 的 aich_version ≥ 1）。
    pub aich_supported: bool,
}

/// 共享的握手/入队阶段；多源协调器复用相同的协议路径。
pub(super) fn connect_ready_peer(
    cfg: &PeerSessionCfg<'_>,
    mut on_queue: impl FnMut(Option<u16>),
    mut on_connected: impl FnMut(&Conn) -> Result<(), String>,
) -> Result<ReadyPeer, String> {
    let total_parts = part_count(cfg.file_size).max(1);
    if (cfg.stop)() {
        return Err("ed2k_stopped".into());
    }
    let mut peer = Conn::connect(cfg.addr, cfg.connect_timeout, cfg.read_timeout)?;
    on_connected(&peer)?;

    // 1) 握手
    peer.send(
        Protocol::Edonkey,
        ed2k::HELLO,
        &hello_payload_with_hash(false, cfg.user_hash),
    )?;
    let ans = peer
        .wait_for(ed2k::HELLOANSWER, cfg.read_timeout)
        .map_err(|e| format!("ed2k_hello_wait: {e}"))?;
    let remote = HelloInfo::decode(ed2k::HELLOANSWER, &ans.payload)
        .map_err(|e| format!("ed2k_hello: {e}"))?;
    // 对端的 AICH 版本：只有对端也支持时才会应答 OP_AICHREQUEST。
    let aich_supported = remote
        .tag(0xFA)
        .and_then(|t| t.as_u64())
        .map(|v| MiscOptions1::from_u32(v as u32).aich_version > 0)
        .unwrap_or(false);

    // 2) 文件名
    peer.send(Protocol::Edonkey, ed2k::REQUESTFILENAME, &cfg.file_hash)?;
    // 经典 eMule 对已经撤销共享的文件可能不回复 REQUESTFILENAME，
    // SETREQFILEID 会明确回复 FNF；正常源则并行返回位图。
    if total_parts > 1 {
        peer.send(Protocol::Edonkey, ed2k::SETREQFILEID, &cfg.file_hash)?;
    }
    let mut peer_file_name = None;
    let mut parts_available: Option<Vec<bool>> = None;
    let deadline = Instant::now() + cfg.read_timeout;
    while peer_file_name.is_none() {
        if (cfg.stop)() {
            return Err("ed2k_stopped".into());
        }
        if Instant::now() > deadline {
            return Err("ed2k_filename_timeout".into());
        }
        let p = peer
            .recv()
            .map_err(|e| format!("ed2k_filename_wait: {e}"))?;
        match (p.protocol, p.opcode) {
            (Protocol::Edonkey, ed2k::REQFILENAMEANSWER) => {
                let mut r = Parser::new(&p.payload);
                if r.hash16()? != cfg.file_hash {
                    return Err("ed2k_filename_wrong_file".into());
                }
                peer_file_name = Some(String::from_utf8_lossy(r.short_bytes()?).into_owned());
            }
            (Protocol::Edonkey, ed2k::FILEREQANSNOFIL) => return Err("ed2k_peer_no_file".into()),
            (Protocol::Edonkey, ed2k::FILESTATUS) => {
                parts_available = Some(parse_file_status(&p.payload, total_parts, &cfg.file_hash)?);
            }
            _ => {}
        }
    }

    // 3) 分片哈希集（>1 片才有意义）：先自洽校验，再用于逐片校验
    let mut part_hashes: Option<Vec<[u8; 16]>> = None;
    if total_parts > 1 {
        peer.send(Protocol::Edonkey, ed2k::HASHSETREQUEST, &cfg.file_hash)?;
        let deadline = Instant::now() + cfg.read_timeout;
        loop {
            if (cfg.stop)() {
                return Err("ed2k_stopped".into());
            }
            if Instant::now() > deadline {
                break; // 拿不到就退化为整文件校验
            }
            match peer.recv() {
                Ok(p) if p.protocol == Protocol::Edonkey && p.opcode == ed2k::HASHSETANSWER => {
                    match parse_hashset(&p.payload, total_parts, &cfg.file_hash) {
                        Ok(hs) => {
                            part_hashes = Some(hs);
                        }
                        Err(e) => return Err(e), // 哈希集不自洽 → 这个源不可信
                    }
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }

    // 4) 分片位图（>1 片且还没拿到时）
    if total_parts > 1 && parts_available.is_none() {
        peer.send(Protocol::Edonkey, ed2k::SETREQFILEID, &cfg.file_hash)?;
        let deadline = Instant::now() + cfg.read_timeout;
        while parts_available.is_none() {
            if (cfg.stop)() {
                return Err("ed2k_stopped".into());
            }
            if Instant::now() > deadline {
                break;
            }
            match peer.recv() {
                Ok(p) if p.protocol == Protocol::Edonkey && p.opcode == ed2k::FILESTATUS => {
                    parts_available =
                        Some(parse_file_status(&p.payload, total_parts, &cfg.file_hash)?);
                }
                Ok(p) if p.opcode == ed2k::FILEREQANSNOFIL => {
                    return Err("ed2k_peer_no_file".into())
                }
                Ok(_) => continue,
                Err(e) => return Err(e),
            }
        }
    }
    let parts_available = parts_available.unwrap_or_else(|| vec![true; total_parts]);

    // 5) 入队
    peer.send(Protocol::Edonkey, ed2k::STARTUPLOADREQ, &cfg.file_hash)?;
    let mut queue_rank = None;
    on_queue(queue_rank);
    let accept_deadline = Instant::now() + QUEUE_WAIT_LIMIT;
    peer.set_read_timeout(cfg.read_timeout.min(Duration::from_secs(1)))?;
    loop {
        if (cfg.stop)() {
            let _ = peer.send(Protocol::Edonkey, ed2k::END_OF_DOWNLOAD, &cfg.file_hash);
            return Err("ed2k_stopped".into());
        }
        if Instant::now() > accept_deadline {
            return Err("ed2k_queue_timeout".into());
        }
        let Some(p) = peer
            .recv_idle()
            .map_err(|e| format!("ed2k_queue_wait rank={queue_rank:?}: {e}"))?
        else {
            continue; // 只在完整帧边界超时继续排队，不吞掉 EOF/半包。
        };
        match (p.protocol, p.opcode) {
            (Protocol::Edonkey, ed2k::ACCEPTUPLOADREQ) => break,
            (Protocol::Emule, emule::QUEUERANKING) => {
                queue_rank = Some(
                    QueueRanking::decode(&p.payload)
                        .map_err(|e| format!("ed2k_rank: {e}"))?
                        .rank,
                );
                on_queue(queue_rank);
            }
            (Protocol::Edonkey, ed2k::QUEUERANK) => {
                queue_rank =
                    Some(peer::decode_queue_rank(&p.payload).map_err(|e| e.to_string())? as u16);
                on_queue(queue_rank);
            }
            (Protocol::Edonkey, ed2k::FILEREQANSNOFIL) => return Err("ed2k_peer_no_file".into()),
            _ => {}
        }
    }
    peer.set_read_timeout(cfg.read_timeout)?;

    Ok(ReadyPeer {
        conn: peer,
        part_hashes,
        parts_available,
        peer_file_name,
        queue_rank,
        aich_supported,
    })
}

/// 连接一个源并下载。失败返回可读原因（上层据此换源或进入"等待源"）。
pub fn download_from_peer(
    cfg: &PeerSessionCfg<'_>,
    mut on_progress: impl FnMut(u64),
) -> Result<PeerDownload, String> {
    let total_parts = part_count(cfg.file_size).max(1);
    let part_len = |i: usize| -> u64 {
        cfg.file_size
            .saturating_sub(i as u64 * PARTSIZE)
            .min(PARTSIZE)
    };
    let ReadyPeer {
        conn: mut peer,
        part_hashes,
        parts_available,
        peer_file_name,
        queue_rank,
        aich_supported,
    } = connect_ready_peer(cfg, |_| {}, |_| Ok(()))?;

    // 6) 传输
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(cfg.target)
        .map_err(|e| format!("ed2k_open_file: {e}"))?;

    let mut done = vec![false; total_parts];
    let mut received: Vec<Vec<PartRange>> = vec![Vec::new(); total_parts];
    let mut written = 0u64;
    // 文件长度不能证明覆盖范围：定位写会留下洞，旧文件也可能属于别的任务。
    // 只复用经过本文件哈希/自洽 hashset 验证的完整片，未验证的尾片重新请求。
    let existing_len = file
        .metadata()
        .map_err(|e| format!("ed2k_stat: {e}"))?
        .len();
    let existing_whole_valid = part_hashes.is_none()
        && existing_len == cfg.file_size
        && verify_whole_file(cfg.target, &cfg.file_hash)?;
    for i in 0..total_parts {
        let start = i as u64 * PARTSIZE;
        let end = start + part_len(i);
        let expected = part_hashes.as_ref().and_then(|hs| hs.get(i));
        let valid = existing_whole_valid
            || (existing_len >= end
                && expected.is_some_and(|want| {
                    read_back_and_hash(&mut file, i, part_len(i))
                        .map(|got| &got == want)
                        .unwrap_or(false)
                }));
        if valid {
            done[i] = true;
            received[i].push(PartRange { start, end });
            written += part_len(i);
        }
    }
    on_progress(written);

    let mut corrupt_parts = 0usize;
    let mut corrupt_retries = vec![0usize; total_parts];
    let mut aich_tries = vec![0usize; total_parts];
    let mut aich_recovered_blocks = 0usize;
    let mut inflight: Vec<PartRange> = Vec::new();
    let mut stopped = false;
    // 对端可能把一次请求拆成多条 SENDINGPART：按片累积，不假设一次收满
    let mut out_of_part_reqs = 0usize;
    let mut last_payload = Instant::now();

    while done.iter().any(|d| !d) {
        if (cfg.stop)() {
            stopped = true;
            break;
        }
        let mut requested = Vec::new();
        while inflight.len() < MAX_PARALLEL_BLOCKS {
            let next = (0..total_parts)
                .filter(|i| !done[*i] && parts_available.get(*i).copied().unwrap_or(false))
                .find_map(|i| {
                    next_block(
                        i as u64 * PARTSIZE,
                        i as u64 * PARTSIZE + part_len(i),
                        &received[i],
                        &inflight,
                    )
                });
            if let Some(range) = next {
                requested.push(range.clone());
                inflight.push(range);
            } else {
                break;
            }
        }
        if !requested.is_empty() {
            let rp = RequestParts {
                file_hash: cfg.file_hash,
                ranges: requested,
            };
            let (protocol, op, payload) = encode_request_parts(&rp)?;
            peer.send(protocol, op, &payload)?;
        }
        if inflight.is_empty() {
            return Err("ed2k_no_available_parts".into());
        }

        if last_payload.elapsed() > TRANSFER_IDLE_LIMIT.max(cfg.read_timeout) {
            return Err("ed2k_transfer_idle_timeout".into());
        }
        let Some(p) = peer
            .recv_idle()
            .map_err(|e| format!("ed2k_transfer_wait: {e}"))?
        else {
            continue;
        };
        match (p.protocol, p.opcode) {
            (Protocol::Edonkey, ed2k::SENDINGPART) | (Protocol::Emule, emule::SENDINGPART_I64) => {
                let sp = SendingPart::decode(p.opcode, &p.payload)
                    .map_err(|e| format!("ed2k_sendingpart: {e}"))?;
                if sp.file_hash != cfg.file_hash {
                    continue;
                }
                let idx = (sp.start / PARTSIZE) as usize;
                if idx >= total_parts
                    || sp.end > cfg.file_size
                    || (sp.end - 1) / PARTSIZE != sp.start / PARTSIZE
                {
                    return Err("ed2k_sendingpart_out_of_bounds".into());
                }
                let range = PartRange {
                    start: sp.start,
                    end: sp.end,
                };
                // 重复包不增加进度，也不能覆写已经验证通过的内容。
                if covers(&received[idx], &range) {
                    continue;
                }
                if !inflight
                    .iter()
                    .any(|r| r.start <= sp.start && r.end >= sp.end)
                {
                    return Err("ed2k_sendingpart_unsolicited".into());
                }
                file.seek(std::io::SeekFrom::Start(sp.start))
                    .map_err(|e| format!("ed2k_seek: {e}"))?;
                file.write_all(&sp.data)
                    .map_err(|e| format!("ed2k_write: {e}"))?;
                let before = covered_len(&received[idx]);
                insert_range(&mut received[idx], range);
                last_payload = Instant::now();
                written += covered_len(&received[idx]) - before;
                on_progress(written);
                inflight.retain(|r| !covers(&received[idx], r));
                out_of_part_reqs = 0;

                if covered_len(&received[idx]) == part_len(idx) {
                    let ok = match &part_hashes {
                        Some(hs) => match hs.get(idx) {
                            Some(want) => read_back_and_hash(&mut file, idx, part_len(idx))
                                .map(|h| &h == want)?,
                            None => false, // 哈希集缺这一片：当作校验失败，重下
                        },
                        None => true, // 没有哈希集：留到收尾做整文件校验
                    };
                    if ok {
                        done[idx] = true;
                    } else {
                        corrupt_parts += 1;
                        corrupt_retries[idx] += 1;
                        if corrupt_retries[idx] > MAX_CORRUPT_RETRIES {
                            return Err("ed2k_corrupt_part_retries_exhausted".into());
                        }
                        // 先试 AICH 块级重下：只丢损坏的 180 KiB 块，而不是整片 9.7 MB。
                        let mut recovered = false;
                        if aich_tries[idx] < MAX_AICH_RETRIES {
                            aich_tries[idx] += 1;
                            let before = covered_len(&received[idx]);
                            match try_aich_recovery(
                                &mut peer,
                                cfg,
                                aich_supported,
                                &mut file,
                                idx,
                                &mut received[idx],
                            ) {
                                Ok(Some(blocks)) => {
                                    aich_recovered_blocks += blocks;
                                    let after = covered_len(&received[idx]);
                                    written = written.saturating_sub(before - after);
                                    // 恢复期间对端若同时塞了数据包，会被等待循环丢掉；
                                    // 在途请求一律作废，让未覆盖的块（含被丢掉的那些）重新可请求，
                                    // 否则它们会永远挂在 inflight 里造成静默停摆。
                                    inflight.clear();
                                    on_progress(written);
                                    recovered = true;
                                }
                                Ok(None) => {}
                                Err(e) => return Err(e),
                            }
                        }
                        if !recovered {
                            written -= covered_len(&received[idx]);
                            received[idx].clear();
                            on_progress(written);
                        }
                    }
                }
            }
            (Protocol::Edonkey, ed2k::OUTOFPARTREQS) => {
                // 对端暂时没有这些分片：清空在途，稍后重试；连续多次则放弃这个源
                out_of_part_reqs += 1;
                inflight.clear();
                if out_of_part_reqs > 8 {
                    return Err("ed2k_peer_out_of_parts".into());
                }
            }
            (Protocol::Edonkey, ed2k::FILEREQANSNOFIL) => return Err("ed2k_peer_no_file".into()),
            _ => {}
        }
    }

    file.flush().map_err(|e| format!("ed2k_flush: {e}"))?;
    let _ = peer.send(Protocol::Edonkey, ed2k::END_OF_DOWNLOAD, &cfg.file_hash);

    let out = PeerDownload {
        written,
        parts_done: done.iter().filter(|d| **d).count(),
        parts_total: total_parts,
        corrupt_parts,
        peer_file_name,
        queue_rank,
        has_hashset: part_hashes.is_some(),
        aich_recovered_blocks,
        stopped,
    };

    // 收尾确认文件长度和整文件哈希；旧文件多余尾部不能进入交付内容。
    if !out.stopped && out.is_complete() {
        file.set_len(cfg.file_size)
            .map_err(|e| format!("ed2k_truncate: {e}"))?;
        let ok = verify_whole_file(cfg.target, &cfg.file_hash)?;
        if !ok {
            return Err("ed2k_hash_mismatch".into());
        }
    }
    // 有哈希集时逐片已校验；再确认片数收满
    if !out.stopped && !out.is_complete() {
        return Err("ed2k_incomplete".into());
    }
    Ok(out)
}

/// 请求的协议字节必须与 32/64 位 opcode 同时切换。
fn encode_request_parts(rp: &RequestParts) -> Result<(Protocol, u8, Vec<u8>), String> {
    let protocol = if rp.uses_i64() {
        Protocol::Emule
    } else {
        Protocol::Edonkey
    };
    let (opcode, payload) = rp.encode().map_err(|e| format!("ed2k_reqparts: {e}"))?;
    Ok((protocol, opcode, payload))
}

fn covered_len(ranges: &[PartRange]) -> u64 {
    ranges.iter().map(PartRange::len).sum()
}

fn covers(ranges: &[PartRange], range: &PartRange) -> bool {
    ranges
        .iter()
        .any(|r| r.start <= range.start && r.end >= range.end)
}

/// 合并覆盖区间，重复/交叠包只计算一次。
fn insert_range(ranges: &mut Vec<PartRange>, range: PartRange) {
    ranges.push(range);
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<PartRange> = Vec::with_capacity(ranges.len());
    for r in ranges.drain(..) {
        if let Some(last) = merged.last_mut() {
            if r.start <= last.end {
                last.end = last.end.max(r.end);
                continue;
            }
        }
        merged.push(r);
    }
    *ranges = merged;
}

/// 找出未覆盖、未在途的首个块；块绝不跨越 eD2k 分片边界。
fn next_block(
    start: u64,
    end: u64,
    received: &[PartRange],
    inflight: &[PartRange],
) -> Option<PartRange> {
    let mut occupied = received.to_vec();
    for range in inflight {
        insert_range(&mut occupied, range.clone());
    }
    let mut cursor = start;
    for range in occupied {
        if range.end <= cursor {
            continue;
        }
        if range.start >= end {
            break;
        }
        if range.start > cursor {
            return Some(PartRange {
                start: cursor,
                end: (cursor + EMBLOCKSIZE).min(range.start).min(end),
            });
        }
        cursor = cursor.max(range.end);
    }
    (cursor < end).then(|| PartRange {
        start: cursor,
        end: (cursor + EMBLOCKSIZE).min(end),
    })
}

/// 从文件读回某一片并算 MD4。
pub(super) fn read_back_and_hash(
    file: &mut std::fs::File,
    idx: usize,
    len: u64,
) -> Result<[u8; 16], String> {
    file.seek(std::io::SeekFrom::Start(idx as u64 * PARTSIZE))
        .map_err(|e| format!("ed2k_seek: {e}"))?;
    let mut buf = vec![0u8; len as usize];
    file.read_exact(&mut buf)
        .map_err(|e| format!("ed2k_read_back: {e}"))?;
    Ok(md4_of(&buf))
}

/// 一片被分配分片的下载结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct PartOutcome {
    /// 该分片是否已通过分片哈希校验（没有哈希集时为 false：由协调器收尾整文件校验）。
    pub verified: bool,
    /// 通过 AICH 块级恢复重下的 180 KiB 块数。
    pub aich_recovered_blocks: usize,
}

/// 一条已入队连接下载协调器独占分配的校验片。不同 peer 不会同时写同一片。
/// `progress(覆盖字节, 实收字节)` 把续传/重试覆盖量与网络流量分开。
/// `on_xs` 接收对端源交换应答里的可直连地址（畸形应答丢弃，不断开传输）。
pub(super) fn download_assigned_part(
    peer: &mut Conn,
    cfg: &PeerSessionCfg<'_>,
    file: &mut std::fs::File,
    idx: usize,
    expected_hash: Option<[u8; 16]>,
    aich_supported: bool,
    mut should_abort: impl FnMut() -> bool,
    mut progress: impl FnMut(u64, u64),
    mut on_xs: impl FnMut(Vec<SocketAddr>),
) -> Result<PartOutcome, String> {
    let start = idx as u64 * PARTSIZE;
    let len = cfg.file_size.saturating_sub(start).min(PARTSIZE);
    let end = start + len;
    let mut covered = Vec::new();
    let mut inflight: Vec<PartRange> = Vec::new();
    let mut corrupt_retries = 0;
    let mut aich_tries = 0;
    let mut aich_recovered_blocks = 0;
    let mut empty_replies = 0;
    let mut last_payload = Instant::now();
    loop {
        if (cfg.stop)() {
            return Err("ed2k_stopped".into());
        }
        if should_abort() {
            return Err("ed2k_peer_low_score".into());
        }
        let mut ranges = Vec::new();
        while inflight.len() < MAX_PARALLEL_BLOCKS {
            let Some(range) = next_block(start, end, &covered, &inflight) else {
                break;
            };
            ranges.push(range.clone());
            inflight.push(range);
        }
        if !ranges.is_empty() {
            let request = RequestParts {
                file_hash: cfg.file_hash,
                ranges,
            };
            let (protocol, op, payload) = encode_request_parts(&request)?;
            peer.send(protocol, op, &payload)?;
        }
        if last_payload.elapsed() > TRANSFER_IDLE_LIMIT.max(cfg.read_timeout) {
            return Err("ed2k_transfer_idle_timeout".into());
        }
        let Some(packet) = peer
            .recv_idle()
            .map_err(|e| format!("ed2k_transfer_wait: {e}"))?
        else {
            continue;
        };
        match (packet.protocol, packet.opcode) {
            (Protocol::Edonkey, ed2k::SENDINGPART) | (Protocol::Emule, emule::SENDINGPART_I64) => {
                let part = SendingPart::decode(packet.opcode, &packet.payload)
                    .map_err(|e| format!("ed2k_sendingpart: {e}"))?;
                if part.file_hash != cfg.file_hash {
                    continue;
                }
                if part.start < start || part.end > end {
                    return Err("ed2k_sendingpart_out_of_assignment".into());
                }
                let range = PartRange {
                    start: part.start,
                    end: part.end,
                };
                if covers(&covered, &range) {
                    progress(covered_len(&covered), part.data.len() as u64);
                    continue;
                }
                if !inflight
                    .iter()
                    .any(|r| r.start <= range.start && range.end <= r.end)
                {
                    return Err("ed2k_sendingpart_unsolicited".into());
                }
                file.seek(std::io::SeekFrom::Start(part.start))
                    .map_err(|e| format!("ed2k_seek: {e}"))?;
                file.write_all(&part.data)
                    .map_err(|e| format!("ed2k_write: {e}"))?;
                insert_range(&mut covered, range);
                inflight.retain(|r| !covers(&covered, r));
                last_payload = Instant::now();
                empty_replies = 0;
                progress(covered_len(&covered), part.data.len() as u64);
                if covered_len(&covered) == len {
                    let valid = match expected_hash {
                        Some(want) => read_back_and_hash(file, idx, len)? == want,
                        None => true, // 协调器最终执行整文件哈希，不能据此宣称已验证。
                    };
                    if valid {
                        return Ok(PartOutcome {
                            verified: expected_hash.is_some(),
                            aich_recovered_blocks,
                        });
                    }
                    corrupt_retries += 1;
                    if corrupt_retries > MAX_CORRUPT_RETRIES {
                        return Err("ed2k_corrupt_part_retries_exhausted".into());
                    }
                    // 先试 AICH 块级重下：只丢损坏的 180 KiB 块
                    let mut recovered = false;
                    if aich_tries < MAX_AICH_RETRIES {
                        aich_tries += 1;
                        match try_aich_recovery(peer, cfg, aich_supported, file, idx, &mut covered)
                        {
                            Ok(Some(blocks)) => {
                                aich_recovered_blocks += blocks;
                                // 恢复期间丢掉的在途数据要重新请求，见多分片循环里的同款注释。
                                inflight.clear();
                                progress(covered_len(&covered), 0);
                                recovered = true;
                            }
                            Ok(None) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    if !recovered {
                        covered.clear();
                        inflight.clear();
                        progress(0, 0);
                    }
                }
            }
            (Protocol::Edonkey, ed2k::OUTOFPARTREQS) => {
                empty_replies += 1;
                if empty_replies > 8 {
                    return Err("ed2k_peer_out_of_parts".into());
                }
                inflight.clear();
            }
            (Protocol::Emule, emule::ANSWERSOURCES2) => {
                // 对端主动或应请求给的源：只收可直连地址，畸形包丢弃，不断开传输。
                // 入站的 0x83 请求暂不回答（见握手声明注释）。
                if let Ok(list) = decode_answer_sources2(&packet.payload, &cfg.file_hash) {
                    let addrs: Vec<SocketAddr> =
                        list.iter().filter_map(|s| s.socket_addr()).collect();
                    if !addrs.is_empty() {
                        on_xs(addrs);
                    }
                }
            }
            (Protocol::Edonkey, ed2k::FILEREQANSNOFIL) => return Err("ed2k_peer_no_file".into()),
            _ => {}
        }
    }
}

/// 分片 MD4（统一走 core 的实现，引擎不直接依赖加密库）。
fn md4_of(data: &[u8]) -> [u8; 16] {
    ed2k_core::hash::md4(data)
}

/// 从覆盖集合里扣掉 `[start, end)`（绝对偏移）：相交的区间被拆成两半。
///
/// AICH 恢复就靠这一步：**只把损坏块从"已收"里去掉**，请求循环随后自然只会重下这几块。
fn subtract_range(ranges: &mut Vec<PartRange>, start: u64, end: u64) {
    let mut out: Vec<PartRange> = Vec::with_capacity(ranges.len() + 2);
    for r in ranges.drain(..) {
        if r.end <= start || r.start >= end {
            out.push(r);
            continue;
        }
        if r.start < start {
            out.push(PartRange {
                start: r.start,
                end: start,
            });
        }
        if r.end > end {
            out.push(PartRange {
                start: end,
                end: r.end,
            });
        }
    }
    *ranges = out;
}

/// 读回某分片的本地字节（AICH 需要按 180 KiB 块比对）。
fn read_part_bytes(file: &mut std::fs::File, idx: usize, len: u64) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len as usize];
    file.seek(std::io::SeekFrom::Start(idx as u64 * PARTSIZE))
        .map_err(|e| format!("ed2k_seek: {e}"))?;
    file.read_exact(&mut buf)
        .map_err(|e| format!("ed2k_aich_read: {e}"))?;
    Ok(buf)
}

/// AICH 块级恢复：向**同一个源**索取该分片的恢复数据，定位并扣掉损坏的 180 KiB 块。
///
/// 返回 `Ok(Some(损坏块数))` 表示已精确定位（覆盖集合已被扣掉这些块，调用方不必清整片）；
/// `Ok(None)` 表示这次用不上（没有可信根、对端不支持、对端失败、树不自洽、本地数据与
/// 可信叶哈希一致），调用方按既有行为整片重下。
///
/// **MD4 仍是最终闸门**：这里只决定"重下多少"，不决定"是否接受"。
fn try_aich_recovery(
    peer: &mut Conn,
    cfg: &PeerSessionCfg<'_>,
    aich_supported: bool,
    file: &mut std::fs::File,
    idx: usize,
    covered: &mut Vec<PartRange>,
) -> Result<Option<usize>, String> {
    let Some(master) = cfg.aich_root else {
        return Ok(None);
    };
    if !aich_supported {
        return Ok(None);
    }
    let start = idx as u64 * PARTSIZE;
    let len = cfg.file_size.saturating_sub(start).min(PARTSIZE);
    if len == 0 {
        return Ok(None);
    }
    let request = AichRequest {
        file_hash: cfg.file_hash,
        part: idx as u16,
        master_hash: master,
    };
    peer.send(Protocol::Emule, emule::AICHREQUEST, &request.encode())?;

    let deadline = Instant::now() + cfg.read_timeout;
    let hashes = loop {
        if (cfg.stop)() {
            return Err("ed2k_stopped".into());
        }
        if Instant::now() > deadline {
            return Ok(None); // 对端不应答：退回整片重下
        }
        let Some(packet) = peer
            .recv_idle()
            .map_err(|e| format!("ed2k_aich_wait: {e}"))?
        else {
            continue;
        };
        match (packet.protocol, packet.opcode) {
            (Protocol::Emule, emule::AICHANSWER) => match AichAnswer::decode(&packet.payload) {
                // 定长 16 字节 = 对端没有该文件/哈希集/根不匹配。
                Ok(AichAnswer::Failed { .. }) => return Ok(None),
                Ok(AichAnswer::Recovery {
                    request: echo,
                    hashes,
                }) => {
                    if echo.file_hash != cfg.file_hash
                        || echo.part != idx as u16
                        || echo.master_hash != master
                    {
                        return Ok(None); // 回显对不上：不是回答我们这次的请求
                    }
                    break hashes;
                }
                Err(_) => return Ok(None), // 畸形应答不能当成"这片刻坏了"
            },
            // 恢复期间对端仍可能塞数据包/源交换；不把它当作恢复应答，继续等。
            _ => continue,
        }
    };
    if hashes.is_empty() {
        return Ok(None);
    }
    let recovery: Vec<ed2k_core::aich::RecoveryHash> = hashes
        .iter()
        .map(|h| ed2k_core::aich::RecoveryHash {
            identifier: h.identifier,
            wide: h.wide_identifier,
            hash: h.hash,
        })
        .collect();
    let blocks =
        match ed2k_core::aich::recover_part_blocks(cfg.file_size, start, len, master, &recovery) {
            Ok(b) => b,
            // 树不自洽/根不匹配/块不齐：这个源给的恢复数据不可用。
            Err(_) => return Ok(None),
        };
    let local = read_part_bytes(file, idx, len)?;
    let corrupt = match ed2k_core::aich::corrupt_blocks(&local, &blocks) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    if corrupt.is_empty() {
        // 本地数据与可信叶哈希一致，但分片 MD4 不符：问题不在块内容（对端哈希集可疑），
        // 不能靠块级重下来"修好"，退回整片重下。
        return Ok(None);
    }
    for block in &corrupt {
        let at = *block as u64 * EMBLOCKSIZE;
        if at >= len {
            return Ok(None);
        }
        subtract_range(covered, start + at, start + (at + EMBLOCKSIZE).min(len));
    }
    Ok(Some(corrupt.len()))
}

/// 整文件 eD2k 哈希校验。
pub fn verify_whole_file(target: &Path, file_hash: &[u8; 16]) -> Result<bool, String> {
    let f = std::fs::File::open(target).map_err(|e| format!("ed2k_open: {e}"))?;
    let d = ed2k_core::hash::hash_reader(Flavor::Official, std::io::BufReader::new(f))
        .map_err(|e| format!("ed2k_hash: {e}"))?;
    Ok(&d.file == file_hash)
}

/// 解析 `OP_FILESTATUS`；"完整源"展开成全部可用。
fn parse_file_status(
    payload: &[u8],
    total_parts: usize,
    file_hash: &[u8; 16],
) -> Result<Vec<bool>, String> {
    let fs = FileStatus::decode(payload).map_err(|e| format!("ed2k_filestatus: {e}"))?;
    if &fs.file_hash != file_hash {
        return Err("ed2k_filestatus_wrong_file".into());
    }
    if fs.complete_source {
        return Ok(vec![true; total_parts]);
    }
    let mut v = fs.parts;
    v.resize(total_parts, false);
    Ok(v)
}

/// 解析 `OP_HASHSETANSWER`：`hash16 + count(u16) + count×hash16`。
///
/// 并且**先自洽校验**：`MD4(各分片哈希拼接) == 文件哈希`。不自洽说明对端在骗人。
fn parse_hashset(
    payload: &[u8],
    total_parts: usize,
    file_hash: &[u8; 16],
) -> Result<Vec<[u8; 16]>, String> {
    let mut r = Parser::new(payload);
    let hash = r.hash16()?;
    if &hash != file_hash {
        return Err("ed2k_hashset_wrong_file".into());
    }
    let count = u16::from_le_bytes(r.take(2)?.try_into().unwrap()) as usize;
    if count == 0 || count > 4096 {
        return Err("ed2k_hashset_bad_count".into());
    }
    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        parts.push(r.hash16()?);
    }
    // 自洽性判据分两种（eD2k 规则本身就有这个分叉，别漏）：
    // - 只有 1 片：文件哈希 **就等于** 该片的 MD4（不再套一层）
    // - 多片：文件哈希 = MD4(各片哈希拼接)
    let consistent = if parts.len() == 1 {
        parts[0] == *file_hash
    } else {
        let mut concat = Vec::with_capacity(parts.len() * 16);
        for p in &parts {
            concat.extend_from_slice(p);
        }
        ed2k_core::hash::md4(&concat) == *file_hash
    };
    if !consistent {
        return Err("ed2k_hashset_mismatch".into());
    }
    // 片数比我们推算的少 → 说明**本地的文件大小不对**（哈希集本身是自洽的），
    // 这种情况必须报错而不是补零：补零会让后面按错的分片边界去校验。
    if parts.len() < total_parts {
        return Err("ed2k_hashset_short".into());
    }
    // 片数更多则以对端为准（对端才是权威）。取用时用 .get() 兜底，不假设长度相等。
    Ok(parts)
}

/// 构造 `OP_HELLO` 载荷。
///
/// 我们是纯下载端：不监听 TCP/UDP，因此端口与 `client_id` 都给 0；
/// `SupportsCryptLayer` **如实声明为 false**（未实现加密层）。
fn hello_payload(is_answer: bool) -> Vec<u8> {
    hello_payload_with_hash(is_answer, client_hash())
}

fn hello_payload_with_hash(is_answer: bool, user_hash: [u8; 16]) -> Vec<u8> {
    let misc1 = MiscOptions1 {
        aich_version: 0,
        unicode: true,
        udp_version: 0,
        data_compression: 0,
        sec_ident: 0,
        // v1 源交换已废弃（我们不实现 0x81/0x82），但 eMule 系客户端以它判断
        // "对方懂不懂源交换"；v2 真正的门控是 MISCOPTIONS2 的 source_exchange2 位。
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
        // 我们实现源交换 v2（0x83/0x84）才置位；对端发来的 0x83 请求暂不回答，
        // 只向对端请求（eMule 不因此惩罚排队，信用只看上传字节）。
        source_exchange2: true,
        requires_crypt: false,
        requests_crypt: false,
        supports_crypt: false,
        ext_multipacket: false,
        large_files: true,
        kad_version: 0,
    };
    let info = HelloInfo {
        user_hash,
        client_id: 0,
        tcp_port: 0,
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
    info.encode(is_answer)
}

/// 本进程的客户端哈希（eMule 特征位必须正确，否则对端不当作 eMule 客户端）。
pub fn client_hash() -> [u8; 16] {
    use std::sync::OnceLock;
    static HASH: OnceLock<[u8; 16]> = OnceLock::new();
    *HASH.get_or_init(|| {
        let nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let pid = std::process::id() as u64;
        let mut seed = [0u8; 16];
        for (i, b) in seed.iter_mut().enumerate() {
            let v = nano
                .wrapping_mul(6364136223846793005)
                .wrapping_add(pid.wrapping_mul(1442695040888963407))
                .wrapping_add(i as u64 * 2654435761);
            *b = (v >> ((i % 8) * 8)) as u8;
        }
        peer::make_emule_hash(seed)
    })
}

/// 探活：连接一个对等点并完成 HELLO 交换，返回对端信息。
///
/// 用途：① 判断一个源是否在线（避免把连接超时耗尽在死源上）；
/// ② 作为字节序/协议正确性的**真实网络证据**（能收到 HELLOANSWER 就说明我们的
/// 报文与客户哈希特征被真实 eMule 客户端接受了）。
pub fn probe_peer(
    addr: SocketAddr,
    connect_timeout: Duration,
    read_timeout: Duration,
) -> Result<HelloInfo, String> {
    let mut conn = Conn::connect(addr, connect_timeout, read_timeout)?;
    conn.send(Protocol::Edonkey, ed2k::HELLO, &hello_payload(false))?;
    let ans = conn.wait_for(ed2k::HELLOANSWER, read_timeout)?;
    HelloInfo::decode(ed2k::HELLOANSWER, &ans.payload).map_err(|e| format!("ed2k_hello: {e}"))
}

/// 解析 `host:port` 形式的源地址。
pub fn resolve_source(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("ed2k_resolve: {e}"))?
        .next()
        .ok_or_else(|| "ed2k_resolve: empty".to_string())
}

/// 极简解析器（与编解码层的 `Reader` 同语义，错误类型为 String）。
struct Parser<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Parser<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, o: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.o + n > self.b.len() {
            return Err("ed2k_parse_truncated".into());
        }
        let s = &self.b[self.o..self.o + n];
        self.o += n;
        Ok(s)
    }

    fn hash16(&mut self) -> Result<[u8; 16], String> {
        Ok(self.take(16)?.try_into().unwrap())
    }

    fn short_bytes(&mut self) -> Result<&'a [u8], String> {
        let n = u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hashset_and_rejects_inconsistent_one() {
        // 造一个两分片的文件哈希：MD4(h0 || h1)
        let h0 = md4_of(b"part-zero");
        let h1 = md4_of(b"part-one");
        let mut concat = Vec::new();
        concat.extend_from_slice(&h0);
        concat.extend_from_slice(&h1);
        let root: [u8; 16] = ed2k_core::hash::md4(&concat);

        let mut payload = root.to_vec();
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(&h0);
        payload.extend_from_slice(&h1);

        let hs = parse_hashset(&payload, 2, &root).unwrap();
        assert_eq!(hs, vec![h0, h1]);

        // 只给 1 条哈希但文件哈希是 2 片算出来的 → 先被"自洽性"拦下
        // （一致性检查在长度检查之前，这是刻意的：对 2 片文件给 1 条哈希本身就不自洽）
        let mut short = root.to_vec();
        short.extend_from_slice(&1u16.to_le_bytes());
        short.extend_from_slice(&h0);
        assert_eq!(
            parse_hashset(&short, 2, &root).unwrap_err(),
            "ed2k_hashset_mismatch"
        );

        // 真正能触发 hashset_short 的情形：哈希集自洽（root == MD4(h0)），
        // 但我们自己推算的分片数更多 —— 说明**本地的文件大小是错的**。
        let mut lone = h0.to_vec();
        lone.extend_from_slice(&1u16.to_le_bytes());
        lone.extend_from_slice(&h0);
        assert_eq!(parse_hashset(&lone, 1, &h0).unwrap().len(), 1);
        assert_eq!(
            parse_hashset(&lone, 3, &h0).unwrap_err(),
            "ed2k_hashset_short"
        );

        // 自洽性不符 → 拒绝（对端给了假的哈希集）
        let mut lying = root.to_vec();
        lying.extend_from_slice(&2u16.to_le_bytes());
        lying.extend_from_slice(&[0xAA; 16]);
        lying.extend_from_slice(&[0xBB; 16]);
        assert_eq!(
            parse_hashset(&lying, 2, &root).unwrap_err(),
            "ed2k_hashset_mismatch"
        );

        // 哈希对应的是别的文件 → 拒绝
        assert_eq!(
            parse_hashset(&payload, 2, &[0u8; 16]).unwrap_err(),
            "ed2k_hashset_wrong_file"
        );

        // 计数为 0 / 过大 → 拒绝
        let mut zero = root.to_vec();
        zero.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(
            parse_hashset(&zero, 2, &root).unwrap_err(),
            "ed2k_hashset_bad_count"
        );
    }

    #[test]
    fn hello_payload_is_wellformed() {
        let hello = hello_payload(false);
        let answer = hello_payload(true);
        assert_eq!(answer.len(), hello.len() - 1, "两者只差 UserHash 长度字节");
        // 能被自己的解码器读回，且标签齐全
        let a = HelloInfo::decode(ed2k::HELLO, &hello).unwrap();
        let b = HelloInfo::decode(ed2k::HELLOANSWER, &answer).unwrap();
        assert_eq!(a, b);
        for id in [0x01u8, 0x11, 0xF9, 0xFA, 0xFE, 0xFB] {
            assert!(a.tag(id).is_some(), "缺少标签 0x{id:02X}");
        }
        assert_eq!(a.tag(0x11).and_then(|v| v.as_u64()), Some(0x3C));
        // 客户端哈希必须是 eMule 特征
        assert!(peer::is_emule_hash(&a.user_hash));
        // 加密能力必须如实声明为不支持
        let m2 = MiscOptions2::from_u32(a.tag(0xFE).and_then(|v| v.as_u64()).unwrap() as u32);
        assert!(!m2.supports_crypt && !m2.requests_crypt && !m2.requires_crypt);
        assert!(m2.large_files, "应声明支持大文件");
        assert!(!m2.file_ident && m2.kad_version == 0);
        // 源交换 v2（0x83/0x84）已实现才置位；v1 字段是废弃的兼容标记
        assert!(m2.source_exchange2, "应声明支持源交换 v2");
        let m1 = MiscOptions1::from_u32(a.tag(0xFA).and_then(|v| v.as_u64()).unwrap() as u32);
        assert_eq!(m1.data_compression, 0);
        assert_eq!(
            m1.ext_requests, 0,
            "文件请求仅发送 hash，不声明附加大小字段"
        );
        assert_eq!(m1.aich_version, 0);
        assert!(!m1.multi_packet && !m1.peer_cache);
        assert_eq!(m1.source_exchange, 1, "v1 废弃字段置兼容标记，见握手注释");
    }

    #[test]
    fn request_protocol_tracks_offsets_at_four_gib_boundary() {
        for (start, end, want_proto, want_opcode) in [
            (0, EMBLOCKSIZE, Protocol::Edonkey, ed2k::REQUESTPARTS),
            (
                u32::MAX as u64 - 1,
                u32::MAX as u64,
                Protocol::Edonkey,
                ed2k::REQUESTPARTS,
            ),
            (
                u32::MAX as u64,
                u32::MAX as u64 + 1,
                Protocol::Emule,
                emule::REQUESTPARTS_I64,
            ),
            (
                1u64 << 32,
                (1u64 << 32) + EMBLOCKSIZE,
                Protocol::Emule,
                emule::REQUESTPARTS_I64,
            ),
        ] {
            let request = RequestParts {
                file_hash: [7; 16],
                ranges: vec![PartRange { start, end }],
            };
            let (protocol, opcode, payload) = encode_request_parts(&request).unwrap();
            assert_eq!((protocol, opcode), (want_proto, want_opcode));
            assert_eq!(RequestParts::decode(opcode, &payload).unwrap(), request);
        }
    }
}
