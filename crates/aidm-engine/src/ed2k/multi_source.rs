//! 多源协调：中央独占分配 9.7 MB 校验片，一条连接内最多三个 180 KiB 块。
//! 每个地址最多建立一条连接，源发现和下载并行，未完成片断线后重新分配。
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Condvar, Mutex,
};
use std::time::{Duration, Instant};

use aidm_core::ed2k::peer::{ed2k, emule, encode_request_sources2, part_count, Protocol, PARTSIZE};

use super::peer_session::{
    connect_ready_peer, download_assigned_part, read_back_and_hash, PeerSessionCfg,
};

/// 全局连接许可必须原子申请；received 只统计实传 payload，不含磁盘复用。
pub trait TransferHooks: Sync {
    fn try_acquire_connection(&self) -> bool;
    fn release_connection(&self);
    fn received(&self, bytes: u64);
}

#[derive(Debug, Clone)]
pub enum PeerEvent {
    Connecting {
        addr: SocketAddr,
    },
    Queued {
        addr: SocketAddr,
        rank: Option<u16>,
    },
    Receiving {
        addr: SocketAddr,
        network_bytes: u64,
    },
    Finished {
        addr: SocketAddr,
        network_bytes: u64,
        error: Option<String>,
    },
}

#[derive(Clone)]
pub struct MultiSourceCfg<'a> {
    pub user_hash: [u8; 16],
    pub file_hash: [u8; 16],
    pub file_size: u64,
    pub target: &'a Path,
    /// 任务硬上限，运行时限定在 1..=32。
    pub max_connections: usize,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    /// 只限制等待增量源的时间；已开始的传输不被此期限截断，最多 60 秒。
    pub discovery_timeout: Duration,
    pub stop: &'a (dyn Fn() -> bool + Sync),
    pub hooks: &'a dyn TransferHooks,
    pub on_event: &'a (dyn Fn(PeerEvent) + Sync),
    /// 源交换（XS）发现的新地址出口；None 则不请求也不收集。
    /// 由调用方负责去重、落库与合法性过滤。
    pub xs_sources: Option<mpsc::Sender<SocketAddr>>,
    /// 外部查源中继已结束（查源线程退出）。调用方若用额外线程
    /// 向 `sources` 通道补增量源（如 XS 转发），通道断开信号不可靠，
    /// 调度器以此标志做快速退出；None 则沿用原有断开/时限语义。
    pub feed_done: Option<Arc<AtomicBool>>,
    /// **可信的** AICH 根哈希（`ed2k://…|h=BASE32|/`）。`None` 则不做块级恢复，
    /// 分片 MD4 失败仍然整片重下（理由见 `PeerSessionCfg::aich_root`）。
    pub aich_root: Option<[u8; 20]>,
    /// **分片归属**：`Some` 时本池只负责过滤出的分片，用于两个池并发写同一文件。
    /// `None`（默认）= 独占整个文件（历史行为）。
    pub part_filter: Option<Arc<PartFilter>>,
    /// 私有池的完成交接：私有池先完成自己的份额时，等待编排层停掉标准池并
    /// 打开 `all`，再继续接管标准池剩余的分片。标准池不使用。
    pub expansion: Option<Arc<ExpandSignal>>,
    /// 归属观测回调：认领、释放、完成或阶段变化时以最新快照回调。
    ///
    /// 只读：实现不得连接、重试、换源或写下载文件。`None` 时零成本
    /// （不构造快照、不改任何下载行为），因此 legacy 路径不受影响。
    pub on_ownership: Option<&'a (dyn Fn(&[PartOwnership]) + Sync)>,
    /// 号段耗尽时的续领回调：参数是希望的数量，返回 `(start, count)`。
    ///
    /// 返回 `None` 表示无法续领（例如数据库不可用）。调用方必须**停止认领并报错**，
    /// 不能退回墙钟基数——那就不是“持久身份”了。
    pub claim_refill: Option<Arc<dyn Fn(u64) -> Option<(u64, u64)> + Send + Sync>>,
    /// 本号段的容量（与 `claim_base` 一起决定终点）。
    pub claim_reserve: u64,
    /// 领取序号起点（由调用方从任务级号段分配）。
    ///
    /// C1 要求：跨重启不依赖墙钟基数。号段来自 `download_runtime.next_claim_seq`
    /// （事务内自增），所以同一 `assignment_id` 不会在重启后指向另一次归属。
    /// 每次新建池（含兜底轮）必须拿一个新号段，否则两池重叠。
    pub claim_base: u64,
}

/// 私有池完成自己的固定份额后，不立刻退出；由编排层决定是否把剩余全部
/// 分片交给它。这样快源不会被固定 filter 提前送走。
#[derive(Debug, Default)]
pub struct ExpandSignal {
    /// 私有池已下完自己的初始份额，等待交接。
    pub ready: AtomicBool,
    /// 允许私有池认领全部剩余分片。
    pub all: AtomicBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolProgress {
    pub verifying: bool,
    /// 校验复用片 + 当前独占片的不重叠覆盖量；换源时可回退，绝不能累加作流量。
    pub done: u64,
    pub verified_parts: usize,
    pub total_parts: usize,
    /// 逐切片状态：0=pending，1=active，2=done，3=checking。
    pub slices: Vec<u8>,
    pub active_peers: usize,
    pub transferring_peers: usize,
    pub queued_peers: usize,
    /// 通过 AICH 块级恢复重下的 180 KiB 块数（累计）。
    pub aich_recovered_blocks: usize,
    /// 归属版本号：认领、释放、完成或阶段变化时递增。
    ///
    /// 消费方只需比较它决定是否重新读 [`PartOwnership`]，不必每拍重算全部分片，
    /// 也不会因为“按源数推算”而把没有归属的片当成有人在下载。
    pub ownership_rev: u64,
}

/// 单个原生的归属观测：哪个对端正在负责哪个 part 区间。
///
/// 这是“某片正在下载”之外的第二个事实：**谁**在下。没有它，界面只能把源数
/// 除以切片数去凑一组看起来像真的通路（文档第 2 节、第 6.3 节明确禁止）。
/// 任何一项未知都保留 `None`，不按源数推算。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartOwnership {
    /// 原生 part 序号（eD2k 固定 9728000 字节，末块单独算）。
    pub part_index: usize,
    /// 资源坐标系中的左闭右开范围。
    pub span_start: u64,
    pub span_end: u64,
    /// 池内 owner 序号；属于原生命名空间，**不是** `source_id`。
    pub owner: Option<usize>,
    /// 对端地址；未建立连接或未知时为 `None`。
    pub peer_addr: Option<SocketAddr>,
    /// 归属生命周期序号：同一 part 被重新认领或换源后变值。
    ///
    /// “同一次分配刷新保持 ID；释放后重领、换源则生成新 ID”靠它实现：
    /// 只靠 part 序号无法区分“同一个源持续下”与“换了个源接着下”。
    pub claim_seq: u64,
    /// `pending` / `connecting` / `queued` / `idle` / `receiving` / `done` / `checking`。
    pub state: &'static str,
    /// 该片校验是否已通过。
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiDownload {
    pub written: u64,
    pub verified_parts: usize,
    pub total_parts: usize,
    pub stopped: bool,
    /// 通过 AICH 块级恢复重下的 180 KiB 块数（0 表示没用到块级恢复）。
    pub aich_recovered_blocks: usize,
}
impl MultiDownload {
    pub fn is_complete(&self) -> bool {
        !self.stopped && self.total_parts > 0 && self.verified_parts == self.total_parts
    }
}

#[derive(Clone, Copy)]
enum PartState {
    Pending,
    Owned(usize),
    Done(bool),
    /// 已落盘、正在被后台线程读回校验。**对 peer 不可见**（`claim` 只挑 `Pending`），
    /// 所以校验再慢也不会被重复下载，同时也不占用连源/传输的关键路径。
    Checking,
}
struct Part {
    state: PartState,
    received: u64,
    /// 领取序号：每次被重新认领（含释放后重领、换源）时递增。
    ///
    /// “同一次分配刷新保持 ID；释放后重领、换源则生成新 ID”靠它实现：
    /// 只靠 part 序号无法区分“同一个源持续下”与“换了个源接着下”。
    claim_seq: u64,
}
#[derive(Clone, Copy)]
enum Phase {
    Connecting,
    Queued,
    Idle,
    Receiving,
}
struct State {
    parts: Vec<Part>,
    hashes: Option<Vec<[u8; 16]>>,
    existing_len: u64,
    peers: HashMap<usize, Phase>,
    /// owner → 对端地址。
    ///
    /// 原先只有 `peers: owner → Phase` 与 `parts[i] = Owned(owner)`。于是
    /// “某片正在下载”与“哪个源负责哪个区间”是两回事：投影到界面时 owner 一丢，
    /// 就只能按源数平均推算。这里把对端地址与 owner 绑定，供只读观测使用。
    /// 地址属于受控内部信息，不直接进公共视图。
    owner_peer: HashMap<usize, SocketAddr>,
    streams: HashMap<usize, TcpStream>,
    /// 归属版本号：认领、释放、完成与阶段变化时递增。
    ownership_rev: u64,
    /// 下一个可用领取序号（从 `claim_base` 起递增）。
    claim_next: u64,
    /// 通过 AICH 块级恢复重下的 180 KiB 块数（池内累计，仅用于进度/审计）。
    aich_recovered_blocks: usize,
}
struct Pool {
    state: Mutex<State>,
    changed: Condvar,
    file_size: u64,
    /// 分片归属过滤器（None = 独占整个文件，历史行为）。
    filter: Option<Arc<PartFilter>>,
    started: Instant,
    /// 本池领取序号的基础偏移（来自任务级号段）。
    ///
    /// 只用于诊断：真正的分配水位在 `State::claim_next`，上界在 `claim_end`。
    #[allow(dead_code)]
    claim_base: u64,
    /// 号段上界（不含）；耗尽后靠 `claim_refill` 续领。
    claim_end: std::sync::atomic::AtomicU64,
    /// 续领回调；`None` 表示不允许续领（耗尽即报错）。
    claim_refill: Option<Arc<dyn Fn(u64) -> Option<(u64, u64)> + Send + Sync>>,
}
#[derive(Debug, PartialEq, Eq)]
enum Claim {
    Part(usize, Option<[u8; 16]>),
    Wait,
    Finished,
    /// 号段已耗尽且续领失败：不能再冒充持久身份，必须让上层报错。
    Exhausted,
}

/// 分片归属过滤器：两个下载池**并发**写同一个分片文件时，各自只碰自己那一份。
///
/// - `None`（默认）= 不过滤：单池独占整个文件，行为与历史完全一致。
/// - `Some(f)`：池只在 `f.contains(idx)` 为真的分片上 claim/assign；启动时的
///   "读回已有数据并校验"也只认这些分片，否则会把对方负责的片读成半片、
///   误判为失败后重复下载（甚至两边同时写同一片）。
///
/// 分片编号与 `PARTSIZE`/`part_count` 同一坐标系，两个池一致
/// （都来自 `aidm_core::ed2k::peer`，见本文件 `PARTSIZE` 引入与 `private_pool` 同名常量）。
#[derive(Debug, Clone)]
pub struct PartFilter {
    mask: Arc<Vec<bool>>,
    owned: usize,
    /// 初始份额完成后，允许本池接管全部剩余分片（只对私有池开启）。
    all: Arc<AtomicBool>,
}

impl PartFilter {
    /// 取模分配：本池负责 `idx % stride == offset` 的分片。
    ///
    /// `stride` 至少按 1 处理；`offset >= stride` 得到空集合（该池立即无事可做）。
    pub fn modulo(total: usize, stride: usize, offset: usize) -> Self {
        let stride = stride.max(1);
        let mut mask = vec![false; total];
        let mut owned = 0usize;
        if offset < stride {
            let mut idx = offset;
            while idx < total {
                mask[idx] = true;
                owned += 1;
                idx += stride;
            }
        }
        Self {
            mask: Arc::new(mask),
            owned,
            all: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 从显式索引构造（越界索引忽略，重复只算一次）。
    pub fn from_indices(total: usize, indices: impl IntoIterator<Item = usize>) -> Self {
        let mut mask = vec![false; total];
        let mut owned = 0usize;
        for idx in indices {
            if idx < total && !mask[idx] {
                mask[idx] = true;
                owned += 1;
            }
        }
        Self {
            mask: Arc::new(mask),
            owned,
            all: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 该分片是否归本池负责。越界一律 false。
    #[inline]
    pub fn contains(&self, idx: usize) -> bool {
        self.all.load(Ordering::Relaxed) || self.mask.get(idx).copied().unwrap_or(false)
    }

    /// 初始份额完成后允许接管全部剩余分片。
    pub fn allow_all(&self) {
        self.all.store(true, Ordering::Release);
    }

    pub fn all_allowed(&self) -> bool {
        self.all.load(Ordering::Acquire)
    }

    /// 本池负责的分片数。
    pub fn owned(&self) -> usize {
        self.owned
    }

    pub fn is_empty(&self) -> bool {
        self.owned == 0
    }

    /// 分片总数（与 `part_count(file_size)` 一致）。
    pub fn total(&self) -> usize {
        self.mask.len()
    }
}

impl Pool {
    fn length(&self, idx: usize) -> u64 {
        self.file_size
            .saturating_sub(idx as u64 * PARTSIZE)
            .min(PARTSIZE)
    }
    fn progress(&self) -> PoolProgress {
        let s = self.state.lock().unwrap();
        PoolProgress {
            verifying: false,
            done: s.parts.iter().map(|p| p.received).sum(),
            verified_parts: s
                .parts
                .iter()
                .filter(|p| matches!(p.state, PartState::Done(true)))
                .count(),
            total_parts: s.parts.len(),
            slices: s
                .parts
                .iter()
                .map(|p| match p.state {
                    PartState::Pending | PartState::Done(false) => 0,
                    PartState::Owned(_) => 1,
                    PartState::Done(true) => 2,
                    PartState::Checking => 3,
                })
                .collect(),
            active_peers: s.peers.len(),
            transferring_peers: s
                .peers
                .values()
                .filter(|p| matches!(p, Phase::Receiving))
                .count(),
            queued_peers: s
                .peers
                .values()
                .filter(|p| matches!(p, Phase::Queued))
                .count(),
            aich_recovered_blocks: s.aich_recovered_blocks,
            ownership_rev: s.ownership_rev,
        }
    }

    /// 归属观测：每个分片当前由哪个 owner / 对端负责。
    ///
    /// 只在调用方需要时构造（`ownership_rev` 变化后），不参与每拍进度计算。
    /// 未建立连接时 `peer_addr` 为 `None`，从不用“源数”推算。
    fn ownership(&self) -> Vec<PartOwnership> {
        let s = self.state.lock().unwrap();
        let mut out = Vec::with_capacity(s.parts.len());
        for (idx, part) in s.parts.iter().enumerate() {
            let (owner, state, verified) = match part.state {
                PartState::Pending => (None, "pending", false),
                PartState::Owned(o) => (Some(o), phase_state(s.peers.get(&o)), false),
                PartState::Done(true) => (None, "done", true),
                // 校验失败的片会重新待分配，不能一直显示为已完成。
                PartState::Done(false) => (None, "pending", false),
                PartState::Checking => (None, "checking", false),
            };
            let span_start = idx as u64 * PARTSIZE;
            out.push(PartOwnership {
                part_index: idx,
                span_start,
                span_end: span_start + self.length(idx),
                owner,
                peer_addr: owner.and_then(|o| s.owner_peer.get(&o).copied()),
                claim_seq: part.claim_seq,
                state,
                verified,
            });
        }
        out
    }
    /// 本池当前平均速率，用于标准池慢源的相对阈值。
    fn average_bps(&self) -> f64 {
        let s = self.state.lock().unwrap();
        let done: u64 = s.parts.iter().map(|p| p.received).sum();
        let secs = self.started.elapsed().as_secs_f64();
        if secs > 0.0 {
            done as f64 / secs
        } else {
            0.0
        }
    }

    /// 本池是否负责该分片（无过滤器 = 全部）。
    #[inline]
    fn owns(&self, idx: usize) -> bool {
        self.filter.as_ref().is_none_or(|f| f.contains(idx))
    }
    /// 本池负责的分片是否都已校验完成。
    /// 有过滤器时这**不等于**整文件完成：整包判定由编排层在两池 join 后统一做。
    fn complete(&self) -> bool {
        let s = self.state.lock().unwrap();
        s.parts
            .iter()
            .enumerate()
            .filter(|(i, _)| self.owns(*i))
            .all(|(_, p)| matches!(p.state, PartState::Done(_)))
    }
    fn hashes(
        &self,
        hashes: Option<Vec<[u8; 16]>>,
        file: &mut File,
        stop: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        let Some(hashes) = hashes else {
            return Ok(());
        };
        let mut s = self.state.lock().unwrap();
        if s.hashes.is_some() {
            return Ok(());
        }
        for (idx, want) in hashes.iter().take(s.parts.len()).enumerate() {
            if stop() {
                return Err("ed2k_stopped".into());
            }
            if !self.owns(idx) {
                continue;
            }
            let len = self.length(idx);
            // 只有未分配片和已结束片可读回，不能与仍有写入的 owner 竞态。
            // `Checking` 片由后台校验线程独占，这里不能碰（否则两边各读一半）。
            if matches!(
                s.parts[idx].state,
                PartState::Owned(_) | PartState::Checking
            ) {
                continue;
            }
            if s.existing_len >= idx as u64 * PARTSIZE + len
                || matches!(s.parts[idx].state, PartState::Done(_))
            {
                if read_back_and_hash(file, idx, len)? == *want {
                    s.parts[idx].state = PartState::Done(true);
                    s.parts[idx].received = len;
                } else {
                    s.parts[idx].state = PartState::Pending;
                    s.parts[idx].received = 0;
                }
            }
        }
        s.hashes = Some(hashes);
        self.changed.notify_all();
        Ok(())
    }

    /// 把「已完整落盘」的分片标成 `Checking`，交给后台线程校验。
    ///
    /// **必须在任何 peer 启动之前调用**：这一步只做索引运算（微秒级），而真正的
    /// 读回 + MD4 是 O(已下载字节) 的。校验若放在连源之前同步做，
    /// "暂停后恢复"要先花 3~12 秒重读已下好的片才开始连源（延迟随已下载数据量
    /// 线性增长）。标成 `Checking` 后 peer 既不会重复下载它们，也不会被校验挡住
    /// 连源与传输。
    fn begin_check(&self) {
        let mut s = self.state.lock().unwrap();
        let existing_len = s.existing_len;
        let total = s.parts.len();
        for idx in 0..total {
            if !self.owns(idx) {
                continue;
            }
            let len = self.length(idx);
            if len == 0 {
                continue;
            }
            if existing_len >= idx as u64 * PARTSIZE + len {
                // `received = len`：这些字节**确实在盘上**，进度条不能因为"还没校验"
                // 就先掉回 0（校验在后台进行，完成前也必须立刻计入，
                // 否则恢复瞬间进度会从几 GB 掉到 0）。
                s.parts[idx].state = PartState::Checking;
                s.parts[idx].received = len;
            }
        }
    }

    fn has_checking(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .parts
            .iter()
            .any(|p| matches!(p.state, PartState::Checking))
    }

    /// 拿不到可信哈希集（索引查不到 / 被拒 / 读回失败）时把待校验片放回
    /// `Pending`，交给 peer 重新下载——与"从来没有哈希集"的历史行为一致，
    /// 绝不能把没校验过的片当成已完成。
    fn release_checking(&self) {
        let mut s = self.state.lock().unwrap();
        for p in &mut s.parts {
            if matches!(p.state, PartState::Checking) {
                p.state = PartState::Pending;
                p.received = 0;
            }
        }
        self.changed.notify_all();
    }

    /// 后台读回校验。**全程不持锁做 IO**，所以 peer 的连接 / HELLO / 认领都不受影响。
    fn resolve_checking(
        &self,
        hashes: &[[u8; 16]],
        target: &Path,
        stop: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        {
            let mut s = self.state.lock().unwrap();
            if s.hashes.is_none() {
                s.hashes = Some(hashes.to_vec());
            }
        }
        // 独立只读句柄：主句柄在传输线程手里，且校验期间不能被别人 seek。
        let mut file = OpenOptions::new()
            .read(true)
            .open(target)
            .map_err(|e| format!("ed2k_open_file: {e}"))?;
        let todo: Vec<(usize, [u8; 16])> = {
            let s = self.state.lock().unwrap();
            s.parts
                .iter()
                .enumerate()
                .filter(|(_, p)| matches!(p.state, PartState::Checking))
                .filter_map(|(idx, _)| hashes.get(idx).map(|h| (idx, *h)))
                .collect()
        };
        for (idx, want) in todo {
            if stop() {
                return Err("ed2k_stopped".into());
            }
            let len = self.length(idx);
            let got = read_back_and_hash(&mut file, idx, len)?;
            let mut s = self.state.lock().unwrap();
            if matches!(s.parts[idx].state, PartState::Checking) {
                if got == want {
                    s.parts[idx].state = PartState::Done(true);
                    s.parts[idx].received = len;
                } else {
                    s.parts[idx].state = PartState::Pending;
                    s.parts[idx].received = 0;
                }
            }
            drop(s);
            self.changed.notify_all();
        }
        Ok(())
    }

    /// 号段剩余不足时续领。
    ///
    /// 故意**在 state 锁外**调回调：续领会访问数据库，而 `claim` 持 state 锁，
    /// 两者交叉就会死锁。续领失败时把上界设为当前水位，让 `claim` 返回
    /// `Exhausted`（上层报错），而不是悄悄退回墙钟基数。
    fn top_up_claim(&self) {
        const LOW_WATER: u64 = 8;
        let end = self.claim_end.load(Ordering::Relaxed);
        let next = self.state.lock().unwrap().claim_next;
        if next + LOW_WATER < end {
            return;
        }
        let Some(refill) = &self.claim_refill else {
            return;
        };
        match refill(256) {
            Some((start, count)) if count > 0 => {
                self.state.lock().unwrap().claim_next = start;
                self.claim_end
                    .store(start + count, Ordering::Relaxed);
            }
            _ => {
                // 续领失败：卡住水位，下一次 `claim` 立刻返回 Exhausted。
                self.claim_end.store(next, Ordering::Relaxed);
            }
        }
    }

    fn claim(&self, owner: usize, available: &[bool]) -> Claim {
        let mut s = self.state.lock().unwrap();
        if s.claim_next >= self.claim_end.load(Ordering::Relaxed) {
            // 耗尽：不能拿墙钟基数凑合，让上层续领或报错。
            return Claim::Exhausted;
        }
        if let Some(idx) = s.parts.iter().enumerate().position(|(i, p)| {
            matches!(p.state, PartState::Pending)
                && available.get(i).copied().unwrap_or(false)
                && self.owns(i)
        }) {
            s.parts[idx].state = PartState::Owned(owner);
            s.parts[idx].received = 0;
            s.parts[idx].claim_seq = s.claim_next;
            s.claim_next += 1;
            s.peers.insert(owner, Phase::Idle);
            s.ownership_rev = s.ownership_rev.wrapping_add(1);
            return Claim::Part(idx, s.hashes.as_ref().and_then(|h| h.get(idx)).copied());
        }
        if s.parts.iter().enumerate().any(|(i, p)| {
            matches!(p.state, PartState::Owned(_))
                && available.get(i).copied().unwrap_or(false)
                && self.owns(i)
        }) {
            s.peers.insert(owner, Phase::Idle);
            Claim::Wait
        } else if s
            .parts
            .iter()
            .enumerate()
            .any(|(i, p)| matches!(p.state, PartState::Checking) && self.owns(i))
        {
            // 还有分片在后台读回校验：现在收工会让"校验失败、需要重下"的片没人接。
            // 让连接留在池里等（50ms 一轮），校验结果一出就能立刻认领。
            s.peers.insert(owner, Phase::Idle);
            Claim::Wait
        } else {
            Claim::Finished
        }
    }
    fn update(&self, owner: usize, idx: usize, received: u64) {
        let mut s = self.state.lock().unwrap();
        if matches!(s.parts[idx].state, PartState::Owned(id) if id == owner) {
            s.parts[idx].received = received.min(self.length(idx));
            if !matches!(s.peers.get(&owner), Some(Phase::Receiving)) {
                s.peers.insert(owner, Phase::Receiving);
                // 阶段从排队/空闲变为接收，归属事实发生变化。
                s.ownership_rev = s.ownership_rev.wrapping_add(1);
            }
        }
    }
    fn finish_part(&self, owner: usize, idx: usize, verified: bool) {
        let mut s = self.state.lock().unwrap();
        if matches!(s.parts[idx].state, PartState::Owned(id) if id == owner) {
            s.parts[idx].state = PartState::Done(verified);
            s.parts[idx].received = self.length(idx);
            s.ownership_rev = s.ownership_rev.wrapping_add(1);
        }
        self.changed.notify_all();
    }
    fn finish_peer(&self, owner: usize, stopped: bool) {
        let mut s = self.state.lock().unwrap();
        let mut released = false;
        for p in &mut s.parts {
            if matches!(p.state, PartState::Owned(id) if id == owner) {
                p.state = PartState::Pending;
                released = true;
                if !stopped {
                    p.received = 0;
                }
            }
        }
        s.streams.remove(&owner);
        s.peers.remove(&owner);
        s.owner_peer.remove(&owner);
        if released {
            // 释放归属也必须让观测方知道：否则界面会继续显示一个已经不存在的通路。
            s.ownership_rev = s.ownership_rev.wrapping_add(1);
        }
        self.changed.notify_all();
    }
    fn shutdown(&self) {
        for stream in self.state.lock().unwrap().streams.values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        self.changed.notify_all();
    }
}

/// 兜底领取序号：DB 号段不可用时的退路（进程内单调 + 启动时刻基数）。
///
/// **正常路径不用它**：C1 起，号段由 `download_runtime.next_claim_seq`
/// 在事务内分配，跨重启继续递增。这里只在数据库不可用时避免撞号。
///
/// 单池内递增不够：兜底轮、暂停恢复都会新建池，每个池的局部计数都从 1 开始，
/// 于是同一任务同一 part 可能生成相同的 `...-c1`，把两次不同的归属当成同一次。
/// 基数取进程启动时刻，避免跨重启又从 1 开始。
pub fn fallback_claim_seq() -> u64 {
    use std::sync::OnceLock;

    static SEQ: AtomicU64 = AtomicU64::new(0);
    static BASE: OnceLock<u64> = OnceLock::new();
    let base = *BASE.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_nanos() as u64) & 0xFFFF_FFFF_0000)
            .unwrap_or(0)
            .max(1)
    });
    base + SEQ.fetch_add(1, Ordering::Relaxed)
}

/// 池内阶段 → 观测字符串（未开始时为 `unknown`，不猜）。
fn phase_state(phase: Option<&Phase>) -> &'static str {
    match phase {
        Some(Phase::Connecting) => "connecting",
        Some(Phase::Queued) => "queued",
        Some(Phase::Idle) => "idle",
        Some(Phase::Receiving) => "receiving",
        None => "unknown",
    }
}

struct Permit<'a>(&'a dyn TransferHooks);
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0.release_connection();
    }
}

/// 标准池慢源阈值：低于本池平均速率的 25% 视为慢源。
const SLOW_RELATIVE: f64 = 0.25;

/// 标准池的单源低速观察：分片下载期间按约 1 秒窗口采样。
/// 20 秒后仍低于 1 KiB/s 才中止，避免把刚入队/刚拿到片的慢启动源误杀。
struct SlowWatch {
    started: Instant,
    sample_at: Instant,
    sample_bytes: u64,
    samples: u32,
    total: u64,
    min_bps: f64,
}

impl SlowWatch {
    fn new(min_bps: f64) -> Self {
        let now = Instant::now();
        Self {
            started: now,
            sample_at: now,
            sample_bytes: 0,
            samples: 0,
            total: 0,
            min_bps: min_bps.max(1024.0),
        }
    }

    fn add(&mut self, bytes: u64) {
        self.total = self.total.saturating_add(bytes);
        self.sample_bytes = self.sample_bytes.saturating_add(bytes);
        if self.sample_at.elapsed() >= Duration::from_secs(1) {
            self.samples = self.samples.saturating_add(1);
            self.sample_bytes = 0;
            self.sample_at = Instant::now();
        }
    }

    fn should_abort(&self) -> bool {
        let age = self.started.elapsed();
        if age < Duration::from_secs(20) {
            return false;
        }
        // 完全静默时没有采样窗口；超过观察期仍零字节直接中止。
        if self.total == 0 {
            return true;
        }
        if self.samples < 3 {
            return false;
        }
        // 用累计字节 / 运行时长，避免只看最后一个窗口而被暂停/抖动误导。
        let secs = age.as_secs_f64();
        secs > 0.0 && (self.total as f64 / secs) < self.min_bps
    }
}

fn run_peer(
    cfg: &MultiSourceCfg<'_>,
    pool: &Pool,
    owner: usize,
    addr: SocketAddr,
    wake: &mpsc::Sender<()>,
    network: &mut u64,
) -> Result<(), String> {
    (cfg.on_event)(PeerEvent::Connecting { addr });
    let peer_cfg = PeerSessionCfg {
        user_hash: cfg.user_hash,
        addr,
        file_hash: cfg.file_hash,
        file_size: cfg.file_size,
        target: cfg.target,
        connect_timeout: cfg.connect_timeout,
        read_timeout: cfg.read_timeout,
        stop: cfg.stop,
        aich_root: cfg.aich_root,
    };
    let mut ready = connect_ready_peer(
        &peer_cfg,
        |rank| {
            let mut s = pool.state.lock().unwrap();
            s.peers.insert(owner, Phase::Queued);
            s.owner_peer.insert(owner, addr);
            drop(s);
            (cfg.on_event)(PeerEvent::Queued { addr, rank });
            let _ = wake.send(());
        },
        |conn| {
            pool.state
                .lock()
                .unwrap()
                .streams
                .insert(owner, conn.interrupt_handle()?);
            if (cfg.stop)() || pool.complete() {
                pool.shutdown();
            }
            Ok(())
        },
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(cfg.target)
        .map_err(|e| format!("ed2k_open_file: {e}"))?;
    let hashes = if part_count(cfg.file_size) == 1 {
        Some(vec![cfg.file_hash])
    } else {
        ready.part_hashes.clone()
    };
    pool.hashes(hashes, &mut file, cfg.stop)?;
    let _ = wake.send(());
    // 源交换：入队成功后问一次（best-effort；对端不回或拒绝不影响传输）。
    // 发包失败同样不致命——本连接照常用，只是少一条来源通道。
    if cfg.xs_sources.is_some() {
        let _ = ready.conn.send(
            Protocol::Emule,
            emule::REQUESTSOURCES2,
            &encode_request_sources2(&cfg.file_hash),
        );
    }
    loop {
        if (cfg.stop)() {
            return Err("ed2k_stopped".into());
        }
        // 号段快要见底时先续领：续领在锁外调数据库，避免与 `claim` 的 state 锁互堵。
        pool.top_up_claim();
        match pool.claim(owner, &ready.parts_available) {
            Claim::Exhausted => {
                // 明确报错，不退回墙钟基数：那就不再是持久身份。
                return Err("ed2k_claim_seq_exhausted".into());
            }
            Claim::Part(idx, expected) => {
                let expected = expected
                    .or_else(|| ready.part_hashes.as_ref().and_then(|h| h.get(idx)).copied());
                let min_bps = (pool.average_bps() * SLOW_RELATIVE).max(1024.0);
                let slow = Arc::new(Mutex::new(SlowWatch::new(min_bps)));
                let slow_abort = slow.clone();
                let slow_bytes = slow.clone();
                let outcome = download_assigned_part(
                    &mut ready.conn,
                    &peer_cfg,
                    &mut file,
                    idx,
                    expected,
                    ready.aich_supported,
                    || slow_abort.lock().unwrap().should_abort(),
                    |covered, bytes| {
                        slow_bytes.lock().unwrap().add(bytes);
                        if bytes > 0 {
                            cfg.hooks.received(bytes);
                            *network += bytes;
                            (cfg.on_event)(PeerEvent::Receiving {
                                addr,
                                network_bytes: *network,
                            });
                        }
                        pool.update(owner, idx, covered);
                        let _ = wake.send(());
                    },
                    |addrs| {
                        // 源交换回包：直接透传，由外层统一做去重/落库/合法性过滤。
                        if let Some(tx) = &cfg.xs_sources {
                            for a in addrs {
                                let _ = tx.send(a);
                            }
                        }
                    },
                )?;
                let mut verified = outcome.verified;
                if outcome.aich_recovered_blocks > 0 {
                    pool.state.lock().unwrap().aich_recovered_blocks +=
                        outcome.aich_recovered_blocks;
                    let _ = wake.send(());
                }
                // 其他 peer 可能在本片开始传输之后才提供自洽 hashset。
                if !verified {
                    let want = pool
                        .state
                        .lock()
                        .unwrap()
                        .hashes
                        .as_ref()
                        .and_then(|h| h.get(idx))
                        .copied();
                    if let Some(want) = want {
                        if read_back_and_hash(&mut file, idx, pool.length(idx))? != want {
                            return Err("ed2k_hash_mismatch".into());
                        }
                        verified = true;
                    }
                }
                pool.finish_part(owner, idx, verified);
                let _ = wake.send(());
            }
            Claim::Wait => {
                let guard = pool.state.lock().unwrap();
                drop(
                    pool.changed
                        .wait_timeout(guard, Duration::from_millis(50))
                        .unwrap(),
                );
            }
            Claim::Finished => break,
        }
    }
    file.flush().map_err(|e| format!("ed2k_flush: {e}"))?;
    let _ = ready
        .conn
        .send(Protocol::Edonkey, ed2k::END_OF_DOWNLOAD, &cfg.file_hash);
    Ok(())
}

/// 增量接收查源结果。sender 全部释放后立即结束发现等待；已连接源继续传输。
/// 源全部不可用时返回不完整结果，由 worker 进入等待源；文件/校验错误返回 Err。
pub fn download_from_sources(
    cfg: &MultiSourceCfg<'_>,
    sources: mpsc::Receiver<SocketAddr>,
    on_progress: impl FnMut(PoolProgress),
) -> Result<MultiDownload, String> {
    download_from_sources_with_hashsets(cfg, sources, None, on_progress)
}

/// 索引校验片可以先于任何 peer 到达；接收过程不阻塞源连接和传输。
pub fn download_from_sources_with_hashsets(
    cfg: &MultiSourceCfg<'_>,
    sources: mpsc::Receiver<SocketAddr>,
    hashsets: Option<mpsc::Receiver<Vec<[u8; 16]>>>,
    mut on_progress: impl FnMut(PoolProgress),
) -> Result<MultiDownload, String> {
    if cfg.file_size == 0 {
        return Err("ed2k_empty_file".into());
    }
    // 主句柄只用于建文件、量长度与收尾截断；分片读回校验在后台线程里用独立句柄。
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(cfg.target)
        .map_err(|e| format!("ed2k_open_file: {e}"))?;
    let existing_len = file
        .metadata()
        .map_err(|e| format!("ed2k_stat: {e}"))?
        .len();
    let total = part_count(cfg.file_size);
    let pool = Pool {
        state: Mutex::new(State {
            parts: (0..total)
                .map(|_| Part {
                    state: PartState::Pending,
                    received: 0,
                    claim_seq: 0,
                })
                .collect(),
            hashes: None,
            existing_len,
            peers: HashMap::new(),
            owner_peer: HashMap::new(),
            ownership_rev: 0,
            claim_next: cfg.claim_base.max(1),
            streams: HashMap::new(),
            aich_recovered_blocks: 0,
        }),
        changed: Condvar::new(),
        filter: cfg.part_filter.clone(),
        file_size: cfg.file_size,
        started: Instant::now(),
        claim_base: cfg.claim_base.max(1),
        claim_end: std::sync::atomic::AtomicU64::new(
            cfg.claim_base.max(1) + cfg.claim_reserve.max(1),
        ),
        claim_refill: cfg.claim_refill.clone(),
    };
    let (wake_tx, wake_rx) = mpsc::channel();
    // 每任务连接数不设限：上限只由"本池负责的分片数"与调用方给的期望值决定
    //（调用方已把 0 = 不限 折算成全局闸门值）。
    let owned_total = cfg.part_filter.as_ref().map(|f| f.owned()).unwrap_or(total);
    let max = cfg.max_connections.max(1).min(owned_total.max(1));
    let deadline = Instant::now() + cfg.discovery_timeout.min(Duration::from_secs(60));
    // 有校验片来源时，先把"已完整落盘"的片圈起来（微秒级），再让源立刻连上；
    // 读回校验交给下面的后台线程。没有哈希集来源时维持历史行为（全部 Pending）。
    if hashsets.is_some() {
        pool.begin_check();
    }
    on_progress(pool.progress());
    std::thread::scope(|scope| {
        // 已落盘分片的读回校验：独立线程，不挡连源、不挡传输。
        let pool_ref = &pool;
        let checker = hashsets.map(|rx| {
            scope.spawn(move || {
                // 全新下载（盘上没有任何完整分片）没有东西要校验：直接退出，
                // 否则 scope 收尾要陪着等哈希集，白等几秒。
                if !pool_ref.has_checking() {
                    return;
                }
                let mut got: Option<Vec<[u8; 16]>> = None;
                while !(cfg.stop)() {
                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(h) => {
                            got = Some(h);
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        // 索引线程结束（查不到 / 被拒 / 暂停）都不会再送哈希集
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                let valid = got.as_ref().is_some_and(|hashes| {
                    hashes.len() == total
                        && total > 0
                        && if total == 1 {
                            hashes[0] == cfg.file_hash
                        } else {
                            aidm_core::ed2k::hash::md4(hashes.as_flattened()) == cfg.file_hash
                        }
                });
                if !valid {
                    pool_ref.release_checking();
                    return;
                }
                let hashes = got.unwrap_or_default();
                if let Err(e) = pool_ref.resolve_checking(&hashes, cfg.target, cfg.stop) {
                    log::debug!("ed2k 已落盘分片读回校验中断：{e}");
                    pool_ref.release_checking();
                }
            })
        });
        let mut handles = Vec::new();
        let mut seen = HashSet::new();
        let mut pending = VecDeque::new();
        let mut discovery_done = false;
        let mut next_owner = 0;
        let mut last_progress = pool.progress();
        loop {
            if (cfg.stop)() {
                pool.shutdown();
                break;
            }
            if pool.complete() {
                // 其他连接可能仍在 HELLO/排队等待；不能为收尾再等完整读超时。
                pool.shutdown();
                break;
            }
            // 外部补源通道常开时，仅靠断开信号无法判断"不会再有新源"：
            // 中继结束（无在途对端、无待连）即退出，时限仍是后备。
            let feed_done = cfg
                .feed_done
                .as_ref()
                .is_none_or(|f| f.load(Ordering::Acquire));
            if !discovery_done {
                loop {
                    match sources.try_recv() {
                        Ok(addr) if seen.insert(addr) => pending.push_back(addr),
                        Ok(_) => {}
                        Err(mpsc::TryRecvError::Disconnected) => {
                            discovery_done = true;
                            break;
                        }
                        Err(mpsc::TryRecvError::Empty) => break,
                    }
                }
                if Instant::now() >= deadline {
                    discovery_done = true;
                }
            }
            let mut pos = 0;
            while pos < handles.len() {
                let finished = {
                    let (_, handle): &(usize, std::thread::ScopedJoinHandle<'_, ()>) =
                        &handles[pos];
                    handle.is_finished()
                };
                if finished {
                    let (_, handle) = handles.swap_remove(pos);
                    let _ = handle.join();
                } else {
                    pos += 1;
                }
            }
            while handles.len() < max && !pending.is_empty() {
                if !cfg.hooks.try_acquire_connection() {
                    break;
                }
                let permit = Permit(cfg.hooks);
                let addr = pending.pop_front().unwrap();
                let owner = next_owner;
                next_owner += 1;
                pool.state
                    .lock()
                    .unwrap()
                    .owner_peer
                    .insert(owner, addr);
                pool.state
                    .lock()
                    .unwrap()
                    .peers
                    .insert(owner, Phase::Connecting);
                let pool_ref = &pool;
                let wake = wake_tx.clone();
                let handle = scope.spawn(move || {
                    let _permit = permit;
                    let mut network = 0;
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run_peer(cfg, pool_ref, owner, addr, &wake, &mut network)
                    }))
                    .unwrap_or_else(|_| Err("ed2k_peer_panic".into()));
                    let stopped = (cfg.stop)();
                    pool_ref.finish_peer(owner, stopped);
                    (cfg.on_event)(PeerEvent::Finished {
                        addr,
                        network_bytes: network,
                        error: result.err().filter(|_| !stopped && !pool_ref.complete()),
                    });
                    let _ = wake.send(());
                });
                handles.push((owner, handle));
            }
            let progress = pool.progress();
            if progress != last_progress {
                // 归属变化才重建快照：认领/释放/完成/阶段转换都会推进版本号。
                if progress.ownership_rev != last_progress.ownership_rev {
                    if let Some(on_ownership) = cfg.on_ownership {
                        on_ownership(&pool.ownership());
                    }
                }
                on_progress(progress.clone());
                last_progress = progress;
            }
            // 还有分片在后台校验时不能收尾：它们既不算完成，也不该被当成失败。
            if (discovery_done || feed_done)
                && pending.is_empty()
                && handles.is_empty()
                && !pool.has_checking()
            {
                break;
            }
            let _ = wake_rx.recv_timeout(Duration::from_millis(25));
        }
        for (_, handle) in handles {
            let _ = handle.join();
        }
        // 后台校验线程由 scope 统一 join（它最多再读回若干分片，不影响已完成判定）。
        drop(checker);
    });
    // 有分片过滤器时不做收尾截断与整包校验：本池"完成"只代表自己那份分片完成，
    // 文件仍是两池共写的产物，整包 MD4 必须由编排层在两池 join 之后统一做。
    if cfg.part_filter.is_none() && !(cfg.stop)() && pool.complete() {
        file.set_len(cfg.file_size)
            .map_err(|e| format!("ed2k_truncate: {e}"))?;
        let mut progress = pool.progress();
        progress.verifying = true;
        on_progress(progress);
        let verified = verify_interruptible(cfg);
        if !(cfg.stop)() {
            match verified {
                Ok(true) => {
                    for p in &mut pool.state.lock().unwrap().parts {
                        p.state = PartState::Done(true);
                    }
                }
                Ok(false) => {
                    on_progress(pool.progress());
                    return Err("ed2k_hash_mismatch".into());
                }
                Err(e) => {
                    on_progress(pool.progress());
                    return Err(e);
                }
            }
        }
    }
    let stopped = (cfg.stop)();
    let progress = pool.progress();
    on_progress(progress.clone());
    Ok(MultiDownload {
        written: progress.done,
        verified_parts: progress.verified_parts,
        total_parts: total,
        stopped,
        aich_recovered_blocks: progress.aich_recovered_blocks,
    })
}

pub(crate) fn verify_interruptible(cfg: &MultiSourceCfg<'_>) -> Result<bool, String> {
    struct CheckedReader<'a> {
        file: File,
        stop: &'a (dyn Fn() -> bool + Sync),
    }
    impl Read for CheckedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if (self.stop)() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "ed2k_stopped",
                ));
            }
            self.file.read(buf)
        }
    }
    let file = File::open(cfg.target).map_err(|e| format!("ed2k_open: {e}"))?;
    aidm_core::ed2k::hash::hash_reader(
        aidm_core::ed2k::Flavor::Official,
        CheckedReader {
            file,
            stop: cfg.stop,
        },
    )
    .map(|digest| digest.file == cfg.file_hash)
    .map_err(|e| format!("ed2k_hash: {e}"))
}

#[cfg(test)]
mod part_filter_tests {
    use super::{PartFilter, SlowWatch};
    use std::time::Instant;

    /// 各份取模过滤**恰好**把全部分片分成互不相交的并集。
    #[test]
    fn modulo_partitions_are_disjoint_and_cover_everything() {
        let total = 461usize;
        for stride in [1usize, 2, 3, 4, 7] {
            let mut seen = vec![0u32; total];
            for offset in 0..stride {
                let f = PartFilter::modulo(total, stride, offset);
                for idx in 0..total {
                    if f.contains(idx) {
                        seen[idx] += 1;
                    }
                }
            }
            assert!(
                seen.iter().all(|n| *n == 1),
                "stride={stride} 时每个分片应恰好归一份"
            );
        }
    }

    #[test]
    fn allow_all_expands_without_changing_initial_share() {
        let f = PartFilter::modulo(8, 4, 0);
        assert!(!f.contains(1));
        assert_eq!(f.owned(), 2);
        f.allow_all();
        assert!(f.all_allowed());
        assert!(f.contains(1));
        assert_eq!(f.owned(), 2, "初始份额保持原值，用于启动预算");
    }

    #[test]
    fn slow_watch_requires_grace_samples_and_low_average() {
        let mut w = SlowWatch::new(1024.0);
        assert!(!w.should_abort(), "刚连上的源不在观察期内");
        w.started = Instant::now() - std::time::Duration::from_secs(21);
        w.samples = 3;
        w.total = 0;
        assert!(w.should_abort(), "20 秒后仍无字节，应中止");
        w.total = 1024 * 30;
        assert!(
            !w.should_abort(),
            "30 秒收到 30 KiB，平均 1 KiB/s 附近不应误杀"
        );
        w.total = 1024;
        assert!(w.should_abort(), "30 秒仅 1 KiB，应低于阈值");
    }

    #[test]
    fn modulo_counts_and_bounds() {
        let total = 10usize;
        let f = PartFilter::modulo(total, 4, 1);
        assert_eq!(f.owned(), 3, "10 片按 %4==1 得到 1/5/9");
        assert!(f.contains(1) && f.contains(5) && f.contains(9));
        assert!(!f.contains(0) && !f.contains(10), "越界一律 false");
        assert_eq!(f.total(), total);

        let empty = PartFilter::modulo(total, 4, 4);
        assert!(empty.is_empty() && empty.owned() == 0);
        assert!(!empty.contains(0));

        // stride=0 按 1 处理（不 panic、不空转成"没人负责"）
        let all = PartFilter::modulo(3, 0, 0);
        assert_eq!(all.owned(), 3);
    }

    #[test]
    fn from_indices_ignores_out_of_range_and_duplicates() {
        let f = PartFilter::from_indices(5, [3, 3, 9, 0]);
        assert_eq!(f.owned(), 2, "重复与越界只算一次/忽略");
        assert!(f.contains(0) && f.contains(3));
        assert!(!f.contains(9));
    }
}

/// 「暂停后恢复」的连源时序：已落盘分片先被圈起来（微秒级），读回校验放后台。
///
/// 读回 + MD4 若放在连源之前同步做，延迟随已下载字节线性增长，
/// 用户看到的就是"恢复后迟迟连不上资源"。
#[cfg(test)]
mod existing_parts_check_tests {
    use super::*;

    fn pool_with_disk(file_size: u64, existing_len: u64) -> Pool {
        let total = part_count(file_size);
        Pool {
            changed: Condvar::new(),
            state: Mutex::new(State {
                parts: (0..total)
                    .map(|_| Part {
                        state: PartState::Pending,
                        received: 0,
                        claim_seq: 0,
                    })
                    .collect(),
                hashes: None,
                existing_len,
                peers: HashMap::new(),
                owner_peer: HashMap::new(),
                ownership_rev: 0,
                claim_next: 1,
                streams: HashMap::new(),
                aich_recovered_blocks: 0,
            }),
            claim_base: 1,
            claim_end: std::sync::atomic::AtomicU64::new(1 + 1024),
            claim_refill: None,
            filter: None,
            file_size,
            started: Instant::now(),
        }
    }

    #[test]
    fn ownership_tracks_claim_update_finish_and_release() {
        // 验收要求：不能只把 `Owned(owner)` 压成 `active`；归属必须在
        // 认领、阶段变化、完成、释放四个真实位置可观测。
        let size = PARTSIZE * 2;
        let pool = pool_with_disk(size, 0);
        let rev0 = pool.progress().ownership_rev;

        // 认领 part0（owner 0）与 part1（owner 1）。
        assert!(matches!(pool.claim(0, &[true, true]), Claim::Part(0, _)));
        assert!(matches!(pool.claim(1, &[true, true]), Claim::Part(1, _)));
        assert!(
            pool.progress().ownership_rev > rev0,
            "认领必须推进归属版本"
        );

        let snap = pool.ownership();
        assert_eq!(snap[0].owner, Some(0));
        assert_eq!(
            snap[0].peer_addr, None,
            "未登记地址时必须是未知，不能按源数推算"
        );
        assert_eq!(snap[1].owner, Some(1));

        // 建连后登记对端地址（与 `run_peer` 的写入位置一致）。
        let addr: SocketAddr = "127.0.0.1:1234".parse().expect("addr");
        pool.state.lock().unwrap().owner_peer.insert(0, addr);
        assert_eq!(pool.ownership()[0].peer_addr, Some(addr));

        // 阶段变为接收（原来 Idle）：推进版本。
        let rev = pool.progress().ownership_rev;
        pool.update(0, 0, 1024);
        assert!(pool.progress().ownership_rev > rev);
        assert_eq!(pool.ownership()[0].state, "receiving");

        // 完成且校验通过：verified 必须如实上报。
        pool.finish_part(0, 0, true);
        let snap = pool.ownership();
        assert!(snap[0].verified);
        assert_eq!(snap[0].state, "done");

        // 释放 owner 1：part1 回到 pending，地址被清、版本推进。
        let rev = pool.progress().ownership_rev;
        pool.finish_peer(1, false);
        assert!(
            pool.progress().ownership_rev > rev,
            "释放必须推进归属版本，否则界面会继续显示已不存在的通路"
        );
        let snap = pool.ownership();
        assert_eq!(snap[1].owner, None);
        assert!(!pool.state.lock().unwrap().owner_peer.contains_key(&1));
    }

    #[test]
    fn reclaiming_a_part_bumps_claim_seq() {
        // “同一次分配刷新保持 ID；释放后重领、换源则生成新 ID”的底层保证：
        // 归属生命周期由原生分片上的领取序号表达。
        let size = PARTSIZE;
        let pool = pool_with_disk(size, 0);

        assert!(matches!(pool.claim(0, &[true]), Claim::Part(0, _)));
        let first = pool.ownership()[0].claim_seq;
        assert!(first > 0, "领取必须分配非零生命周期序号");

        // 同一次领取内刷新：序号不变。
        pool.update(0, 0, 1024);
        assert_eq!(
            pool.ownership()[0].claim_seq,
            first,
            "同一次领取刷新不得改序号，否则 UI 会看到一个假的新分配"
        );

        // 释放后重领：序号必须变。
        pool.finish_peer(0, false);
        assert!(matches!(pool.claim(0, &[true]), Claim::Part(0, _)));
        let second = pool.ownership()[0].claim_seq;
        assert!(
            second > first,
            "释放后重领必须产生新的归属生命周期（{first} -> {second}）"
        );
    }

    #[test]
    fn disk_parts_are_reserved_before_any_peer_claims() {
        let size = PARTSIZE * 2;
        let pool = pool_with_disk(size, PARTSIZE);
        pool.begin_check();
        {
            let s = pool.state.lock().unwrap();
            assert!(matches!(s.parts[0].state, PartState::Checking));
            assert!(matches!(s.parts[1].state, PartState::Pending));
            assert_eq!(s.parts[0].received, PARTSIZE, "盘上字节必须立刻计入进度");
        }
        assert!(pool.has_checking());
        // 第 0 片在校验中：不能被认领，但连接也不能因此收工（否则校验失败就没人接）
        assert!(matches!(pool.claim(0, &[true, true]), Claim::Part(1, _)));
        assert!(matches!(pool.claim(1, &[true, false]), Claim::Wait));
        let p = pool.progress();
        assert_eq!(p.done, PARTSIZE);
        assert_eq!(p.verified_parts, 0, "校验完成之前不算已验证");
        assert_eq!(
            p.slices,
            vec![3, 1],
            "校验中的片为 checking，已认领的片为 active"
        );
        assert!(!pool.complete());
    }

    #[test]
    fn background_check_verifies_or_releases_parts() {
        let head: Vec<u8> = (0..PARTSIZE as usize)
            .map(|i| (i.wrapping_mul(7) ^ (i / 251)) as u8)
            .collect();
        let mut bytes = head.clone();
        bytes.extend_from_slice(&head[..1000]);
        let _tmp = crate::testsupport::tempdir("ed2k-check");
        let path = _tmp.path().join("check.bin");
        std::fs::write(&path, &bytes).unwrap();
        let size = bytes.len() as u64;
        let good = vec![
            aidm_core::ed2k::hash::md4(&head),
            aidm_core::ed2k::hash::md4(&head[..1000]),
        ];

        // 命中：两片转 Done(true)，且不算流量（这里只验状态机）
        let pool = pool_with_disk(size, size);
        pool.begin_check();
        pool.resolve_checking(&good, &path, &|| false).unwrap();
        assert!(!pool.has_checking());
        assert!(pool.complete());
        assert_eq!(pool.progress().verified_parts, 2);
        assert_eq!(pool.progress().slices, vec![2, 2]);

        // 不命中：整片回到 Pending 且字节清零，交给 peer 重下
        let mut bad = good.clone();
        bad[0][0] ^= 1;
        let pool = pool_with_disk(size, size);
        pool.begin_check();
        pool.resolve_checking(&bad, &path, &|| false).unwrap();
        {
            let s = pool.state.lock().unwrap();
            assert!(matches!(s.parts[0].state, PartState::Pending));
            assert_eq!(s.parts[0].received, 0);
            assert!(matches!(s.parts[1].state, PartState::Done(true)));
        }
        assert!(!pool.complete());
        assert!(matches!(pool.claim(0, &[true, true]), Claim::Part(0, _)));
        let _ = std::fs::remove_file(&path);
    }

    /// 拿不到可信哈希集时必须放回 Pending：绝不能把没校验过的片当成已完成。
    #[test]
    fn releasing_without_a_hashset_puts_parts_back() {
        let size = PARTSIZE * 2;
        let pool = pool_with_disk(size, size);
        pool.begin_check();
        pool.release_checking();
        assert!(!pool.has_checking());
        assert!(!pool.complete());
        let s = pool.state.lock().unwrap();
        assert!(s
            .parts
            .iter()
            .all(|p| matches!(p.state, PartState::Pending) && p.received == 0));
    }
}

#[cfg(test)]
mod c1_claim_range_tests {
    use super::*;

    fn pool() -> Pool {
        let p = Pool {
            changed: Condvar::new(),
            state: Mutex::new(State {
                parts: (0..4)
                    .map(|_| Part {
                        state: PartState::Pending,
                        received: 0,
                        claim_seq: 0,
                    })
                    .collect(),
                hashes: None,
                existing_len: 0,
                peers: HashMap::new(),
                owner_peer: HashMap::new(),
                ownership_rev: 0,
                claim_next: 1,
                streams: HashMap::new(),
                aich_recovered_blocks: 0,
            }),
            claim_base: 1,
            claim_end: AtomicU64::new(2), // 只剩 1 个序号
            claim_refill: None,
            filter: None,
            file_size: PARTSIZE * 4,
            started: Instant::now(),
        };
        p.claim_end.store(2, Ordering::Relaxed);
        p
    }

    #[test]
    fn exhausting_the_range_reports_exhausted_instead_of_reusing() {
        // 用户反例：池只有起点、没有终点检查，耗尽后会拿墙钟基数凑合。
        let p = pool();
        assert!(matches!(p.claim(0, &[true; 4]), Claim::Part(0, _)));
        assert_eq!(p.ownership()[0].claim_seq, 1);
        assert_eq!(
            p.claim(1, &[true; 4]),
            Claim::Exhausted,
            "号段耗尽必须明确报错"
        );
    }

    #[test]
    fn refill_extends_the_range_from_the_database() {
        let mut p = pool();
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        p.claim_refill = Some(Arc::new(move |want: u64| {
            c.fetch_add(1, Ordering::SeqCst);
            Some((1000, want))
        }));
        assert!(matches!(p.claim(0, &[true; 4]), Claim::Part(0, _)));

        p.top_up_claim();
        assert_eq!(calls.load(Ordering::SeqCst), 1, "水位见底应触发一次续领");

        assert!(matches!(p.claim(1, &[true; 4]), Claim::Part(1, _)));
        assert_eq!(
            p.ownership()[1].claim_seq,
            1000,
            "续领后的序号必须来自新号段，不能接着用旧的"
        );
    }

    #[test]
    fn failing_refill_reports_exhausted_instead_of_wallclock_fallback() {
        let mut p = pool();
        p.claim_refill = Some(Arc::new(|_| None));
        assert!(matches!(p.claim(0, &[true; 4]), Claim::Part(0, _)));

        p.top_up_claim();
        assert_eq!(
            p.claim(1, &[true; 4]),
            Claim::Exhausted,
            "续领失败必须报错，不能退回墙钟基数冒充持久身份"
        );
    }
}
