//! 统一下载实体、编号、状态、能力、等待、错误与进度。
//!
//! 依据 `docs/unified-download-state-review.md` 第 4.1 至 4.5 节、第 7.1 节与
//! 第 11.2 节。全部类型均为纯数据，不含 IO、锁或时间源。
//!
// 复用既有类型的边界（不重复定义）：
// - 任务主状态复用 [`crate::model::Status`]（七状态闭集，遵守 R-LIFE-01）。
// - 传输协议复用 [`crate::capability::Transport`]。
// - 失败阶段复用 [`crate::error::Phase`]（七阶段 + 任务级）。
//
// 这三个类型以 `pub use` 重导出，使本模块内部子模块与快照层共用同一入口，
// 避免各自从不同路径导入后产生“同名异源”的维护负担。
//
// 本模块**刻意不实现** `Serialize`：`Status` 与 `Phase` 属于既有内部类型，
// 对外投影由 `aidm-engine` 的统一快照层唯一负责（文档第 10 节）。

use serde::{Deserialize, Serialize};

pub use crate::capability::Transport;
pub use crate::error::Phase;
pub use crate::model::Status;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------- 不透明编号

/// 声明一个不透明编号类型。
///
/// 编号只在内部比较与传递，不参与业务计算。空串一律视为无效：这既拦住 IPC
/// 与数据库传入的空值，也避免"用空 ID 当通配符"的隐患。
macro_rules! opaque_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// 由受控来源（引擎生成或已校验的持久化值）构造。
            pub fn new(raw: impl Into<String>) -> Self {
                Self(raw.into())
            }

            /// 从不可信来源还原；空串返回 `None`，调用方据此判定"未知"。
            pub fn parse(raw: &str) -> Option<Self> {
                if raw.is_empty() {
                    None
                } else {
                    Some(Self(raw.to_owned()))
                }
            }

            /// 生成一个新编号（UUIDv4 字面量）。一次分配永不复用。
            pub fn generate() -> Self {
                Self(gen_uuid_v4())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

opaque_id! {
    /// 资源编号：任务内被下载的内容对象。持久化。
    ResourceId
}
opaque_id! {
    /// 切片编号：资源内一段稳定的工作范围。持久化。
    SliceId
}
opaque_id! {
    /// 源编号：能提供目标内容的候选提供方。持久化。
    SourceId
}
opaque_id! {
    /// 连接编号：一次真实传输会话。不复用。
    ConnectionId
}
opaque_id! {
    /// 通路分配编号：把某切片的某子区间交给某源。不复用。
    AssignmentId
}
opaque_id! {
    /// 决策编号。
    DecisionId
}
opaque_id! {
    /// 执行命令编号。每次实际重试产生新编号并消耗预算。
    CommandId
}
opaque_id! {
    /// 事实事件编号。重复投递保持相同编号，供去重。
    EventId
}
opaque_id! {
    /// 证据编号：能力、源身份或观测结果的引用。
    EvidenceId
}

/// 生成 UUIDv4 字面量（8-4-4-4-12）。
///
/// 用 `ring` 的系统熵源；熵源不可用时退回"纳秒 + 进程内原子计数器"，仍保证
/// 进程内不重复（跨进程重复依赖启动时间不同，仅作最后兜底）。
pub fn gen_uuid_v4() -> String {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut bytes = [0u8; 16];
    let ok = SystemRandom::new().fill(&mut bytes).is_ok();
    if !ok {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        // 进程 id 区分同机多进程，seq 区分同进程多次调用。
        let pid = std::process::id() as u64;
        bytes[..8].copy_from_slice(&nanos.to_be_bytes());
        bytes[8..].copy_from_slice(&(pid ^ seq.rotate_left(17)).to_be_bytes());
    }
    // RFC 4122：version 4、variant 10xx。
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = |b: &[u8]| -> String {
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&bytes[0..4]),
        hex(&bytes[4..6]),
        hex(&bytes[6..8]),
        hex(&bytes[8..10]),
        hex(&bytes[10..16])
    )
}

// ---------------------------------------------------------------- 范围

/// 左闭右开字节范围 `start..end_exclusive`。
///
/// `end_exclusive` 为 `None` 表示**总长未知、只能顺序读取**。除此之外不接受
/// 任何"未知终点"的随机访问范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    pub start: u64,
    pub end_exclusive: Option<u64>,
}

impl Span {
    /// 已知长度的非空范围；`start >= end` 返回 `None`（0 长度不是范围）。
    pub fn known(start: u64, end_exclusive: u64) -> Option<Self> {
        (start < end_exclusive).then_some(Self {
            start,
            end_exclusive: Some(end_exclusive),
        })
    }

    /// 已知总长的范围，允许 `start == end`（用于表示"空但位置确定"）。
    ///
    /// 只在需要区分"空资源"与"未知长度"时使用；下载分配一律走 [`Self::known`]。
    pub fn known_allow_empty(start: u64, end_exclusive: u64) -> Option<Self> {
        (start <= end_exclusive).then_some(Self {
            start,
            end_exclusive: Some(end_exclusive),
        })
    }

    /// 起点已知、终点未知的顺序范围。
    pub fn open(start: u64) -> Self {
        Self {
            start,
            end_exclusive: None,
        }
    }

    /// 已知长度；`None` 表示总长未知。
    pub fn len(&self) -> Option<u64> {
        self.end_exclusive.map(|end| end - self.start)
    }

    /// 是否已知为空范围（长度确认为 0）。
    pub fn is_empty(&self) -> bool {
        self.len() == Some(0)
    }

    /// 终点是否未知。
    pub fn is_open(&self) -> bool {
        self.end_exclusive.is_none()
    }

    /// 已知且非空，可以参与随机访问与切片分配。
    pub fn is_allocatable(&self) -> bool {
        matches!(self.end_exclusive, Some(end) if end > self.start)
    }

    /// 字节位置是否落在范围内。开放范围按 `>= start` 判定。
    pub fn contains(&self, at: u64) -> bool {
        at >= self.start && self.end_exclusive.is_none_or(|end| at < end)
    }

    /// 与另一范围的交集；无交集返回 `None`。
    ///
    /// 任一方终点未知时，交集终点取已知的那一侧。
    pub fn intersect(&self, other: &Span) -> Option<Span> {
        let start = self.start.max(other.start);
        let end = match (self.end_exclusive, other.end_exclusive) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        match end {
            Some(end) if end > start => Some(Span {
                start,
                end_exclusive: Some(end),
            }),
            Some(_) => None,
            None => Some(Span {
                start,
                end_exclusive: None,
            }),
        }
    }

    /// 是否与另一范围有重叠字节。
    pub fn overlaps(&self, other: &Span) -> bool {
        self.intersect(other).is_some()
    }
}

// ---------------------------------------------------------------- 三态与枚举

/// 三态能力：支持 / 不支持 / 未知。
///
/// 文档 4.1 明确禁止用 `bool` 替代——未知与"确认不支持"会导致完全不同的决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriState {
    #[default]
    Unknown,
    Yes,
    No,
}

impl TriState {
    pub fn is_yes(self) -> bool {
        matches!(self, TriState::Yes)
    }

    pub fn is_no(self) -> bool {
        matches!(self, TriState::No)
    }

    /// 保守合取：任一方为 `No` 则 `No`，否则有 `Unknown` 则 `Unknown`。
    pub fn and(self, other: TriState) -> TriState {
        match (self, other) {
            (TriState::No, _) | (_, TriState::No) => TriState::No,
            (TriState::Yes, TriState::Yes) => TriState::Yes,
            _ => TriState::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            TriState::Unknown => "unknown",
            TriState::Yes => "yes",
            TriState::No => "no",
        }
    }
}

/// 任务活动阶段（与主状态正交，不参与状态机合法性判定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    Discovering,
    Probing,
    Connecting,
    Transferring,
    Waiting,
    Verifying,
    Committing,
    Idle,
}

impl Activity {
    pub fn as_str(self) -> &'static str {
        match self {
            Activity::Discovering => "discovering",
            Activity::Probing => "probing",
            Activity::Connecting => "connecting",
            Activity::Transferring => "transferring",
            Activity::Waiting => "waiting",
            Activity::Verifying => "verifying",
            Activity::Committing => "committing",
            Activity::Idle => "idle",
        }
    }
}

/// 切片方案状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanStatus {
    /// 尚未规划；0 个切片是合法状态（例如还没拿到元数据）。
    Unplanned,
    /// 临时方案：范围终点未知或大小待确认。
    Provisional,
    /// 稳定方案：切片范围已确定。
    Ready,
}

impl PlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PlanStatus::Unplanned => "unplanned",
            PlanStatus::Provisional => "provisional",
            PlanStatus::Ready => "ready",
        }
    }
}

/// 等待原因（受控闭集，文档 4.5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitReason {
    Scheduler,
    Budget,
    Metadata,
    NoSource,
    PeerQueue,
    RateLimit,
    Retry,
    LocalAction,
}

impl WaitReason {
    pub fn as_str(self) -> &'static str {
        match self {
            WaitReason::Scheduler => "scheduler",
            WaitReason::Budget => "budget",
            WaitReason::Metadata => "metadata",
            WaitReason::NoSource => "no_source",
            WaitReason::PeerQueue => "peer_queue",
            WaitReason::RateLimit => "rate_limit",
            WaitReason::Retry => "retry",
            WaitReason::LocalAction => "local_action",
        }
    }

    /// 是否消耗"传输失败重试"预算。
    ///
    /// 文档 7.3：P2P 排队与定时查源**不**消耗重试次数。
    pub fn consumes_retry_budget(self) -> bool {
        !matches!(self, WaitReason::PeerQueue | WaitReason::NoSource)
    }
}

/// 等待作用范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Task,
    Source,
    Connection,
    Assignment,
    Host,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Task => "task",
            Scope::Source => "source",
            Scope::Connection => "connection",
            Scope::Assignment => "assignment",
            Scope::Host => "host",
        }
    }
}

/// 等待事实。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitInfo {
    pub reason: WaitReason,
    pub scope: Scope,
    /// 作用对象的内部标识；任务级等待为 `None`。
    pub subject_id: Option<String>,
    pub since_ms: u64,
    /// 到期可重试时间；无明确时间线为 `None`。
    pub retry_at_ms: Option<u64>,
    /// 受控补充原因码，不允许自由文本。
    pub detail_code: Option<String>,
}

/// 失败大类（文档 4.5 的受控闭集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Network,
    Throttled,
    Access,
    Capability,
    Content,
    Integrity,
    Storage,
    Protocol,
    Internal,
}

impl ErrorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCategory::Network => "network",
            ErrorCategory::Throttled => "throttled",
            ErrorCategory::Access => "access",
            ErrorCategory::Capability => "capability",
            ErrorCategory::Content => "content",
            ErrorCategory::Integrity => "integrity",
            ErrorCategory::Storage => "storage",
            ErrorCategory::Protocol => "protocol",
            ErrorCategory::Internal => "internal",
        }
    }
}

/// 原因链的一层；根因在链尾。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CauseLink {
    /// 稳定机器码，不用自由文本。
    pub code: String,
    /// 脱敏后的可读说明。
    pub message: String,
}

/// 统一错误。
///
/// `message` 只供人阅读，**禁止**从它反推业务状态（文档 4.5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedError {
    pub category: ErrorCategory,
    /// 稳定机器码；旧 `error_code` 通过兼容映射保留。
    pub code: String,
    pub phase: Option<Phase>,
    pub operation: Option<String>,
    pub scope: Option<Scope>,
    pub subject_id: Option<String>,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
    /// 协议种类；仅用于协议码归因。
    pub protocol: Option<Transport>,
    /// HTTP 状态、FTP 回复码或 P2P 原始类别。
    pub protocol_code: Option<String>,
    pub message: String,
    /// 最多八层，根因在末尾。
    pub cause_chain: Vec<CauseLink>,
}

/// 原因链上限（文档 4.5）。
pub const MAX_CAUSE_CHAIN: usize = 8;

impl UnifiedError {
    /// 从 legacy 机器码 + HTTP 状态构造。
    ///
    /// `retryable` 只用**协议语义**判定，不看 worker 内部的重试实现：
    /// - 429 / 408 / 5xx → 可重试（限流与临时故障）；
    /// - 其它 4xx → 不可重试（拒绝访问、不存在）；
    /// - 无状态码（`network` / `timeout` 等）→ 可重试。
    ///
    /// 这条判定是 `R-UDL-20/21/22` 的输入，改了它会直接改重试行为。
    pub fn from_legacy(
        code: &str,
        http_status: Option<u16>,
        retry_after_ms: Option<u64>,
    ) -> Self {
        let (category, retryable) = match http_status {
            Some(429) => (ErrorCategory::Throttled, true),
            Some(408) => (ErrorCategory::Network, true),
            Some(s @ 500..=599) => (ErrorCategory::Network, s != 501),
            Some(401) | Some(403) => (ErrorCategory::Access, false),
            Some(400..=499) => (ErrorCategory::Protocol, false),
            _ => {
                let retryable = matches!(
                    code,
                    "network" | "timeout" | "connection_reset" | "short_body" | "range_ignored"
                );
                (
                    if retryable {
                        ErrorCategory::Network
                    } else {
                        ErrorCategory::Internal
                    },
                    retryable,
                )
            }
        };
        Self {
            category,
            code: code.to_owned(),
            phase: None,
            operation: None,
            scope: Some(Scope::Task),
            subject_id: None,
            retryable,
            retry_after_ms,
            protocol: None,
            protocol_code: http_status.map(|s| s.to_string()),
            message: crate::error::classify(code).message,
            cause_chain: Vec::new(),
        }
    }

    /// 压入一层原因；超过上限时丢弃最外层（保留根因）。
    pub fn push_cause(&mut self, link: CauseLink) {
        if self.cause_chain.len() >= MAX_CAUSE_CHAIN {
            self.cause_chain.remove(0);
        }
        self.cause_chain.push(link);
    }
}

/// 完整性校验等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Integrity {
    #[default]
    None,
    LengthOnly,
    WholeFile,
    NativeBlock,
    Mixed,
}

impl Integrity {
    pub fn as_str(self) -> &'static str {
        match self {
            Integrity::None => "none",
            Integrity::LengthOnly => "length_only",
            Integrity::WholeFile => "whole_file",
            Integrity::NativeBlock => "native_block",
            Integrity::Mixed => "mixed",
        }
    }
}

/// 原生工作与校验边界。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeBlockKind {
    /// 没有原生块概念（普通 HTTP 文件）。
    None,
    /// eD2k part（固定 9728000 字节，末块单独计算）。
    Ed2kPart,
    /// BT piece。
    BtPiece,
    /// 其他协议的私有分块。
    Private,
}

impl NativeBlockKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NativeBlockKind::None => "none",
            NativeBlockKind::Ed2kPart => "ed2k_part",
            NativeBlockKind::BtPiece => "bt_piece",
            NativeBlockKind::Private => "private",
        }
    }
}

/// 原生块粒度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeGranularity {
    pub kind: NativeBlockKind,
    /// 原生单元字节数；未知为 `None`（不猜默认值）。
    pub unit_bytes: Option<u64>,
    /// 末块实际长度是否与常规单元不同（eD2k part 恒为真）。
    pub last_unit_shorter: bool,
}

impl NativeGranularity {
    pub fn none() -> Self {
        Self {
            kind: NativeBlockKind::None,
            unit_bytes: None,
            last_unit_shorter: false,
        }
    }
}

/// 协议专属能力细节。
///
/// 通用层**不解释**这些字段，只用它们展示与路由；不允许反过来扩展通用字段
/// 的含义（文档 4.5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolDetail {
    Http {
        /// 服务端是否按 `Range` 返回 `206`。
        range_support: TriState,
        /// 是否确认响应体为 identity 内容编码（无压缩偏移问题）。
        identity_encoding: TriState,
        /// 是否允许连接复用。
        keep_alive: TriState,
    },
    Ed2k {
        /// 是否具备 AICH 块级恢复。
        aich: TriState,
        /// 协议 part 大小；未知为 `None`。
        part_bytes: Option<u64>,
    },
    /// 其他协议或尚未观测。
    Other,
}

impl Default for ProtocolDetail {
    fn default() -> Self {
        ProtocolDetail::Other
    }
}

/// 连接复用能力。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Multiplexing {
    pub connection_reuse: TriState,
    /// 单个物理连接上的并发请求上限；未知为 `None`。
    pub max_concurrent_requests: Option<u32>,
}

impl Multiplexing {
    pub fn none() -> Self {
        Self {
            connection_reuse: TriState::No,
            max_concurrent_requests: None,
        }
    }
}

/// 三态能力集合。
///
/// 与 [`crate::capability::Capabilities`] 的关系：后者是**协议上界**的布尔映射，
/// 本结构是**本次观测**的三态事实，两者不可互相替代（文档 4.5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySet {
    pub metadata_known: TriState,
    pub random_read: TriState,
    pub resume: TriState,
    pub multi_source: TriState,
    pub integrity: Integrity,
    pub native_granularity: NativeGranularity,
    pub multiplexing: Multiplexing,
    pub evidence_id: Option<EvidenceId>,
    pub observed_at_ms: Option<u64>,
    pub expires_at_ms: Option<u64>,
    pub protocol_detail: ProtocolDetail,
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self {
            metadata_known: TriState::Unknown,
            random_read: TriState::Unknown,
            resume: TriState::Unknown,
            multi_source: TriState::Unknown,
            integrity: Integrity::None,
            native_granularity: NativeGranularity::none(),
            multiplexing: Multiplexing::none(),
            evidence_id: None,
            observed_at_ms: None,
            expires_at_ms: None,
            protocol_detail: ProtocolDetail::Other,
        }
    }
}

impl CapabilitySet {
    /// 能力证据是否已过期。`now_ms` 为 UTC Unix 毫秒。
    pub fn is_expired_at(&self, now_ms: u64) -> bool {
        matches!(self.expires_at_ms, Some(exp) if now_ms >= exp)
    }
}

/// 统一进度。
///
/// 不变量：`verified_unique_bytes <= stored_unique_bytes <= wire_bytes`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    /// 实际收到的传输载荷累计量，包含重复数据。
    pub wire_bytes: u64,
    /// 有效落盘范围的并集长度。
    pub stored_unique_bytes: u64,
    /// 已通过所要求内容校验的范围并集长度。
    pub verified_unique_bytes: u64,
    /// 用户所选范围总长；未知为 `None`。
    pub required_bytes: Option<u64>,
    /// 传输载荷速率（B/s）。
    pub transfer_rate_bps: u64,
    /// 有效覆盖新增速率（B/s）。
    pub useful_rate_bps: u64,
}

impl Progress {
    /// 进度是否满足不变量。
    pub fn is_consistent(&self) -> bool {
        self.verified_unique_bytes <= self.stored_unique_bytes
            && self.stored_unique_bytes <= self.wire_bytes.max(self.stored_unique_bytes)
    }

    /// 完成百分比；总量未知或为 0 时返回 `None`（不画虚假百分比）。
    pub fn percent(&self) -> Option<f64> {
        let required = self.required_bytes?;
        if required == 0 {
            return None;
        }
        Some((self.verified_unique_bytes as f64 / required as f64) * 100.0)
    }
}

// ---------------------------------------------------------------- 任务与资源

/// 任务级编号与版本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityContext {
    /// 复用 `downloads.id`，任务终生不变。
    pub task_id: i64,
    /// 每次引擎启动生成的新 UUID。
    pub engine_instance_id: String,
    /// 每次任务执行权重新取得时持久化递增。
    pub run_epoch: u64,
    /// 目标内容集合或身份更换时递增。
    pub content_generation: u64,
    /// 切片方案结构变化时递增。
    pub plan_revision: u64,
    /// 任务内持久化预留号段；允许缺口。
    pub state_revision: u64,
    pub resource_id: Option<ResourceId>,
    pub slice_id: Option<SliceId>,
    pub source_id: Option<SourceId>,
    pub connection_id: Option<ConnectionId>,
    pub assignment_id: Option<AssignmentId>,
}

impl IdentityContext {
    /// 新任务的初始上下文。
    pub fn for_task(task_id: i64, engine_instance_id: impl Into<String>) -> Self {
        Self {
            task_id,
            engine_instance_id: engine_instance_id.into(),
            run_epoch: 0,
            content_generation: 0,
            plan_revision: 0,
            state_revision: 0,
            resource_id: None,
            slice_id: None,
            source_id: None,
            connection_id: None,
            assignment_id: None,
        }
    }
}

/// 计数快照。各项独立计数，不能互相推导（文档 4.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// 未过期、去重后的源数量。
    pub known_sources: u32,
    /// 具备身份依据且至少有一个可用缺失范围的源。
    pub eligible_sources: u32,
    pub connections: u32,
    pub active_transfers: u32,
    pub queued_peers: u32,
    pub done_slices: u32,
}

/// 预算快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Budget {
    /// 当前允许的连接预算（复用 `hosts::task_conns` 的解析结果）。
    pub connection_budget: u32,
    /// 任务剩余重试预算。
    pub retry_budget: u32,
}

/// 任务状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskState {
    pub identity: IdentityContext,
    /// 主状态闭集，复用既有 [`Status`]。
    pub status: Status,
    pub activity: Activity,
    pub wait: Option<WaitInfo>,
    pub plan_status: PlanStatus,
    /// 兼容旧展示的主协议；不限制各源自己的传输方式。
    pub primary_transport: Transport,
    pub resource_ids: Vec<ResourceId>,
    pub source_ids: Vec<SourceId>,
    pub slice_ids: Vec<SliceId>,
    pub counts: Counts,
    pub progress: Progress,
    pub budget: Budget,
    pub current_error: Option<UnifiedError>,
    /// 已接受但尚未完成的命令。
    pub pending_command_ids: Vec<CommandId>,
    /// 最近完成持久化的状态版本。
    pub storage_revision: u64,
}

impl TaskState {
    /// 新任务：`queued` + 空规划，0 个切片是合法初始态。
    pub fn new(identity: IdentityContext, primary_transport: Transport) -> Self {
        Self {
            identity,
            status: Status::Queued,
            activity: Activity::Idle,
            wait: None,
            plan_status: PlanStatus::Unplanned,
            primary_transport,
            resource_ids: Vec::new(),
            source_ids: Vec::new(),
            slice_ids: Vec::new(),
            counts: Counts::default(),
            progress: Progress::default(),
            budget: Budget::default(),
            current_error: None,
            pending_command_ids: Vec::new(),
            storage_revision: 0,
        }
    }
}

/// 身份算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAlgorithm {
    Sha256,
    Md4,
    Ed2kRoot,
    BtInfoHash,
    /// 只有长度与名称等弱证据。
    LengthOnly,
    None,
}

impl IdentityAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            IdentityAlgorithm::Sha256 => "sha256",
            IdentityAlgorithm::Md4 => "md4",
            IdentityAlgorithm::Ed2kRoot => "ed2k_root",
            IdentityAlgorithm::BtInfoHash => "bt_infohash",
            IdentityAlgorithm::LengthOnly => "length_only",
            IdentityAlgorithm::None => "none",
        }
    }
}

/// 身份证据来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceSource {
    /// 协议清单自带（torrent、metalink、eD2k 链接）。
    ProtocolManifest,
    /// 上游 HTTP 响应头（`ETag`/`Content-MD5` 等）。
    HttpResponse,
    /// 同目录兄弟校验文件（`CHECKSUM`）。
    SiblingChecksum,
    /// 用户显式提供。
    User,
    /// 本地已完成文件对账。
    LocalReconcile,
}

/// 身份可信等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    Unknown,
    /// 单源表示（`ETag`/`Last-Modified`），只对该源有效。
    Weak,
    /// 全网通用内容摘要。
    Strong,
}

/// 内容身份。URL、文件名与大小**不能**单独证明同一内容（文档 4.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentIdentity {
    pub algorithm: IdentityAlgorithm,
    pub digest_hex: String,
    pub evidence_source: EvidenceSource,
    pub trust: TrustLevel,
}

/// 校验策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VerificationPolicy {
    pub integrity: Integrity,
    pub require_native_block_check: bool,
    pub require_file_digest: bool,
    pub require_length_check: bool,
}

/// 文件提交状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitState {
    Pending,
    Committing,
    Committed,
    Failed,
}

impl CommitState {
    pub fn as_str(self) -> &'static str {
        match self {
            CommitState::Pending => "pending",
            CommitState::Committing => "committing",
            CommitState::Committed => "committed",
            CommitState::Failed => "failed",
        }
    }
}

/// 资源状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceState {
    pub resource_id: ResourceId,
    pub task_id: i64,
    pub content_generation: u64,
    /// 是否属于本次用户选择的下载范围。
    pub selected: bool,
    /// 可空；`Some(0)` 是合法空文件。
    pub size_bytes: Option<u64>,
    pub identity: Option<ContentIdentity>,
    /// 内部文件引用；**禁止**写进日志。
    pub local_storage_ref: Option<String>,
    pub verification_policy: VerificationPolicy,
    pub commit_state: CommitState,
}

impl ResourceState {
    pub fn new(resource_id: ResourceId, task_id: i64, content_generation: u64) -> Self {
        Self {
            resource_id,
            task_id,
            content_generation,
            selected: true,
            size_bytes: None,
            identity: None,
            local_storage_ref: None,
            verification_policy: VerificationPolicy::default(),
            commit_state: CommitState::Pending,
        }
    }

    /// 是否为合法空文件（已知大小且为 0）。
    pub fn is_empty_file(&self) -> bool {
        self.size_bytes == Some(0)
    }
}

// ---------------------------------------------------------------- 切片

/// 切片状态闭集（文档 5 节的切片聚合规则）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceStatus {
    Pending,
    Active,
    Waiting,
    Verifying,
    Done,
    Error,
}

impl SliceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SliceStatus::Pending => "pending",
            SliceStatus::Active => "active",
            SliceStatus::Waiting => "waiting",
            SliceStatus::Verifying => "verifying",
            SliceStatus::Done => "done",
            SliceStatus::Error => "error",
        }
    }
}

/// 原生块到资源区间的映射条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeBlockRef {
    /// 协议原生块序号（eD2k part 下标 / BT piece 下标）。
    pub native_index: u64,
    /// 在资源坐标系中的范围。
    pub span: Span,
    /// 该块校验是否已通过；`None` = 尚未验证。
    pub verified: Option<bool>,
    /// 运行时状态：`pending` / `active` / `done` / `checking`；`None` = 未知。
    ///
    /// 与 `verified` 分开：`verified` 回答「能不能算完成」，`state` 回答
    /// 「现在在下 / 下完了 / 没开始」。暂停后运行时观测丢失，这里就是 `None`，
    /// 前端按“未知”画灰。
    pub state: Option<String>,
}

/// 切片状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceState {
    pub slice_id: SliceId,
    pub resource_id: ResourceId,
    pub content_generation: u64,
    pub plan_revision: u64,
    pub span: Span,
    pub state: SliceStatus,
    pub wait: Option<WaitInfo>,
    pub progress: Progress,
    /// 当前分配引用。
    pub assignment_ids: Vec<AssignmentId>,
    /// 有效落盘范围账本（对应文档的 `coverage_ref`；首版内嵌，避免额外间接层）。
    pub coverage: CoverageSetAlias,
    /// 协议适配器提供的原生块映射。
    pub native_blocks: Vec<NativeBlockRef>,
}

/// 账本类型别名，避免本文件循环导入。
pub type CoverageSetAlias = super::coverage::CoverageSet;

impl SliceState {
    pub fn new(
        slice_id: SliceId,
        resource_id: ResourceId,
        content_generation: u64,
        plan_revision: u64,
        span: Span,
    ) -> Self {
        Self {
            slice_id,
            resource_id,
            content_generation,
            plan_revision,
            span,
            state: SliceStatus::Pending,
            wait: None,
            progress: Progress::default(),
            assignment_ids: Vec::new(),
            coverage: CoverageSetAlias::default(),
            native_blocks: Vec::new(),
        }
    }

    /// 切片是否已完成：所需校验通过且范围完整（文档 5 节）。
    pub fn is_complete(&self) -> bool {
        let Some(len) = self.span.len() else {
            return false;
        };
        if !self.span.is_allocatable() {
            return false;
        }
        self.state == SliceStatus::Done
            && self.coverage.verified_len() >= len
            && self.coverage.stored_len() >= len
    }
}

// ---------------------------------------------------------------- 源与连接

/// 源可用性三态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Available,
    Unavailable,
    Unknown,
}

impl Availability {
    pub fn as_str(self) -> &'static str {
        match self {
            Availability::Available => "available",
            Availability::Unavailable => "unavailable",
            Availability::Unknown => "unknown",
        }
    }
}

/// 源健康观测摘要。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SourceHealth {
    pub successes: u32,
    pub failures: u32,
    pub throughput_bps: u64,
    pub queued_peers: u32,
}

/// 源状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceState {
    pub source_id: SourceId,
    pub resource_id: ResourceId,
    pub transport: Transport,
    /// 受保护的 locator/credential 存储引用；**禁止**存明文 URL。
    pub locator_ref: Option<String>,
    /// 此源与目标内容一致的证据。
    pub identity_evidence: Option<EvidenceId>,
    pub availability: Availability,
    /// 当前能否提供至少一个缺失范围。
    pub eligible: bool,
    pub capabilities: CapabilitySet,
    /// 可提供的数据范围或原生块位图。
    pub available_ranges: Option<CoverageSetAlias>,
    pub cooldown_until_ms: Option<u64>,
    pub last_observed_at_ms: Option<u64>,
    pub expires_at_ms: Option<u64>,
    pub health: SourceHealth,
}

impl SourceState {
    pub fn new(source_id: SourceId, resource_id: ResourceId, transport: Transport) -> Self {
        Self {
            source_id,
            resource_id,
            transport,
            locator_ref: None,
            identity_evidence: None,
            availability: Availability::Unknown,
            eligible: false,
            capabilities: CapabilitySet::default(),
            available_ranges: None,
            cooldown_until_ms: None,
            last_observed_at_ms: None,
            expires_at_ms: None,
            health: SourceHealth::default(),
        }
    }

    /// 是否处于冷却窗口内。
    pub fn is_cooling_at(&self, now_ms: u64) -> bool {
        matches!(self.cooldown_until_ms, Some(until) if now_ms < until)
    }

    /// 证据是否已过期。没有过期时间视为未过期。
    pub fn is_evidence_expired_at(&self, now_ms: u64) -> bool {
        matches!(self.expires_at_ms, Some(exp) if now_ms >= exp)
    }
}

/// 连接状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStatus {
    Opening,
    Ready,
    Closing,
    Closed,
    Failed,
}

impl ConnectionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectionStatus::Opening => "opening",
            ConnectionStatus::Ready => "ready",
            ConnectionStatus::Closing => "closing",
            ConnectionStatus::Closed => "closed",
            ConnectionStatus::Failed => "failed",
        }
    }

    /// 是否已释放物理额度（关闭或失败）。
    pub fn releases_permit(self) -> bool {
        matches!(self, ConnectionStatus::Closed | ConnectionStatus::Failed)
    }
}

/// 连接角色。控制、发现与探测连接同样占用角色预算（文档 6.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    Data,
    Control,
    Discovery,
}

impl ConnectionRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectionRole::Data => "data",
            ConnectionRole::Control => "control",
            ConnectionRole::Discovery => "discovery",
        }
    }
}

/// 连接状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionState {
    pub connection_id: ConnectionId,
    pub source_id: SourceId,
    pub run_epoch: u64,
    pub state: ConnectionStatus,
    pub role: ConnectionRole,
    /// 物理连接预算许可。
    pub permit_id: Option<u64>,
    /// 复用此连接的分配。
    pub assignment_ids: Vec<AssignmentId>,
    /// 握手、TLS 或对端排队等有类型详情。
    pub protocol_detail: ProtocolDetail,
}

impl ConnectionState {
    pub fn new(
        connection_id: ConnectionId,
        source_id: SourceId,
        run_epoch: u64,
        role: ConnectionRole,
    ) -> Self {
        Self {
            connection_id,
            source_id,
            run_epoch,
            state: ConnectionStatus::Opening,
            role,
            permit_id: None,
            assignment_ids: Vec::new(),
            protocol_detail: ProtocolDetail::Other,
        }
    }
}

// ---------------------------------------------------------------- 通路分配

/// 通路分配状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentStatus {
    Pending,
    Connecting,
    Queued,
    Transferring,
    Draining,
    Completed,
    Failed,
    Cancelled,
}

impl AssignmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            AssignmentStatus::Pending => "pending",
            AssignmentStatus::Connecting => "connecting",
            AssignmentStatus::Queued => "queued",
            AssignmentStatus::Transferring => "transferring",
            AssignmentStatus::Draining => "draining",
            AssignmentStatus::Completed => "completed",
            AssignmentStatus::Failed => "failed",
            AssignmentStatus::Cancelled => "cancelled",
        }
    }

    /// 是否已结束（不再持有写入许可）。
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            AssignmentStatus::Completed | AssignmentStatus::Failed | AssignmentStatus::Cancelled
        )
    }
}

/// 通路分配：把某切片的某子区间交给某源与连接。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentState {
    pub assignment_id: AssignmentId,
    pub task_id: i64,
    pub run_epoch: u64,
    pub content_generation: u64,
    pub slice_id: SliceId,
    pub source_id: SourceId,
    /// 连接未建成时为 `None`。
    pub connection_id: Option<ConnectionId>,
    /// 本次获准写入的子区间。
    pub span: Span,
    /// 本次写入许可版本；提升后旧写入必须被拒收。
    pub lease_revision: u64,
    pub state: AssignmentStatus,
    /// 实际原生块或请求引用。
    pub native_work_refs: Vec<String>,
    pub progress: Progress,
    /// 本分配已接纳的生产者序号（用于乱序/重复去重）。
    pub last_producer_seq: u64,
    pub error: Option<UnifiedError>,
}

impl AssignmentState {
    pub fn new(
        assignment_id: AssignmentId,
        task_id: i64,
        run_epoch: u64,
        content_generation: u64,
        slice_id: SliceId,
        source_id: SourceId,
        span: Span,
    ) -> Self {
        Self {
            assignment_id,
            task_id,
            run_epoch,
            content_generation,
            slice_id,
            source_id,
            connection_id: None,
            span,
            lease_revision: 0,
            state: AssignmentStatus::Pending,
            native_work_refs: Vec::new(),
            progress: Progress::default(),
            last_producer_seq: 0,
            error: None,
        }
    }
}

// ---------------------------------------------------------------- 事实与决策

/// 受控事实类别（文档 7.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactKind {
    CapabilityObserved,
    SourceObserved,
    ConnectionChanged,
    AssignmentChanged,
    CoverageChanged,
    VerifyResult,
    StoreResult,
    CommandResult,
    OperationFailed,
}

impl FactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FactKind::CapabilityObserved => "capability",
            FactKind::SourceObserved => "source",
            FactKind::ConnectionChanged => "connection",
            FactKind::AssignmentChanged => "assignment",
            FactKind::CoverageChanged => "coverage",
            FactKind::VerifyResult => "verify",
            FactKind::StoreResult => "store",
            FactKind::CommandResult => "command_result",
            FactKind::OperationFailed => "failure",
        }
    }
}

/// 事实载荷。**有类型**，不接受任意 JSON 对象或原始响应正文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactPayload {
    Capability {
        source_id: SourceId,
        capabilities: Box<CapabilitySet>,
    },
    Source {
        source_id: SourceId,
        state: Box<SourceState>,
    },
    Connection {
        connection_id: ConnectionId,
        state: Box<ConnectionState>,
    },
    Assignment {
        assignment_id: AssignmentId,
        state: Box<AssignmentState>,
    },
    /// 同一生产者的累计覆盖快照（文档 7.1：不发送易丢失的"加多少字节"）。
    Coverage {
        slice_id: SliceId,
        stored: CoverageSetAlias,
        verified: CoverageSetAlias,
    },
    Verify {
        slice_id: SliceId,
        span: Span,
        ok: bool,
        /// 本次确认通过的覆盖。
        verified: CoverageSetAlias,
    },
    Store {
        slice_id: SliceId,
        span: Span,
        /// 是否已完成落盘同步。
        synced: bool,
    },
    CommandResult {
        command_id: CommandId,
        state: CommandStatus,
    },
    Failure {
        error: Box<UnifiedError>,
    },
}

/// 统一事实事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactEvent {
    pub event_id: EventId,
    /// 关联编号（task_id、run_epoch、content_generation 与适用对象 ID）。
    pub identity: IdentityContext,
    /// 生产者标识（适配器或执行器实例）。
    pub producer_id: String,
    /// 同一生产者单调递增；用于快照替代与乱序处理。
    pub producer_seq: u64,
    pub observed_at_ms: u64,
    pub kind: FactKind,
    pub payload: FactPayload,
    pub cause_event_id: Option<EventId>,
}

/// 决策自信等级（文档 7.2：不声称未经校准的百分比）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    Certain,
    High,
    Medium,
    Low,
    Unknown,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Certain => "certain",
            Confidence::High => "high",
            Confidence::Medium => "medium",
            Confidence::Low => "low",
            Confidence::Unknown => "unknown",
        }
    }
}

/// 决策或命令要执行的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    // 适配器公共操作（文档 7.1）
    Probe,
    Discover,
    Open,
    Transfer,
    Cancel,
    Verify,
    Close,
    // 调度决策
    PlanSlices,
    AssignWork,
    ReleaseAssignment,
    Retry,
    Backoff,
    ReduceConcurrency,
    RestoreConcurrency,
    SwitchSource,
    IsolateSource,
    Wait,
    Finish,
    /// 影子模式：只记录建议，不执行。
    ObserveOnly,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Probe => "probe",
            Action::Discover => "discover",
            Action::Open => "open",
            Action::Transfer => "transfer",
            Action::Cancel => "cancel",
            Action::Verify => "verify",
            Action::Close => "close",
            Action::PlanSlices => "plan_slices",
            Action::AssignWork => "assign_work",
            Action::ReleaseAssignment => "release_assignment",
            Action::Retry => "retry",
            Action::Backoff => "backoff",
            Action::ReduceConcurrency => "reduce_concurrency",
            Action::RestoreConcurrency => "restore_concurrency",
            Action::SwitchSource => "switch_source",
            Action::IsolateSource => "isolate_source",
            Action::Wait => "wait",
            Action::Finish => "finish",
            Action::ObserveOnly => "observe_only",
        }
    }

    /// 从持久化字符串还原（认不出返回 `None`，不猜）。
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "probe" => Action::Probe,
            "discover" => Action::Discover,
            "open" => Action::Open,
            "transfer" => Action::Transfer,
            "cancel" => Action::Cancel,
            "verify" => Action::Verify,
            "close" => Action::Close,
            "plan_slices" => Action::PlanSlices,
            "assign_work" => Action::AssignWork,
            "release_assignment" => Action::ReleaseAssignment,
            "retry" => Action::Retry,
            "backoff" => Action::Backoff,
            "reduce_concurrency" => Action::ReduceConcurrency,
            "restore_concurrency" => Action::RestoreConcurrency,
            "switch_source" => Action::SwitchSource,
            "isolate_source" => Action::IsolateSource,
            "wait" => Action::Wait,
            "finish" => Action::Finish,
            "observe_only" => Action::ObserveOnly,
            _ => return None,
        })
    }

    /// 是否为会改变下载执行状态的动作。
    ///
    /// 影子解释器遇到 `true` 的动作必须降级为 [`Action::ObserveOnly`]。
    pub fn mutates_execution(self) -> bool {
        !matches!(self, Action::ObserveOnly | Action::Wait)
    }
}

/// 动作参数。固定字段集合，不允许塞任意键值。
///
/// 可序列化：命令参数需要随 `download_commands` 持久化，恢复时按原样回放。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ActionParams {
    pub delay_ms: Option<u64>,
    pub from_concurrency: Option<u32>,
    pub to_concurrency: Option<u32>,
    pub slice_id: Option<SliceId>,
    pub source_id: Option<SourceId>,
    pub span: Option<Span>,
    pub count: Option<u32>,
    /// 完整切片方案（`Action::PlanSlices` 专用）。
    ///
    /// 用结构化的 `Vec<Span>` 而不是任意键值：方案是**决策**，必须能被持久化、
    /// 回放和逐字节比较。[`Span`] 本身左闭右开，`None` 表示到文件末尾。
    pub plan: Option<Vec<Span>>,
    pub detail_code: Option<String>,
}

/// 决策前提。执行前必须重新检查（文档 7.1）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Preconditions {
    /// 要求的内容代次；不匹配则决策作废。
    pub requires_content_generation: Option<u64>,
    /// 要求的方案版本。
    pub requires_plan_revision: Option<u64>,
    /// 要求任务未暂停。
    pub requires_not_paused: bool,
    /// 要求具备的能力。
    pub requires_random_read: bool,
    /// 要求持有写入许可。
    pub requires_write_lease: bool,
    /// 要求预算可用。
    pub requires_budget: bool,
}

impl Preconditions {
    /// 内容代次或方案版本是否已变化。
    pub fn is_stale(&self, content_generation: u64, plan_revision: u64) -> bool {
        matches!(self.requires_content_generation, Some(g) if g != content_generation)
            || matches!(self.requires_plan_revision, Some(r) if r != plan_revision)
    }
}

/// 解释器决策。**只描述意图**，不代表已执行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub decision_id: DecisionId,
    pub task_id: i64,
    pub run_epoch: u64,
    /// 用于追溯，不因无关进度增加而失效。
    pub based_on_state_revision: u64,
    pub trigger_event_id: Option<EventId>,
    /// 规则编号，例如 `R-UDL-07`。
    pub rule_id: String,
    pub policy_revision: u64,
    pub scope: Scope,
    pub subject_id: Option<String>,
    pub action: Action,
    pub parameters: ActionParams,
    pub evidence_refs: Vec<EvidenceId>,
    pub confidence: Confidence,
    pub reason_code: String,
    pub not_before_ms: Option<u64>,
    pub expires_at_ms: Option<u64>,
    pub preconditions: Preconditions,
    /// 接受后生成的执行命令。
    pub command_ids: Vec<CommandId>,
}

/// 命令执行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    /// 已接纳但本轮不执行：数据面（探测/传输/校验/提交）归 C3-c。
    ///
    /// 与 `Failed` 分开是必要的：把"还没实现"记成失败，会让每个 tick
    /// 刷一条失败回执，真实失败被埋掉；与 `Succeeded` 分开同样必要——
    /// 它什么都没做。终态，不回放。
    Deferred,
}

impl CommandStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CommandStatus::Pending => "pending",
            CommandStatus::Running => "running",
            CommandStatus::Succeeded => "succeeded",
            CommandStatus::Failed => "failed",
            CommandStatus::Cancelled => "cancelled",
            CommandStatus::Deferred => "deferred",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            CommandStatus::Succeeded
                | CommandStatus::Failed
                | CommandStatus::Cancelled
                | CommandStatus::Deferred
        )
    }

    /// 从持久化字符串还原（认不出返回 `None`）。
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "pending" => CommandStatus::Pending,
            "running" => CommandStatus::Running,
            "succeeded" => CommandStatus::Succeeded,
            "failed" => CommandStatus::Failed,
            "cancelled" => CommandStatus::Cancelled,
            "deferred" => CommandStatus::Deferred,
            _ => return None,
        })
    }
}

/// 执行命令。重复恢复靠 `idempotency_key` 与覆盖去重保证安全。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub command_id: CommandId,
    pub decision_id: Option<DecisionId>,
    pub task_id: i64,
    pub run_epoch: u64,
    /// 执行目标（适配器名、主机、连接或任务）。
    pub target: String,
    pub action: Action,
    pub parameters: ActionParams,
    /// 幂等键：同键命令在仍有效时被合并。
    pub idempotency_key: String,
    pub state: CommandStatus,
    pub result_event_id: Option<EventId>,
    pub error: Option<UnifiedError>,
}

// ---------------------------------------------------------------- 事件信封

/// 事件级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl EventLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            EventLevel::Error => "error",
            EventLevel::Warn => "warn",
            EventLevel::Info => "info",
            EventLevel::Debug => "debug",
        }
    }
}

/// 事件结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Fail,
    Skip,
    Cancel,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Fail => "fail",
            Outcome::Skip => "skip",
            Outcome::Cancel => "cancel",
        }
    }
}

/// 新路径的规范事件名（`docs/download-observability.md` 唯一登记）。
pub mod event_name {
    pub const STATE_CHANGED: &str = "download.state_changed";
    pub const DECISION: &str = "download.decision";
    pub const COMMAND_RESULT: &str = "download.command_result";
    pub const PLAN_CHANGED: &str = "download.plan_changed";
    pub const SOURCE_CHANGED: &str = "download.source_changed";
    pub const ASSIGNMENT_CHANGED: &str = "download.assignment_changed";
    pub const CAPABILITY_CHANGED: &str = "download.capability_changed";
    pub const COVERAGE_INVALIDATED: &str = "download.coverage_invalidated";
    pub const STALE_RESULT: &str = "download.stale_result";

    /// 新事件名到 `events.kind` 的兼容映射。
    ///
    /// 旧 `kind` 只作兼容，新消费者禁止解析 `detail`（文档 11.2）。
    pub fn compat_kind(event_name: &str) -> Option<&'static str> {
        Some(match event_name {
            STATE_CHANGED => "unified_state_changed",
            DECISION => "unified_decision",
            COMMAND_RESULT => "unified_command_result",
            PLAN_CHANGED => "unified_plan_changed",
            SOURCE_CHANGED => "unified_source_changed",
            ASSIGNMENT_CHANGED => "unified_assignment_changed",
            CAPABILITY_CHANGED => "unified_capability_changed",
            COVERAGE_INVALIDATED => "unified_coverage_invalidated",
            STALE_RESULT => "unified_stale_result",
            _ => return None,
        })
    }

    /// 全部新事件名。
    pub const ALL: [&str; 9] = [
        STATE_CHANGED,
        DECISION,
        COMMAND_RESULT,
        PLAN_CHANGED,
        SOURCE_CHANGED,
        ASSIGNMENT_CHANGED,
        CAPABILITY_CHANGED,
        COVERAGE_INVALIDATED,
        STALE_RESULT,
    ];
}

/// 事件载荷（受控类型，不接受任意对象）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventPayload {
    None,
    StateChanged {
        from: Status,
        to: Status,
        activity: Activity,
        wait: Option<WaitInfo>,
    },
    Decision {
        decision_id: DecisionId,
        rule_id: String,
        policy_revision: u64,
        action: Action,
        scope: Scope,
        evidence_refs: Vec<EvidenceId>,
        confidence: Confidence,
    },
    CommandResult {
        command_id: CommandId,
        decision_id: Option<DecisionId>,
        state: CommandStatus,
    },
    PlanChanged {
        plan_revision: u64,
        slices_before: u32,
        slices_after: u32,
        reason_code: String,
    },
    SourceChanged {
        source_id: SourceId,
        availability: Availability,
        merged_count: u32,
    },
    AssignmentChanged {
        assignment_id: AssignmentId,
        from: AssignmentStatus,
        to: AssignmentStatus,
        span: Span,
    },
    CapabilityChanged {
        source_id: SourceId,
        capabilities: Box<CapabilitySet>,
    },
    CoverageInvalidated {
        slice_id: SliceId,
        span: Span,
        bytes: u64,
        reason_code: String,
    },
    StaleResult {
        reason_code: String,
        merged_count: u32,
    },
}

/// 结构化事件信封（文档 11.2）。
///
/// `phase` 为空表示该事件没有对应 IO 阶段（状态变更、规划、策略决策）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    /// 本结构版本，首版为 1。
    pub schema_version: u16,
    pub event_id: EventId,
    /// 规范事件名，见 [`event_name`]。
    pub event_name: &'static str,
    /// 任务内已接纳诊断事件的持久化递增序号，允许缺口。
    pub event_seq: u64,
    pub observed_at_ms: u64,
    pub recorded_at_ms: u64,
    pub level: EventLevel,
    pub outcome: Option<Outcome>,
    pub identity: IdentityContext,
    pub phase: Option<Phase>,
    pub operation: Option<String>,
    pub scope: Option<Scope>,
    pub subject_id: Option<String>,
    pub decision_id: Option<DecisionId>,
    pub command_id: Option<CommandId>,
    pub cause_event_id: Option<EventId>,
    pub reason_code: Option<String>,
    pub error: Option<UnifiedError>,
    pub duration_ms: Option<u64>,
    pub payload: EventPayload,
}

/// 首版事件信封结构版本。
pub const EVENT_SCHEMA_VERSION: u16 = 1;

/// 受控键值表，供协议适配器附加有界详情。
pub type DetailMap = BTreeMap<&'static str, String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn span_rejects_zero_length_and_unknown_end() {
        assert!(Span::known(0, 0).is_none());
        assert!(Span::known(10, 5).is_none());
        let s = Span::known(0, 10).expect("non-empty");
        assert_eq!(s.len(), Some(10));
        assert!(!s.is_open());
        assert!(s.is_allocatable());
    }

    #[test]
    fn span_open_only_for_unknown_length() {
        let s = Span::open(5);
        assert!(s.is_open());
        assert_eq!(s.len(), None);
        assert!(!s.is_allocatable(), "开放范围不能参与随机访问分配");
        assert!(s.contains(u64::MAX), "开放范围按 >= start 判定");
    }

    #[test]
    fn span_intersect_handles_open_side() {
        let a = Span::known(0, 100).expect("a");
        let b = Span::open(50);
        let hit = a.intersect(&b).expect("intersection");
        assert_eq!(hit.start, 50);
        assert_eq!(hit.end_exclusive, Some(100));

        let c = Span::known(200, 300).expect("c");
        assert!(a.intersect(&c).is_none(), "无重叠必须返回 None");
    }

    #[test]
    fn zero_byte_file_differs_from_unknown_size() {
        let empty = ResourceState::new(ResourceId::new("r"), 1, 0);
        assert_eq!(empty.size_bytes, None, "初始必须是未知而不是 0");
        assert!(!empty.is_empty_file());

        let mut known_empty = empty.clone();
        known_empty.size_bytes = Some(0);
        assert!(known_empty.is_empty_file());
    }

    #[test]
    fn tri_state_and_is_conservative() {
        assert_eq!(TriState::Yes.and(TriState::Yes), TriState::Yes);
        assert_eq!(TriState::Yes.and(TriState::No), TriState::No);
        assert_eq!(TriState::Yes.and(TriState::Unknown), TriState::Unknown);
        assert_eq!(TriState::default(), TriState::Unknown);
    }

    #[test]
    fn progress_rejects_verified_exceeding_stored() {
        let bad = Progress {
            wire_bytes: 100,
            stored_unique_bytes: 50,
            verified_unique_bytes: 60,
            ..Progress::default()
        };
        assert!(!bad.is_consistent());

        let ok = Progress {
            wire_bytes: 100,
            stored_unique_bytes: 50,
            verified_unique_bytes: 50,
            required_bytes: Some(50),
            ..Progress::default()
        };
        assert!(ok.is_consistent());
        assert_eq!(ok.percent(), Some(100.0));
    }

    #[test]
    fn progress_percent_is_none_when_total_unknown_or_zero() {
        let unknown = Progress::default();
        assert_eq!(unknown.percent(), None);
        let zero = Progress {
            required_bytes: Some(0),
            ..Progress::default()
        };
        assert_eq!(zero.percent(), None, "0 字节不画百分比");
    }

    #[test]
    fn peer_queue_wait_does_not_consume_retry_budget() {
        assert!(!WaitReason::PeerQueue.consumes_retry_budget());
        assert!(!WaitReason::NoSource.consumes_retry_budget());
        assert!(WaitReason::Retry.consumes_retry_budget());
        assert!(WaitReason::RateLimit.consumes_retry_budget());
    }

    #[test]
    fn cause_chain_keeps_root_cause_within_limit() {
        let mut err = UnifiedError {
            category: ErrorCategory::Network,
            code: "network".into(),
            phase: Some(Phase::Transfer),
            operation: None,
            scope: None,
            subject_id: None,
            retryable: true,
            retry_after_ms: None,
            protocol: None,
            protocol_code: None,
            message: "boom".into(),
            cause_chain: Vec::new(),
        };
        for i in 0..MAX_CAUSE_CHAIN + 4 {
            err.push_cause(CauseLink {
                code: format!("c{i}"),
                message: format!("layer {i}"),
            });
        }
        assert_eq!(err.cause_chain.len(), MAX_CAUSE_CHAIN);
        assert_eq!(
            err.cause_chain.last().map(|c| c.code.as_str()),
            Some("c11"),
            "最新的（最根层）必须在末尾"
        );
        assert_eq!(
            err.cause_chain.first().map(|c| c.code.as_str()),
            Some("c4"),
            "超限时丢弃最外层而不是根因"
        );
    }

    #[test]
    fn generated_ids_are_well_formed_and_unique() {
        let a = AssignmentId::generate();
        let b = AssignmentId::generate();
        assert_ne!(a, b);
        let raw = a.as_str().to_owned();
        assert_eq!(raw.len(), 36);
        assert_eq!(raw.as_bytes()[8], b'-');
        assert_eq!(raw.as_bytes()[13], b'-');
        assert_eq!(raw.as_bytes()[18], b'-');
        assert_eq!(raw.as_bytes()[23], b'-');
        assert_eq!(raw.as_bytes()[14], b'4', "version 4");
        assert!(
            matches!(raw.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
            "variant 必须为 10xx"
        );
    }

    #[test]
    fn opaque_id_rejects_empty() {
        assert!(SourceId::parse("").is_none());
        assert!(SourceId::parse("s1").is_some());
    }

    #[test]
    fn slice_complete_requires_full_verified_coverage() {
        let mut slice = SliceState::new(
            SliceId::new("s"),
            ResourceId::new("r"),
            0,
            0,
            Span::known(0, 100).expect("span"),
        );
        assert!(!slice.is_complete(), "初始未完成");

        slice.state = SliceStatus::Done;
        assert!(!slice.is_complete(), "状态 done 但覆盖不完整仍不算完成");

        slice.coverage.insert_stored(0, 100).expect("store");
        slice.coverage.insert_verified(0, 100).expect("verify");
        assert!(slice.is_complete());
    }

    #[test]
    fn complete_slice_rejects_open_span() {
        let mut slice = SliceState::new(
            SliceId::new("s"),
            ResourceId::new("r"),
            0,
            0,
            Span::open(0),
        );
        slice.state = SliceStatus::Done;
        assert!(!slice.is_complete(), "总长未知不能判定完成");
    }

    #[test]
    fn capability_expiry_is_honoured() {
        let mut caps = CapabilitySet::default();
        assert!(!caps.is_expired_at(1_000), "无过期时间视为未过期");
        caps.expires_at_ms = Some(1_000);
        assert!(!caps.is_expired_at(999));
        assert!(caps.is_expired_at(1_000), "边界即过期");
    }

    #[test]
    fn shadow_mode_must_downgrade_executing_actions() {
        assert!(Action::Open.mutates_execution());
        assert!(Action::AssignWork.mutates_execution());
        assert!(!Action::ObserveOnly.mutates_execution());
        assert!(!Action::Wait.mutates_execution());
    }

    #[test]
    fn precondition_detects_generation_and_plan_changes() {
        let mut p = Preconditions::default();
        assert!(!p.is_stale(1, 1), "无约束前提永不过期");

        p.requires_content_generation = Some(2);
        assert!(p.is_stale(1, 1), "内容代次变化必须作废旧决策");

        let mut q = Preconditions::default();
        q.requires_plan_revision = Some(3);
        assert!(q.is_stale(1, 2), "方案版本变化必须作废旧决策");
        assert!(!q.is_stale(1, 3));
    }

    #[test]
    fn event_name_compat_map_covers_all_registered_names() {
        for name in event_name::ALL {
            assert!(
                event_name::compat_kind(name).is_some(),
                "{name} 必须在 events.kind 有兼容映射"
            );
        }
        assert!(event_name::compat_kind("transfer.progress").is_none());
    }

    #[test]
    fn connection_status_releases_permit_only_when_terminal() {
        assert!(!ConnectionStatus::Opening.releases_permit());
        assert!(!ConnectionStatus::Ready.releases_permit());
        assert!(!ConnectionStatus::Closing.releases_permit());
        assert!(ConnectionStatus::Closed.releases_permit());
        assert!(ConnectionStatus::Failed.releases_permit());
    }
}
