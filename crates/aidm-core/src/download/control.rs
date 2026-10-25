//! 接管边界、命令回执与写入许可契约（纯逻辑，不含 IO）。
//!
//! 依据 `docs/unified-download-state-review.md` 12.2.6 的 C0：
//! - 明确 legacy / unified 的任务归属，默认继续 legacy；
//! - 固化运行身份、事实、命令、回执与写入许可的接口；
//! - 用不变量测试固定“旧轮次/旧许可不得写入”。
//!
//! 本模块**不做持久化、不建表、不接管 worker**——那些属于 C1/C2。
//! 这里只回答三个问题：
//!
//! 1. 这次写入凭据是否仍有效？（[`LeaseBook::accepts_write`]）
//! 2. 这条命令是新命令、幂等重复，还是与已接纳命令合并？（[`CommandLedger::accept`]）
//! 3. 这个任务现在归谁？（[`ControlPolicy`]）
//!
//! C0 的验收是“字段能一一对应”，不是“执行路径已启用”。

use super::model::{
    AssignmentId, Command, CommandId, CommandStatus, EventId, SliceId, Span, UnifiedError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- 执行模式

/// 执行模式。一个任务同一时刻只能由一种路径拥有（文档 12.2）。
///
/// C0 只定义契约与默认值：**默认一律 legacy**，unified 需要显式登记后才可能接管，
/// 且本批不提供任何切换到 unified 的入口。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// 现行 worker 路径。
    Legacy,
    /// 统一协调器路径。
    Unified,
}

impl ExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionMode::Legacy => "legacy",
            ExecutionMode::Unified => "unified",
        }
    }

    /// 从持久化字符串还原（认不出返回 `None`，不猜）。
    ///
    /// 认不出时调用方应回退到 [`ExecutionMode::default_for_new_task`]：
    /// 模式是持久化状态，读不懂就按默认 legacy，**不允许**猜成 unified。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "legacy" => Some(ExecutionMode::Legacy),
            "unified" => Some(ExecutionMode::Unified),
            _ => None,
        }
    }

    /// C0 的默认：新任务、未知任务、无法判定时都归 legacy。
    ///
    /// 显式返回一个常量而不是 `Default`，是为了让“默认 legacy”在代码里可被搜索到。
    pub fn default_for_new_task() -> Self {
        ExecutionMode::Legacy
    }

    /// 是否允许写入下载文件。
    ///
    /// 两种模式都允许，但**凭据来源不同**：legacy 由 worker 自己的线程持有，
    /// unified 必须持有 [`WriteLease`]。这条区分正是 C2 的验收点。
    pub fn allows_file_write(self) -> bool {
        matches!(self, ExecutionMode::Legacy | ExecutionMode::Unified)
    }
}

/// 任务归属查询结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// 归 legacy，unified 不得写。
    Legacy,
    /// 归 unified，legacy 不得写。
    Unified,
    /// 两种记录冲突：必须停下并上报，不能猜一个。
    Conflict { recorded: ExecutionMode },
}

/// 任务归属判定。
///
/// C0 只做**纯判定**：给定“持久化记录”（可能为空）与“本次是否要求 unified”，
/// 返回该由谁执行。真实记录读取在 C1。
pub fn resolve_ownership(
    recorded: Option<ExecutionMode>,
    unified_requested: bool,
) -> Ownership {
    match (recorded, unified_requested) {
        // 已有记录：以记录为准；若本次要求另一种模式，就是冲突，不能硬切。
        (Some(ExecutionMode::Legacy), false) => Ownership::Legacy,
        (Some(ExecutionMode::Unified), true) => Ownership::Unified,
        (Some(recorded), _) => Ownership::Conflict { recorded },
        // 无记录：默认 legacy；显式要求 unified 时也必须先“登记”再接管，
        // 不能在无记录状态下直接跑 unified（否则重启后无人知道谁在写）。
        (None, false) => Ownership::Legacy,
        (None, true) => Ownership::Conflict {
            recorded: ExecutionMode::Legacy,
        },
    }
}

// ---------------------------------------------------------------- 写入许可

/// 一次子区间分配的写入凭据。
///
/// 字段与文档 4.4 的 `AssignmentState` 对齐：`run_epoch`、`content_generation`、
/// `lease_revision` 三者任一过期都必须拒绝写入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteLease {
    pub assignment_id: AssignmentId,
    pub slice_id: SliceId,
    pub lease_revision: u64,
    pub run_epoch: u64,
    pub content_generation: u64,
    /// 本次获准写入的子区间。
    pub span: Span,
}

/// 写入判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteDecision {
    Accept,
    /// 运行轮次已过期（任务被重新接管）。
    StaleEpoch { current: u64 },
    /// 内容代次已过期（目标内容变了）。
    StaleGeneration { current: u64 },
    /// 许可版本已过期（同一分配被重新签发或被撤销后重发）。
    StaleLease { current: u64 },
    /// 许可已被撤销（暂停、删除、接管）。
    Revoked,
    /// 账本里没有这次分配。
    Unknown,
    /// 写入范围超出许可范围。
    OutOfRange,
}

impl WriteDecision {
    /// 是否允许继续写盘。
    pub fn allows_write(&self) -> bool {
        matches!(self, WriteDecision::Accept)
    }

    /// 供诊断/事件使用的稳定原因码。
    pub fn code(&self) -> &'static str {
        match self {
            WriteDecision::Accept => "accept",
            WriteDecision::StaleEpoch { .. } => "stale_epoch",
            WriteDecision::StaleGeneration { .. } => "stale_generation",
            WriteDecision::StaleLease { .. } => "stale_lease",
            WriteDecision::Revoked => "revoked",
            WriteDecision::Unknown => "unknown_lease",
            WriteDecision::OutOfRange => "out_of_range",
        }
    }
}

/// 写入许可账本。
///
/// 谁持有它，谁就在“当前运行轮次”的视角下判断写入是否合法。它**不做持久化**：
/// C1 负责把 `lease_revision` 与 `run_epoch` 落库；C2 负责在协调器里独占持有。
#[derive(Debug, Clone, Default)]
pub struct LeaseBook {
    next_revision: u64,
    active: BTreeMap<AssignmentId, WriteLease>,
    terminated: BTreeSet<AssignmentId>,
    /// 当前运行轮次与内容代次；签发许可时写入，用于拒绝陈旧写入。
    current_epoch: u64,
    current_generation: u64,
    /// 已关闭（暂停/取消/交接中）：此时**新签发的许可一律作废**。
    ///
    /// 不设这个标志就会留一个窗口：暂停先撤销了现有许可、宣布已停止，
    /// 随后一个迟到的 `issue`（段线程刚起来、单连接路径刚走到签发处）又拿到
    /// 有效凭据，于是“暂停了还在下载”。P1-01 修复的就是这个窗口。
    closed: bool,
}

impl LeaseBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// 开始新一轮运行：撤销全部许可，轮次与内容代次更新，并**重新开放签发**。
    ///
    /// 文档 4.2：旧轮次的写入必须被拒，不能只靠“事件被忽略”。
    pub fn begin_epoch(&mut self, run_epoch: u64, content_generation: u64) {
        self.revoke_all();
        self.closed = false;
        self.current_epoch = run_epoch;
        self.current_generation = content_generation;
    }

    /// 关闭签发并撤销现有许可。返回被撤销的分配数量。
    ///
    /// 关闭之后 [`LeaseBook::issue`] 仍会返回一个 `WriteLease`（调用方签名不变），
    /// 但它立刻处于「已终止」状态，[`LeaseBook::accepts_write`] 只会返回 `Revoked`。
    pub fn close(&mut self) -> usize {
        self.closed = true;
        self.revoke_all()
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn current_generation(&self) -> u64 {
        self.current_generation
    }

    /// 签发一份写入许可。同一分配重新签发会得到更高版本，旧版本随即失效。
    pub fn issue(
        &mut self,
        assignment_id: AssignmentId,
        slice_id: SliceId,
        span: Span,
    ) -> WriteLease {
        self.next_revision += 1;
        let lease = WriteLease {
            assignment_id: assignment_id.clone(),
            slice_id,
            lease_revision: self.next_revision,
            run_epoch: self.current_epoch,
            content_generation: self.current_generation,
            span,
        };
        if self.closed {
            // 关闭期间签发的凭据一律作废，避免“暂停后再拿到写权”。
            self.terminated.insert(assignment_id);
            return lease;
        }
        self.terminated.remove(&assignment_id);
        self.active.insert(assignment_id, lease.clone());
        lease
    }

    /// 撤销单个许可（分配结束、换源、暂停）。
    pub fn revoke(&mut self, assignment_id: &AssignmentId) -> bool {
        let removed = self.active.remove(assignment_id).is_some();
        if removed {
            self.terminated.insert(assignment_id.clone());
        }
        removed
    }

    /// 撤销全部许可（暂停、删除、接管交接）。
    ///
    /// 返回被撤销的分配数量，供“暂停已完成”的确认条件使用。
    pub fn revoke_all(&mut self) -> usize {
        let n = self.active.len();
        for id in self.active.keys() {
            self.terminated.insert(id.clone());
        }
        self.active.clear();
        n
    }

    /// 是否仍有活跃许可。暂停/删除只有在它为 0 时才能对外宣布“已停止写入”。
    pub fn active_len(&self) -> usize {
        self.active.len()
    }

    /// 判断一次写入是否被允许。
    ///
    /// 检查顺序固定：撤销 → 轮次 → 内容代次 → 许可版本 → 范围。
    /// 顺序本身是契约：先判“最根本的失效”，诊断码才稳定。
    pub fn accepts_write(&self, lease: &WriteLease, start: u64, end_exclusive: u64) -> WriteDecision {
        let Some(current) = self.active.get(&lease.assignment_id) else {
            return if self.terminated.contains(&lease.assignment_id) {
                WriteDecision::Revoked
            } else {
                WriteDecision::Unknown
            };
        };
        if lease.run_epoch != self.current_epoch {
            return WriteDecision::StaleEpoch {
                current: self.current_epoch,
            };
        }
        if lease.content_generation != self.current_generation {
            return WriteDecision::StaleGeneration {
                current: self.current_generation,
            };
        }
        if lease.lease_revision != current.lease_revision {
            return WriteDecision::StaleLease {
                current: current.lease_revision,
            };
        }
        // 范围必须落在许可区间内；零长度或越界一律拒绝。
        if start >= end_exclusive {
            return WriteDecision::OutOfRange;
        }
        match current.span.end_exclusive {
            Some(end) if start >= current.span.start && end_exclusive <= end => {
                WriteDecision::Accept
            }
            None if start >= current.span.start => WriteDecision::Accept,
            _ => WriteDecision::OutOfRange,
        }
    }
}

// ---------------------------------------------------------------- 写入闸门

/// 写入闸门：**唯一真实写盘检查点**，并提供“撤销后确已静止”的确认。
///
/// [`LeaseBook`] 只能回答「这次写入合法吗」，回答不了「撤销之后还有没有写入在路上」。
/// 暂停/删除只有在 `in_flight == 0` 时才能对外宣布“已停止写入”，所以要把
/// 「检查许可」与「写入进行中」这两步放进同一把锁里原子完成：
///
/// - [`WriteGate::check`] 通过后返回 [`WriteTicket`]，Drop 时才代表写入真的结束；
/// - [`WriteGate::revoke_all_quiescent`] 在同一把锁里撤销，然后等 `in_flight` 归零。
///
/// 这样就不存在“检查通过 → 许可被撤销 → 仍继续写”的窗口：撤销必须等写入退出。
#[derive(Debug)]
pub struct WriteGate {
    state: Mutex<GateState>,
    idle: Condvar,
}

#[derive(Debug)]
struct GateState {
    book: LeaseBook,
    /// 已通过检查、尚未结束的写入数。
    in_flight: usize,
    /// 因静止等待超时被强制作废的写入数（诊断用，不参与判定）。
    stragglers: u64,
}

/// 一次已获准的写入。**Drop 即视为写入结束**。
///
/// 故意不实现 `Clone`/`Copy` 且 `!Send`：许可凭据按线程持有，跨线程传递会让
/// “写入结束”的记账与真实线程脱钩。
#[derive(Debug)]
pub struct WriteTicket<'a> {
    gate: &'a WriteGate,
    _not_send: PhantomData<*const ()>,
}

impl Drop for WriteTicket<'_> {
    fn drop(&mut self) {
        let mut s = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        s.in_flight = s.in_flight.saturating_sub(1);
        if s.in_flight == 0 {
            self.gate.idle.notify_all();
        }
    }
}

impl Default for WriteGate {
    fn default() -> Self {
        Self::new()
    }
}

impl WriteGate {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(GateState {
                book: LeaseBook::new(),
                in_flight: 0,
                stragglers: 0,
            }),
            idle: Condvar::new(),
        }
    }

    /// 开始新一轮运行：撤销全部许可并更新轮次/内容代次。
    ///
    /// 与 [`WriteGate::revoke_all_quiescent`] 不同，这里**不等待**在途写入：
    /// 它用于“已经确认静止之后”的轮次切换，等待由调用方在更上层完成。
    pub fn begin_epoch(&self, run_epoch: u64, content_generation: u64) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.book.begin_epoch(run_epoch, content_generation);
    }

    /// 在锁内访问许可账本（签发、撤销单个许可）。
    pub fn with_book<R>(&self, f: impl FnOnce(&mut LeaseBook) -> R) -> R {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut s.book)
    }

    /// 签发许可。等价于 `with_book(|b| b.issue(..))`。
    pub fn issue(&self, assignment_id: AssignmentId, slice_id: SliceId, span: Span) -> WriteLease {
        self.with_book(|b| b.issue(assignment_id, slice_id, span))
    }

    pub fn current_epoch(&self) -> u64 {
        self.with_book(|b| b.current_epoch())
    }

    pub fn current_generation(&self) -> u64 {
        self.with_book(|b| b.current_generation())
    }

    /// 只读预检：不占 `in_flight`。
    ///
    /// 用于“这次尝试还值得开始吗”——签发之后、开跑之前先问一次，
    /// 避免为一个注定被拒的传输白建连接（P2-03）。
    pub fn accepts(&self, lease: &WriteLease, start: u64, end_exclusive: u64) -> bool {
        self.with_book(|b| b.accepts_write(lease, start, end_exclusive).allows_write())
    }

    /// 写入前检查。通过则返回票据，Drop 时记账“写入结束”。
    ///
    /// 检查与 `in_flight += 1` 在同一把锁内完成，撤销方不可能插在中间。
    pub fn check(
        &self,
        lease: &WriteLease,
        start: u64,
        end_exclusive: u64,
    ) -> Result<WriteTicket<'_>, WriteDecision> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match s.book.accepts_write(lease, start, end_exclusive) {
            WriteDecision::Accept => {
                s.in_flight += 1;
                Ok(WriteTicket {
                    gate: self,
                    _not_send: PhantomData,
                })
            }
            other => Err(other),
        }
    }

    /// 撤销全部许可并等待在途写入归零。
    ///
    /// 返回 `None` 表示等待超时：仍有写入没退出来，调用方**不得**宣布“已停止写入”，
    /// 只能把任务保持在停止中并上报原因。超时的在途写入数记入 `stragglers`。
    pub fn revoke_all_quiescent(&self, timeout: Duration) -> Result<usize, QuiesceTimeout> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // 先关闭签发，再撤销：顺序不能反。反了的话，撤销与关闭之间那一瞬
        // 仍可能有人拿到有效凭据（P1-01）。
        let revoked = s.book.close();
        let deadline = Instant::now() + timeout;
        while s.in_flight > 0 {
            let now = Instant::now();
            if now >= deadline {
                s.stragglers = s.stragglers.saturating_add(s.in_flight as u64);
                return Err(QuiesceTimeout {
                    revoked,
                    still_running: s.in_flight,
                });
            }
            let (guard, _res) = self
                .idle
                .wait_timeout(s, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            s = guard;
        }
        Ok(revoked)
    }

    /// 给一份许可配一个自动撤销器：Drop 时把它从账本里摘掉。
    pub fn reaper(self: &Arc<Self>, lease: &WriteLease) -> LeaseReaper {
        LeaseReaper {
            gate: Arc::clone(self),
            assignment_id: lease.assignment_id.clone(),
        }
    }

    /// 当前在途写入数。
    pub fn in_flight(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).in_flight
    }

    pub fn active_leases(&self) -> usize {
        self.with_book(|b| b.active_len())
    }

    /// 因静止等待超时而遗留的写入数（诊断用）。
    pub fn stragglers(&self) -> u64 {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).stragglers
    }
}

/// 许可的自动撤销（RAII）。
///
/// 用在**归属结束**的地方：段线程退出、单连接下载返回、fastdl 收尾。
/// 暂停/取消不走它——那些路径要 `revoke_all_quiescent` 统一撤销并等静止。
///
/// 没有它，每次签发都会在账本里留下一条永不释放的分配：
/// `active_len` 随时间线性增长，暂停时“撤销了几个”也就失去意义。
///
/// 持有 `Arc<WriteGate>` 而不是引用：段线程里的 `SegmentArgs` 后续还会被可变借用，
/// 借用型 guard 会和它冲突；持有 Arc 也让 guard 的生命周期与 args 解耦。
#[derive(Debug, Clone)]
pub struct LeaseReaper {
    gate: Arc<WriteGate>,
    assignment_id: AssignmentId,
}

impl Drop for LeaseReaper {
    fn drop(&mut self) {
        self.gate.with_book(|b| {
            b.revoke(&self.assignment_id);
        });
    }
}

/// 静止等待超时。带上现场信息，便于在状态里如实登记“没停干净”。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuiesceTimeout {
    pub revoked: usize,
    pub still_running: usize,
}

impl QuiesceTimeout {
    /// 供诊断/事件使用的稳定原因码。
    pub fn code(&self) -> &'static str {
        "quiesce_timeout"
    }
}

// ---------------------------------------------------------------- 命令账本

/// 命令接纳结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// 新命令，可以执行。
    Accepted,
    /// 与一条未完成的同幂等键命令合并：**不重复执行副作用**。
    Merged(CommandId),
    /// 同 `command_id` 已执行过（重复投递），只补回执，不再执行。
    Duplicate(CommandId),
    /// 命令属于旧轮次，直接拒收。
    StaleEpoch { incoming: u64, current: u64 },
}

/// 命令账本里的一条记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRecord {
    pub command: Command,
    pub attempts: u32,
    pub result_event_id: Option<EventId>,
    pub error: Option<UnifiedError>,
}

/// 命令账本：幂等接纳、状态推进与回执。
///
/// 文档 7.1：同一原因形成的重复事件不能无限生成相同命令；每次**实际重试**
/// 产生新的 `command_id` 并消耗预算。本类型只保证“重复投递不重复副作用”。
#[derive(Debug, Clone, Default)]
pub struct CommandLedger {
    by_id: BTreeMap<CommandId, CommandRecord>,
    by_key: BTreeMap<String, CommandId>,
    current_epoch: u64,
}

impl CommandLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// 切换运行轮次：未完成命令全部作废。
    ///
    /// 返回被作废的命令数量。旧轮次的命令**不回放**给新轮次。
    pub fn begin_epoch(&mut self, run_epoch: u64) -> usize {
        self.current_epoch = run_epoch;
        let mut cancelled = 0;
        for rec in self.by_id.values_mut() {
            if !rec.command.state.is_terminal() {
                rec.command.state = CommandStatus::Cancelled;
                cancelled += 1;
            }
        }
        cancelled
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// 幂等接纳一条命令。
    pub fn accept(&mut self, command: Command) -> AcceptOutcome {
        if command.run_epoch != self.current_epoch {
            return AcceptOutcome::StaleEpoch {
                incoming: command.run_epoch,
                current: self.current_epoch,
            };
        }
        // 同一个 command_id：已结束就是重复投递，未结束就是合并。
        if let Some(rec) = self.by_id.get(&command.command_id) {
            return if rec.command.state.is_terminal() {
                AcceptOutcome::Duplicate(command.command_id.clone())
            } else {
                AcceptOutcome::Merged(command.command_id.clone())
            };
        }
        // 同一幂等键：只要还有未完成的那条，就合并到它上面。
        if let Some(existing) = self.by_key.get(&command.idempotency_key) {
            if let Some(rec) = self.by_id.get(existing) {
                if !rec.command.state.is_terminal() {
                    return AcceptOutcome::Merged(existing.clone());
                }
            }
        }
        self.by_key
            .insert(command.idempotency_key.clone(), command.command_id.clone());
        self.by_id.insert(
            command.command_id.clone(),
            CommandRecord {
                command,
                attempts: 1,
                result_event_id: None,
                error: None,
            },
        );
        AcceptOutcome::Accepted
    }

    /// 标记开始执行。返回 `false` 表示命令不存在或已结束。
    pub fn mark_running(&mut self, id: &CommandId) -> bool {
        match self.by_id.get_mut(id) {
            Some(rec) if rec.command.state == CommandStatus::Pending => {
                rec.command.state = CommandStatus::Running;
                true
            }
            _ => false,
        }
    }

    /// 写回执（成功/失败/取消）。重复结束不会覆盖第一条结果。
    pub fn complete(
        &mut self,
        id: &CommandId,
        state: CommandStatus,
        result_event_id: Option<EventId>,
        error: Option<UnifiedError>,
    ) -> bool {
        match self.by_id.get_mut(id) {
            Some(rec) if !rec.command.state.is_terminal() => {
                rec.command.state = state;
                rec.result_event_id = result_event_id;
                rec.error = error;
                true
            }
            _ => false,
        }
    }

    pub fn record(&self, id: &CommandId) -> Option<&CommandRecord> {
        self.by_id.get(id)
    }

    /// 未完成的命令（含 `Pending` 与 `Running`）。
    pub fn pending(&self) -> impl Iterator<Item = &CommandRecord> {
        self.by_id
            .values()
            .filter(|r| !r.command.state.is_terminal())
    }

    /// 已完成的命令数（诊断/测试用）。
    pub fn finished_len(&self) -> usize {
        self.by_id
            .values()
            .filter(|r| r.command.state.is_terminal())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::model::{Action, ActionParams};

    fn lease_book() -> LeaseBook {
        let mut book = LeaseBook::new();
        book.begin_epoch(3, 7);
        book
    }

    fn assignment() -> AssignmentId {
        AssignmentId::new("a-1")
    }

    fn slice() -> SliceId {
        SliceId::new("s-1")
    }

    fn span(start: u64, end: u64) -> Span {
        Span::known(start, end).expect("span")
    }

    #[test]
    fn default_mode_is_legacy() {
        assert_eq!(ExecutionMode::default_for_new_task(), ExecutionMode::Legacy);
        assert_eq!(ExecutionMode::Legacy.as_str(), "legacy");
        assert!(ExecutionMode::Legacy.allows_file_write());
    }

    #[test]
    fn ownership_defaults_to_legacy_and_refuses_silent_switch() {
        assert_eq!(resolve_ownership(None, false), Ownership::Legacy);
        // 无记录却要求 unified：必须先登记再接管，不能直接跑。
        assert!(matches!(
            resolve_ownership(None, true),
            Ownership::Conflict { .. }
        ));
        assert_eq!(
            resolve_ownership(Some(ExecutionMode::Unified), true),
            Ownership::Unified
        );
        // 记录是 legacy，却要求 unified：冲突，不得硬切。
        assert!(matches!(
            resolve_ownership(Some(ExecutionMode::Legacy), true),
            Ownership::Conflict { .. }
        ));
        // 记录是 unified，却按 legacy 跑：同样冲突。
        assert!(matches!(
            resolve_ownership(Some(ExecutionMode::Unified), false),
            Ownership::Conflict { .. }
        ));
    }

    #[test]
    fn issued_lease_accepts_writes_inside_its_span() {
        let mut book = lease_book();
        let lease = book.issue(assignment(), slice(), span(100, 200));
        assert_eq!(book.accepts_write(&lease, 100, 200), WriteDecision::Accept);
        assert_eq!(book.accepts_write(&lease, 150, 160), WriteDecision::Accept);
    }

    #[test]
    fn writes_outside_the_lease_span_are_refused() {
        let mut book = lease_book();
        let lease = book.issue(assignment(), slice(), span(100, 200));
        assert_eq!(
            book.accepts_write(&lease, 50, 120),
            WriteDecision::OutOfRange,
            "起点越界必须拒绝，不能写进别人的区间"
        );
        assert_eq!(
            book.accepts_write(&lease, 180, 220),
            WriteDecision::OutOfRange
        );
        assert_eq!(
            book.accepts_write(&lease, 120, 120),
            WriteDecision::OutOfRange,
            "零长度写入不合法"
        );
    }

    #[test]
    fn stale_epoch_write_is_refused() {
        let mut book = lease_book();
        let lease = book.issue(assignment(), slice(), span(0, 100));
        // 新一轮运行：同一分配即使重新签发，旧凭据也必须失效。
        book.begin_epoch(4, 7);
        assert!(matches!(
            book.accepts_write(&lease, 0, 10),
            WriteDecision::Revoked
        ));
    }

    #[test]
    fn stale_generation_write_is_refused() {
        let mut book = lease_book();
        let lease = book.issue(assignment(), slice(), span(0, 100));
        // 只改内容代次（目标内容变了），轮次不变。
        book.begin_epoch(3, 8);
        assert!(matches!(
            book.accepts_write(&lease, 0, 10),
            WriteDecision::Revoked
        ));
    }

    #[test]
    fn generation_change_without_reissue_is_rejected() {
        let mut book = LeaseBook::new();
        book.begin_epoch(1, 1);
        let lease = book.issue(assignment(), slice(), span(0, 100));
        // 直接改代次而不重新签发：旧凭据必须被拒。
        // 这里返回 `StaleGeneration`（而不是 `Revoked`）：诊断需要知道**为什么**失效，
        // 暂停/撤销走 `Revoked`，内容代次变化走 `StaleGeneration`。
        book.current_generation = 2;
        assert_eq!(
            book.accepts_write(&lease, 0, 10),
            WriteDecision::StaleGeneration { current: 2 }
        );
    }

    #[test]
    fn reissuing_a_lease_invalidates_the_previous_revision() {
        let mut book = lease_book();
        let old = book.issue(assignment(), slice(), span(0, 100));
        let new = book.issue(assignment(), slice(), span(0, 100));
        assert!(new.lease_revision > old.lease_revision);
        assert_eq!(
            book.accepts_write(&old, 0, 10),
            WriteDecision::StaleLease {
                current: new.lease_revision
            },
            "旧版本许可不得继续写"
        );
        assert_eq!(book.accepts_write(&new, 0, 10), WriteDecision::Accept);
    }

    #[test]
    fn revoke_blocks_further_writes_and_is_idempotent() {
        let mut book = lease_book();
        let lease = book.issue(assignment(), slice(), span(0, 100));
        assert!(book.revoke(&assignment()));
        assert_eq!(
            book.accepts_write(&lease, 0, 10),
            WriteDecision::Revoked
        );
        assert!(!book.revoke(&assignment()), "重复撤销返回 false");
        assert_eq!(book.active_len(), 0);
    }

    #[test]
    fn revoke_all_reports_how_many_leases_were_dropped() {
        let mut book = lease_book();
        book.issue(AssignmentId::new("a-1"), slice(), span(0, 10));
        book.issue(AssignmentId::new("a-2"), slice(), span(10, 20));
        assert_eq!(book.active_len(), 2);
        assert_eq!(book.revoke_all(), 2);
        assert_eq!(book.active_len(), 0, "暂停后必须没有活跃许可");
    }

    #[test]
    fn unknown_assignment_is_reported_separately_from_revoked() {
        let book = lease_book();
        let fake = WriteLease {
            assignment_id: AssignmentId::new("never-issued"),
            slice_id: slice(),
            lease_revision: 1,
            run_epoch: 3,
            content_generation: 7,
            span: span(0, 10),
        };
        assert_eq!(
            book.accepts_write(&fake, 0, 10),
            WriteDecision::Unknown,
            "未知分配与已撤销必须可区分"
        );
    }

    #[test]
    fn reaper_removes_the_lease_so_ledgers_do_not_leak() {
        // P2-01：签发点没有对应撤销时，每次分配都会永留在账本里。
        let gate = std::sync::Arc::new(WriteGate::new());
        gate.begin_epoch(1, 1);
        for i in 0..5 {
            let lease = gate.issue(
                AssignmentId::new(format!("a-{i}")),
                slice(),
                span(0, 100),
            );
            assert_eq!(gate.active_leases(), 1);
            drop(gate.reaper(&lease));
            assert_eq!(gate.active_leases(), 0, "Drop 必须把许可摘掉");
        }
        // 摘掉之后旧凭据仍然写不了（撤过的号不能复活）。
        let lease = gate.issue(assignment(), slice(), span(0, 100));
        let reaper = gate.reaper(&lease);
        drop(reaper);
        assert_eq!(
            gate.check(&lease, 0, 10).unwrap_err(),
            WriteDecision::Revoked
        );
    }

    #[test]
    fn a_lease_issued_after_close_is_dead_on_arrival() {
        // P1-01 反例：暂停先撤销许可并宣布已停止，随后迟到的 `issue`
        // 又拿到有效凭据 → “暂停了还在下载”。
        let mut book = LeaseBook::new();
        book.begin_epoch(3, 7);
        assert_eq!(book.close(), 0, "关闭时没有活跃许可");

        let late = book.issue(assignment(), slice(), span(0, 100));
        assert_eq!(
            book.accepts_write(&late, 0, 10),
            WriteDecision::Revoked,
            "关闭期间签发的许可必须当场作废"
        );

        // 新一轮开始后签发恢复。
        book.begin_epoch(4, 7);
        let fresh = book.issue(assignment(), slice(), span(0, 100));
        assert_eq!(book.accepts_write(&fresh, 0, 10), WriteDecision::Accept);
    }

    #[test]
    fn late_issue_through_the_gate_cannot_write() {
        let gate = WriteGate::new();
        gate.begin_epoch(1, 1);
        gate.revoke_all_quiescent(Duration::from_millis(50))
            .expect("quiesce");

        let late = gate.issue(assignment(), slice(), span(0, 100));
        assert_eq!(
            gate.check(&late, 0, 10).unwrap_err(),
            WriteDecision::Revoked,
            "静止确认之后再签发的许可不得放行写入"
        );
        assert_eq!(
            gate.in_flight(),
            0,
            "被拒的检查不能留下在途计数"
        );
    }

    #[test]
    fn issuing_after_quiesce_then_begin_epoch_works_again() {
        // 暂停 → 恢复：同一任务必须能重新获得写权，否则 resume 会永久写不了。
        let gate = WriteGate::new();
        gate.begin_epoch(1, 1);
        gate.revoke_all_quiescent(Duration::from_millis(50))
            .expect("quiesce");
        gate.begin_epoch(2, 1);

        let lease = gate.issue(assignment(), slice(), span(0, 100));
        assert!(gate.check(&lease, 0, 10).is_ok(), "恢复后应能继续写");
    }

    #[test]
    fn gate_refuses_writes_whose_lease_was_revoked() {
        let gate = WriteGate::new();
        gate.begin_epoch(1, 1);
        let lease = gate.issue(assignment(), slice(), span(0, 100));
        assert!(gate.check(&lease, 0, 10).is_ok());
        gate.with_book(|b| b.revoke(&assignment()));
        assert_eq!(
            gate.check(&lease, 0, 10).unwrap_err(),
            WriteDecision::Revoked,
            "撤销后不得再放行写入"
        );
    }

    #[test]
    fn revoke_all_waits_for_in_flight_writes_before_reporting_stopped() {
        // C2 验收：许可撤销与正在进行的写入之间不能有竞态——
        // 撤销必须等写入真的退出，才好对外宣布“已停止写入”。
        let gate = WriteGate::new();
        gate.begin_epoch(1, 1);
        let lease = gate.issue(assignment(), slice(), span(0, 100));
        let ticket = gate.check(&lease, 0, 10).expect("accept");
        assert_eq!(gate.in_flight(), 1);

        let done_at = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sink = done_at.clone();
        std::thread::scope(|s| {
            let h = s.spawn(|| gate.revoke_all_quiescent(Duration::from_secs(5)));
            std::thread::sleep(Duration::from_millis(80));
            // 撤销已发出，但写入还没退出：此时不得认为已静止。
            assert_eq!(gate.in_flight(), 1, "写入仍在进行");
            *sink.lock().unwrap() = Some(Instant::now());
            drop(ticket);
            assert_eq!(h.join().unwrap(), Ok(1));
        });
        assert_eq!(gate.in_flight(), 0);
        assert_eq!(gate.stragglers(), 0);
    }

    #[test]
    fn quiesce_timeout_is_reported_instead_of_pretending_stopped() {
        let gate = WriteGate::new();
        gate.begin_epoch(1, 1);
        let lease = gate.issue(assignment(), slice(), span(0, 100));
        let ticket = gate.check(&lease, 0, 10).expect("accept");

        let err = gate
            .revoke_all_quiescent(Duration::from_millis(30))
            .expect_err("未退出的写入必须让静止确认失败");
        assert_eq!(
            err,
            QuiesceTimeout {
                revoked: 1,
                still_running: 1
            }
        );
        assert_eq!(err.code(), "quiesce_timeout");
        assert_eq!(gate.stragglers(), 1, "超时必须在诊断里留痕");
        // 撤销本身已生效：新检查一律拒绝。
        assert_eq!(
            gate.check(&lease, 0, 10).unwrap_err(),
            WriteDecision::Revoked
        );
        drop(ticket);
    }

    #[test]
    fn check_and_in_flight_are_atomic_under_concurrency() {
        // 并发压力：任何一次“检查通过”都必须对应一次可观测的在途写入，
        // 撤销返回 Ok 之后绝不能再有 check 通过。
        let gate = std::sync::Arc::new(WriteGate::new());
        gate.begin_epoch(1, 1);
        let lease = gate.issue(assignment(), slice(), span(0, 100));
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let leaked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        std::thread::scope(|s| {
            for _ in 0..4 {
                let gate = gate.clone();
                let lease = lease.clone();
                let accepted = accepted.clone();
                let leaked = leaked.clone();
                let stop = stop.clone();
                s.spawn(move || {
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        match gate.check(&lease, 0, 10) {
                            Ok(ticket) => {
                                accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                drop(ticket);
                            }
                            Err(_) => {
                                leaked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                });
            }
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(
                gate.revoke_all_quiescent(Duration::from_secs(5)),
                Ok(1),
                "撤销必须成功等到静止"
            );
            let before = accepted.load(std::sync::atomic::Ordering::Relaxed);
            assert_eq!(gate.in_flight(), 0, "撤销返回时不得有在途写入");
            std::thread::sleep(Duration::from_millis(20));
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            assert_eq!(
                accepted.load(std::sync::atomic::Ordering::Relaxed),
                before,
                "撤销返回后不得再有写入被放行"
            );
        });
        assert!(leaked.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }

    fn command(id: &str, key: &str, epoch: u64) -> Command {
        Command {
            command_id: CommandId::new(id),
            decision_id: None,
            task_id: 1,
            run_epoch: epoch,
            target: "http".to_owned(),
            action: Action::Open,
            parameters: ActionParams::default(),
            idempotency_key: key.to_owned(),
            state: CommandStatus::Pending,
            result_event_id: None,
            error: None,
        }
    }

    fn ledger() -> CommandLedger {
        let mut l = CommandLedger::new();
        l.begin_epoch(3);
        l
    }

    #[test]
    fn same_command_id_is_not_executed_twice() {
        let mut l = ledger();
        assert_eq!(
            l.accept(command("c1", "k1", 3)),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            l.accept(command("c1", "k1", 3)),
            AcceptOutcome::Merged(CommandId::new("c1")),
            "未完成时重复投递合并到同一条"
        );
        assert!(l.complete(&CommandId::new("c1"), CommandStatus::Succeeded, None, None));
        assert_eq!(
            l.accept(command("c1", "k1", 3)),
            AcceptOutcome::Duplicate(CommandId::new("c1")),
            "已完成后重复投递只补回执，不再执行"
        );
        assert_eq!(l.finished_len(), 1);
    }

    #[test]
    fn same_idempotency_key_merges_unless_finished() {
        let mut l = ledger();
        assert_eq!(
            l.accept(command("c1", "same-key", 3)),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            l.accept(command("c2", "same-key", 3)),
            AcceptOutcome::Merged(CommandId::new("c1")),
            "同幂等键的未完成命令必须合并，避免重复副作用"
        );
        // 结束后同键可以重新接纳（新的实际尝试）。
        l.complete(&CommandId::new("c1"), CommandStatus::Failed, None, None);
        assert_eq!(
            l.accept(command("c3", "same-key", 3)),
            AcceptOutcome::Accepted
        );
    }

    #[test]
    fn stale_epoch_commands_are_rejected_not_replayed() {
        let mut l = ledger();
        assert!(matches!(
            l.accept(command("c1", "k1", 2)),
            AcceptOutcome::StaleEpoch { incoming: 2, current: 3 }
        ));
    }

    #[test]
    fn begin_epoch_cancels_unfinished_commands() {
        let mut l = ledger();
        l.accept(command("c1", "k1", 3));
        l.accept(command("c2", "k2", 3));
        l.complete(&CommandId::new("c1"), CommandStatus::Succeeded, None, None);
        let cancelled = l.begin_epoch(4);
        assert_eq!(cancelled, 1, "只作废未完成的命令");
        assert_eq!(
            l.record(&CommandId::new("c2")).expect("c2").command.state,
            CommandStatus::Cancelled
        );
        assert_eq!(
            l.record(&CommandId::new("c1")).expect("c1").command.state,
            CommandStatus::Succeeded,
            "已完成命令保留原回执"
        );
    }

    #[test]
    fn completing_twice_keeps_the_first_receipt() {
        let mut l = ledger();
        l.accept(command("c1", "k1", 3));
        assert!(l.complete(&CommandId::new("c1"), CommandStatus::Succeeded, None, None));
        assert!(
            !l.complete(&CommandId::new("c1"), CommandStatus::Failed, None, None),
            "第二次结束必须被拒绝，不能把成功翻成失败"
        );
        assert_eq!(
            l.record(&CommandId::new("c1")).expect("c1").command.state,
            CommandStatus::Succeeded
        );
    }

    #[test]
    fn pending_lists_only_unfinished_commands() {
        let mut l = ledger();
        l.accept(command("c1", "k1", 3));
        l.accept(command("c2", "k2", 3));
        assert_eq!(l.pending().count(), 2);
        l.complete(&CommandId::new("c1"), CommandStatus::Cancelled, None, None);
        assert_eq!(l.pending().count(), 1);
    }
}
