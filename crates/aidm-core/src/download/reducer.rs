//! 状态归约器：合法转换、乱序与重复去重、切片聚合成任务状态。
//!
//! 依据 `docs/unified-download-state-review.md` 第 5 节与第 7.1 节。
//!
//! 归约器是任务的**唯一逻辑写入者**：所有状态变更都必须经过 [`Reducer::apply`]，
//! 协议适配器和执行器只提交事实，不直接改状态。
//!
//! 拒收规则（文档 4.2）：旧轮次的进度、结果和定时器不得改变新轮次状态。
//! 拒收不是"忽略"——必须能被记录成 `download.stale_result`，所以这里把拒收原因
//! 作为返回值交给调用方，而不是静默丢弃。

use super::coverage::CoverageSet;
use super::model::{
    Activity, AssignmentId, AssignmentState, AssignmentStatus, Availability, CapabilitySet,
    ConnectionId, ConnectionState, ConnectionStatus, Counts, EventId, FactEvent, FactKind,
    FactPayload, IdentityContext, PlanStatus, ResourceId, ResourceState, SliceId, SliceState,
    SliceStatus, SourceId, SourceState, Span, Status, TaskState, TriState, UnifiedError, WaitInfo,
};
use std::collections::{BTreeMap, HashSet, VecDeque};

/// 已见事件编号的保留上限。
///
/// 去重只需要覆盖"重复投递可能出现的窗口"，不承诺永久记忆。超限后按 FIFO 淘汰，
/// 最坏结果是极旧事件被重复应用——而应用本身是幂等的并集运算，不会污染覆盖。
pub const SEEN_EVENT_CAPACITY: usize = 4096;

/// 事实被拒收的原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// 任务编号不匹配。
    WrongTask { incoming: i64, current: i64 },
    /// 旧轮次或不匹配的轮次。
    EpochMismatch { incoming: u64, current: u64 },
    /// 内容代次不匹配。
    GenerationMismatch { incoming: u64, current: u64 },
    /// 相同 `event_id` 已处理过。
    DuplicateEvent,
    /// 快照的生产者序号不高于已接纳值。
    StaleSnapshot { incoming: u64, accepted: u64 },
    /// 作用对象不存在。
    UnknownSubject,
    /// 非法主状态转换。
    IllegalTransition { from: Status, to: Status },
    /// 事实类别与载荷不匹配。
    KindMismatch,
}

impl RejectReason {
    /// 供 `download.stale_result` 使用的受控原因码。
    pub fn code(&self) -> &'static str {
        match self {
            RejectReason::WrongTask { .. } => "wrong_task",
            RejectReason::EpochMismatch { .. } => "stale_epoch",
            RejectReason::GenerationMismatch { .. } => "stale_generation",
            RejectReason::DuplicateEvent => "duplicate_event",
            RejectReason::StaleSnapshot { .. } => "stale_snapshot",
            RejectReason::UnknownSubject => "unknown_subject",
            RejectReason::IllegalTransition { .. } => "illegal_transition",
            RejectReason::KindMismatch => "kind_mismatch",
        }
    }

    /// 是否属于"可安全合并计数的重复投递"（用于事件聚合）。
    pub fn is_duplicate_like(&self) -> bool {
        matches!(
            self,
            RejectReason::DuplicateEvent | RejectReason::StaleSnapshot { .. }
        )
    }
}

/// 一次事实应用的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// 已接纳并改变了状态；`state_revision` 已推进。
    Applied,
    /// 已接纳但状态无变化（幂等重复）。
    Unchanged,
    /// 被拒收；调用方应为它写一条 `download.stale_result`。
    Rejected(RejectReason),
}

/// 主状态转换是否合法。
///
/// 闭集来自文档第 5 节。同状态"转换"恒合法（用于刷新 activity / wait）。
/// `done` 只能经显式重新下载回到 `queued`，不复活旧命令。
pub fn is_legal_transition(from: Status, to: Status) -> bool {
    use Status::*;
    if from == to {
        return true;
    }
    matches!(
        (from, to),
        (Queued, Connecting)
            | (Queued, Paused)
            | (Queued, Error)
            | (Queued, Verifying)
            | (Connecting, Downloading)
            | (Connecting, Verifying)
            | (Connecting, Queued)
            | (Connecting, Error)
            | (Connecting, Paused)
            | (Downloading, Verifying)
            | (Downloading, Queued)
            | (Downloading, Error)
            | (Downloading, Paused)
            | (Verifying, Done)
            | (Verifying, Downloading)
            | (Verifying, Error)
            | (Verifying, Paused)
            | (Paused, Queued)
            | (Paused, Error)
            | (Error, Queued)
            | (Error, Paused)
            | (Done, Queued)
    )
}

/// 任务归约器：持有任务的当前运行事实。
#[derive(Debug, Clone)]
pub struct Reducer {
    task: TaskState,
    resources: BTreeMap<ResourceId, ResourceState>,
    slices: BTreeMap<SliceId, SliceState>,
    sources: BTreeMap<SourceId, SourceState>,
    connections: BTreeMap<ConnectionId, ConnectionState>,
    assignments: BTreeMap<AssignmentId, AssignmentState>,
    /// 已处理事件编号（FIFO 有界）。
    seen_order: VecDeque<EventId>,
    seen: HashSet<EventId>,
    /// 每个生产者已接纳的最高序号。
    producer_high: BTreeMap<String, u64>,
    /// 注入的逻辑时钟（毫秒）。归约器不读真实时钟，冷却与过期判定由调用方注入。
    now_ms: Option<u64>,
}

impl Reducer {
    /// 由初始任务状态构造。
    pub fn new(task: TaskState) -> Self {
        Self {
            task,
            resources: BTreeMap::new(),
            slices: BTreeMap::new(),
            sources: BTreeMap::new(),
            connections: BTreeMap::new(),
            assignments: BTreeMap::new(),
            seen_order: VecDeque::new(),
            seen: HashSet::new(),
            producer_high: BTreeMap::new(),
            now_ms: None,
        }
    }

    // ------------------------------------------------------------ 读访问

    /// 可变访问任务状态。**只给快照对齐用**（影子期的 `observe`），
    /// 正常状态推进必须走 [`Reducer::apply`]——否则 `state_revision`
    /// 与事实序列的对应关系就断了。
    pub fn task_mut(&mut self) -> &mut TaskState {
        &mut self.task
    }

    pub fn task(&self) -> &TaskState {
        &self.task
    }

    pub fn resource(&self, id: &ResourceId) -> Option<&ResourceState> {
        self.resources.get(id)
    }

    pub fn slice(&self, id: &SliceId) -> Option<&SliceState> {
        self.slices.get(id)
    }

    pub fn source(&self, id: &SourceId) -> Option<&SourceState> {
        self.sources.get(id)
    }

    pub fn connection(&self, id: &ConnectionId) -> Option<&ConnectionState> {
        self.connections.get(id)
    }

    pub fn assignment(&self, id: &AssignmentId) -> Option<&AssignmentState> {
        self.assignments.get(id)
    }

    /// 全部切片，按编号排序（稳定顺序，便于快照与测试）。
    pub fn slices(&self) -> impl Iterator<Item = &SliceState> {
        self.slices.values()
    }

    /// 全部源。
    pub fn sources(&self) -> impl Iterator<Item = &SourceState> {
        self.sources.values()
    }

    /// 全部活跃分配。
    pub fn assignments(&self) -> impl Iterator<Item = &AssignmentState> {
        self.assignments.values()
    }

    /// 活动连接数（`opening` / `ready`）。
    pub fn live_connections(&self) -> usize {
        self.connections
            .values()
            .filter(|c| matches!(c.state, ConnectionStatus::Opening | ConnectionStatus::Ready))
            .count()
    }

    // ------------------------------------------------------------ 生命周期

    /// 开始新一轮运行：提升 `run_epoch`，清空上一轮的连接与分配。
    ///
    /// 文档 4.2：`run_epoch` 只在"任务执行权重新取得"时递增，不由 `retry_count`
    /// 推导。旧连接与旧分配从此不再拥有写入权。
    pub fn begin_run(&mut self, run_epoch: u64, content_generation: u64) {
        let identity = &mut self.task.identity;
        identity.run_epoch = run_epoch;
        identity.content_generation = content_generation;
        self.connections.clear();
        self.assignments.clear();
        for slice in self.slices.values_mut() {
            slice.assignment_ids.clear();
        }
        self.task.pending_command_ids.clear();
    }

    /// 记录/替换资源。
    pub fn upsert_resource(&mut self, resource: ResourceState) {
        if !self.task.resource_ids.contains(&resource.resource_id) {
            self.task.resource_ids.push(resource.resource_id.clone());
        }
        self.resources.insert(resource.resource_id.clone(), resource);
    }

    /// 记录/替换切片。
    pub fn upsert_slice(&mut self, slice: SliceState) {
        if !self.task.slice_ids.contains(&slice.slice_id) {
            self.task.slice_ids.push(slice.slice_id.clone());
        }
        self.slices.insert(slice.slice_id.clone(), slice);
    }

    /// 记录/替换源。
    pub fn upsert_source(&mut self, source: SourceState) {
        if !self.task.source_ids.contains(&source.source_id) {
            self.task.source_ids.push(source.source_id.clone());
        }
        self.sources.insert(source.source_id.clone(), source);
    }

    /// 规划完成：写入切片集合并提升 `plan_revision`。
    ///
    /// 文档 6.1：运行时预算变化**不**重新编号切片；这里只用于初次规划与
    /// 显式重新规划（后者首版不自动进行）。
    pub fn set_plan(&mut self, slices: Vec<SliceState>, plan_status: PlanStatus) {
        let revision = self.task.identity.plan_revision + 1;
        self.task.identity.plan_revision = revision;
        self.task.plan_status = plan_status;
        self.task.slice_ids.clear();
        self.slices.clear();
        for mut slice in slices {
            slice.plan_revision = revision;
            self.task.slice_ids.push(slice.slice_id.clone());
            self.slices.insert(slice.slice_id.clone(), slice);
        }
        self.recompute_progress();
        self.recompute_counts();
    }

    /// 追加一个分配（在创建时就登记，避免"已知切片但不知道谁负责"）。
    pub fn upsert_assignment(&mut self, assignment: AssignmentState) {
        if let Some(slice) = self.slices.get_mut(&assignment.slice_id) {
            if !slice.assignment_ids.contains(&assignment.assignment_id) {
                slice.assignment_ids.push(assignment.assignment_id.clone());
            }
        }
        if let Some(conn) = assignment.connection_id.as_ref() {
            if let Some(state) = self.connections.get_mut(conn) {
                if !state.assignment_ids.contains(&assignment.assignment_id) {
                    state.assignment_ids.push(assignment.assignment_id.clone());
                }
            }
        }
        self.assignments
            .insert(assignment.assignment_id.clone(), assignment);
        self.recompute_counts();
    }

    // ------------------------------------------------------------ 事实应用

    /// 应用一个统一事实。
    pub fn apply(&mut self, fact: &FactEvent) -> ApplyOutcome {
        // 1) 关联一致性：任务、轮次、内容代次。
        if fact.identity.task_id != self.task.identity.task_id {
            return ApplyOutcome::Rejected(RejectReason::WrongTask {
                incoming: fact.identity.task_id,
                current: self.task.identity.task_id,
            });
        }
        let current_epoch = self.task.identity.run_epoch;
        if fact.identity.run_epoch != current_epoch {
            return ApplyOutcome::Rejected(RejectReason::EpochMismatch {
                incoming: fact.identity.run_epoch,
                current: current_epoch,
            });
        }
        let current_gen = self.task.identity.content_generation;
        if fact.identity.content_generation != current_gen {
            return ApplyOutcome::Rejected(RejectReason::GenerationMismatch {
                incoming: fact.identity.content_generation,
                current: current_gen,
            });
        }

        // 2) 事件去重：同 event_id 只应用一次。
        if self.seen.contains(&fact.event_id) {
            return ApplyOutcome::Rejected(RejectReason::DuplicateEvent);
        }

        // 3) 快照类事实的序号门：更高序号可替代旧快照，低序号拒收。
        //    局部增量（Store/Verify）不走序号门——文档要求"不能仅凭序号丢弃
        //    尚未包含的区间"，它们靠并集与 event_id 去重保证正确。
        if fact.kind == FactKind::CoverageChanged {
            let accepted = self.producer_high.get(&fact.producer_id).copied();
            if let Some(accepted) = accepted {
                if fact.producer_seq <= accepted {
                    self.mark_seen(&fact.event_id);
                    return ApplyOutcome::Rejected(RejectReason::StaleSnapshot {
                        incoming: fact.producer_seq,
                        accepted,
                    });
                }
            }
        }

        // 4) 按类别分发。
        let changed = match (&fact.kind, &fact.payload) {
            (FactKind::CapabilityObserved, FactPayload::Capability { source_id, capabilities }) => {
                self.apply_capability(source_id, capabilities)
            }
            (FactKind::SourceObserved, FactPayload::Source { state, .. }) => {
                self.apply_source(state);
                true
            }
            (FactKind::ConnectionChanged, FactPayload::Connection { connection_id, state }) => {
                self.apply_connection(connection_id, state)
            }
            (FactKind::AssignmentChanged, FactPayload::Assignment { state, .. }) => {
                self.apply_assignment(state)
            }
            (FactKind::CoverageChanged, FactPayload::Coverage { slice_id, stored, verified }) => {
                self.apply_coverage_snapshot(slice_id, stored, verified)
            }
            (
                FactKind::VerifyResult,
                FactPayload::Verify {
                    slice_id,
                    span,
                    ok,
                    verified,
                },
            ) => self.apply_verify(slice_id, *span, *ok, verified),
            (FactKind::StoreResult, FactPayload::Store { slice_id, span, synced }) => {
                self.apply_store(slice_id, *span, *synced)
            }
            (FactKind::CommandResult, FactPayload::CommandResult { command_id, state }) => {
                self.apply_command_result(command_id, *state)
            }
            (FactKind::OperationFailed, FactPayload::Failure { error }) => {
                self.apply_failure(error)
            }
            _ => {
                return ApplyOutcome::Rejected(RejectReason::KindMismatch);
            }
        };

        self.mark_seen(&fact.event_id);
        if fact.kind == FactKind::CoverageChanged {
            self.producer_high
                .insert(fact.producer_id.clone(), fact.producer_seq);
        }

        if changed {
            self.bump_revision();
            ApplyOutcome::Applied
        } else {
            ApplyOutcome::Unchanged
        }
    }

    fn mark_seen(&mut self, event_id: &EventId) {
        if !self.seen.insert(event_id.clone()) {
            return;
        }
        self.seen_order.push_back(event_id.clone());
        while self.seen_order.len() > SEEN_EVENT_CAPACITY {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
    }

    fn bump_revision(&mut self) {
        self.task.identity.state_revision += 1;
        self.recompute_progress();
        self.recompute_counts();
        self.derive_activity();
    }

    fn apply_capability(&mut self, source_id: &SourceId, caps: &CapabilitySet) -> bool {
        match self.sources.get_mut(source_id) {
            Some(source) => {
                if source.capabilities == *caps {
                    return false;
                }
                source.capabilities = caps.clone();
                true
            }
            None => false,
        }
    }

    fn apply_source(&mut self, state: &SourceState) {
        self.sources.insert(state.source_id.clone(), state.clone());
        if !self.task.source_ids.contains(&state.source_id) {
            self.task.source_ids.push(state.source_id.clone());
        }
    }

    fn apply_connection(&mut self, id: &ConnectionId, state: &ConnectionState) -> bool {
        if let Some(existing) = self.connections.get(id) {
            if existing.state == state.state && existing.assignment_ids == state.assignment_ids {
                return false;
            }
        }
        self.connections.insert(id.clone(), state.clone());
        true
    }

    fn apply_assignment(&mut self, state: &AssignmentState) -> bool {
        if let Some(existing) = self.assignments.get(&state.assignment_id) {
            // 写入许可版本不可回退：旧版本的分配不得覆盖新版本。
            if state.lease_revision < existing.lease_revision {
                return false;
            }
            if existing.state == state.state
                && existing.progress.stored_unique_bytes == state.progress.stored_unique_bytes
                && existing.lease_revision == state.lease_revision
            {
                return false;
            }
        }
        let mut state = state.clone();
        // 结束的分配不再持有写入许可。
        if state.state.is_terminal() {
            state.span = Span {
                start: state.span.start,
                end_exclusive: Some(state.span.start),
            };
        }
        self.upsert_assignment(state);
        true
    }

    fn apply_coverage_snapshot(
        &mut self,
        slice_id: &SliceId,
        stored: &CoverageSet,
        verified: &CoverageSet,
    ) -> bool {
        let Some(slice) = self.slices.get_mut(slice_id) else {
            return false;
        };
        let merged = merge_snapshot(stored, verified);
        if slice.coverage == merged {
            return false;
        }
        slice.coverage = merged;
        let len = slice.span.len().unwrap_or(0);
        slice.progress.stored_unique_bytes = slice.coverage.stored_len();
        slice.progress.verified_unique_bytes = slice.coverage.verified_len();
        slice.progress.wire_bytes = slice.progress.wire_bytes.max(slice.progress.stored_unique_bytes);
        if slice.span.is_allocatable() {
            slice.progress.required_bytes = Some(len);
        }
        self.refresh_slice_state(slice_id);
        true
    }

    fn apply_verify(
        &mut self,
        slice_id: &SliceId,
        span: Span,
        ok: bool,
        verified: &CoverageSet,
    ) -> bool {
        let Some(slice) = self.slices.get_mut(slice_id) else {
            return false;
        };
        let mut changed = false;
        if ok {
            // 先并入本次确认通过的覆盖，再按 span 补记（两者都是幂等并集）。
            slice.coverage.merge(verified);
            if let Some((start, end)) = known_bounds(span) {
                if slice.coverage.insert_stored(start, end).is_ok() {
                    let _ = slice.coverage.insert_verified(start, end);
                    changed = true;
                }
            }
        } else if let Some((start, end)) = known_bounds(span) {
            // 校验失败：失效该区间的验证与落盘，等待修复（文档 7.3）。
            let (stored_removed, verified_removed) = slice.coverage.invalidate(start, end);
            changed = stored_removed > 0 || verified_removed > 0;
        }
        if changed {
            slice.progress.stored_unique_bytes = slice.coverage.stored_len();
            slice.progress.verified_unique_bytes = slice.coverage.verified_len();
            self.refresh_slice_state(slice_id);
        }
        changed
    }

    fn apply_store(&mut self, slice_id: &SliceId, span: Span, synced: bool) -> bool {
        let Some((start, end)) = known_bounds(span) else {
            return false;
        };
        let Some(slice) = self.slices.get_mut(slice_id) else {
            return false;
        };
        // 已通过校验的区域不能重写；迟到/重复的落盘事实按"数据已在"处理。
        let added = match slice.coverage.insert_stored(start, end) {
            Ok(added) => added,
            Err(_) => 0,
        };
        if added == 0 && !synced {
            return false;
        }
        slice.progress.stored_unique_bytes = slice.coverage.stored_len();
        slice.progress.wire_bytes = slice.progress.wire_bytes.max(slice.progress.stored_unique_bytes);
        if slice.span.is_allocatable() {
            slice.progress.required_bytes = slice.span.len();
        }
        self.refresh_slice_state(slice_id);
        added > 0
    }

    fn apply_command_result(
        &mut self,
        command_id: &super::model::CommandId,
        state: super::model::CommandStatus,
    ) -> bool {
        if state.is_terminal() {
            let before = self.task.pending_command_ids.len();
            self.task.pending_command_ids.retain(|c| c != command_id);
            return before != self.task.pending_command_ids.len();
        }
        if !self.task.pending_command_ids.contains(command_id) {
            self.task.pending_command_ids.push(command_id.clone());
            return true;
        }
        false
    }

    fn apply_failure(&mut self, error: &UnifiedError) -> bool {
        if self.task.current_error.as_ref() == Some(error) {
            return false;
        }
        self.task.current_error = Some(error.clone());
        true
    }

    // ------------------------------------------------------------ 聚合

    /// 按切片重算任务进度：所选资源的所选区间求并集再求和（文档第 8 节）。
    ///
    /// 直接合并切片覆盖而不是把各切片字节数相加：切片一旦出现重叠（重新规划
    /// 的潜在情形），相加会虚增完成量。
    pub fn recompute_progress(&mut self) {
        let mut union = CoverageSet::new();
        for slice in self.slices.values() {
            union.merge(&slice.coverage);
        }
        self.task.progress.stored_unique_bytes = union.stored_len();
        self.task.progress.verified_unique_bytes = union.verified_len();
        if self.task.progress.wire_bytes < self.task.progress.stored_unique_bytes {
            self.task.progress.wire_bytes = self.task.progress.stored_unique_bytes;
        }

        // 所需总量：所有可分配切片的长度之和（切片互不重叠的前提下正确）。
        let mut required: u64 = 0;
        let mut all_known = true;
        for slice in self.slices.values() {
            match slice.span.len() {
                Some(len) => required += len,
                None => {
                    all_known = false;
                    break;
                }
            }
        }
        self.task.progress.required_bytes = if self.slices.is_empty() || !all_known {
            None
        } else {
            Some(required)
        };
    }

    /// 重算计数。各项独立计数，不互相推导（文档 4.4）。
    pub fn recompute_counts(&mut self) {
        let now_ms = self.task_now_ms();

        let known = self
            .sources
            .values()
            .filter(|s| !s.is_evidence_expired_at(now_ms))
            .count() as u32;

        let eligible = self
            .sources
            .values()
            .filter(|s| s.eligible && s.availability == Availability::Available)
            .count() as u32;

        let active_transfers = self
            .assignments
            .values()
            .filter(|a| a.state == AssignmentStatus::Transferring)
            .count() as u32;

        let queued_peers: u32 = self.sources.values().map(|s| s.health.queued_peers).sum();

        let done_slices = self
            .slices
            .values()
            .filter(|s| s.state == SliceStatus::Done)
            .count() as u32;

        self.task.counts = Counts {
            known_sources: known,
            eligible_sources: eligible,
            connections: self.live_connections() as u32,
            active_transfers,
            queued_peers,
            done_slices,
        };
    }

    /// 应用外部观测到的连接计数。
    ///
    /// 用于 legacy 兼容投影：旧执行器只提供“有多少活动连接、多少在传、
    /// 多少排队”，不提供精确的源/分配归属。这三项只能来自观测，不能让
    /// `recompute_counts` 从空集合算成 0。
    pub fn apply_observed_counts(
        &mut self,
        connections: u32,
        active_transfers: u32,
        queued_peers: u32,
    ) {
        self.task.counts.connections = connections;
        self.task.counts.active_transfers = active_transfers;
        self.task.counts.queued_peers = queued_peers;
    }

    /// 由切片与连接推导 `activity`；不改主状态。
    fn derive_activity(&mut self) {
        let ActivityContext {
            any_transferring,
            any_verifying,
            any_connecting,
        } = self.activity_context();

        let activity = if any_verifying {
            Activity::Verifying
        } else if any_transferring {
            Activity::Transferring
        } else if any_connecting {
            Activity::Connecting
        } else if self.task.status == Status::Verifying {
            Activity::Verifying
        } else if self.task.wait.is_some() {
            Activity::Waiting
        } else {
            Activity::Idle
        };
        self.task.activity = activity;
    }

    /// 设定方案版本（eD2k 的切片方案由首次规划固定）。
    ///
    /// 与 `state_revision` 分开：方案版本只在**结构变化**（切片范围/数量变了）
    /// 时递增，预算变化不改变它。
    pub fn assign_plan_revision(&mut self, revision: u64) {
        self.task.identity.plan_revision = revision;
        if !self.task.slice_ids.is_empty() {
            self.task.plan_status = PlanStatus::Ready;
        }
    }

    /// 推进 `state_revision`。
    ///
    /// 文档 4.2：`state_revision` 是持久化预留号段，批量接纳状态时取下一个序号、
    /// 允许缺口。推进时机（检查点、执行权交接）由协调器决定，归约器只提供入口。
    pub fn advance_state_revision(&mut self, to: u64) {
        if to > self.task.identity.state_revision {
            self.task.identity.state_revision = to;
        }
    }

    /// 直接设定 `state_revision`（不要求单调）。
    ///
    /// legacy 兼容投影用「可见事实指纹」当版本号：指纹可能上升也可能
    /// 下降，但**任何可见变化都必须与旧值不同**。顺序号段届时换成
    /// 持久化预留值。
    pub fn assign_state_revision(&mut self, rev: u64) {
        self.task.identity.state_revision = rev;
    }

    fn activity_context(&self) -> ActivityContext {
        let any_transferring = self
            .assignments
            .values()
            .any(|a| a.state == AssignmentStatus::Transferring);
        let any_verifying = self.slices.values().any(|s| s.state == SliceStatus::Verifying);
        let any_connecting = self.connections.values().any(|c| {
            matches!(c.state, ConnectionStatus::Opening)
        });
        ActivityContext {
            any_transferring,
            any_verifying,
            any_connecting,
        }
    }

    /// 重新计算单个切片的状态。
    ///
    /// 聚合规则（文档第 5 节）：所要求校验完成且范围完整才 `done`；有有效传输
    /// `active`；仅待校验 `verifying`；无活动且可恢复 `waiting`；尚未分配
    /// `pending`；需要人工处理 `error`。
    fn refresh_slice_state(&mut self, slice_id: &SliceId) {
        let Some(slice) = self.slices.get_mut(slice_id) else {
            return;
        };

        // error 是显式状态：只有显式清除才能离开，不被自动聚合覆盖。
        if slice.state == SliceStatus::Error {
            return;
        }

        // 直接用覆盖判定"是否已完成"：不能调 `is_complete()`，后者要求
        // `state == Done`，而本函数正在计算 `state`，会形成循环依赖。
        let fully_verified =
            slice.span.is_allocatable() && slice.coverage.covers_verified(slice.span);

        let next = if fully_verified {
            SliceStatus::Done
        } else if self
            .assignments
            .values()
            .any(|a| a.slice_id == *slice_id && a.state == AssignmentStatus::Transferring)
        {
            SliceStatus::Active
        } else if slice.coverage.stored_len() > 0 {
            // 有落盘但还没校验通过：要么在校验，要么等下一次继续。
            if slice.coverage.verified_len() < slice.coverage.stored_len() {
                SliceStatus::Verifying
            } else {
                SliceStatus::Waiting
            }
        } else if slice.assignment_ids.is_empty() {
            SliceStatus::Pending
        } else {
            SliceStatus::Waiting
        };

        if slice.state != next {
            slice.state = next;
        }
    }

    /// 显式把切片标为错误（需要人工处理）。
    pub fn mark_slice_error(&mut self, slice_id: &SliceId) -> bool {
        match self.slices.get_mut(slice_id) {
            Some(slice) if slice.state != SliceStatus::Error => {
                slice.state = SliceStatus::Error;
                true
            }
            _ => false,
        }
    }

    /// 设置等待原因；`None` 表示解除等待。
    pub fn set_wait(&mut self, wait: Option<WaitInfo>) -> bool {
        if self.task.wait == wait {
            return false;
        }
        self.task.wait = wait;
        self.derive_activity();
        true
    }

    /// 请求主状态转换。非法转换被拒绝并返回原因，**不会**静默改状态。
    pub fn request_status(&mut self, to: Status) -> Result<(), RejectReason> {
        let from = self.task.status;
        if !is_legal_transition(from, to) {
            return Err(RejectReason::IllegalTransition { from, to });
        }
        if from == to {
            return Ok(());
        }
        self.task.status = to;
        // 离开 waiting 相关状态时清掉陈旧等待原因。
        if matches!(to, Status::Done | Status::Error) {
            self.task.wait = None;
        }
        self.bump_revision();
        Ok(())
    }

    /// 任务级"是否有任何进展可能"。
    ///
    /// 0 个切片、没有可用源都只是等待原因，不是错误（文档第 2 节）。
    pub fn has_actionable_work(&self) -> bool {
        self.slices.values().any(|s| {
            s.span.is_allocatable() && !s.coverage.covers_verified(s.span)
        })
    }

    /// 时间基线：由任务已记录的等待时间推进，避免归约器依赖真实时钟。
    ///
    /// 归约器必须保持纯逻辑（文档第 3 节），所以不调用 `SystemTime::now()`。
    /// 需要"当前时间"的判定（冷却、证据过期）由调用方通过
    /// [`Self::set_now_ms`] 注入。
    pub fn set_now_ms(&mut self, now_ms: u64) {
        self.now_ms = Some(now_ms);
    }

    fn task_now_ms(&self) -> u64 {
        self.now_ms.unwrap_or(0)
    }

    /// 当前时间基线（未注入时为 0）。
    pub fn now_ms(&self) -> Option<u64> {
        self.now_ms
    }

    /// 身份上下文（供快照与事件）。
    pub fn identity(&self) -> &IdentityContext {
        &self.task.identity
    }

    /// 源是否可用于新分配（文档 6.3 的排除条件）。
    pub fn source_is_usable(&self, source_id: &SourceId) -> bool {
        let Some(source) = self.sources.get(source_id) else {
            return false;
        };
        let now = self.task_now_ms();
        source.availability == Availability::Available
            && source.eligible
            && !source.is_cooling_at(now)
            && !source.is_evidence_expired_at(now)
            && source.capabilities.multi_source != TriState::No
    }
}

/// 归约器内部的活动上下文。
#[derive(Debug, Clone, Copy)]
struct ActivityContext {
    any_transferring: bool,
    any_verifying: bool,
    any_connecting: bool,
}

/// 把"落盘 + 验证"两份快照合并成一个自洽账本。
fn merge_snapshot(stored: &CoverageSet, verified: &CoverageSet) -> CoverageSet {
    let mut merged = stored.clone();
    merged.merge(verified);
    // 快照可能被裁剪过；重新施加 verified ⊆ stored。
    CoverageSet::from_snapshot(merged.stored_spans(), merged.verified_spans())
}

/// 把 [`Span`] 拆成已知边界。
fn known_bounds(span: Span) -> Option<(u64, u64)> {
    span.end_exclusive.map(|end| (span.start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Transport;
    use crate::download::model::{
        CommandId, CommandStatus, EventId, FactEvent, FactKind, FactPayload,
    };

    fn identity(epoch: u64, generation: u64) -> IdentityContext {
        let mut id = IdentityContext::for_task(7, "engine-1");
        id.run_epoch = epoch;
        id.content_generation = generation;
        id
    }

    fn reducer() -> Reducer {
        let mut task = TaskState::new(identity(1, 0), Transport::Http);
        task.identity.run_epoch = 1;
        Reducer::new(task)
    }

    fn fact(kind: FactKind, payload: FactPayload) -> FactEvent {
        FactEvent {
            event_id: EventId::generate(),
            identity: identity(1, 0),
            producer_id: "test".into(),
            producer_seq: 1,
            observed_at_ms: 1_000,
            kind,
            payload,
            cause_event_id: None,
        }
    }

    fn store_fact(slice: &SliceId, start: u64, end: u64) -> FactEvent {
        fact(
            FactKind::StoreResult,
            FactPayload::Store {
                slice_id: slice.clone(),
                span: Span::known(start, end).expect("span"),
                synced: true,
            },
        )
    }

    fn verify_fact(slice: &SliceId, start: u64, end: u64, ok: bool) -> FactEvent {
        fact(
            FactKind::VerifyResult,
            FactPayload::Verify {
                slice_id: slice.clone(),
                span: Span::known(start, end).expect("span"),
                ok,
                verified: CoverageSet::default(),
            },
        )
    }

    fn add_slice(r: &mut Reducer, start: u64, end: u64) -> SliceId {
        let id = SliceId::generate();
        let slice = SliceState::new(
            id.clone(),
            ResourceId::new("r1"),
            0,
            0,
            Span::known(start, end).expect("span"),
        );
        r.task.identity.plan_revision = 1;
        r.upsert_slice(slice);
        id
    }

    #[test]
    fn legal_transition_table_is_closed() {
        use Status::*;
        assert!(is_legal_transition(Queued, Connecting));
        assert!(is_legal_transition(Connecting, Downloading));
        assert!(is_legal_transition(Downloading, Verifying));
        assert!(is_legal_transition(Verifying, Done));
        assert!(is_legal_transition(Paused, Queued));
        assert!(is_legal_transition(Error, Queued));
        assert!(is_legal_transition(Done, Queued));

        // 非法：跳过中间态、从终态直接跳到下载、逆转验证。
        assert!(!is_legal_transition(Queued, Downloading));
        assert!(!is_legal_transition(Queued, Done));
        assert!(!is_legal_transition(Done, Downloading));
        assert!(!is_legal_transition(Done, Error));
        assert!(!is_legal_transition(Paused, Downloading));
        assert!(is_legal_transition(Downloading, Downloading), "同状态恒合法");
    }

    #[test]
    fn illegal_transition_is_rejected_not_silently_applied() {
        let mut r = reducer();
        assert_eq!(
            r.request_status(Status::Downloading),
            Err(RejectReason::IllegalTransition {
                from: Status::Queued,
                to: Status::Downloading
            })
        );
        assert_eq!(r.task().status, Status::Queued, "状态必须保持不变");
    }

    #[test]
    fn stale_epoch_facts_are_rejected() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        r.begin_run(2, 0);

        let mut f = store_fact(&slice, 0, 100);
        f.identity.run_epoch = 1;
        match r.apply(&f) {
            ApplyOutcome::Rejected(RejectReason::EpochMismatch { incoming, current }) => {
                assert_eq!((incoming, current), (1, 2));
            }
            other => panic!("旧轮次必须被拒收，实际 {other:?}"),
        }
        assert_eq!(r.slice(&slice).expect("slice").coverage.stored_len(), 0);
    }

    #[test]
    fn stale_generation_facts_are_rejected() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        let mut f = store_fact(&slice, 0, 50);
        f.identity.content_generation = 9;
        assert!(matches!(
            r.apply(&f),
            ApplyOutcome::Rejected(RejectReason::GenerationMismatch { .. })
        ));
    }

    #[test]
    fn wrong_task_is_rejected() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        let mut f = store_fact(&slice, 0, 10);
        f.identity.task_id = 99;
        assert!(matches!(
            r.apply(&f),
            ApplyOutcome::Rejected(RejectReason::WrongTask { .. })
        ));
    }

    #[test]
    fn duplicate_event_id_is_applied_once() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        let f = store_fact(&slice, 0, 50);

        assert_eq!(r.apply(&f), ApplyOutcome::Applied);
        assert_eq!(
            r.apply(&f),
            ApplyOutcome::Rejected(RejectReason::DuplicateEvent)
        );
        assert_eq!(r.slice(&slice).expect("slice").coverage.stored_len(), 50);
    }

    #[test]
    fn out_of_order_store_facts_union_instead_of_replacing() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);

        // 乱序到达：先 60..100，再 0..40，最后 40..60。
        r.apply(&store_fact(&slice, 60, 100));
        r.apply(&store_fact(&slice, 0, 40));
        r.apply(&store_fact(&slice, 40, 60));

        let coverage = &r.slice(&slice).expect("slice").coverage;
        assert_eq!(coverage.stored_len(), 100, "乱序增量必须求并集");
        assert!(coverage.covers_stored(Span::known(0, 100).expect("span")));
    }

    #[test]
    fn stale_coverage_snapshot_is_rejected() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);

        let mut newer = fact(
            FactKind::CoverageChanged,
            FactPayload::Coverage {
                slice_id: slice.clone(),
                stored: CoverageSet::from_snapshot(&[0..100], &[]),
                verified: CoverageSet::default(),
            },
        );
        newer.producer_id = "p1".into();
        newer.producer_seq = 10;
        assert_eq!(r.apply(&newer), ApplyOutcome::Applied);

        let mut older = fact(
            FactKind::CoverageChanged,
            FactPayload::Coverage {
                slice_id: slice.clone(),
                stored: CoverageSet::from_snapshot(&[0..10], &[]),
                verified: CoverageSet::default(),
            },
        );
        older.producer_id = "p1".into();
        older.producer_seq = 5;
        assert_eq!(
            r.apply(&older),
            ApplyOutcome::Rejected(RejectReason::StaleSnapshot {
                incoming: 5,
                accepted: 10
            })
        );
        assert_eq!(
            r.slice(&slice).expect("slice").coverage.stored_len(),
            100,
            "旧快照不得回退覆盖"
        );
    }

    #[test]
    fn verify_marks_slice_done_only_when_fully_covered() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);

        r.apply(&store_fact(&slice, 0, 100));
        assert_ne!(r.slice(&slice).expect("slice").state, SliceStatus::Done);

        r.apply(&verify_fact(&slice, 0, 100, true));
        let s = r.slice(&slice).expect("slice");
        assert_eq!(s.state, SliceStatus::Done);
        assert!(s.is_complete());
    }

    #[test]
    fn failed_verify_invalidates_coverage() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        r.apply(&store_fact(&slice, 0, 100));
        r.apply(&verify_fact(&slice, 0, 100, true));
        assert_eq!(r.slice(&slice).expect("slice").coverage.verified_len(), 100);

        r.apply(&verify_fact(&slice, 20, 30, false));
        let c = &r.slice(&slice).expect("slice").coverage;
        assert_eq!(c.verified_len(), 90, "坏块必须如实降低有效覆盖");
        assert_eq!(c.stored_len(), 90);
        assert!(c.is_consistent());
    }

    #[test]
    fn slice_with_partial_coverage_is_not_done_even_if_marked() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        r.apply(&store_fact(&slice, 0, 50));
        let mut s = r.slice(&slice).expect("slice").clone();
        s.state = SliceStatus::Done;
        r.upsert_slice(s);
        assert!(!r.slice(&slice).expect("slice").is_complete());
    }

    #[test]
    fn zero_slices_is_legal_and_not_an_error() {
        let r = reducer();
        assert_eq!(r.task().status, Status::Queued);
        assert_eq!(r.task().progress.required_bytes, None, "0 切片不伪造总量");
        assert!(!r.has_actionable_work());
        assert_eq!(r.task().plan_status, PlanStatus::Unplanned);
    }

    #[test]
    fn open_span_slice_never_reports_required_bytes() {
        let mut r = reducer();
        let id = SliceId::generate();
        r.upsert_slice(SliceState::new(
            id,
            ResourceId::new("r"),
            0,
            1,
            Span::open(0),
        ));
        r.recompute_progress();
        assert_eq!(
            r.task().progress.required_bytes,
            None,
            "总长未知不能给出总量"
        );
    }

    #[test]
    fn task_progress_uses_union_not_sum() {
        let mut r = reducer();
        // 两个重叠切片：相加会虚增，求并集才是真实完成量。
        let a = add_slice(&mut r, 0, 100);
        let b = add_slice(&mut r, 50, 150);
        r.apply(&store_fact(&a, 0, 100));
        r.apply(&store_fact(&b, 50, 150));
        r.recompute_progress();
        assert_eq!(
            r.task().progress.stored_unique_bytes,
            150,
            "重叠切片求并集，不能相加成 200"
        );
    }

    #[test]
    fn waiting_slice_keeps_coverage_and_reports_wait() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        r.apply(&store_fact(&slice, 0, 40));
        let wait = WaitInfo {
            reason: crate::download::model::WaitReason::NoSource,
            scope: crate::download::model::Scope::Task,
            subject_id: None,
            since_ms: 1_000,
            retry_at_ms: None,
            detail_code: Some("no_eligible_source".into()),
        };
        r.set_wait(Some(wait.clone()));
        assert_eq!(r.task().wait, Some(wait));
        assert_eq!(r.slice(&slice).expect("slice").coverage.stored_len(), 40);
        assert_eq!(r.task().progress.stored_unique_bytes, 40);
    }

    #[test]
    fn terminal_assignment_releases_its_span() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        let mut a = AssignmentState::new(
            AssignmentId::generate(),
            7,
            1,
            0,
            slice.clone(),
            SourceId::new("src"),
            Span::known(0, 50).expect("span"),
        );
        a.state = AssignmentStatus::Transferring;
        r.upsert_assignment(a.clone());
        assert_eq!(r.task().counts.active_transfers, 1);

        a.state = AssignmentStatus::Failed;
        r.apply(&fact(
            FactKind::AssignmentChanged,
            FactPayload::Assignment {
                assignment_id: a.assignment_id.clone(),
                state: Box::new(a.clone()),
            },
        ));
        assert_eq!(r.task().counts.active_transfers, 0);
        let stored = r.assignment(&a.assignment_id).expect("assignment");
        assert!(
            stored.span.end_exclusive == Some(stored.span.start),
            "结束的分配不再持有写入区间"
        );
    }

    #[test]
    fn assignment_lease_cannot_go_backwards() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        let mut a = AssignmentState::new(
            AssignmentId::generate(),
            7,
            1,
            0,
            slice.clone(),
            SourceId::new("src"),
            Span::known(0, 50).expect("span"),
        );
        a.lease_revision = 5;
        r.upsert_assignment(a.clone());

        let mut older = a.clone();
        older.lease_revision = 3;
        older.state = AssignmentStatus::Transferring;
        let changed = r.apply(&fact(
            FactKind::AssignmentChanged,
            FactPayload::Assignment {
                assignment_id: older.assignment_id.clone(),
                state: Box::new(older),
            },
        ));
        assert_eq!(changed, ApplyOutcome::Unchanged, "旧许可不得覆盖新许可");
    }

    #[test]
    fn command_result_clears_pending_list() {
        let mut r = reducer();
        let cmd = CommandId::generate();
        r.task.pending_command_ids.push(cmd.clone());

        let mut f = fact(
            FactKind::CommandResult,
            FactPayload::CommandResult {
                command_id: cmd.clone(),
                state: CommandStatus::Running,
            },
        );
        f.event_id = EventId::generate();
        r.apply(&f);
        assert_eq!(r.task().pending_command_ids.len(), 1, "运行中仍在待完成列表");

        let mut done = fact(
            FactKind::CommandResult,
            FactPayload::CommandResult {
                command_id: cmd.clone(),
                state: CommandStatus::Succeeded,
            },
        );
        done.event_id = EventId::generate();
        r.apply(&done);
        assert!(r.task().pending_command_ids.is_empty());
    }

    #[test]
    fn kind_mismatch_is_rejected() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        let f = fact(
            FactKind::StoreResult,
            FactPayload::Store {
                slice_id: slice.clone(),
                span: Span::open(0),
                synced: true,
            },
        );
        // Store 类别配 Store 载荷是匹配的，只是开放范围无法落账 → Unchanged。
        assert_eq!(r.apply(&f), ApplyOutcome::Unchanged);

        let bad = fact(
            FactKind::VerifyResult,
            FactPayload::Source {
                source_id: SourceId::new("s"),
                state: Box::new(SourceState::new(
                    SourceId::new("s"),
                    ResourceId::new("r"),
                    Transport::Http,
                )),
            },
        );
        assert_eq!(
            r.apply(&bad),
            ApplyOutcome::Rejected(RejectReason::KindMismatch)
        );
    }

    #[test]
    fn source_usability_honours_cooldown_and_expiry() {
        let mut r = reducer();
        r.set_now_ms(1_000);
        let mut source = SourceState::new(SourceId::new("s1"), ResourceId::new("r"), Transport::Http);
        source.availability = Availability::Available;
        source.eligible = true;
        source.capabilities.multi_source = TriState::Yes;
        r.upsert_source(source.clone());
        assert!(r.source_is_usable(&source.source_id));

        // 冷却中不可用。
        let mut cooling = source.clone();
        cooling.cooldown_until_ms = Some(2_000);
        r.upsert_source(cooling);
        assert!(!r.source_is_usable(&source.source_id), "冷却窗口内不得分配");

        // 证据过期不可用。
        let mut expired = source.clone();
        expired.expires_at_ms = Some(1_000);
        r.upsert_source(expired);
        assert!(!r.source_is_usable(&source.source_id), "证据过期需重探");
    }

    #[test]
    fn counts_are_independent() {
        let mut r = reducer();
        r.set_now_ms(0);
        // 一个已过期源 + 一个可用源 + 一个排队源。
        let mut expired = SourceState::new(SourceId::new("a"), ResourceId::new("r"), Transport::Http);
        expired.expires_at_ms = Some(0);
        r.upsert_source(expired);

        let mut live = SourceState::new(SourceId::new("b"), ResourceId::new("r"), Transport::Ed2k);
        live.availability = Availability::Available;
        live.eligible = true;
        live.health.queued_peers = 3;
        r.upsert_source(live);

        r.recompute_counts();
        assert_eq!(r.task().counts.known_sources, 1, "过期源不计入已知源");
        assert_eq!(r.task().counts.eligible_sources, 1);
        assert_eq!(r.task().counts.queued_peers, 3, "排队对端独立计数");
        assert_eq!(r.task().counts.connections, 0);
    }

    #[test]
    fn begin_run_clears_previous_connections_and_leases() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        let a = AssignmentState::new(
            AssignmentId::generate(),
            7,
            1,
            0,
            slice.clone(),
            SourceId::new("src"),
            Span::known(0, 50).expect("span"),
        );
        r.upsert_assignment(a.clone());
        assert_eq!(r.assignments().count(), 1);

        r.begin_run(2, 0);
        assert_eq!(r.assignments().count(), 0, "旧分配不得跨轮次存活");
        assert!(r.slice(&slice).expect("slice").assignment_ids.is_empty());
        assert_eq!(r.identity().run_epoch, 2);
    }

    #[test]
    fn state_revision_advances_only_on_change() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        let before = r.identity().state_revision;

        r.apply(&store_fact(&slice, 0, 50));
        let after = r.identity().state_revision;
        assert!(after > before, "有效变更必须推进 state_revision");

        // 幂等重复（相同区间、新 event_id）不应推进版本。
        r.apply(&store_fact(&slice, 0, 50));
        assert_eq!(r.identity().state_revision, after);
    }

    #[test]
    fn error_slice_sticks_until_explicit_clear() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100);
        r.mark_slice_error(&slice);
        assert_eq!(r.slice(&slice).expect("slice").state, SliceStatus::Error);

        // 后续落盘事实不应把 error 自动洗成 active。
        r.apply(&store_fact(&slice, 0, 100));
        assert_eq!(
            r.slice(&slice).expect("slice").state,
            SliceStatus::Error,
            "需要人工处理的错误不能被自动聚合覆盖"
        );
    }
}
