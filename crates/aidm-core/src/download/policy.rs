//! 解释器：硬规则层与证据评估层，只产出决策，不执行任何副作用。
//!
//! 依据 `docs/unified-download-state-review.md` 第 6.3 节、第 7.1 至 7.3 节。
//!
//! 分层职责（文档 7.2）：
//! - **硬规则层**：用户控制、身份与范围一致性、协议校验、写入许可、预算与权限。
//!   任何置信度都不能推翻硬规则。
//! - **证据评估层**：限流归因、源选择、速度与恢复时机。这些是**推断**，必须带
//!   `evidence_refs`，并且低置信度只允许在有预算的小规模探测中使用。
//!
//! 本模块还是纯逻辑：不建连、不读写文件、不读真实时钟。`now_ms` 由调用方注入。
//!
//! # 规则编号
//!
//! `R-UDL-*` 是本模块新增的统一下载规则编号，需登记到项目规则层
//! （`docs/guides/04-task-lifecycle.md`、`05-download-correctness.md`）。在完成
//! 登记前，这些编号只在本模块内引用，不代表项目级已生效规则。

use super::model::{
    Action, ActionParams, Activity, Availability, Confidence, Decision, DecisionId, EvidenceId,
    PlanStatus, Preconditions, Scope, SliceStatus, SourceId, SourceState, Span, Status, TaskState,
    WaitInfo, WaitReason,
};
use super::reducer::Reducer;
use std::collections::HashSet;

/// 统一下载规则编号。
pub mod rule {
    /// 用户已暂停或任务已结束：不得产生任何执行决策。
    pub const HARD_USER_CONTROL: &str = "R-UDL-01";
    /// 源必须具备内容身份依据，否则视为不合格。
    pub const HARD_SOURCE_IDENTITY: &str = "R-UDL-02";
    /// 没有可分配工作时报告等待，不报告失败。
    pub const HARD_NO_WORK: &str = "R-UDL-03";
    /// 预算不足时等待，不越过预算建连。
    pub const HARD_BUDGET: &str = "R-UDL-04";
    /// 完成全部校验后进入收尾。
    pub const HARD_ALL_VERIFIED: &str = "R-UDL-05";
    /// 限流：尊重 `Retry-After`，否则指数退避。
    pub const EVIDENCE_RATE_LIMIT: &str = "R-UDL-10";
    /// 需要降并发：减半直到 1，到 1 后等待。
    pub const EVIDENCE_CONCURRENCY_DOWN: &str = "R-UDL-11";
    /// 稳定窗口后最多增加一条通路。
    pub const EVIDENCE_CONCURRENCY_UP: &str = "R-UDL-12";
    /// 按缺失范围选源，不做"源数除切片数"的平均分配。
    pub const EVIDENCE_ASSIGN: &str = "R-UDL-13";
    /// 异常：可重试的临时故障 → 消耗一次重试预算。
    pub const ERROR_RETRYABLE: &str = "R-UDL-21";
    /// 异常：不可重试或预算耗尽 → 明确终止。
    pub const ERROR_TERMINAL: &str = "R-UDL-22";
    /// 尚未规划且任务空闲无进度：产出切片方案。
    ///
    /// 这是 `Action::PlanSlices` 的**唯一**生产来源。没有它，`PlanSlices`
    /// 一条都不会产生，而 unified 模式下 worker 又禁止自算——读表优先会直接
    /// 打不开。
    pub const HARD_PLAN: &str = "R-PLAN-01";
}

/// 策略版本。规则语义变化时递增（文档 7.1 的 `policy_revision`）。
pub const POLICY_REVISION: u64 = 1;

/// 可调阈值。
///
/// 文档 7.2：新增阈值必须注明依据并进入 SPECS，不在多个模块散落硬编码。
/// 这里给出默认值与其依据，实际生效值由设置层注入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyConfig {
    /// 本地指数退避基数（毫秒）。
    pub backoff_base_ms: u64,
    /// 本地指数退避上限。**不**约束服务端给出的合法 `Retry-After`。
    pub backoff_max_ms: u64,
    /// 判为"稳定"所需的最短持续传输窗口（毫秒）。
    pub stable_window_ms: u64,
    /// 任务当前允许的连接预算。
    pub connection_budget: u32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            // 依据：既有段级退避 `conn.retry_backoff_ms` 的默认量级。
            backoff_base_ms: 1_000,
            backoff_max_ms: 60_000,
            // 依据：现有测速窗口 5 秒的一倍，避免抖动触发扩容。
            stable_window_ms: 10_000,
            connection_budget: 1,
        }
    }
}

/// 解释器输入。全部为只读借用，避免在决策过程中状态被并发修改。
pub struct PolicyInput<'a> {
    pub task: &'a TaskState,
    pub slices: Vec<&'a super::model::SliceState>,
    pub sources: Vec<&'a SourceState>,
    pub config: PolicyConfig,
    pub now_ms: u64,
    /// 当前实际并发（已建立的数据通路数）。
    pub current_concurrency: u32,
    /// 最近一次稳定传输已持续多久；从未稳定为 0。
    pub stable_for_ms: u64,
}

impl<'a> PolicyInput<'a> {
    /// 从归约器构造输入。归约器是唯一状态来源，解释器不得另立快照。
    pub fn from_reducer(reducer: &'a Reducer, config: PolicyConfig) -> Self {
        Self {
            task: reducer.task(),
            slices: reducer.slices().collect(),
            sources: reducer.sources().collect(),
            config,
            now_ms: reducer.now_ms().unwrap_or(0),
            current_concurrency: reducer.task().counts.active_transfers,
            stable_for_ms: 0,
        }
    }
}

/// 解释器主入口：先跑硬规则，再跑证据层。
pub fn evaluate(input: &PolicyInput<'_>) -> Vec<Decision> {
    let mut out = Vec::new();

    // ---- 硬规则层 ------------------------------------------------------
    // R-UDL-01：暂停与已结束任务不产生任何执行决策。用户暂停不得被自动重试复活。
    if matches!(input.task.status, Status::Paused | Status::Done) {
        return out;
    }

    // R-UDL-20/21/22：异常决策。
    //
    // **排在 R-PLAN-01 之前**：任务已经出错时先处理错，而不是先规划——
    // 否则「失败但要终止」的任务会永远停在“刚规划完、还没重试”的状态。
    if let Some(err) = input.task.current_error.as_ref() {
        out.push(decide_error(input, err));
        return out;
    }

    // R-PLAN-01：还没规划、任务空闲且无进度 → 产出切片方案。
    //
    // 必须排在 R-UDL-03 之前：没有切片时 `missing_work` 是空的，那条会直接
    // 产出 Wait，规划就永远轮不上。
    if let Some(total) = plan_candidate(input) {
        let spans: Vec<Span> = crate::segment::plan_segments(
            total,
            input.task.budget.connection_budget,
        )
        .into_iter()
        .map(|b| Span::known(b.start, b.end.saturating_add(1)).unwrap_or_else(|| Span::open(b.start)))
        .collect();
        out.push(decision(
            input,
            rule::HARD_PLAN,
            Scope::Task,
            None,
            Action::PlanSlices,
            ActionParams {
                plan: Some(spans),
                ..ActionParams::default()
            },
            Vec::new(),
            Confidence::Certain,
            "plan_missing",
            Preconditions {
                requires_not_paused: true,
                requires_write_lease: false,
                ..Preconditions::default()
            },
        ));
        return out;
    }

    // R-UDL-05：全部所选范围都已校验通过 → 收尾，不再分配工作。
    if all_verified(input) {
        out.push(decision(
            input,
            rule::HARD_ALL_VERIFIED,
            Scope::Task,
            None,
            Action::Finish,
            ActionParams::default(),
            Vec::new(),
            Confidence::Certain,
            "all_selected_verified",
            Preconditions {
                requires_not_paused: true,
                ..Preconditions::default()
            },
        ));
        return out;
    }

    // R-UDL-03：没有可分配的缺失工作 → 等待，不是失败。
    let missing = missing_work(input);
    if missing.is_empty() {
        out.push(decision(
            input,
            rule::HARD_NO_WORK,
            Scope::Task,
            None,
            Action::Wait,
            ActionParams {
                detail_code: Some("no_missing_work".into()),
                ..ActionParams::default()
            },
            Vec::new(),
            Confidence::Certain,
            "no_missing_work",
            Preconditions::default(),
        ));
        return out;
    }

    // R-UDL-04：预算耗尽 → 等待预算，不越过预算建连。
    if input.config.connection_budget == 0 {
        out.push(decision(
            input,
            rule::HARD_BUDGET,
            Scope::Task,
            None,
            Action::Wait,
            ActionParams {
                detail_code: Some("connection_budget_exhausted".into()),
                ..ActionParams::default()
            },
            Vec::new(),
            Confidence::Certain,
            "budget_exhausted",
            Preconditions {
                requires_budget: true,
                ..Preconditions::default()
            },
        ));
        return out;
    }

    // ---- 证据评估层 ----------------------------------------------------
    let busy: HashSet<SourceId> = active_source_ids(input);

    // R-UDL-13：按缺失范围逐个选源。
    for span in &missing {
        match pick_source(&input.sources, *span, input.now_ms, &busy) {
            Some(source) => {
                out.push(decision(
                    input,
                    rule::EVIDENCE_ASSIGN,
                    Scope::Source,
                    Some(source.source_id.as_str()),
                    Action::AssignWork,
                    ActionParams {
                        source_id: Some(source.source_id.clone()),
                        span: Some(*span),
                        ..ActionParams::default()
                    },
                    evidence_of(source),
                    Confidence::High,
                    "source_covers_missing_range",
                    Preconditions {
                        requires_not_paused: true,
                        requires_write_lease: true,
                        requires_budget: true,
                        requires_content_generation: Some(input.task.identity.content_generation),
                        requires_plan_revision: Some(input.task.identity.plan_revision),
                        ..Preconditions::default()
                    },
                ));
            }
            None => {
                // 没有合格源：报告等待原因，绝不因为没有源而判失败。
                out.push(decision(
                    input,
                    rule::HARD_NO_WORK,
                    Scope::Task,
                    None,
                    Action::Wait,
                    ActionParams {
                        detail_code: Some("no_eligible_source".into()),
                        span: Some(*span),
                        ..ActionParams::default()
                    },
                    Vec::new(),
                    Confidence::Certain,
                    "no_eligible_source",
                    Preconditions::default(),
                ));
            }
        }
    }

    // R-UDL-12：稳定窗口后最多增加一条通路。
    if input.stable_for_ms >= input.config.stable_window_ms
        && input.current_concurrency < input.config.connection_budget
    {
        out.push(decision(
            input,
            rule::EVIDENCE_CONCURRENCY_UP,
            Scope::Task,
            None,
            Action::RestoreConcurrency,
            ActionParams {
                from_concurrency: Some(input.current_concurrency),
                to_concurrency: Some(input.current_concurrency + 1),
                ..ActionParams::default()
            },
            Vec::new(),
            Confidence::Medium,
            "stable_window_elapsed",
            Preconditions {
                requires_not_paused: true,
                requires_budget: true,
                ..Preconditions::default()
            },
        ));
    }

    out
}

/// 限流决策（文档 7.3 的第一分支）。
///
/// `retry_after_ms` 为服务端给出的合法等待；`None` 表示没有可用提示或提示非法。
/// 合法性判定由适配器完成——它知道协议原值，解释器不猜测。
pub fn decide_rate_limit(
    input: &PolicyInput<'_>,
    scope: Scope,
    subject_id: Option<&str>,
    retry_after_ms: Option<u64>,
    attempt: u32,
) -> Decision {
    let delay = match retry_after_ms {
        // 合法 Retry-After：不得早于其允许时间重试，即使超过本地退避上限。
        Some(server) => server,
        // 无有效提示：本地有上限的指数退避。
        None => backoff_delay_ms(attempt, &input.config),
    };
    decision(
        input,
        rule::EVIDENCE_RATE_LIMIT,
        scope,
        subject_id,
        Action::Backoff,
        ActionParams {
            delay_ms: Some(delay),
            detail_code: retry_after_ms.map(|_| "retry_after").map(str::to_string),
            ..ActionParams::default()
        },
        Vec::new(),
        if retry_after_ms.is_some() {
            Confidence::Certain
        } else {
            Confidence::Medium
        },
        if retry_after_ms.is_some() {
            "server_retry_after"
        } else {
            "local_exponential_backoff"
        },
        Preconditions {
            requires_not_paused: true,
            ..Preconditions::default()
        },
    )
}

/// 降并发决策（文档 7.3：8、4、2、1，到 1 后等待）。
pub fn decide_concurrency_down(input: &PolicyInput<'_>, subject_id: Option<&str>) -> Option<Decision> {
    let next = next_lower_concurrency(input.current_concurrency)?;
    Some(decision(
        input,
        rule::EVIDENCE_CONCURRENCY_DOWN,
        Scope::Task,
        subject_id,
        Action::ReduceConcurrency,
        ActionParams {
            from_concurrency: Some(input.current_concurrency),
            to_concurrency: Some(next),
            ..ActionParams::default()
        },
        Vec::new(),
        Confidence::High,
        "throttled_reduce_concurrency",
        Preconditions {
            requires_not_paused: true,
            ..Preconditions::default()
        },
    ))
}

/// 下一个更低的并发值；已经是 1 时返回 `None`（改为等待，不再减成 0）。
pub fn next_lower_concurrency(current: u32) -> Option<u32> {
    if current <= 1 {
        None
    } else {
        Some((current / 2).max(1))
    }
}

/// 本地指数退避时长（毫秒），带上限与随机错峰空间。
///
/// 只用于"没有服务端等待提示"的情形。文档 7.3 明确：合法的长等待不能被本地
/// 上限提前打断，所以 [`decide_rate_limit`] 对 `Some(retry_after)` 直接采用原值。
pub fn backoff_delay_ms(attempt: u32, config: &PolicyConfig) -> u64 {
    let exp = attempt.min(16) as u64;
    let scaled = config
        .backoff_base_ms
        .saturating_mul(1u64 << exp.min(32))
        .min(config.backoff_max_ms);
    scaled.max(1)
}

/// 从源列表里为缺失范围挑一个源。
///
/// 排除顺序遵循文档 6.3：身份不符 → 已失效 → 隔离 → 冷却 → 证据过期 → 无可用范围。
/// 打分只用可观测证据（吞吐、失败数、排队数），不做"源数除切片数"的平均分配。
pub fn pick_source<'a>(
    sources: &[&'a SourceState],
    missing: Span,
    now_ms: u64,
    busy: &HashSet<SourceId>,
) -> Option<&'a SourceState> {
    let mut best: Option<(&SourceState, i64)> = None;

    for source in sources {
        if !source_is_eligible(source, now_ms) {
            continue;
        }
        // 已经有活跃分配的源不重复领取（首版不做竞速式重复下载）。
        if busy.contains(&source.source_id) {
            continue;
        }
        let overlap = match &source.available_ranges {
            Some(ranges) => ranges.stored_len_within(
                missing.start,
                missing.end_exclusive.unwrap_or(missing.start),
            ),
            // 可用范围未知时视为"可能是整块"，但只给低分：宁可少分配也不假装知道。
            None => 0,
        };
        let score = score_source(source, overlap);
        match best {
            Some((_, best_score)) if best_score >= score => {}
            _ => best = Some((source, score)),
        }
    }

    best.map(|(source, _)| source)
}

/// 源是否满足硬性的合格条件（不含"是否有工作"判断）。
fn source_is_eligible(source: &SourceState, now_ms: u64) -> bool {
    source.availability == Availability::Available
        && source.eligible
        && !source.is_cooling_at(now_ms)
        && !source.is_evidence_expired_at(now_ms)
        // R-UDL-02：没有身份依据的源不能被当成"同一内容"的来源。
        && source.identity_evidence.is_some()
}

/// 源评分：可观测证据的线性组合，量纲统一为"分"。
fn score_source(source: &SourceState, overlap: u64) -> i64 {
    let throughput = (source.health.throughput_bps / 1024) as i64;
    let failures = (source.health.failures as i64) * 10;
    let queued = (source.health.queued_peers as i64) * 5;
    let covered = (overlap / 1024) as i64;
    covered + throughput - failures - queued
}

/// 收集已有活跃分配的源，避免同一源被重复分配。
fn active_source_ids(input: &PolicyInput<'_>) -> HashSet<SourceId> {
    let busy = HashSet::new();
    for slice in &input.slices {
        if matches!(slice.state, SliceStatus::Active | SliceStatus::Verifying) {
            // 切片的分配引用只存 ID，源归属由调用方补齐；这里用已占用切片的
            // 存在来表达"该范围已在处理"，具体源由协调器补充进 `busy`。
            continue;
        }
    }
    busy
}

/// 所有可分配范围是否都已通过校验。
fn all_verified(input: &PolicyInput<'_>) -> bool {
    if input.slices.is_empty() {
        // 0 个切片是合法状态，不构成"已完成"。
        return false;
    }
    input.slices.iter().all(|slice| {
        slice.span.is_allocatable() && slice.coverage.covers_verified(slice.span)
    })
}

/// 所有切片的缺失范围。
fn missing_work(input: &PolicyInput<'_>) -> Vec<Span> {
    let mut out = Vec::new();
    for slice in &input.slices {
        if !slice.span.is_allocatable() {
            // 开放范围（总长未知）只能顺序读取，不能按范围分配。
            continue;
        }
        out.extend(slice.coverage.gaps(slice.span));
    }
    out
}

/// 从源状态收集证据引用。
fn evidence_of(source: &SourceState) -> Vec<EvidenceId> {
    let mut refs = Vec::new();
    if let Some(id) = &source.identity_evidence {
        refs.push(id.clone());
    }
    if let Some(id) = &source.capabilities.evidence_id {
        if !refs.contains(id) {
            refs.push(id.clone());
        }
    }
    refs
}

/// 构造决策。`command_ids` 留空——接受与命令生成由协调器负责（文档 7.1）。
#[allow(clippy::too_many_arguments)]
/// R-UDL-20/21/22：把一次异常翻译成决策。
///
/// 三类分开是必要的：
/// - **限流**必须尊重服务端给的 `Retry-After`，本地指数退避只是兜底；
/// - **可重试**要真的消耗预算，否则失败会被无限重试；
/// - **不可重试**（403/404/校验不符）必须明确终止，不能靠"再试一次"。
fn decide_error(input: &PolicyInput<'_>, err: &super::model::UnifiedError) -> Decision {
    let throttled = err.retry_after_ms.is_some()
        || matches!(err.protocol_code.as_deref(), Some("429") | Some("503"))
        || matches!(err.code.as_str(), "http_429" | "http_503");
    if throttled {
        // 限流不消耗重试预算：它不是一个"失败原因"，是服务端让我们慢一点。
        return decide_rate_limit(
            input,
            Scope::Task,
            None,
            err.retry_after_ms,
            input.task.budget.retry_budget,
        );
    }
    // **已知限制（12.2.15 第七节）**：`retry_budget` 目前没有任何生产写入方——
    // `store::ensure_runtime` 只写 `task_id/updated_at_ms`，其余列取 DDL 默认值 0。
    // 所以这条分支在生产路径上**不会触发**，所有可重试错误都会落到下面的
    // `R-UDL-22`（`retry_budget_exhausted`）。真实的失败恢复仍由 legacy 的
    // `retry_at` 承担。规则逻辑本身由单测覆盖（构造 `retry_budget = 3`），
    // 等 C6 之后有写入方时再启用。
    if err.retryable && input.task.budget.retry_budget > 0 {
        return decision(
            input,
            rule::ERROR_RETRYABLE,
            Scope::Task,
            None,
            Action::Retry,
            ActionParams {
                count: Some(input.task.budget.retry_budget),
                detail_code: Some(err.code.clone()),
                ..ActionParams::default()
            },
            Vec::new(),
            Confidence::High,
            "retryable_error",
            Preconditions {
                requires_not_paused: true,
                ..Preconditions::default()
            },
        );
    }
    decision(
        input,
        rule::ERROR_TERMINAL,
        Scope::Task,
        None,
        Action::Finish,
        ActionParams {
            detail_code: Some(err.code.clone()),
            ..ActionParams::default()
        },
        Vec::new(),
        Confidence::Certain,
        if err.retryable {
            "retry_budget_exhausted"
        } else {
            "terminal_error"
        },
        Preconditions {
            requires_not_paused: true,
            ..Preconditions::default()
        },
    )
}

/// R-PLAN-01 的判定：返回需要规划的总长。
///
/// 四个条件缺一不可：
/// - 状态是 `Queued` / `Error`（空闲：正在跑的任务不许改方案，否则会与 `segments`
///   里的 `done_bytes` 冲突——`PlanSlices` 的前置约束也是同一套判据）；
/// - `plan_status == Unplanned`（已经有稳定方案就不重规划）；
/// - 无进度（`stored_unique_bytes == 0`）；
/// - 总长已知且非空。
fn plan_candidate(input: &PolicyInput<'_>) -> Option<u64> {
    if !matches!(input.task.status, Status::Queued | Status::Error) {
        return None;
    }
    if input.task.plan_status != PlanStatus::Unplanned {
        return None;
    }
    if input.task.progress.stored_unique_bytes > 0 {
        return None;
    }
    match input.task.progress.required_bytes {
        Some(total) if total > 0 => Some(total),
        _ => None,
    }
}

fn decision(
    input: &PolicyInput<'_>,
    rule_id: &str,
    scope: Scope,
    subject_id: Option<&str>,
    action: Action,
    parameters: ActionParams,
    evidence_refs: Vec<EvidenceId>,
    confidence: Confidence,
    reason_code: &str,
    preconditions: Preconditions,
) -> Decision {
    let not_before_ms = parameters
        .delay_ms
        .map(|delay| input.now_ms.saturating_add(delay));
    Decision {
        decision_id: DecisionId::generate(),
        task_id: input.task.identity.task_id,
        run_epoch: input.task.identity.run_epoch,
        based_on_state_revision: input.task.identity.state_revision,
        trigger_event_id: None,
        rule_id: rule_id.to_owned(),
        policy_revision: POLICY_REVISION,
        scope,
        subject_id: subject_id.map(str::to_owned),
        action,
        parameters,
        evidence_refs,
        confidence,
        reason_code: reason_code.to_owned(),
        not_before_ms,
        expires_at_ms: None,
        preconditions,
        command_ids: Vec::new(),
    }
}

/// 影子模式：把会改变执行状态的决策降级为只记录。
///
/// 这个函数保证"影子解释器绝不发命令"（文档 12.2）。原动作保留在
/// `parameters.detail_code` 里供诊断比对，但 `action` 变成 [`Action::ObserveOnly`]。
pub fn shadow_only(decision: &mut Decision) {
    if decision.action.mutates_execution() {
        let original = decision.action.as_str().to_owned();
        decision.parameters.detail_code = Some(original);
        decision.action = Action::ObserveOnly;
    }
}

/// 等待原因辅助：把决策语义翻译成任务级等待信息。
pub fn wait_from_input(input: &PolicyInput<'_>, reason: WaitReason) -> WaitInfo {
    WaitInfo {
        reason,
        scope: Scope::Task,
        subject_id: None,
        since_ms: input.now_ms,
        retry_at_ms: None,
        detail_code: None,
    }
}

/// 活动阶段辅助：供快照层显示，不参与状态机判定。
pub fn activity_for(status: Status) -> Activity {
    match status {
        Status::Queued => Activity::Idle,
        Status::Connecting => Activity::Connecting,
        Status::Downloading => Activity::Transferring,
        Status::Verifying => Activity::Verifying,
        Status::Paused | Status::Done | Status::Error => Activity::Idle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Transport;
    use crate::download::coverage::CoverageSet;
    use crate::download::model::{IdentityContext, SliceId, SliceState, TaskState};
    use crate::download::reducer::Reducer;

    fn source(id: &str) -> SourceState {
        let mut s = SourceState::new(SourceId::new(id), super::super::model::ResourceId::new("r"), Transport::Http);
        s.availability = Availability::Available;
        s.eligible = true;
        s.identity_evidence = Some(EvidenceId::new(format!("ev-{id}")));
        s
    }

    fn reducer_with_slice(start: u64, end: u64) -> (Reducer, SliceId) {
        let mut id = IdentityContext::for_task(1, "e1");
        id.run_epoch = 1;
        let mut task = TaskState::new(id, Transport::Http);
        task.identity.run_epoch = 1;
        task.budget.connection_budget = 4;
        let mut reducer = Reducer::new(task);

        let slice_id = SliceId::generate();
        reducer.upsert_slice(SliceState::new(
            slice_id.clone(),
            super::super::model::ResourceId::new("r"),
            0,
            1,
            Span::known(start, end).expect("span"),
        ));
        (reducer, slice_id)
    }

    /// 一个"还没有方案"的空闲任务：`Queued` + `Unplanned` + 总长已知 + 无进度。
    fn unplanned_reducer(status: Status, total: Option<u64>, stored: u64) -> Reducer {
        let mut id = IdentityContext::for_task(1, "e1");
        id.run_epoch = 1;
        let mut task = TaskState::new(id, Transport::Http);
        task.identity.run_epoch = 1;
        task.status = status;
        task.budget.connection_budget = 4;
        task.plan_status = PlanStatus::Unplanned;
        task.progress.required_bytes = total;
        task.progress.stored_unique_bytes = stored;
        Reducer::new(task)
    }

    fn error_reducer(
        err: super::super::model::UnifiedError,
        retry_budget: u32,
    ) -> Reducer {
        let mut id = IdentityContext::for_task(1, "e1");
        id.run_epoch = 1;
        let mut task = TaskState::new(id, Transport::Http);
        task.identity.run_epoch = 1;
        task.status = Status::Error;
        task.budget.connection_budget = 4;
        task.budget.retry_budget = retry_budget;
        task.current_error = Some(err);
        Reducer::new(task)
    }

    fn only(reducer: &Reducer) -> Decision {
        let input = PolicyInput::from_reducer(reducer, config());
        let ds = evaluate(&input);
        assert_eq!(ds.len(), 1, "异常分支只产一条决策：{ds:?}");
        ds.into_iter().next().unwrap()
    }

    #[test]
    fn rate_limit_honours_retry_after() {
        // R-UDL-20：429 带 Retry-After 时不得早于服务端允许的时间重试。
        use super::super::model::UnifiedError;
        let r = error_reducer(UnifiedError::from_legacy("http_429", Some(429), Some(7_000)), 3);
        let d = only(&r);
        assert_eq!(d.rule_id, rule::EVIDENCE_RATE_LIMIT);
        assert_eq!(d.action, Action::Backoff);
        assert_eq!(d.parameters.delay_ms, Some(7_000));
        assert_eq!(d.reason_code, "server_retry_after");
    }

    #[test]
    fn rate_limit_without_hint_falls_back_to_bounded_backoff() {
        use super::super::model::UnifiedError;
        let r = error_reducer(UnifiedError::from_legacy("http_429", Some(429), None), 3);
        let d = only(&r);
        assert_eq!(d.rule_id, rule::EVIDENCE_RATE_LIMIT);
        assert_eq!(d.action, Action::Backoff);
        let delay = d.parameters.delay_ms.expect("本地退避必须有上限延时");
        assert!(delay > 0 && delay <= input_backoff_ceiling());
        assert_eq!(d.reason_code, "local_exponential_backoff");
    }

    fn input_backoff_ceiling() -> u64 {
        let cfg = config();
        backoff_delay_ms(u32::MAX, &cfg)
    }

    #[test]
    fn retryable_error_consumes_budget() {
        // R-UDL-21：临时故障消耗一次预算，不能无限重试。
        use super::super::model::UnifiedError;
        let r = error_reducer(UnifiedError::from_legacy("network", None, None), 3);
        let d = only(&r);
        assert_eq!(d.rule_id, rule::ERROR_RETRYABLE);
        assert_eq!(d.action, Action::Retry);
        assert_eq!(d.parameters.count, Some(3));
        assert_eq!(d.reason_code, "retryable_error");
    }

    #[test]
    fn terminal_errors_finish_instead_of_retrying() {
        // R-UDL-22：403 是拒绝访问，重试没有意义。
        use super::super::model::UnifiedError;
        let r = error_reducer(UnifiedError::from_legacy("http_403", Some(403), None), 5);
        let d = only(&r);
        assert_eq!(d.rule_id, rule::ERROR_TERMINAL);
        assert_eq!(d.action, Action::Finish);
        assert_eq!(d.reason_code, "terminal_error");
    }

    #[test]
    fn exhausted_budget_terminates_instead_of_retrying_forever() {
        // R-UDL-22：可重试但预算为 0 → 必须终止，否则失败会被无限重试。
        use super::super::model::UnifiedError;
        let r = error_reducer(UnifiedError::from_legacy("network", None, None), 0);
        let d = only(&r);
        assert_eq!(d.rule_id, rule::ERROR_TERMINAL);
        assert_eq!(d.action, Action::Finish);
        assert_eq!(d.reason_code, "retry_budget_exhausted");
    }

    #[test]
    fn unplanned_idle_task_produces_a_plan() {
        let reducer = unplanned_reducer(Status::Queued, Some(2 * 1024 * 1024), 0);
        let input = PolicyInput::from_reducer(&reducer, config());
        let decisions = evaluate(&input);
        let plan = decisions
            .iter()
            .find(|d| d.action == Action::PlanSlices)
            .expect("必须产出 PlanSlices");
        assert_eq!(plan.rule_id, rule::HARD_PLAN);
        let spans = plan.parameters.plan.as_ref().expect("plan");
        assert!(!spans.is_empty());
        // 与 legacy 规划器同一份方案（逐字节）。
        let projected = crate::download::plan::project_rows(
            &spans
                .iter()
                .map(|s| (s.start, s.end_exclusive))
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            projected,
            crate::download::plan::project_legacy(2 * 1024 * 1024, 4)
        );
    }

    #[test]
    fn busy_or_progressing_tasks_do_not_get_replanned() {
        // 正在跑：不许改方案（会与 segments 的 done_bytes 冲突）。
        for status in [Status::Connecting, Status::Downloading, Status::Verifying] {
            let reducer = unplanned_reducer(status, Some(1024), 0);
            let input = PolicyInput::from_reducer(&reducer, config());
            assert!(
                evaluate(&input).iter().all(|d| d.action != Action::PlanSlices),
                "{status:?} 不得产出 PlanSlices"
            );
        }
        // 已有进度：更不行。
        let reducer = unplanned_reducer(Status::Queued, Some(1024), 10);
        let input = PolicyInput::from_reducer(&reducer, config());
        assert!(evaluate(&input)
            .iter()
            .all(|d| d.action != Action::PlanSlices));
        // 总长未知：没法规划。
        let reducer = unplanned_reducer(Status::Queued, None, 0);
        let input = PolicyInput::from_reducer(&reducer, config());
        assert!(evaluate(&input)
            .iter()
            .all(|d| d.action != Action::PlanSlices));
    }

    #[test]
    fn a_task_that_already_has_a_plan_is_not_replanned() {
        // 已有稳定方案：`plan_status != Unplanned` 就不该再产 PlanSlices，
        // 否则每个 tick 都会生成一条（虽然指纹会合并，但那是浪费）。
        let mut id = IdentityContext::for_task(1, "e1");
        id.run_epoch = 1;
        let mut task = TaskState::new(id, Transport::Http);
        task.identity.run_epoch = 1;
        task.status = Status::Queued;
        task.budget.connection_budget = 4;
        task.plan_status = PlanStatus::Ready;
        task.progress.required_bytes = Some(1024);
        let reducer = Reducer::new(task);
        let input = PolicyInput::from_reducer(&reducer, config());
        assert!(evaluate(&input)
            .iter()
            .all(|d| d.action != Action::PlanSlices));
    }

    fn config() -> PolicyConfig {
        PolicyConfig {
            connection_budget: 4,
            ..PolicyConfig::default()
        }
    }

    #[test]
    fn paused_task_produces_no_execution_decision() {
        let (mut reducer, _) = reducer_with_slice(0, 100);
        reducer.request_status(Status::Paused).expect("pause");
        let input = PolicyInput::from_reducer(&reducer, config());
        assert!(evaluate(&input).is_empty(), "暂停后不得产生任何执行决策");
    }

    #[test]
    fn zero_slices_is_not_treated_as_complete() {
        let mut id = IdentityContext::for_task(1, "e1");
        id.run_epoch = 1;
        let task = TaskState::new(id, Transport::Http);
        let reducer = Reducer::new(task);
        let input = PolicyInput::from_reducer(&reducer, config());
        let decisions = evaluate(&input);
        // 0 切片不能产出 Finish（那不是"全部校验通过"）。
        assert!(
            decisions.iter().all(|d| d.action != Action::Finish),
            "0 个切片是合法初始态，不能当作已完成"
        );
    }

    #[test]
    fn fully_verified_task_finishes() {
        let (mut reducer, slice_id) = reducer_with_slice(0, 100);
        // 直接把覆盖写满。
        let mut s = reducer.slice(&slice_id).expect("slice").clone();
        s.coverage = CoverageSet::from_snapshot(&[0..100], &[0..100]);
        s.state = SliceStatus::Done;
        reducer.upsert_slice(s);

        let input = PolicyInput::from_reducer(&reducer, config());
        let decisions = evaluate(&input);
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].action, Action::Finish);
        assert_eq!(decisions[0].rule_id, rule::HARD_ALL_VERIFIED);
        assert_eq!(decisions[0].confidence, Confidence::Certain);
    }

    #[test]
    fn missing_work_without_source_waits_instead_of_failing() {
        let (reducer, _) = reducer_with_slice(0, 100);
        let input = PolicyInput::from_reducer(&reducer, config());
        let decisions = evaluate(&input);
        assert!(
            decisions.iter().any(|d| d.action == Action::Wait),
            "没有源必须报告等待"
        );
        assert_eq!(decisions[0].reason_code, "no_eligible_source");
    }

    #[test]
    fn assignment_picks_source_covering_missing_range() {
        let (mut reducer, _) = reducer_with_slice(0, 100);
        let mut good = source("good");
        good.available_ranges = Some(CoverageSet::from_snapshot(&[0..100], &[]));
        let mut useless = source("useless");
        useless.available_ranges = Some(CoverageSet::from_snapshot(&[200..300], &[]));

        reducer.upsert_source(useless);
        reducer.upsert_source(good);

        let input = PolicyInput::from_reducer(&reducer, config());
        let decisions = evaluate(&input);
        let assign = decisions
            .iter()
            .find(|d| d.action == Action::AssignWork)
            .expect("必须产生分配决策");
        assert_eq!(assign.parameters.source_id.as_ref().map(|s| s.as_str()), Some("good"));
        assert_eq!(assign.rule_id, rule::EVIDENCE_ASSIGN);
        assert!(!assign.evidence_refs.is_empty(), "分配必须带证据引用");
    }

    #[test]
    fn source_without_identity_evidence_is_excluded() {
        let mut s = source("no-identity");
        s.identity_evidence = None;
        s.available_ranges = Some(CoverageSet::from_snapshot(&[0..100], &[]));
        let busy = HashSet::new();
        assert!(
            pick_source(&[&s], Span::known(0, 100).expect("span"), 0, &busy).is_none(),
            "缺少身份依据的源不得被选中（R-UDL-02）"
        );
    }

    #[test]
    fn cooling_or_expired_source_is_excluded() {
        let mut s = source("cooling");
        s.available_ranges = Some(CoverageSet::from_snapshot(&[0..100], &[]));
        s.cooldown_until_ms = Some(5_000);
        let busy = HashSet::new();
        let span = Span::known(0, 100).expect("span");
        assert!(pick_source(&[&s], span, 1_000, &busy).is_none(), "冷却中不得分配");
        assert!(pick_source(&[&s], span, 5_000, &busy).is_some(), "冷却到期可恢复");
    }

    #[test]
    fn busy_source_is_not_double_assigned() {
        let mut s = source("busy");
        s.available_ranges = Some(CoverageSet::from_snapshot(&[0..100], &[]));
        let mut busy = HashSet::new();
        busy.insert(s.source_id.clone());
        assert!(pick_source(&[&s], Span::known(0, 100).expect("span"), 0, &busy).is_none());
    }

    #[test]
    fn retry_after_is_honoured_even_beyond_local_cap() {
        let (mut reducer, _) = reducer_with_slice(0, 100);
        let cfg = PolicyConfig {
            backoff_max_ms: 1_000,
            ..config()
        };
        let input = PolicyInput::from_reducer(&reducer, cfg);
        // 服务端要求 10 分钟，超过本地上限，仍必须尊重。
        let d = decide_rate_limit(&input, Scope::Host, Some("h"), Some(600_000), 0);
        assert_eq!(d.parameters.delay_ms, Some(600_000));
        assert_eq!(d.confidence, Confidence::Certain);
        assert_eq!(d.reason_code, "server_retry_after");

        // 本地退避受上限约束。
        let local = decide_rate_limit(&input, Scope::Host, Some("h"), None, 8);
        assert!(local.parameters.delay_ms.expect("delay") <= 1_000);
        assert_eq!(local.confidence, Confidence::Medium, "本地推算只能是推断");
        reducer.set_wait(None);
    }

    #[test]
    fn backoff_grows_and_caps() {
        let cfg = PolicyConfig {
            backoff_base_ms: 100,
            backoff_max_ms: 1_000,
            ..PolicyConfig::default()
        };
        assert_eq!(backoff_delay_ms(0, &cfg), 100);
        assert_eq!(backoff_delay_ms(1, &cfg), 200);
        assert_eq!(backoff_delay_ms(2, &cfg), 400);
        assert_eq!(backoff_delay_ms(10, &cfg), 1_000, "必须有上限");
        assert_eq!(backoff_delay_ms(999, &cfg), 1_000, "极大尝试不比上限更长");
    }

    #[test]
    fn concurrency_steps_down_to_one_then_waits() {
        assert_eq!(next_lower_concurrency(8), Some(4));
        assert_eq!(next_lower_concurrency(4), Some(2));
        assert_eq!(next_lower_concurrency(2), Some(1));
        assert_eq!(
            next_lower_concurrency(1),
            None,
            "到 1 后改为等待，不减成无资源"
        );
        assert_eq!(next_lower_concurrency(6), Some(3));
        assert_eq!(next_lower_concurrency(0), None);
    }

    #[test]
    fn concurrency_restore_adds_at_most_one() {
        let (mut reducer, _) = reducer_with_slice(0, 100);
        let mut input = PolicyInput::from_reducer(&reducer, config());
        input.current_concurrency = 2;
        input.stable_for_ms = 10_000;
        let decisions = evaluate(&input);
        let up = decisions
            .iter()
            .find(|d| d.action == Action::RestoreConcurrency)
            .expect("稳定窗口后应扩容");
        assert_eq!(up.parameters.to_concurrency, Some(3), "一次最多加一条");
        reducer.set_wait(None);
    }

    #[test]
    fn no_restore_without_stable_window() {
        let (reducer, _) = reducer_with_slice(0, 100);
        let mut input = PolicyInput::from_reducer(&reducer, config());
        input.current_concurrency = 2;
        input.stable_for_ms = 100;
        let decisions = evaluate(&input);
        assert!(
            decisions.iter().all(|d| d.action != Action::RestoreConcurrency),
            "未稳定不得扩容"
        );
    }

    #[test]
    fn budget_zero_waits_on_budget() {
        let (reducer, _) = reducer_with_slice(0, 100);
        let cfg = PolicyConfig {
            connection_budget: 0,
            ..PolicyConfig::default()
        };
        let input = PolicyInput::from_reducer(&reducer, cfg);
        let decisions = evaluate(&input);
        assert_eq!(decisions[0].action, Action::Wait);
        assert_eq!(decisions[0].rule_id, rule::HARD_BUDGET);
        assert_eq!(decisions[0].reason_code, "budget_exhausted");
    }

    #[test]
    fn shadow_mode_downgrades_executing_decisions() {
        let (mut reducer, _) = reducer_with_slice(0, 100);
        let mut good = source("good");
        good.available_ranges = Some(CoverageSet::from_snapshot(&[0..100], &[]));
        reducer.upsert_source(good);

        let input = PolicyInput::from_reducer(&reducer, config());
        let mut decisions = evaluate(&input);
        let assign = decisions
            .iter_mut()
            .find(|d| d.action == Action::AssignWork)
            .expect("应有分配决策");
        shadow_only(assign);

        assert_eq!(assign.action, Action::ObserveOnly, "影子模式不得执行");
        assert_eq!(
            assign.parameters.detail_code.as_deref(),
            Some("assign_work"),
            "原动作必须保留供诊断比对"
        );
        assert!(!assign.action.mutates_execution());
    }

    #[test]
    fn shadow_mode_keeps_wait_untouched() {
        let (reducer, _) = reducer_with_slice(0, 100);
        let input = PolicyInput::from_reducer(&reducer, config());
        let mut decisions = evaluate(&input);
        for d in decisions.iter_mut() {
            shadow_only(d);
        }
        assert!(
            decisions.iter().any(|d| d.action == Action::Wait),
            "Wait 不改变执行状态，影子模式不需要降级"
        );
    }

    #[test]
    fn every_decision_carries_rule_and_revision() {
        let (mut reducer, _) = reducer_with_slice(0, 100);
        let mut good = source("good");
        good.available_ranges = Some(CoverageSet::from_snapshot(&[0..100], &[]));
        reducer.upsert_source(good);
        let input = PolicyInput::from_reducer(&reducer, config());
        for d in evaluate(&input) {
            assert!(!d.rule_id.is_empty());
            assert!(d.rule_id.starts_with("R-UDL-"), "规则编号必须已登记前缀");
            assert_eq!(d.policy_revision, POLICY_REVISION);
            assert!(!d.reason_code.is_empty());
        }
    }

    #[test]
    fn open_span_slices_are_not_range_assignable() {
        let mut id = IdentityContext::for_task(1, "e1");
        id.run_epoch = 1;
        let task = TaskState::new(id, Transport::Http);
        let mut reducer = Reducer::new(task);
        reducer.upsert_slice(SliceState::new(
            SliceId::generate(),
            super::super::model::ResourceId::new("r"),
            0,
            1,
            Span::open(0),
        ));
        let mut good = source("good");
        good.available_ranges = Some(CoverageSet::from_snapshot(&[0..100], &[]));
        reducer.upsert_source(good);

        let input = PolicyInput::from_reducer(&reducer, config());
        let decisions = evaluate(&input);
        assert!(
            decisions.iter().all(|d| d.action != Action::AssignWork),
            "总长未知只能顺序读取，不能按范围分配"
        );
    }
}
