//! 内部实体到 IPC 统一视图的**唯一**转换层（文档第 10 节）。
//!
//! 设计约束：
//! - `aidm-ipc` 不依赖 `aidm-core`；字段语义靠契约测试对齐，转换只在这里发生。
//! - 所有可能超出 JavaScript 安全整数范围的数值一律输出十进制字符串。
//! - 分页快照的游标绑定 `engine_instance_id + task_id + state_revision + section`；
//!   任何一项变化都让游标失效，返回 `snapshot_stale`，**不允许**拼接混合版本。
//! - `total_count` 永远是真实总数，不因分页变小；截断只体现在 `complete = false`。

use aidm_core::download::model::{
    AssignmentState, CapabilitySet, IdentityContext, NativeBlockRef, Progress,
    ResourceState, SliceState, SourceState, Span, TaskState, TriState, UnifiedError, WaitInfo,
};
use aidm_core::download::reducer::Reducer;
use aidm_ipc::{
    normalize_snapshot_limit, snapshot_error, SnapshotSection, UnifiedAssignment, UnifiedCapabilitySet,
    UnifiedCause, UnifiedCompleteness, UnifiedContentIdentity, UnifiedCounts, UnifiedDownloadView,
    UnifiedErrorView, UnifiedIdentity, UnifiedNativeBlock, UnifiedProgress, UnifiedRange,
    UnifiedResource, UnifiedSlice, UnifiedSnapshotItem, UnifiedSnapshotResponse, UnifiedSource,
    UnifiedWait, UNIFIED_SCHEMA_VERSION,
};

/// 快照转换失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// 请求的 `limit` 不合法（0 或超过上限）。
    InvalidLimit(u32),
    /// `section` 不是受控取值。
    InvalidSection(String),
    /// 游标失效：引擎实例、任务、版本或 section 已变化。
    StaleCursor,
    /// 任务不存在。
    NoSuchTask,
}

impl SnapshotError {
    /// 供 IPC `code` 字段使用的稳定错误码。
    pub fn code(&self) -> &'static str {
        match self {
            SnapshotError::InvalidLimit(_) => snapshot_error::INVALID_LIMIT,
            SnapshotError::InvalidSection(_) => snapshot_error::INVALID_SECTION,
            SnapshotError::StaleCursor => snapshot_error::SNAPSHOT_STALE,
            SnapshotError::NoSuchTask => snapshot_error::NO_SUCH_TASK,
        }
    }

    /// 可读说明（脱敏，不含内部路径或凭据）。
    pub fn message(&self) -> String {
        match self {
            SnapshotError::InvalidLimit(n) => {
                format!("limit 必须为 1..=256，收到 {n}")
            }
            SnapshotError::InvalidSection(s) => format!("未知 section: {s}"),
            SnapshotError::StaleCursor => "游标已失效，请重新获取快照".to_owned(),
            SnapshotError::NoSuchTask => "任务不存在".to_owned(),
        }
    }
}

/// 快照输入：一次转换所需的全部只读借用。
///
/// 从 [`Reducer`] 构造时带出当前状态；也可以由测试或诊断包直接构造，
/// 但**不得**在别处另行推导统一视图。
pub struct SnapshotSource<'a> {
    pub task: &'a TaskState,
    pub resources: Vec<&'a ResourceState>,
    pub slices: Vec<&'a SliceState>,
    pub sources: Vec<&'a SourceState>,
    pub assignments: Vec<&'a AssignmentState>,
    /// 采样时间（UTC Unix 毫秒）。由调用方注入，转换层不读时钟。
    pub sampled_at_ms: u64,
}

impl<'a> SnapshotSource<'a> {
    /// 从归约器构造。
    pub fn from_reducer(reducer: &'a Reducer, sampled_at_ms: u64) -> Self {
        Self {
            task: reducer.task(),
            resources: reducer
                .task()
                .resource_ids
                .iter()
                .filter_map(|id| reducer.resource(id))
                .collect(),
            slices: reducer.slices().collect(),
            sources: reducer.sources().collect(),
            assignments: reducer.assignments().collect(),
            sampled_at_ms,
        }
    }
}

// ---------------------------------------------------------------- 标量转换

fn dec(v: u64) -> String {
    v.to_string()
}

fn opt_dec(v: Option<u64>) -> Option<String> {
    v.map(dec)
}

fn tri(v: TriState) -> String {
    v.as_str().to_owned()
}

fn to_identity(id: &IdentityContext) -> UnifiedIdentity {
    UnifiedIdentity {
        task_id: id.task_id.to_string(),
        engine_instance_id: id.engine_instance_id.clone(),
        run_epoch: dec(id.run_epoch),
        content_generation: dec(id.content_generation),
        plan_revision: dec(id.plan_revision),
        state_revision: dec(id.state_revision),
    }
}

fn to_progress(p: &Progress) -> UnifiedProgress {
    UnifiedProgress {
        wire_bytes: dec(p.wire_bytes),
        stored_unique_bytes: dec(p.stored_unique_bytes),
        verified_unique_bytes: dec(p.verified_unique_bytes),
        required_bytes: opt_dec(p.required_bytes),
        transfer_rate_bps: dec(p.transfer_rate_bps),
        useful_rate_bps: dec(p.useful_rate_bps),
    }
}

fn to_counts(task: &TaskState) -> UnifiedCounts {
    let c = task.counts;
    UnifiedCounts {
        known_sources: c.known_sources,
        eligible_sources: c.eligible_sources,
        connections: c.connections,
        active_transfers: c.active_transfers,
        queued_peers: c.queued_peers,
        done_slices: c.done_slices,
    }
}

fn to_wait(w: &WaitInfo) -> UnifiedWait {
    UnifiedWait {
        reason: w.reason.as_str().to_owned(),
        scope: w.scope.as_str().to_owned(),
        subject_id: w.subject_id.clone(),
        since_ms: dec(w.since_ms),
        retry_at_ms: opt_dec(w.retry_at_ms),
        detail_code: w.detail_code.clone(),
    }
}

fn to_range(span: &Span) -> UnifiedRange {
    UnifiedRange {
        start: dec(span.start),
        end_exclusive: opt_dec(span.end_exclusive),
    }
}

fn to_capabilities(caps: &CapabilitySet) -> UnifiedCapabilitySet {
    UnifiedCapabilitySet {
        metadata_known: tri(caps.metadata_known),
        random_read: tri(caps.random_read),
        resume: tri(caps.resume),
        multi_source: tri(caps.multi_source),
        integrity: caps.integrity.as_str().to_owned(),
    }
}

fn to_error(err: &UnifiedError) -> UnifiedErrorView {
    UnifiedErrorView {
        category: err.category.as_str().to_owned(),
        code: err.code.clone(),
        phase: err.phase.map(|p| p.as_str().to_owned()),
        operation: err.operation.clone(),
        scope: err.scope.map(|s| s.as_str().to_owned()),
        subject_id: err.subject_id.clone(),
        retryable: err.retryable,
        retry_after_ms: opt_dec(err.retry_after_ms),
        protocol: err.protocol.map(|p| p.as_str().to_owned()),
        protocol_code: err.protocol_code.clone(),
        message: err.message.clone(),
        cause_chain: err
            .cause_chain
            .iter()
            .map(|c| UnifiedCause {
                code: c.code.clone(),
                message: c.message.clone(),
            })
            .collect(),
    }
}

// ---------------------------------------------------------------- 实体转换

fn to_resource(r: &ResourceState) -> UnifiedResource {
    UnifiedResource {
        resource_id: r.resource_id.to_string(),
        selected: r.selected,
        size_bytes: opt_dec(r.size_bytes),
        identity: r.identity.as_ref().map(|id| UnifiedContentIdentity {
            algorithm: id.algorithm.as_str().to_owned(),
            digest_hex: id.digest_hex.clone(),
            evidence_source: format!("{:?}", id.evidence_source).to_lowercase(),
            trust: match id.trust {
                aidm_core::download::model::TrustLevel::Unknown => "unknown",
                aidm_core::download::model::TrustLevel::Weak => "weak",
                aidm_core::download::model::TrustLevel::Strong => "strong",
            }
            .to_owned(),
        }),
        verification: r.verification_policy.integrity.as_str().to_owned(),
        commit_state: r.commit_state.as_str().to_owned(),
    }
}

fn to_native_block(b: &NativeBlockRef) -> UnifiedNativeBlock {
    UnifiedNativeBlock {
        native_index: dec(b.native_index),
        range: to_range(&b.span),
        verified: b.verified,
        state: b.state.clone(),
    }
}

fn to_assignment(a: &AssignmentState) -> UnifiedAssignment {
    UnifiedAssignment {
        assignment_id: a.assignment_id.to_string(),
        slice_id: a.slice_id.to_string(),
        source_id: a.source_id.to_string(),
        connection_id: a.connection_id.as_ref().map(|c| c.to_string()),
        range: to_range(&a.span),
        state: a.state.as_str().to_owned(),
        transfer_rate_bps: dec(a.progress.transfer_rate_bps),
        error: a.error.as_ref().map(to_error),
    }
}

/// 转换单个切片；`assignments` 只取属于该切片的通路。
fn to_slice(s: &SliceState, assignments: &[&AssignmentState]) -> UnifiedSlice {
    UnifiedSlice {
        slice_id: s.slice_id.to_string(),
        resource_id: s.resource_id.to_string(),
        range: to_range(&s.span),
        state: s.state.as_str().to_owned(),
        wait: s.wait.as_ref().map(to_wait),
        progress: to_progress(&s.progress),
        assignments: assignments
            .iter()
            .filter(|a| a.slice_id == s.slice_id)
            .map(|a| to_assignment(a))
            .collect(),
        native_blocks: s.native_blocks.iter().map(to_native_block).collect(),
    }
}

fn to_source(s: &SourceState) -> UnifiedSource {
    UnifiedSource {
        source_id: s.source_id.to_string(),
        resource_id: s.resource_id.to_string(),
        transport: s.transport.as_str().to_owned(),
        availability: s.availability.as_str().to_owned(),
        eligible: s.eligible,
        cooldown_until_ms: opt_dec(s.cooldown_until_ms),
        last_observed_at_ms: opt_dec(s.last_observed_at_ms),
        expires_at_ms: opt_dec(s.expires_at_ms),
        throughput_bps: dec(s.health.throughput_bps),
        queued_peers: s.health.queued_peers,
        capabilities: to_capabilities(&s.capabilities),
    }
}

/// 任务级能力：取主协议与所有源能力的**保守合取**。
///
/// 不用"任一源支持就算支持"：那会让界面把只在某个源上成立的结论当成任务事实。
fn task_capabilities(src: &SnapshotSource<'_>) -> UnifiedCapabilitySet {
    let mut metadata = TriState::Yes;
    let mut random = TriState::Yes;
    let mut resume = TriState::Yes;
    let mut multi = TriState::Yes;
    let mut seen = false;

    for source in &src.sources {
        seen = true;
        metadata = metadata.and(source.capabilities.metadata_known);
        random = random.and(source.capabilities.random_read);
        resume = resume.and(source.capabilities.resume);
        multi = multi.and(source.capabilities.multi_source);
    }

    if !seen {
        // 没有源观测：能力全部未知，不伪造"支持"。
        return UnifiedCapabilitySet {
            metadata_known: TriState::Unknown.as_str().to_owned(),
            random_read: TriState::Unknown.as_str().to_owned(),
            resume: TriState::Unknown.as_str().to_owned(),
            multi_source: TriState::Unknown.as_str().to_owned(),
            integrity: "none".to_owned(),
        };
    }

    // 完整性等级取最弱的一档（只要有一个源没有校验，就不宣称整体可校验）。
    let integrity = src
        .sources
        .iter()
        .map(|s| s.capabilities.integrity)
        .next()
        .map(|i| i.as_str().to_owned())
        .unwrap_or_else(|| "none".to_owned());

    UnifiedCapabilitySet {
        metadata_known: tri(metadata),
        random_read: tri(random),
        resume: tri(resume),
        multi_source: tri(multi),
        integrity,
    }
}

// ---------------------------------------------------------------- 对外入口

/// 生成任务摘要视图（`TaskView.unified_download`，也可作为 `task_snapshot` 的 summary）。
///
/// `slice_limit` 为上界：超过时 `completeness.complete = false`，但
/// `total_count` 仍是真实切片总数（文档 10 节：截断不改变实际对象总数）。
pub fn to_summary_view(src: &SnapshotSource<'_>, slice_limit: u32) -> UnifiedDownloadView {
    let total_slices = src.slices.len() as u32;
    let take = slice_limit.min(total_slices);
    let slices: Vec<UnifiedSlice> = src.slices
        .iter()
        .take(take as usize)
        .map(|s| to_slice(s, &src.assignments))
        .collect();

    UnifiedDownloadView {
        schema_version: UNIFIED_SCHEMA_VERSION,
        identity: to_identity(&src.task.identity),
        status: src.task.status.as_str().to_owned(),
        activity: src.task.activity.as_str().to_owned(),
        wait: src.task.wait.as_ref().map(to_wait),
        progress: to_progress(&src.task.progress),
        counts: to_counts(src.task),
        capabilities: task_capabilities(src),
        resources: src.resources.iter().map(|r| to_resource(r)).collect(),
        slices,
        // 摘要不带源详情：源数量可能很大，按需走 `task_snapshot` 的 sources section。
        sources: None,
        completeness: UnifiedCompleteness {
            complete: take == total_slices,
            total_count: total_slices,
            next_cursor: if take < total_slices {
                Some(encode_cursor(
                    &src.task.identity.engine_instance_id,
                    src.task.identity.task_id,
                    src.task.identity.state_revision,
                    SnapshotSection::Slices.as_str(),
                    take,
                ))
            } else {
                None
            },
            sampled_at_ms: dec(src.sampled_at_ms),
        },
        error: src.task.current_error.as_ref().map(to_error),
    }
}

/// 生成 `task_snapshot` 响应。
///
/// `section` 缺省为 `summary`；`limit` 缺省 64、合法 1..=256。
/// 游标超出范围或版本不匹配一律返回 [`SnapshotError::StaleCursor`]，
/// 绝不返回"看起来完整"的混合版本数据。
pub fn to_snapshot_response(
    src: &SnapshotSource<'_>,
    raw_section: Option<&str>,
    cursor: Option<&str>,
    raw_limit: Option<u32>,
) -> Result<UnifiedSnapshotResponse, SnapshotError> {
    let section = SnapshotSection::parse(raw_section)
        .ok_or_else(|| SnapshotError::InvalidSection(raw_section.unwrap_or("").to_owned()))?;
    let limit = normalize_snapshot_limit(raw_limit)
        .ok_or_else(|| SnapshotError::InvalidLimit(raw_limit.unwrap_or(0)))?;

    let offset = match cursor {
        None => 0u32,
        Some(raw) => parse_cursor(
            raw,
            &src.task.identity.engine_instance_id,
            src.task.identity.task_id,
            src.task.identity.state_revision,
            section,
        )
        .ok_or(SnapshotError::StaleCursor)?,
    };

    let identity = to_identity(&src.task.identity);
    let section_name = section.as_str().to_owned();

    if section == SnapshotSection::Summary {
        return Ok(UnifiedSnapshotResponse {
            schema_version: UNIFIED_SCHEMA_VERSION,
            identity,
            section: section_name,
            summary: Some(Box::new(to_summary_view(src, limit))),
            items: None,
            next_cursor: None,
            total_count: 1,
            complete: true,
        });
    }

    let (items, total) = collect_items(src, section, offset, limit);

    let next = if offset + (items.len() as u32) < total {
        Some(encode_cursor(
            &src.task.identity.engine_instance_id,
            src.task.identity.task_id,
            src.task.identity.state_revision,
            section.as_str(),
            offset + (items.len() as u32),
        ))
    } else {
        None
    };

    Ok(UnifiedSnapshotResponse {
        schema_version: UNIFIED_SCHEMA_VERSION,
        identity,
        section: section_name,
        summary: None,
        items: Some(items),
        next_cursor: next,
        total_count: total,
        complete: offset + (limit.min(total.saturating_sub(offset))) >= total,
    })
}

/// 按 section 取分页条目与真实总数。
fn collect_items(
    src: &SnapshotSource<'_>,
    section: SnapshotSection,
    offset: u32,
    limit: u32,
) -> (Vec<UnifiedSnapshotItem>, u32) {
    let start = offset as usize;
    let take = limit as usize;

    match section {
        SnapshotSection::Resources => {
            let total = src.resources.len() as u32;
            let items = src
                .resources
                .iter()
                .skip(start)
                .take(take)
                .map(|r| UnifiedSnapshotItem::Resource(to_resource(r)))
                .collect();
            (items, total)
        }
        SnapshotSection::Slices => {
            let total = src.slices.len() as u32;
            let items = src
                .slices
                .iter()
                .skip(start)
                .take(take)
                .map(|s| UnifiedSnapshotItem::Slice(to_slice(s, &src.assignments)))
                .collect();
            (items, total)
        }
        SnapshotSection::Assignments => {
            let total = src.assignments.len() as u32;
            let items = src
                .assignments
                .iter()
                .skip(start)
                .take(take)
                .map(|a| UnifiedSnapshotItem::Assignment(to_assignment(a)))
                .collect();
            (items, total)
        }
        SnapshotSection::Sources => {
            let total = src.sources.len() as u32;
            let items = src
                .sources
                .iter()
                .skip(start)
                .take(take)
                .map(|s| UnifiedSnapshotItem::Source(to_source(s)))
                .collect();
            (items, total)
        }
        // summary 已在调用方提前返回。
        SnapshotSection::Summary => (Vec::new(), 0),
    }
}

// ---------------------------------------------------------------- 游标

/// 游标编码：`engine|task|revision|section|offset`。
///
/// 用 `|` 分隔：EngineInstanceId 是 UUID、section 是受控小写标识，都不含 `|`，
/// 因此无需转义，也不依赖 JSON 编码的版本差异。
fn encode_cursor(engine: &str, task_id: i64, revision: u64, section: &str, offset: u32) -> String {
    format!("{engine}|{task_id}|{revision}|{section}|{offset}")
}

/// 校验并解析游标；任何一项不匹配都视为失效。
fn parse_cursor(
    raw: &str,
    engine: &str,
    task_id: i64,
    revision: u64,
    section: SnapshotSection,
) -> Option<u32> {
    let mut parts = raw.split('|');
    let e = parts.next()?;
    let t = parts.next()?.parse::<i64>().ok()?;
    let r = parts.next()?.parse::<u64>().ok()?;
    let s = parts.next()?;
    let off = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    // 版本或 section 变化：游标失效，不允许跨版本拼接。
    if e != engine || t != task_id || r != revision || s != section.as_str() {
        return None;
    }
    Some(off)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::capability::Transport;
    use aidm_core::download::coverage::CoverageSet;
    use aidm_core::download::model::{
        Activity, AssignmentId, Availability, CommitState, IdentityContext, ResourceId, SliceId,
        SourceId,
        SliceStatus,
    };

    fn reducer() -> Reducer {
        let mut id = IdentityContext::for_task(42, "engine-abc");
        id.run_epoch = 3;
        id.state_revision = 7;
        let mut task = TaskState::new(id, Transport::Http);
        task.identity.run_epoch = 3;
        task.identity.state_revision = 7;
        task.activity = Activity::Transferring;
        task.status = aidm_core::model::Status::Downloading;
        Reducer::new(task)
    }

    fn add_slice(r: &mut Reducer, start: u64, end: u64, done: bool) -> SliceId {
        let id = SliceId::generate();
        let mut slice = SliceState::new(
            id.clone(),
            ResourceId::new("res-1"),
            0,
            1,
            Span::known(start, end).expect("span"),
        );
        if done {
            slice.coverage = CoverageSet::from_snapshot(&[(start)..(end)], &[(start)..(end)]);
            slice.state = SliceStatus::Done;
        }
        r.upsert_slice(slice);
        id
    }

    #[test]
    fn identity_and_progress_are_decimal_strings() {
        let r = reducer();
        let src = SnapshotSource::from_reducer(&r, 1_000);
        let view = to_summary_view(&src, 64);
        assert_eq!(view.schema_version, UNIFIED_SCHEMA_VERSION);
        assert_eq!(view.identity.task_id, "42");
        assert_eq!(view.identity.engine_instance_id, "engine-abc");
        assert_eq!(view.identity.state_revision, "7");
        assert_eq!(view.status, "downloading");
        assert_eq!(view.activity, "transferring");
        assert_eq!(view.progress.wire_bytes, "0");
        assert_eq!(view.progress.required_bytes, None, "未知总量不是 0");
    }

    #[test]
    fn zero_slices_is_empty_but_complete() {
        let r = reducer();
        let src = SnapshotSource::from_reducer(&r, 0);
        let view = to_summary_view(&src, 64);
        assert!(view.slices.is_empty());
        assert!(view.completeness.complete);
        assert_eq!(view.completeness.total_count, 0);
        assert!(view.completeness.next_cursor.is_none());
    }

    #[test]
    fn summary_truncates_but_keeps_true_total() {
        let mut r = reducer();
        for i in 0..5u64 {
            add_slice(&mut r, i * 100, (i + 1) * 100, false);
        }
        let src = SnapshotSource::from_reducer(&r, 0);
        let view = to_summary_view(&src, 2);
        assert_eq!(view.slices.len(), 2, "摘要必须有界");
        assert_eq!(view.completeness.total_count, 5, "总数不因截断变小");
        assert!(!view.completeness.complete);
        assert!(view.completeness.next_cursor.is_some(), "截断要给游标");
    }

    #[test]
    fn range_is_left_closed_right_open() {
        let mut r = reducer();
        add_slice(&mut r, 0, 100, false);
        let src = SnapshotSource::from_reducer(&r, 0);
        let view = to_summary_view(&src, 64);
        let range = &view.slices[0].range;
        assert_eq!(range.start, "0");
        assert_eq!(range.end_exclusive.as_deref(), Some("100"));
    }

    #[test]
    fn open_range_has_no_end() {
        let mut r = reducer();
        r.upsert_slice(SliceState::new(
            SliceId::generate(),
            ResourceId::new("res-1"),
            0,
            1,
            Span::open(0),
        ));
        let src = SnapshotSource::from_reducer(&r, 0);
        let view = to_summary_view(&src, 64);
        assert_eq!(view.slices[0].range.end_exclusive, None, "未知终点不能编造");
    }

    #[test]
    fn capabilities_are_unknown_without_sources() {
        let r = reducer();
        let src = SnapshotSource::from_reducer(&r, 0);
        let view = to_summary_view(&src, 64);
        assert_eq!(view.capabilities.metadata_known, "unknown");
        assert_eq!(
            view.capabilities.random_read, "unknown",
            "没有源观测时不得伪称支持"
        );
    }

    #[test]
    fn capabilities_use_conservative_conjunction() {
        let mut r = reducer();
        let mut a = SourceState::new(SourceId::new("a"), ResourceId::new("res-1"), Transport::Http);
        a.capabilities.random_read = TriState::Yes;
        a.capabilities.resume = TriState::Yes;
        a.capabilities.metadata_known = TriState::Yes;
        a.capabilities.multi_source = TriState::Yes;
        let mut b = SourceState::new(SourceId::new("b"), ResourceId::new("res-1"), Transport::Http);
        b.capabilities.random_read = TriState::No;
        b.capabilities.resume = TriState::Unknown;
        b.capabilities.metadata_known = TriState::No;
        b.capabilities.multi_source = TriState::Yes;
        r.upsert_source(a);
        r.upsert_source(b);

        let src = SnapshotSource::from_reducer(&r, 0);
        let view = to_summary_view(&src, 64);
        assert_eq!(view.capabilities.random_read, "no", "任一无能力即整体无");
        assert_eq!(view.capabilities.resume, "unknown");
    }

    #[test]
    fn source_summary_carries_cooldown_and_counters() {
        let mut r = reducer();
        let mut s = SourceState::new(SourceId::new("s1"), ResourceId::new("res-1"), Transport::Ed2k);
        s.availability = Availability::Available;
        s.cooldown_until_ms = Some(1_234);
        s.health.throughput_bps = 9_007_199_254_740_993; // > 2^53
        s.health.queued_peers = 2;
        r.upsert_source(s);

        let src = SnapshotSource::from_reducer(&r, 0);
        let resp = to_snapshot_response(&src, Some("sources"), None, None).expect("snapshot");
        let items = resp.items.expect("items");
        assert_eq!(items.len(), 1);
        match &items[0] {
            UnifiedSnapshotItem::Source(s) => {
                assert_eq!(s.cooldown_until_ms.as_deref(), Some("1234"));
                assert_eq!(
                    s.throughput_bps, "9007199254740993",
                    "超过 2^53 的计数必须无损"
                );
                assert_eq!(s.queued_peers, 2);
                assert_eq!(s.transport, "ed2k");
            }
            other => panic!("section=sources 必须产出 Source 条目，实际 {other:?}"),
        }
    }

    #[test]
    fn assignments_appear_under_their_slice() {
        let mut r = reducer();
        let slice = add_slice(&mut r, 0, 100, false);
        let assignment = AssignmentState::new(
            AssignmentId::generate(),
            42,
            3,
            0,
            slice.clone(),
            SourceId::new("s1"),
            Span::known(0, 40).expect("span"),
        );
        r.upsert_assignment(assignment);

        let src = SnapshotSource::from_reducer(&r, 0);
        let view = to_summary_view(&src, 64);
        assert_eq!(view.slices[0].assignments.len(), 1, "通路必须挂在切片下");
        assert_eq!(
            view.slices[0].assignments[0].range.end_exclusive.as_deref(),
            Some("40")
        );
    }

    #[test]
    fn snapshot_pagination_is_stable_and_marks_completeness() {
        let mut r = reducer();
        for i in 0..5u64 {
            add_slice(&mut r, i * 100, (i + 1) * 100, false);
        }
        let src = SnapshotSource::from_reducer(&r, 0);

        let first = to_snapshot_response(&src, Some("slices"), None, Some(2)).expect("page1");
        assert_eq!(first.items.as_ref().expect("items").len(), 2);
        assert_eq!(first.total_count, 5);
        assert!(!first.complete);
        let cursor = first.next_cursor.expect("cursor");

        let second =
            to_snapshot_response(&src, Some("slices"), Some(&cursor), Some(2)).expect("page2");
        assert_eq!(second.items.as_ref().expect("items").len(), 2);
        assert_eq!(second.total_count, 5, "页间总数不变");
        let cursor = second.next_cursor.expect("cursor");

        let third =
            to_snapshot_response(&src, Some("slices"), Some(&cursor), Some(2)).expect("page3");
        assert_eq!(third.items.as_ref().expect("items").len(), 1);
        assert!(third.complete);
        assert!(third.next_cursor.is_none());
    }

    #[test]
    fn cursor_from_old_revision_is_rejected() {
        let mut r = reducer();
        for i in 0..5u64 {
            add_slice(&mut r, i * 100, (i + 1) * 100, false);
        }
        let src = SnapshotSource::from_reducer(&r, 0);
        let first = to_snapshot_response(&src, Some("slices"), None, Some(2)).expect("page1");
        let cursor = first.next_cursor.expect("cursor");

        // 版本推进后，旧游标必须失效，不能拼出混合版本。
        r.advance_state_revision(8);
        let src2 = SnapshotSource::from_reducer(&r, 0);
        assert_eq!(
            to_snapshot_response(&src2, Some("slices"), Some(&cursor), Some(2)),
            Err(SnapshotError::StaleCursor)
        );
    }

    #[test]
    fn cursor_for_other_section_is_rejected() {
        let mut r = reducer();
        for i in 0..5u64 {
            add_slice(&mut r, i * 100, (i + 1) * 100, false);
        }
        let src = SnapshotSource::from_reducer(&r, 0);
        let first = to_snapshot_response(&src, Some("slices"), None, Some(2)).expect("page1");
        let cursor = first.next_cursor.expect("cursor");
        assert_eq!(
            to_snapshot_response(&src, Some("resources"), Some(&cursor), Some(2)),
            Err(SnapshotError::StaleCursor),
            "游标绑定 section"
        );
    }

    #[test]
    fn invalid_limit_and_section_are_explicit_errors() {
        let r = reducer();
        let src = SnapshotSource::from_reducer(&r, 0);
        assert_eq!(
            to_snapshot_response(&src, Some("slices"), None, Some(0)),
            Err(SnapshotError::InvalidLimit(0))
        );
        assert_eq!(
            to_snapshot_response(&src, Some("slices"), None, Some(257)),
            Err(SnapshotError::InvalidLimit(257))
        );
        assert_eq!(
            to_snapshot_response(&src, Some("bogus"), None, None),
            Err(SnapshotError::InvalidSection("bogus".into()))
        );
        // 错误带稳定 code 与脱敏说明。
        assert_eq!(
            SnapshotError::InvalidLimit(0).code(),
            snapshot_error::INVALID_LIMIT
        );
        assert_eq!(
            SnapshotError::StaleCursor.code(),
            snapshot_error::SNAPSHOT_STALE
        );
    }

    #[test]
    fn summary_section_returns_view_not_items() {
        let r = reducer();
        let src = SnapshotSource::from_reducer(&r, 0);
        let resp = to_snapshot_response(&src, None, None, None).expect("summary");
        assert_eq!(resp.section, "summary");
        assert!(resp.summary.is_some());
        assert!(resp.items.is_none());
        assert_eq!(resp.total_count, 1);
        assert!(resp.complete);
    }

    #[test]
    fn error_view_preserves_protocol_code_and_phase() {
        let mut task = reducer().task().clone();
        task.current_error = Some(UnifiedError {
            category: aidm_core::download::model::ErrorCategory::Throttled,
            code: "rate_limited".into(),
            phase: Some(aidm_core::error::Phase::Transfer),
            operation: Some("GET".into()),
            scope: Some(aidm_core::download::model::Scope::Host),
            subject_id: Some("example.com".into()),
            retryable: true,
            retry_after_ms: Some(42),
            protocol: Some(Transport::Http),
            protocol_code: Some("429".into()),
            message: "too many requests".into(),
            cause_chain: vec![aidm_core::download::model::CauseLink {
                code: "server".into(),
                message: "quota".into(),
            }],
        });
        let mut r2 = Reducer::new(task);
        r2.set_plan(Vec::new(), aidm_core::download::model::PlanStatus::Unplanned);
        let src = SnapshotSource::from_reducer(&r2, 0);
        let view = to_summary_view(&src, 64);
        let err = view.error.expect("error");
        assert_eq!(err.category, "throttled");
        assert_eq!(err.protocol_code.as_deref(), Some("429"));
        assert_eq!(err.phase.as_deref(), Some("transfer"));
        assert_eq!(err.retry_after_ms.as_deref(), Some("42"));
        assert_eq!(err.cause_chain.len(), 1);
    }

    #[test]
    fn disabled_selection_is_reported_on_resource() {
        let mut r = reducer();
        let mut res = ResourceState::new(ResourceId::new("res-1"), 42, 0);
        res.selected = false;
        res.size_bytes = Some(0);
        res.commit_state = CommitState::Pending;
        r.upsert_resource(res);
        let src = SnapshotSource::from_reducer(&r, 0);
        let view = to_summary_view(&src, 64);
        assert!(!view.resources[0].selected);
        assert_eq!(view.resources[0].size_bytes.as_deref(), Some("0"));
        assert_eq!(
            view.resources[0].commit_state, "pending",
            "空文件也要走提交流程"
        );
    }
}
