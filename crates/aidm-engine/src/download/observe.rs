//! 从现有执行器读取**只读**观测。
//!
//! 职责边界：
//! - 不改下载行为、不建连、不重试、不换源、不写下载文件。
//! - 把现有执行器已经知道的真实事实（eD2k part 归属、peer 地址、校验结果）
//!   投影成 `aidm-core::download` 的实体。
//! - **未知就是未知**：没有 peer 地址的 part 不生成通路，不用"源数 ÷ 切片数"
//!   凑出一组看起来真实的分配（文档第 2 节、第 6.3 节明确禁止）。
//!
//! 为什么需要 [`PeerSourceMap`]：`aidm-engine` 内部的 owner 序号与 `SocketAddr`
//! 属于受控内部信息，不能直接进公共视图；对外只看不透明 `source_id`。映射表由
//! 本模块持有，随任务生命周期回收。

use std::collections::HashMap;
use std::net::SocketAddr;

use aidm_core::capability::Transport;
use aidm_core::download::model::{
    AssignmentId, AssignmentState, AssignmentStatus, Availability, CapabilitySet, NativeBlockKind,
    NativeBlockRef, NativeGranularity, ResourceId, SliceId, SliceState, SliceStatus, SourceId,
    SourceState, Span, TriState,
};
use aidm_core::ed2k::peer::PARTSIZE;

use crate::ed2k::multi_source::PartOwnership;

/// `SocketAddr` 到不透明 `source_id` 的稳定映射。
///
/// 同一对端在一次任务内始终得到同一个 `source_id`；地址不进入公共视图。
/// 不提供"按地址推 source_id"的哈希做法——那会被误认为脱敏（文档 11.5）。
#[derive(Debug, Default)]
pub struct PeerSourceMap {
    by_addr: HashMap<SocketAddr, SourceId>,
}

impl PeerSourceMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// 取得（或首次分配）该地址的 `source_id`。
    ///
    /// 地址未知时返回 `None`：调用方必须把该 part 当作"归属未知"处理。
    pub fn source_for(&mut self, addr: Option<SocketAddr>) -> Option<SourceId> {
        let addr = addr?;
        Some(
            self.by_addr
                .entry(addr)
                .or_insert_with(SourceId::generate)
                .clone(),
        )
    }

    /// 已登记的源数量。
    pub fn len(&self) -> usize {
        self.by_addr.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty()
    }

    /// 清理已经不再出现的地址（任务换轮次时调用，避免映射无限增长）。
    pub fn retain_seen(&mut self, seen: &[Option<SocketAddr>]) {
        let keep: std::collections::HashSet<SocketAddr> = seen.iter().flatten().copied().collect();
        self.by_addr.retain(|addr, _| keep.contains(addr));
    }
}

/// eD2k 观测投影结果。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ed2kProjection {
    /// 稳定切片（按原生 part 分组，数量受任务预算约束）。
    pub slices: Vec<SliceState>,
    /// 当前真实存在的通路。归属未知的 part 不产生通路。
    pub assignments: Vec<AssignmentState>,
    /// 参与本次归属的源。
    pub sources: Vec<SourceState>,
}

impl Ed2kProjection {
    /// 是否包含任何可展示的工作。
    pub fn is_empty(&self) -> bool {
        self.slices.is_empty()
    }
}

/// 切片分组：把 `total_parts` 个原生 part 分成不超过 `budget` 组。
///
/// 文档 6.1：eD2k 按原生 part 边界组成逻辑切片，切片数不超过可分组的原生工作
/// 单元数。分组只影响展示粒度，**不改变**原生校验边界（`NativeBlockRef` 仍是一
/// part 一项）。
pub fn part_groups(total_parts: usize, budget: u32) -> Vec<std::ops::Range<usize>> {
    if total_parts == 0 {
        return Vec::new();
    }
    let groups = (budget.max(1) as usize).min(total_parts);
    // 向上取整：保证最后一组不会为空，组数不超过 groups。
    let chunk = total_parts.div_ceil(groups);
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < total_parts {
        let end = (start + chunk).min(total_parts);
        out.push(start..end);
        start = end;
    }
    out
}

/// 把一次归属快照投影成切片、通路与源。
///
/// **编号稳定性**：切片与通路的 ID 由任务与原生序号**确定性**
/// 生成，不是每次投影新 UUID。否则同一个切片每次刷新都换“身份证”，UI 无法连续
/// 渲染、日志也无法追踪同一次归属的生命周期。
///
/// 参数 `budget` 是任务期望的切片/连接预算（复用 `hosts::task_conns` 的结果，
/// 由调用方传入）。投影本身**不**申请连接、不决定并发。
#[allow(clippy::too_many_arguments)]
pub fn project_ed2k(
    task_id: i64,
    run_epoch: u64,
    content_generation: u64,
    plan_revision: u64,
    resource_id: &ResourceId,
    file_size: u64,
    budget: u32,
    parts: &[PartOwnership],
    map: &mut PeerSourceMap,
) -> Ed2kProjection {
    let groups = part_groups(parts.len(), budget);
    project_ed2k_with_groups(
        task_id,
        run_epoch,
        content_generation,
        plan_revision,
        resource_id,
        file_size,
        &groups,
        parts,
        map,
    )
}

/// 用**已固定的**切片分组投影。
///
/// 运行时预算变化不得重新分组（文档 6.1）：一旦方案生成，同一 `slice_id`
/// 的范围就不能变。调用方负责把首次规划的分组缓存下来并传进来。
#[allow(clippy::too_many_arguments)]
pub fn project_ed2k_with_groups(
    task_id: i64,
    run_epoch: u64,
    content_generation: u64,
    plan_revision: u64,
    resource_id: &ResourceId,
    file_size: u64,
    groups: &[std::ops::Range<usize>],
    parts: &[PartOwnership],
    map: &mut PeerSourceMap,
) -> Ed2kProjection {
    if parts.is_empty() || file_size == 0 {
        return Ed2kProjection::default();
    }
    let mut slices: Vec<SliceState> = Vec::with_capacity(groups.len());
    for (group_idx, group) in groups.iter().enumerate() {
        let first = &parts[group.start];        // 末块实际长度与常规单元不同，范围必须按真实 part 边界取。
        let last = &parts[group.end - 1];
        let span = Span::known(first.span_start, last.span_end)
            .unwrap_or_else(|| Span::open(first.span_start));
        let mut slice = SliceState::new(
            // 同一任务、同一分组序号的切片始终是同一个实体。
            SliceId::new(format!("task-{task_id}-slice-{group_idx}")),
            resource_id.clone(),
            content_generation,
            plan_revision,
            span,
        );
        // 原生块映射：一 part 一项，校验边界不可被切片粒度量重定义。
        for part in &parts[group.clone()] {
            slice.native_blocks.push(NativeBlockRef {
                native_index: part.part_index as u64,
                span: Span::known(part.span_start, part.span_end)
                    .unwrap_or_else(|| Span::open(part.span_start)),
                verified: if part.verified { Some(true) } else { None },
                state: Some(part.state.to_owned()),
            });
        }
        slices.push(slice);
    }

    let mut assignments: Vec<AssignmentState> = Vec::new();
    let mut sources: Vec<SourceState> = Vec::new();
    let mut source_index: HashMap<SourceId, usize> = HashMap::new();

    for (group_idx, group) in groups.iter().enumerate() {
        let slice = &mut slices[group_idx];
        let mut any_owner = false;

        for part in &parts[group.clone()] {
            let span = Span::known(part.span_start, part.span_end)
                .unwrap_or_else(|| Span::open(part.span_start));

            // 覆盖只来自**可信原生块事实**：done(verified) / done(未验) / checking。
            // 不用累计字节数猜位置：实际可能只下了文件后半段。
            if part.verified {
                let _ = slice.coverage.insert_stored(span.start, span_end(span));
                let _ = slice.coverage.insert_verified(span.start, span_end(span));
            } else if part.state == "done" || part.state == "checking" {
                let _ = slice.coverage.insert_stored(span.start, span_end(span));
            }

            // 归属：只有同时具备 owner 与对端地址才生成通路。
            let Some(source_id) = map.source_for(part.peer_addr) else {
                continue;
            };
            any_owner = true;

            let status = match part.state {
                "connecting" => AssignmentStatus::Connecting,
                "queued" => AssignmentStatus::Queued,
                "receiving" => AssignmentStatus::Transferring,
                "done" => AssignmentStatus::Completed,
                "checking" => AssignmentStatus::Draining,
                _ => AssignmentStatus::Pending,
            };

            let mut assignment = AssignmentState::new(
                // 首版一个原生 part 同时只有一个所有者。归属生命周期由领取序号决定：
                // 同一次领取刷新保持同一 ID；释放后重领或换源会让 claim_seq 变值，
                // 于是产生新的 assignment_id——否则两个不同源的下载会被当成同一次分配。
                AssignmentId::new(format!(
                    "task-{task_id}-part-{}-c{}",
                    part.part_index, part.claim_seq
                )),
                task_id,
                run_epoch,
                content_generation,
                slice.slice_id.clone(),
                source_id.clone(),
                span,
            );
            assignment.state = status;
            assignment.native_work_refs = vec![format!("part:{}", part.part_index)];
            assignments.push(assignment);

            if !source_index.contains_key(&source_id) {
                source_index.insert(source_id.clone(), sources.len());
                let mut source =
                    SourceState::new(source_id.clone(), resource_id.clone(), Transport::Ed2k);
                source.availability = Availability::Available;
                source.eligible = true;
                source.last_observed_at_ms = Some(0);
                let mut caps = CapabilitySet::default();
                caps.native_granularity = NativeGranularity {
                    kind: NativeBlockKind::Ed2kPart,
                    unit_bytes: Some(PARTSIZE),
                    last_unit_shorter: true,
                };
                caps.integrity = aidm_core::download::model::Integrity::NativeBlock;
                caps.metadata_known = TriState::Yes;
                caps.multi_source = TriState::Yes;
                caps.random_read = TriState::Yes;
                caps.resume = TriState::Yes;
                source.capabilities = caps;
                sources.push(source);
            }
        }

        slice.progress.stored_unique_bytes = slice.coverage.stored_len();
        slice.progress.verified_unique_bytes = slice.coverage.verified_len();
        slice.progress.wire_bytes = slice.progress.stored_unique_bytes;
        slice.progress.required_bytes = span_len(slice.span);
        // 原生块校验是 eD2k 的完成依据：已验证覆盖铺满才算 done。
        slice.state = if slice.coverage.covers_verified(slice.span) {
            SliceStatus::Done
        } else if any_owner {
            SliceStatus::Active
        } else if slice.coverage.stored_len() > 0 {
            SliceStatus::Verifying
        } else {
            SliceStatus::Pending
        };
    }

    Ed2kProjection {
        slices,
        assignments,
        sources,
    }
}

/// 已知范围的终点（`Span` 在投影里总是已知的；开放范围按 start 处理）。
fn span_end(span: Span) -> u64 {
    span.end_exclusive.unwrap_or(span.start)
}

/// 范围长度。
fn span_len(span: Span) -> Option<u64> {
    span.end_exclusive.map(|end| end.saturating_sub(span.start))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(idx: usize, file_size: u64) -> PartOwnership {
        let start = idx as u64 * PARTSIZE;
        let end = (start + PARTSIZE).min(file_size);
        PartOwnership {
            part_index: idx,
            span_start: start,
            span_end: end,
            owner: None,
            peer_addr: None,
            claim_seq: 0,
            state: "pending",
            verified: false,
        }
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[test]
    fn empty_input_projects_nothing() {
        let mut map = PeerSourceMap::new();
        let resource = ResourceId::new("r");
        let p = project_ed2k(1, 1, 0, 0, &resource, 0, 8, &[], &mut map);
        assert!(p.is_empty());
        assert!(p.assignments.is_empty());
    }

    #[test]
    fn groups_are_bounded_by_budget_and_cover_all_parts() {
        assert_eq!(part_groups(0, 8).len(), 0);
        assert_eq!(part_groups(1, 8).len(), 1);
        assert_eq!(part_groups(8, 8).len(), 8);
        let groups = part_groups(103, 8);
        assert_eq!(groups.len(), 8, "切片数不超过预算");
        assert_eq!(groups.first().expect("first").start, 0);
        assert_eq!(groups.last().expect("last").end, 103, "必须覆盖全部 part");
        // 连续、无空洞。
        for w in groups.windows(2) {
            assert_eq!(w[0].end, w[1].start);
        }
    }

    #[test]
    fn groups_never_exceed_part_count() {
        assert_eq!(part_groups(3, 64).len(), 3, "part 少于预算时按 part 数");
    }

    #[test]
    fn span_uses_real_last_part_length() {
        let file_size = PARTSIZE * 2 + 9_728; // 末块不足一个 part
        let parts: Vec<PartOwnership> = (0..3).map(|i| part(i, file_size)).collect();
        let mut map = PeerSourceMap::new();
        let p = project_ed2k(
            1,
            1,
            0,
            0,
            &ResourceId::new("r"),
            file_size,
            1,
            &parts,
            &mut map,
        );
        assert_eq!(p.slices.len(), 1);
        assert_eq!(
            p.slices[0].span.end_exclusive,
            Some(file_size),
            "末块必须按实际长度收尾，不能按整 part 长度"
        );
    }

    #[test]
    fn unknown_peer_produces_no_assignment() {
        let mut parts: Vec<PartOwnership> = (0..2).map(|i| part(i, PARTSIZE * 4)).collect();
        // 有 owner 但没有对端地址：归属未知。
        parts[0].owner = Some(0);
        parts[0].state = "receiving";
        let mut map = PeerSourceMap::new();
        let p = project_ed2k(
            1,
            1,
            0,
            0,
            &ResourceId::new("r"),
            PARTSIZE * 4,
            4,
            &parts,
            &mut map,
        );
        assert!(
            p.assignments.is_empty(),
            "缺少 peer 地址时必须标记未知，不能按源数推算通路"
        );
    }

    #[test]
    fn known_peer_produces_assignment_with_real_range() {
        let mut parts: Vec<PartOwnership> = (0..2).map(|i| part(i, PARTSIZE * 4)).collect();
        parts[1].owner = Some(7);
        parts[1].peer_addr = Some(addr(4001));
        parts[1].state = "receiving";
        let mut map = PeerSourceMap::new();
        let p = project_ed2k(
            1,
            1,
            0,
            0,
            &ResourceId::new("r"),
            PARTSIZE * 4,
            4,
            &parts,
            &mut map,
        );
        assert_eq!(p.assignments.len(), 1);
        let a = &p.assignments[0];
        assert_eq!(a.span.start, PARTSIZE, "通路区间必须是对应 part 的真实范围");
        assert_eq!(a.state, AssignmentStatus::Transferring);
        assert_eq!(p.sources.len(), 1);
    }

    #[test]
    fn same_peer_maps_to_same_source_id() {
        let mut parts: Vec<PartOwnership> = (0..4).map(|i| part(i, PARTSIZE * 8)).collect();
        for idx in [0usize, 2] {
            parts[idx].owner = Some(idx);
            parts[idx].peer_addr = Some(addr(5000));
            parts[idx].state = "receiving";
        }
        let mut map = PeerSourceMap::new();
        let p = project_ed2k(
            1,
            1,
            0,
            0,
            &ResourceId::new("r"),
            PARTSIZE * 8,
            4,
            &parts,
            &mut map,
        );
        let ids: std::collections::HashSet<_> =
            p.assignments.iter().map(|a| a.source_id.clone()).collect();
        assert_eq!(ids.len(), 1, "同一地址必须得到同一 source_id");
        assert_eq!(p.sources.len(), 1);
    }

    #[test]
    fn distinct_peers_map_to_distinct_source_ids() {
        let mut parts: Vec<PartOwnership> = (0..4).map(|i| part(i, PARTSIZE * 8)).collect();
        parts[0].owner = Some(0);
        parts[0].peer_addr = Some(addr(6001));
        parts[0].state = "receiving";
        parts[1].owner = Some(1);
        parts[1].peer_addr = Some(addr(6002));
        parts[1].state = "queued";
        let mut map = PeerSourceMap::new();
        let p = project_ed2k(
            1,
            1,
            0,
            0,
            &ResourceId::new("r"),
            PARTSIZE * 8,
            4,
            &parts,
            &mut map,
        );
        assert_eq!(p.sources.len(), 2);
        assert_eq!(p.assignments.len(), 2);
    }

    #[test]
    fn one_slice_can_be_served_by_two_peers() {
        // 文档 6.3：同一逻辑切片可由不同源下载不同 part。
        let file_size = PARTSIZE * 4;
        let mut parts: Vec<PartOwnership> = (0..4).map(|i| part(i, file_size)).collect();
        parts[0].owner = Some(0);
        parts[0].peer_addr = Some(addr(7001));
        parts[0].state = "receiving";
        parts[1].owner = Some(1);
        parts[1].peer_addr = Some(addr(7002));
        parts[1].state = "receiving";

        let mut map = PeerSourceMap::new();
        let p = project_ed2k(1, 1, 0, 0, &ResourceId::new("r"), file_size, 1, &parts, &mut map);
        assert_eq!(p.slices.len(), 1, "预算 1 → 单切片");
        assert_eq!(p.assignments.len(), 2);
        assert!(
            p.assignments.iter().all(|a| a.slice_id == p.slices[0].slice_id),
            "两条通路属于同一逻辑切片"
        );
        // 不同 part ⇒ 区间互不重叠。
        let a = &p.assignments[0];
        let b = &p.assignments[1];
        assert_ne!(a.span.start, b.span.start);
    }

    #[test]
    fn verified_parts_mark_slice_done() {
        let file_size = PARTSIZE * 2;
        let mut parts: Vec<PartOwnership> = (0..2).map(|i| part(i, file_size)).collect();
        for p in parts.iter_mut() {
            p.state = "done";
            p.verified = true;
        }
        let mut map = PeerSourceMap::new();
        let p = project_ed2k(1, 1, 0, 0, &ResourceId::new("r"), file_size, 2, &parts, &mut map);
        assert!(p.slices.iter().all(|s| s.state == SliceStatus::Done));
        for s in &p.slices {
            assert_eq!(
                s.progress.verified_unique_bytes,
                s.progress.required_bytes.expect("required"),
                "已验证覆盖必须铺满切片"
            );
        }
    }

    #[test]
    fn done_but_unverified_counts_as_stored_only() {
        let file_size = PARTSIZE;
        let mut parts: Vec<PartOwnership> = (0..1).map(|i| part(i, file_size)).collect();
        parts[0].state = "done";
        parts[0].verified = false;
        let mut map = PeerSourceMap::new();
        let p = project_ed2k(1, 1, 0, 0, &ResourceId::new("r"), file_size, 1, &parts, &mut map);
        let s = &p.slices[0];
        assert_eq!(s.progress.stored_unique_bytes, file_size);
        assert_eq!(s.progress.verified_unique_bytes, 0, "未校验不得计入已验证");
        assert_ne!(s.state, SliceStatus::Done);
    }

    #[test]
    fn native_blocks_keep_part_boundaries() {
        let file_size = PARTSIZE * 3;
        let parts: Vec<PartOwnership> = (0..3).map(|i| part(i, file_size)).collect();
        let mut map = PeerSourceMap::new();
        let p = project_ed2k(1, 1, 0, 0, &ResourceId::new("r"), file_size, 1, &parts, &mut map);
        let s = &p.slices[0];
        assert_eq!(s.native_blocks.len(), 3, "原生校验边界不能被切片粒度改写");
        assert_eq!(s.native_blocks[0].native_index, 0);
        assert_eq!(s.native_blocks[2].native_index, 2);
    }

    #[test]
    fn ids_are_stable_across_projections() {
        // 用户验收缺口：同一切片/归属不能每次刷新都换“身份证”。
        let file_size = PARTSIZE * 4;
        let mut parts: Vec<PartOwnership> = (0..4).map(|i| part(i, file_size)).collect();
        parts[0].owner = Some(0);
        parts[0].peer_addr = Some(addr(9001));
        parts[0].state = "receiving";

        let mut map = PeerSourceMap::new();
        let resource = ResourceId::new("r");
        let first = project_ed2k(7, 1, 0, 1, &resource, file_size, 2, &parts, &mut map);
        let second = project_ed2k(7, 1, 0, 1, &resource, file_size, 2, &parts, &mut map);

        let ids1: Vec<String> = first.slices.iter().map(|s| s.slice_id.to_string()).collect();
        let ids2: Vec<String> = second.slices.iter().map(|s| s.slice_id.to_string()).collect();
        assert_eq!(ids1, ids2, "同一方案内切片 ID 必须跨投影复用");
        assert_eq!(
            first.assignments[0].assignment_id, second.assignments[0].assignment_id,
            "同一次归属生命周期内分配 ID 必须复用"
        );
        assert_eq!(
            first.assignments[0].source_id, second.assignments[0].source_id,
            "同一个对端必须映射到同一个 source_id"
        );
    }

    #[test]
    fn different_claim_seq_yields_different_assignment_id() {
        // 用户验收缺口：把不同源先后承担的归属当成同一次分配。
        let file_size = PARTSIZE;
        let resource = ResourceId::new("r");
        let mut map = PeerSourceMap::new();

        let mut p = part(0, file_size);
        p.owner = Some(0);
        p.peer_addr = Some(addr(9100));
        p.state = "receiving";
        p.claim_seq = 1;
        let first = project_ed2k(
            7,
            1,
            0,
            1,
            &resource,
            file_size,
            1,
            std::slice::from_ref(&p),
            &mut map,
        );

        // 释放后重领（或换源）：生命周期变了，分配 ID 必须变。
        p.claim_seq = 2;
        let second = project_ed2k(
            7,
            1,
            0,
            1,
            &resource,
            file_size,
            1,
            std::slice::from_ref(&p),
            &mut map,
        );

        assert_ne!(
            first.assignments[0].assignment_id, second.assignments[0].assignment_id,
            "重领/换源必须生成新的分配 ID，不能把两次不同的下载当成同一次"
        );
        assert_eq!(
            first.slices[0].slice_id, second.slices[0].slice_id,
            "切片 ID 不受归属生命周期影响（方案没变）"
        );
    }

    #[test]
    fn peer_map_retains_only_seen_addresses() {
        let mut map = PeerSourceMap::new();
        let a = addr(8001);
        let b = addr(8002);
        map.source_for(Some(a)).expect("a");
        map.source_for(Some(b)).expect("b");
        assert_eq!(map.len(), 2);
        map.retain_seen(&[Some(a)]);
        assert_eq!(map.len(), 1, "不再出现的地址要回收，避免映射无限增长");
    }
}
