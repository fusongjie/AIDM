//! 动态分段规划。
//!
//! 与静态等分（[`aidm_core::segment::plan_segments`]）的差别：
//!
//! 1. 段不是一次切成固定份数，而是**按需再切**：新连接领取「剩余最多的块」的
//!    上半段，原属主把末端收窄到切点（含）。已落盘数据一律不搬动。
//! 2. 切点 = `max(剩余中点, 属主当前位置)`。
//! 3. 段的 `end` 是共享原子量：属主在流式读取的每一轮都会重新读取它，
//!    被收窄后立即停止并把该段标记完成，不会越过切点重复下载。
//! 4. 一个连接下完自己的块后不会退出，而是回到队列**再领一块**（抢分）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// 最小段长：小于该长度就不再切分。与产品规格 §3.2 的 `MIN_SEGMENT_BYTES` 一致，
/// 所以「设置改动后一分为二」在两条路径上的切分阈值相同。
pub const MIN_CHUNK_BYTES: u64 = 256 * 1024;

/// 交给下载线程的一次取块结果。
pub struct Job {
    pub idx: usize,
    /// 本次从该字节开始（续传时是上次落盘位置之后）
    pub start: u64,
    /// 闭区间末端；可能被协调线程随时收窄
    pub end: Arc<AtomicU64>,
}

impl Job {
    #[inline]
    pub fn end_now(&self) -> u64 {
        self.end.load(Ordering::Acquire)
    }

    #[inline]
    pub fn len_hint(&self) -> u64 {
        (self.end_now() + 1).saturating_sub(self.start)
    }
}

/// 一个块（闭区间 `[start, end]`）。
pub struct Chunk {
    pub start: u64,
    pub end: Arc<AtomicU64>,
    /// 下一个待下载字节（`start` + 已确认落盘的字节数）
    pub next: u64,
    pub owner: Option<u32>,
    pub done: bool,
}

impl Chunk {
    #[inline]
    pub fn end(&self) -> u64 {
        self.end.load(Ordering::Acquire)
    }

    /// 还未下载的字节数。
    #[inline]
    pub fn remaining(&self) -> u64 {
        (self.end() + 1).saturating_sub(self.next)
    }
}

/// 一次续传持久化用的快照行：`(start, end, next)`。
pub type ChunkSnapshot = (u64, u64, u64);

pub struct Plan {
    pub total: u64,
    pub chunks: Vec<Chunk>,
    pub max_conns: usize,
    /// 当前允许同时在跑的连接数（爬坡用）
    target: usize,
    /// 未认领块的轮询游标（避免所有连接都去抢第 0 块）
    cursor: usize,
    /// 已确认落盘字节合计
    pub bytes_done: u64,
    /// 已发生的再切分次数
    pub splits: u32,
}

impl Plan {
    /// 初始等分 `n` 份；`n` 会被 `max_conns` 与最小段长夹紧。
    pub fn new(total: u64, n: usize, max_conns: usize) -> Self {
        let max_conns = max_conns.max(1);
        let by_size = (total / MIN_CHUNK_BYTES).max(1) as usize;
        let n = n.clamp(1, max_conns).min(by_size).max(1) as u64;
        let base = total / n;
        let rem = total % n;
        let mut chunks = Vec::with_capacity(n as usize);
        let mut pos = 0u64;
        for i in 0..n {
            let len = base + u64::from(i < rem);
            let start = pos;
            let end = pos + len - 1;
            chunks.push(Chunk {
                start,
                end: Arc::new(AtomicU64::new(end)),
                next: start,
                owner: None,
                done: len == 0,
            });
            pos = end + 1;
        }
        Self {
            total,
            chunks,
            max_conns,
            target: 0,
            cursor: 0,
            bytes_done: 0,
            splits: 0,
        }
    }

    /// 从续传快照恢复。
    pub fn from_snapshot(total: u64, snap: &[ChunkSnapshot], max_conns: usize) -> Self {
        let chunks = snap
            .iter()
            .map(|&(start, end, next)| Chunk {
                start,
                end: Arc::new(AtomicU64::new(end)),
                next: next.clamp(start, end.saturating_add(1)),
                owner: None,
                done: next > end,
            })
            .collect::<Vec<_>>();
        let bytes_done = snap
            .iter()
            .map(|&(start, _, next)| next.saturating_sub(start))
            .sum();
        Self {
            total,
            chunks,
            max_conns: max_conns.max(1),
            target: 0,
            cursor: 0,
            bytes_done,
            splits: 0,
        }
    }

    pub fn snapshot(&self) -> Vec<ChunkSnapshot> {
        self.chunks
            .iter()
            .map(|c| (c.start, c.end(), c.next))
            .collect()
    }

    pub fn target(&self) -> usize {
        self.target
    }

    /// 热调并发上限：不改分段布局，只改"还能再放多少条连接"。
    ///
    /// 已经在跑的连接不会被砍（砍掉要丢已收数据），它们把当前块下完；
    /// 上限调小后新块不再发放，调大则空闲连接立刻可以领到活。
    pub fn set_max_conns(&mut self, n: usize) {
        self.max_conns = n.max(1);
        if self.target > self.max_conns {
            self.target = self.max_conns;
        }
    }

    /// 调整并发上限（只增不减，收敛由 `max_conns` 决定）。
    pub fn set_target(&mut self, t: usize) {
        self.target = t.min(self.max_conns).max(1);
    }

    /// 正在被连接持有的块数。
    pub fn active(&self) -> usize {
        self.chunks
            .iter()
            .filter(|c| c.owner.is_some() && !c.done)
            .count()
    }

    /// **已经收到过数据**的块数（`next` 超过了 `start`）。
    ///
    /// 与 `active()` 的区别正是"连上"与"真的在收数据"的区别：连接建好但服务端
    /// 还没开口时 `active` 会涨、`started` 不涨。ramp 需要这个区分 ——
    /// 只看 `active` 会在"连上但拿不到数据"时继续猛加连接。
    /// 实测（15 GiB 真实任务）：10 秒里 `active` 到了 224 而 `started` 恒为 7。
    pub fn started(&self) -> usize {
        self.chunks.iter().filter(|c| c.next > c.start).count()
    }

    pub fn is_complete(&self) -> bool {
        self.chunks.iter().all(|c| c.done || c.next > c.end())
    }

    pub fn remaining(&self) -> u64 {
        self.chunks.iter().map(Chunk::remaining).sum()
    }

    /// 取下一块：先领未认领的，没有就抢分最大剩余块的上半段。
    ///
    /// `respect_target` 为 false 时忽略并发上限（用于收尾阶段把剩余块分光）。
    pub fn claim(&mut self, worker: u32) -> Option<Job> {
        if self.active() >= self.target {
            return None;
        }
        if let Some(i) = self.pick_unclaimed() {
            return Some(self.claim_at(i, worker));
        }
        let i = self.split_largest()?;
        Some(self.claim_at(i, worker))
    }

    /// 收尾：忽略并发上限，把剩余块全部分出去（下载已接近尾声时用）。
    pub fn claim_beyond_target(&mut self, worker: u32) -> Option<Job> {
        if let Some(i) = self.pick_unclaimed() {
            return Some(self.claim_at(i, worker));
        }
        let i = self.split_largest()?;
        Some(self.claim_at(i, worker))
    }

    fn claim_at(&mut self, i: usize, worker: u32) -> Job {
        let c = &mut self.chunks[i];
        c.owner = Some(worker);
        Job {
            idx: i,
            start: c.next,
            end: c.end.clone(),
        }
    }

    fn pick_unclaimed(&mut self) -> Option<usize> {
        let n = self.chunks.len();
        for k in 0..n {
            let i = (self.cursor + k) % n;
            let c = &self.chunks[i];
            // 必须同时满足「未认领」：否则空闲连接会把别人正在下的块再领一遍，
            // 白烧带宽（写同样的偏移，数据虽然不错，但流量翻倍）。
            if c.owner.is_none() && !c.done && c.next <= c.end() {
                self.cursor = (i + 1) % n;
                return Some(i);
            }
        }
        None
    }

    /// 把剩余最多的块一分为二，返回新块（上半段）下标。
    ///
    /// 切点 = `next + remaining / 2`，即「剩余区间的中点」；因为 `next` 就是属主
    /// 当前位置，这等价于 `max(中点, 当前位置)`——属主已经越过中点时切点就在它脚下。
    ///
    /// 块数不超过 `max_conns`：它是本任务解析后的**连接预算**
    ///（`hosts::task_conns`：每服务器例外 > 全局闸门），同时也就是任务属性里展示的
    /// 分段数上限——多出来的块没有连接会用，只会让界面上的分段数和预算对不上。
    pub fn split_largest(&mut self) -> Option<usize> {
        if self.chunks.len() >= self.max_conns {
            return None;
        }
        let mut best: Option<(usize, u64)> = None;
        for (i, c) in self.chunks.iter().enumerate() {
            if c.done {
                continue;
            }
            let rem = c.remaining();
            if rem < 2 * MIN_CHUNK_BYTES {
                continue;
            }
            if best.map(|(_, b)| rem > b).unwrap_or(true) {
                best = Some((i, rem));
            }
        }
        let (i, rem) = best?;
        let next = self.chunks[i].next;
        let old_end = self.chunks[i].end();
        let cut = next + rem / 2;
        if cut > old_end {
            return None;
        }
        self.chunks[i].end.store(cut - 1, Ordering::Release);
        // 新块 **追加** 到末尾：块下标必须稳定，连接线程持有的是下标，
        // 中间插入会让下标指向别的块（数据写错位）。
        self.chunks.push(Chunk {
            start: cut,
            end: Arc::new(AtomicU64::new(old_end)),
            next: cut,
            owner: None,
            done: false,
        });
        self.splits += 1;
        Some(self.chunks.len() - 1)
    }

    /// 指定块被再切分（慢块抢分）。返回新块下标。块数同样不超过 `max_conns`。
    pub fn split_at(&mut self, i: usize) -> Option<usize> {
        if self.chunks.len() >= self.max_conns {
            return None;
        }
        let c = self.chunks.get(i)?;
        if c.done {
            return None;
        }
        let rem = c.remaining();
        if rem < 2 * MIN_CHUNK_BYTES {
            return None;
        }
        let next = c.next;
        let old_end = c.end();
        let cut = next + rem / 2;
        if cut > old_end {
            return None;
        }
        self.chunks[i].end.store(cut - 1, Ordering::Release);
        self.chunks.push(Chunk {
            start: cut,
            end: Arc::new(AtomicU64::new(old_end)),
            next: cut,
            owner: None,
            done: false,
        });
        self.splits += 1;
        Some(self.chunks.len() - 1)
    }

    /// 落盘推进；返回本次新增字节。
    pub fn advance(&mut self, i: usize, to: u64) -> u64 {
        let c = &mut self.chunks[i];
        let to = to.min(c.end().saturating_add(1));
        if to <= c.next {
            return 0;
        }
        let delta = to - c.next;
        c.next = to;
        self.bytes_done += delta;
        delta
    }

    pub fn complete(&mut self, i: usize) {
        if let Some(c) = self.chunks.get_mut(i) {
            let end = c.end();
            c.next = end.saturating_add(1);
            c.done = true;
            c.owner = None;
        }
    }

    /// 连接放弃该块（失败/被抢占），块回到未认领状态，已落盘进度保留。
    pub fn release(&mut self, i: usize) {
        if let Some(c) = self.chunks.get_mut(i) {
            c.owner = None;
            if c.next > c.end() {
                c.done = true;
            }
        }
    }

    /// 已确认落盘的连续前缀长度：从文件头开始，所有块都下完才能继续往后。
    ///
    /// 哈希流水线用它判断「可以从哪里往下算 SHA-256」。
    pub fn complete_prefix(&self) -> u64 {
        let mut sorted: Vec<(u64, u64, bool)> = self
            .chunks
            .iter()
            .map(|c| (c.start, c.end(), c.done || c.next > c.end()))
            .collect();
        sorted.sort_unstable_by_key(|c| c.0);
        let mut h = 0u64;
        for (start, end, done) in sorted {
            if start > h {
                break; // 空洞（理论上不会出现，防一手）
            }
            if !done {
                break;
            }
            h = end.saturating_add(1);
        }
        h
    }

    pub fn merge_ranges(&self) -> Vec<(u64, u64, u64)> {
        self.chunks
            .iter()
            .map(|c| (c.start, c.end(), c.next))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_never_hands_out_an_owned_chunk() {
        let total = 16 * MIN_CHUNK_BYTES;
        let mut p = Plan::new(total, 2, 8);
        p.set_target(8);
        let a = p.claim(0).unwrap();
        let b = p.claim(1).unwrap();
        assert_ne!(a.idx, b.idx);
        // 只有两块，两块都被认领；再要只能靠抢分，绝不能把 a/b 再发一次
        for w in 0..6 {
            if let Some(j) = p.claim(w + 2) {
                assert!(j.idx != a.idx && j.idx != b.idx, "重复发放了已认领的块");
            }
        }
        assert_eq!(p.active(), 2 + p.chunks.len().saturating_sub(2).min(6));
    }

    #[test]
    fn equal_split_covers_all() {
        let p = Plan::new(10 * MIN_CHUNK_BYTES, 8, 32);
        assert_eq!(p.chunks.len(), 8);
        assert_eq!(p.chunks[0].start, 0);
        assert_eq!(p.chunks.last().unwrap().end(), 10 * MIN_CHUNK_BYTES - 1);
        for w in p.chunks.windows(2) {
            assert_eq!(w[1].start, w[0].end() + 1);
        }
    }

    #[test]
    fn split_takes_upper_half_and_keeps_coverage() {
        let total = 64 * MIN_CHUNK_BYTES;
        let mut p = Plan::new(total, 1, 32);
        p.set_target(32);
        let j = p.claim(0).unwrap();
        assert_eq!(j.idx, 0);
        assert_eq!(j.end_now(), total - 1);
        let new = p.split_largest().unwrap();
        // 上半段从剩余中点开始
        assert_eq!(p.chunks[new].start, total / 2);
        assert_eq!(p.chunks[new].end(), total - 1);
        assert_eq!(p.chunks[0].end(), total / 2 - 1);
        // 覆盖不变、无空洞
        let sum: u64 = p.chunks.iter().map(|c| c.end() - c.start + 1).sum();
        assert_eq!(sum, total);
        for w in p.chunks.windows(2) {
            assert_eq!(w[1].start, w[0].end() + 1);
        }
    }

    #[test]
    fn split_point_follows_owner_position() {
        let total = 64 * MIN_CHUNK_BYTES;
        let mut p = Plan::new(total, 1, 32);
        p.set_target(32);
        p.claim(0).unwrap();
        // 属主已经下到中点之后
        let past = total / 2 + 5 * MIN_CHUNK_BYTES;
        p.advance(0, past);
        let new = p.split_largest().unwrap();
        assert_eq!(p.chunks[new].start, past + (total - past) / 2);
    }

    #[test]
    fn split_respects_min_chunk() {
        let total = 3 * MIN_CHUNK_BYTES;
        let mut p = Plan::new(total, 2, 32);
        p.set_target(32);
        let _ = p.claim(0).unwrap();
        let _ = p.claim(1).unwrap();
        assert!(p.split_largest().is_none(), "剩余不足两倍最小段长时不切");
    }

    #[test]
    fn target_gates_claims() {
        let mut p = Plan::new(32 * MIN_CHUNK_BYTES, 8, 32);
        p.set_target(2);
        assert!(p.claim(0).is_some());
        assert!(p.claim(1).is_some());
        assert!(
            p.claim(2).is_none(),
            "并发已达 target，即使还有未认领块也不发"
        );
        p.set_target(4);
        assert!(p.claim(2).is_some());
    }

    #[test]
    fn donor_stops_at_narrowed_end() {
        let total = 64 * MIN_CHUNK_BYTES;
        let mut p = Plan::new(total, 1, 32);
        p.set_target(32);
        let j = p.claim(0).unwrap();
        let new = p.split_largest().unwrap();
        assert_eq!(j.end_now(), p.chunks[0].end());
        assert!(j.end_now() < p.chunks[new].start);
        p.advance(0, j.end_now() + 1);
        p.complete(0);
        assert!(p.chunks[0].done);
        assert_eq!(p.chunks[0].remaining(), 0);
    }

    #[test]
    fn complete_then_steal_by_splitting_not_by_stealing_owned_chunks() {
        let total = 16 * MIN_CHUNK_BYTES;
        let mut p = Plan::new(total, 4, 8);
        p.set_target(4);
        let mut jobs = vec![];
        for w in 0..4 {
            jobs.push(p.claim(w).unwrap());
        }
        let owned: Vec<usize> = jobs.iter().map(|j| j.idx).collect();
        p.complete(jobs[0].idx);
        // 该连接下完后又领到活：只能要么是没人认领的块，要么是把最大块劈出来的新块，
        // 绝不能是别人正在下的块。
        let again = p.claim(0).unwrap();
        assert!(
            !owned.iter().any(|i| *i == again.idx && *i != jobs[0].idx),
            "抢走了别人已认领的块 {:?} / owned={owned:?}",
            again.idx
        );
        assert!(again.idx >= 4, "应当来自一次再切分，得到 idx={}", again.idx);
    }

    #[test]
    fn snapshot_roundtrip_preserves_progress() {
        let total = 32 * MIN_CHUNK_BYTES;
        let mut p = Plan::new(total, 4, 32);
        p.advance(0, 3 * MIN_CHUNK_BYTES);
        p.advance(1, MIN_CHUNK_BYTES);
        let snap = p.snapshot();
        let q = Plan::from_snapshot(total, &snap, 32);
        assert_eq!(q.bytes_done, p.bytes_done);
        assert_eq!(q.snapshot(), snap);
        assert_eq!(q.remaining(), p.remaining());
    }

    #[test]
    fn split_at_specific_slow_chunk_keeps_indices_stable() {
        let total = 64 * MIN_CHUNK_BYTES;
        let mut p = Plan::new(total, 4, 32);
        p.set_target(32);
        for w in 0..4 {
            p.claim(w).unwrap();
        }
        let before: Vec<(u64, u64)> = p.chunks.iter().map(|c| (c.start, c.end())).collect();
        let new = p.split_at(2).unwrap();
        assert_eq!(new, 4, "新块追加到末尾，既有块下标不变");
        // 既有块 0/1/3 的区间未被改动
        assert_eq!((p.chunks[0].start, p.chunks[0].end()), before[0]);
        assert_eq!((p.chunks[1].start, p.chunks[1].end()), before[1]);
        assert_eq!((p.chunks[3].start, p.chunks[3].end()), before[3]);
        assert_eq!(p.chunks[3].start, p.chunks[new].end() + 1);
        let sum: u64 = p.chunks.iter().map(|c| c.end() - c.start + 1).sum();
        assert_eq!(sum, total);
    }

    #[test]
    fn chunk_count_never_exceeds_max_conns() {
        // 分段数与「每任务连接数上限」对齐：用户设 32 段，就最多 32 段。
        let total = 256 * MIN_CHUNK_BYTES;
        let mut p = Plan::new(total, 32, 32);
        p.set_target(32);
        assert_eq!(p.chunks.len(), 32, "初始就按上限切满");
        for w in 0..32 {
            p.claim(w).unwrap();
        }
        // 所有块都被认领后，再想抢活只能再切分——但已到上限，必须拒绝
        p.complete(0);
        assert!(p.claim(0).is_none(), "已达 max_conns，不应再切出新块");
        assert!(p.split_largest().is_none());
        assert!(p.split_at(1).is_none());
        assert_eq!(p.chunks.len(), 32);
    }

    #[test]
    fn chunk_count_can_grow_up_to_max_conns() {
        // 上限之内仍然允许「慢块抢分」
        let total = 256 * MIN_CHUNK_BYTES;
        let mut p = Plan::new(total, 4, 32);
        p.set_target(32);
        for w in 0..4 {
            p.claim(w).unwrap();
        }
        p.complete(0);
        let again = p.claim(0).expect("上限内仍可再切分");
        assert!(again.idx >= 4);
        assert_eq!(p.chunks.len(), 5);
    }
}
