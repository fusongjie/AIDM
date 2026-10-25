//! 有效覆盖账本：左闭右开区间的并集、失效、缺失洞与完整性判定。
//!
//! 依据 `docs/unified-download-state-review.md` 第 4.4 节、第 8 节与第 13 节。
//!
//! 两层账本同时维护：
//! - `stored`：当前仍有效的**落盘**范围并集。
//! - `verified`：已通过所要求内容**校验**的范围并集。
//!
//! 硬性不变量：`verified ⊆ stored`。任何会让 `verified` 超出 `stored` 的操作
//! 都必须被拒绝或裁剪，不允许"先记验证、回头再补落盘"。
//!
//! 存储用有序、互不重叠且**相邻已合并**的区间列表。合并相邻是必要的：否则
//! 逐块写入会把列表涨成与原生长度同阶，既浪费内存也让"是否连续"判定复杂化。

use super::model::Span;
use std::ops::Range;

/// `segments.done_bytes` 能否当作「段内**已落盘前缀**长度」。
///
/// 这决定覆盖账本**能否**由 `segments` 汇总出来：
///
/// | 协议 | `done_bytes` 的含义 | 可推导覆盖 |
/// |---|---|---|
/// | HTTP（单连接 / 多段 / zsync / manifest） | 段内顺序写下的前缀长度 | ✅ |
/// | FTP | 顺序写，续传读文件长度 | ✅ |
/// | eD2k | **跨 part 的累计接收量**，乱序、可能含重复 | ❌ |
/// | BitTorrent | 写盘由 librqbit 内部完成，项目侧无此语义 | ❌ |
///
/// 新增协议**必须**在这里显式声明，不要写「不是 eD2k 就算可信」——
/// 那会在接 BT/QUIC 时静默地把错的数据当成覆盖。
///
/// 反例（真实数据）：一个 eD2k 任务 `done_bytes = 921_968_640`，磁盘上的
/// `part0` 只有 725 MB，且 `done_bytes / 9728000 = 94.8` 不是整数——它根本不是前缀。
pub fn done_bytes_is_prefix(url_orig: &str) -> bool {
    let u = url_orig.trim().to_ascii_lowercase();
    if u.starts_with("ed2k:") {
        return false;
    }
    // `.torrent` 文件、磁力、裸 btih 三种入口都归 BT。
    if u.starts_with("magnet:") || u.starts_with("btih:") || u.ends_with(".torrent") {
        return false;
    }
    true
}

/// 覆盖账本的违规操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageError {
    /// 区间为空或起止颠倒：`start >= end`。
    EmptySpan,
    /// 写入命中已通过校验的区域。必须先撤销该区域的验证与分配许可。
    RewritesVerified,
    /// 登记已验证覆盖，但该区间尚无落盘数据。
    VerifiedWithoutStored,
}

impl CoverageError {
    pub fn as_str(self) -> &'static str {
        match self {
            CoverageError::EmptySpan => "empty_span",
            CoverageError::RewritesVerified => "rewrites_verified",
            CoverageError::VerifiedWithoutStored => "verified_without_stored",
        }
    }
}

/// 有效覆盖账本。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoverageSet {
    /// 已落盘范围：有序、不重叠、不相邻。
    stored: Vec<Range<u64>>,
    /// 已验证范围：有序、不重叠、不相邻，且恒为 `stored` 的子集。
    verified: Vec<Range<u64>>,
}

impl CoverageSet {
    /// 空账本。
    pub fn new() -> Self {
        Self::default()
    }

    /// 由累计覆盖快照构造：`verified` 会被裁剪到 `stored` 之内。
    ///
    /// 用于接收执行器的"累计覆盖快照"事实（文档 7.1）。裁剪而不是报错，因为
    /// 快照可能来自旧轮次或边界竞态；但裁剪后仍然维持 `verified ⊆ stored`。
    pub fn from_snapshot(stored: &[Range<u64>], verified: &[Range<u64>]) -> Self {
        let merged_stored = union_ranges(stored, &[]);
        let merged_verified = union_ranges(verified, &[]);
        let clipped = intersect_ranges(&merged_verified, &merged_stored);
        Self {
            stored: merged_stored,
            verified: clipped,
        }
    }

    /// 已落盘范围的只读视图。
    pub fn stored_spans(&self) -> &[Range<u64>] {
        &self.stored
    }

    /// 已验证范围的只读视图。
    pub fn verified_spans(&self) -> &[Range<u64>] {
        &self.verified
    }

    /// 已落盘唯一字节总数。
    pub fn stored_len(&self) -> u64 {
        self.stored.iter().map(|r| r.end - r.start).sum()
    }

    /// 已验证唯一字节总数。
    pub fn verified_len(&self) -> u64 {
        self.verified.iter().map(|r| r.end - r.start).sum()
    }

    /// 账本是否为空（没有任何落盘覆盖）。
    pub fn is_empty(&self) -> bool {
        self.stored.is_empty()
    }

    /// 账本是否自洽：`verified ⊆ stored` 且两层各自有序不重叠。
    pub fn is_consistent(&self) -> bool {
        let stored_ok = is_normalized(&self.stored);
        let verified_ok = is_normalized(&self.verified);
        if !stored_ok || !verified_ok {
            return false;
        }
        // verified 必须被 stored 完全覆盖。
        intersect_ranges(&self.verified, &self.stored).len() == self.verified.len()
            && intersect_ranges(&self.verified, &self.stored)
                .iter()
                .map(|r| r.end - r.start)
                .sum::<u64>()
                == self.verified_len()
    }

    /// 在 `[start, end)` 内已落盘的字节数。
    pub fn stored_len_within(&self, start: u64, end: u64) -> u64 {
        covered_len(&self.stored, start, end)
    }

    /// 在 `[start, end)` 内已验证的字节数。
    pub fn verified_len_within(&self, start: u64, end: u64) -> u64 {
        covered_len(&self.verified, start, end)
    }

    /// 登记已落盘覆盖，返回**新增**的唯一字节数。
    ///
    /// 命中已验证区域时返回 [`CoverageError::RewritesVerified`]：已验证区域原则上
    /// 不可重写（文档第 8 节），修复必须先 [`Self::invalidate`]。
    pub fn insert_stored(&mut self, start: u64, end: u64) -> Result<u64, CoverageError> {
        if start >= end {
            return Err(CoverageError::EmptySpan);
        }
        if covered_len(&self.verified, start, end) > 0 {
            return Err(CoverageError::RewritesVerified);
        }
        let added = (end - start) - covered_len(&self.stored, start, end);
        insert_range(&mut self.stored, start, end);
        Ok(added)
    }

    /// 登记已验证覆盖，返回**新增**的已验证字节数。
    ///
    /// 传入区间会被裁剪到已落盘范围内；裁剪后为空则返回
    /// [`CoverageError::VerifiedWithoutStored`]。
    pub fn insert_verified(&mut self, start: u64, end: u64) -> Result<u64, CoverageError> {
        if start >= end {
            return Err(CoverageError::EmptySpan);
        }
        let clipped = intersect_ranges(&[start..end], &self.stored);
        if clipped.is_empty() {
            return Err(CoverageError::VerifiedWithoutStored);
        }
        let mut added = 0;
        for r in clipped {
            added += (r.end - r.start) - covered_len(&self.verified, r.start, r.end);
            insert_range(&mut self.verified, r.start, r.end);
        }
        Ok(added)
    }

    /// 让 `[start, end)` 的落盘与验证同时失效。
    ///
    /// 返回 `(失效的落盘字节, 失效的已验证字节)`。文档第 8 节要求"数据失效时
    /// 覆盖可以减少，必须给出修复原因"，字节数供调用方写
    /// `download.coverage_invalidated` 事件。
    pub fn invalidate(&mut self, start: u64, end: u64) -> (u64, u64) {
        if start >= end {
            return (0, 0);
        }
        let stored_removed = covered_len(&self.stored, start, end);
        let verified_removed = covered_len(&self.verified, start, end);
        remove_range(&mut self.stored, start, end);
        remove_range(&mut self.verified, start, end);
        (stored_removed, verified_removed)
    }

    /// 整个账本清空（内容代次更换、任务重启放弃旧数据）。
    pub fn clear(&mut self) {
        self.stored.clear();
        self.verified.clear();
    }

    /// 合并另一账本（两个切片或两条通路各自的有效覆盖）。
    ///
    /// 合并结果仍满足 `verified ⊆ stored`：两侧各自的已验证范围都被自己的
    /// 落盘范围覆盖，取并集后性质保持。
    pub fn merge(&mut self, other: &CoverageSet) {
        self.stored = union_ranges(&self.stored, &other.stored);
        self.verified = union_ranges(&self.verified, &other.verified);
    }

    /// 裁剪出落在 `span` 内的部分。
    pub fn clip(&self, span: Span) -> CoverageSet {
        let Some((start, end)) = known_bounds(span) else {
            // 开放范围无法精确裁剪：保守返回空，避免把未知终点当成已知。
            return CoverageSet::new();
        };
        CoverageSet {
            stored: intersect_ranges(&self.stored, &[start..end]),
            verified: intersect_ranges(&self.verified, &[start..end]),
        }
    }

    /// 还缺哪些区间才能铺满 `span`。开放范围返回空列表（无法判定"还缺"）。
    pub fn gaps(&self, span: Span) -> Vec<Span> {
        let Some((start, end)) = known_bounds(span) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut cursor = start;
        for r in &self.stored {
            if r.end <= cursor {
                continue;
            }
            if r.start >= end {
                break;
            }
            if r.start > cursor {
                out.push(known_span(cursor, r.start.min(end)));
            }
            cursor = cursor.max(r.end);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            out.push(known_span(cursor, end));
        }
        out
    }

    /// `span` 是否已被**落盘**完全覆盖。
    pub fn covers_stored(&self, span: Span) -> bool {
        let Some((start, end)) = known_bounds(span) else {
            return false;
        };
        end > start && self.stored_len_within(start, end) == end - start
    }

    /// `span` 是否已被**校验通过**完全覆盖。
    pub fn covers_verified(&self, span: Span) -> bool {
        let Some((start, end)) = known_bounds(span) else {
            return false;
        };
        end > start && self.verified_len_within(start, end) == end - start
    }
}

/// 把 [`Span`] 拆成已知边界；终点未知返回 `None`。
fn known_bounds(span: Span) -> Option<(u64, u64)> {
    span.end_exclusive.map(|end| (span.start, end))
}

/// 构造一个已知非空 [`Span`]。
///
/// 调用方保证 `start < end`；这里放宽为 `<=`，空结果由上层决定是否丢弃。
fn known_span(start: u64, end: u64) -> Span {
    Span {
        start,
        end_exclusive: Some(end),
    }
}

/// 区间列表是否已归一并自洽：有序、不重叠、不相邻、非空。
fn is_normalized(ranges: &[Range<u64>]) -> bool {
    let mut prev_end: Option<u64> = None;
    for r in ranges {
        if r.start >= r.end {
            return false;
        }
        if let Some(prev) = prev_end {
            // 严格大于：相邻（==）必须在插入时合并掉。
            if r.start <= prev {
                return false;
            }
        }
        prev_end = Some(r.end);
    }
    true
}

/// 在有序列表中计算 `[start, end)` 的已覆盖长度。
fn covered_len(ranges: &[Range<u64>], start: u64, end: u64) -> u64 {
    if start >= end {
        return 0;
    }
    ranges
        .iter()
        .filter_map(|r| {
            let lo = r.start.max(start);
            let hi = r.end.min(end);
            // 不能用 `then_some(hi - lo)`：`then_some` 是急切求值，条件为假时
            // 仍然会算 `hi - lo`，在 `hi < lo` 时整数下溢。
            if hi > lo {
                Some(hi - lo)
            } else {
                None
            }
        })
        .sum()
}

/// 插入一个区间并合并重叠或相邻的邻居。
fn insert_range(ranges: &mut Vec<Range<u64>>, start: u64, end: u64) {
    if start >= end {
        return;
    }
    let mut lo = start;
    let mut hi = end;
    let mut first: Option<usize> = None;
    let mut last_exclusive: Option<usize> = None;

    for (i, r) in ranges.iter().enumerate() {
        // `r.end < lo` 才是严格分离：`r.end == lo` 属于相邻，需要合并。
        if r.end < lo {
            continue;
        }
        if r.start > hi {
            break;
        }
        lo = lo.min(r.start);
        hi = hi.max(r.end);
        if first.is_none() {
            first = Some(i);
        }
        last_exclusive = Some(i + 1);
    }

    match (first, last_exclusive) {
        (Some(f), Some(t)) => {
            ranges.splice(f..t, std::iter::once(lo..hi));
        }
        _ => {
            let pos = ranges.partition_point(|r| r.end < lo);
            ranges.insert(pos, lo..hi);
        }
    }
}

/// 从有序列表中移除一个区间，必要时把跨越边界的区间切成两段。
fn remove_range(ranges: &mut Vec<Range<u64>>, start: u64, end: u64) {
    if start >= end {
        return;
    }
    let mut out: Vec<Range<u64>> = Vec::with_capacity(ranges.len() + 1);
    for r in ranges.drain(..) {
        if r.end <= start || r.start >= end {
            out.push(r);
            continue;
        }
        if r.start < start {
            out.push(r.start..start);
        }
        if r.end > end {
            out.push(end..r.end);
        }
    }
    *ranges = out;
}

/// 两个有序区间列表的并集（合并重叠与相邻）。
fn union_ranges(a: &[Range<u64>], b: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut all: Vec<Range<u64>> = Vec::with_capacity(a.len() + b.len());
    all.extend(a.iter().cloned());
    all.extend(b.iter().cloned());
    all.sort_by_key(|r| r.start);

    let mut out: Vec<Range<u64>> = Vec::with_capacity(all.len());
    for r in all {
        match out.last_mut() {
            // `<=` 把相邻区间合并，保持"不相邻"不变量。
            Some(last) if r.start <= last.end => {
                if r.end > last.end {
                    last.end = r.end;
                }
            }
            _ => out.push(r),
        }
    }
    // 丢弃空区间（理论上输入不含，防御性处理）。
    out.retain(|r| r.start < r.end);
    out
}

/// 两个有序区间列表的交集。
fn intersect_ranges(a: &[Range<u64>], b: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        let start = a[i].start.max(b[j].start);
        let end = a[i].end.min(b[j].end);
        if end > start {
            out.push(start..end);
        }
        if a[i].end < b[j].end {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(stored: &[(u64, u64)], verified: &[(u64, u64)]) -> CoverageSet {
        let s: Vec<Range<u64>> = stored.iter().map(|&(a, b)| a..b).collect();
        let v: Vec<Range<u64>> = verified.iter().map(|&(a, b)| a..b).collect();
        CoverageSet::from_snapshot(&s, &v)
    }

    fn spans(set: &CoverageSet) -> Vec<(u64, u64)> {
        set.stored_spans()
            .iter()
            .map(|r| (r.start, r.end))
            .collect()
    }

    #[test]
    fn overlapping_inserts_are_merged_not_accumulated() {
        let mut c = CoverageSet::new();
        assert_eq!(c.insert_stored(0, 100), Ok(100));
        // 完全包含：不新增。
        assert_eq!(c.insert_stored(10, 50), Ok(0));
        // 部分重叠：只算超出部分。
        assert_eq!(c.insert_stored(80, 150), Ok(50));
        assert_eq!(c.stored_len(), 150);
        assert_eq!(spans(&c), vec![(0, 150)]);
    }

    #[test]
    fn adjacent_inserts_are_merged() {
        let mut c = CoverageSet::new();
        c.insert_stored(0, 100).expect("first");
        c.insert_stored(100, 200).expect("adjacent");
        assert_eq!(spans(&c), vec![(0, 200)], "相邻必须合并为一段");
        assert_eq!(c.stored_len(), 200);
    }

    #[test]
    fn out_of_order_inserts_stay_sorted() {
        let mut c = CoverageSet::new();
        for (a, b) in [(300, 400), (0, 100), (200, 300), (150, 250), (500, 600)] {
            c.insert_stored(a, b).expect("insert");
        }
        assert_eq!(spans(&c), vec![(0, 100), (150, 400), (500, 600)]);
        assert!(c.is_consistent());
    }

    #[test]
    fn gap_detection_reports_holes_in_order() {
        let c = set(&[(0, 100), (200, 300)], &[]);
        let gaps = c.gaps(Span::known(0, 400).expect("span"));
        let got: Vec<(u64, u64)> = gaps
            .iter()
            .map(|s| (s.start, s.end_exclusive.expect("known")))
            .collect();
        assert_eq!(got, vec![(100, 200), (300, 400)]);
        assert!(!c.covers_stored(Span::known(0, 400).expect("span")));
        assert!(c.covers_stored(Span::known(0, 100).expect("span")));
    }

    #[test]
    fn gap_detection_on_empty_and_fully_covered() {
        let empty = CoverageSet::new();
        let gaps = empty.gaps(Span::known(5, 10).expect("span"));
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].start, 5);

        let full = set(&[(0, 10)], &[]);
        assert!(full.gaps(Span::known(0, 10).expect("span")).is_empty());
        assert!(full.gaps(Span::known(3, 7).expect("span")).is_empty());
    }

    #[test]
    fn repeated_bytes_do_not_increase_unique_coverage() {
        // 文档验收：重复 1 MiB 只增加 1 MiB 唯一覆盖。
        let mut c = CoverageSet::new();
        let first = c.insert_stored(0, 1024 * 1024).expect("first");
        let second = c.insert_stored(0, 1024 * 1024).expect("repeat");
        assert_eq!(first, 1024 * 1024);
        assert_eq!(second, 0, "重复传输只增加 wire_bytes，不增加唯一覆盖");
        assert_eq!(c.stored_len(), 1024 * 1024);
    }

    #[test]
    fn invalidate_splits_and_reduces_coverage() {
        let c = set(&[(0, 300)], &[(0, 300)]);
        let mut c = c;
        let (stored, verified) = c.invalidate(100, 200);
        assert_eq!((stored, verified), (100, 100), "失效字节数必须如实报告");
        assert_eq!(spans(&c), vec![(0, 100), (200, 300)], "中间挖洞要切成两段");
        assert_eq!(c.stored_len(), 200);
        assert_eq!(c.verified_len(), 200);
        assert!(c.is_consistent(), "失效后仍须自洽");
    }

    #[test]
    fn invalidate_beyond_edges_is_clamped() {
        let mut c = set(&[(100, 200)], &[(100, 200)]);
        let (s, v) = c.invalidate(0, 150);
        assert_eq!((s, v), (50, 50));
        assert_eq!(spans(&c), vec![(150, 200)]);
    }

    #[test]
    fn verified_never_exceeds_stored() {
        // 快照里 verified 超出 stored，必须被裁剪而不是相信输入。
        let c = set(&[(0, 100)], &[(0, 200)]);
        assert_eq!(c.verified_len(), 100);
        assert!(c.is_consistent());

        // 完全没有 stored 时，verified 一律丢弃。
        let c = set(&[], &[(0, 100)]);
        assert_eq!(c.verified_len(), 0);
        assert!(c.is_consistent());
    }

    #[test]
    fn insert_verified_without_stored_is_rejected() {
        let mut c = CoverageSet::new();
        assert_eq!(
            c.insert_verified(0, 100),
            Err(CoverageError::VerifiedWithoutStored)
        );
        assert_eq!(c.verified_len(), 0);
    }

    #[test]
    fn insert_verified_clips_to_stored() {
        let mut c = CoverageSet::new();
        c.insert_stored(50, 100).expect("store");
        // 请求验证 0..100，只有 50..100 有落盘数据。
        let added = c.insert_verified(0, 100).expect("verify");
        assert_eq!(added, 50, "只把落盘范围内的一段计入验证");
        assert_eq!(c.verified_len(), 50);
        assert!(c.is_consistent());
    }

    #[test]
    fn rewriting_verified_region_is_rejected() {
        let mut c = CoverageSet::new();
        c.insert_stored(0, 100).expect("store");
        c.insert_verified(0, 100).expect("verify");
        assert_eq!(
            c.insert_stored(0, 100),
            Err(CoverageError::RewritesVerified),
            "已验证区域不可直接重写"
        );
        // 撤销验证后可以重写。
        c.invalidate(0, 100);
        assert_eq!(c.insert_stored(0, 100), Ok(100));
    }

    #[test]
    fn empty_span_is_rejected() {
        let mut c = CoverageSet::new();
        assert_eq!(c.insert_stored(5, 5), Err(CoverageError::EmptySpan));
        assert_eq!(c.insert_stored(10, 5), Err(CoverageError::EmptySpan));
        assert_eq!(c.insert_verified(5, 5), Err(CoverageError::EmptySpan));
        assert_eq!(c.invalidate(5, 5), (0, 0));
    }

    #[test]
    fn merge_of_two_slices_keeps_invariants() {
        let a = set(&[(0, 100)], &[(0, 50)]);
        let b = set(&[(100, 200)], &[(100, 200)]);
        let mut c = a.clone();
        c.merge(&b);
        assert_eq!(c.stored_len(), 200);
        assert_eq!(c.verified_len(), 150);
        assert!(c.is_consistent());
        assert_eq!(spans(&c), vec![(0, 200)], "合并后相邻段归一");
    }

    #[test]
    fn clip_restricts_to_span() {
        let c = set(&[(0, 100), (200, 300)], &[(20, 80)]);
        let clipped = c.clip(Span::known(10, 250).expect("span"));
        assert_eq!(
            clipped.stored_spans().iter().map(|r| (r.start, r.end)).collect::<Vec<_>>(),
            vec![(10, 100), (200, 250)]
        );
        assert_eq!(clipped.verified_len(), 60);
    }

    #[test]
    fn open_span_cannot_be_judged_complete_or_clipped() {
        let c = set(&[(0, 100)], &[]);
        assert!(!c.covers_stored(Span::open(0)), "总长未知不能判定完整");
        assert!(c.gaps(Span::open(0)).is_empty(), "开放范围无法计算缺失");
        assert!(c.clip(Span::open(0)).is_empty(), "开放范围不裁剪成已知");
    }

    #[test]
    fn normalize_check_rejects_unsorted_input() {
        let bad = vec![10..20, 0..5];
        assert!(!is_normalized(&bad));
        let adjacent = vec![0..10, 10..20];
        assert!(!is_normalized(&adjacent), "相邻未合并视为未归一");
    }

    #[test]
    fn clear_resets_both_layers() {
        let mut c = set(&[(0, 100)], &[(0, 100)]);
        c.clear();
        assert_eq!(c.stored_len(), 0);
        assert_eq!(c.verified_len(), 0);
        assert!(c.is_consistent());
    }

    #[test]
    fn corrupted_coverage_lowers_reported_completion() {
        // 文档验收：损坏失效如实降低有效覆盖，不能用"只增不减"掩盖。
        let mut c = set(&[(0, 1000)], &[(0, 1000)]);
        assert_eq!(c.verified_len(), 1000);
        c.invalidate(400, 600);
        assert_eq!(c.verified_len(), 800, "损坏后覆盖必须下降");
        assert_eq!(c.stored_len(), 800);
    }
}
