//! §3.2 分段算法与 Range / Retry-After 解析（纯逻辑，无网络 IO）。

use std::path::{Path, PathBuf};
use std::time::Duration;

/// 最小段长 256KB（§3.2）。
///
/// 这是分段数量的**唯一**上限来源：段数 = `min(期望连接数, total / 256KB)`。
/// 早先还有一个 `MAX_CONNS_PER_TASK = 32` 的硬上限，已删除 ——
/// 每任务连接数不再设限，真正的资源闸门只有全局 `conn.global_conn_cap`。
pub const MIN_SEGMENT_BYTES: u64 = 256 * 1024;
/// 段级最大重试次数（§3.2：上限 5 次）。
pub const SEGMENT_RETRY_MAX: u32 = 5;
/// 段级指数退避秒数：1/2/4/8/16。
pub const SEGMENT_BACKOFF_SECS: [u64; 5] = [1, 2, 4, 8, 16];

/// 一段闭区间 `[start, end]`（字节下标，含端点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSpan {
    pub start: u64,
    pub end: u64,
}

impl ByteSpan {
    pub fn len(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// 合法 Content-Range（`bytes start-end/total` 或 `bytes start-end/*`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentRange {
    pub start: u64,
    pub end: u64,
    pub total: Option<u64>,
}

/// 按「总大小 / 期望连接数，最小段 256KB」切分。
///
/// 返回的段覆盖 `[0, total)`，相邻无重叠无空洞。`total == 0` 时返回空。
/// `desired_conns` 不再有硬上限：段数由 `total / MIN_SEGMENT_BYTES` 自然封顶，
/// 所以"不限连接数"不会切出比文件本身能容纳的更多的段。
pub fn plan_segments(total: u64, desired_conns: u32) -> Vec<ByteSpan> {
    if total == 0 {
        return Vec::new();
    }
    let desired = u64::from(desired_conns.max(1));
    let max_by_size = (total / MIN_SEGMENT_BYTES).max(1);
    let n = desired.min(max_by_size).max(1);
    let base = total / n;
    let rem = total % n;
    let mut segs = Vec::with_capacity(n as usize);
    let mut pos = 0u64;
    for i in 0..n {
        let len = base + u64::from(i < rem);
        let end = pos + len - 1;
        segs.push(ByteSpan { start: pos, end });
        pos += len;
    }
    segs
}

/// 每任务**期望**连接数：`requested > 0` 为用户指定值；`requested <= 0` = 不限，
/// 取全局闸门值作为期望。
///
/// 返回的只是期望值：HTTP 侧再由 [`MIN_SEGMENT_BYTES`] 收窄（段数不能超过
/// `total / 256KB`），eD2k 侧再由候选源数与分片数收窄。
pub fn desired_conns(requested: i64, global_cap: u64) -> u32 {
    if requested > 0 {
        return requested.min(i64::from(u32::MAX)) as u32;
    }
    global_cap.clamp(1, u64::from(u32::MAX)) as u32
}

/// 每个任务最多同时使用几个来源。
///
/// 限制的理由：失败路径上每多一个来源就多一次探测与重试，而且更多来源并不会
/// 让本机带宽变宽 —— 收益只在"单个来源给不满"时出现。4 是保守值。
pub const MAX_SOURCES: usize = 4;

/// 跨源聚合下载的前提：**必须能证明各来源是同一份文件**。
///
/// 没有分片级哈希时，唯一兜底是「完成后用上游整文件哈希校验」，所以三个条件
/// 缺一不可：
/// 1. 拿得到上游整文件 SHA-256（否则内容不同只能等用户自己发现）；
/// 2. 至少两个来源；
/// 3. 每个来源报出的总长度都相同，且与已落库长度一致（长度不同 = 不是同一份文件）。
///
/// 任一条件不满足就返回 `false` —— 此时保持单源，与从前行为完全一致。
pub fn multi_source_allowed(
    has_expected_hash: bool,
    recorded_size: Option<i64>,
    pool_sizes: &[Option<u64>],
) -> bool {
    if !has_expected_hash || pool_sizes.len() < 2 {
        return false;
    }
    // 报不出长度的来源不能进池：无法与别人比对。
    let Some(first) = pool_sizes[0] else {
        return false;
    };
    if pool_sizes.iter().any(|s| *s != Some(first)) {
        return false;
    }
    match recorded_size {
        Some(old) if old > 0 => old as u64 == first,
        _ => true,
    }
}

/// 把分段轮流分给来源：**同一段只绑一个源，不混源**。
///
/// 来源少于两个时返回全 `None`（= 用任务级地址，即单源）。
pub fn assign_sources(seg_count: usize, sources: &[String]) -> Vec<Option<String>> {
    if sources.len() < 2 {
        return vec![None; seg_count];
    }
    (0..seg_count)
        .map(|i| Some(sources[i % sources.len()].clone()))
        .collect()
}

/// 某段失败后换到下一个来源（在列表里循环）。
///
/// 只有一个来源时返回原值：换也没得换，不该假装换过。
pub fn next_source(current: Option<&str>, sources: &[String]) -> Option<String> {
    if sources.len() < 2 {
        return current.map(str::to_string);
    }
    let idx = current
        .and_then(|c| sources.iter().position(|s| s == c))
        .map(|i| (i + 1) % sources.len())
        .unwrap_or(0);
    Some(sources[idx].clone())
}

/// 一个已存在分段的当前状态（设置改动后「再切分」的输入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentState {
    pub start: u64,
    pub end: u64,
    /// 已下载字节（相对 `start`）。
    pub done: u64,
}

/// 再切分后的分段布局（§3.2「一分为二」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedSegment {
    pub start: u64,
    pub end: u64,
    pub done: u64,
    /// `Some(i)` = 沿用 `states[i]` 的 part 文件与已完成字节；
    /// `None` = 新切出来的段（需新建 part 文件，从 `start` 开始下）。
    pub source: Option<usize>,
}

/// 把段数补到 `desired`：每次取「剩余最多」的段，在其**剩余区间**的中点一分为二。
///
/// 前半段沿用原 part 文件与已完成字节（`done` 不变，只收窄 `end`），后半段作为新段
/// 从切点续下，因此不需要搬动任何已落盘数据。两半都不小于 [`MIN_SEGMENT_BYTES`]
/// 时才切，所以返回的段数可能小于 `desired`。返回按 `start` 升序的完整布局；
/// `desired` 不大于现有段数时原样返回（不做合并）。
pub fn resplit_segments(states: &[SegmentState], desired: u32) -> Vec<PlannedSegment> {
    let desired = desired.max(1) as usize;
    let mut out: Vec<PlannedSegment> = states
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let len = s.end.saturating_sub(s.start).saturating_add(1);
            PlannedSegment {
                start: s.start,
                end: s.end,
                done: s.done.min(len),
                source: Some(i),
            }
        })
        .collect();
    out.sort_by_key(|s| s.start);
    while out.len() < desired {
        let Some(i) = best_split_candidate(&out) else {
            break;
        };
        let seg = out[i];
        let cut = seg.start.saturating_add(seg.done);
        let rem = seg.end.saturating_sub(cut).saturating_add(1);
        let split_at = cut + rem / 2 - 1;
        out[i] = PlannedSegment {
            end: split_at,
            ..seg
        };
        out.insert(
            i + 1,
            PlannedSegment {
                start: split_at + 1,
                end: seg.end,
                done: 0,
                source: None,
            },
        );
    }
    out
}

/// 剩余最多且仍够切两半（各 ≥ [`MIN_SEGMENT_BYTES`]）的段下标。
fn best_split_candidate(segs: &[PlannedSegment]) -> Option<usize> {
    let mut best: Option<(usize, u64)> = None;
    for (i, s) in segs.iter().enumerate() {
        let rem = s
            .end
            .saturating_sub(s.start.saturating_add(s.done))
            .saturating_add(1);
        if rem < 2 * MIN_SEGMENT_BYTES {
            continue;
        }
        if best.map(|(_, b)| rem > b).unwrap_or(true) {
            best = Some((i, rem));
        }
    }
    best.map(|(i, _)| i)
}

/// 解析 `Content-Range: bytes start-end/total`。无法解析返回 None（探测失败 → 降级单线程）。
pub fn parse_content_range(header: &str) -> Option<ContentRange> {
    let rest = header.trim();
    let rest = rest
        .strip_prefix("bytes")
        .or_else(|| rest.strip_prefix("BYTES"))?
        .trim();
    let (range, total) = rest.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start: u64 = start.trim().parse().ok()?;
    let end: u64 = end.trim().parse().ok()?;
    if end < start {
        return None;
    }
    let total = match total.trim() {
        "*" => None,
        t => Some(t.parse().ok()?),
    };
    if let Some(t) = total {
        if end >= t {
            return None;
        }
    }
    Some(ContentRange { start, end, total })
}

/// 206 + 合法 Content-Range 且总长已知 ⇒ 支持多连接。
pub fn range_supports_multi(status: u16, content_range: Option<&str>) -> bool {
    status == 206
        && content_range
            .and_then(parse_content_range)
            .and_then(|cr| cr.total)
            .is_some()
}

/// 解析 Retry-After：整秒，或 IMF-fixdate（尽力）；都失败则 None。
pub fn parse_retry_after(header: &str) -> Option<Duration> {
    let s = header.trim();
    if let Ok(secs) = s.parse::<u64>() {
        return Some(Duration::from_secs(secs.min(300)));
    }
    parse_imf_fixdate_secs(s).map(|unix| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let wait = unix.saturating_sub(now).clamp(0, 300) as u64;
        Duration::from_secs(wait)
    })
}

/// 第 `attempt` 次重试（1..=5）应对应的退避时长。
pub fn backoff_for_attempt(attempt: u32) -> Duration {
    let idx = attempt.saturating_sub(1) as usize;
    let secs = SEGMENT_BACKOFF_SECS
        .get(idx)
        .copied()
        .unwrap_or(*SEGMENT_BACKOFF_SECS.last().unwrap());
    Duration::from_secs(secs)
}

/// `<save_dir>/.aidm/<task_id>/`
pub fn part_dir(save_dir: &Path, task_id: i64) -> PathBuf {
    save_dir.join(".aidm").join(task_id.to_string())
}

/// `<save_dir>/.aidm/<task_id>/part<i>`
pub fn part_path(save_dir: &Path, task_id: i64, idx: i32) -> PathBuf {
    part_dir(save_dir, task_id).join(format!("part{idx}"))
}

/// 已存储的 ETag / Last-Modified 与本次响应比较：双方都有且不一致 ⇒ 拒绝续传。
pub fn validators_changed(
    stored_etag: Option<&str>,
    stored_lm: Option<&str>,
    new_etag: Option<&str>,
    new_lm: Option<&str>,
) -> bool {
    if let (Some(old), Some(new)) = (nonzero(stored_etag), nonzero(new_etag)) {
        if normalize_etag(old) != normalize_etag(new) {
            return true;
        }
    }
    if let (Some(old), Some(new)) = (nonzero(stored_lm), nonzero(new_lm)) {
        if old != new {
            return true;
        }
    }
    false
}

fn nonzero(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

fn normalize_etag(s: &str) -> &str {
    s.trim().trim_start_matches("W/").trim_matches('"')
}

/// 解析 `Wed, 21 Oct 2015 07:28:00 GMT` 为 unix 秒；失败返回 None。
fn parse_imf_fixdate_secs(s: &str) -> Option<i64> {
    // "Dow, DD Mon YYYY HH:MM:SS GMT"
    let rest = s.split_once(", ")?.1;
    let mut parts = rest.split_whitespace();
    let day: u32 = parts.next()?.parse().ok()?;
    let mon = month_num(parts.next()?)?;
    let year: i32 = parts.next()?.parse().ok()?;
    let time = parts.next()?;
    let tz = parts.next()?;
    if !tz.eq_ignore_ascii_case("GMT") && !tz.eq_ignore_ascii_case("UTC") {
        return None;
    }
    let mut hm = time.split(':');
    let hour: u32 = hm.next()?.parse().ok()?;
    let min: u32 = hm.next()?.parse().ok()?;
    let sec: u32 = hm.next()?.parse().ok()?;
    datetime_to_unix(year, mon, day, hour, min, sec)
}

fn month_num(m: &str) -> Option<u32> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn datetime_to_unix(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y) { 366 } else { 365 };
    }
    const MD: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for m in 1..month {
        days += i64::from(MD[(m - 1) as usize]);
        if m == 2 && is_leap(year) {
            days += 1;
        }
    }
    days += i64::from(day.saturating_sub(1));
    Some(days * 86400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec))
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn multi_source_requires_a_proof_of_identity() {
        let two_same = [Some(100u64), Some(100u64)];
        // 没有上游整文件哈希 → 不许跨源
        assert!(!multi_source_allowed(false, None, &two_same));
        // 有哈希、两个来源、长度一致 → 允许
        assert!(multi_source_allowed(true, None, &two_same));
        assert!(multi_source_allowed(true, Some(100), &two_same));
        // 只有一个来源 = 单源，没意义
        assert!(!multi_source_allowed(true, Some(100), &[Some(100)]));
        assert!(!multi_source_allowed(true, None, &[]));
        // 长度不同 → 不是同一份文件
        assert!(!multi_source_allowed(true, None, &[Some(100), Some(101)]));
        // 报不出长度 → 无法比对
        assert!(!multi_source_allowed(true, None, &[None, Some(100)]));
        assert!(!multi_source_allowed(true, None, &[Some(100), None]));
        // 与已落库长度不一致 → 拒绝
        assert!(!multi_source_allowed(true, Some(99), &two_same));
        // 已落库长度为 0/NULL（新任务）时不构成约束
        assert!(multi_source_allowed(true, Some(0), &two_same));
    }

    #[test]
    fn assign_sources_round_robins_and_never_mixes_within_a_segment() {
        let pool = s(&["a", "b", "c"]);
        let got = assign_sources(7, &pool);
        assert_eq!(got.len(), 7);
        let got: Vec<&str> = got.iter().map(|o| o.as_deref().unwrap()).collect();
        assert_eq!(got, vec!["a", "b", "c", "a", "b", "c", "a"]);
        // 每个段只绑一个源（类型上就是单值，这里断言不出现拼接）
        assert!(got.iter().all(|u| u.len() == 1));
    }

    #[test]
    fn assign_sources_is_single_source_when_pool_is_too_small() {
        assert_eq!(assign_sources(3, &[]), vec![None, None, None]);
        assert_eq!(assign_sources(3, &s(&["only"])), vec![None, None, None]);
        assert!(assign_sources(0, &s(&["a", "b"])).is_empty());
    }

    #[test]
    fn next_source_rotates_and_wraps() {
        let pool = s(&["a", "b", "c"]);
        assert_eq!(next_source(Some("a"), &pool).as_deref(), Some("b"));
        assert_eq!(
            next_source(Some("c"), &pool).as_deref(),
            Some("a"),
            "要绕回去"
        );
        // 当前值不在池里（用户改过备用地址）→ 从第一个开始，而不是留在原地
        assert_eq!(next_source(Some("zzz"), &pool).as_deref(), Some("a"));
        assert_eq!(next_source(None, &pool).as_deref(), Some("a"));
        // 只有一个来源：换了也没得换，不该假装换过
        let one = s(&["only"]);
        assert_eq!(next_source(Some("only"), &one).as_deref(), Some("only"));
        assert_eq!(next_source(None, &one), None);
    }

    #[test]
    fn plans_min_segment_and_cap() {
        let segs = plan_segments(1024 * 1024, 8);
        assert_eq!(segs.len(), 4); // 1MiB / 256KiB
        assert_eq!(segs[0].start, 0);
        assert_eq!(segs.last().unwrap().end, 1024 * 1024 - 1);
        assert_eq!(segs.iter().map(|s| s.len()).sum::<u64>(), 1024 * 1024);

        let segs = plan_segments(8 * 1024 * 1024, 8);
        assert_eq!(segs.len(), 8);

        let tiny = plan_segments(100, 8);
        assert_eq!(tiny.len(), 1);
        assert_eq!(tiny[0], ByteSpan { start: 0, end: 99 });

        // 段数不再有"每任务 32"的硬上限：只受最小段长约束（64MiB / 256KiB = 256）。
        let uncapped = plan_segments(64 * 1024 * 1024, 64);
        assert_eq!(uncapped.len(), 64);
        // 期望值超过文件能容纳的段数时，按最小段长封顶。
        let by_size = plan_segments(64 * 1024 * 1024, 1000);
        assert_eq!(by_size.len(), 256);
        assert_eq!(
            by_size.iter().map(|s| s.len()).sum::<u64>(),
            64 * 1024 * 1024
        );

        assert!(plan_segments(0, 8).is_empty());
    }

    #[test]
    fn resplit_halves_the_largest_remaining() {
        let total = 8 * 1024 * 1024u64;
        let states = [
            SegmentState {
                start: 0,
                end: total / 2 - 1,
                done: 0,
            },
            SegmentState {
                start: total / 2,
                end: total - 1,
                done: 0,
            },
        ];
        let out = resplit_segments(&states, 4);
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].start, 0);
        assert_eq!(out.last().unwrap().end, total - 1);
        assert_eq!(
            out.iter().map(|s| s.end - s.start + 1).sum::<u64>(),
            total,
            "coverage must be untouched"
        );
        for w in out.windows(2) {
            assert_eq!(w[1].start, w[0].end + 1, "no gap, no overlap: {out:?}");
        }
        // 每段各切一次：前半沿用原 part，后半是新段
        assert_eq!(
            out.iter().map(|s| s.source).collect::<Vec<_>>(),
            vec![Some(0), None, Some(1), None]
        );
        assert!(out
            .iter()
            .filter(|s| s.source.is_none())
            .all(|s| s.done == 0));
    }

    #[test]
    fn resplit_keeps_done_and_new_starts_at_cut() {
        let total = 8 * 1024 * 1024u64;
        let done = 1024 * 1024u64;
        let states = [SegmentState {
            start: 0,
            end: total - 1,
            done,
        }];
        let out = resplit_segments(&states, 2);
        assert_eq!(out.len(), 2);
        let rem = total - done;
        let first = rem / 2;
        assert_eq!(
            out[0],
            PlannedSegment {
                start: 0,
                end: done + first - 1,
                done,
                source: Some(0),
            }
        );
        assert_eq!(
            out[1],
            PlannedSegment {
                start: done + first,
                end: total - 1,
                done: 0,
                source: None,
            },
            "new segment starts exactly at the cut"
        );
    }

    #[test]
    fn resplit_respects_min_segment_and_done() {
        let total = 1024 * 1024u64;
        let states: Vec<SegmentState> = plan_segments(total, 4)
            .into_iter()
            .map(|s| SegmentState {
                start: s.start,
                end: s.end,
                done: 0,
            })
            .collect();
        // 每段只剩 256KiB（= 最小段长），切两半不够 → 段数不变
        assert_eq!(resplit_segments(&states, 16).len(), 4);
        // 已达标不切
        let out = resplit_segments(&states, 4);
        assert_eq!(out.len(), 4);
        assert!(out.iter().all(|s| s.source.is_some()));

        // 已完成的段不再切，只切还有剩余的段
        let states = [
            SegmentState {
                start: 0,
                end: 1024 * 1024 - 1,
                done: 1024 * 1024,
            },
            SegmentState {
                start: 1024 * 1024,
                end: 4 * 1024 * 1024 - 1,
                done: 0,
            },
        ];
        let out = resplit_segments(&states, 3);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].source, Some(0));
        assert_eq!(out[0].done, 1024 * 1024, "fully done segment stays as-is");
    }

    #[test]
    fn parses_content_range() {
        let cr = parse_content_range("bytes 0-0/12345").unwrap();
        assert_eq!(
            cr,
            ContentRange {
                start: 0,
                end: 0,
                total: Some(12345)
            }
        );
        assert_eq!(parse_content_range("bytes 0-0/*").unwrap().total, None);
        assert!(parse_content_range("bytes 5-1/10").is_none());
        assert!(parse_content_range("bytes 0-9/10").is_some()); // last byte index 9 of 10
        assert!(parse_content_range("bytes 0-10/10").is_none()); // end >= total
        assert!(range_supports_multi(206, Some("bytes 0-0/100")));
        assert!(!range_supports_multi(200, Some("bytes 0-0/100")));
        assert!(!range_supports_multi(206, Some("bytes 0-0/*")));
    }

    #[test]
    fn retry_after_seconds_and_date() {
        assert_eq!(parse_retry_after("2"), Some(Duration::from_secs(2)));
        assert_eq!(parse_retry_after("9999"), Some(Duration::from_secs(300)));
        // 已过去的日期 → 0s
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(Duration::from_secs(0))
        );
        assert!(parse_retry_after("not-a-date").is_none());
    }

    #[test]
    fn backoff_sequence() {
        assert_eq!(backoff_for_attempt(1), Duration::from_secs(1));
        assert_eq!(backoff_for_attempt(5), Duration::from_secs(16));
        assert_eq!(backoff_for_attempt(9), Duration::from_secs(16));
    }

    #[test]
    fn validator_change_rules() {
        assert!(!validators_changed(None, None, Some("a"), Some("b")));
        assert!(validators_changed(
            Some("\"abc\""),
            None,
            Some("\"xyz\""),
            None
        ));
        assert!(!validators_changed(
            Some("\"abc\""),
            None,
            Some("W/\"abc\""),
            None
        ));
        assert!(validators_changed(
            None,
            Some("Mon, 01 Jan 2024 00:00:00 GMT"),
            None,
            Some("Tue, 02 Jan 2024 00:00:00 GMT")
        ));
        assert!(!validators_changed(
            Some("\"abc\""),
            Some("old"),
            None,
            None
        ));
    }

    #[test]
    fn part_layout() {
        let dir = Path::new("/tmp/dl");
        assert_eq!(part_path(dir, 7, 2), PathBuf::from("/tmp/dl/.aidm/7/part2"));
    }
}
