//! 切片方案投影（等价性工具）。
//!
//! 目的只有一个：**让「legacy 算出来的切片」与「`download_slices` 表里的切片」
//! 能被逐字节比较**。没有这一步，接管切片决策权时只能靠"看起来一样"，
//! 而范围语义（闭区间 vs 左闭右开）恰恰是最容易差一的地方。
//!
//! 约定：
//! - 内部统一用 `[start, end_exclusive)`，`None` 表示开区间（未知总长）；
//! - 投影按 `start` 升序，**不**信任输入顺序（表里没有 ORDER BY 保证）；
//! - 投影只包含范围，不含 `slice_id`/`state`：等价性关心的是"切在哪"，
//!   不是"怎么命名"。命名不一致属于缺陷，但不该让等价性测试失败到无法定位。

use crate::segment;

/// 一份方案允许的最大切片数。
///
/// `plan_segments` 天然受 `total / MIN_SEGMENT_BYTES` 与连接预算双重收窄，
/// 但表里的方案可以由 `PlanSlices` 命令塞进来——没有上限就是「一条命令
/// spawn 1024+ 个线程」。取 1024 与 `conn.global_conn_cap` 的上界对齐。
pub const MAX_PLAN_SLICES: usize = 1024;

/// 切片方案投影的格式版本。改格式必须改版本号，避免旧断言静默失效。
pub const PLAN_PROJECTION_VERSION: &str = "plan-v1";

/// 一段范围的规范化表示：左闭右开，`None` = 到文件末尾。
pub type NormalizedSpan = (u64, Option<u64>);

/// 把一段范围编码成稳定字符串。
///
/// 开区间写成 `start..`（不带终点），闭区间写成 `start..end`。
/// 用 `..` 而不是 `-`：负号在字节串里不会被误读，而 `-` 会。
fn encode_span(span: NormalizedSpan) -> String {
    match span.1 {
        Some(end) => format!("{}..{}", span.0, end),
        None => format!("{}..", span.0),
    }
}

/// 核心投影：排序 + 编码。**纯逻辑，不碰 IO。**
///
/// 排序用 `start`，相同 `start` 时用终点排（`None` 视为最大），
/// 保证同一组范围无论从哪来都得到同一串字节。
pub fn project(spans: &[NormalizedSpan]) -> String {
    let mut v = spans.to_vec();
    v.sort_by(|a, b| {
        a.0.cmp(&b.0).then_with(|| match (a.1, b.1) {
            (None, None) => std::cmp::Ordering::Equal,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (Some(_), None) => std::cmp::Ordering::Less,
            (Some(x), Some(y)) => x.cmp(&y),
        })
    });
    let mut out = String::with_capacity(PLAN_PROJECTION_VERSION.len() + 1 + v.len() * 24);
    out.push_str(PLAN_PROJECTION_VERSION);
    for span in v {
        out.push('|');
        out.push_str(&encode_span(span));
    }
    out
}

/// 把 legacy 的分段规划投影成同一格式。
///
/// `segment::plan_segments` 返回的是**闭区间** `[start, end]`，
/// 这里做 `end + 1` 转换成左闭右开。这个 `+1` 就是本模块存在的理由：
/// 漏了它，两边会"看起来一样"却差一字节。
pub fn project_legacy(total: u64, desired_conns: u32) -> String {
    let spans: Vec<NormalizedSpan> = segment::plan_segments(total, desired_conns)
        .into_iter()
        .map(|s| (s.start, Some(s.end.saturating_add(1))))
        .collect();
    project(&spans)
}

/// 把表里的切片行投影成同一格式。
///
/// 入参是 `download_slices` 的 `(span_start, span_end_exclusive)` 列。
/// 不做任何"修正"：`end_exclusive <= start` 这种坏行照原样编码，
/// 让比较失败而不是被悄悄抹平。
pub fn project_rows(rows: &[NormalizedSpan]) -> String {
    project(rows)
}

/// 方案的稳定指纹（FNV-1a，十六进制 16 位）。
///
/// 用途：`PlanSlices` 的 `command_id` 与幂等键都要带它。不带的话，
/// 「同一任务、同一轮次、同一条规则」派生出的 id 恒等——方案变了，
/// `CommandLedger::accept` 会先按 `command_id` 命中旧命令直接 `Merged`
/// （去重顺序是 by_id 优先、by_key 其后），新方案永远发不出去。
///
/// 用 FNV-1a 而不是标准库 `Hasher`：`DefaultHasher` 不保证跨版本稳定，
/// 而命令 id 是要落库、要跨重启比对的东西。
pub fn fingerprint(spans: &[NormalizedSpan]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in project(spans).as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// 方案是否**恰好**覆盖 `[0, total)`：起点为 0、相邻无缝、终点为 total。
///
/// 读表优先之前必须先过这一关：表可能来自另一个 `total`（文件变大/变小）、
/// 来自未知长度的开区间、或者被坏数据污染。用错方案会把字节写到错误位置，
/// 所以这里只要有一条不满足就**回退重算**，不做任何修补。
pub fn covers_exactly(spans: &[NormalizedSpan], total: u64) -> bool {
    if spans.is_empty() || total == 0 {
        return false;
    }
    let mut v = spans.to_vec();
    v.sort_by_key(|s| (s.0, s.1));
    let mut cursor = 0u64;
    for (start, end) in v {
        // 开区间（未知总长）不能用于已知总长的任务。
        let Some(end) = end else {
            return false;
        };
        if start != cursor || end <= start {
            // 空洞、重叠、倒挂都不接受。
            return false;
        }
        cursor = end;
    }
    cursor == total
}

/// 投影里实际编码的段数（诊断用）。
pub fn span_count(projection: &str) -> usize {
    projection.matches('|').count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_projection_converts_inclusive_end_to_exclusive() {
        // 1 MiB / 4 段 = 每段 262144 字节。
        let p = project_legacy(1024 * 1024, 4);
        assert_eq!(
            p,
            "plan-v1|0..262144|262144..524288|524288..786432|786432..1048576"
        );
        assert_eq!(span_count(&p), 4);
    }

    #[test]
    fn legacy_and_rows_project_identically_for_the_same_plan() {
        // 这正是 C3-a 的等价性断言：两条来源、同一方案、同一字节串。
        let total = 3_000_000;
        let conns = 6;
        let legacy = project_legacy(total, conns);
        let rows: Vec<NormalizedSpan> = segment::plan_segments(total, conns)
            .into_iter()
            .map(|s| (s.start, Some(s.end + 1)))
            .collect();
        assert_eq!(legacy, project_rows(&rows));
    }

    #[test]
    fn projection_is_order_independent() {
        let a = project_rows(&[(0, Some(10)), (10, Some(20)), (20, Some(30))]);
        let b = project_rows(&[(20, Some(30)), (0, Some(10)), (10, Some(20))]);
        assert_eq!(a, b, "表里没有 ORDER BY 保证，投影必须自己排序");
    }

    #[test]
    fn open_ended_spans_are_distinguishable_from_closed_ones() {
        // 未知总长必须是开区间；写成 `0..1` 就会和真正的 1 字节段混淆。
        let open = project_rows(&[(0, None)]);
        let one_byte = project_rows(&[(0, Some(1))]);
        assert_ne!(open, one_byte);
        assert_eq!(open, "plan-v1|0..");
        assert_eq!(one_byte, "plan-v1|0..1");
    }

    #[test]
    fn empty_and_zero_total_project_to_the_bare_version() {
        assert_eq!(project_legacy(0, 4), "plan-v1");
        assert_eq!(project_rows(&[]), "plan-v1");
        assert_eq!(span_count("plan-v1"), 0);
    }

    #[test]
    fn single_segment_covers_the_whole_file() {
        // total < MIN_SEGMENT_BYTES 时只能有一段，且必须覆盖到末尾。
        let p = project_legacy(1_000, 8);
        assert_eq!(p, "plan-v1|0..1000");
    }

    #[test]
    fn malformed_rows_are_not_normalized_away() {
        // 坏行（结束 <= 起点）照原样编码：让对照失败，而不是被抹平成"看起来对"。
        let bad = project_rows(&[(100, Some(100))]);
        assert_eq!(bad, "plan-v1|100..100");
    }
}

#[cfg(test)]
mod coverage_validation_tests {
    use super::*;

    #[test]
    fn a_plan_that_exactly_covers_the_file_is_accepted() {
        assert!(covers_exactly(&[(0, Some(100)), (100, Some(200))], 200));
        assert!(covers_exactly(&[(0, Some(200))], 200));
        // 乱序也接受（排序后判断）。
        assert!(covers_exactly(&[(100, Some(200)), (0, Some(100))], 200));
    }

    #[test]
    fn gaps_overlaps_and_misalignment_are_rejected() {
        // 空洞
        assert!(!covers_exactly(&[(0, Some(100)), (150, Some(200))], 200));
        // 重叠
        assert!(!covers_exactly(&[(0, Some(120)), (100, Some(200))], 200));
        // 起点不在 0
        assert!(!covers_exactly(&[(10, Some(200))], 200));
        // 没覆盖到末尾
        assert!(!covers_exactly(&[(0, Some(150))], 200));
        // 超出末尾
        assert!(!covers_exactly(&[(0, Some(300))], 200));
    }

    #[test]
    fn open_ended_or_empty_plans_are_rejected_for_known_totals() {
        // 未知总长的方案不能拿去给已知总长的任务用。
        assert!(!covers_exactly(&[(0, None)], 200));
        assert!(!covers_exactly(&[], 200));
        assert!(!covers_exactly(&[(0, Some(0))], 0));
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    #[test]
    fn same_plan_same_fingerprint_different_plan_different_fingerprint() {
        let a = fingerprint(&[(0, Some(100)), (100, Some(200))]);
        let b = fingerprint(&[(0, Some(100)), (100, Some(200))]);
        let c = fingerprint(&[(0, Some(200))]);
        assert_eq!(a, b);
        assert_ne!(a, c, "方案变了指纹必须变，否则命令会被 by_id 合并掉");
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn fingerprint_ignores_input_order_but_not_content() {
        // 与投影同源：顺序无关，内容有关。
        assert_eq!(
            fingerprint(&[(100, Some(200)), (0, Some(100))]),
            fingerprint(&[(0, Some(100)), (100, Some(200))])
        );
        assert_ne!(
            fingerprint(&[(0, Some(100))]),
            fingerprint(&[(0, Some(101))])
        );
    }

    #[test]
    fn open_ended_and_closed_plans_differ() {
        assert_ne!(fingerprint(&[(0, None)]), fingerprint(&[(0, Some(1))]));
    }
}
