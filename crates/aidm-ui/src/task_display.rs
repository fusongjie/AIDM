//! 属性面板展示辅助（与 `ui/app.js` 对齐，无 WebView 可测）。

// 本模块是 `ui/app.js` 对应逻辑的 Rust 规格镜像：二进制只消费其中少数入口
// （见 `main.rs` 的模块注释），其余条目只被本文件的 `#[cfg(test)] mod tests`
// 使用。这里显式声明，避免每条规格都报 `never used` 把真正的告警淹掉。
#![allow(dead_code)]

use aidm_ipc::SegmentView;

/// IPC `idx` 为 0 起；界面展示为 1 起。
pub fn segment_display_number(idx: u32) -> u32 {
    idx + 1
}

/// 与 `ui/app.js` 的 `fmtBytes` 一致（不含「—」占位）。
pub fn format_bytes_human(n: u64) -> String {
    if n < 1024 {
        return format!("{n} B");
    }
    const UNITS: &[&str] = &["KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut unit_idx = 0usize;
    while v >= 1024.0 && unit_idx < UNITS.len() {
        v /= 1024.0;
        unit_idx += 1;
    }
    let unit = UNITS[unit_idx - 1];
    let num = if v >= 100.0 {
        format!("{:.0}", v)
    } else {
        format!("{:.1}", v)
    };
    format!("{num} {unit}")
}

/// 与 `ui/app.js` 的 `fmtByteRange` 一致。
pub fn format_byte_range(pos_start: u64, pos_end: Option<u64>) -> String {
    match pos_end {
        Some(end) => format!(
            "{} – {}",
            format_bytes_human(pos_start),
            format_bytes_human(end)
        ),
        None => format!("{} – 未知", format_bytes_human(pos_start)),
    }
}

pub fn segment_progress_percent(seg: &SegmentView) -> Option<f64> {
    let end = seg.pos_end?;
    let span = end.saturating_sub(seg.pos_start) + 1;
    if span == 0 {
        return None;
    }
    Some(((seg.done_bytes as f64 / span as f64) * 100.0).min(100.0))
}

/// 状态栏「连接数」：各任务 `segments` 中 `status == running` 的条数之和。
pub fn active_connection_count(segment_statuses_per_task: &[&[&str]]) -> u32 {
    segment_statuses_per_task
        .iter()
        .flat_map(|statuses| statuses.iter())
        .filter(|s| **s == "running")
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_number_is_one_based() {
        assert_eq!(segment_display_number(0), 1);
        assert_eq!(segment_display_number(7), 8);
    }

    #[test]
    fn human_byte_range() {
        assert_eq!(format_byte_range(0, None), "0 B – 未知");
        assert_eq!(format_byte_range(0, Some(13_107_199)), "0 B – 12.5 MB");
    }

    #[test]
    fn half_done_segment() {
        let seg = SegmentView {
            idx: 1,
            pos_start: 1000,
            pos_end: Some(1999),
            done_bytes: 500,
            status: "running".into(),
            retries: None,
        };
        let pct = segment_progress_percent(&seg).unwrap();
        assert!((pct - 50.0).abs() < 0.01);
    }

    #[test]
    fn open_ended_segment_has_no_percent() {
        let seg = SegmentView {
            idx: 0,
            pos_start: 0,
            pos_end: None,
            done_bytes: 100,
            status: "running".into(),
            retries: None,
        };
        assert!(segment_progress_percent(&seg).is_none());
    }

    #[test]
    fn active_connections_counts_running_segments_only() {
        let tasks = [
            &["done", "running", "running"][..],
            &["pending", "running"][..],
            &["done"][..],
        ];
        assert_eq!(active_connection_count(&tasks), 3);
    }
}
