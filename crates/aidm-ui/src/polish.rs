//! 列表 / 属性面板 polish 纯逻辑（与 `ui/lib/polish.js` 对齐）。本模块不做 IO。

use crate::logic::{format_limit_kbps, KIB};

pub const FINISH_TIME_HEADER: &str = "完成时间";
pub const RENAME_EMPTY: &str = "文件名不能为空";
pub const RENAME_INVALID: &str = "文件名无效，请重新输入";
pub const RENAME_TAKEN: &str = "已存在同名文件，请换一个名字";
pub const RENAME_MISSING: &str = "任务不存在或已删除";
pub const RENAME_FAIL: &str = "重命名失败，请重试";
pub const RENAME_UNAVAILABLE: &str = "当前无法重命名";
pub const DASH: &str = "—";

/// 工具条限速按钮：0 / 未设置 →「不限速」；否则「限速 500 KB/s」。
pub fn format_speed_limit_button(kbps: Option<u64>) -> String {
    match kbps {
        None | Some(0) => "不限速".into(),
        Some(n) => format!("限速 {}", format_limit_kbps(n)),
    }
}

pub fn format_speed_limit_button_bps(bps: Option<u64>) -> String {
    format_speed_limit_button(bps.map(|b| b / KIB))
}

pub fn format_remaining_seconds(secs: u64) -> String {
    if secs < 60 {
        format!("{secs} 秒")
    } else if secs < 3600 {
        format!("{} 分钟", secs.div_ceil(60))
    } else {
        format!("{:.1} 小时", secs as f64 / 3600.0)
    }
}

/// 时长格式：`HH:MM:SS`（小时不封顶，例如 `26:05:03`）。
pub fn format_duration_seconds(secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// 列表「完成时间」单元格：下载中 → 剩余；已完成 → 用时；其它 →「—」。
pub fn format_finish_cell(
    state: &str,
    remaining_secs: Option<u64>,
    duration_secs: Option<u64>,
) -> String {
    match state {
        "downloading" => remaining_secs
            .map(format_remaining_seconds)
            .unwrap_or_else(|| DASH.into()),
        "done" => duration_secs
            .map(format_duration_seconds)
            .unwrap_or_else(|| DASH.into()),
        _ => DASH.into(),
    }
}

/// 属性面板「完成时间」：下载中带「约」，已完成带「用时」。
pub fn format_finish_props(
    state: &str,
    remaining_secs: Option<u64>,
    duration_secs: Option<u64>,
) -> String {
    match state {
        "downloading" => remaining_secs
            .map(|s| format!("约 {}", format_remaining_seconds(s)))
            .unwrap_or_else(|| DASH.into()),
        "done" => duration_secs
            .map(|s| format!("用时 {}", format_duration_seconds(s)))
            .unwrap_or_else(|| DASH.into()),
        _ => DASH.into(),
    }
}

pub fn remaining_seconds(state: &str, done: u64, total: Option<u64>, speed: u64) -> Option<u64> {
    if state != "downloading" || speed == 0 {
        return None;
    }
    let total = total.filter(|t| *t > 0)?;
    let remain = total.saturating_sub(done);
    if remain == 0 {
        return None;
    }
    Some(remain.div_ceil(speed))
}

pub fn file_basename(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

/// 新建下载对话框：兜底名（JS 侧同值）。
pub const FILENAME_FALLBACK: &str = "download.bin";

/// 从 URL 路径解析文件名。空串表示「解析不出」（host 后没有路径 / 结尾是目录 / 空片段）。
///
/// 直接复用 `aidm-core` 的同一套规则（引擎落盘也走它）并限长 255，
/// 保证对话框预览和最终文件名一致。
pub fn filename_from_url(url: &str) -> String {
    if url.trim().is_empty() {
        return String::new();
    }
    let Some(name) = aidm_core::filename::filename_from_url(url) else {
        return String::new();
    };
    if name.chars().count() > 255 {
        return name.chars().take(255).collect();
    }
    name
}

/// 对话框自动填名：`None` = 用户手动改过，保持不动；`Some("")` = 清空。
pub fn auto_filename_for(current: &str, last_auto: &str, url: &str) -> Option<String> {
    if !current.is_empty() && current != last_auto {
        return None;
    }
    Some(filename_from_url(url))
}

pub fn file_extension(name: &str) -> String {
    let base = file_basename(name);
    match base.rfind('.') {
        Some(i) if i > 0 && i + 1 < base.len() => base[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

pub fn extension_changed(original: &str, next: &str) -> bool {
    file_extension(original) != file_extension(next)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenameCommit {
    Empty,
    Noop,
    Confirm,
    Rename,
}

pub fn rename_commit_decision(original: &str, typed: &str) -> RenameCommit {
    let name = typed.trim();
    if name.is_empty() {
        return RenameCommit::Empty;
    }
    if name == original {
        return RenameCommit::Noop;
    }
    if extension_changed(original, name) {
        return RenameCommit::Confirm;
    }
    RenameCommit::Rename
}

/// 对齐 aidm-ipc：`invalid_filename` / `name_taken` 在 `code`；
/// `task_not_found` 现有引擎走 `error`（`EngineResponse::err`），也认 `code`。
pub fn rename_error_text(code: &str) -> &'static str {
    match code {
        aidm_ipc::ERR_INVALID_FILENAME => RENAME_INVALID,
        aidm_ipc::ERR_NAME_TAKEN => RENAME_TAKEN,
        "task_not_found" => RENAME_MISSING,
        _ => RENAME_FAIL,
    }
}

pub fn rename_error_from_resp(code: Option<&str>, error: Option<&str>) -> &'static str {
    let raw = code
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| error.map(str::trim).filter(|s| !s.is_empty()))
        .unwrap_or("");
    rename_error_text(raw)
}

pub fn can_rename_task(task_present: bool, engine_offline: bool) -> bool {
    task_present && !engine_offline
}

pub fn source_field_text(source: Option<&str>) -> &'static str {
    match source {
        Some("ext") => "浏览器",
        Some("manual") => "手动",
        _ => DASH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speed_limit_button_unlimited_when_zero_or_unset() {
        assert_eq!(format_speed_limit_button(None), "不限速");
        assert_eq!(format_speed_limit_button(Some(0)), "不限速");
        assert_eq!(format_speed_limit_button_bps(None), "不限速");
        assert_eq!(format_speed_limit_button_bps(Some(0)), "不限速");
    }

    #[test]
    fn speed_limit_button_shows_value() {
        assert_eq!(format_speed_limit_button(Some(500)), "限速 500 KB/s");
        assert_eq!(format_speed_limit_button(Some(1024)), "限速 1 MB/s");
        assert_eq!(
            format_speed_limit_button_bps(Some(500 * 1024)),
            "限速 500 KB/s"
        );
    }

    #[test]
    fn finish_header_is_stable() {
        assert_eq!(FINISH_TIME_HEADER, "完成时间");
        assert_ne!(FINISH_TIME_HEADER, "剩余时间");
    }

    #[test]
    fn finish_cell_remaining_duration_or_dash() {
        assert_eq!(format_finish_cell("downloading", Some(180), None), "3 分钟");
        assert_eq!(format_finish_cell("downloading", Some(12), None), "12 秒");
        assert_eq!(
            format_finish_cell("done", None, Some(12 * 60 + 30)),
            "00:12:30"
        );
        assert_eq!(format_finish_cell("done", None, None), DASH);
        assert_eq!(format_finish_cell("queued", Some(10), Some(10)), DASH);
        assert_eq!(format_finish_cell("paused", Some(10), Some(10)), DASH);
        assert_eq!(format_finish_cell("error", Some(10), Some(10)), DASH);
    }

    #[test]
    fn finish_props_prefixes() {
        assert_eq!(
            format_finish_props("downloading", Some(180), None),
            "约 3 分钟"
        );
        assert_eq!(
            format_finish_props("done", None, Some(12 * 60 + 30)),
            "用时 00:12:30"
        );
        assert_eq!(format_finish_props("queued", Some(9), Some(9)), DASH);
    }

    #[test]
    fn remaining_from_progress() {
        assert_eq!(remaining_seconds("downloading", 50, Some(150), 50), Some(2));
        assert_eq!(remaining_seconds("paused", 50, Some(150), 50), None);
        assert_eq!(remaining_seconds("downloading", 50, None, 50), None);
        assert_eq!(remaining_seconds("downloading", 50, Some(150), 0), None);
    }

    #[test]
    fn extension_change_detects_type_not_case_or_stem() {
        assert!(!extension_changed("a.ZIP", "b.zip"));
        assert!(!extension_changed("movie.mkv", "movie-final.mkv"));
        assert!(extension_changed("a.zip", "a.txt"));
        assert!(extension_changed("a.zip", "a"));
        assert!(extension_changed("a", "a.zip"));
        assert!(!extension_changed("a", "b"));
        assert_eq!(file_extension("dir/name.Tar.Gz"), "gz");
    }

    #[test]
    fn rename_empty_name_does_not_save() {
        assert_eq!(rename_commit_decision("a.bin", ""), RenameCommit::Empty);
        assert_eq!(rename_commit_decision("a.bin", "   "), RenameCommit::Empty);
        assert_eq!(RENAME_EMPTY, "文件名不能为空");
    }

    #[test]
    fn rename_confirm_only_when_extension_changes() {
        assert_eq!(
            rename_commit_decision("file.zip", "file.zip"),
            RenameCommit::Noop
        );
        assert_eq!(
            rename_commit_decision("file.zip", "other.zip"),
            RenameCommit::Rename
        );
        assert_eq!(
            rename_commit_decision("file.ZIP", "file.zip"),
            RenameCommit::Rename
        );
        assert_eq!(
            rename_commit_decision("file.zip", "file.txt"),
            RenameCommit::Confirm
        );
        assert_eq!(
            rename_commit_decision("file.zip", "file"),
            RenameCommit::Confirm
        );
    }

    #[test]
    fn rename_error_codes() {
        assert_eq!(
            rename_error_text(aidm_ipc::ERR_INVALID_FILENAME),
            RENAME_INVALID
        );
        assert_eq!(rename_error_text(aidm_ipc::ERR_NAME_TAKEN), RENAME_TAKEN);
        assert_eq!(rename_error_text("task_not_found"), RENAME_MISSING);
        assert_eq!(rename_error_text("busy"), RENAME_FAIL);
        assert_eq!(rename_error_text(""), RENAME_FAIL);
        assert_eq!(
            rename_error_from_resp(Some(aidm_ipc::ERR_INVALID_FILENAME), Some("ignored")),
            RENAME_INVALID
        );
        assert_eq!(
            rename_error_from_resp(None, Some("task_not_found")),
            RENAME_MISSING
        );
        assert_eq!(
            rename_error_from_resp(None, Some("rename: io")),
            RENAME_FAIL
        );
    }

    #[test]
    fn consumes_aidm_ipc_rename_request() {
        let req: aidm_ipc::EngineRequest =
            serde_json::from_str(r#"{"op":"rename","id":3,"filename":"new.bin"}"#).unwrap();
        assert_eq!(
            req,
            aidm_ipc::EngineRequest::Rename {
                id: 3,
                filename: "new.bin".into()
            }
        );
    }

    #[test]
    fn rename_unavailable_when_offline_or_missing() {
        assert!(can_rename_task(true, false));
        assert!(!can_rename_task(true, true));
        assert!(!can_rename_task(false, false));
        assert_eq!(RENAME_UNAVAILABLE, "当前无法重命名");
    }

    #[test]
    fn source_labels() {
        assert_eq!(source_field_text(Some("ext")), "浏览器");
        assert_eq!(source_field_text(Some("manual")), "手动");
        assert_eq!(source_field_text(None), DASH);
    }

    #[test]
    fn new_download_filename_from_url() {
        assert_eq!(
            filename_from_url("https://cdn.example/a/pkg-1.2.zip?x=1"),
            "pkg-1.2.zip"
        );
        assert_eq!(
            filename_from_url("https://cdn.example/a/pkg-1.2.zip#frag"),
            "pkg-1.2.zip"
        );
        assert_eq!(
            filename_from_url("https://cdn.example/%E4%B8%AD.bin"),
            "中.bin"
        );
        assert_eq!(
            filename_from_url("https://cdn.example/a/na%20me.tar.gz"),
            "na me.tar.gz"
        );
        // 解析不出：留给引擎按 Content-Disposition 决定
        assert_eq!(filename_from_url("https://cdn.example/"), "");
        assert_eq!(filename_from_url("https://cdn.example"), "");
        assert_eq!(filename_from_url(""), "");
        assert_eq!(filename_from_url("   "), "");
        let long = format!("https://x/{}", "a".repeat(300));
        assert_eq!(filename_from_url(&long).chars().count(), 255);
        assert_eq!(FILENAME_FALLBACK, "download.bin");
    }

    #[test]
    fn new_download_auto_filename_rules() {
        // 空输入框 → 解析并填入
        assert_eq!(
            auto_filename_for("", "", "https://x/a.zip"),
            Some("a.zip".into())
        );
        // 现值等于上次自动填入值 → 跟随新链接
        assert_eq!(
            auto_filename_for("a.zip", "a.zip", "https://x/b.zip"),
            Some("b.zip".into())
        );
        // 用户手动改过 → 不动
        assert_eq!(
            auto_filename_for("mine.zip", "a.zip", "https://x/b.zip"),
            None
        );
        // 清空文件名 → 恢复自动解析
        assert_eq!(
            auto_filename_for("", "a.zip", "https://x/b.zip"),
            Some("b.zip".into())
        );
        // 链接清空 → 文件名一起清空
        assert_eq!(auto_filename_for("a.zip", "a.zip", ""), Some(String::new()));
    }
}
