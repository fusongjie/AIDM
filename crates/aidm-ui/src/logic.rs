//! UI 纯逻辑：格式化、限速换算、URL 校验、设置 diff、虚拟列表窗口。
//!
//! 与 `ui/app.js` 对齐，便于无 WebView 单测。本模块不做 IO。

// 本模块是 `ui/app.js` 对应逻辑的 Rust 规格镜像：二进制只消费其中少数入口
// （见 `main.rs` 的模块注释），其余条目只被本文件的 `#[cfg(test)] mod tests`
// 使用。这里显式声明，避免每条规格都报 `never used` 把真正的告警淹掉。
#![allow(dead_code)]

use std::collections::BTreeMap;

/// 设置键 `speed.global_limit_kbps`：1 KB = 1024 字节。界面一律写 KB，不写 KiB。
pub const KIB: u64 = 1024;

/// 限速页帮助文案（与 `ui/index.html` 一致）。
pub const SPEED_LIMIT_HELP: &str = "0 = 不限，单位 KB/s（1 KB = 1024 字节）";

/// `settings_set` 失败时的用户可见文案（原始错误只写日志）。
pub const SETTINGS_SAVE_FAILED: &str = "设置保存失败，请重试";

pub const SUBSCRIBE_STALE_SECS: u64 = 45;

pub const LIST_ROW_HEIGHT: u64 = 36;
pub const LIST_OVERSCAN: usize = 8;
pub const COLUMN_MIN_WIDTH: f64 = 60.0;

/// 文件名 / 大小 / 进度 / 速率 / 完成时间 / 状态
pub const DEFAULT_COLUMN_WIDTHS: [f64; 6] = [220.0, 90.0, 170.0, 90.0, 90.0, 150.0];

/// 限速展示：0 = 「不限」。≥1024 KB/s 用 MB/s。界面单位为 KB（1024 字节）。
pub fn format_limit_kbps(kbps: u64) -> String {
    if kbps == 0 {
        return "不限".into();
    }
    if kbps >= KIB {
        let mb = kbps as f64 / KIB as f64;
        if mb.fract() == 0.0 || mb >= 100.0 {
            format!("{} MB/s", mb.round())
        } else {
            format!("{mb:.1} MB/s")
        }
    } else {
        format!("{kbps} KB/s")
    }
}

/// `stats.speed_limit` / `stats.total_speed` 为 B/s。
pub fn format_limit_bps(bps: u64) -> String {
    format_limit_kbps(bps / KIB)
}

pub fn kbps_to_bps(kbps: u64) -> u64 {
    kbps.saturating_mul(KIB)
}

pub fn bps_to_kbps(bps: u64) -> u64 {
    bps / KIB
}

/// 托盘：空闲只显示应用名，不出现「0 B/s」。
pub fn tray_tooltip(total_speed_bps: u64) -> String {
    if total_speed_bps == 0 {
        "AIDM".into()
    } else {
        format!(
            "AIDM  {}/s",
            crate::task_display::format_bytes_human(total_speed_bps)
        )
    }
}

pub fn should_notify_complete(notify_on_complete: bool) -> bool {
    notify_on_complete
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlValidation {
    Ok,
    Empty,
    Scheme,
}

impl UrlValidation {
    pub fn error_text(self) -> Option<&'static str> {
        match self {
            Self::Ok => None,
            Self::Empty => Some("请输入下载链接"),
            Self::Scheme => Some("仅支持 http:// 或 https://"),
        }
    }
}

/// 新建下载 URL：只允许 http/https（引擎独占 HTTP，UI 只做格式校验）。
pub fn validate_download_url(url: &str) -> UrlValidation {
    let u = url.trim();
    if u.is_empty() {
        return UrlValidation::Empty;
    }
    let lower = u.to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("https://") {
        r
    } else if let Some(r) = lower.strip_prefix("http://") {
        r
    } else {
        return UrlValidation::Scheme;
    };
    if rest.is_empty() || rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('#') {
        return UrlValidation::Scheme;
    }
    UrlValidation::Ok
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassAction {
    /// 未改密码：不发送 `proxy.pass`（引擎保持原值）。
    Omit,
    /// 「清除密码」：发送空串。
    Clear,
    /// 用户输入了新密码。
    Set(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingChange {
    pub key: String,
    pub value: String,
}

fn setting_eq(a: &str, b: &str) -> bool {
    a.trim() == b.trim()
}

/// 计算需要 `settings_set` 的键。永不发送 `proxy.has_password`。
/// `proxy.pass` 仅在 Clear / Set 时出现。
pub fn settings_diff(
    original: &BTreeMap<String, String>,
    edited: &BTreeMap<String, String>,
    pass: &PassAction,
) -> Vec<SettingChange> {
    let mut out = Vec::new();
    let mut keys: Vec<&String> = edited.keys().collect();
    keys.sort();
    for key in keys {
        if key == "proxy.pass" || key == "proxy.has_password" {
            continue;
        }
        let new_v = edited[key].trim();
        let old_v = original.get(key).map(|s| s.as_str()).unwrap_or("");
        if !setting_eq(old_v, new_v) {
            out.push(SettingChange {
                key: key.clone(),
                value: new_v.to_string(),
            });
        }
    }
    match pass {
        PassAction::Omit => {}
        PassAction::Clear => out.push(SettingChange {
            key: "proxy.pass".into(),
            value: String::new(),
        }),
        PassAction::Set(v) => out.push(SettingChange {
            key: "proxy.pass".into(),
            value: v.clone(),
        }),
    }
    out
}

pub fn parse_setting_bool(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::String(s) => s.trim() == "true",
        _ => false,
    }
}

/// 虚拟列表可见区间（含 overscan）。`end` 为开区间。
pub fn visible_range(
    scroll_top: u64,
    viewport_h: u64,
    total: usize,
    row_h: u64,
    overscan: usize,
) -> (usize, usize) {
    if total == 0 || row_h == 0 {
        return (0, 0);
    }
    let first = ((scroll_top / row_h) as usize).min(total.saturating_sub(1));
    let visible = (viewport_h / row_h) as usize + 1;
    let start = first.saturating_sub(overscan);
    let end = first
        .saturating_add(visible)
        .saturating_add(overscan)
        .min(total);
    (start, end)
}

pub fn normalize_column_widths(stored: &[f64], defaults: &[f64], min: f64) -> Vec<f64> {
    if stored.len() != defaults.len() {
        return defaults.to_vec();
    }
    stored
        .iter()
        .map(|&w| if w.is_finite() { w.max(min) } else { min })
        .collect()
}

/// `settings_set` 失败：未知码仍用 [`SETTINGS_SAVE_FAILED`]；可读校验见 [`crate::sched::settings_set_user_error`]。
pub fn settings_set_user_error(code: &str) -> String {
    crate::sched::settings_set_user_error("", code, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_kbps_zero_is_unlimited() {
        assert_eq!(format_limit_kbps(0), "不限");
    }

    #[test]
    fn limit_kbps_units() {
        assert_eq!(format_limit_kbps(1), "1 KB/s");
        assert_eq!(format_limit_kbps(512), "512 KB/s");
        assert_eq!(format_limit_kbps(1024), "1 MB/s");
        assert_eq!(format_limit_kbps(1536), "1.5 MB/s");
        assert_eq!(format_limit_kbps(2048), "2 MB/s");
    }

    #[test]
    fn kib_conversion() {
        assert_eq!(kbps_to_bps(128), 128 * 1024);
        assert_eq!(bps_to_kbps(128 * 1024), 128);
        assert_eq!(format_limit_bps(0), "不限");
        assert_eq!(format_limit_bps(512 * 1024), "512 KB/s");
        assert_eq!(format_limit_bps(1024 * 1024), "1 MB/s");
    }

    #[test]
    fn tray_hides_zero_speed() {
        assert_eq!(tray_tooltip(0), "AIDM");
        assert!(tray_tooltip(1500).contains("AIDM  "));
        assert!(!tray_tooltip(1500).contains("0 B/s"));
        assert!(!tray_tooltip(0).contains("0 B/s"));
    }

    #[test]
    fn url_http_https_only() {
        assert_eq!(
            validate_download_url("https://example.com/a.zip"),
            UrlValidation::Ok
        );
        assert_eq!(
            validate_download_url("HTTP://example.com/a.zip"),
            UrlValidation::Ok
        );
        assert_eq!(validate_download_url(""), UrlValidation::Empty);
        assert_eq!(validate_download_url("   "), UrlValidation::Empty);
        assert_eq!(
            validate_download_url("ftp://example.com/a"),
            UrlValidation::Scheme
        );
        assert_eq!(
            validate_download_url("file:///tmp/a"),
            UrlValidation::Scheme
        );
        assert_eq!(
            validate_download_url("javascript:alert(1)"),
            UrlValidation::Scheme
        );
        assert_eq!(validate_download_url("https://"), UrlValidation::Scheme);
        assert_eq!(
            validate_download_url("https:///no-host"),
            UrlValidation::Scheme
        );
        assert_eq!(
            validate_download_url("https://example.com/a.zip").error_text(),
            None
        );
        assert_eq!(
            validate_download_url("").error_text(),
            Some("请输入下载链接")
        );
    }

    fn map_from(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn settings_diff_omits_unchanged_and_password() {
        let orig = map_from(&[
            ("speed.global_limit_kbps", "0"),
            ("proxy.mode", "follow-system"),
            ("proxy.has_password", "true"),
        ]);
        let edited = map_from(&[
            ("speed.global_limit_kbps", "128"),
            ("proxy.mode", "follow-system"),
            ("proxy.has_password", "true"),
            ("proxy.pass", "should-not-matter"),
        ]);
        let diff = settings_diff(&orig, &edited, &PassAction::Omit);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].key, "speed.global_limit_kbps");
        assert_eq!(diff[0].value, "128");
        assert!(diff.iter().all(|c| c.key != "proxy.pass"));
        assert!(diff.iter().all(|c| c.key != "proxy.has_password"));
    }

    #[test]
    fn settings_diff_clear_and_set_password() {
        let orig = map_from(&[("proxy.mode", "manual")]);
        let edited = map_from(&[("proxy.mode", "manual")]);
        let clear = settings_diff(&orig, &edited, &PassAction::Clear);
        assert_eq!(
            clear,
            vec![SettingChange {
                key: "proxy.pass".into(),
                value: String::new()
            }]
        );
        let set = settings_diff(&orig, &edited, &PassAction::Set("secret".into()));
        assert_eq!(
            set,
            vec![SettingChange {
                key: "proxy.pass".into(),
                value: "secret".into()
            }]
        );
    }

    #[test]
    fn settings_diff_trims_and_skips_equal() {
        let orig = map_from(&[("proxy.host", "corp.example")]);
        let edited = map_from(&[("proxy.host", "  corp.example  ")]);
        assert!(settings_diff(&orig, &edited, &PassAction::Omit).is_empty());
    }

    #[test]
    fn settings_diff_omits_metadata_dir_when_not_edited() {
        let orig = map_from(&[
            ("paths.metadata_dir", "$HOME/.local/share/aidm"),
            ("paths.default_dir", "$HOME/Downloads"),
        ]);
        let edited = map_from(&[("paths.default_dir", "$HOME/Downloads")]);
        let diff = settings_diff(&orig, &edited, &PassAction::Omit);
        assert!(diff.is_empty());
        assert!(diff.iter().all(|c| c.key != "paths.metadata_dir"));
    }

    #[test]
    fn visible_range_handles_10k() {
        let (s, e) = visible_range(0, 360, 10_000, LIST_ROW_HEIGHT, LIST_OVERSCAN);
        assert_eq!(s, 0);
        assert!(e <= 30, "window too large: {e}");
        assert!(e >= 10);

        let (s, e) = visible_range(3600, 360, 10_000, LIST_ROW_HEIGHT, LIST_OVERSCAN);
        assert_eq!(s, 100 - LIST_OVERSCAN);
        assert_eq!(e, 100 + 10 + 1 + LIST_OVERSCAN);
        assert!((e - s) < 40);

        assert_eq!(
            visible_range(0, 360, 0, LIST_ROW_HEIGHT, LIST_OVERSCAN),
            (0, 0)
        );
        let (s, e) = visible_range(u64::from(u32::MAX), 360, 5, LIST_ROW_HEIGHT, LIST_OVERSCAN);
        assert_eq!((s, e), (0, 5));
    }

    #[test]
    fn column_widths_reject_wrong_len_and_clamp() {
        assert_eq!(
            normalize_column_widths(&[1.0], &DEFAULT_COLUMN_WIDTHS, COLUMN_MIN_WIDTH),
            DEFAULT_COLUMN_WIDTHS.to_vec()
        );
        let stored = [10.0, 90.0, 170.0, 90.0, 90.0, 150.0];
        let out = normalize_column_widths(&stored, &DEFAULT_COLUMN_WIDTHS, COLUMN_MIN_WIDTH);
        assert_eq!(out[0], COLUMN_MIN_WIDTH);
        assert_eq!(out[1], 90.0);
    }

    #[test]
    fn parse_bool_from_json() {
        assert!(parse_setting_bool(&serde_json::Value::Bool(true)));
        assert!(parse_setting_bool(&serde_json::json!("true")));
        assert!(!parse_setting_bool(&serde_json::json!("false")));
        assert!(!parse_setting_bool(&serde_json::Value::Null));
    }

    #[test]
    fn notify_flag() {
        assert!(should_notify_complete(true));
        assert!(!should_notify_complete(false));
    }

    #[test]
    fn settings_set_hides_developer_codes() {
        for code in [
            "bool_invalid",
            "unknown_setting_key",
            "setting_readonly",
            "speed_limit_invalid",
            "custom_code",
        ] {
            assert_eq!(settings_set_user_error(code), SETTINGS_SAVE_FAILED);
            assert_ne!(settings_set_user_error(code), "取值必须是 true 或 false");
            assert_ne!(settings_set_user_error(code), "未知设置项");
            assert_ne!(settings_set_user_error(code), "该项只读");
        }
    }

    #[test]
    fn speed_limit_help_uses_kb_not_kib() {
        assert_eq!(SPEED_LIMIT_HELP, "0 = 不限，单位 KB/s（1 KB = 1024 字节）");
        assert!(!SPEED_LIMIT_HELP.contains("KiB"));
        assert!(SPEED_LIMIT_HELP.contains("KB/s"));
    }
}
