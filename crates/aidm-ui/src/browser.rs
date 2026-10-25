//! 浏览器集成纯逻辑：文件名推导、候选过滤/选择、过期文案、扩展降级决策。
//!
//! 与 `ui/app.js` / `extension/lib/logic.js` 对齐，无 IO。

use std::collections::BTreeSet;

use aidm_core::settings;
use aidm_ipc::{
    AIDM_EXT_ID, LIMIT_COOKIES, LIMIT_FILENAME, LIMIT_OFFER_ITEMS, LIMIT_REFERRER, LIMIT_URL,
};

pub const OFFER_EXPIRED_TEXT: &str = "候选已过期，请在页面上重新收集";
pub const UI_NOT_RUNNING_TEXT: &str = "请先打开 AIDM";
pub const INTEGRATION_DISABLED_TEXT: &str = "浏览器集成已在 AIDM 中关闭，已改用浏览器下载";
pub const OFFER_DISABLED_TEXT: &str = "浏览器集成已在 AIDM 中关闭";
pub const OFFER_FAIL_TEXT: &str = "无法交给 AIDM，请稍后重试";
pub const FALLBACK_TEXT: &str = "无法交给 AIDM，已改用浏览器下载";
pub const TOO_LONG_TEXT: &str = "链接过长，已改用浏览器下载";
pub const UNCERTAIN_TEXT: &str = "无法确认是否已交给 AIDM，请在 AIDM 列表中查看";
pub const STATUS_DISCONNECT_TEXT: &str = "未连接到 AIDM，请先打开 AIDM";
pub const STATUS_ENGINE_OFF_TEXT: &str = "AIDM 引擎未运行";

pub const HOST_STATUS_FAIL: &str = "无法检测浏览器连接状态，请重试";
pub const HOST_COMPONENT_LABEL: &str = "浏览器连接组件";
pub const LAST_EXT_CONFIRM: &str = "这是最后一个允许的扩展，确定删除？";
pub const TRUNCATED_BANNER: &str = "只显示前 500 项";
pub const CAND_NONE: &str = "页面上没有发现可下载的链接";
pub const CAND_NO_MATCH: &str = "没有匹配的链接";
pub const CAND_ALL_FAIL: &str = "添加失败，请重试";
pub const REGISTER_HKCU_NOTE: &str = "只写入当前用户的注册表";
pub const CLICK_TAKEOVER_NOTE: &str = "后续版本提供";
pub const WHITELIST_HEADING: &str = "允许的扩展 ID（默认包含 AIDM 扩展）";

const FALLBACK_CODES: &[&str] = &[
    "unsupported_scheme",
    "not_allowed",
    "bad_url",
    "disabled",
    "engine_unreachable",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Link,
    Video,
    Audio,
}

impl ItemKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "link" => Some(Self::Link),
            "video" => Some(Self::Video),
            "audio" => Some(Self::Audio),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Video => "video",
            Self::Audio => "audio",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Link => "链接",
            Self::Video => "视频",
            Self::Audio => "音频",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRow {
    pub url: String,
    pub kind: ItemKind,
    pub filename: String,
}

/// 缺文件名时从 URL 路径推导；失败则 `download.bin`。最长 255。
pub fn derive_filename(explicit: Option<&str>, url: &str) -> String {
    if let Some(name) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return clip_filename(basename(name));
    }
    if let Some(name) = filename_from_url(url) {
        return clip_filename(name);
    }
    "download.bin".into()
}

fn basename(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim()
        .to_string()
}

fn filename_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let path = after_scheme.split_once('/')?.1;
    let path = path.split(['?', '#']).next()?.trim_end_matches('/');
    let name = path.rsplit(['/', '\\']).next()?;
    let name = percent_decode(name);
    if name.is_empty() || name == "." || name == ".." {
        None
    } else {
        Some(name)
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(&h), Some(&l)) = (bytes.get(i + 1), bytes.get(i + 2)) {
                if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&[h, l]).unwrap_or("zz"), 16)
                {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn clip_filename(name: String) -> String {
    if name.chars().count() <= LIMIT_FILENAME {
        name
    } else {
        name.chars().take(LIMIT_FILENAME).collect()
    }
}

/// 列表展示用截断 URL（末尾省略）。
pub fn truncate_url(url: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = url.chars().count();
    if count <= max_chars {
        return url.to_string();
    }
    if max_chars <= 1 {
        return "…".into();
    }
    let keep = max_chars - 1;
    let mut s: String = url.chars().take(keep).collect();
    s.push('…');
    s
}

pub fn row_matches(row: &CandidateRow, kind_filter: Option<ItemKind>, query: &str) -> bool {
    if let Some(k) = kind_filter {
        if row.kind != k {
            return false;
        }
    }
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return true;
    }
    row.filename.to_ascii_lowercase().contains(&q) || row.url.to_ascii_lowercase().contains(&q)
}

pub fn filter_rows<'a>(
    rows: &'a [CandidateRow],
    kind_filter: Option<ItemKind>,
    query: &str,
) -> Vec<&'a CandidateRow> {
    rows.iter()
        .filter(|r| row_matches(r, kind_filter, query))
        .collect()
}

/// 全选可见行（不可见行保持原选中状态）。
pub fn select_visible(selected: &BTreeSet<usize>, visible: &[usize]) -> BTreeSet<usize> {
    let mut out = selected.clone();
    for i in visible {
        out.insert(*i);
    }
    out
}

/// 反选可见行。
pub fn invert_visible(selected: &BTreeSet<usize>, visible: &[usize]) -> BTreeSet<usize> {
    let mut out = selected.clone();
    for i in visible {
        if !out.insert(*i) {
            out.remove(i);
        }
    }
    out
}

pub fn download_selected_label(n: usize) -> String {
    format!("下载选中的 {n} 项")
}

pub fn candidate_add_result(added: u64, failed: u64) -> Option<String> {
    if added == 0 && failed == 0 {
        return None;
    }
    if added == 0 {
        return Some(CAND_ALL_FAIL.into());
    }
    if failed == 0 {
        return None;
    }
    Some(format!("已添加 {added} 项，{failed} 项添加失败"))
}

pub fn candidate_dialog_title(page_title: &str, n: usize) -> String {
    let title = page_title.trim();
    let title = if title.is_empty() {
        "未命名页面"
    } else {
        title
    };
    format!("从 {title} 发现 {n} 个链接")
}

pub fn source_label(source: Option<&str>) -> &'static str {
    match source {
        Some("ext") => "浏览器扩展",
        _ => "手动添加",
    }
}

pub fn is_ext_source(source: Option<&str>) -> bool {
    source == Some("ext")
}

/// 引擎 / 宿主返回的错误码 → 用户文案（下载提交 / add）。
pub fn host_user_message(code: &str) -> &'static str {
    match code.trim() {
        "ui_not_running" => UI_NOT_RUNNING_TEXT,
        "disabled" => INTEGRATION_DISABLED_TEXT,
        "too_long" => TOO_LONG_TEXT,
        "offer_expired" => OFFER_EXPIRED_TEXT,
        c if FALLBACK_CODES.contains(&c) => FALLBACK_TEXT,
        _ => UNCERTAIN_TEXT,
    }
}

/// 收集页面链接（offer）：不得出现「已改用浏览器下载」。
pub fn offer_user_message(code: &str) -> &'static str {
    match code.trim() {
        "ui_not_running" => UI_NOT_RUNNING_TEXT,
        "disabled" => OFFER_DISABLED_TEXT,
        "offer_expired" => OFFER_EXPIRED_TEXT,
        _ => OFFER_FAIL_TEXT,
    }
}

pub fn status_user_message(disconnected: bool, engine_online: bool) -> &'static str {
    if disconnected {
        STATUS_DISCONNECT_TEXT
    } else if !engine_online {
        STATUS_ENGINE_OFF_TEXT
    } else {
        ""
    }
}

/// 原生消息结果。降级浏览器下载的决策只看这个枚举，不看「可能已接受」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeOutcome {
    /// `{ok:true}`，或已收到成功形状。
    Accepted,
    /// 宿主明确 `{ok:false, code}`。
    ExplicitFailure { code: String },
    /// 宿主未安装，或在任何响应之前断开。
    DisconnectedBeforeResponse,
    /// 超时 / 空响应 / 形状不明：可能已被接受，禁止降级以免双下。
    Unknown,
}

/// 仅在明确失败码白名单时降级。断开 / 无响应 / 未知码不降级。
pub fn should_fallback_to_browser(outcome: &NativeOutcome) -> bool {
    match outcome {
        NativeOutcome::ExplicitFailure { code } => FALLBACK_CODES.contains(&code.as_str()),
        NativeOutcome::Accepted
        | NativeOutcome::Unknown
        | NativeOutcome::DisconnectedBeforeResponse => false,
    }
}

pub fn outcome_user_message(outcome: &NativeOutcome) -> &'static str {
    match outcome {
        NativeOutcome::Accepted => "",
        NativeOutcome::ExplicitFailure { code } => host_user_message(code),
        NativeOutcome::DisconnectedBeforeResponse | NativeOutcome::Unknown => UNCERTAIN_TEXT,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRegState {
    Registered,
    Unregistered,
    Unavailable,
}

pub fn host_reg_state(ok: bool, registered: Option<bool>, error: Option<&str>) -> HostRegState {
    if ok {
        return match registered {
            Some(true) => HostRegState::Registered,
            Some(false) => HostRegState::Unregistered,
            None => HostRegState::Unavailable,
        };
    }
    let _ = error;
    HostRegState::Unavailable
}

fn engine_default_ext_ids_json() -> &'static str {
    settings::default_of("browser.allowed_ext_ids").unwrap_or("[]")
}

/// 引擎 `browser.allowed_ext_ids` 默认值（#12 起即 `AIDM_EXT_ID`）。
pub fn engine_default_ext_ids() -> Vec<String> {
    settings::parse_allowed_ext_ids(engine_default_ext_ids_json())
        .unwrap_or_else(|_| vec![AIDM_EXT_ID.to_string()])
}

pub fn parse_ext_id_list(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return engine_default_ext_ids();
    }
    match settings::parse_allowed_ext_ids(trimmed) {
        Ok(list) => list,
        Err(_) => engine_default_ext_ids(),
    }
}

pub fn encode_ext_id_list(ids: &[String]) -> String {
    serde_json::to_string(ids).unwrap_or_else(|_| engine_default_ext_ids_json().to_string())
}

/// 删除前：若是最后一项则需要确认。
pub fn removing_last_ext_id(current: &[String], removing: &str) -> bool {
    current.len() == 1 && current[0] == removing
}

pub fn truncate_offer_items<T: Clone>(items: &[T]) -> (Vec<T>, bool) {
    if items.len() <= LIMIT_OFFER_ITEMS {
        (items.to_vec(), false)
    } else {
        (items[..LIMIT_OFFER_ITEMS].to_vec(), true)
    }
}

pub fn add_field_too_long(
    url: &str,
    referrer: Option<&str>,
    cookies: Option<&str>,
    filename: Option<&str>,
) -> bool {
    if url.len() > LIMIT_URL {
        return true;
    }
    if referrer.map(|s| s.len() > LIMIT_REFERRER).unwrap_or(false) {
        return true;
    }
    if cookies.map(|s| s.len() > LIMIT_COOKIES).unwrap_or(false) {
        return true;
    }
    if filename
        .map(|s| s.chars().count() > LIMIT_FILENAME)
        .unwrap_or(false)
    {
        return true;
    }
    false
}

pub fn default_extension_id() -> &'static str {
    AIDM_EXT_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_from_url_and_explicit() {
        assert_eq!(
            derive_filename(None, "https://cdn.example/a/pkg-1.2.zip?x=1"),
            "pkg-1.2.zip"
        );
        assert_eq!(
            derive_filename(Some("mine.bin"), "https://cdn.example/other.zip"),
            "mine.bin"
        );
        assert_eq!(
            derive_filename(None, "https://cdn.example/%E4%B8%AD.bin"),
            "中.bin"
        );
        assert_eq!(
            derive_filename(None, "https://cdn.example/"),
            "download.bin"
        );
        assert_eq!(derive_filename(Some("  "), "https://x/"), "download.bin");
        let long = "a".repeat(300);
        assert_eq!(
            derive_filename(Some(&long), "https://x/a").chars().count(),
            255
        );
    }

    fn row(kind: ItemKind, name: &str, url: &str) -> CandidateRow {
        CandidateRow {
            url: url.into(),
            kind,
            filename: name.into(),
        }
    }

    #[test]
    fn filter_by_kind_and_search() {
        let rows = [
            row(ItemKind::Link, "a.zip", "https://e/a.zip"),
            row(ItemKind::Video, "clip.mp4", "https://e/v/clip.mp4"),
            row(ItemKind::Audio, "song.mp3", "https://e/a/song.mp3"),
        ];
        assert_eq!(filter_rows(&rows, Some(ItemKind::Video), "").len(), 1);
        assert_eq!(filter_rows(&rows, None, "CLIP").len(), 1);
        assert_eq!(filter_rows(&rows, None, "https://e/a/").len(), 1);
        assert!(filter_rows(&rows, Some(ItemKind::Link), "mp4").is_empty());
        assert_eq!(filter_rows(&rows, None, "  ").len(), 3);
    }

    #[test]
    fn selection_select_all_and_invert() {
        let mut selected = BTreeSet::new();
        selected.insert(9);
        let visible = vec![0, 1, 2];
        let all = select_visible(&selected, &visible);
        assert!(all.contains(&0) && all.contains(&1) && all.contains(&2) && all.contains(&9));
        let inv = invert_visible(&all, &visible);
        assert!(!inv.contains(&0));
        assert!(inv.contains(&9));
        let inv2 = invert_visible(&inv, &visible);
        assert!(inv2.contains(&0) && inv2.contains(&1) && inv2.contains(&2));
    }

    #[test]
    fn default_none_selected_disables_download() {
        let selected: BTreeSet<usize> = BTreeSet::new();
        assert_eq!(selected.len(), 0);
        assert_eq!(download_selected_label(0), "下载选中的 0 项");
        assert_eq!(
            candidate_dialog_title("示例页", 3),
            "从 示例页 发现 3 个链接"
        );
        assert_eq!(
            candidate_dialog_title("  ", 1),
            "从 未命名页面 发现 1 个链接"
        );
    }

    #[test]
    fn expiry_message_and_no_fallback() {
        assert_eq!(host_user_message("offer_expired"), OFFER_EXPIRED_TEXT);
        assert!(!should_fallback_to_browser(
            &NativeOutcome::ExplicitFailure {
                code: "offer_expired".into()
            }
        ));
        assert_eq!(host_user_message("ui_not_running"), UI_NOT_RUNNING_TEXT);
        assert_eq!(host_user_message("disabled"), INTEGRATION_DISABLED_TEXT);
        assert_eq!(
            outcome_user_message(&NativeOutcome::DisconnectedBeforeResponse),
            UNCERTAIN_TEXT
        );
        assert_eq!(
            outcome_user_message(&NativeOutcome::Unknown),
            UNCERTAIN_TEXT
        );
    }

    #[test]
    fn fallback_only_on_explicit_allowlist_codes() {
        assert!(!should_fallback_to_browser(&NativeOutcome::Accepted));
        assert!(!should_fallback_to_browser(&NativeOutcome::Unknown));
        assert!(!should_fallback_to_browser(
            &NativeOutcome::DisconnectedBeforeResponse
        ));
        for code in [
            "unsupported_scheme",
            "not_allowed",
            "bad_url",
            "disabled",
            "engine_unreachable",
        ] {
            assert!(
                should_fallback_to_browser(&NativeOutcome::ExplicitFailure { code: code.into() }),
                "{code}"
            );
        }
        assert!(!should_fallback_to_browser(
            &NativeOutcome::ExplicitFailure {
                code: "too_long".into()
            }
        ));
        assert!(!should_fallback_to_browser(
            &NativeOutcome::ExplicitFailure {
                code: "ui_not_running".into()
            }
        ));
        assert!(!should_fallback_to_browser(
            &NativeOutcome::ExplicitFailure {
                code: "offer_expired".into()
            }
        ));
        assert_eq!(host_user_message("unsupported_scheme"), FALLBACK_TEXT);
        assert_eq!(host_user_message("mystery"), UNCERTAIN_TEXT);
        assert_eq!(host_user_message("too_long"), TOO_LONG_TEXT);
        assert_eq!(offer_user_message("disabled"), OFFER_DISABLED_TEXT);
        assert_eq!(offer_user_message("engine_unreachable"), OFFER_FAIL_TEXT);
        assert!(!offer_user_message("disabled").contains("已改用浏览器下载"));
        assert_eq!(status_user_message(true, false), STATUS_DISCONNECT_TEXT);
        assert_eq!(status_user_message(false, false), STATUS_ENGINE_OFF_TEXT);
        assert_eq!(status_user_message(false, true), "");
        assert_eq!(
            candidate_add_result(2, 1).as_deref(),
            Some("已添加 2 项，1 项添加失败")
        );
        assert_eq!(candidate_add_result(0, 3).as_deref(), Some(CAND_ALL_FAIL));
        assert_eq!(candidate_add_result(2, 0), None);
    }

    #[test]
    fn host_reg_and_whitelist() {
        assert_eq!(
            host_reg_state(true, Some(true), None),
            HostRegState::Registered
        );
        assert_eq!(
            host_reg_state(true, Some(false), None),
            HostRegState::Unregistered
        );
        assert_eq!(
            host_reg_state(false, None, Some("engine_unreachable")),
            HostRegState::Unavailable
        );
        let engine = engine_default_ext_ids();
        assert_eq!(engine, vec![AIDM_EXT_ID.to_string()]);
        assert_eq!(parse_ext_id_list(""), engine);
        assert!(parse_ext_id_list("[]").is_empty());
        assert_eq!(
            parse_ext_id_list(&format!("[\"{AIDM_EXT_ID}\"]")),
            vec![AIDM_EXT_ID.to_string()]
        );
        let two = parse_ext_id_list("[\"aaa\",\"bbb\"]");
        assert_eq!(two.len(), 2);
        assert!(removing_last_ext_id(&engine, AIDM_EXT_ID));
        assert!(!removing_last_ext_id(&two, "aaa"));
    }

    #[test]
    fn offer_truncate_and_limits() {
        let items: Vec<u32> = (0..501).collect();
        let (kept, trunc) = truncate_offer_items(&items);
        assert_eq!(kept.len(), 500);
        assert!(trunc);
        let (kept, trunc) = truncate_offer_items(&[1, 2, 3]);
        assert_eq!(kept, vec![1, 2, 3]);
        assert!(!trunc);
        assert!(add_field_too_long(
            &"u".repeat(LIMIT_URL + 1),
            None,
            None,
            None
        ));
        assert!(!add_field_too_long(
            "https://x/a",
            None,
            None,
            Some("a.bin")
        ));
        assert_eq!(source_label(Some("ext")), "浏览器扩展");
        assert_eq!(source_label(None), "手动添加");
        assert!(is_ext_source(Some("ext")));
        assert!(!is_ext_source(Some("manual")));
        assert_eq!(truncate_url("abcdefghij", 5), "abcd…");
        assert_eq!(ItemKind::parse("video").unwrap().label(), "视频");
        assert_eq!(ItemKind::Video.as_str(), "video");
        assert_eq!(
            encode_ext_id_list(&[AIDM_EXT_ID.to_string()]),
            format!("[\"{AIDM_EXT_ID}\"]")
        );
        assert_eq!(default_extension_id(), AIDM_EXT_ID);
        assert_eq!(AIDM_EXT_ID, "npapgdblbbcppnbmhgdnmdbggfdnpahg");
        assert_eq!(TRUNCATED_BANNER, "只显示前 500 项");
        assert_eq!(REGISTER_HKCU_NOTE, "只写入当前用户的注册表");
        assert_eq!(CLICK_TAKEOVER_NOTE, "后续版本提供");
        assert_eq!(HOST_STATUS_FAIL, "无法检测浏览器连接状态，请重试");
        assert_eq!(HOST_COMPONENT_LABEL, "浏览器连接组件");
        assert_eq!(LAST_EXT_CONFIRM, "这是最后一个允许的扩展，确定删除？");
        assert_eq!(WHITELIST_HEADING, "允许的扩展 ID（默认包含 AIDM 扩展）");
        assert_eq!(
            UNCERTAIN_TEXT,
            "无法确认是否已交给 AIDM，请在 AIDM 列表中查看"
        );
        assert_eq!(CAND_NONE, "页面上没有发现可下载的链接");
        assert_eq!(CAND_NO_MATCH, "没有匹配的链接");
    }
}
