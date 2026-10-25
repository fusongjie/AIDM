//! 宿主协议：鉴权、字段上限、转发引擎。

use std::time::Duration;

use aidm_core::settings;
use aidm_ipc::{
    engine_roundtrip, parse_ext_request, truncate_offer_items, validate_add_fields, validate_url,
    EngineRequest, EngineResponse, ExtRequest, ExtResponse, FieldError, OfferItem,
};

pub const ACTIVE_STATES: &[&str] = &["queued", "connecting", "downloading", "verifying"];

#[derive(Debug, Clone)]
pub struct HostSettings {
    pub enabled: bool,
    pub allowed_ext_ids: Vec<String>,
}

impl HostSettings {
    pub fn from_db(conn: &rusqlite::Connection) -> Self {
        Self {
            enabled: settings::browser_enabled(conn),
            allowed_ext_ids: settings::allowed_ext_ids(conn),
        }
    }
}

pub fn load_host_settings() -> Result<HostSettings, String> {
    let conn = aidm_core::open_db(&aidm_core::db_path()).map_err(|e| e.to_string())?;
    let _ = settings::ensure_defaults(&conn);
    Ok(HostSettings::from_db(&conn))
}

/// Chrome/Edge 把调用方 origin 放在 argv[1]，形如 `chrome-extension://<id>/`。
pub fn caller_origin_from_argv(args: &[String]) -> Option<String> {
    args.get(1).cloned().filter(|s| !s.trim().is_empty())
}

pub fn parse_extension_id(origin: &str) -> Option<String> {
    let rest = origin.trim().strip_prefix("chrome-extension://")?;
    let id = rest.split('/').next()?.trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

pub fn origin_allowed(origin: Option<&str>, allowed: &[String]) -> bool {
    let Some(origin) = origin else {
        return false;
    };
    let Some(id) = parse_extension_id(origin) else {
        return false;
    };
    allowed.iter().any(|entry| {
        let entry = entry.trim();
        if let Some(eid) = parse_extension_id(entry) {
            eid.eq_ignore_ascii_case(&id)
        } else {
            entry.eq_ignore_ascii_case(&id)
        }
    })
}

fn map_field(err: FieldError) -> ExtResponse {
    ExtResponse::err(err.as_str())
}

fn engine_err(e: impl Into<String>) -> ExtResponse {
    let e = e.into();
    if e.contains("connect") || e.contains("engine") || e.contains("recv") || e.contains("send") {
        ExtResponse::err("engine_unreachable")
    } else {
        ExtResponse::err("engine_unreachable")
    }
}

fn forward(port: u16, req: EngineRequest) -> Result<EngineResponse, ExtResponse> {
    match engine_roundtrip(port, &req, Duration::from_secs(8)) {
        Ok(resp) => Ok(resp),
        Err(e) => Err(engine_err(e)),
    }
}

fn from_engine(resp: EngineResponse) -> ExtResponse {
    if !resp.ok {
        let code = resp
            .code
            .filter(|s| !s.is_empty())
            .or(resp.error)
            .unwrap_or_else(|| "engine_unreachable".into());
        return ExtResponse::err(code);
    }
    let mut out = ExtResponse::ok();
    out.id = resp.id;
    out.offer_id = resp.offer_id;
    out.truncated = resp.truncated;
    out.tasks = resp.tasks;
    out
}

pub fn handle(
    req: ExtRequest,
    origin: Option<&str>,
    parent_ok: bool,
    settings: &HostSettings,
    engine_port: Option<u16>,
) -> ExtResponse {
    if !parent_ok {
        return ExtResponse::err("not_allowed");
    }
    if !origin_allowed(origin, &settings.allowed_ext_ids) {
        return ExtResponse::err("not_allowed");
    }
    if !settings.enabled && !matches!(req, ExtRequest::Ping | ExtRequest::ShowUi) {
        return ExtResponse::err("disabled");
    }
    match req {
        ExtRequest::Ping => ExtResponse::ok(),
        ExtRequest::Add {
            url,
            referrer,
            filename,
            cookies,
            user_agent,
            custom_headers,
        } => {
            if let Err(e) = validate_add_fields(
                &url,
                referrer.as_deref(),
                filename.as_deref(),
                cookies.as_deref(),
            ) {
                return map_field(e);
            }
            let Some(port) = engine_port else {
                return ExtResponse::err("engine_unreachable");
            };
            match forward(
                port,
                EngineRequest::Add {
                    url,
                    dir: None,
                    filename,
                    referrer,
                    cookies,
                    user_agent,
                    custom_headers,
                    // 浏览器只交出一个 URL：备用地址是用户在新建对话框里填的。
                    alt_urls: None,
                    offer_id: None,
                    source: Some("ext".into()),
                    speed_limit_kbps: 0,
                    start: None,
                },
            ) {
                Ok(resp) => from_engine(resp),
                Err(e) => e,
            }
        }
        ExtRequest::Offer {
            page_url,
            title,
            items,
        } => handle_offer(page_url, title, items, engine_port),
        ExtRequest::Status => handle_status(engine_port),
        ExtRequest::Settings => handle_settings(engine_port),
        ExtRequest::List => {
            let Some(port) = engine_port else {
                return ExtResponse::err("engine_unreachable");
            };
            match forward(port, EngineRequest::List) {
                Ok(resp) => from_engine(resp),
                Err(e) => e,
            }
        }
        // 唤醒桌面 UI 不依赖引擎：UI 未运行时由这里启动，引擎由 UI 自己拉起。
        ExtRequest::ShowUi => match crate::ui_window::open_or_focus() {
            Ok(()) => ExtResponse::ok(),
            Err(code) => ExtResponse::err(code),
        },
    }
}

/// 浏览器接管相关的设置子集（只读）。
///
/// 为什么在宿主里做白名单而不是让扩展直接读引擎：宿主是唯一有机会
/// 把"代理密码、路径"这类敏感键挡在浏览器进程之外的地方。这里只放行
/// 接管相关的键。
const EXT_SETTINGS_KEYS: &[&str] = &[
    "browser.enabled",
    "browser.allowed_ext_ids",
    "browser.click_takeover",
    "browser.exclude_hosts",
    "browser.auto_catch_exts",
    "browser.panel_enabled",
    "browser.panel_exts",
    "browser.panel_exclude_hosts",
    "browser.skip_html",
    "browser.monitor_clipboard",
    "browser.hotkey_prevent",
    "browser.hotkey_force",
    "ui.duplicate_action",
];

fn handle_settings(engine_port: Option<u16>) -> ExtResponse {
    let Some(port) = engine_port else {
        return ExtResponse::err("engine_unreachable");
    };
    match forward(port, EngineRequest::SettingsGet) {
        Ok(resp) if resp.ok => {
            let mut out = serde_json::Map::new();
            if let Some(all) = resp.settings {
                for key in EXT_SETTINGS_KEYS {
                    if let Some(v) = all.get(*key) {
                        out.insert((*key).to_string(), v.clone());
                    }
                }
            }
            let mut r = ExtResponse::ok();
            r.settings = Some(out);
            r
        }
        Ok(resp) => from_engine(resp),
        Err(e) => e,
    }
}

fn handle_offer(
    page_url: String,
    title: String,
    items: Vec<OfferItem>,
    engine_port: Option<u16>,
) -> ExtResponse {
    if let Err(e) = validate_url(&page_url) {
        return map_field(e);
    }
    let mut kept = Vec::with_capacity(items.len().min(aidm_ipc::LIMIT_OFFER_ITEMS));
    for item in items {
        if validate_url(&item.url).is_err() {
            continue;
        }
        if validate_add_fields(&item.url, None, item.filename.as_deref(), None).is_err() {
            continue;
        }
        kept.push(item);
    }
    let (items, truncated) = truncate_offer_items(kept);
    let Some(port) = engine_port else {
        return ExtResponse::err("engine_unreachable");
    };
    match forward(
        port,
        EngineRequest::Offer {
            page_url,
            title,
            items,
            truncated,
            cookies: None,
        },
    ) {
        Ok(resp) => from_engine(resp),
        Err(e) => e,
    }
}

fn handle_status(engine_port: Option<u16>) -> ExtResponse {
    let mut out = ExtResponse::ok();
    let Some(port) = engine_port else {
        out.engine_online = Some(false);
        out.active = Some(0);
        return out;
    };
    match forward(port, EngineRequest::Ping) {
        Ok(resp) if resp.ok => {
            out.engine_online = Some(true);
            let active = match forward(port, EngineRequest::List) {
                Ok(list) => count_active(list.tasks.as_deref().unwrap_or(&[])),
                Err(_) => 0,
            };
            out.active = Some(active);
            out
        }
        _ => {
            out.engine_online = Some(false);
            out.active = Some(0);
            out
        }
    }
}

pub fn count_active(tasks: &[aidm_ipc::TaskView]) -> u64 {
    tasks
        .iter()
        .filter(|t| ACTIVE_STATES.contains(&t.state.as_str()))
        .count() as u64
}

pub fn decode_request(bytes: &[u8]) -> Result<ExtRequest, ExtResponse> {
    let text = std::str::from_utf8(bytes).map_err(|_| ExtResponse::err("too_long"))?;
    parse_ext_request(text).map_err(|_| ExtResponse::err("too_long"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_ipc::{encode_nmh_message, read_nmh_message, OfferKind};

    fn allowed() -> HostSettings {
        HostSettings {
            enabled: true,
            allowed_ext_ids: vec!["npapgdblbbcppnbmhgdnmdbggfdnpahg".into()],
        }
    }

    fn origin() -> &'static str {
        "chrome-extension://npapgdblbbcppnbmhgdnmdbggfdnpahg/"
    }

    #[test]
    fn settings_op_filters_to_browser_keys() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut buf = String::new();
            reader.read_line(&mut buf).unwrap();
            assert!(buf.contains("\"op\":\"settings_get\""), "实际请求: {buf}");
            let mut s = reader.get_ref().try_clone().unwrap();
            // 引擎回一大堆设置，其中包含绝不能外泄的键
            writeln!(
                s,
                r#"{{"ok":true,"settings":{{"browser.exclude_hosts":"a.com","browser.auto_catch_exts":"iso zip","browser.hotkey_prevent":"ctrl","proxy.pass":"SECRET","proxy.has_password":true,"paths.default_dir":"D:\\x"}}}}"#
            )
            .unwrap();
        });
        let resp = handle(
            ExtRequest::Settings,
            Some(origin()),
            true,
            &allowed(),
            Some(port),
        );
        t.join().unwrap();
        assert!(resp.ok, "应成功: {resp:?}");
        let s = resp.settings.expect("settings");
        assert_eq!(
            s.get("browser.exclude_hosts").and_then(|v| v.as_str()),
            Some("a.com")
        );
        assert_eq!(
            s.get("browser.auto_catch_exts").and_then(|v| v.as_str()),
            Some("iso zip")
        );
        // 白名单之外的一律不出去
        assert!(!s.contains_key("proxy.pass"), "密码绝不能进扩展进程");
        assert!(!s.contains_key("proxy.has_password"));
        assert!(!s.contains_key("paths.default_dir"));
    }

    #[test]
    fn settings_op_without_engine_is_reported() {
        let resp = handle(ExtRequest::Settings, Some(origin()), true, &allowed(), None);
        assert!(!resp.ok);
        assert_eq!(resp.code.as_deref(), Some("engine_unreachable"));
    }
    #[test]
    fn whitelist_reject() {
        let resp = handle(
            ExtRequest::Ping,
            Some("chrome-extension://bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/"),
            true,
            &allowed(),
            None,
        );
        assert_eq!(resp.code.as_deref(), Some("not_allowed"));
        let resp = handle(ExtRequest::Ping, None, true, &allowed(), None);
        assert_eq!(resp.code.as_deref(), Some("not_allowed"));
        let resp = handle(ExtRequest::Ping, Some(origin()), false, &allowed(), None);
        assert_eq!(resp.code.as_deref(), Some("not_allowed"));
    }

    #[test]
    fn disabled_rejects_mutating_ops() {
        let mut s = allowed();
        s.enabled = false;
        let ping = handle(ExtRequest::Ping, Some(origin()), true, &s, None);
        assert!(ping.ok);
        let add = handle(
            ExtRequest::Add {
                url: "https://x/a".into(),
                referrer: None,
                filename: None,
                cookies: None,
                user_agent: None,
                custom_headers: None,
            },
            Some(origin()),
            true,
            &s,
            None,
        );
        assert_eq!(add.code.as_deref(), Some("disabled"));
    }

    #[test]
    fn scheme_reject() {
        let resp = handle(
            ExtRequest::Add {
                url: "file:///etc/passwd".into(),
                referrer: None,
                filename: None,
                cookies: None,
                user_agent: None,
                custom_headers: None,
            },
            Some(origin()),
            true,
            &allowed(),
            Some(1),
        );
        assert_eq!(resp.code.as_deref(), Some("bad_url"));
    }

    #[test]
    fn limits_too_long() {
        let url = format!("https://x/{}", "a".repeat(aidm_ipc::LIMIT_URL));
        let resp = handle(
            ExtRequest::Add {
                url,
                referrer: None,
                filename: None,
                cookies: None,
                user_agent: None,
                custom_headers: None,
            },
            Some(origin()),
            true,
            &allowed(),
            Some(1),
        );
        assert_eq!(resp.code.as_deref(), Some("too_long"));
        let cookies = "c".repeat(aidm_ipc::LIMIT_COOKIES + 1);
        let resp = handle(
            ExtRequest::Add {
                url: "https://x/a".into(),
                referrer: None,
                filename: None,
                cookies: Some(cookies),
                user_agent: None,
                custom_headers: None,
            },
            Some(origin()),
            true,
            &allowed(),
            Some(1),
        );
        assert_eq!(resp.code.as_deref(), Some("too_long"));
    }

    #[test]
    fn engine_missing_is_unreachable() {
        let resp = handle(
            ExtRequest::Add {
                url: "https://x/a".into(),
                referrer: None,
                filename: None,
                cookies: None,
                user_agent: None,
                custom_headers: None,
            },
            Some(origin()),
            true,
            &allowed(),
            None,
        );
        assert_eq!(resp.code.as_deref(), Some("engine_unreachable"));
    }

    #[test]
    fn framing_roundtrip_via_host_payload() {
        let raw = br#"{"v":1,"op":"ping"}"#;
        let framed = encode_nmh_message(raw).unwrap();
        let mut cur = std::io::Cursor::new(framed);
        let body = read_nmh_message(&mut cur).unwrap();
        let req = decode_request(&body).unwrap();
        assert_eq!(req, ExtRequest::Ping);
    }

    #[test]
    fn offer_item_kinds() {
        let items = vec![
            OfferItem {
                url: "https://x/a".into(),
                kind: OfferKind::Link,
                filename: None,
            },
            OfferItem {
                url: "file://bad".into(),
                kind: OfferKind::Video,
                filename: None,
            },
        ];
        let resp = handle(
            ExtRequest::Offer {
                page_url: "https://p/".into(),
                title: "t".into(),
                items,
            },
            Some(origin()),
            true,
            &allowed(),
            None,
        );
        assert_eq!(resp.code.as_deref(), Some("engine_unreachable"));
    }

    #[test]
    fn ftp_add_passes_host_whitelist_and_forwards_unsupported_scheme() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut buf = String::new();
            reader.read_line(&mut buf).unwrap();
            assert!(buf.contains("\"op\":\"add\""));
            assert!(buf.contains("ftp://"));
            let mut s = reader.get_ref().try_clone().unwrap();
            writeln!(s, r#"{{"ok":false,"error":"unsupported_scheme"}}"#).unwrap();
        });
        let resp = handle(
            ExtRequest::Add {
                url: "ftp://files.example/a.bin".into(),
                referrer: None,
                filename: None,
                cookies: None,
                user_agent: None,
                custom_headers: None,
            },
            Some(origin()),
            true,
            &allowed(),
            Some(port),
        );
        t.join().unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.code.as_deref(), Some("unsupported_scheme"));
    }

    #[test]
    fn offer_expired_code_is_passed_through_unchanged() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut buf = String::new();
            reader.read_line(&mut buf).unwrap();
            let mut s = reader.get_ref().try_clone().unwrap();
            writeln!(s, r#"{{"ok":false,"code":"offer_expired"}}"#).unwrap();
        });
        let resp = handle(
            ExtRequest::Add {
                url: "https://cdn.example/a.bin".into(),
                referrer: None,
                filename: None,
                cookies: None,
                user_agent: None,
                custom_headers: None,
            },
            Some(origin()),
            true,
            &allowed(),
            Some(port),
        );
        t.join().unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.code.as_deref(), Some("offer_expired"));
        assert!(resp.version.is_none() || resp.id.is_none());
    }
}
