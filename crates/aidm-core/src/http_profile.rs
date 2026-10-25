//! 请求头配置：把设置里那几项解析成"一次任务实际要发的头"。
//!
//! 内置集合来自浏览器请求实测，保证与常见浏览器一致：
//!
//! ```text
//! GET /probe.bin HTTP/1.1
//! Accept: */*
//! Accept-Charset: *
//! Accept-Encoding: identity
//! Accept-Language: zh-CN
//! Host: 127.0.0.1:8899
//! Referer: http://127.0.0.1:8899/          ← 没给 Referer 时自动补站点根
//! User-Agent: Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
//! ```
//!
//! User-Agent 规则：内置默认串，设置可整串覆盖；浏览器发起时透传浏览器 UA。
//! 这里用 [`RequestProfile`] 表达同一套规则。

use crate::setting_spec::DEFAULT_USER_AGENT;
use crate::settings;

/// 一次任务实际使用的请求头配置（已解析，无 IO）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestProfile {
    pub user_agent: String,
    pub accept: String,
    pub accept_charset: String,
    pub accept_language: String,
    pub accept_encoding: String,
    /// 没给 Referer 时是否自动补 `<scheme>://<host>/`
    pub referer_fallback: bool,
    /// 换成**不声明客户端身份**的 UA（空值），而不是设置里那套"自称浏览器"的 UA。
    ///
    /// 只给"自动派生的镜像候选"用。实测（curl 与裸 socket 两种方式互证）：
    ///
    /// | 发出的 UA | `mirrors.nju.edu.cn` | `mirrors.sjtug.sjtu.edu.cn` | `mirrors.huaweicloud.com` |
    /// |---|---|---|---|
    /// | IE11 / Chrome（本仓库默认） | 302 跳回自己 + `Set-Cookie: bcheck=true` | 200 + `cerberus` 反爬页 | 206 |
    /// | **空值**（本标记） | **206** | **206** | 206（但该站会**状态化**地回 418，与 UA 无关） |
    /// | `curl/*`、`AIDM/*` 这类命令行标识 | 206 | 206 | **418** |
    ///
    /// 两条结论：① 触发挑战的是"**声称自己是浏览器**"这件事本身，与哪家浏览器无关；
    /// ② 空值是唯一对上述三者都通行的取值（自报标识会被 huaweicloud 以 418 拒掉，
    /// 而 huaweicloud 的 418 本身还会随时间/IP 漂移，不能依赖）。
    ///
    /// 为什么不是"干脆不发这个头"：ureq 在 `unit.rs:459` 是
    /// `if !has_header(user-agent) { 写 agent 默认值 }`，而 agent 默认值就是本仓库设的
    /// 那串 IE11 —— 跳过设置只会退回它。所以"空值"是 ureq 下最接近"没有身份"的形态。
    ///
    /// 主地址与用户自己填的地址**永远不带这个标记**：那些地址保持与内置请求头一致
    /// （见 docs/http-profile.md），只有 AIDM 自己猜出来的镜像才走这条。
    pub no_browser_ua: bool,
}

/// 派生镜像候选用的 UA 值：**空**（不声明任何客户端身份）。依据见
/// [`RequestProfile::no_browser_ua`]。
pub const ANON_USER_AGENT: &str = "";

impl RequestProfile {
    /// 派生一个"用客户端自报标识、不冒充浏览器"的副本（其余头不变）。
    pub fn without_browser_ua(mut self) -> Self {
        self.no_browser_ua = true;
        self
    }
}

impl Default for RequestProfile {
    fn default() -> Self {
        Self {
            user_agent: DEFAULT_USER_AGENT.to_string(),
            accept: "*/*".into(),
            accept_charset: "*".into(),
            accept_language: system_accept_language(),
            accept_encoding: "identity".into(),
            referer_fallback: true,
            no_browser_ua: false,
        }
    }
}

/// 清洗外部传入的 UA（浏览器透传 / IPC 字段）。
///
/// UA 会直接拼进请求头，所以必须挡住 CR/LF（头注入）与过长取值：
/// 含控制字符即视为非法并丢弃，超长则截断到 [`UA_MAX_BYTES`]。
pub fn sanitize_user_agent(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control()) {
        return None;
    }
    if trimmed.len() <= UA_MAX_BYTES {
        return Some(trimmed.to_string());
    }
    let mut end = UA_MAX_BYTES;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    Some(trimmed[..end].to_string())
}

/// UA 允许的最大字节数（浏览器 UA 一般 ~120 字节，留足余量）。
pub const UA_MAX_BYTES: usize = 512;

impl RequestProfile {
    /// 直接读库构造（没有快照的路径，例如独立抓取工具）。
    pub fn from_conn(conn: &rusqlite::Connection) -> Self {
        let raw = |key: &str| settings::get(conn, key).ok().flatten();
        let pick = |key: &str, fallback: String| -> String {
            match raw(key).map(|v| v.trim().to_string()) {
                Some(v) if !v.is_empty() && v != "auto" => v,
                _ => fallback,
            }
        };
        let ua = match raw("net.user_agent").map(|v| v.trim().to_string()) {
            Some(v) if !v.is_empty() => v,
            _ => DEFAULT_USER_AGENT.to_string(),
        };
        Self {
            user_agent: ua,
            accept: pick("net.accept", "*/*".into()),
            accept_charset: pick("net.accept_charset", "*".into()),
            accept_language: pick("net.accept_language", system_accept_language()),
            accept_encoding: pick("net.accept_encoding", "identity".into()),
            referer_fallback: raw("net.referer_fallback").as_deref() != Some("false"),
            // 设置里读出来的档案永远带 UA；只有派生镜像候选会临时改成不发
            no_browser_ua: false,
        }
    }

    /// 从设置快照构造。
    pub fn from_snapshot(snap: &settings::Snapshot) -> Self {
        let pick = |key: &str, fallback: String| -> String {
            match snap.raw(key) {
                Some(v) if !v.trim().is_empty() && v.trim() != "auto" => v.trim().to_string(),
                Some(v) if v.trim() == "auto" => fallback,
                _ => fallback,
            }
        };
        // UA 规则：空串 = 回到内置默认
        let ua = match snap.raw("net.user_agent") {
            Some(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => DEFAULT_USER_AGENT.to_string(),
        };
        Self {
            user_agent: ua,
            accept: pick("net.accept", "*/*".into()),
            accept_charset: pick("net.accept_charset", "*".into()),
            accept_language: pick("net.accept_language", system_accept_language()),
            accept_encoding: pick("net.accept_encoding", "identity".into()),
            referer_fallback: snap
                .raw("net.referer_fallback")
                .map(|v| v != "false")
                .unwrap_or(true),
            no_browser_ua: false,
        }
    }

    /// 浏览器发起时透传浏览器 UA（浏览器请求本身自带 User-Agent）。
    pub fn with_browser_user_agent(mut self, ua: Option<&str>) -> Self {
        if let Some(clean) = ua.and_then(sanitize_user_agent) {
            self.user_agent = clean;
        }
        self
    }

    /// 没给 Referer 时补站点根：`https://host/path` → `https://host/`。
    pub fn referer_for<'a>(&self, given: Option<&'a str>, url: &str) -> Option<String> {
        if let Some(r) = given.map(str::trim).filter(|s| !s.is_empty()) {
            return Some(r.to_string());
        }
        if !self.referer_fallback {
            return None;
        }
        let lower = url.trim().to_ascii_lowercase();
        let scheme = if lower.starts_with("https://") {
            "https"
        } else if lower.starts_with("http://") {
            "http"
        } else {
            return None;
        };
        let rest = &url[scheme.len() + 3..];
        let authority = rest.split(['/', '?', '#']).next()?;
        if authority.is_empty() {
            return None;
        }
        Some(format!("{scheme}://{authority}/"))
    }
}

/// 系统区域转成 `Accept-Language`（按系统语言发，取系统默认）。
///
/// Windows 用 `GetUserDefaultLocaleName`；其它平台读 `LANG`/`LC_ALL`，都没有则 en-US。
pub fn system_accept_language() -> String {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
        let mut buf = [0u16; 85];
        let n = unsafe { GetUserDefaultLocaleName(buf.as_mut_ptr(), buf.len() as i32) };
        if n > 1 {
            let s = String::from_utf16_lossy(&buf[..(n as usize - 1)]);
            if !s.trim().is_empty() {
                return s;
            }
        }
        "en-US".into()
    }
    #[cfg(not(windows))]
    {
        for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
            if let Ok(v) = std::env::var(key) {
                let v = v.trim();
                if !v.is_empty() && v != "C" && v != "POSIX" {
                    // en_US.UTF-8 → en-US
                    let base = v
                        .split('.')
                        .next()
                        .unwrap_or(v)
                        .split('@')
                        .next()
                        .unwrap_or(v);
                    return base.replace('_', "-");
                }
            }
        }
        "en-US".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referer_fallback_uses_origin_root() {
        let p = RequestProfile::default();
        assert_eq!(
            p.referer_for(None, "http://127.0.0.1:8899/probe.bin"),
            Some("http://127.0.0.1:8899/".into())
        );
        assert_eq!(
            p.referer_for(None, "https://cdn.example.com/a/b/c.iso?x=1"),
            Some("https://cdn.example.com/".into())
        );
        // 显式给的 Referer 优先，原样保留
        assert_eq!(
            p.referer_for(
                Some("https://page.example/x"),
                "https://cdn.example.com/a.iso"
            ),
            Some("https://page.example/x".into())
        );
        // 非 http(s) 不补
        assert_eq!(p.referer_for(None, "ftp://example.com/a"), None);
        // 关掉兜底就什么都不补
        let off = RequestProfile {
            referer_fallback: false,
            ..Default::default()
        };
        assert_eq!(off.referer_for(None, "https://a.example/b"), None);
    }

    #[test]
    fn user_agent_injection_is_rejected() {
        // CR/LF 会伪造请求头，必须丢弃
        assert_eq!(sanitize_user_agent("ok/1.0\r\nX-Evil: 1"), None);
        assert_eq!(sanitize_user_agent("ok/1.0\nX-Evil: 1"), None);
        assert_eq!(sanitize_user_agent("bad\u{7f}"), None);
        assert_eq!(sanitize_user_agent("   "), None);
        assert_eq!(sanitize_user_agent(" ok/1.0 "), Some("ok/1.0".into()));
        let long = "a".repeat(UA_MAX_BYTES + 50);
        assert_eq!(sanitize_user_agent(&long).unwrap().len(), UA_MAX_BYTES);
        // 透传路径同样受保护
        let p = RequestProfile::default().with_browser_user_agent(Some("x\r\nEvil: 1"));
        assert_eq!(p.user_agent, DEFAULT_USER_AGENT);
    }

    #[test]
    fn without_browser_ua_only_flips_that_one_flag() {
        let base = RequestProfile::default();
        let no_ua = base.clone().without_browser_ua();
        assert!(no_ua.no_browser_ua);
        // 其余字段一个都不能变（UA 取值本身仍保留，便于回退时复用）
        assert_eq!(no_ua.user_agent, base.user_agent);
        assert_eq!(no_ua.accept, base.accept);
        assert_eq!(no_ua.accept_encoding, base.accept_encoding);
        assert_eq!(no_ua.referer_fallback, base.referer_fallback);
        // 反过来：默认档案永远带 UA
        assert!(!RequestProfile::default().no_browser_ua);
        assert!(!RequestProfile::from_snapshot(&settings::Snapshot::defaults()).no_browser_ua);
    }

    #[test]
    fn browser_user_agent_overrides() {
        let p = RequestProfile::default().with_browser_user_agent(Some("Browser/1.0"));
        assert_eq!(p.user_agent, "Browser/1.0");
        // 空值不覆盖
        let p2 = RequestProfile::default().with_browser_user_agent(Some("  "));
        assert_eq!(p2.user_agent, DEFAULT_USER_AGENT);
        let p3 = RequestProfile::default().with_browser_user_agent(None);
        assert_eq!(p3.user_agent, DEFAULT_USER_AGENT);
    }

    #[test]
    fn system_language_is_some_like_tag() {
        let v = system_accept_language();
        assert!(!v.is_empty());
        assert!(!v.contains('_'), "应归一成 xx-YY：{v}");
    }
}
