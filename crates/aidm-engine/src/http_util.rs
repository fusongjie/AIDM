//! 引擎 HTTP 辅助：连接池 Agent、§3.4 公共请求头、AIDM 进程内代理。
//! 仅引擎进程使用（UI 零网络 IO）。follow-system 只读系统代理，永不写入。

use std::sync::{Mutex, RwLock};
use std::time::Duration;

use aidm_core::proxy::{self, ProxyMode, ProxyScheme};
use aidm_core::secret;
use aidm_core::settings;
use rusqlite::Connection;
use ureq::{Agent, AgentBuilder, Request};

const DEFAULT_CONNECT_S: u64 = 15;
const DEFAULT_IDLE_S: u64 = 60;

/// 可热更新的 Agent（代理 / 超时变更后重建，运行中任务下次请求生效）。
///
/// 同时持有"走代理"与"直连"两份 Agent：代理开关是**按目标**决定的，
/// 单份 Agent 表达不了。
pub struct HttpRuntime {
    inner: RwLock<Agents>,
}

struct Agents {
    proxied: Agent,
    direct: Agent,
    /// 与上两者同配置，但 `redirects(0)`：只在需要看"第一跳跳到哪里"时用，
    /// 正常下载路径一律走跟随重定向的 Agent。
    proxied_noredirect: Agent,
    direct_noredirect: Agent,
    has_proxy: bool,
    /// 命中即直连
    bypass: Vec<String>,
    /// `all` / `http` / `https`
    only_for: String,
}

impl HttpRuntime {
    pub fn from_db(db: &Mutex<Connection>) -> std::sync::Arc<Self> {
        let conn = db.lock().unwrap();
        std::sync::Arc::new(Self {
            inner: RwLock::new(agents_from_conn(&conn)),
        })
    }

    pub fn reload(&self, db: &Mutex<Connection>) {
        let conn = db.lock().unwrap();
        let agents = agents_from_conn(&conn);
        *self.inner.write().unwrap() = agents;
    }

    /// 默认（不区分目标）的 Agent：走配置里的代理。
    pub fn agent(&self) -> Agent {
        self.inner.read().unwrap().proxied.clone()
    }

    /// 按目标 URL 选 Agent：命中直连表、或协议被 `proxy.only_for` 排除时不走代理。
    pub fn agent_for(&self, url: &str) -> Agent {
        let g = self.inner.read().unwrap();
        if proxy_skipped(&g, url) {
            g.direct.clone()
        } else {
            g.proxied.clone()
        }
    }

    /// 与 [`Self::agent_for`] 同一套选路，但**不跟随重定向**。
    ///
    /// 只用于读"第一跳的 `Location`"（主地址 302 到另一个主机时，那个目标本身
    /// 是另一个可试的地址）。正常探测与下载都不该用它。
    pub fn agent_for_noredirect(&self, url: &str) -> Agent {
        let g = self.inner.read().unwrap();
        if proxy_skipped(&g, url) {
            g.direct_noredirect.clone()
        } else {
            g.proxied_noredirect.clone()
        }
    }

    /// 该目标是否**应当**走代理（与 [`Self::agent_for`] 同一套判定）。
    ///
    /// 单独暴露出来是为了能直接断言规则本身，而不用去比较两个 `Agent`。
    pub fn proxy_applies(&self, url: &str) -> bool {
        let g = self.inner.read().unwrap();
        g.has_proxy && !proxy_skipped(&g, url)
    }
}

/// 命中直连表、或协议被 `proxy.only_for` 排除 → 该目标不走代理。
fn proxy_skipped(g: &Agents, url: &str) -> bool {
    if !g.has_proxy {
        return true;
    }
    let host = aidm_core::sched::url_host(url);
    if aidm_core::sched::host_matches_any(&g.bypass, &host) {
        return true;
    }
    let https = url
        .trim_start()
        .to_ascii_lowercase()
        .starts_with("https://");
    match g.only_for.as_str() {
        "http" => https,
        "https" => !https,
        _ => false,
    }
}

fn agents_from_conn(conn: &Connection) -> Agents {
    let snap = aidm_core::settings::Snapshot::load(conn)
        .unwrap_or_else(|_| aidm_core::settings::Snapshot::defaults());
    let base = build_agent(conn, None);
    let base_nr = build_agent_noredirect(conn, None);
    match resolve_proxy_url(conn) {
        Some(url) => match ureq::Proxy::new(&url) {
            Ok(p) => Agents {
                proxied: build_agent(conn, Some(p.clone())),
                direct: base,
                proxied_noredirect: build_agent_noredirect(conn, Some(p)),
                direct_noredirect: base_nr,
                has_proxy: true,
                bypass: snap.proxied_hosts_skip.clone(),
                only_for: snap.proxy_only_for.clone(),
            },
            Err(e) => {
                log::warn!(
                    "proxy ignored ({}): {e}",
                    aidm_core::redact::redact_url(&url)
                );
                Agents {
                    proxied: base.clone(),
                    direct: base,
                    proxied_noredirect: base_nr.clone(),
                    direct_noredirect: base_nr,
                    has_proxy: false,
                    bypass: Vec::new(),
                    only_for: "all".into(),
                }
            }
        },
        None => Agents {
            proxied: base.clone(),
            direct: base,
            proxied_noredirect: base_nr.clone(),
            direct_noredirect: base_nr,
            has_proxy: false,
            bypass: Vec::new(),
            only_for: "all".into(),
        },
    }
}

/// 与 [`build_agent`] 同配置，但 `redirects(0)`：拿到 3xx 本身而不是跟到底。
fn build_agent_noredirect(conn: &Connection, proxy: Option<ureq::Proxy>) -> Agent {
    let connect_s = settings::get(conn, "conn.timeout_connect_s")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok());
    let idle_s = settings::get(conn, "conn.timeout_idle_s")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok());
    let mut builder = AgentBuilder::new()
        .timeout_connect(Duration::from_secs(connect_s.unwrap_or(DEFAULT_CONNECT_S)))
        .timeout_read(Duration::from_secs(idle_s.unwrap_or(DEFAULT_IDLE_S)))
        .redirects(0);
    if let Some(p) = proxy {
        builder = builder.proxy(p);
    }
    builder.build()
}

fn build_agent(conn: &Connection, proxy: Option<ureq::Proxy>) -> Agent {
    let connect_s = settings::get(conn, "conn.timeout_connect_s")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok());
    let idle_s = settings::get(conn, "conn.timeout_idle_s")
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok());
    let mut builder = AgentBuilder::new()
        .timeout_connect(Duration::from_secs(connect_s.unwrap_or(DEFAULT_CONNECT_S)))
        .timeout_read(Duration::from_secs(idle_s.unwrap_or(DEFAULT_IDLE_S)));
    if let Some(p) = proxy {
        builder = builder.proxy(p);
    }
    builder.build()
}

/// 按当前设置解析 ureq 代理 URL。`none` / 无系统代理 → None。
pub fn resolve_proxy_url(conn: &Connection) -> Option<String> {
    let mode = settings::get(conn, "proxy.mode")
        .ok()
        .flatten()
        .and_then(|s| proxy::parse_mode(&s))
        .unwrap_or(ProxyMode::FollowSystem);
    match mode {
        ProxyMode::None => None,
        ProxyMode::FollowSystem => {
            proxy::read_system_proxy().map(|p| format!("http://{}:{}", p.host, p.port))
        }
        ProxyMode::Manual => {
            let host = settings::get(conn, "proxy.host")
                .ok()
                .flatten()
                .unwrap_or_default();
            if proxy::validate_host(&host).is_err() || host.trim().is_empty() {
                return None;
            }
            let port = settings::get(conn, "proxy.port")
                .ok()
                .flatten()
                .and_then(|s| proxy::validate_port(&s).ok().flatten())
                .unwrap_or(8080);
            let scheme = settings::get(conn, "proxy.scheme")
                .ok()
                .flatten()
                .and_then(|s| proxy::parse_scheme(&s))
                .unwrap_or(ProxyScheme::Http);
            let scheme_s = match scheme {
                ProxyScheme::Http => "http",
                ProxyScheme::Socks5 => "socks5",
            };
            let user = settings::get(conn, "proxy.user")
                .ok()
                .flatten()
                .unwrap_or_default();
            let pass = settings::get(conn, "proxy.pass")
                .ok()
                .flatten()
                .and_then(|v| {
                    if v.is_empty() {
                        None
                    } else {
                        secret::unprotect(&v).ok().filter(|s| !s.is_empty())
                    }
                });
            Some(format_proxy_url(
                scheme_s,
                host.trim(),
                port,
                user.trim(),
                pass.as_deref(),
            ))
        }
    }
}

fn format_proxy_url(scheme: &str, host: &str, port: u16, user: &str, pass: Option<&str>) -> String {
    if user.is_empty() && pass.is_none() {
        return format!("{scheme}://{host}:{port}");
    }
    let u = urlencode(user);
    let p = urlencode(pass.unwrap_or(""));
    format!("{scheme}://{u}:{p}@{host}:{port}")
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// 给请求套上统一的请求头（与 fastdl 的自有协议栈共用同一套头）。
///
/// `profile` 里已经包含 UA / Accept 系列 / Referer 兜底，因此这里不再各自 set，
/// 避免"小文件走 ureq、大文件走自有栈"两套头不一致导致的行为差异。
/// 两个 http(s) URL 是否同源（scheme + authority，忽略大小写）。
pub(crate) fn same_origin(a: &str, b: &str) -> bool {
    fn origin(raw: &str) -> Option<(&str, &str)> {
        let (scheme, rest) = raw.split_once("://")?;
        let authority = rest.split(['/', '?', '#']).next()?;
        Some((scheme, authority))
    }
    match (origin(a), origin(b)) {
        (Some((sa, aa)), Some((sb, ab))) => {
            sa.eq_ignore_ascii_case(sb) && aa.eq_ignore_ascii_case(ab)
        }
        _ => false,
    }
}

pub fn apply_common(
    req: Request,
    profile: &aidm_core::http_profile::RequestProfile,
    url: &str,
    referer: Option<&str>,
    cookies: Option<&str>,
    custom_headers: &[aidm_core::headers::HeaderLine],
) -> Request {
    // 自动派生的镜像候选换成客户端自报标识，避免被"只挑战浏览器"的 WAF 拦住
    // （实测表见 `RequestProfile::no_browser_ua`）。
    //
    // **必须始终显式设置这个头**：ureq 在 `unit.rs:459` 是
    // `if !has_header(user-agent) { 写 agent 默认值 }` —— 跳过设置只会退回 agent 的
    // 默认 UA（本仓库把它设成了那串 IE11），而不是"不发"。所以这里是**换值**，不是省略。
    let ua = if profile.no_browser_ua {
        aidm_core::http_profile::ANON_USER_AGENT
    } else {
        profile.user_agent.as_str()
    };
    let mut req = req
        .set("User-Agent", ua)
        .set("Accept", &profile.accept)
        .set("Accept-Charset", &profile.accept_charset)
        .set("Accept-Encoding", &profile.accept_encoding)
        .set("Accept-Language", &profile.accept_language);
    // 显式 Referer（浏览器/命令行给的）优先；没给才用站点根兜底。
    //
    // 但兜底值就是下载 URL 自己的 origin，发给 CDN 会被判成盗链（实测某
    // 分发域名：`Referer: https://下载站自身/` → 403，不带 Referer → 206）。
    // 因此只在兜底值与目标跨源时才发；显式给的 Referer 仍然原样发送。
    if let Some(r) = profile.referer_for(referer, url) {
        let derived_same_origin = referer.is_none() && same_origin(&r, url);
        if !derived_same_origin {
            req = req.set("Referer", &r);
        }
    }
    if let Some(c) = cookies.filter(|c| !c.is_empty()) {
        req = req.set("Cookie", c);
    }
    // 每任务自定义头（受管头与控制字符已在解析阶段挡掉）
    for h in custom_headers {
        if !aidm_core::headers::is_managed_header(&h.name)
            && !h.value.chars().any(|c| c.is_control())
        {
            req = req.set(&h.name, &h.value);
        }
    }
    req
}

pub fn header_owned(resp: &ureq::Response, name: &str) -> Option<String> {
    resp.header(name).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::db::open_db;
    use std::path::Path;

    #[test]
    fn same_origin_ignores_case_and_paths() {
        assert!(same_origin(
            "https://Down15.WSYHN.com/",
            "https://down15.wsyhn.com/app/a.apk?x=1"
        ));
        assert!(!same_origin(
            "https://shouyou.3dmgame.com/",
            "https://down15.wsyhn.com/app/a.apk"
        ));
        assert!(!same_origin("ftp://a.example/", "https://a.example/f"));
    }

    #[test]
    fn none_mode_has_no_proxy() {
        let conn = open_db(Path::new(":memory:")).unwrap();
        settings::ensure_defaults(&conn).unwrap();
        settings::set_validated(&conn, "proxy.mode", "none").unwrap();
        assert!(resolve_proxy_url(&conn).is_none());
    }

    #[test]
    fn manual_builds_http_and_socks_url() {
        let conn = open_db(Path::new(":memory:")).unwrap();
        settings::ensure_defaults(&conn).unwrap();
        settings::set_validated(&conn, "proxy.mode", "manual").unwrap();
        settings::set_validated(&conn, "proxy.host", "127.0.0.1").unwrap();
        settings::set_validated(&conn, "proxy.port", "8080").unwrap();
        assert_eq!(
            resolve_proxy_url(&conn).as_deref(),
            Some("http://127.0.0.1:8080")
        );
        settings::set_validated(&conn, "proxy.scheme", "socks5").unwrap();
        settings::set_validated(&conn, "proxy.user", "u").unwrap();
        settings::set_validated(&conn, "proxy.pass", "p@ss").unwrap();
        let url = resolve_proxy_url(&conn).unwrap();
        assert!(url.starts_with("socks5://u:p%40ss@127.0.0.1:8080"));
        assert!(!url.contains("p@ss"));
    }

    fn runtime_with(settings: &[(&str, &str)]) -> std::sync::Arc<HttpRuntime> {
        let conn = aidm_core::open_db(std::path::Path::new(":memory:")).unwrap();
        aidm_core::settings::ensure_defaults(&conn).unwrap();
        for (k, v) in settings {
            aidm_core::settings::set(&conn, k, v).unwrap();
        }
        let db = Mutex::new(conn);
        HttpRuntime::from_db(&db)
    }

    /// 代理适用范围：排除表与 only_for 都要真正改变"是否走代理"。
    #[test]
    fn bypass_and_protocol_scope_decide_proxy_use() {
        let rt = runtime_with(&[
            ("proxy.mode", "manual"),
            ("proxy.host", "127.0.0.1"),
            ("proxy.port", "7897"),
            ("proxy.bypass_hosts", "*.internal.test, direct.example"),
            ("proxy.only_for", "http"),
        ]);
        assert!(
            !rt.proxy_applies("http://a.internal.test/f"),
            "通配排除应直连"
        );
        assert!(
            !rt.proxy_applies("http://direct.example/f"),
            "精确排除应直连"
        );
        assert!(
            !rt.proxy_applies("https://other.example/f"),
            "only_for=http 时 https 直连"
        );
        assert!(rt.proxy_applies("http://other.example/f"), "其余走代理");

        let rt_all = runtime_with(&[
            ("proxy.mode", "manual"),
            ("proxy.host", "127.0.0.1"),
            ("proxy.port", "7897"),
        ]);
        assert!(rt_all.proxy_applies("https://other.example/f"));

        let rt_none = runtime_with(&[("proxy.mode", "none")]);
        assert!(
            !rt_none.proxy_applies("http://other.example/f"),
            "不用代理时一律直连"
        );
    }
}
