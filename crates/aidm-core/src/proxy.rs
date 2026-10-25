//! AIDM 进程内代理配置（只读系统代理，永不写系统 / PAC）。
//!
//! 模式：`none` / `follow-system`（兼容旧值 `system`） / `manual`。
//! `follow-system` 仅读取 Windows 注册表 / WinHTTP，或非 Windows 的环境变量。

use std::net::{Ipv4Addr, Ipv6Addr};

/// 解析后的代理模式。`system` 与 `follow-system` 等价。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    None,
    FollowSystem,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyScheme {
    Http,
    Socks5,
}

/// 只读系统代理（host + port）。无系统代理时为 `None`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemProxy {
    pub host: String,
    pub port: u16,
}

pub fn parse_mode(raw: &str) -> Option<ProxyMode> {
    match raw.trim() {
        "none" => Some(ProxyMode::None),
        "follow-system" | "system" => Some(ProxyMode::FollowSystem),
        "manual" => Some(ProxyMode::Manual),
        _ => None,
    }
}

pub fn parse_scheme(raw: &str) -> Option<ProxyScheme> {
    match raw.trim() {
        "" | "http" | "https" => Some(ProxyScheme::Http),
        "socks5" | "socks" => Some(ProxyScheme::Socks5),
        _ => None,
    }
}

/// 校验 `proxy.host`：空值表示清除；拒绝 URL、端口混写、空白与非法字符。
pub fn validate_host(raw: &str) -> Result<(), String> {
    let host = raw.trim();
    if host.is_empty() {
        return Ok(());
    }
    if host.contains("://") {
        return Err("proxy_host_malformed".into());
    }
    if host.contains('/') || host.contains('@') || host.contains('?') || host.contains('#') {
        return Err("proxy_host_malformed".into());
    }
    if host.chars().any(|c| c.is_whitespace()) {
        return Err("proxy_host_malformed".into());
    }
    if host.starts_with('[') {
        let end = host
            .find(']')
            .ok_or_else(|| "proxy_host_malformed".to_string())?;
        if end != host.len() - 1 {
            return Err("proxy_host_malformed".into());
        }
        let inner = &host[1..end];
        if inner.parse::<Ipv6Addr>().is_err() {
            return Err("proxy_host_malformed".into());
        }
        return Ok(());
    }
    if host.contains(':') {
        // 端口必须走 proxy.port，host 里带端口视为格式错误
        return Err("proxy_host_malformed".into());
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    if is_dns_label_host(host) {
        return Ok(());
    }
    Err("proxy_host_malformed".into())
}

/// 校验 `proxy.port`：空值表示清除；必须是 1..=65535。
pub fn validate_port(raw: &str) -> Result<Option<u16>, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if s.starts_with('-') || s.starts_with('+') {
        return Err("proxy_port_malformed".into());
    }
    let port: u64 = s.parse().map_err(|_| "proxy_port_malformed".to_string())?;
    if port == 0 || port > u64::from(u16::MAX) {
        return Err("proxy_port_malformed".into());
    }
    Ok(Some(port as u16))
}

fn is_dns_label_host(host: &str) -> bool {
    if host.len() > 253 || host.is_empty() {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && label
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

/// 读取系统代理。本函数及本模块**只读**，不写注册表、不改 WinHTTP、不写 PAC。
pub fn read_system_proxy() -> Option<SystemProxy> {
    #[cfg(windows)]
    {
        win_read::read().or_else(read_env_proxy)
    }
    #[cfg(not(windows))]
    {
        read_env_proxy()
    }
}

/// 环境变量回退（CI / 非 Windows）。只读，不设置环境变量。
pub fn read_env_proxy() -> Option<SystemProxy> {
    const VARS: &[&str] = &[
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ];
    for var in VARS {
        if let Ok(val) = std::env::var(var) {
            if let Some(p) = parse_proxy_endpoint(&val) {
                return Some(p);
            }
        }
    }
    None
}

/// 解析 `host:port` / `http://host:port` / `socks5://user:pass@host:port`。
pub fn parse_proxy_endpoint(raw: &str) -> Option<SystemProxy> {
    let s = raw.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("direct") {
        return None;
    }
    let rest = s
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(s)
        .split(';')
        .next()
        .unwrap_or(s)
        .trim();
    // 丢掉 user:pass@
    let hostport = rest.rsplit('@').next().unwrap_or(rest);
    if let Some(inner) = hostport.strip_prefix('[') {
        let (host, rest) = inner.split_once(']')?;
        let port = rest.strip_prefix(':')?.parse().ok()?;
        if port == 0 {
            return None;
        }
        return Some(SystemProxy {
            host: format!("[{host}]"),
            port,
        });
    }
    // scheme=host:port（IE 列表）
    let hostport = hostport.split('=').next_back().unwrap_or(hostport).trim();
    let (host, port_s) = hostport.rsplit_once(':')?;
    let port = port_s.parse().ok()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    Some(SystemProxy {
        host: host.to_string(),
        port,
    })
}

#[cfg(windows)]
mod win_read {
    use super::{parse_proxy_endpoint, SystemProxy};

    /// 先 WinHTTP IE 配置，再 HKCU Internet Settings。绝不调用任何 Set / 写 API。
    pub fn read() -> Option<SystemProxy> {
        read_winhttp().or_else(read_registry)
    }

    fn read_winhttp() -> Option<SystemProxy> {
        use windows_sys::Win32::Foundation::GlobalFree;
        use windows_sys::Win32::Networking::WinHttp::{
            WinHttpGetIEProxyConfigForCurrentUser, WINHTTP_CURRENT_USER_IE_PROXY_CONFIG,
        };

        let mut cfg = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG {
            fAutoDetect: 0,
            lpszAutoConfigUrl: std::ptr::null_mut(),
            lpszProxy: std::ptr::null_mut(),
            lpszProxyBypass: std::ptr::null_mut(),
        };
        let ok = unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut cfg) };
        let proxy = if ok != 0 && !cfg.lpszProxy.is_null() {
            let s = unsafe { widestr(cfg.lpszProxy) };
            parse_proxy_endpoint(&s)
        } else {
            None
        };
        unsafe {
            if !cfg.lpszAutoConfigUrl.is_null() {
                GlobalFree(cfg.lpszAutoConfigUrl.cast());
            }
            if !cfg.lpszProxy.is_null() {
                GlobalFree(cfg.lpszProxy.cast());
            }
            if !cfg.lpszProxyBypass.is_null() {
                GlobalFree(cfg.lpszProxyBypass.cast());
            }
        }
        proxy
    }

    fn read_registry() -> Option<SystemProxy> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = hkcu
            .open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
            .ok()?;
        let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        if enabled == 0 {
            return None;
        }
        let server: String = key.get_value("ProxyServer").ok()?;
        parse_proxy_endpoint(&server)
    }

    unsafe fn widestr(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_aliases() {
        assert_eq!(parse_mode("none"), Some(ProxyMode::None));
        assert_eq!(parse_mode("follow-system"), Some(ProxyMode::FollowSystem));
        assert_eq!(parse_mode("system"), Some(ProxyMode::FollowSystem));
        assert_eq!(parse_mode("manual"), Some(ProxyMode::Manual));
        assert_eq!(parse_mode("pac"), None);
    }

    #[test]
    fn host_validation() {
        assert!(validate_host("").is_ok());
        assert!(validate_host("proxy.example.com").is_ok());
        assert!(validate_host("127.0.0.1").is_ok());
        assert!(validate_host("[::1]").is_ok());
        assert!(validate_host("http://evil").is_err());
        assert!(validate_host("host:8080").is_err());
        assert!(validate_host("bad host").is_err());
        assert!(validate_host("user@host").is_err());
    }

    #[test]
    fn port_validation() {
        assert_eq!(validate_port("").unwrap(), None);
        assert_eq!(validate_port("8080").unwrap(), Some(8080));
        assert!(validate_port("0").is_err());
        assert!(validate_port("-1").is_err());
        assert!(validate_port("65536").is_err());
        assert!(validate_port("abc").is_err());
    }

    #[test]
    fn parse_endpoints() {
        assert_eq!(
            parse_proxy_endpoint("http://127.0.0.1:8888"),
            Some(SystemProxy {
                host: "127.0.0.1".into(),
                port: 8888
            })
        );
        assert_eq!(
            parse_proxy_endpoint("socks5://u:p@10.0.0.1:1080"),
            Some(SystemProxy {
                host: "10.0.0.1".into(),
                port: 1080
            })
        );
        assert_eq!(
            parse_proxy_endpoint("http=corp:3128;https=corp:3128"),
            Some(SystemProxy {
                host: "corp".into(),
                port: 3128
            })
        );
    }

    #[test]
    fn env_proxy_is_read_only() {
        // 不写系统代理；仅确认读函数可安全调用。
        let _ = read_system_proxy();
    }
}
