//! 链接封装解码：专用链、裸地址封装、带标记地址封装、网盘资源标识。
//!
//! 这些**不是传输协议**，而是第三方工具对真实 URL 的一层编码外壳；
//! 去掉外壳后仍然是一个 `http(s)://`、`ftp://`、`magnet:` 或 `ed2k://` 地址，
//! 走既有内核下载。所以这里只需要一个纯函数解码器，并在 `add` 时先解码再校验。
//!
//! 支持的封装形式（宽容解析，兼容多种变体）：
//!
//! | 类型 | 载荷（Base64 解码后） |
//! |---|---|
//! | 专用链 | `AA<真实URL>ZZ` |
//! | 早期专用链 | 同专用链 |
//! | 裸地址封装 | `<真实URL>` |
//! | 带标记封装 | `[TAG]<真实URL>[TAG]`（也接受无方括号） |
//! | 网盘资源标识 | `<资源哈希>|<文件名>|<字节数>` |

/// 解码结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLink {
    /// 真实地址；网盘资源标识这类没有直链的载荷为 `None`。
    pub url: Option<String>,
    /// 面向用户的说明（例如"该链接依赖已停运的服务"）。
    pub note: Option<String>,
}

impl DecodedLink {
    fn url(url: impl Into<String>) -> Self {
        Self {
            url: Some(url.into()),
            note: None,
        }
    }
}

/// 该 scheme 是否属于本模块处理的封装协议。
pub fn is_wrapped_scheme(raw: &str) -> bool {
    let s = raw.trim().to_ascii_lowercase();
    WRAPPED.iter().any(|p| s.starts_with(p))
}

/// 顺序无关：`starts_with` 是精确前缀匹配，长短前缀各自独立。
const WRAPPED: &[&str] = &[
    "thunder://",
    "thunders://",
    "qqdl://",
    "flashget://",
    "fs2you://",
];

/// 解码任意封装链接。非封装链接返回 `Ok(None)`，由调用方按普通 URL 处理。
pub fn decode_link(raw: &str) -> Result<Option<DecodedLink>, String> {
    let s = raw.trim();
    let lower = s.to_ascii_lowercase();
    for scheme in WRAPPED {
        if let Some(rest) = lower.strip_prefix(scheme) {
            // 用原始串里对应的长度切，避免大小写转换影响载荷
            let payload = &s[s.len() - rest.len()..];
            return Ok(Some(decode_payload(scheme, payload)?));
        }
    }
    Ok(None)
}

fn decode_payload(scheme: &str, payload: &str) -> Result<DecodedLink, String> {
    let payload = payload.trim().trim_end_matches(['/', '=']).to_string();
    // Base64 载荷可能带 URL-safe 变体与空白
    let normalized: String = payload
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let bytes = base64_decode(&normalized).map_err(|_| "link_decode_failed".to_string())?;
    let text = String::from_utf8_lossy(&bytes).trim().to_string();
    if text.is_empty() {
        return Err("link_decode_empty".into());
    }
    match scheme {
        // 早期专用链：载荷格式与专用链相同。界面的剪贴板嗅探早已覆盖，
        // 引擎这边也必须认，否则会出现"抓得到、下不了"。
        "thunder://" | "thunders://" => {
            let inner = strip_markers(&text, "AA", "ZZ");
            let url = extract_url(&inner).ok_or_else(|| "link_decode_failed".to_string())?;
            Ok(DecodedLink::url(url))
        }
        "qqdl://" => {
            let url = extract_url(&text).ok_or_else(|| "link_decode_failed".to_string())?;
            Ok(DecodedLink::url(url))
        }
        "flashget://" => {
            let inner = strip_markers(&text, "[FLASHGET]", "[FLASHGET]");
            let inner = strip_markers(&inner, "FLASHGET", "FLASHGET");
            let url = extract_url(&inner).ok_or_else(|| "link_decode_failed".to_string())?;
            Ok(DecodedLink::url(url))
        }
        "fs2you://" => {
            // 网盘资源标识：<hash>|<文件名>|<字节数>，不是直链
            let body = text.strip_prefix("fs2you://").unwrap_or(&text);
            let mut parts = body.split('|');
            let hash = parts.next().unwrap_or("").trim();
            let name = parts.next().unwrap_or("").trim();
            let size = parts.next().unwrap_or("").trim();
            if hash.is_empty() {
                return Err("link_decode_failed".into());
            }
            let mut note = format!("网盘资源哈希 {hash}");
            if !name.is_empty() {
                note.push_str(&format!("，文件名 {name}"));
            }
            if !size.is_empty() {
                note.push_str(&format!("，声明大小 {size} 字节"));
            }
            note.push_str("；该服务已停运，无法直接下载");
            Ok(DecodedLink {
                url: None,
                note: Some(note),
            })
        }
        other => Err(format!("link_decode_unsupported: {other}")),
    }
}

/// 去掉首尾标记（大小写不敏感地匹配给定字面量）。
fn strip_markers(s: &str, prefix: &str, suffix: &str) -> String {
    let mut t = s.trim();
    let upper = t.to_ascii_uppercase();
    if upper.starts_with(&prefix.to_ascii_uppercase()) {
        // 标记可能带方括号变体，逐字符切更稳：按长度切
        t = &t[prefix.len().min(t.len())..];
    }
    let upper = t.to_ascii_uppercase();
    if upper.ends_with(&suffix.to_ascii_uppercase()) {
        let cut = t.len().saturating_sub(suffix.len());
        t = &t[..cut];
    }
    t.trim().to_string()
}

/// 从文本里取出**最靠前**的可下载地址（容忍前后残留）。
///
/// 除了 http/ftp，也认 `magnet:` 与 `ed2k://` —— 专用链同样被第三方站点用来包
/// 这两种（绕开链接过滤）。它们没有 `//` 之后的主机部分，所以同一套"找 scheme 再截到
/// 空白"的写法就能覆盖；取**最靠前**而非按 scheme 优先级，是为了保持"第一个地址"
/// 这个直觉 —— 文本里先出现的那个才是作者真正想给的。
fn extract_url(s: &str) -> Option<String> {
    let lower = s.to_ascii_lowercase();
    let mut best: Option<(usize, String)> = None;
    for scheme in [
        "http://", "https://", "ftp://", "ftps://", "magnet:?", "ed2k://",
    ] {
        let Some(idx) = lower.find(scheme) else {
            continue;
        };
        let tail = &s[idx..];
        // 截断到空白或控制字符
        let end = tail
            .find(|c: char| c.is_whitespace() || c.is_control())
            .unwrap_or(tail.len());
        let url = tail[..end].trim_end_matches(['\0']).to_string();
        if url.len() <= scheme.len() {
            continue;
        }
        let better = match &best {
            None => true,
            Some((seen, _)) => idx < *seen,
        };
        if better {
            best = Some((idx, url));
        }
    }
    best.map(|(_, url)| url)
}

/// 标准 Base64 解码（容忍缺失的 `=` 填充；拒绝非法字符）。
fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = input.bytes().filter(|b| *b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, b) in chunk.iter().enumerate() {
            let v = val(*b).ok_or(())?;
            n |= (v as u32) << (6 * (3 - i));
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用编码器：与解码器互逆，用来构造已知向量。
    fn b64(input: &str) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let data = input.as_bytes();
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(T[(n >> 18) as usize & 63] as char);
            out.push(T[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(T[(n >> 6) as usize & 63] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(T[n as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    #[test]
    fn decodes_delimited_links() {
        let inner = "AAhttp://example.com/a.zipZZ";
        let link = format!("thunder://{}", b64(inner));
        let got = decode_link(&link).unwrap().unwrap();
        assert_eq!(got.url.as_deref(), Some("http://example.com/a.zip"));
        // 大小写不敏感的 scheme
        let upper = format!("THUNDER://{}", b64(inner));
        assert_eq!(
            decode_link(&upper).unwrap().unwrap().url.as_deref(),
            Some("http://example.com/a.zip")
        );
        // 载荷带 `=` 填充也要能解
        let padded = b64("AAhttp://example.com/b.rarZZ");
        assert_eq!(
            decode_link(&format!("thunder://{padded}"))
                .unwrap()
                .unwrap()
                .url
                .as_deref(),
            Some("http://example.com/b.rar")
        );
    }

    #[test]
    fn decodes_legacy_delimited_links_the_same_way() {
        // 早期专用链写法：载荷与常规专用链相同。
        // 剪贴板嗅探一直认它，引擎不认就会"抓得到、下不了"。
        let inner = "AAhttps://example.com/c.binZZ";
        let got = decode_link(&format!("thunders://{}", b64(inner)))
            .unwrap()
            .unwrap();
        assert_eq!(got.url.as_deref(), Some("https://example.com/c.bin"));
        assert!(is_wrapped_scheme("THUNDERS://x"));
        assert!(is_wrapped_scheme("thunder://x"));
    }

    #[test]
    fn delimited_link_can_carry_magnet_or_ed2k() {
        // 第三方站点常把 magnet/ed2k 包进专用链绕过链接过滤；
        // 解码器若只认 http/ftp，这类链接会以 link_decode_failed 被丢掉。
        let magnet = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=a.iso";
        let got = decode_link(&format!("thunder://{}", b64(&format!("AA{magnet}ZZ"))))
            .unwrap()
            .unwrap();
        assert_eq!(got.url.as_deref(), Some(magnet));

        let ed2k = "ed2k://|file|a.iso|1024|0123456789abcdef0123456789abcdef|/";
        let got = decode_link(&format!("thunder://{}", b64(&format!("AA{ed2k}ZZ"))))
            .unwrap()
            .unwrap();
        assert_eq!(got.url.as_deref(), Some(ed2k));
    }

    #[test]
    fn extract_url_takes_the_earliest_address() {
        // 位置优先，而不是 scheme 优先级：文本里先出现的才是作者想给的
        assert_eq!(
            extract_url("见 https://first.test/a 或 magnet:?xt=urn:btih:abc").as_deref(),
            Some("https://first.test/a")
        );
        assert_eq!(
            extract_url("magnet:?xt=urn:btih:abc 然后 https://later.test/a").as_deref(),
            Some("magnet:?xt=urn:btih:abc")
        );
    }

    #[test]
    fn decodes_raw_and_tagged_wrappers() {
        let u = "https://cdn.example.com/f.iso";
        assert_eq!(
            decode_link(&format!("qqdl://{}", b64(u)))
                .unwrap()
                .unwrap()
                .url
                .as_deref(),
            Some(u)
        );
        let fg = format!("[FLASHGET]{u}[FLASHGET]");
        assert_eq!(
            decode_link(&format!("flashget://{}", b64(&fg)))
                .unwrap()
                .unwrap()
                .url
                .as_deref(),
            Some(u)
        );
        // 无方括号的变体
        let fg2 = format!("FLASHGET{u}FLASHGET");
        assert_eq!(
            decode_link(&format!("flashget://{}", b64(&fg2)))
                .unwrap()
                .unwrap()
                .url
                .as_deref(),
            Some(u)
        );
    }

    #[test]
    fn decodes_fs2you_without_claiming_a_direct_url() {
        let payload = "fs2you://abc123hash|movie.mkv|1073741824";
        let got = decode_link(&format!("fs2you://{}", b64(payload)))
            .unwrap()
            .unwrap();
        assert!(got.url.is_none(), "网盘哈希不是直链，不能假装能下");
        let note = got.note.unwrap();
        assert!(note.contains("abc123hash"));
        assert!(note.contains("movie.mkv"));
        assert!(note.contains("已停运"), "应说明服务不可用: {note}");
    }

    #[test]
    fn ignores_plain_urls_and_reports_bad_payloads() {
        assert!(decode_link("https://example.com/a.bin").unwrap().is_none());
        assert!(decode_link("ftp://example.com/a.bin").unwrap().is_none());
        // 载荷不是合法 Base64
        assert_eq!(
            decode_link("thunder://***not-base64***").unwrap_err(),
            "link_decode_failed"
        );
        // 解出来但没有可识别 URL
        assert_eq!(
            decode_link(&format!("qqdl://{}", b64("nothing useful here"))).unwrap_err(),
            "link_decode_failed"
        );
        assert!(is_wrapped_scheme("Thunder://xx"));
        assert!(!is_wrapped_scheme("https://x"));
    }

    #[test]
    fn base64_roundtrip_matches_known_vectors() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64_decode("TWFu").unwrap(), b"Man");
        assert_eq!(base64_decode("TWE=").unwrap(), b"Ma");
        assert!(base64_decode("!!!!").is_err());
    }
}
