//! 日志脱敏（开发文档 §11「安全与隐私基线：URL 查询串中的 token/sign 打码」）。
//!
//! 只作用于**写进日志的文本**，不改动任务记录本身：`url_orig` / `url_final` /
//! 分段 sidecar 里的 URL 必须保持原样，否则续传与条件请求会失效。
//! 调用点是 `model::log_event`（events 表的唯一写入口），所以任何调用方
//! 都不可能绕过；引擎另有两条直接打到进程日志的 URL 也走这里。
//!
//! 判定取向是「宁可多打码」：查询串参数名归一化（小写、去掉 `_`/`-`/`.`）后
//! **包含**任一敏感词就打码。下载 URL 里出现 `design=`、`keynote=` 这类
//! 误报的代价只是日志少一个值，而漏打码的代价是凭据落盘。

use std::borrow::Cow;

/// 打码后的占位符。固定长度，不泄露原文长度。
const MASK: &str = "***";

/// 出现在 URL 之后即视为 URL 已结束的字符（含中文全角标点，避免把后文吞进 URL）。
const TRAILING_SEPARATORS: &str = "\"'<>()[]{},;，；。、：）】";

/// 敏感参数名片段（归一化后按「包含」匹配）。
const SENSITIVE: &[&str] = &[
    "token",
    "sign",
    "key",
    "auth",
    "secret",
    "password",
    "passwd",
    "pwd",
    "credential",
    "hmac",
    "ticket",
    "session",
    "cookie",
];

/// 参数名是否敏感。`X-Amz-Signature` / `access_token` / `AWSAccessKeyId` 都命中。
fn sensitive_key(raw: &str) -> bool {
    let norm: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    !norm.is_empty() && SENSITIVE.iter().any(|s| norm.contains(s))
}

/// `a=1&b=2` 形式的查询串：逐个参数判定，`&` 原样保留。
fn redact_params(query: &str) -> String {
    let mut out = String::with_capacity(query.len());
    let mut rest = query;
    while !rest.is_empty() {
        match rest.find('&') {
            Some(i) => {
                out.push_str(&redact_param(&rest[..i]));
                out.push('&');
                rest = &rest[i + 1..];
            }
            None => {
                out.push_str(&redact_param(rest));
                break;
            }
        }
    }
    out
}

fn redact_param(seg: &str) -> String {
    // 键名原样保留，只替换值；值是嵌套 URL 时继续往下脱敏。
    match seg.split_once('=') {
        Some((key, _)) if sensitive_key(key) => format!("{key}={MASK}"),
        Some((key, value)) if is_absolute_url(value) => format!("{key}={}", redact_url(value)),
        _ => seg.to_string(),
    }
}

fn is_absolute_url(s: &str) -> bool {
    let Some((scheme, _)) = s.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
}

/// 对单个 URL 脱敏：保留 scheme / host / path，打码敏感查询串与 userinfo 口令。
/// 不是 URL 的文本原样返回。
pub fn redact_url(url: &str) -> Cow<'_, str> {
    let Some((scheme, after)) = url.split_once("://") else {
        return Cow::Borrowed(url);
    };
    if !is_absolute_url(url) {
        return Cow::Borrowed(url);
    }
    // 权威段结束于第一个 `/`、`?`、`#`。
    let auth_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (auth_raw, tail) = after.split_at(auth_end);
    let (auth, had_userinfo) = match auth_raw.rsplit_once('@') {
        Some((userinfo, host)) => {
            let user = userinfo.split_once(':').map(|(u, _)| u).unwrap_or(userinfo);
            (format!("{user}:{MASK}@{host}"), true)
        }
        None => (auth_raw.to_string(), false),
    };
    let (path, query) = match tail.find(['?', '#']) {
        Some(i) => tail.split_at(i),
        None => (tail, ""),
    };
    let body = if query.is_empty() {
        String::new()
    } else {
        redact_params(&query[1..])
    };
    if !had_userinfo && body == query.get(1..).unwrap_or("") {
        return Cow::Borrowed(url);
    }
    if query.is_empty() {
        Cow::Owned(format!("{scheme}://{auth}{path}"))
    } else {
        Cow::Owned(format!("{scheme}://{auth}{path}{}{body}", &query[..1]))
    }
}

/// 一段可能夹带 URL 的自由文本（事件 detail、日志行）。
pub fn redact_text(text: &str) -> Cow<'_, str> {
    let mut out: Option<String> = None;
    let mut cursor = 0usize;
    let bytes = text.as_bytes();
    while let Some(at) = text[cursor..].find("://") {
        let sep = cursor + at;
        // 回退到 scheme 起始处。
        let mut start = sep;
        while start > 0 {
            let c = bytes[start - 1] as char;
            if c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.' {
                start -= 1;
            } else {
                break;
            }
        }
        if start == sep || !is_absolute_url(&text[start..]) {
            cursor = sep + 3;
            continue;
        }
        // URL 结束于空白或明显的分隔符（含全角标点，避免把后文中文吞进 URL）。
        let rest = &text[sep + 3..];
        let mut end = sep + 3;
        for (i, c) in rest.char_indices() {
            if c.is_whitespace() || TRAILING_SEPARATORS.contains(c) {
                end = sep + 3 + i;
                break;
            }
            end = sep + 3 + i + c.len_utf8();
        }
        let redacted = redact_url(&text[start..end]);
        if let Cow::Owned(r) = redacted {
            let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
            buf.push_str(&text[cursor..start]);
            buf.push_str(&r);
            cursor = end;
        } else {
            cursor = end;
        }
    }
    match out {
        Some(mut buf) => {
            buf.push_str(&text[cursor..]);
            Cow::Owned(buf)
        }
        None => Cow::Borrowed(text),
    }
}

/// 用户目录 token：出现即替换为 `~`（大小写不敏感按 ASCII 比较）。
const HOME_TOKENS: &[&str] = &["%USERPROFILE%", "%HOMEPATH%", "%HOME%", "${HOME}", "$HOME"];

/// 用户名段的路径标记（ASCII 小写比较）：命中后**丢弃**用户名及之前的路径。
const USER_ROOT_MARKERS: &[&str] = &["\\users\\", "/users/", "/home/"];

/// 用户文件路径脱敏：把用户目录替换为 `~`，丢弃用户名段，保留后续相对路径与文件名。
///
/// 例：`C:\Users\bob\Downloads\a.zip` → `~\Downloads\a.zip`；
/// `%USERPROFILE%\Downloads\a.zip` → `~\Downloads\a.zip`；
/// `/home/bob/x.iso` → `~/x.iso`。不含用户目录的路径原样返回。
///
/// 刻意**不**打码文件名：定位问题需要知道下载的是哪个文件，而用户名与盘符
/// 属于隐私面。判定取向与 [`redact_url`] 一致 —— 宁可多打码。
pub fn redact_path(path: &str) -> Cow<'_, str> {
    if path.is_empty() {
        return Cow::Borrowed(path);
    }
    // 索引靠 ASCII 小写副本对齐：`to_ascii_lowercase` 不改变字节长度（非 ASCII 原样）。
    let lower = path.to_ascii_lowercase();

    // 1) 字面 token（`%USERPROFILE%` / `$HOME`）。
    for tok in HOME_TOKENS {
        let t = tok.to_ascii_lowercase();
        if let Some(pos) = lower.find(&t) {
            let mut out = String::with_capacity(path.len());
            out.push_str(&path[..pos]);
            out.push('~');
            out.push_str(&path[pos + tok.len()..]);
            return Cow::Owned(out);
        }
    }

    // 2) 已展开的当前用户目录前缀。
    for var in ["USERPROFILE", "HOME"] {
        let Ok(home) = std::env::var(var) else {
            continue;
        };
        let home = home.trim_end_matches(['\\', '/']);
        if home.len() < 3 || !lower.starts_with(&home.to_ascii_lowercase()) {
            continue;
        }
        let mut out = String::with_capacity(path.len());
        out.push('~');
        out.push_str(&path[home.len()..]);
        return Cow::Owned(out);
    }

    // 3) 通用形态：任意 `...\Users\<名>\` / `/Users/<名>/` / `/home/<名>/`。
    for marker in USER_ROOT_MARKERS {
        let Some(pos) = lower.find(marker) else {
            continue;
        };
        let rest = &path[pos + marker.len()..];
        let end = rest.find(['\\', '/']).unwrap_or(rest.len());
        let mut out = String::with_capacity(path.len() - pos - marker.len());
        out.push('~');
        out.push_str(&rest[end..]);
        return Cow::Owned(out);
    }

    Cow::Borrowed(path)
}

/// 头名是否承载凭据（归一化后包含敏感词即命中，复用查询串那套判定）。
fn sensitive_header(name: &str) -> bool {
    sensitive_key(name)
}

/// 头值里可能夹带 URL 的头（值本身不敏感，但要按 URL 规则脱敏）。
fn url_header(name: &str) -> bool {
    let norm: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    matches!(
        norm.as_str(),
        "referer" | "referrer" | "origin" | "location" | "contentlocation" | "from"
    )
}

/// 请求头文本块脱敏（`Name: value` 逐行，保留原有行尾）。
///
/// 敏感头的**值整体**替换为 `***`（Cookie 可能是 `a=1; b=2` 多段，逐段判定没有意义）；
/// `Referer` 这类头保留结构、只按 URL 规则打码查询串。
pub fn redact_headers(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(raw.len());
    for line in raw.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        let eol = &line[body.len()..];
        match body.split_once(':') {
            Some((name, _value)) if sensitive_header(name) => {
                out.push_str(name);
                out.push_str(": ");
                out.push_str(MASK);
                out.push_str(eol);
            }
            Some((name, value)) if url_header(name) => {
                out.push_str(name);
                out.push_str(": ");
                out.push_str(&redact_url(value.trim_start()));
                out.push_str(eol);
            }
            _ => out.push_str(line),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(u: &str) -> String {
        redact_url(u).into_owned()
    }

    #[test]
    fn sensitive_query_values_are_masked() {
        assert_eq!(
            r("https://cdn.example/a.iso?token=deadbeef&size=1"),
            "https://cdn.example/a.iso?token=***&size=1"
        );
        assert_eq!(
            r("https://cdn.example/a.iso?X-Amz-Signature=abc%2Fdef&X-Amz-Expires=60"),
            "https://cdn.example/a.iso?X-Amz-Signature=***&X-Amz-Expires=60"
        );
        assert_eq!(
            r("http://h/p?a=1&access_token=x&b=2"),
            "http://h/p?a=1&access_token=***&b=2"
        );
        // 大小写与复合名同样命中（归一化后包含 `key`）。
        assert_eq!(
            r("http://h/p?AWSAccessKeyId=AKIA&Signature=s"),
            "http://h/p?AWSAccessKeyId=***&Signature=***"
        );
    }

    #[test]
    fn identity_parameters_are_kept() {
        // 磁力链的身份就是查询串，打码会毁掉日志的可读性。
        let m = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=a.iso";
        assert_eq!(r(m), m);
        // 签名之外的真实查询参数要留着。
        assert_eq!(r("https://h/d?id=7&part=3"), "https://h/d?id=7&part=3");
    }

    #[test]
    fn userinfo_password_and_fragment_are_handled() {
        assert_eq!(
            r("ftp://user:secret@ftp.example/pub/a.iso"),
            "ftp://user:***@ftp.example/pub/a.iso"
        );
        assert_eq!(
            r("https://h/p#access_token=x"),
            "https://h/p#access_token=***"
        );
    }

    #[test]
    fn nested_url_values_are_redacted_too() {
        // 值是明文 URL：继续按 URL 规则脱敏内层查询串。
        assert_eq!(
            r("http://h/p?next=https://other/q?sign=1&keep=2"),
            "http://h/p?next=https://other/q?sign=***&keep=2"
        );
        // 百分号编码过的内层 URL 不做二次解码：保留原样，宁可少改也不猜。
        let encoded = "magnet:?xt=urn:btih:abc&tr=https%3A%2F%2Ft%2Fa%3Ftoken%3D1";
        assert_eq!(r(encoded), encoded);
    }

    #[test]
    fn unrelated_urls_are_returned_borrowed() {
        assert!(matches!(
            redact_url("https://example.com/plain/path.iso"),
            Cow::Borrowed(_)
        ));
        // 非 URL 文本不动。
        assert!(matches!(redact_url("not a url"), Cow::Borrowed(_)));
    }

    #[test]
    fn free_text_keeps_structure_and_masks_urls() {
        assert_eq!(
            redact_text("created: https://h/a.iso?sign=1 (mirror)"),
            "created: https://h/a.iso?sign=*** (mirror)"
        );
        assert_eq!(
            redact_text("retry count=2 code=timeout"),
            "retry count=2 code=timeout"
        );
        assert_eq!(
            redact_text("ed2k://|file|a.iso|4478906368|E7C526499308841A4A6D116C857DB669|/"),
            "ed2k://|file|a.iso|4478906368|E7C526499308841A4A6D116C857DB669|/"
        );
        assert_eq!(
            redact_text("a https://x/1?token=a 和 https://y/2?token=b 都要"),
            "a https://x/1?token=*** 和 https://y/2?token=*** 都要"
        );
    }

    #[test]
    fn multibyte_text_is_not_split() {
        let s = "链接：https://h/中文.iso?auth=1，提取码";
        assert_eq!(redact_text(s), "链接：https://h/中文.iso?auth=***，提取码");
    }

    #[test]
    fn user_paths_are_reduced_to_home() {
        assert_eq!(
            redact_path(r"C:\Users\bob\Downloads\a.zip"),
            r"~\Downloads\a.zip"
        );
        assert_eq!(redact_path("/home/bob/x.iso"), "~/x.iso");
        assert_eq!(redact_path("/Users/bob/x.iso"), "~/x.iso");
        assert_eq!(
            redact_path(r"%USERPROFILE%\Downloads\a.zip"),
            r"~\Downloads\a.zip"
        );
        assert_eq!(redact_path("$HOME/dl/a.zip"), "~/dl/a.zip");
        assert_eq!(redact_path("${HOME}/dl/a.zip"), "~/dl/a.zip");
        // 大小写不同也命中（Windows 路径）。
        assert_eq!(redact_path(r"c:\users\bob\a.bin"), r"~\a.bin");
        // 不含用户目录的路径不动：盘符与自定义目录不是隐私面。
        assert!(matches!(redact_path(r"D:\media\a.zip"), Cow::Borrowed(_)));
        assert!(matches!(redact_path("a.zip"), Cow::Borrowed(_)));
        // 只替换用户段，绝不吞掉文件名。
        assert!(redact_path(r"C:\Users\bob\a.zip").ends_with(r"\a.zip"));
    }

    #[test]
    fn credential_headers_are_masked_but_structure_kept() {
        let raw =
            "Cookie: SID=abc; token=xyz\r\nContent-Length: 42\r\nReferer: https://h/p?sign=1\r\n";
        let got = redact_headers(raw);
        assert!(got.contains("Cookie: ***\r\n"), "{got}");
        assert!(got.contains("Content-Length: 42\r\n"), "{got}");
        assert!(got.contains("Referer: https://h/p?sign=***\r\n"), "{got}");
        // 行尾风格原样保留（CRLF 不被打乱）。
        assert_eq!(got.matches("\r\n").count(), 3);
    }

    #[test]
    fn authorization_and_key_headers_are_masked() {
        let got =
            redact_headers("Authorization: Basic dXNlcjpwYXNz\nX-Api-Key: k\nUser-Agent: AIDM\n");
        assert_eq!(
            got,
            "Authorization: ***\nX-Api-Key: ***\nUser-Agent: AIDM\n"
        );
        // 空块不 panic。
        assert_eq!(redact_headers(""), "");
    }
}
