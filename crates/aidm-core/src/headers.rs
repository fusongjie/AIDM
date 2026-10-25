//! 每任务自定义请求头。
//!
//! 浏览器抓到的请求头按 `Name: value` 逐行存进下载记录，重放时原样发出。
//! 这里提供解析与校验：**只接受普通头，拒绝会破坏协议语义的头**，
//! 并挡住 CR/LF 头注入与超长取值。
//!
//! 文本格式：
//!
//! ```text
//! Sec-Fetch-Site: cross-site
//! Sec-Fetch-Mode: navigate
//! X-Api-Key: abc
//! ```
//!
//! 空行与 `#` 开头的注释行忽略。

/// 单条自定义头。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderLine {
    pub name: String,
    pub value: String,
}

/// 自定义头条数上限（浏览器一次请求的常规头数量级）。
pub const MAX_CUSTOM_HEADERS: usize = 32;
/// 头名长度上限。
pub const MAX_HEADER_NAME: usize = 64;
/// 头值长度上限。
pub const MAX_HEADER_VALUE: usize = 2048;

/// 解析失败原因（供 UI 显示与 IPC 错误码使用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// 缺少 `:` 分隔。
    MissingColon { line: usize },
    /// 头名为空。
    EmptyName { line: usize },
    /// 头名含非法字符（非 RFC 7230 token）。
    BadName { line: usize, name: String },
    /// 头名或头值含控制字符（CR/LF 注入）。
    ControlChar { line: usize },
    /// 头名/头值超长。
    TooLong { line: usize },
    /// 条数超上限。
    TooMany,
    /// 试图覆盖由引擎管理的头（Host/Range/Content-Length/…）。
    Managed { line: usize, name: String },
}

impl HeaderError {
    /// 稳定的错误码，供 IPC 回传（不暴露内部结构）。
    pub fn code(&self) -> &'static str {
        match self {
            HeaderError::MissingColon { .. } => "header_bad_line",
            HeaderError::EmptyName { .. } => "header_empty_name",
            HeaderError::BadName { .. } => "header_bad_name",
            HeaderError::ControlChar { .. } => "header_control_char",
            HeaderError::TooLong { .. } => "header_too_long",
            HeaderError::TooMany => "header_too_many",
            HeaderError::Managed { .. } => "header_managed",
        }
    }

    /// 出错的行号（1 起；条数超限时为首条超限行）。
    pub fn line(&self) -> usize {
        match self {
            HeaderError::MissingColon { line }
            | HeaderError::EmptyName { line }
            | HeaderError::BadName { line, .. }
            | HeaderError::ControlChar { line }
            | HeaderError::TooLong { line }
            | HeaderError::Managed { line, .. } => *line,
            HeaderError::TooMany => MAX_CUSTOM_HEADERS + 1,
        }
    }
}

/// 由引擎管理的头：客户端不得覆盖，否则会破坏 Range/Host 语义或引发请求走私。
///
/// 说明：`Cookie` / `User-Agent` / `Referer` 有专门字段承载（浏览器透传），
/// 这里一并拒绝，避免同一头出现两份。
const MANAGED: &[&str] = &[
    "host",
    "range",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "cookie",
    "cookie2",
    "user-agent",
    "referer",
    "accept-encoding",
    "accept-charset",
    "accept-language",
    "accept",
];

/// 该头是否由引擎管理。
pub fn is_managed_header(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    MANAGED.contains(&lower.as_str())
}

/// RFC 7230 `token`：`!#$%&'*+-.^_`|~` 与数字字母。
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// 解析自定义头文本块。
///
/// 逐行处理，遇到第一个非法行即返回错误（不做部分接受），避免"看起来生效了一半"。
pub fn parse_custom_headers(raw: &str) -> Result<Vec<HeaderLine>, HeaderError> {
    let mut out: Vec<HeaderLine> = Vec::new();
    for (idx, raw_line) in raw.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim_end_matches(['\r', '\n']);
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if out.len() >= MAX_CUSTOM_HEADERS {
            return Err(HeaderError::TooMany);
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            return Err(HeaderError::MissingColon { line: line_no });
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err(HeaderError::EmptyName { line: line_no });
        }
        if name.chars().any(|c| c.is_control()) || value.chars().any(|c| c.is_control()) {
            return Err(HeaderError::ControlChar { line: line_no });
        }
        if !is_token(name) {
            return Err(HeaderError::BadName {
                line: line_no,
                name: name.to_string(),
            });
        }
        if name.len() > MAX_HEADER_NAME || value.len() > MAX_HEADER_VALUE {
            return Err(HeaderError::TooLong { line: line_no });
        }
        if is_managed_header(name) {
            return Err(HeaderError::Managed {
                line: line_no,
                name: name.to_string(),
            });
        }
        // 同名头只保留第一次出现，避免歧义
        if out.iter().any(|h| h.name.eq_ignore_ascii_case(name)) {
            continue;
        }
        out.push(HeaderLine {
            name: name.to_string(),
            value: value.to_string(),
        });
    }
    Ok(out)
}

/// 把自定义头还原成可编辑文本（属性面板/编辑框回显）。
pub fn format_custom_headers(headers: &[HeaderLine]) -> String {
    headers
        .iter()
        .map(|h| format!("{}: {}", h.name, h.value))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_browser_style_block() {
        let raw = "# 浏览器抓到的头\nSec-Fetch-Site: cross-site\n\nSec-Fetch-Mode: navigate\nX-Api-Key: abc123\n";
        let got = parse_custom_headers(raw).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].name, "Sec-Fetch-Site");
        assert_eq!(got[0].value, "cross-site");
        assert_eq!(got[2].name, "X-Api-Key");
        assert_eq!(got[2].value, "abc123");
    }

    #[test]
    fn rejects_header_injection() {
        // 输入本身是"多行块"格式：CRLF 就是行分隔符，两行 = 两个头（这是既定语义）
        let two = parse_custom_headers("X-A: 1\r\nEvil: 2").unwrap();
        assert_eq!(two.len(), 2);
        assert_eq!(two[1].name, "Evil");

        // 真正要挡的是**残留在取值里的控制字符**：它们会被拼进请求行造成头注入
        assert_eq!(
            parse_custom_headers("X-A: 1\rEvil: 2"),
            Err(HeaderError::ControlChar { line: 1 })
        );
        assert_eq!(
            parse_custom_headers("X-A: 1\u{0}"),
            Err(HeaderError::ControlChar { line: 1 })
        );
        assert_eq!(
            parse_custom_headers("X-A: 1\u{7f}"),
            Err(HeaderError::ControlChar { line: 1 })
        );
        // 头名里也不允许
        assert_eq!(
            parse_custom_headers("X-A\u{1}: 1"),
            Err(HeaderError::ControlChar { line: 1 })
        );
    }

    #[test]
    fn rejects_managed_headers() {
        // 这些头一旦可覆盖，会破坏 Range/Host 语义或造成请求走私
        for bad in [
            "Host: evil.example",
            "Range: bytes=0-1",
            "Content-Length: 999",
            "Transfer-Encoding: chunked",
            "Connection: close",
            "Cookie: a=1",
            "User-Agent: x",
            "Referer: y",
            "Accept-Encoding: gzip",
            "Accept: text/html",
        ] {
            let err = parse_custom_headers(bad).unwrap_err();
            assert_eq!(err.code(), "header_managed", "{bad} 应被拒绝");
        }
    }

    #[test]
    fn rejects_malformed_lines() {
        assert_eq!(
            parse_custom_headers("NoColonHere"),
            Err(HeaderError::MissingColon { line: 1 })
        );
        assert_eq!(
            parse_custom_headers(": value"),
            Err(HeaderError::EmptyName { line: 1 })
        );
        assert_eq!(
            parse_custom_headers("Bad Name: v"),
            Err(HeaderError::BadName {
                line: 1,
                name: "Bad Name".into()
            })
        );
        assert_eq!(
            parse_custom_headers(&format!("X-Long: {}", "a".repeat(MAX_HEADER_VALUE + 1))),
            Err(HeaderError::TooLong { line: 1 })
        );
    }

    #[test]
    fn enforces_count_limit_and_dedupes() {
        let many = (0..=MAX_CUSTOM_HEADERS)
            .map(|i| format!("X-H{i}: v"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(parse_custom_headers(&many), Err(HeaderError::TooMany));
        // 同名只保留第一条
        let dup = parse_custom_headers("X-A: 1\nx-a: 2").unwrap();
        assert_eq!(dup.len(), 1);
        assert_eq!(dup[0].value, "1");
    }

    #[test]
    fn formats_back_to_text() {
        let got = parse_custom_headers("X-A: 1\nX-B: 2").unwrap();
        assert_eq!(format_custom_headers(&got), "X-A: 1\nX-B: 2");
        assert!(parse_custom_headers("").unwrap().is_empty());
    }
}
