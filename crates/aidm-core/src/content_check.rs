//! 「错误页冒充文件」的识别：内容类型与地址上的文件名矛盾时判为不可用。
//!
//! 背景：部分镜像站会对特定 UA 返回 **200 + `text/html`** 的反爬提示页，
//! 而普通浏览器 UA 得到的是 `206 + application/octet-stream`。若只看状态码与
//! `Content-Range`，提示页会被当成合法候选 → 降级单线程 → **5 KB 的 HTML
//! 被存成 .iso 并判定完成**。那比"明确失败"更糟：用户以为下好了。
//!
//! 判定要保守：**只否定"确定矛盾"的情况**，拿不准一律放行（不误伤真正的 HTML 下载）。

/// 这些扩展名本来就可能是 HTML —— 地址以它们结尾时不参与判定。
const HTML_EXTS: &[&str] = &[
    "html", "htm", "xhtml", "shtml", "php", "php3", "php4", "php5", "phtml", "asp", "aspx", "jsp",
    "jspx", "do", "action", "cgi", "pl",
];

/// 内容类型是否是 HTML 家族。
pub fn is_html_content_type(content_type: Option<&str>) -> bool {
    let Some(ct) = content_type else {
        return false;
    };
    // 只看 `;` 之前的媒体类型，忽略 `charset=...`
    let media = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    media == "text/html" || media == "application/xhtml+xml"
}

/// 地址上最后一个路径段的扩展名（小写，无点）。没有扩展名时返回 `None`。
///
/// **必须先剥掉 scheme 与 authority**：否则 `https://m.test/` 的"最后一段"会变成主机名
/// `m.test`，把 TLD `test` 当成扩展名 —— 那会把一个纯首页误判成"错误页"。
pub fn url_extension(url: &str) -> Option<String> {
    let s = url.trim();
    let rest = match s.split_once("://") {
        Some((_, r)) => r,
        None => s,
    };
    // 没有 `/` 说明只有主机名，不存在路径段
    let path = match rest.find('/') {
        Some(i) => &rest[i..],
        None => return None,
    };
    let no_tail = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path)
        .trim_end_matches('/');
    if no_tail.is_empty() {
        return None;
    }
    let last = no_tail.rsplit('/').next()?;
    let (_, ext) = last.rsplit_once('.')?;
    let ext = ext.trim().to_ascii_lowercase();
    if ext.is_empty() || ext.len() > 8 || !ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(ext)
}

/// 该响应是否"确定是错误页冒充文件"。
///
/// 三个条件同时成立才判真：
/// 1. 内容类型是 HTML；
/// 2. 地址最后一个路径段**有**扩展名（没扩展名就无从判断，放行）；
/// 3. 那个扩展名不是 HTML 家族（`.iso` 收到 HTML 就是错误页）。
pub fn looks_like_error_page(content_type: Option<&str>, url: &str) -> bool {
    if !is_html_content_type(content_type) {
        return false;
    }
    match url_extension(url) {
        None => false,
        Some(ext) => !HTML_EXTS.contains(&ext.as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_served_as_html_is_an_error_page() {
        // 本次故障的原始形态
        assert!(looks_like_error_page(
            Some("text/html; charset=utf-8"),
            "https://mirrors.sjtug.sjtu.edu.cn/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-dvd.iso"
        ));
        assert!(looks_like_error_page(
            Some("TEXT/HTML"),
            "http://m.test/a.zip?token=1#frag"
        ));
        assert!(looks_like_error_page(
            Some("application/xhtml+xml"),
            "https://m.test/x.tar.gz"
        ));
    }

    #[test]
    fn real_html_downloads_are_not_touched() {
        for url in [
            "https://m.test/index.html",
            "https://m.test/page.htm",
            "https://m.test/gen.php",
            "https://m.test/x.aspx?id=1",
            "https://m.test/a.shtml",
        ] {
            assert!(
                !looks_like_error_page(Some("text/html; charset=utf-8"), url),
                "真正的 HTML 地址不该被判为错误页: {url}"
            );
        }
    }

    #[test]
    fn stays_conservative_when_it_cannot_tell() {
        // 没有内容类型 → 放行（探测可能来自不带该头的服务器）
        assert!(!looks_like_error_page(None, "https://m.test/a.iso"));
        // 没有扩展名 → 无从判断，放行
        assert!(!looks_like_error_page(
            Some("text/html"),
            "https://m.test/download"
        ));
        assert!(!looks_like_error_page(Some("text/html"), "https://m.test/"));
        // 二进制类型 → 放行
        assert!(!looks_like_error_page(
            Some("application/octet-stream"),
            "https://m.test/a.iso"
        ));
        // 文本类型不是 HTML → 放行（例如纯文本清单）
        assert!(!looks_like_error_page(
            Some("text/plain"),
            "https://m.test/CHECKSUM"
        ));
    }

    #[test]
    fn extension_parsing_handles_odd_shapes() {
        assert_eq!(
            url_extension("https://m.test/a.iso").as_deref(),
            Some("iso")
        );
        assert_eq!(
            url_extension("https://m.test/dir.v2/a.tar.gz").as_deref(),
            Some("gz")
        );
        assert_eq!(
            url_extension("https://m.test/a.iso?x=1").as_deref(),
            Some("iso")
        );
        assert_eq!(url_extension("https://m.test/dir/").as_deref(), None);
        assert_eq!(url_extension("https://m.test/name").as_deref(), None);
        // 主机名里的点不是扩展名（回归：曾把首页判成错误页）
        assert_eq!(url_extension("https://m.test/").as_deref(), None);
        assert_eq!(url_extension("https://m.test").as_deref(), None);
        assert_eq!(
            url_extension("https://mirrors.nju.edu.cn/").as_deref(),
            None
        );
        // 超长"扩展名"多半是别的东西，不当扩展名
        assert_eq!(
            url_extension("https://m.test/a.abcdefghijkl").as_deref(),
            None
        );
    }
}
