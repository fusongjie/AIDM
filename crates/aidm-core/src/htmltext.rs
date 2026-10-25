//! HTML 实体反解：粘贴来的链接经常带 `&amp;` 这类转义。
//!
//! 下载站把链接写进 HTML 时 `&` 会被转义成 `&amp;`。这类串原样入库的后果是可观测的：
//! - `dn=` 变成参数名 `amp;dn` → 文件名丢失，回退成 `download.bin`；
//! - `tr=` 同理 → **tracker 全部丢失**，只剩 DHT；DHT 不通时任务永久停在 `connecting`。
//!
//! 所以链接收口（`Manager::add_spec`）必须先把实体还原成真实字符。这里只处理链接里
//! 会出现的五个命名实体与数字实体，不做完整 HTML 解析（不需要，也不该顺手扩大）。

use std::borrow::Cow;

/// 把 `&amp;` / `&#38;` / `&#x26;` 这类实体还原成真实字符；没有 `&` 时零拷贝。
pub fn unescape_entities(s: &str) -> Cow<'_, str> {
    if !s.contains('&') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        match take_entity(tail) {
            Some((ch, used)) => {
                out.push(ch);
                rest = &tail[used..];
            }
            None => {
                // 不是实体：保留原字符，继续从下一个字节扫描。
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// 识别 `tail` 开头的实体，返回（字符，消耗的字节数）。
fn take_entity(tail: &str) -> Option<(char, usize)> {
    for (name, ch) in [
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&apos;", '\''),
    ] {
        if tail.len() >= name.len()
            && tail.is_char_boundary(name.len())
            && tail[..name.len()].eq_ignore_ascii_case(name)
        {
            return Some((ch, name.len()));
        }
    }
    // 数字实体：`&#38;`（十进制）与 `&#x26;`（十六进制）。
    let semi = tail.find(';')?;
    if semi > 12 {
        return None;
    }
    let digits = tail[1..semi].strip_prefix('#')?;
    let (radix, digits) = match digits.strip_prefix(['x', 'X']) {
        Some(d) => (16, d),
        None => (10, digits),
    };
    if digits.is_empty() {
        return None;
    }
    let code = u32::from_str_radix(digits, radix).ok()?;
    char::from_u32(code).map(|c| (c, semi + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_entities_are_unescaped() {
        assert_eq!(unescape_entities("a&amp;b"), "a&b");
        assert_eq!(unescape_entities("&lt;x&gt;"), "<x>");
        assert_eq!(unescape_entities("&quot;q&quot;"), "\"q\"");
        assert_eq!(unescape_entities("&apos;s&apos;"), "'s'");
    }

    #[test]
    fn numeric_entities_are_unescaped() {
        assert_eq!(unescape_entities("a&#38;b"), "a&b");
        assert_eq!(unescape_entities("a&#x26;b"), "a&b");
        assert_eq!(unescape_entities("&#X26;"), "&");
    }

    #[test]
    fn plain_text_is_borrowed_and_bare_ampersand_survives() {
        assert!(matches!(
            unescape_entities("no entity here"),
            Cow::Borrowed(_)
        ));
        assert_eq!(unescape_entities("a & b"), "a & b");
        assert_eq!(unescape_entities("&notanentity;"), "&notanentity;");
        assert_eq!(unescape_entities("100% &"), "100% &");
    }

    #[test]
    fn delimited_payload_needs_the_second_pass() {
        // 封装可能把**已经 HTML 转义**的 magnet 直接 base64 进载荷：解码之后
        // `&amp;` 还在（外层还原够不到内层），所以链接收口必须"解码前一次 + 解码后再一次"。
        // 少这一次，`dn` 就变成参数名 `amp;dn`，文件名与 `tr` 一起丢。
        let decoded = "magnet:?xt=urn:btih:abc&amp;dn=a.mp4&amp;tr=http%3A%2F%2Ft%2Fa";
        assert!(decoded.contains("&amp;"), "解码后的载荷里实体仍在");
        assert_eq!(
            unescape_entities(decoded).as_ref(),
            "magnet:?xt=urn:btih:abc&dn=a.mp4&tr=http%3A%2F%2Ft%2Fa"
        );
    }

    #[test]
    fn magnet_with_escaped_separators_keeps_dn_and_tr() {
        let escaped = "magnet:?xt=urn:btih:abc&amp;dn=a.mp4&amp;tr=http%3A%2F%2Ft.example%2Fa";
        let fixed = unescape_entities(escaped);
        assert_eq!(
            fixed.as_ref(),
            "magnet:?xt=urn:btih:abc&dn=a.mp4&tr=http%3A%2F%2Ft.example%2Fa"
        );
    }
}
