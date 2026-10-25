//! MirrorBrain 风格的 `.mirrorlist` 页面解析。
//!
//! 实测：TDF 与 KDE 的 `.mirrorlist` **都是 HTML 页面**，
//! 里面是各镜像上的**完整文件地址**，并不是"镜像基础地址列表"（那样才需要与原地址的
//! 相对路径拼接）。所以判定规则只有一条：
//!
//! > 是绝对 `http(s)` 地址，**且以同一个文件名结尾**。
//!
//! 这条规则对 HTML 与纯文本都成立，也不需要理解页面的其余结构 —— 与 Metalink 一样，
//! 我们只取自己认得出的东西，认不出就不给。
//!
//! **按文件名过滤是必须的**：同一页面里还有同目录的其它产物（`.sig`、语言包、其它
//! 版本），实测 KDE 那份 90 个地址里只有 39 个是目标文件。

/// 一次最多返回多少条。来源池本来只取前几条，这里只是别让内存被超大页面拖走。
pub const MAX_URLS: usize = 64;

/// 从页面正文里抽出目标文件在各镜像上的地址（去重、保持出现顺序）。
pub fn parse(text: &str, file_name: &str) -> Vec<String> {
    let want = file_name.trim();
    if want.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(i) = find_scheme(rest) {
        let after = &rest[i..];
        let end = after.find(|c: char| is_delimiter(c)).unwrap_or(after.len());
        let token = trim_trailing_junk(&after[..end]);
        if token.len() > want.len() && token.ends_with(want) && is_http_url(token) {
            let owned = token.to_string();
            if !out.iter().any(|u| u == &owned) {
                out.push(owned);
                if out.len() >= MAX_URLS {
                    break;
                }
            }
        }
        // 从令牌之后继续，避免在同一段文本里反复匹配到同一个 scheme
        rest = &after[end.max(1)..];
    }
    out
}

/// 地址里不可能出现的字符即分隔符。
fn is_delimiter(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '<' | '>' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '\\' | '`' | '|'
        )
}

/// 剥掉 URL 尾部可能粘上的句读（HTML 里地址常被 `,`/`;`/中文标点包着）。
fn trim_trailing_junk(token: &str) -> &str {
    const JUNK: &[char] = &[
        ',', ';', ':', '.', '!', '?', '，', '。', '；', '：', '！', '？', '、',
    ];
    token.trim_end_matches(JUNK)
}

fn find_scheme(s: &str) -> Option<usize> {
    let lower = s.to_ascii_lowercase();
    match (lower.find("https://"), lower.find("http://")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn is_http_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    let Some(rest) = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
    else {
        return false;
    };
    !rest.is_empty() && !rest.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(name: &str) -> String {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mirrorlist")
            .join(name);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display()))
    }

    #[test]
    fn parses_the_real_tdf_mirrorlist() {
        let name = "LibreOffice_26.8.1_Linux_x86-64_deb.tar.gz";
        let got = parse(&fixture("tdf-libreoffice.mirrorlist"), name);
        assert!(got.len() >= 20, "应当抽出很多镜像：{}", got.len());
        for u in &got {
            assert!(u.ends_with(name), "只留目标文件: {u}");
            assert!(u.starts_with("https://") || u.starts_with("http://"), "{u}");
        }
        assert!(
            got[0].contains("mirrors.nju.edu.cn"),
            "保持页面里的出现顺序: {}",
            got[0]
        );
    }

    #[test]
    fn parses_the_real_kde_mirrorlist_and_filters_siblings() {
        // KDE 那份页面里有 90 个地址，只有 39 个是目标文件（其余是同目录其它产物）。
        // 这条用例守的就是"按文件名过滤"这一步。
        let name = "aurorae-6.5.0.tar.xz";
        let text = fixture("kde-plasma.mirrorlist");
        let got = parse(&text, name);
        assert!(got.len() >= 20, "{}", got.len());
        for u in &got {
            assert!(u.ends_with(name), "{u}");
        }
        // 页面里的地址总数远多于目标文件的地址数（其余是同目录其它产物与页面链接），
        // 说明过滤真的在起作用，而不是碰巧全中。
        let raw_hits = text.matches("http").count();
        assert!(
            raw_hits > got.len() * 2,
            "页面地址数 {raw_hits} 应当远多于目标文件地址数 {}",
            got.len()
        );
        // 兄弟文件（校验文件/签名）不能被当成目标文件
        assert!(parse(&text, "aurorae-6.5.0.tar.xz.sig").is_empty());
    }

    #[test]
    fn works_on_plain_text_lists_too() {
        let text = "\
# mirrors for a.iso
https://m1.test/pub/a.iso
https://m2.test/x/a.iso   <- 更快
https://m1.test/pub/a.iso
https://m1.test/pub/a.iso.sig
https://m9.test/other/b.iso
";
        let got = parse(text, "a.iso");
        assert_eq!(
            got,
            vec!["https://m1.test/pub/a.iso", "https://m2.test/x/a.iso"],
            "去重、剔除兄弟文件、保持顺序"
        );
    }

    #[test]
    fn ignores_non_http_and_trailing_punctuation() {
        let text = "ftp://m.test/a.iso, https://m2.test/a.iso。 其他 https://m3.test/a.iso)";
        let got = parse(text, "a.iso");
        assert_eq!(
            got,
            vec!["https://m2.test/a.iso", "https://m3.test/a.iso"],
            "ftp 不认；中英文句读要剥掉"
        );
    }

    #[test]
    fn fails_closed_on_empty_or_mismatched_input() {
        assert!(parse("", "a.iso").is_empty());
        assert!(parse("no urls here", "a.iso").is_empty());
        assert!(parse("https://m.test/a.iso", "").is_empty());
        assert!(parse("https://m.test/b.iso", "a.iso").is_empty());
        // 只有域名、没有文件名的地址不算
        assert!(parse("https://m.test/", "a.iso").is_empty());
    }

    #[test]
    fn caps_the_result() {
        let mut text = String::new();
        for i in 0..(MAX_URLS + 20) {
            text.push_str(&format!("https://m{i}.test/a.iso "));
        }
        assert_eq!(parse(&text, "a.iso").len(), MAX_URLS);
    }
}
