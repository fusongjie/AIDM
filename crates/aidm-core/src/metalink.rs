//! Metalink（Metalink 3.0 / RFC 5854）的**有界**解析。
//!
//! 只取真正需要的四样东西：文件名、长度、**整文件 SHA-256**、镜像 URL；另外记录
//! 分片哈希的长度与条数（暂不参与校验）。
//!
//! **这不是通用 XML 解析器。** 遇到不认识的结构一律少给而不是猜：Metalink 由第三方
//! 生成，猜错就会把另一个文件当成同一份，后果是"下出一个拼错的包"。所以本模块
//! 只认双引号属性、只认闭合标签，任何异常都返回 `None`/空。
//!
//! 为什么它值得单独做：实测 openSUSE 的 `.metalink`（MirrorCache 生成）**同时**给出
//! 11 个镜像 URL、整文件 SHA-256 与 4 MiB 粒度的分片哈希 —— 一份文件就能同时解决
//! "去哪找镜像"和"怎么证明是同一份文件"两件事。而 AlmaLinux 的 ISO 实测**没有**
//! `.metalink`，所以它只是**多一条路**，不是替代 CHECKSUM。

/// 一个 `<file>` 条目的有界投影。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileEntry {
    pub name: String,
    pub size: Option<u64>,
    /// 整文件 SHA-256（64 位小写十六进制）。
    pub sha256: Option<String>,
    /// `<pieces length="N">` 的分片粒度（字节）；没有 `<pieces>` 时为 None。
    pub piece_length: Option<u64>,
    /// `<pieces>` 里的分片条数。
    pub piece_count: usize,
    /// `<resources>` 里列出的镜像地址（原文，未解码外的任何加工）。
    pub urls: Vec<String>,
}

impl FileEntry {
    /// 这条记录是否足以参与"跨源聚合"的身份判定：要有哈希、要有长度、要有至少一个地址。
    pub fn is_usable(&self) -> bool {
        self.sha256.is_some() && self.size.is_some() && !self.urls.is_empty()
    }
}

/// 解析出全部 `<file>` 条目。非 Metalink / 结构异常时返回空 Vec。
pub fn parse(text: &str) -> Vec<FileEntry> {
    let xml = strip_comments(text);
    let Some(files) = section(&xml, "files") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut rest = files;
    // 逐个 `<file ...>`：取到配对 `</file>` 为止。
    while let Some(start) = rest.find("<file ") {
        let after = &rest[start..];
        let Some(tag_end) = after.find('>') else {
            break;
        };
        let tag = &after[..tag_end];
        let Some(name) = attr(tag, "name") else {
            rest = &after[tag_end + 1..];
            continue;
        };
        let body_start = tag_end + 1;
        let Some(close) = after[body_start..].find("</file>") else {
            break;
        };
        let body = &after[body_start..body_start + close];
        out.push(parse_entry(&name, body));
        rest = &after[body_start + close + "</file>".len()..];
    }
    out
}

/// 按文件名找条目：先精确匹配，再退回大小写不敏感（镜像上文件名大小写会不一致）。
pub fn find<'a>(entries: &'a [FileEntry], file_name: &str) -> Option<&'a FileEntry> {
    let want = file_name.trim();
    entries
        .iter()
        .find(|e| e.name == want)
        .or_else(|| entries.iter().find(|e| e.name.eq_ignore_ascii_case(want)))
}

fn parse_entry(name: &str, body: &str) -> FileEntry {
    let size = section(body, "size").and_then(|s| s.trim().parse::<u64>().ok());
    let sha256 = whole_file_sha256(body);
    let (piece_length, piece_count) = pieces(body);
    let urls = url_list(body);
    FileEntry {
        name: unescape(name),
        size,
        sha256,
        piece_length,
        piece_count,
        urls,
    }
}

/// `<verification>` 里的整文件 SHA-256。
///
/// 只在 `<verification>` 段内找，且**排除** `<pieces>` 段：分片哈希用的是
/// `<hash piece="N" type="sha-1">`，粒度不是整文件，混进来会得出错误的凭证。
fn whole_file_sha256(body: &str) -> Option<String> {
    let verification = section(body, "verification")?;
    let scan = match section(verification, "pieces") {
        // 去掉分片段落再扫，避免任何形态的分片哈希混入
        Some(pieces) => verification.replacen(pieces, "", 1),
        None => verification.to_string(),
    };
    let mut rest = scan.as_str();
    while let Some(i) = rest.find("<hash") {
        let after = &rest[i..];
        let tag_end = after.find('>')?;
        let tag = &after[..tag_end];
        let text = inner_text(&after[tag_end + 1..], "</hash>")?;
        let is_sha256 = attr(tag, "type")
            .map(|t| t.eq_ignore_ascii_case("sha-256") || t.eq_ignore_ascii_case("sha256"))
            .unwrap_or(false);
        if is_sha256 {
            let hex = text.trim().to_ascii_lowercase();
            if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(hex);
            }
        }
        let consumed = tag_end + 1 + text.len() + "</hash>".len();
        rest = &after[consumed.min(after.len())..];
        if rest.is_empty() {
            break;
        }
    }
    None
}

/// `<pieces length="N" ...>` 的粒度与条数。
fn pieces(body: &str) -> (Option<u64>, usize) {
    let Some((tag, inner)) = element(body, "pieces") else {
        return (None, 0);
    };
    let len = attr(tag, "length").and_then(|v| v.trim().parse::<u64>().ok());
    (len, inner.matches("<hash").count())
}

/// `<resources>` 里（本文件块内）的全部 `<url>` 文本。
///
/// 取整个 file 块的 url：发布者信息里的 `<url>download.opensuse.org</url>` 在
/// `<files>` 之外，进不到这里。
fn url_list(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find("<url") {
        let after = &rest[i..];
        let Some(tag_end) = after.find('>') else {
            break;
        };
        // 自闭合标签没有内容，跳过它
        if after[..tag_end].ends_with('/') {
            rest = &after[tag_end + 1..];
            continue;
        }
        let Some(text) = inner_text(&after[tag_end + 1..], "</url>") else {
            break;
        };
        let url = unescape(text.trim());
        // 有界：URL 里不该出现 '<'；出现说明我们的边界判断错了，宁可不给
        if !url.is_empty() && !url.contains('<') && !url.contains('>') {
            out.push(url);
        }
        let consumed = tag_end + 1 + text.len() + "</url>".len();
        rest = &after[consumed.min(after.len())..];
        if rest.is_empty() {
            break;
        }
    }
    out
}

/// 取 `<name ...>...</name>` 的**开标签原文**与内层文本。
///
/// 开标签允许带属性（`<pieces length="4194304">`），所以不能直接找 `<name>`；
/// 同时要求标签名后紧跟 `>` 或空白，避免 `<file` 匹配到 `<files`。
fn element<'a>(s: &'a str, name: &str) -> Option<(&'a str, &'a str)> {
    let open_key = format!("<{name}");
    let close = format!("</{name}>");
    let mut from = 0usize;
    while let Some(i) = s[from..].find(&open_key) {
        let i = from + i;
        let after = &s[i + open_key.len()..];
        if after.starts_with('>') || after.starts_with(char::is_whitespace) {
            let tag_end = s[i..].find('>').map(|j| i + j)?;
            let inner_end = s[tag_end..].find(&close).map(|j| tag_end + j)?;
            return Some((&s[i..=tag_end], &s[tag_end + 1..inner_end]));
        }
        from = i + open_key.len();
    }
    None
}

/// 取 `<name ...>...</name>` 的内层文本。
fn section<'a>(s: &'a str, name: &str) -> Option<&'a str> {
    element(s, name).map(|(_, inner)| inner)
}

/// 取到下一个 `close` 之前的文本（不含 close）。
fn inner_text<'a>(s: &'a str, close: &str) -> Option<&'a str> {
    let end = s.find(close)?;
    Some(&s[..end])
}

/// 双引号属性；单引号/无引号一律不认（实测的生成器都用双引号）。
fn attr(tag: &str, name: &str) -> Option<String> {
    let key = format!("{name}=\"");
    let start = tag.find(&key)? + key.len();
    let rest = &tag[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// 去掉 XML 注释。Metalink 会用注释分隔地区（`<!-- Mirrors in ... -->`），
/// 不先去掉它们，`<url>` 的扫描会被注释里的文字干扰。
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("<!--") {
        out.push_str(&rest[..i]);
        match rest[i..].find("-->") {
            Some(j) => rest = &rest[i + j + 3..],
            None => return out, // 注释没闭合：截断，剩余内容不参与解析
        }
    }
    out.push_str(rest);
    out
}

/// 实体还原：与链接收口共用 `htmltext` 的同一份实现（含数字实体）。
fn unescape(s: &str) -> String {
    crate::htmltext::unescape_entities(s).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// 真实样本：`https://download.opensuse.org/tumbleweed/iso/
    /// openSUSE-Tumbleweed-DVD-x86_64-Current.iso.metalink`（抓取，
    /// 87,778 B，MirrorCache 生成的 Metalink 3.0）。
    fn real() -> String {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/metalink/opensuse-tumbleweed-dvd.metalink");
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", p.display()))
    }

    #[test]
    fn parses_the_real_opensuse_metalink() {
        let entries = parse(&real());
        assert_eq!(entries.len(), 1, "样本里只有一个 <file>");
        let e = find(
            &entries,
            "openSUSE-Tumbleweed-DVD-x86_64-Snapshot20261016-Media.iso",
        )
        .expect("按名字要能找到");
        assert_eq!(e.size, Some(4_666_163_200));
        assert_eq!(
            e.sha256.as_deref(),
            Some("2a5d04dfdd254bf27881c2b56c25d1e48fc4138df2ea0ca464f00759ff646b0d"),
            "要取整文件 sha-256，而不是 md5/sha-1/sha-512"
        );
        assert_eq!(e.piece_length, Some(4_194_304), "分片粒度 4 MiB");
        assert!(e.piece_count > 100, "分片条数应当很多：{}", e.piece_count);
        assert!(e.urls.len() >= 5, "镜像地址应当有多条：{}", e.urls.len());
        assert!(
            e.urls.iter().all(|u| u.starts_with("https://")),
            "{:?}",
            e.urls
        );
        assert!(e.is_usable());
    }

    #[test]
    fn publisher_url_never_leaks_into_the_mirror_list() {
        // 样本里 <publisher><url>download.opensuse.org</url></publisher> 在 <files> 之外，
        // 它是"发布者主页"而不是下载地址；混进来会变成一条永远失败的候选。
        let entries = parse(&real());
        for e in &entries {
            assert!(
                !e.urls.iter().any(|u| u == "download.opensuse.org"),
                "发布者地址不该进镜像列表: {:?}",
                e.urls
            );
        }
    }

    #[test]
    fn comments_between_mirrors_do_not_disturb_the_list() {
        // 真实样本用注释分隔地区；不剥注释就会把注释文字当成 url 内容。
        let e = &parse(&real())[0];
        assert!(
            !e.urls
                .iter()
                .any(|u| u.contains("Mirrors") || u.contains("-->")),
            "{:?}",
            e.urls
        );
        // 每个 url 都应当是完整地址
        for u in &e.urls {
            assert!(u.starts_with("http"), "{u}");
            assert!(!u.contains(' '), "地址里不该有空格: {u}");
        }
    }

    #[test]
    fn piece_hashes_never_masquerade_as_the_whole_file_hash() {
        // 分片是 <hash piece="N" type="sha-1">，粒度不是整文件；
        // 一旦被当成整文件凭证，跨源校验会在正确内容上误报失败。
        let text = "\
<metalink version=\"3.0\"><files>
  <file name=\"a.iso\">
    <size>100</size>
    <verification>
      <pieces length=\"4194304\" type=\"sha-1\">
        <hash piece=\"0\">aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</hash>
      </pieces>
      <hash type=\"sha-256\">1111111111111111111111111111111111111111111111111111111111111111</hash>
    </verification>
    <resources><url type=\"https\">https://m.test/a.iso</url></resources>
  </file>
</files></metalink>";
        let e = &parse(text)[0];
        assert_eq!(
            e.sha256.as_deref(),
            Some("1111111111111111111111111111111111111111111111111111111111111111")
        );
        assert_eq!(e.piece_count, 1);
        assert_eq!(e.piece_length, Some(4_194_304));
    }

    #[test]
    fn accepts_meta4_style_file_names_and_unescapes_entities() {
        let text = "\
<metalink><files>
  <file name=\"b&amp;c.iso\">
    <size>7</size>
    <verification><hash type=\"sha-256\">2222222222222222222222222222222222222222222222222222222222222222</hash></verification>
    <resources><url>https://m.test/b?x=1&amp;y=2</url></resources>
  </file>
</files></metalink>";
        let entries = parse(text);
        assert_eq!(entries[0].name, "b&c.iso");
        assert_eq!(entries[0].urls, vec!["https://m.test/b?x=1&y=2"]);
    }

    #[test]
    fn fails_closed_on_anything_unexpected() {
        // 不是 Metalink
        assert!(parse("hello").is_empty());
        assert!(parse("").is_empty());
        assert!(parse("<html><body>nope</body></html>").is_empty());
        // 没有 </files> 就整体不认，而不是猜一半
        assert!(parse("<metalink><files><file name=\"a\">").is_empty());
        // 没有 sha-256 的条目不可用（不能拿去当身份凭证）
        let no_hash = "\
<metalink><files><file name=\"a.iso\"><size>1</size>
<resources><url>https://m.test/a.iso</url></resources></file></files></metalink>";
        let e = &parse(no_hash)[0];
        assert_eq!(e.sha256, None);
        assert!(!e.is_usable());
        // 只有一个 file 块但没有 name 属性 → 跳过该块
        assert!(
            parse("<metalink><files><file><size>1</size></file></files></metalink>").is_empty()
        );
    }

    #[test]
    fn find_prefers_exact_then_case_insensitive() {
        let entries = vec![
            FileEntry {
                name: "A.iso".into(),
                ..Default::default()
            },
            FileEntry {
                name: "a.iso".into(),
                ..Default::default()
            },
        ];
        assert_eq!(find(&entries, "A.iso").unwrap().name, "A.iso");
        assert_eq!(find(&entries, "a.iso").unwrap().name, "a.iso");
        assert_eq!(find(&entries, "A.ISO").unwrap().name, "A.iso");
        assert!(find(&entries, "nope.iso").is_none());
    }
}
