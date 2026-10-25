//! 兄弟文件里的整文件 SHA-256（同目录 `CHECKSUM` / `<文件名>.sha256`）。
//!
//! 作用是把「跨镜像同一性」从"长度相等"升级为"内容哈希相等"，并在下载完成后校验整包。
//!
//! **不校验上游签名**——不内置任何发行方公钥，所以拿到的是"上游署名文本里写的哈希"，
//! 属于内容凭证，不是信任根。取不到时返回 `None`，调用方按"没有哈希"继续，
//! 行为与没有这个模块时完全一致。
//!
//! 实测（AlmaLinux 9）：`9/isos/x86_64/CHECKSUM` 是 PGP 明文签名文本，内含
//! `# <文件名>: <N> bytes` 与 `SHA256 (<文件名>) = <hex>`；关键性质是
//! **它在 ISO 自己被 302 到不可达主机时仍然可读**，所以对镜像身份判定最有用。

use std::io::Read;

use aidm_core::headers::HeaderLine;
use aidm_core::http_profile::RequestProfile;

/// 正文读取上限。这些文件是纯文本清单，正常几 KB；设上限避免被超大响应拖住。
const MAX_BODY: u64 = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// 64 位小写十六进制。
    pub sha256: String,
    /// 清单里声明的字节数（形如 `# name: 15151923200 bytes`）；没有为 None。
    pub size: Option<u64>,
}

/// 兄弟文件候选：同目录 `CHECKSUM` 优先，其次 `<url>.sha256`。
pub fn sibling_urls(url: &str) -> Vec<String> {
    let trimmed = url.trim();
    let Some((_, rest)) = trimmed.split_once("://") else {
        return Vec::new();
    };
    let base_end = trimmed.len() - rest.len(); // scheme:// 之后的下标
    let Some(slash) = rest.rfind('/') else {
        return Vec::new();
    };
    let dir = &trimmed[..base_end + slash + 1];
    let mut out = vec![format!("{dir}CHECKSUM")];
    // `<file>.sha256` 与 `CHECKSUM` 同时存在时都能命中；去重交给调用方的候选去重。
    out.push(format!("{trimmed}.sha256"));
    out
}

/// 从兄弟文件正文里取 `file_name` 对应的 SHA-256。
///
/// 支持两种常见写法：
/// - BSD 风格：`SHA256 (name) = <hex>`（AlmaLinux / FreeBSD 的 `CHECKSUM`）
/// - sha256sum 风格：`<hex>  name` 或 `<hex> *name`
///
/// 文件名先精确匹配，再退回大小写不敏感匹配；`./` 前缀会被忽略。
pub fn parse(text: &str, file_name: &str) -> Option<Expected> {
    let want = file_name.trim();
    let want_trimmed = want.trim_start_matches("./");
    // 声明长度只在 `# name: N bytes` 这种注释行里出现，先扫一遍。
    let size = parse_declared_size(text, want_trimmed);

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((name, hex)) = parse_bsd_line(line) {
            if name_matches(name, want_trimmed) {
                return normalize(hex).map(|sha256| Expected { sha256, size });
            }
        }
        if let Some((name, hex)) = parse_sum_line(line) {
            if name_matches(name, want_trimmed) {
                return normalize(hex).map(|sha256| Expected { sha256, size });
            }
        }
    }
    // 清单里只列了一个文件时（`<file>.sha256` 那种单行文件），文件名可能没写全，
    // 此时接受"唯一一条哈希"，否则等于有清单却用不上。
    if let Some((name, hex)) = unique_entry(text) {
        if name_matches(name, want_trimmed) || name.is_empty() {
            return normalize(hex).map(|sha256| Expected { sha256, size });
        }
    }
    None
}

/// 拉取并解析兄弟文件；两个候选都不行就返回 `None`。
///
/// 只接受 HTTP 200：404/403/30x 一律视为"该镜像没有清单"，继续用下一个候选。
pub fn fetch(
    agent: &ureq::Agent,
    url: &str,
    file_name: &str,
    profile: &RequestProfile,
    referer: Option<&str>,
    cookies: Option<&str>,
    custom_headers: &[HeaderLine],
) -> Option<Expected> {
    for cand in sibling_urls(url) {
        let resp = match crate::http_util::apply_common(
            agent.get(&cand),
            profile,
            &cand,
            referer,
            cookies,
            custom_headers,
        )
        .call()
        {
            Ok(r) if r.status() == 200 => r,
            _ => continue,
        };
        let mut raw = Vec::new();
        // 先看声明长度：明显过大就不读正文。这条请求挡在下载主路径上，
        // 对面回的若是大文件（或慢速连接），"读满上限再放弃"会把任务卡住很久。
        if crate::http_util::header_owned(&resp, "content-length")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .is_some_and(|n| n > MAX_BODY)
        {
            log::debug!("checksum: {cand} 响应过大，跳过");
            continue;
        }
        if resp
            .into_reader()
            .take(MAX_BODY)
            .read_to_end(&mut raw)
            .is_err()
        {
            continue;
        }
        let text = String::from_utf8_lossy(&raw);
        if let Some(e) = parse(&text, file_name) {
            return Some(e);
        }
    }
    None
}

/// `# <name>: <N> bytes`
fn parse_declared_size(text: &str, file_name: &str) -> Option<u64> {
    for line in text.lines() {
        let line = line.trim().trim_start_matches('#').trim();
        let Some((name, rest)) = line.rsplit_once(':') else {
            continue;
        };
        if !name_matches(name.trim(), file_name) {
            continue;
        }
        let digits: String = rest
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(n) = digits.parse::<u64>() {
            return Some(n);
        }
    }
    None
}

/// `SHA256 (name) = <hex>`
fn parse_bsd_line(line: &str) -> Option<(&str, &str)> {
    let open = line.find('(')?;
    let close = line[open..].find(')')? + open;
    let algo = line[..open].trim();
    if !algo.eq_ignore_ascii_case("SHA256") {
        return None;
    }
    let name = line[open + 1..close].trim();
    let rest = line[close + 1..].trim_start().strip_prefix('=')?;
    Some((name, rest.trim()))
}

/// `<hex>  name` / `<hex> *name`
fn parse_sum_line(line: &str) -> Option<(&str, &str)> {
    let (head, tail) = line.split_once(char::is_whitespace)?;
    if head.len() != 64 || !head.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let name = tail.trim_start().trim_start_matches('*').trim();
    (!name.is_empty()).then_some((name, head))
}

/// 正文里唯一一条可解析的记录（单行 `<file>.sha256` 常见形态）。
fn unique_entry(text: &str) -> Option<(&str, &str)> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("-----") {
            continue;
        }
        let entry = parse_bsd_line(line)
            .or_else(|| parse_sum_line(line))
            // 裸哈希行：`<file>.sha256` 里常见，没有文件名可匹配
            .or_else(|| is_hex64(line).then_some(("", line)));
        match entry {
            Some(e) => {
                if found.is_some() {
                    return None; // 多于一条，不能靠"唯一"来认
                }
                found = Some(e);
            }
            // 有无法解析的行时同样放弃"唯一"捷径
            None => return None,
        }
    }
    found
}

fn name_matches(candidate: &str, want: &str) -> bool {
    let a = candidate.trim().trim_start_matches("./");
    a == want || a.eq_ignore_ascii_case(want)
}

fn normalize(hex: &str) -> Option<String> {
    let hex = hex.trim();
    is_hex64(hex).then(|| hex.to_ascii_lowercase())
}

fn is_hex64(s: &str) -> bool {
    let s = s.trim();
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 取自实测抓到的 `mirrors.aliyun.com/almalinux/9/isos/x86_64/CHECKSUM` 片段。
    const ALMA: &str = "\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

# AlmaLinux-9.8-x86_64-boot.iso: 1519271936 bytes
SHA256 (AlmaLinux-9.8-x86_64-boot.iso) = 445f99e24399bbe98aab86111d60751c142eda049d2444fd76da5eb03472e4ab
# AlmaLinux-9-latest-x86_64-boot.iso: 1519271936 bytes
SHA256 (AlmaLinux-9-latest-x86_64-boot.iso) = 445f99e24399bbe98aab86111d60751c142eda049d2444fd76da5eb03472e4ab
# AlmaLinux-9-latest-x86_64-dvd.iso: 15151923200 bytes
SHA256 (AlmaLinux-9-latest-x86_64-dvd.iso) = 7a392bdc879afd159b30da39a356b7b26c1ddf618b01549164da9aadbc40d814
-----BEGIN PGP SIGNATURE-----
";

    #[test]
    fn parses_the_real_almalinux_checksum() {
        let e = parse(ALMA, "AlmaLinux-9-latest-x86_64-dvd.iso").unwrap();
        assert_eq!(
            e.sha256,
            "7a392bdc879afd159b30da39a356b7b26c1ddf618b01549164da9aadbc40d814"
        );
        assert_eq!(e.size, Some(15151923200));
    }

    #[test]
    fn picks_the_entry_that_matches_the_requested_file() {
        let e = parse(ALMA, "AlmaLinux-9-latest-x86_64-boot.iso").unwrap();
        assert_eq!(e.size, Some(1519271936));
        assert_ne!(
            e.sha256,
            "7a392bdc879afd159b30da39a356b7b26c1ddf618b01549164da9aadbc40d814"
        );
    }

    #[test]
    fn returns_none_when_the_file_is_not_listed() {
        assert_eq!(parse(ALMA, "Some-Other.iso"), None);
    }

    #[test]
    fn parses_sha256sum_style_and_normalizes_case() {
        let text = "7A392BDC879AFD159B30DA39A356B7B26C1DDF618B01549164DA9AADBC40D814  ./a.iso\n";
        let e = parse(text, "a.iso").unwrap();
        assert_eq!(
            e.sha256,
            "7a392bdc879afd159b30da39a356b7b26c1ddf618b01549164da9aadbc40d814"
        );
        assert_eq!(e.size, None);
    }

    #[test]
    fn accepts_a_single_unlabelled_hash_file() {
        // `<file>.sha256` 常见形态：一行裸哈希，没有文件名
        let text = "7a392bdc879afd159b30da39a356b7b26c1ddf618b01549164da9aadbc40d814\n";
        assert_eq!(
            parse(text, "whatever.iso").unwrap().sha256,
            "7a392bdc879afd159b30da39a356b7b26c1ddf618b01549164da9aadbc40d814"
        );
    }

    #[test]
    fn refuses_ambiguous_or_malformed_input() {
        // 两条记录但没有文件名 → 不能靠"唯一"来认
        let two = "aa".to_string() + &"0".repeat(62) + "\n" + &"b".repeat(64) + "\n";
        assert_eq!(parse(&two, "x.iso"), None);
        // 哈希长度不对
        let bad = "SHA256 (x.iso) = 1234\n";
        assert_eq!(parse(bad, "x.iso"), None);
        // 空正文
        assert_eq!(parse("", "x.iso"), None);
    }

    #[test]
    fn derives_sibling_urls_from_a_file_url() {
        let u =
            "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-dvd.iso";
        assert_eq!(
            sibling_urls(u),
            vec![
                "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/CHECKSUM".to_string(),
                format!("{u}.sha256"),
            ]
        );
        // 带端口与查询串时仍以最后一个 `/` 定目录
        assert_eq!(
            sibling_urls("http://a.test:8080/x/y.iso?q=1")[0],
            "http://a.test:8080/x/CHECKSUM"
        );
        assert!(sibling_urls("not-a-url").is_empty());
    }
}
