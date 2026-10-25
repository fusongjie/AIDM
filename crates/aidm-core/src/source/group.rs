//! 去重与分组器（`docs/source-discovery.md` §4.6）。
//!
//! 两件事，都是纯函数：
//!
//! 1. **判重**：[`normalize_url`] + [`dedup`]，键是 `(platform, normalized_url)`。
//!    规范化**只用于判重，不用于下载** —— 下载必须用原串（签名串被改写就失效）。
//! 2. **分组**：[`group_key`] + [`group`]，把"同一份内容"的候选收进 [`ContentGroup`]。
//!
//! # 规范化规则（§4.6）
//!
//! - scheme / host 小写；去掉默认端口 `80` / `443`；路径里连续 `/` 合并成一个；
//! - **查询串原样保留**（可能含签名/版本；排序会破坏签名，所以不排序）；
//! - **去掉 fragment**；百分号编码**不改写**（`%2F` 不还原成 `/`，大小写不统一）；
//! - 空路径按 RFC 3986 §6.2.3 归一成 `/`（`http://h` 与 `http://h/` 是同一个）；
//! - **丢弃 userinfo**（`user:password@`）：凭据只经 `auth_ref`，不进入判重键、
//!   分组键或事件；
//! - 解析失败（含非 HTTP(S)）返回 `None`，判重退回原串。
//!
//! # 分组键（§3.1 / §4.6）
//!
//! | 级别 | 键 | 说明 |
//! |---|---|---|
//! | `L4` | `d:<algo>:<hex>` | 强摘要，同摘要即同一份文件 |
//! | `L3` | `p:<id>` | 分片清单标识 |
//! | `L2` | `w:<algo>:<hex>` | 弱摘要，只做完成对账 |
//! | `L1` | `s:<size>:<name>:<version>:<container>` | 同名不同版本、压缩包 vs 解压内容必须分开 |
//! | `L0` | `u:<sha256 hex>` | 什么都没有：永不与"别的地址"并组；键里只有规范化地址的哈希 |
//!
//! L0 用规范化 URL 的 SHA-256 而不是原文：地址可能带签名/Token 查询串，
//! 而键会进分组 ID 与事件（§8.2 禁记查询串）。
//!
//! `version` / `container` 缺省写 `-`，所以 `s:1:a.iso:-:-` 与 `s:1:a.iso:1.0:-` 天然不同组。

use std::collections::HashMap;

use crate::hash::sha256_hex;

use super::candidate::{CandidateSource, Platform};
use super::evidence::{EvidenceLevel, IdentityEvidence};

/// 只做**判重**用的规范化。下载一律用原串。
///
/// 规则见模块注释。返回 `None` 表示"这个地址没法安全地规范化"（空串、非 HTTP(S)、
/// 主机为空、端口非数字等），调用方应退回原串判重 —— 宁可漏一次去重，
/// 也不能把两个不同地址错误地当成同一个。
///
/// **userinfo（`user:password@`）会被丢弃**：凭据只走 `auth_ref`，
/// 留在规范化串里会经 L0 分组键渗进事件/诊断。
pub fn normalize_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (scheme, rest) = raw.split_once("://")?;
    if !valid_scheme(scheme) {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    // 只处理 HTTP(S)：平台适配器产出的候选全是这两种，默认端口规则也只对它们有意义。
    // 对 ftp:/ed2k: 等 scheme 猜规则会造出错误的等价关系（eD2k 链接里没有 host）。
    if scheme != "http" && scheme != "https" {
        return None;
    }

    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    if authority.is_empty() {
        return None;
    }
    // userinfo 只用来定位 host，重建时**不回写**（凭据不进键/事件）。
    let hostport = match authority.rsplit_once('@') {
        Some((_userinfo, hp)) => hp,
        None => authority,
    };
    let (host, port) = split_host_port(hostport)?;
    if host.is_empty() {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let port = match port {
        // 空端口（`http://h:/a`）视为没写端口。
        None | Some("") => None,
        Some(p) if !p.bytes().all(|b| b.is_ascii_digit()) => return None,
        Some("80") if scheme == "http" => None,
        Some("443") if scheme == "https" => None,
        Some(p) => Some(p),
    };

    // 余下部分：`path?query#fragment`，fragment 整段丢掉。
    let tail = &rest[auth_end..];
    let tail = match tail.find('#') {
        Some(i) => &tail[..i],
        None => tail,
    };
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (tail, None),
    };
    let path = collapse_slashes(path);

    let mut out = String::with_capacity(raw.len());
    out.push_str(&scheme);
    out.push_str("://");
    out.push_str(&host);
    if let Some(p) = port {
        out.push(':');
        out.push_str(p);
    }
    if path.is_empty() {
        out.push('/');
    } else {
        out.push_str(&path);
    }
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }
    Some(out)
}

/// 按 `(platform, normalize_url(url))` 去重；保留**第一次**出现的那条。
///
/// 无法规范化的 URL 按**原串**判重（精确相同才合并）。
/// 查询串不同（不同签名）→ 键不同 → 两条都保留。
pub fn dedup(cands: Vec<CandidateSource>) -> Vec<CandidateSource> {
    let mut seen: Vec<(Platform, String)> = Vec::new();
    let mut out: Vec<CandidateSource> = Vec::new();
    for c in cands {
        let key = normalize_url(&c.url).unwrap_or_else(|| c.url.clone());
        if seen.iter().any(|(p, u)| *p == c.platform && *u == key) {
            continue;
        }
        seen.push((c.platform, key));
        out.push(c);
    }
    out
}

/// 分组键。`Hash` 由派生得到，判等即"同一份内容"。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupKey(pub String);

/// 一个内容分组：同一份内容的候选集合。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentGroup {
    pub key: GroupKey,
    /// 组内最高级别的证据。
    pub evidence: IdentityEvidence,
    /// 组内候选，保持输入顺序。
    pub candidates: Vec<CandidateSource>,
}

/// 算分组键（规则见模块注释）。
///
/// `file_name` 是**任务**的文件名（过闸门后的那个），`normalized_name` 取它的
/// ASCII 小写 —— 只统一大小写，不做 NFC/去后缀之类的改写。
pub fn group_key(cand: &CandidateSource, file_name: &str) -> GroupKey {
    let ev = &cand.evidence;
    // `level()` 已保证"级别 ↔ 变体"一致；万一对不上（不该发生）就退回 L0 的地址键，
    // 纯函数不 panic。
    let unknown = || GroupKey(format!("u:{}", url_key(cand)));
    let key = match ev.level() {
        EvidenceLevel::L4StrongDigest => match ev {
            IdentityEvidence::StrongDigest(h) => {
                GroupKey(format!("d:{}:{}", h.algo.as_str(), h.normalized_hex()))
            }
            _ => unknown(),
        },
        EvidenceLevel::L3PieceManifest => match ev {
            IdentityEvidence::PieceManifest { id, .. } => GroupKey(format!("p:{id}")),
            _ => unknown(),
        },
        EvidenceLevel::L2WeakDigest => match ev {
            IdentityEvidence::StrongDigest(h) | IdentityEvidence::WeakDigest(h) => {
                GroupKey(format!("w:{}:{}", h.algo.as_str(), h.normalized_hex()))
            }
            _ => unknown(),
        },
        EvidenceLevel::L1SizeOnly => {
            let size = match ev {
                IdentityEvidence::SizeOnly { size } => *size,
                // 不变式外的构造（例如 L1 却装了别的证据）：用候选声明的大小兜底。
                _ => cand.size.unwrap_or(0),
            };
            GroupKey(format!(
                "s:{size}:{}:{}:{}",
                file_name.to_ascii_lowercase(),
                cand.version.as_deref().unwrap_or("-"),
                cand.container.as_deref().unwrap_or("-"),
            ))
        }
        EvidenceLevel::L0Unverified => unknown(),
    };
    key
}

/// 分组并按"证据级别高者优先、同级保持输入顺序"排序；组内候选保持输入顺序。
///
/// 排序用稳定排序：同级组的先后就是它们第一次出现的先后，所以同样的输入
/// 永远得到同样的序列（`alt_cursor` 之类的下标依赖稳定性）。
pub fn group(cands: Vec<CandidateSource>, file_name: &str) -> Vec<ContentGroup> {
    let mut order: Vec<GroupKey> = Vec::new();
    let mut buckets: HashMap<GroupKey, Vec<CandidateSource>> = HashMap::new();
    for c in cands {
        let key = group_key(&c, file_name);
        if !buckets.contains_key(&key) {
            order.push(key.clone());
        }
        buckets.entry(key).or_default().push(c);
    }
    let mut out: Vec<ContentGroup> = order
        .into_iter()
        .map(|key| {
            let candidates = buckets.remove(&key).unwrap_or_default();
            let evidence = pick_evidence(&candidates);
            ContentGroup {
                key,
                evidence,
                candidates,
            }
        })
        .collect();
    // 稳定排序：级别降序，同级保持输入顺序。
    out.sort_by(|a, b| b.evidence.level().cmp(&a.evidence.level()));
    out
}

/// 组内最高级别的证据（同级取先出现的那个）。
fn pick_evidence(cands: &[CandidateSource]) -> IdentityEvidence {
    let mut best: Option<&IdentityEvidence> = None;
    for c in cands {
        match best {
            Some(b) if b.level() >= c.evidence.level() => {}
            _ => best = Some(&c.evidence),
        }
    }
    best.cloned().unwrap_or(IdentityEvidence::Unverified)
}

/// L0 的键部分：规范化地址的 SHA-256（退回原串时同样只哈希，不写原文）。
///
/// 地址可能携带签名/Token 查询串，而键会进分组 ID 与事件（§8.2），
/// 所以键里只出现哈希。
fn url_key(cand: &CandidateSource) -> String {
    let normalized = normalize_url(&cand.url).unwrap_or_else(|| cand.url.clone());
    sha256_hex(normalized.as_bytes())
}

/// RFC 3986 的 scheme 语法：`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`。
fn valid_scheme(s: &str) -> bool {
    let mut it = s.bytes();
    match it.next() {
        Some(b) if b.is_ascii_alphabetic() => {}
        _ => return false,
    }
    it.all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
}

/// 拆 `host[:port]`；IPv6 字面量按方括号**整体**返回（重建时方括号要原样写回）。
/// 端口**不**在这里判合法性。
fn split_host_port(hostport: &str) -> Option<(&str, Option<&str>)> {
    if hostport.starts_with('[') {
        let close = hostport.find(']')?;
        if close <= 1 {
            // `[]` 里没有主机
            return None;
        }
        let host = &hostport[..=close];
        let after = &hostport[close + 1..];
        if after.is_empty() {
            return Some((host, None));
        }
        let port = after.strip_prefix(':')?;
        return Some((host, Some(port)));
    }
    match hostport.rsplit_once(':') {
        // 剩下的 host 里还带冒号 → 不是合法的 host:port（`h:80:90`）。
        Some((host, port)) if !host.contains(':') => Some((host, Some(port))),
        Some(_) => None,
        None => Some((hostport, None)),
    }
}

/// 路径里的连续 `/` 合并成一个；不动其它字符（百分号编码原样保留）。
fn collapse_slashes(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for ch in path.chars() {
        if ch == '/' && out.ends_with('/') {
            continue;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::evidence::{DeclaredHash, EvidenceOrigin, HashAlgo};

    const SHA_A: &str = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08";
    const SHA_B: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    fn ev_strong(hex: &str) -> IdentityEvidence {
        IdentityEvidence::StrongDigest(DeclaredHash {
            algo: HashAlgo::Sha256,
            hex: hex.to_string(),
            origin: EvidenceOrigin::UpstreamMetadata,
        })
    }

    fn ev_weak(hex: &str) -> IdentityEvidence {
        IdentityEvidence::WeakDigest(DeclaredHash {
            algo: HashAlgo::Md5,
            hex: hex.to_string(),
            origin: EvidenceOrigin::PlatformApi,
        })
    }

    fn cand(url: &str, platform: Platform, evidence: IdentityEvidence) -> CandidateSource {
        CandidateSource {
            url: url.to_string(),
            platform,
            kind: super::super::candidate::SourceKind::File,
            size: None,
            version: None,
            container: None,
            evidence,
            auth_ref: None,
            origin: None,
            expires_at: None,
        }
    }

    fn l1(url: &str, size: u64) -> CandidateSource {
        cand(url, Platform::Mirror, IdentityEvidence::SizeOnly { size })
    }

    fn urls(cands: &[CandidateSource]) -> Vec<&str> {
        cands.iter().map(|c| c.url.as_str()).collect()
    }

    #[test]
    fn normalize_keeps_query_and_drops_fragment() {
        assert_eq!(
            normalize_url(
                "https://example.test/a.iso?X-Amz-Signature=AbC123&X-Amz-Expires=60#part2"
            )
            .as_deref(),
            // 查询串原样：大小写、顺序都不动（排序会破坏签名）
            Some("https://example.test/a.iso?X-Amz-Signature=AbC123&X-Amz-Expires=60")
        );
        // 只有 fragment 不同 → 规范化后完全相同
        assert_eq!(
            normalize_url("https://h.test/a#1"),
            normalize_url("https://h.test/a#2")
        );
        // 查询串为空也要保留问号（签名串可能就靠它区分）
        assert_eq!(
            normalize_url("https://h.test/a?").as_deref(),
            Some("https://h.test/a?")
        );
    }

    #[test]
    fn normalize_lowercases_scheme_and_host_and_drops_default_ports() {
        assert_eq!(
            normalize_url("HTTPS://Example.TEST/Path/File.ISO").as_deref(),
            Some("https://example.test/Path/File.ISO"), // 路径大小写敏感，不动
        );
        assert_eq!(
            normalize_url("http://example.test:80/a").as_deref(),
            Some("http://example.test/a")
        );
        assert_eq!(
            normalize_url("https://example.test:443/a").as_deref(),
            Some("https://example.test/a")
        );
        // 非默认端口保留；https 上的 80 也是非默认
        assert_eq!(
            normalize_url("https://example.test:8443/a").as_deref(),
            Some("https://example.test:8443/a")
        );
        assert_eq!(
            normalize_url("https://example.test:80/a").as_deref(),
            Some("https://example.test:80/a")
        );
        // 空路径归一成 `/`（RFC 3986 §6.2.3）
        assert_eq!(
            normalize_url("https://example.test"),
            normalize_url("https://example.test/")
        );
        assert_eq!(
            normalize_url("https://example.test?x=1").as_deref(),
            Some("https://example.test/?x=1")
        );
        // IPv6 字面量：方括号原样保留，只去掉默认端口
        assert_eq!(
            normalize_url("http://[::1]:80/a").as_deref(),
            Some("http://[::1]/a")
        );
        assert_eq!(
            normalize_url("http://[::1]:8080/a").as_deref(),
            Some("http://[::1]:8080/a")
        );
        assert_eq!(normalize_url("http://[]/a"), None, "方括号里没有主机");
    }

    #[test]
    fn normalize_collapses_repeated_slashes_but_keeps_percent_encoding() {
        assert_eq!(
            normalize_url("https://h.test//a///b/").as_deref(),
            Some("https://h.test/a/b/")
        );
        // 百分号编码不改写（不还原、不统一大小写）
        assert_eq!(
            normalize_url("https://h.test/a%2fb%2Fc").as_deref(),
            Some("https://h.test/a%2fb%2Fc")
        );
        // 查询串里的 `//` 不属于路径，不动
        assert_eq!(
            normalize_url("https://h.test/a?u=http://x//y").as_deref(),
            Some("https://h.test/a?u=http://x//y")
        );
    }

    #[test]
    fn normalize_drops_userinfo() {
        // 凭据不进规范化串（否则会随 L0 分组键进事件）
        assert_eq!(
            normalize_url("https://user:pw@a.test/f").as_deref(),
            Some("https://a.test/f")
        );
        assert_eq!(
            normalize_url("http://u@a.test/f").as_deref(),
            Some("http://a.test/f")
        );
        // 与无 userinfo 的同地址规范化后完全相同（判重/分组同一条）
        assert_eq!(
            normalize_url("https://user:pw@a.test/f"),
            normalize_url("https://a.test/f")
        );
        // 只影响 authority 段：端口/路径/查询串规则照常
        assert_eq!(
            normalize_url("https://user:pw@A.TEST:443//f?x=1#frag").as_deref(),
            Some("https://a.test/f?x=1")
        );
        // 输出里不得出现凭据的任何痕迹
        let got = normalize_url("https://user:pw@a.test/f").unwrap();
        assert!(!got.contains("user"), "{got}");
        assert!(!got.contains("pw@"), "{got}");
        // IPv6 地址上的 userinfo 同样丢弃
        assert_eq!(
            normalize_url("http://u:p@[::1]:80/a").as_deref(),
            Some("http://[::1]/a")
        );
    }

    #[test]
    fn l0_key_is_a_digest_and_carries_no_secret_or_query_text() {
        let signed = cand(
            "https://b.test/f.iso?X-Amz-Signature=SECRETSIG&token=tok123",
            Platform::WebSearch,
            IdentityEvidence::Unverified,
        );
        let key = group_key(&signed, "f.iso");
        let hex = key.0.strip_prefix("u:").expect("L0 键前缀应为 u:");
        assert_eq!(hex.len(), 64, "应为 SHA-256 hex：{key:?}");
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "应为小写 hex：{hex}"
        );
        // 键里不得出现查询串/签名/Token
        for bad in ["X-Amz-Signature", "SECRETSIG", "token", "tok123", "?", "="] {
            assert!(!key.0.contains(bad), "L0 键不应包含 {bad:?}：{key:?}");
        }
        // 同一地址的签名不同 → 哈希不同 → 仍是两个组（永不与他者并组）
        let other = cand(
            "https://b.test/f.iso?X-Amz-Signature=OTHER",
            Platform::WebSearch,
            IdentityEvidence::Unverified,
        );
        assert_ne!(key, group_key(&other, "f.iso"));
        assert_eq!(group(vec![signed, other], "f.iso").len(), 2);
        // userinfo 不进键：带凭据与不带凭据的同地址是同一组
        let with_cred = cand(
            "https://user:pw@c.test/f.iso",
            Platform::WebSearch,
            IdentityEvidence::Unverified,
        );
        let without = cand(
            "https://c.test/f.iso",
            Platform::WebSearch,
            IdentityEvidence::Unverified,
        );
        let cred_groups = group(vec![with_cred, without], "f.iso");
        assert_eq!(cred_groups.len(), 1);
        assert!(
            !cred_groups[0].key.0.contains("user"),
            "{:?}",
            cred_groups[0].key
        );
        assert!(
            !cred_groups[0].key.0.contains("pw@"),
            "{:?}",
            cred_groups[0].key
        );
    }

    #[test]
    fn normalize_rejects_what_it_cannot_parse() {
        for bad in [
            "",
            "   ",
            "not a url",
            "https://",
            "https:///a.iso",
            "http://h.test:abc/a",
            "http://h.test:80:90/a",
            "//example.test/a", // 无 scheme
            "ftp://h.test/a",   // 只处理 HTTP(S)
            "ed2k://|file|a.iso|1|b|/",
        ] {
            assert_eq!(normalize_url(bad), None, "{bad:?} 应解析失败");
        }
    }

    #[test]
    fn dedup_keeps_first_and_treats_different_signatures_as_distinct() {
        let got = dedup(vec![
            cand(
                "HTTPS://H.test/a.iso#frag",
                Platform::Mirror,
                IdentityEvidence::Unverified,
            ),
            // 与上一条只差大小写/fragment → 判为重复，保留第一条（原串）
            cand(
                "https://h.test/a.iso",
                Platform::Mirror,
                IdentityEvidence::Unverified,
            ),
            // 签名不同 → 不是重复
            cand(
                "https://h.test/a.iso?token=1",
                Platform::Mirror,
                IdentityEvidence::Unverified,
            ),
            cand(
                "https://h.test/a.iso?token=2",
                Platform::Mirror,
                IdentityEvidence::Unverified,
            ),
            // 平台不同 → 不是重复
            cand(
                "https://h.test/a.iso",
                Platform::Origin,
                IdentityEvidence::Unverified,
            ),
            // 无法规范化 → 按原串判重
            cand(
                "ed2k://|file|a.iso|1|b|/",
                Platform::Origin,
                IdentityEvidence::Unverified,
            ),
            cand(
                "ed2k://|file|a.iso|1|b|/",
                Platform::Origin,
                IdentityEvidence::Unverified,
            ),
        ]);
        assert_eq!(
            urls(&got),
            vec![
                "HTTPS://H.test/a.iso#frag",
                "https://h.test/a.iso?token=1",
                "https://h.test/a.iso?token=2",
                "https://h.test/a.iso",
                "ed2k://|file|a.iso|1|b|/",
            ]
        );
    }

    #[test]
    fn strong_digest_groups_across_platforms_and_ignores_url() {
        // 摘要 hex 大小写/空白不同也算同一份文件
        let a = cand(
            "https://a.test/f.iso",
            Platform::ArchiveOrg,
            ev_strong(SHA_A),
        );
        let b = cand(
            "https://b.test/f.iso",
            Platform::GitHub,
            ev_strong(&SHA_A.to_lowercase()),
        );
        let groups = group(vec![a, b], "f.iso");
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].key,
            GroupKey(format!("d:sha256:{}", SHA_A.to_lowercase()))
        );
        assert_eq!(groups[0].candidates.len(), 2);
        assert!(groups[0].evidence.allows_multi_source());
    }

    #[test]
    fn weak_digest_uses_its_own_prefix_and_does_not_merge_with_strong() {
        let weak = cand(
            "https://a.test/f.iso",
            Platform::Mirror,
            ev_weak("D41D8CD98F00B204E9800998ECF8427E"),
        );
        assert_eq!(
            group_key(&weak, "f.iso"),
            GroupKey("w:md5:d41d8cd98f00b204e9800998ecf8427e".into())
        );
        assert!(!weak.evidence.allows_multi_source());
        // 同一 URL、但一个是强摘要一个是弱摘要 → 两个组（键前缀不同）
        let strong = cand("https://a.test/f.iso", Platform::Mirror, ev_strong(SHA_A));
        assert_ne!(group_key(&weak, "f.iso"), group_key(&strong, "f.iso"));
        assert_eq!(group(vec![weak, strong], "f.iso").len(), 2);
    }

    #[test]
    fn piece_manifest_uses_its_id() {
        let c = cand(
            "https://a.test/f.iso",
            Platform::Origin,
            IdentityEvidence::PieceManifest {
                id: "urn:btih:abc".into(),
                algo: HashAlgo::Sha1,
            },
        );
        assert_eq!(group_key(&c, "f.iso"), GroupKey("p:urn:btih:abc".into()));
        assert!(c.evidence.allows_multi_source());
    }

    #[test]
    fn same_name_different_version_are_different_groups() {
        let mut v1 = l1("https://a.test/f-1.iso", 1024);
        v1.version = Some("1.0".into());
        let mut v2 = l1("https://a.test/f-2.iso", 1024);
        v2.version = Some("2.0".into());
        let none = l1("https://a.test/f.iso", 1024);

        let k1 = group_key(&v1, "f.iso");
        let k2 = group_key(&v2, "f.iso");
        let kn = group_key(&none, "f.iso");
        assert_eq!(k1, GroupKey("s:1024:f.iso:1.0:-".into()));
        assert_eq!(kn, GroupKey("s:1024:f.iso:-:-".into()));
        assert_ne!(k1, k2, "同名不同版本必须不同组");
        assert_ne!(k1, kn);
        assert_eq!(group(vec![v1, v2, none], "f.iso").len(), 3);
    }

    #[test]
    fn archive_and_extracted_content_are_different_groups() {
        let mut zip = l1("https://a.test/f.iso", 1024);
        zip.container = Some("zip".into());
        let raw = l1("https://b.test/f.iso", 1024);
        assert_eq!(
            group_key(&zip, "f.iso"),
            GroupKey("s:1024:f.iso:-:zip".into())
        );
        assert_ne!(
            group_key(&zip, "f.iso"),
            group_key(&raw, "f.iso"),
            "压缩包与解压内容不能并组"
        );
        assert_eq!(group(vec![zip, raw], "f.iso").len(), 2);
        // 同样的 container 才允许并组：两个 zip 合成 1 组、组内 2 条
        let mut zip2 = l1("https://c.test/f.iso", 1024);
        zip2.container = Some("zip".into());
        let mut zip3 = l1("https://d.test/f.iso", 1024);
        zip3.container = Some("zip".into());
        let same_container = group(vec![zip2, zip3], "f.iso");
        assert_eq!(same_container.len(), 1, "同 container 应并组");
        assert_eq!(same_container[0].candidates.len(), 2);
        // 换成另一个 container 必须拆成 2 组（tar ≠ zip）
        let mut tar = l1("https://e.test/f.iso", 1024);
        tar.container = Some("tar".into());
        assert_eq!(
            group(vec![same_container[0].candidates[0].clone(), tar], "f.iso").len(),
            2
        );
    }

    #[test]
    fn group_key_lowercases_the_file_name_only_for_ascii() {
        let c = l1("https://a.test/f.iso", 7);
        // ASCII 大小写统一
        assert_eq!(group_key(&c, "F.ISO"), group_key(&c, "f.iso"));
        // 非 ASCII 不做大小写转换（不猜 locale）
        assert_eq!(
            group_key(&c, "文件.iso"),
            GroupKey("s:7:文件.iso:-:-".into())
        );
    }

    #[test]
    fn unverified_candidates_never_merge_with_each_other_across_urls() {
        let a = cand(
            "https://a.test/f.iso",
            Platform::WebSearch,
            IdentityEvidence::Unverified,
        );
        let b = cand(
            "https://b.test/f.iso",
            Platform::WebSearch,
            IdentityEvidence::Unverified,
        );
        let groups = group(vec![a, b], "f.iso");
        assert_eq!(groups.len(), 2, "L0 永不与他者并组");
        assert_eq!(
            groups[0].key,
            // L0 键 = `u:` + SHA256(规范化地址)
            GroupKey("u:45e07c10419ef1c9183ef6dc9141582cdfd85c8a8e855a33bedc86f4937ab44d".into())
        );
        assert_eq!(groups[0].evidence.level(), EvidenceLevel::L0Unverified);
        assert!(!groups[0].evidence.allows_multi_source());

        // 同一地址（规范化后相同）的 L0 才是同一组
        let same_a = cand(
            "HTTPS://A.test/f.iso#x",
            Platform::WebSearch,
            IdentityEvidence::Unverified,
        );
        let same_b = cand(
            "https://a.test/f.iso",
            Platform::WebSearch,
            IdentityEvidence::Unverified,
        );
        assert_eq!(group(vec![same_a, same_b], "f.iso").len(), 1);
    }

    #[test]
    fn l0_does_not_merge_with_l1_even_on_same_url() {
        let l0 = cand(
            "https://a.test/f.iso",
            Platform::Mirror,
            IdentityEvidence::Unverified,
        );
        let size_only = l1("https://a.test/f.iso", 1024);
        assert_ne!(group_key(&l0, "f.iso"), group_key(&size_only, "f.iso"));
        assert_eq!(group(vec![l0, size_only], "f.iso").len(), 2);
    }

    #[test]
    fn group_order_is_high_evidence_first_and_stable_within_level() {
        let l1_first = l1("https://m1.test/f.iso", 1024);
        let l1_second = l1("https://m2.test/f.iso", 1024);
        let strong = cand("https://s.test/f.iso", Platform::GitHub, ev_strong(SHA_B));
        let weak = cand(
            "https://w.test/f.iso",
            Platform::Zenodo,
            ev_weak("d41d8cd98f00b204e9800998ecf8427e"),
        );
        let groups = group(vec![l1_first, strong, weak, l1_second], "f.iso");
        // 顺序：L4 → L2 → L1；两个 L1 合成一组（同 size 同 name 同 version 同 container）
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].evidence.level(), EvidenceLevel::L4StrongDigest);
        assert_eq!(groups[1].evidence.level(), EvidenceLevel::L2WeakDigest);
        assert_eq!(groups[2].evidence.level(), EvidenceLevel::L1SizeOnly);
        // 组内候选保持输入顺序
        assert_eq!(
            urls(&groups[2].candidates),
            vec!["https://m1.test/f.iso", "https://m2.test/f.iso"]
        );
        // 同样的输入两次得到同样的序列
        let again = group(
            vec![
                l1("https://m1.test/f.iso", 1024),
                cand("https://s.test/f.iso", Platform::GitHub, ev_strong(SHA_B)),
                cand(
                    "https://w.test/f.iso",
                    Platform::Zenodo,
                    ev_weak("d41d8cd98f00b204e9800998ecf8427e"),
                ),
                l1("https://m2.test/f.iso", 1024),
            ],
            "f.iso",
        );
        let keys: Vec<&GroupKey> = again.iter().map(|g| &g.key).collect();
        let first_keys: Vec<&GroupKey> = groups.iter().map(|g| &g.key).collect();
        assert_eq!(keys, first_keys);
    }

    #[test]
    fn group_of_empty_input_is_empty() {
        assert!(group(Vec::new(), "f.iso").is_empty());
        assert!(dedup(Vec::new()).is_empty());
    }
}
