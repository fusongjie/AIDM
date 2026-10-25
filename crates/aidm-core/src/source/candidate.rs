//! 候选源与解析后目标（`docs/source-discovery.md` §3.1）。
//!
//! 这是"找源"与"调度"之间的交接对象：平台适配器产出 [`CandidateSource`]，
//! 地址解析器把它变成 [`ResolvedTarget`]，之后才可能被探测与调度消费。
//!
//! 两条边界：
//!
//! 1. **页面不是文件**：`kind` 为 [`SourceKind::Page`] / [`SourceKind::Record`] 的
//!    候选**不能**直接交给探测器（§4.5），必须先经地址解析器。
//! 2. **认证只存引用**：`auth_ref` 是 `site_login` 的 ID / URL 里的用户名 / 自定义头
//!    的键名，**不复制密码与 Cookie**（`docs/guides/12-credentials-access.md`）。
//!    本类型没有任何 `Debug` 之外的序列化，也不会出现在日志里 —— 打印整条候选时
//!    请先过 `crate::redact`。

use super::evidence::{DeclaredHash, HashAlgo, IdentityEvidence};

/// 候选来源的平台。
///
/// `as_str` 的取值同时是落库 `source_candidates.platform` 的文本，改动会让历史行
/// 对不上，因此这里只增不改。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    ArchiveOrg,
    Wayback,
    GitHub,
    Zenodo,
    Figshare,
    HuggingFace,
    WebSearch,
    Mirror,
    Origin,
}

impl Platform {
    /// 机器可读名字（snake_case，落库文本）。
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::ArchiveOrg => "archive_org",
            Platform::Wayback => "wayback",
            Platform::GitHub => "github",
            Platform::Zenodo => "zenodo",
            Platform::Figshare => "figshare",
            Platform::HuggingFace => "hugging_face",
            Platform::WebSearch => "web_search",
            Platform::Mirror => "mirror",
            Platform::Origin => "origin",
        }
    }

    /// 从落库文本还原；未知值返回 `None`（不猜）。
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "archive_org" => Platform::ArchiveOrg,
            "wayback" => Platform::Wayback,
            "github" => Platform::GitHub,
            "zenodo" => Platform::Zenodo,
            "figshare" => Platform::Figshare,
            "hugging_face" => Platform::HuggingFace,
            "web_search" => Platform::WebSearch,
            "mirror" => Platform::Mirror,
            "origin" => Platform::Origin,
            _ => return None,
        })
    }
}

/// 候选的形态。只有 [`SourceKind::File`] 能直接交给探测器。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Page,
    Record,
    File,
}

impl SourceKind {
    /// 机器可读名字（对齐 `source_candidates.kind -- page | record | file`）。
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Page => "page",
            SourceKind::Record => "record",
            SourceKind::File => "file",
        }
    }

    /// 能否直接探测/下载（只有 `File` 可以）。
    pub fn is_direct_file(self) -> bool {
        matches!(self, SourceKind::File)
    }

    /// 从落库文本还原；未知值返回 `None`。
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "page" => SourceKind::Page,
            "record" => SourceKind::Record,
            "file" => SourceKind::File,
            _ => return None,
        })
    }
}

/// 一个候选源：找源器的原始产物，未经验证、未去重。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSource {
    /// 候选地址（可能仍是页面/记录）。
    pub url: String,
    pub platform: Platform,
    pub kind: SourceKind,
    /// 平台声明的大小（字节）。
    pub size: Option<u64>,
    /// 平台声明的版本/发布标签。**不从文件名猜**（§4.1）。
    pub version: Option<String>,
    /// 压缩包/容器类型（如 `"zip"`/`"tar"`/`"iso"`）；用于阻止"压缩包与解压内容"
    /// 被并进同一组（§4.6）。
    pub container: Option<String>,
    pub evidence: IdentityEvidence,
    /// 该平台需要的认证引用（不复制凭据）。
    pub auth_ref: Option<String>,
    /// 出处：查询串摘要、记录 ID、页面地址；只用于排查，不用于身份。
    pub origin: Option<String>,
    /// 签名地址/临时地址的过期时刻（unix 毫秒）。
    pub expires_at: Option<i64>,
}

/// 运行时能力（§3.3）。**协议允许 ≠ 运行时可用**：`random_read` 必须由探测确认，
/// 探测失败一律按 `false` 处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceCapabilities {
    /// 真实 `206` + 合法 `Content-Range` 才算。
    pub random_read: bool,
    /// 支持从偏移续读。
    pub resume: bool,
    /// 能报出总长。
    pub length_query: bool,
    /// 能提供 ETag / Last-Modified 等**单源**版本标识（跨源不可比）。
    pub version_check: bool,
    /// 该源允许的并发连接（探测/配置/平台声明取小）。
    pub conns_max: u16,
}

impl Default for SourceCapabilities {
    /// 保守缺省：所有能力都当"还没验证过"，并发按 §5.6 的默认值 4。
    fn default() -> Self {
        SourceCapabilities {
            random_read: false,
            resume: false,
            length_query: false,
            version_check: false,
            conns_max: 4,
        }
    }
}

/// 解析后的文件地址 + 响应头摘要（§3.1、§4.5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    /// 解析前的地址（页面/记录地址）。
    pub url: String,
    /// 跟随重定向后的最终地址。
    pub final_url: String,
    pub size: Option<u64>,
    pub content_type: Option<String>,
    /// 从 `Content-Disposition` 或 URL 末段取出的文件名（只用于与任务名比较，
    /// **不回写任务名**，§4.1）。
    pub file_name: Option<String>,
    /// 签名地址的过期时刻（unix 毫秒）。
    pub expires_at: Option<i64>,
}

/// 一次查询的形状（§4.3）：按可用信号选适配器与查询参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceQuery {
    pub file_name: String,
    pub size: Option<u64>,
    /// 可信的声明哈希（只包含 `TaskInput` / 元数据 / 平台来源）。
    pub hashes: Vec<DeclaredHash>,
    pub version: Option<String>,
    /// 原始 URL（Wayback/镜像族按它查）。
    pub orig_url: Option<String>,
    /// 任务来源平台的查询提示（不是身份）。
    pub source_hint: Option<Platform>,
}

impl SourceQuery {
    /// 最强的一条可信哈希（强摘要优先）。查询里没有可信哈希时返回 `None`。
    pub fn best_hash(&self) -> Option<&DeclaredHash> {
        self.hashes.iter().find(|h| {
            h.is_trusted() && h.algo.strength() == super::evidence::DigestStrength::Strong
        })
    }

    /// 是否有任何可用于查询的可信哈希。
    pub fn has_trusted_hash(&self) -> bool {
        self.hashes.iter().any(|h| h.is_trusted())
    }

    /// 清单里出现的算法集合（去重，保持出现顺序）—— 用于"这个平台能不能给出这种摘要"。
    pub fn hash_algos(&self) -> Vec<HashAlgo> {
        let mut out: Vec<HashAlgo> = Vec::new();
        for h in &self.hashes {
            if !out.contains(&h.algo) {
                out.push(h.algo);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::evidence::{DigestStrength, EvidenceOrigin};

    fn dh(algo: HashAlgo, hex: &str, origin: EvidenceOrigin) -> DeclaredHash {
        DeclaredHash {
            algo,
            hex: hex.to_string(),
            origin,
        }
    }

    #[test]
    fn platform_strings_are_snake_case_and_stable() {
        let all = [
            (Platform::ArchiveOrg, "archive_org"),
            (Platform::Wayback, "wayback"),
            (Platform::GitHub, "github"),
            (Platform::Zenodo, "zenodo"),
            (Platform::Figshare, "figshare"),
            (Platform::HuggingFace, "hugging_face"),
            (Platform::WebSearch, "web_search"),
            (Platform::Mirror, "mirror"),
            (Platform::Origin, "origin"),
        ];
        for (p, s) in all {
            assert_eq!(p.as_str(), s);
            assert!(
                s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{s} 必须是 snake_case"
            );
        }
        assert_eq!(SourceKind::File.as_str(), "file");
        assert!(SourceKind::File.is_direct_file());
        assert!(!SourceKind::Page.is_direct_file());
        assert!(!SourceKind::Record.is_direct_file());
    }

    #[test]
    fn capabilities_default_to_unverified_with_four_conns() {
        let c = SourceCapabilities::default();
        assert!(!c.random_read, "random_read 必须由探测确认，不能默认 true");
        assert!(!c.resume);
        assert!(!c.length_query);
        assert!(!c.version_check);
        assert_eq!(c.conns_max, 4, "默认每源并发 4（§5.6）");
    }

    #[test]
    fn query_best_hash_prefers_strong_and_ignores_computed() {
        let q = SourceQuery {
            file_name: "a.iso".into(),
            size: Some(1024),
            hashes: vec![
                dh(
                    HashAlgo::Md5,
                    "d41d8cd98f00b204e9800998ecf8427e",
                    EvidenceOrigin::TaskInput,
                ),
                dh(HashAlgo::Sha256, "aa", EvidenceOrigin::Computed),
                dh(HashAlgo::Sha256, "bb", EvidenceOrigin::UpstreamMetadata),
            ],
            version: None,
            orig_url: None,
            source_hint: None,
        };
        assert_eq!(q.best_hash().map(|h| h.hex.as_str()), Some("bb"));
        assert!(q.has_trusted_hash());
        assert_eq!(q.hash_algos(), vec![HashAlgo::Md5, HashAlgo::Sha256]);
        // 只有 Computed 时不算"有可信哈希"。
        let only_computed = SourceQuery {
            hashes: vec![dh(HashAlgo::Sha256, "aa", EvidenceOrigin::Computed)],
            ..q
        };
        assert!(!only_computed.has_trusted_hash());
        assert!(only_computed.best_hash().is_none());
        assert_eq!(
            dh(HashAlgo::Sha256, "bb", EvidenceOrigin::UpstreamMetadata).strength(),
            DigestStrength::Strong
        );
    }
}
