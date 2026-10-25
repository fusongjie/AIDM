//! 一致性证据分级 `L0`–`L4`（`docs/source-discovery.md` §3.2，核心不变量）。
//!
//! 任何候选都必须落到下面五级之一；**级别决定它能做什么，不能越级**：
//!
//! | 级别 | 证据 | 允许的行为 | 跨源分段 |
//! |---|---|---|---|
//! | `L4 StrongDigest` | SHA-256 / SHA-512 / BLAKE3 | 完成后整文件校验；可跨源 | ✅ |
//! | `L3 PieceManifest` | BT piece / eD2k MD4 分片树 / 上游分片清单 | 逐片校验；可跨源 | ✅ |
//! | `L2 WeakDigest` | MD5 / SHA-1 | 完成后对账，**不授权混源** | ❌ |
//! | `L1 SizeOnly` | 只有长度（+ 文件名） | 顺序换源（现状 `alt` 行为） | ❌ |
//! | `L0 Unverified` | 什么都没有 | 独立尝试，换源从零开始 | ❌ |
//!
//! 三条硬不变量在本模块里落地：
//!
//! 1. **只有 `L3` / `L4` 允许跨源**（[`IdentityEvidence::allows_multi_source`]）；
//! 2. **`Computed` 永远不是文件身份**（[`DeclaredHash::is_trusted`]）——
//!    本地算出来的哈希只能作为 `observed_digest` 写进事件与诊断；
//! 3. **弱摘要不越级**：`StrongDigest` 里若装了弱算法，[`IdentityEvidence::level`]
//!    按算法实际强度降级到 `L2`（宁可少授权跨源，也不让 MD5 冒充 `L4`）。
//!
//! `ETag` 不在这里：它只属于"某个地址的某个版本"，跨源不可比（§3.2 附加不变量）。

/// 摘要算法。强 / 弱划分见 [`HashAlgo::strength`]。
///
/// `Md4` 单列出来是因为 eD2k 按协议定义就要 MD4（RFC 1320）：它在本仓库走
/// **自己的校验路径**（`crate::ed2k` 的分片树），不参与 HTTP 侧的跨源判断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Sha256,
    Sha512,
    Blake3,
    Md5,
    Sha1,
    Md4,
}

impl HashAlgo {
    /// 机器可读名字：落库 `source_candidates.digest_algo` 与分组键都用它。
    pub fn as_str(self) -> &'static str {
        match self {
            HashAlgo::Sha256 => "sha256",
            HashAlgo::Sha512 => "sha512",
            HashAlgo::Blake3 => "blake3",
            HashAlgo::Md5 => "md5",
            HashAlgo::Sha1 => "sha1",
            HashAlgo::Md4 => "md4",
        }
    }

    /// 从落库文本还原；未知值返回 `None`。
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "sha256" => HashAlgo::Sha256,
            "sha512" => HashAlgo::Sha512,
            "blake3" => HashAlgo::Blake3,
            "md5" => HashAlgo::Md5,
            "sha1" => HashAlgo::Sha1,
            "md4" => HashAlgo::Md4,
            _ => return None,
        })
    }

    /// 强 / 弱：SHA-256 / SHA-512 / BLAKE3 是强摘要，其余一律弱摘要。
    pub fn strength(self) -> DigestStrength {
        match self {
            HashAlgo::Sha256 | HashAlgo::Sha512 | HashAlgo::Blake3 => DigestStrength::Strong,
            HashAlgo::Md5 | HashAlgo::Sha1 | HashAlgo::Md4 => DigestStrength::Weak,
        }
    }
}

/// 摘要强度：决定"完成后能不能对账"与"能不能授权跨源"。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestStrength {
    Strong,
    Weak,
}

/// 哈希的**来源**。决定它能不能当文件身份。
///
/// 可信来源只有前四个；`Computed`（本地算出来的）永远不能升格为身份。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceOrigin {
    /// 用户输入（粘贴的链接/扩展带过来的校验和）。
    TaskInput,
    /// 上游元数据（`.metalink` / `.meta4` / `CHECKSUM` / `<文件名>.sha256`）。
    UpstreamMetadata,
    /// 发布方 API（GitHub Releases `digest` 之类）。
    PublisherApi,
    /// 平台 API（archive.org 元数据、Zenodo `checksum` 之类）。
    PlatformApi,
    /// 本地算出来的哈希。永远不能升格为文件身份。
    Computed,
}

/// 一条**被声明**的摘要：算法 + hex + 来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredHash {
    pub algo: HashAlgo,
    pub hex: String,
    pub origin: EvidenceOrigin,
}

impl DeclaredHash {
    /// 强 / 弱（按算法，不看来源 —— 来源只影响能不能当身份）。
    pub fn strength(&self) -> DigestStrength {
        self.algo.strength()
    }

    /// 是否来自可信来源（`Computed` 之外都算）。
    ///
    /// 不可信的哈希只能当"观察值"（`observed_digest`），不能参与身份判定。
    pub fn is_trusted(&self) -> bool {
        !matches!(self.origin, EvidenceOrigin::Computed)
    }

    /// 判重/比对用的 hex：去掉所有空白字符、转小写。
    ///
    /// 只做这两件事 —— 不改写 `sha256:` 之类的前缀、不补零，保持"原文可见"，
    /// 让上层的长度校验（32/64/128 位）自己报错而不是在这里被吃掉。
    pub fn normalized_hex(&self) -> String {
        self.hex
            .chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| c.to_ascii_lowercase())
            .collect()
    }
}

/// 证据级别。`Ord` 的先后就是强弱顺序（`L0 < L1 < … < L4`），排序直接用它。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceLevel {
    L0Unverified,
    L1SizeOnly,
    L2WeakDigest,
    L3PieceManifest,
    L4StrongDigest,
}

impl EvidenceLevel {
    /// 机器可读名字（对齐 `source_candidates.evidence -- l4 | l3 | l2 | l1 | l0`）。
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceLevel::L0Unverified => "l0",
            EvidenceLevel::L1SizeOnly => "l1",
            EvidenceLevel::L2WeakDigest => "l2",
            EvidenceLevel::L3PieceManifest => "l3",
            EvidenceLevel::L4StrongDigest => "l4",
        }
    }
}

/// 一个候选（或一个任务）拿得出的最高身份证据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityEvidence {
    StrongDigest(DeclaredHash),
    PieceManifest {
        /// 清单标识：BT infohash、eD2k AICH 根、上游清单 URL 摘要等。
        id: String,
        /// 清单里每个分片用的算法。
        algo: HashAlgo,
    },
    WeakDigest(DeclaredHash),
    SizeOnly {
        size: u64,
    },
    Unverified,
}

impl IdentityEvidence {
    /// 级别。
    ///
    /// 防御性规则：`StrongDigest` 装的若是弱算法（构造时越级），按算法实际强度
    /// 降级到 `L2` —— `L2` 不授权跨源，所以越级的代价只是"少一次并行"，
    /// 而不是"把 MD5 相同当成文件相同"。
    pub fn level(&self) -> EvidenceLevel {
        match self {
            IdentityEvidence::StrongDigest(h) => match h.strength() {
                DigestStrength::Strong => EvidenceLevel::L4StrongDigest,
                DigestStrength::Weak => EvidenceLevel::L2WeakDigest,
            },
            IdentityEvidence::PieceManifest { .. } => EvidenceLevel::L3PieceManifest,
            IdentityEvidence::WeakDigest(_) => EvidenceLevel::L2WeakDigest,
            IdentityEvidence::SizeOnly { .. } => EvidenceLevel::L1SizeOnly,
            IdentityEvidence::Unverified => EvidenceLevel::L0Unverified,
        }
    }

    /// 只有 `L3` / `L4` 返回 `true`（§3.2：其余级别"不足以授权跨源混合"）。
    pub fn allows_multi_source(&self) -> bool {
        matches!(
            self.level(),
            EvidenceLevel::L3PieceManifest | EvidenceLevel::L4StrongDigest
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dh(algo: HashAlgo, hex: &str, origin: EvidenceOrigin) -> DeclaredHash {
        DeclaredHash {
            algo,
            hex: hex.to_string(),
            origin,
        }
    }

    fn strong_sha() -> DeclaredHash {
        dh(
            HashAlgo::Sha256,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            EvidenceOrigin::UpstreamMetadata,
        )
    }

    #[test]
    fn strong_and_weak_algorithms() {
        for a in [HashAlgo::Sha256, HashAlgo::Sha512, HashAlgo::Blake3] {
            assert_eq!(a.strength(), DigestStrength::Strong, "{a:?} 应为强摘要");
        }
        // eD2k 的 MD4 是**按协议**必须弱：它走自己的校验路径，不授权跨源。
        for a in [HashAlgo::Md5, HashAlgo::Sha1, HashAlgo::Md4] {
            assert_eq!(a.strength(), DigestStrength::Weak, "{a:?} 应为弱摘要");
        }
        assert_eq!(strong_sha().strength(), DigestStrength::Strong);
        assert_eq!(
            dh(
                HashAlgo::Md5,
                "d41d8cd98f00b204e9800998ecf8427e",
                EvidenceOrigin::TaskInput
            )
            .strength(),
            DigestStrength::Weak
        );
        assert_eq!(HashAlgo::Md5.as_str(), "md5");
        assert_eq!(HashAlgo::Blake3.as_str(), "blake3");
    }

    #[test]
    fn computed_hash_is_never_trusted() {
        let computed = dh(HashAlgo::Sha256, "aa", EvidenceOrigin::Computed);
        assert!(!computed.is_trusted(), "本地算出来的哈希不能当文件身份");
        // 即使算法是强摘要，来源不可信也没用。
        assert_eq!(computed.strength(), DigestStrength::Strong);
        for origin in [
            EvidenceOrigin::TaskInput,
            EvidenceOrigin::UpstreamMetadata,
            EvidenceOrigin::PublisherApi,
            EvidenceOrigin::PlatformApi,
        ] {
            assert!(
                dh(HashAlgo::Md5, "d41d8cd98f00b204e9800998ecf8427e", origin).is_trusted(),
                "{origin:?} 是可信来源"
            );
        }
    }

    #[test]
    fn normalized_hex_strips_whitespace_and_lowercases() {
        let h = dh(
            HashAlgo::Sha256,
            "  9F86 D081884C7D659A2FEAA0C55AD015\nA3BF4F1B2B0B822CD15D6C15B0F00A08\t",
            EvidenceOrigin::TaskInput,
        );
        assert_eq!(
            h.normalized_hex(),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        // 前缀与短 hex 不做改写，交给上层长度校验。
        let prefixed = dh(HashAlgo::Sha256, "SHA256:ABC", EvidenceOrigin::PublisherApi);
        assert_eq!(prefixed.normalized_hex(), "sha256:abc");
    }

    #[test]
    fn allows_multi_source_only_for_l3_and_l4() {
        let cases = [
            (IdentityEvidence::StrongDigest(strong_sha()), true),
            (
                IdentityEvidence::PieceManifest {
                    id: "infohash".into(),
                    algo: HashAlgo::Sha1,
                },
                true,
            ),
            (
                IdentityEvidence::WeakDigest(dh(
                    HashAlgo::Sha1,
                    "a9993e364706816aba3e25717850c26c9cd0d89d",
                    EvidenceOrigin::PlatformApi,
                )),
                false,
            ),
            (IdentityEvidence::SizeOnly { size: 1024 }, false),
            (IdentityEvidence::Unverified, false),
        ];
        for (ev, allowed) in cases {
            assert_eq!(ev.allows_multi_source(), allowed, "{ev:?}");
            assert_eq!(
                ev.allows_multi_source(),
                matches!(
                    ev.level(),
                    EvidenceLevel::L3PieceManifest | EvidenceLevel::L4StrongDigest
                ),
                "{ev:?}"
            );
        }
    }

    #[test]
    fn levels_follow_the_declared_order() {
        let levels = [
            IdentityEvidence::Unverified,
            IdentityEvidence::SizeOnly { size: 1 },
            IdentityEvidence::WeakDigest(dh(
                HashAlgo::Md5,
                "d41d8cd98f00b204e9800998ecf8427e",
                EvidenceOrigin::PlatformApi,
            )),
            IdentityEvidence::PieceManifest {
                id: "p".into(),
                algo: HashAlgo::Sha256,
            },
            IdentityEvidence::StrongDigest(strong_sha()),
        ];
        let got: Vec<EvidenceLevel> = levels.iter().map(|e| e.level()).collect();
        assert_eq!(
            got,
            vec![
                EvidenceLevel::L0Unverified,
                EvidenceLevel::L1SizeOnly,
                EvidenceLevel::L2WeakDigest,
                EvidenceLevel::L3PieceManifest,
                EvidenceLevel::L4StrongDigest,
            ]
        );
        // 级别名要与落库文本一致（§7.2 `evidence TEXT -- l4 | l3 | l2 | l1 | l0`）。
        assert_eq!(EvidenceLevel::L4StrongDigest.as_str(), "l4");
        assert_eq!(EvidenceLevel::L0Unverified.as_str(), "l0");
    }

    #[test]
    fn strong_variant_holding_a_weak_algo_is_downgraded() {
        // 构造越级：拿 MD5 塞进 StrongDigest。降级到 L2，不授权跨源。
        let bad = IdentityEvidence::StrongDigest(dh(
            HashAlgo::Md5,
            "d41d8cd98f00b204e9800998ecf8427e",
            EvidenceOrigin::PlatformApi,
        ));
        assert_eq!(bad.level(), EvidenceLevel::L2WeakDigest);
        assert!(!bad.allows_multi_source(), "MD5 不得授权跨源混合");
    }
}
