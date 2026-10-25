//! 任务标准化器（`docs/source-discovery.md` §4.1）：把一行 `DownloadRow` 变成
//! **只读**的 [`TaskProfile`]。
//!
//! 三条边界（改之前先读）：
//!
//! 1. **不新增持久化真相**：`TaskProfile` 全是 `DownloadRow` 的派生，不回写任何列；
//!    文件名只取已过闸门的 `file_name`，候选源声明的名字只在验证器里做比较。
//! 2. **不猜**：`version` 只从用户输入、平台 API、上游元数据取，**不从文件名正则猜**；
//!    本仓库的 `DownloadRow` 目前没有这一列，所以 `from_row` 恒为 `None`。
//! 3. **哈希只认规定来源**：`sha256_expected` 落库值视为 `UpstreamMetadata`；
//!    eD2k 的 `ed2k_hash` 是 `Md4`（**弱摘要**，eD2k 走自己的校验路径）。
//!    本地算出来的哈希（`Computed`）永远不进 [`TaskProfile::best_evidence`]。

use super::candidate::Platform;
use super::evidence::{DeclaredHash, DigestStrength, EvidenceOrigin, HashAlgo, IdentityEvidence};
use crate::model::DownloadRow;

/// 任务级找源策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskPolicy {
    /// 是否允许为这个任务找源。
    pub allow_find: bool,
    /// 是否允许跨源分段（实际还要过证据级别 `L3`/`L4`）。
    pub allow_multi_source: bool,
    /// 同组进入调度池的来源上限（§4.6 `MAX_SOURCES`）。
    pub max_sources: usize,
}

impl Default for TaskPolicy {
    fn default() -> Self {
        TaskPolicy {
            allow_find: true,
            allow_multi_source: true,
            max_sources: 4,
        }
    }
}

/// 任务视图：`DownloadRow` + 策略的只读派生，**不落库**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskProfile {
    pub task_id: i64,
    pub orig_url: String,
    pub final_url: Option<String>,
    pub file_name: String,
    pub size: Option<u64>,
    /// 可信的声明哈希（按 `sha256_expected` → `ed2k_hash` 顺序追加）。
    pub hashes: Vec<DeclaredHash>,
    /// 版本标签。**不从文件名猜**；`DownloadRow` 无此列，故 `from_row` 恒为 `None`。
    pub version: Option<String>,
    /// 站点凭据或 URL 内认证的**引用**（不存明文）；`DownloadRow` 无此列，故恒为 `None`。
    pub auth_ref: Option<String>,
    pub policy: TaskPolicy,
    /// 任务来源平台的查询提示（不是身份）。
    pub source_hint: Option<Platform>,
}

impl TaskProfile {
    /// 从落库行派生任务视图。**只读**：不修改 `DownloadRow`，不猜哈希来源。
    ///
    /// 映射规则：
    /// - `sha256_expected`（非空）→ `DeclaredHash { Sha256, UpstreamMetadata }`；
    /// - `ed2k_hash`（非空）→ `DeclaredHash { Md4, UpstreamMetadata }`（弱摘要）；
    /// - `size_total <= 0` → `None`（未探测出来，不是"零字节文件"）。
    ///
    /// `version` / `auth_ref` / `source_hint` 在当前表结构里没有对应列，
    /// 因此一律为 `None` —— 宁可缺字段，也不从文件名或 URL 里"推测"出来。
    pub fn from_row(row: &DownloadRow, policy: TaskPolicy) -> Self {
        let mut hashes: Vec<DeclaredHash> = Vec::new();
        if let Some(hex) = non_empty(&row.sha256_expected) {
            hashes.push(DeclaredHash {
                algo: HashAlgo::Sha256,
                hex: hex.to_string(),
                origin: EvidenceOrigin::UpstreamMetadata,
            });
        }
        if let Some(hex) = non_empty(&row.ed2k_hash) {
            hashes.push(DeclaredHash {
                algo: HashAlgo::Md4,
                hex: hex.to_string(),
                origin: EvidenceOrigin::UpstreamMetadata,
            });
        }
        TaskProfile {
            task_id: row.id,
            orig_url: row.url_orig.clone(),
            final_url: row.url_final.clone(),
            file_name: row.file_name.clone(),
            size: match row.size_total {
                Some(v) if v > 0 => Some(v as u64),
                _ => None,
            },
            hashes,
            version: None,
            auth_ref: None,
            policy,
            source_hint: None,
        }
    }

    /// 最高级别的证据。
    ///
    /// - 有可信的强摘要 → `StrongDigest`（`L4`，可跨源）；
    /// - 只有弱摘要 → `WeakDigest`（`L2`，只够完成后对账）；
    /// - 都没哈希但知道大小 → `SizeOnly`（`L1`，顺序换源）；
    /// - 连大小都没有 → `Unverified`（`L0`）。
    ///
    /// 不可信来源（`Computed`）一律跳过：本地算出来的哈希不能升格为文件身份。
    pub fn best_evidence(&self) -> IdentityEvidence {
        let mut weakest: Option<&DeclaredHash> = None;
        for h in self.hashes.iter().filter(|h| h.is_trusted()) {
            if h.strength() == DigestStrength::Strong {
                return IdentityEvidence::StrongDigest(h.clone());
            }
            if weakest.is_none() {
                weakest = Some(h);
            }
        }
        if let Some(h) = weakest {
            return IdentityEvidence::WeakDigest(h.clone());
        }
        match self.size {
            Some(size) if size > 0 => IdentityEvidence::SizeOnly { size },
            _ => IdentityEvidence::Unverified,
        }
    }

    /// 实际生效的地址（解析后的优先）。
    pub fn effective_url(&self) -> &str {
        self.final_url.as_deref().unwrap_or(&self.orig_url)
    }

    /// 是否允许把这个任务交给找源器（策略 + 布尔化后的证据级别各管一半）。
    pub fn may_find(&self) -> bool {
        self.policy.allow_find
    }

    /// 是否允许跨源分段：策略允许**且**证据级别到 `L3`/`L4`。
    pub fn allows_multi_source(&self) -> bool {
        self.policy.allow_multi_source && self.best_evidence().allows_multi_source()
    }
}

/// 取非空（去掉首尾空白后仍非空）的字符串。
fn non_empty(v: &Option<String>) -> Option<&str> {
    let s = v.as_deref()?.trim();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Status;
    use crate::source::evidence::EvidenceLevel;

    /// 构造一行"除了被测字段之外都无关"的任务行。
    fn row() -> DownloadRow {
        DownloadRow {
            id: 42,
            url_orig: "https://origin.test/a.iso".into(),
            url_final: Some("https://cdn.test/a.iso".into()),
            file_name: "a.iso".into(),
            dir: "C:\\downloads".into(),
            size_total: Some(1024),
            etag: Some("\"v1\"".into()),
            last_modified: None,
            status: Status::Queued,
            created_at: 1,
            finished_at: None,
            error_code: None,
            error_message: None,
            http_status: None,
            speed_limit_kbps: 0,
            max_conns: 0,
            source: "manual".into(),
            referrer: None,
            custom_headers: None,
            alt_urls: None,
            alt_cursor: 0,
            queue_id: 1,
            bt_files: None,
            active_ms: 0,
            ed2k_hash: None,
            aich_root: None,
            sha256_expected: None,
            priority: 0,
            retry_at: None,
            retry_count: 0,
            start_mode: "now".into(),
            find_rounds: 0,
            find_spent_ms: 0,
            find_last_at: None,
        }
    }

    const SHA: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const ED2K: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

    #[test]
    fn maps_sha256_expected_and_ed2k_hash() {
        let mut r = row();
        r.sha256_expected = Some(SHA.into());
        r.ed2k_hash = Some(ED2K.into());
        let p = TaskProfile::from_row(&r, TaskPolicy::default());

        assert_eq!(p.task_id, 42);
        assert_eq!(p.orig_url, "https://origin.test/a.iso");
        assert_eq!(p.final_url.as_deref(), Some("https://cdn.test/a.iso"));
        assert_eq!(p.effective_url(), "https://cdn.test/a.iso");
        assert_eq!(p.file_name, "a.iso");
        assert_eq!(p.size, Some(1024));
        assert_eq!(p.hashes.len(), 2);

        assert_eq!(p.hashes[0].algo, HashAlgo::Sha256);
        assert_eq!(p.hashes[0].hex, SHA);
        assert_eq!(p.hashes[0].origin, EvidenceOrigin::UpstreamMetadata);
        // eD2k 的 MD4 是弱摘要，来源同为上游元数据
        assert_eq!(p.hashes[1].algo, HashAlgo::Md4);
        assert_eq!(p.hashes[1].origin, EvidenceOrigin::UpstreamMetadata);
        assert_eq!(p.hashes[1].strength(), DigestStrength::Weak);

        // 不从文件名/URL 猜
        assert_eq!(p.version, None);
        assert_eq!(p.auth_ref, None);
        assert_eq!(p.source_hint, None);
    }

    #[test]
    fn blank_hashes_are_ignored() {
        let mut r = row();
        r.sha256_expected = Some("   ".into());
        r.ed2k_hash = Some(String::new());
        let p = TaskProfile::from_row(&r, TaskPolicy::default());
        assert!(p.hashes.is_empty(), "空白哈希不能造出证据: {:?}", p.hashes);
        assert_eq!(p.best_evidence(), IdentityEvidence::SizeOnly { size: 1024 });
    }

    #[test]
    fn non_positive_size_is_none() {
        for v in [Some(0i64), Some(-1), None] {
            let mut r = row();
            r.size_total = v;
            let p = TaskProfile::from_row(&r, TaskPolicy::default());
            assert_eq!(p.size, None, "size_total={v:?} 应为 None");
            assert_eq!(p.best_evidence(), IdentityEvidence::Unverified);
        }
    }

    #[test]
    fn best_evidence_priority_is_strong_weak_size_unverified() {
        // 只有大小
        let mut r = row();
        r.size_total = Some(7);
        assert_eq!(
            TaskProfile::from_row(&r, TaskPolicy::default()).best_evidence(),
            IdentityEvidence::SizeOnly { size: 7 }
        );

        // 弱摘要盖过大小
        r.ed2k_hash = Some(ED2K.into());
        let weak = TaskProfile::from_row(&r, TaskPolicy::default()).best_evidence();
        assert_eq!(weak.level(), EvidenceLevel::L2WeakDigest);
        assert!(!weak.allows_multi_source());

        // 强摘要盖过弱摘要（即使弱摘要先入列）
        r.sha256_expected = Some(SHA.into());
        let best = TaskProfile::from_row(&r, TaskPolicy::default()).best_evidence();
        assert_eq!(best.level(), EvidenceLevel::L4StrongDigest);
        assert!(best.allows_multi_source());
        match best {
            IdentityEvidence::StrongDigest(h) => assert_eq!(h.algo, HashAlgo::Sha256),
            other => panic!("应为 StrongDigest，实际 {other:?}"),
        }
        // 连大小都没有 → Unverified
        let mut empty = row();
        empty.size_total = None;
        assert_eq!(
            TaskProfile::from_row(&empty, TaskPolicy::default()).best_evidence(),
            IdentityEvidence::Unverified
        );
    }

    #[test]
    fn computed_hash_never_becomes_identity() {
        let mut p = TaskProfile::from_row(&row(), TaskPolicy::default());
        p.size = None;
        p.hashes = vec![DeclaredHash {
            algo: HashAlgo::Sha256,
            hex: SHA.into(),
            origin: EvidenceOrigin::Computed,
        }];
        // 本地算出来的强摘要也不能当身份：退回 L0。
        assert_eq!(p.best_evidence(), IdentityEvidence::Unverified);
        assert!(!p.allows_multi_source());

        // 有大小的时候退回 L1，仍然不授权跨源。
        p.size = Some(9);
        let ev = p.best_evidence();
        assert_eq!(ev, IdentityEvidence::SizeOnly { size: 9 });
        assert!(!ev.allows_multi_source());
    }

    #[test]
    fn policy_gates_find_and_multi_source() {
        let mut r = row();
        r.sha256_expected = Some(SHA.into());

        let off = TaskPolicy {
            allow_find: false,
            allow_multi_source: false,
            max_sources: 1,
        };
        let p = TaskProfile::from_row(&r, off);
        assert_eq!(p.policy, off);
        assert!(!p.may_find());
        // 证据够了，但策略不许 → 仍然不许
        assert!(!p.allows_multi_source());
        assert!(p.best_evidence().allows_multi_source());

        let on = TaskProfile::from_row(&r, TaskPolicy::default());
        assert!(on.may_find());
        assert!(on.allows_multi_source());
        assert_eq!(TaskPolicy::default().max_sources, 4);
    }
}
