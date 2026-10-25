//! 平台适配器契约（`docs/source-discovery.md` §4.4）。
//!
//! 一个适配器只负责三件事：**查询**、**把页面/记录解析成文件地址**、**刷新临时地址**。
//! 它不负责去重、分组、验证、评分——那些是 finder / 结果处理器的职责。
//!
//! # 边界
//!
//! - 认证只从 [`CandidateSource::auth_ref`] 取，按目标域名判定；重定向到别的域名
//!   必须重新判定（`docs/guides/12-credentials-access.md` R-CR）。
//! - 返回的每一项必须带 [`SourceKind`]，**不能**把网页直接当文件；
//!   页面/记录由 [`PlatformAdapter::resolve`] 转成 [`ResolvedTarget`]。
//! - 错误串里的 URL 必须过 `aidm_core::redact::redact_text`：ureq/平台 SDK 的
//!   Display 常常带完整查询串（§8.2）。

use aidm_core::source::{CandidateSource, Platform, ResolvedTarget, SourceQuery};

/// 适配器错误。**不新增任务失败码**；这些只在找源层内部与事件 `detail` 里使用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdapterError {
    /// 这个平台不适用于当前查询（例如没有仓库线索的 GitHub）。不写负缓存。
    Unsupported,
    /// 平台返回了无法解析的数据（JSON/HTML 结构变了）。不猜。
    Malformed(String),
    /// 平台返回 401/403（需要认证或凭据失效）。
    Auth { status: u16 },
    /// 平台返回非 2xx。`status` 是 HTTP 状态码。
    Http { status: u16 },
    /// 网络/超时；字符串必须已脱敏。
    Network(String),
    /// 本平台配额用尽；`retry_after_ms` 是建议等待时间。
    Quota { retry_after_ms: i64 },
    /// 单次查询超时（适配器内部 deadline）。
    Timeout,
    /// 页面/记录里没有找到目标文件的下载地址。
    NotFound,
    /// 配置缺失（例如通用 Web 搜索没有 endpoint/key）。
    Config(String),
}

impl AdapterError {
    /// 网络类错误可以换时间重试；`Unsupported`/`Malformed`/`Config` 不要自动重试。
    pub fn is_retryable(&self) -> bool {
        match self {
            AdapterError::Network(_) | AdapterError::Timeout | AdapterError::Quota { .. } => true,
            AdapterError::Http { status } => *status == 429 || *status >= 500,
            AdapterError::Auth { .. } => false,
            AdapterError::Unsupported
            | AdapterError::Malformed(_)
            | AdapterError::NotFound
            | AdapterError::Config(_) => false,
        }
    }

    /// HTTP 状态码 → 分类（401/403 认证、404/410 未找到，其余 Http）。
    pub fn from_status(status: u16) -> Self {
        match status {
            401 | 403 => AdapterError::Auth { status },
            404 | 410 => AdapterError::NotFound,
            _ => AdapterError::Http { status },
        }
    }

    /// 构造一个已脱敏的网络错误。
    pub fn network(msg: impl AsRef<str>) -> Self {
        AdapterError::Network(aidm_core::redact::redact_text(msg.as_ref()).into_owned())
    }

    /// 机器可读分类（事件 `detail` 用；不要写自由文本）。
    pub fn code(&self) -> &'static str {
        match self {
            AdapterError::Unsupported => "unsupported",
            AdapterError::Malformed(_) => "malformed",
            AdapterError::Auth { .. } => "auth",
            AdapterError::Http { .. } => "http",
            AdapterError::Network(_) => "network",
            AdapterError::Quota { .. } => "quota",
            AdapterError::Timeout => "timeout",
            AdapterError::NotFound => "not_found",
            AdapterError::Config(_) => "config",
        }
    }
}

/// 一次查询的预算（由 finder 计算，适配器只读）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchBudget {
    pub now_ms: i64,
    /// 绝对截止时刻（毫秒）。适配器内部 HTTP 超时必须不超过剩余时间。
    pub deadline_ms: i64,
    /// 本平台最多返回多少条（finder 还会做全局截断）。
    pub max_results: usize,
}

impl SearchBudget {
    pub fn new(now_ms: i64, total_ms: i64, max_results: usize) -> Self {
        SearchBudget {
            now_ms,
            deadline_ms: now_ms.saturating_add(total_ms.max(0)),
            max_results: max_results.max(1),
        }
    }

    /// 相对当前时刻还剩多少毫秒；已过期为 0。
    pub fn remaining_ms(&self, now_ms: i64) -> i64 {
        self.deadline_ms.saturating_sub(now_ms).max(0)
    }

    pub fn expired(&self, now_ms: i64) -> bool {
        now_ms >= self.deadline_ms
    }
}

/// 平台适配器。
pub trait PlatformAdapter: Send + Sync {
    fn platform(&self) -> Platform;

    /// 查询。返回的候选可能仍是 Page/Record；finder 只做汇总，不验证。
    fn search(
        &self,
        query: &SourceQuery,
        budget: SearchBudget,
    ) -> Result<Vec<CandidateSource>, AdapterError>;

    /// 页面/记录 → 可下载文件地址。默认不支持。
    fn resolve(&self, _candidate: &CandidateSource) -> Result<ResolvedTarget, AdapterError> {
        Err(AdapterError::Unsupported)
    }

    /// 临时/签名地址刷新。默认不支持。
    fn refresh(&self, _target: &ResolvedTarget) -> Result<ResolvedTarget, AdapterError> {
        Err(AdapterError::Unsupported)
    }

    /// 平台配额（每分钟请求数）；`0` = 不限。finder 取它与设置值的较小者。
    fn quota_per_min(&self) -> u32 {
        6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_remaining_and_expiry() {
        let b = SearchBudget::new(1_000, 6_000, 5);
        assert_eq!(b.deadline_ms, 7_000);
        assert_eq!(b.remaining_ms(1_500), 5_500);
        assert!(!b.expired(6_999));
        assert!(b.expired(7_000));
        assert_eq!(b.remaining_ms(8_000), 0);
    }

    #[test]
    fn budget_clamps_total_and_results() {
        let b = SearchBudget::new(0, -5, 0);
        assert_eq!(b.deadline_ms, 0);
        assert_eq!(b.max_results, 1);
    }

    #[test]
    fn network_errors_are_redacted() {
        let e = AdapterError::network("connect: https://h/a?token=SECRET&x=1");
        match e {
            AdapterError::Network(msg) => {
                assert!(!msg.contains("SECRET"), "查询串必须脱敏: {msg}");
                assert!(msg.contains("https://h/a"), "保留可定位的 host/path: {msg}");
            }
            other => panic!("应为 Network，实际 {other:?}"),
        }
    }

    #[test]
    fn retryable_classification() {
        assert!(AdapterError::Timeout.is_retryable());
        assert!(AdapterError::Quota { retry_after_ms: 10 }.is_retryable());
        assert!(AdapterError::Http { status: 503 }.is_retryable());
        assert!(!AdapterError::Http { status: 404 }.is_retryable());
        assert!(!AdapterError::Auth { status: 401 }.is_retryable());
        assert_eq!(AdapterError::Auth { status: 401 }.code(), "auth");
        assert!(!AdapterError::Unsupported.is_retryable());
        assert!(!AdapterError::Malformed("x".into()).is_retryable());
        assert!(!AdapterError::NotFound.is_retryable());
        assert!(!AdapterError::Config("x".into()).is_retryable());
        assert_eq!(AdapterError::Unsupported.code(), "unsupported");
        assert_eq!(AdapterError::Http { status: 500 }.code(), "http");
    }
}
