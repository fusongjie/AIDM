//! 找源器（`docs/source-discovery.md` §4.3）：组织查询、控制并发/预算、汇总适配器结果。
//!
//! 它**不做**去重、分组、验证、评分：那些在 `group` / `verify` / 结果处理器里。
//! 这里只保证三件事：
//!
//! 1. **同一查询不重复打平台**：正/负缓存 + 每平台分钟配额；
//! 2. **并发有上界**：每批最多 [`MAX_ADAPTERS_IN_FLIGHT`] 个适配器同时跑；
//! 3. **失败可归因**：每个平台的错误单独记录，一个平台挂掉不影响其它平台。
//!
//! # 预算口径
//!
//! `total_ms` 是**整轮找源**的截止时间，不是单适配器超时；适配器内部的 HTTP 超时
//! 必须自己夹到 `SearchBudget::remaining_ms()` 以内。线程无法被安全强杀，所以
//! 截止时间只用于"不再启动新适配器"，已启动的线程会在自己的 HTTP 超时后结束。

use std::collections::HashMap;
use std::sync::Mutex;

use aidm_core::source::{CandidateSource, Platform, SourceQuery};

use super::adapter::{AdapterError, PlatformAdapter, SearchBudget};
use super::cache::{cache_key, NegativeCache, Quota, TtlCache};

/// 同时跑几个适配器。规格 §4.3 给的是 3；再多只会放大平台限流。
pub const MAX_ADAPTERS_IN_FLIGHT: usize = 3;

/// 找源器配置。P1 先由调用方传常量；接设置时再从 `setting_spec` 读。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinderConfig {
    /// 正结果缓存 TTL（默认 24 h）。
    pub positive_ttl_ms: i64,
    /// 负结果缓存 TTL（默认 10 分钟）。
    pub negative_ttl_ms: i64,
    /// 每平台每分钟请求上限；`0` = 不限（适配器自己的 `quota_per_min` 仍生效）。
    pub quota_per_min: u32,
    /// 每批同时跑的适配器数（1..=[`MAX_ADAPTERS_IN_FLIGHT`]）。
    pub max_adapters_in_flight: usize,
}

impl Default for FinderConfig {
    fn default() -> Self {
        FinderConfig {
            positive_ttl_ms: 24 * 60 * 60 * 1000,
            negative_ttl_ms: 10 * 60 * 1000,
            quota_per_min: 6,
            max_adapters_in_flight: MAX_ADAPTERS_IN_FLIGHT,
        }
    }
}

/// 一轮找源的结果。候选**未去重、未分组、未验证**，由结果处理器继续。
#[derive(Debug, Default, Clone)]
pub struct FindOutcome {
    pub candidates: Vec<CandidateSource>,
    /// 每个失败平台一条；同一平台多轮失败会重复出现。
    pub errors: Vec<(Platform, AdapterError)>,
    /// 命中正缓存、直接复用的次数。
    pub cache_hits: usize,
    /// 命中负缓存、跳过平台的次数。
    pub negative_skips: usize,
    /// 适配器明确说"这个查询不适用于我"的次数。
    pub unsupported: usize,
    /// 候选数超过本轮上限、被截断。
    pub truncated: bool,
}

impl FindOutcome {
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    pub fn found_count(&self) -> usize {
        self.candidates.len()
    }
}

/// 进程内找源器。适配器列表在构造时固定，运行期只读。
pub struct Finder {
    adapters: Vec<Box<dyn PlatformAdapter>>,
    config: FinderConfig,
    positive: TtlCache<Vec<CandidateSource>>,
    negative: NegativeCache,
    /// 每个平台一个分钟配额桶。`Platform::as_str()` 是 `'static`，可以直接做键。
    quotas: Mutex<HashMap<&'static str, Quota>>,
}

impl Finder {
    pub fn new(adapters: Vec<Box<dyn PlatformAdapter>>, config: FinderConfig) -> Self {
        Finder {
            adapters,
            config,
            positive: TtlCache::new(config.positive_ttl_ms),
            negative: NegativeCache::new(config.negative_ttl_ms),
            quotas: Mutex::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> FinderConfig {
        self.config
    }

    pub fn adapter_count(&self) -> usize {
        self.adapters.len()
    }

    /// 跑一轮。`max_candidates` 是本轮采纳上限；返回的候选顺序 = 适配器声明顺序。
    pub fn find(
        &self,
        query: &SourceQuery,
        now_ms: i64,
        total_ms: i64,
        max_candidates: usize,
    ) -> FindOutcome {
        self.find_cancellable(query, now_ms, total_ms, max_candidates, &|| false)
    }

    /// 带取消的版本：任务暂停/完成/删除时由调用方置位，finder 在适配器批次之间退出。
    /// 单个适配器内部的 HTTP 请求仍由它自己的超时兜底（6 s）。
    pub fn find_cancellable(
        &self,
        query: &SourceQuery,
        now_ms: i64,
        total_ms: i64,
        max_candidates: usize,
        stop: &(dyn Fn() -> bool + Sync),
    ) -> FindOutcome {
        let mut outcome = FindOutcome::default();
        if self.adapters.is_empty() {
            return outcome;
        }
        // 找源硬顶 60 s（设置已限制，这里再兜一层，防止其它调用方传大值）。
        let total_ms = total_ms.clamp(0, 60_000);
        let budget = SearchBudget::new(now_ms, total_ms, max_candidates.max(1));
        let mut collected: Vec<CandidateSource> = Vec::new();
        let chunk = self
            .config
            .max_adapters_in_flight
            .clamp(1, MAX_ADAPTERS_IN_FLIGHT);
        let mut started = now_ms;

        for adapters in self.adapters.chunks(chunk) {
            if budget.expired(started) || stop() {
                break;
            }
            let mut runnable: Vec<(Platform, String, &dyn PlatformAdapter)> = Vec::new();
            for adapter in adapters {
                if stop() {
                    break;
                }
                let platform = adapter.platform();
                let key = cache_key(
                    platform.as_str(),
                    &query.file_name,
                    query.size,
                    query.version.as_deref(),
                );
                if self.negative.is_hit(&key, now_ms) {
                    outcome.negative_skips += 1;
                    continue;
                }
                if let Some(hit) = self.positive.get(&key, now_ms) {
                    outcome.cache_hits += 1;
                    collected.extend(hit);
                    continue;
                }
                if !self.take_quota(adapter.as_ref(), now_ms, &mut outcome) {
                    continue;
                }
                runnable.push((platform, key, adapter.as_ref()));
            }
            if runnable.is_empty() {
                continue;
            }
            for (platform, key, result) in run_batch(runnable, query, budget) {
                match result {
                    Ok(mut items) => {
                        if items.len() > max_candidates {
                            outcome.truncated = true;
                        }
                        items.truncate(budget.max_results);
                        if items.is_empty() {
                            // 只缓存"确实没找到"；Unsupported / 错误不写负缓存。
                            self.negative.mark(key, now_ms);
                        } else {
                            self.positive.put(key, items.clone(), now_ms);
                            collected.extend(items);
                        }
                    }
                    Err(AdapterError::Unsupported) => {
                        outcome.unsupported += 1;
                    }
                    Err(err) => outcome.errors.push((platform, err)),
                }
            }
            // 下一批是否还来得及，以真实时钟为准；测试传入的 `now_ms` 只用于缓存 TTL。
            started = crate::source_registry::now_ms().max(started);
            if stop() {
                break;
            }
        }

        if collected.len() > max_candidates {
            collected.truncate(max_candidates);
            outcome.truncated = true;
        }
        outcome.candidates = collected;
        outcome
    }

    /// 每平台配额：取"适配器声明"与"设置上限"的较小者；两者都 0 才不限。
    fn take_quota(
        &self,
        adapter: &dyn PlatformAdapter,
        now_ms: i64,
        outcome: &mut FindOutcome,
    ) -> bool {
        let per_min = effective_quota(adapter.quota_per_min(), self.config.quota_per_min);
        if per_min == 0 {
            return true;
        }
        let platform = adapter.platform();
        let mut map = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        let quota = map
            .entry(platform.as_str())
            .or_insert_with(|| Quota::new(per_min));
        if quota.try_acquire(now_ms) {
            true
        } else {
            outcome.errors.push((
                platform,
                AdapterError::Quota {
                    retry_after_ms: quota.retry_after_ms(now_ms),
                },
            ));
            false
        }
    }
}

type AdapterRun = (Platform, String, Result<Vec<CandidateSource>, AdapterError>);

/// 并发跑一小批。线程 panic 不会拖垮整轮：转成 `Config` 错误继续汇总。
fn run_batch(
    runnable: Vec<(Platform, String, &dyn PlatformAdapter)>,
    query: &SourceQuery,
    budget: SearchBudget,
) -> Vec<AdapterRun> {
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(runnable.len());
        let mut fallbacks = Vec::with_capacity(runnable.len());
        for (platform, key, adapter) in runnable {
            fallbacks.push((platform, key.clone()));
            handles.push(scope.spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    adapter.search(query, budget)
                }))
                .unwrap_or_else(|_| Err(AdapterError::Config("adapter panicked".into())));
                (platform, key, result)
            }));
        }
        handles
            .into_iter()
            .zip(fallbacks)
            .map(|(handle, (platform, key))| {
                handle.join().unwrap_or((
                    platform,
                    key,
                    Err(AdapterError::Config("adapter thread aborted".into())),
                ))
            })
            .collect()
    })
}

fn effective_quota(adapter: u32, configured: u32) -> u32 {
    match (adapter, configured) {
        (0, 0) => 0,
        (0, b) => b,
        (a, 0) => a,
        (a, b) => a.min(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aidm_core::source::{IdentityEvidence, SourceKind};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn cand(url: &str) -> CandidateSource {
        CandidateSource {
            url: url.into(),
            platform: Platform::WebSearch,
            kind: SourceKind::File,
            size: Some(10),
            version: None,
            container: None,
            evidence: IdentityEvidence::Unverified,
            auth_ref: None,
            origin: None,
            expires_at: None,
        }
    }

    fn query(name: &str) -> SourceQuery {
        SourceQuery {
            file_name: name.into(),
            size: Some(10),
            hashes: Vec::new(),
            version: None,
            orig_url: None,
            source_hint: None,
        }
    }

    struct Fake {
        platform: Platform,
        result: Result<Vec<CandidateSource>, AdapterError>,
        calls: std::sync::Arc<AtomicUsize>,
        quota: u32,
    }

    impl Fake {
        fn new(platform: Platform, result: Result<Vec<CandidateSource>, AdapterError>) -> Self {
            Fake {
                platform,
                result,
                calls: std::sync::Arc::new(AtomicUsize::new(0)),
                quota: 0,
            }
        }

        fn with_quota(mut self, quota: u32) -> Self {
            self.quota = quota;
            self
        }
    }

    impl PlatformAdapter for Fake {
        fn platform(&self) -> Platform {
            self.platform
        }

        fn search(
            &self,
            _query: &SourceQuery,
            _budget: SearchBudget,
        ) -> Result<Vec<CandidateSource>, AdapterError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }

        fn quota_per_min(&self) -> u32 {
            self.quota
        }
    }

    fn finder(adapters: Vec<Box<dyn PlatformAdapter>>, quota: u32) -> Finder {
        Finder::new(
            adapters,
            FinderConfig {
                quota_per_min: quota,
                ..FinderConfig::default()
            },
        )
    }

    #[test]
    fn merges_adapters_and_caches_positive_hits() {
        let a = Fake::new(Platform::ArchiveOrg, Ok(vec![cand("https://a/1")]));
        let a_calls = a.calls.clone();
        let b = Fake::new(Platform::Zenodo, Ok(vec![cand("https://b/1")]));
        let b_calls = b.calls.clone();
        let f = finder(vec![Box::new(a), Box::new(b)], 0);

        let first = f.find(&query("f.iso"), 1_000, 60_000, 10);
        assert_eq!(first.candidates.len(), 2);
        assert!(first.errors.is_empty());
        assert_eq!(first.cache_hits, 0);
        assert_eq!(a_calls.load(Ordering::SeqCst), 1);
        assert_eq!(b_calls.load(Ordering::SeqCst), 1);

        // 第二轮同一查询：两个平台都应命中正缓存，不再调用适配器。
        let second = f.find(&query("f.iso"), 2_000, 60_000, 10);
        assert_eq!(second.candidates.len(), 2);
        assert_eq!(second.cache_hits, 2);
        assert_eq!(a_calls.load(Ordering::SeqCst), 1);
        assert_eq!(b_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn caches_empty_results_negatively() {
        let fake = Fake::new(Platform::ArchiveOrg, Ok(vec![]));
        let calls = fake.calls.clone();
        let f = finder(vec![Box::new(fake)], 0);
        let first = f.find(&query("f.iso"), 1_000, 60_000, 10);
        assert!(first.candidates.is_empty());
        let second = f.find(&query("f.iso"), 2_000, 60_000, 10);
        assert!(second.candidates.is_empty());
        assert_eq!(second.negative_skips, 1);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "负缓存命中后不应再调用适配器"
        );
    }

    #[test]
    fn errors_are_reported_per_platform() {
        let f = finder(
            vec![Box::new(Fake::new(
                Platform::GitHub,
                Err(AdapterError::Http { status: 500 }),
            ))],
            0,
        );
        let out = f.find(&query("f.iso"), 1_000, 60_000, 10);
        assert!(out.candidates.is_empty());
        assert_eq!(out.errors.len(), 1);
        assert_eq!(out.errors[0].0, Platform::GitHub);
    }

    #[test]
    fn unsupported_is_not_cached_negatively() {
        let fake = Fake::new(Platform::GitHub, Err(AdapterError::Unsupported));
        let f = finder(vec![Box::new(fake)], 0);
        let first = f.find(&query("f.iso"), 1_000, 60_000, 10);
        assert_eq!(first.unsupported, 1);
        let second = f.find(&query("f.iso"), 2_000, 60_000, 10);
        assert_eq!(second.unsupported, 1, "Unsupported 不应写负缓存");
        assert_eq!(second.negative_skips, 0);
    }

    #[test]
    fn quota_blocks_the_second_distinct_query() {
        let fake = Fake::new(Platform::ArchiveOrg, Ok(vec![cand("https://a/1")])).with_quota(1);
        let f = finder(vec![Box::new(fake)], 0);
        let first = f.find(&query("a.iso"), 1_000, 60_000, 10);
        assert_eq!(first.candidates.len(), 1);
        // 不同文件名 => 不同缓存键 => 要真的消耗第二次配额。
        let second = f.find(&query("b.iso"), 2_000, 60_000, 10);
        assert!(second.candidates.is_empty());
        assert!(matches!(
            second.errors.first(),
            Some((_, AdapterError::Quota { .. }))
        ));
    }

    #[test]
    fn truncates_to_round_limit() {
        let items = vec![
            cand("https://a/1"),
            cand("https://a/2"),
            cand("https://a/3"),
        ];
        let f = finder(
            vec![Box::new(Fake::new(Platform::ArchiveOrg, Ok(items)))],
            0,
        );
        let out = f.find(&query("f.iso"), 1_000, 60_000, 2);
        assert_eq!(out.candidates.len(), 2);
        assert!(out.truncated);
    }

    #[test]
    fn cancellable_finder_stops_before_any_adapter() {
        let a = Fake::new(Platform::ArchiveOrg, Ok(vec![cand("https://a/1")]));
        let calls = a.calls.clone();
        let f = finder(vec![Box::new(a)], 0);
        let out = f.find_cancellable(&query("f.iso"), 1_000, 60_000, 10, &|| true);
        assert!(out.candidates.is_empty());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "停止标志应在调用适配器前生效"
        );
    }

    #[test]
    fn empty_adapter_list_is_a_noop() {
        let f = finder(Vec::new(), 0);
        let out = f.find(&query("f.iso"), 1_000, 60_000, 10);
        assert!(out.is_empty());
        assert_eq!(out.found_count(), 0);
        assert_eq!(f.adapter_count(), 0);
    }

    #[test]
    fn effective_quota_rules() {
        assert_eq!(effective_quota(0, 0), 0);
        assert_eq!(effective_quota(0, 6), 6);
        assert_eq!(effective_quota(4, 0), 4);
        assert_eq!(effective_quota(4, 6), 4);
        assert_eq!(effective_quota(6, 4), 4);
    }
}
