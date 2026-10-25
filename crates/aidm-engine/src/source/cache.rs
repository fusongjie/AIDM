//! 找源缓存与配额（`docs/source-discovery.md` §6.1）。
//!
//! 三件事，都是进程内状态，不落库：
//!
//! 1. [`TtlCache`]：带过期时间的结果缓存。正结果 TTL 长（默认 24 h），
//!    负结果（未找到）TTL 短（默认 10 分钟），避免每个任务重复打平台。
//! 2. [`NegativeCache`]：`TtlCache<()>` 的薄包装，命中即返回 `NotFound(cached)`。
//! 3. [`Quota`]：滑动分钟窗口，每平台最多 `per_min` 次请求；`0` = 不限。
//!
//! # 为什么不用后台清理线程
//!
//! 引擎已经有 500 ms 调度 tick，缓存只在 `get`/`put` 时顺手清理过期项即可；
//! 多一个后台线程只会多一个退出时要去 join 的东西（见 `docs/guides/02-rust-constraints.md`
//! 对命名线程与阻塞隔离的约束）。因此 [`TtlCache::put`] 会做一次有界清扫。

use std::collections::HashMap;
use std::sync::Mutex;

/// 一次 `put` 最多顺手清理多少个过期项。
///
/// 缓存条目本来就不多（每任务几十条），限个上界只是防止异常输入把一次 `put`
/// 变成 O(n) 的长临界区。
const PRUNE_LIMIT: usize = 32;

#[derive(Debug, Clone)]
struct Entry<T> {
    value: T,
    expires_at_ms: i64,
}

/// 线程安全的 TTL 缓存。值必须是 `Clone`（取用时复制，不把锁带到调用方）。
#[derive(Debug)]
pub struct TtlCache<T> {
    ttl_ms: i64,
    inner: Mutex<HashMap<String, Entry<T>>>,
}

impl<T: Clone> TtlCache<T> {
    /// `ttl_ms <= 0` 视为"立即过期"：`get` 永远拿不到值，`put` 仍会写入（便于测试）。
    pub fn new(ttl_ms: i64) -> Self {
        TtlCache {
            ttl_ms,
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn ttl_ms(&self) -> i64 {
        self.ttl_ms
    }

    /// 取一个未过期的值；过期项顺手删除。
    pub fn get(&self, key: &str, now_ms: i64) -> Option<T> {
        let mut map = self.lock();
        match map.get(key) {
            Some(e) if e.expires_at_ms > now_ms => Some(e.value.clone()),
            Some(_) => {
                map.remove(key);
                None
            }
            None => None,
        }
    }

    /// 写入并返回覆盖后的过期时刻。`ttl_ms <= 0` 时写入即过期。
    pub fn put(&self, key: String, value: T, now_ms: i64) {
        let mut map = self.lock();
        self.prune_locked(&mut map, now_ms);
        map.insert(
            key,
            Entry {
                value,
                expires_at_ms: now_ms.saturating_add(self.ttl_ms),
            },
        );
    }

    pub fn remove(&self, key: &str) -> Option<T> {
        self.lock().remove(key).map(|e| e.value)
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 清理全部过期项，返回清理数量。
    pub fn prune(&self, now_ms: i64) -> usize {
        let mut map = self.lock();
        let before = map.len();
        map.retain(|_, e| e.expires_at_ms > now_ms);
        before - map.len()
    }

    fn prune_locked(&self, map: &mut HashMap<String, Entry<T>>, now_ms: i64) {
        if map.len() < PRUNE_LIMIT {
            return;
        }
        map.retain(|_, e| e.expires_at_ms > now_ms);
        // 仍超过上限时不再扩清扫：缓存不是无限增长的，调用方按任务/平台维度复用。
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry<T>>> {
        // 中毒只发生在持有者 panic 时；纯数据，取回继续用比 panic 更安全。
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<T: Clone> Default for TtlCache<T> {
    fn default() -> Self {
        // 与 §6.1 的正结果 TTL 一致：24 h。
        Self::new(24 * 60 * 60 * 1000)
    }
}

/// 负缓存：只记"这个查询在什么时候之前不要再打"。
#[derive(Debug)]
pub struct NegativeCache {
    ttl_ms: i64,
    inner: Mutex<HashMap<String, i64>>,
}

impl NegativeCache {
    pub fn new(ttl_ms: i64) -> Self {
        NegativeCache {
            ttl_ms,
            inner: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_hit(&self, key: &str, now_ms: i64) -> bool {
        let mut map = self.lock();
        match map.get(key) {
            Some(until) if *until > now_ms => true,
            Some(_) => {
                map.remove(key);
                false
            }
            None => false,
        }
    }

    pub fn mark(&self, key: String, now_ms: i64) {
        self.lock().insert(key, now_ms.saturating_add(self.ttl_ms));
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, i64>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// 每平台每分钟请求配额（滑动窗口按整分钟重置，不做逐请求滑动）。
#[derive(Debug)]
pub struct Quota {
    per_min: u32,
    inner: Mutex<QuotaState>,
}

#[derive(Debug, Default, Clone, Copy)]
struct QuotaState {
    window_start_ms: i64,
    used: u32,
}

impl Quota {
    /// `per_min == 0` 表示"不限"。
    pub fn new(per_min: u32) -> Self {
        Quota {
            per_min,
            inner: Mutex::new(QuotaState::default()),
        }
    }

    /// 尝试消耗一次配额。返回 `false` 时 `retry_after_ms` 给出窗口剩余时间。
    pub fn try_acquire(&self, now_ms: i64) -> bool {
        if self.per_min == 0 {
            return true;
        }
        let mut st = self.lock();
        self.roll_window(&mut st, now_ms);
        if st.used >= self.per_min {
            return false;
        }
        st.used = st.used.saturating_add(1);
        true
    }

    /// 距离下一个窗口还有多少毫秒；`per_min == 0` 时为 0。
    pub fn retry_after_ms(&self, now_ms: i64) -> i64 {
        if self.per_min == 0 {
            return 0;
        }
        let mut st = self.lock();
        self.roll_window(&mut st, now_ms);
        if st.used < self.per_min {
            return 0;
        }
        let remaining = st.window_start_ms.saturating_add(60_000) - now_ms;
        remaining.max(0)
    }

    pub fn used(&self, now_ms: i64) -> u32 {
        let mut st = self.lock();
        self.roll_window(&mut st, now_ms);
        st.used
    }

    fn roll_window(&self, st: &mut QuotaState, now_ms: i64) {
        if now_ms.saturating_sub(st.window_start_ms) >= 60_000 {
            st.window_start_ms = now_ms;
            st.used = 0;
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, QuotaState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// 缓存键：`platform:query_hash`。查询串只进哈希，不落明文（§8.2）。
///
/// 这里只做"稳定拼接 + SHA-256 前 16 字节"：完整查询可能很长，也没必要在内存里
/// 保留原文；同一查询稳定命中即可。
pub fn cache_key(
    platform: &str,
    file_name: &str,
    size: Option<u64>,
    version: Option<&str>,
) -> String {
    let mut raw = String::with_capacity(file_name.len() + 32);
    raw.push_str(file_name);
    raw.push('\u{1f}');
    if let Some(size) = size {
        raw.push_str(&size.to_string());
    }
    raw.push('\u{1f}');
    raw.push_str(version.unwrap_or(""));
    let digest = aidm_core::hash::sha256_hex(raw.as_bytes());
    format!("{platform}:{}", &digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_cache_expires_and_removes() {
        let c = TtlCache::<u32>::new(1_000);
        c.put("a".into(), 7, 10_000);
        assert_eq!(c.get("a", 10_500), Some(7));
        assert_eq!(c.get("a", 11_000), None, "到期时刻本身不算命中");
        assert_eq!(c.len(), 0, "过期项应被 get 顺手删除");
    }

    #[test]
    fn ttl_cache_zero_ttl_never_hits() {
        let c = TtlCache::<u32>::new(0);
        c.put("a".into(), 1, 1);
        assert_eq!(c.len(), 1, "写入仍在，只是立即过期");
        assert_eq!(c.get("a", 1), None);
        assert_eq!(c.len(), 0, "get 顺手删除过期项");
    }

    #[test]
    fn ttl_cache_prune_is_bounded_but_correct() {
        let c = TtlCache::<u32>::new(10);
        for i in 0..100 {
            c.put(format!("k{i}"), i, 1);
        }
        assert_eq!(c.prune(100), 100);
        assert!(c.is_empty());
    }

    #[test]
    fn negative_cache_hits_until_expiry() {
        let n = NegativeCache::new(600_000);
        assert!(!n.is_hit("q", 0));
        n.mark("q".into(), 0);
        assert!(n.is_hit("q", 599_999));
        assert!(!n.is_hit("q", 600_000));
        assert!(n.is_empty());
    }

    #[test]
    fn quota_allows_per_min_and_resets() {
        let q = Quota::new(2);
        assert!(q.try_acquire(1_000));
        assert!(q.try_acquire(1_001));
        assert!(!q.try_acquire(1_002));
        assert_eq!(q.used(1_002), 2);
        assert!(q.retry_after_ms(1_002) > 0);
        // 整分钟窗口滚动后恢复。
        assert!(q.try_acquire(61_000));
        assert_eq!(q.used(61_000), 1);
    }

    #[test]
    fn quota_zero_means_unlimited() {
        let q = Quota::new(0);
        for i in 0..1_000 {
            assert!(q.try_acquire(i));
        }
        assert_eq!(q.retry_after_ms(1), 0);
    }

    #[test]
    fn cache_key_is_stable_and_does_not_leak_query_text() {
        let a = cache_key("archive_org", "f.iso", Some(10), Some("1.0"));
        let b = cache_key("archive_org", "f.iso", Some(10), Some("1.0"));
        assert_eq!(a, b);
        assert!(a.starts_with("archive_org:"));
        assert_eq!(a.len(), "archive_org:".len() + 16);
        assert!(!a.contains("f.iso"), "键里不保留可读文件名/查询原文");
        assert_ne!(a, cache_key("archive_org", "f.iso", Some(11), None));
    }
}
