//! 进程内的**来源记分板**：把真实传输尝试喂进 [`aidm_core::source_score`] 的打分内核，
//! 并按总分给出取源顺序。
//!
//! # 为什么是进程级全局
//!
//! "这个镜像最近 24 小时在我这条线路上靠不靠得住"**本来就是进程级事实**，不属于某个任务：
//! 同一台镜像在任务 A 上慢，任务 B 就不该再优先用它。做成全局还有两个工程上的好处：
//!
//! 1. 不必往 `worker::Args` 里再加一个字段 —— 那个结构的构造点包括独立基准程序
//!    （`fastdl::fetch_standalone`），每加一个字段都要同步所有构造点。
//! 2. 与"内存中滚动窗口"的定位一致：进程重启后从零累积，不需要落库、迁移与清理。
//!
//! 锁只在读写统计时持有，且临界区里只有纯计算与 `HashMap` 操作 —— 不碰网络、不碰磁盘，
//! 不会把下载线程卡在锁上。
//!
//! # 键怎么取（**刻意保守**）
//!
//! 键 = **URL 的 scheme+host+port**（`https://mirror.example:8443/path` → `https://mirror.example:8443`）。
//! 同一台主机上的不同路径算同一个源：路径不同但主机相同，网络路径是同一段。
//!
//! 用户要求的"**按地区、运营商分别排名**"**没有实现**：那需要 ASN / 地理位置数据，
//! 属于采集侧的前置决定，不是打分公式的一部分。当前把所有来源放在同一个桶里，
//! 这个选择是**保守**的（宁可少一点区分度，也不要把两个不同网络的源串成一个键）。

use std::sync::{Mutex, OnceLock};

use aidm_core::source_score::{Attempt, Score, ScoreParams, SourceScores};

/// 全局记分板。首次使用时按缺省参数建立。
fn board() -> &'static Mutex<SourceScores> {
    static BOARD: OnceLock<Mutex<SourceScores>> = OnceLock::new();
    BOARD.get_or_init(|| Mutex::new(SourceScores::new(ScoreParams::default())))
}

/// 取来源键：`scheme://host[:port]`。解析不出来时退回整串（宁可粗，不要丢记录）。
pub fn source_key(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => match u.host_str() {
            Some(h) => match u.port() {
                Some(p) => format!("{}://{}:{}", u.scheme(), h, p),
                None => format!("{}://{}", u.scheme(), h),
            },
            None => url.to_string(),
        },
        Err(_) => url.to_string(),
    }
}

/// 记录一次**真实的**传输尝试。
///
/// `ttfb_ms` 用 **0 表示"没测到"**（打分内核会把它排除在响应速度样本之外，
/// 而不是当成 0 毫秒满分）。`at_ms` 用 `now_ms`。
pub fn record(url: &str, bytes: u64, elapsed_ms: u64, ttfb_ms: u64, ok: bool, now_ms: i64) {
    let key = source_key(url);
    let a = Attempt {
        bytes,
        elapsed_ms,
        ttfb_ms,
        ok,
        at_ms: now_ms,
    };
    if let Ok(mut b) = board().lock() {
        b.record(&key, a);
    }
}

/// 当前时间（毫秒时间戳）。抽出来是为了让调用方与测试用同一个时钟口径。
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 按总分给出**取源顺序**：有评分且分高的在前；没有评分的（新源、记录不足 20 条、
/// 处于暂停期）**保持原有相对顺序**排在后面。
///
/// "排后面"而不是"剔除"：没有数据不等于不可用，探测阶段仍然要能试到它们；
/// 而"保持原有相对顺序"是为了不把上游已经算好的镜像派生优先级打乱。
///
/// # 排序口径
///
/// **有评分的源一律排在没评分的源之前 —— 即使它的分很差。** 用户明确选择
/// "很差但已入榜的源" 优先于 "没数据的源"：不拿用户的带宽去赌未知源。
/// 因此本函数**不做**"低于某分数就退到未知源之后"的处理。
///
/// "排后面"而不是"剔除"：没有数据不等于不可用，探测阶段仍然要能试到它们；
/// 而"保持原有相对顺序"是为了不把上游已经算好的镜像派生优先级打乱。
pub fn order_by_score(sources: &[String], size_bytes: u64) -> Vec<String> {
    if sources.len() < 2 {
        return sources.to_vec();
    }
    let ranked = {
        let b = match board().lock() {
            Ok(b) => b,
            // 锁中毒（别处 panic）时**不做任何重排**：宁可退回原顺序，也不要半套排序。
            Err(_) => return sources.to_vec(),
        };
        b.ranked(size_bytes, now_ms())
    };
    let score_of = |s: &String| -> Option<f64> {
        let key = source_key(s);
        ranked
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, sc)| sc.total)
    };
    let mut scored: Vec<(usize, String, f64)> = Vec::new();
    let mut unscored: Vec<(usize, String)> = Vec::new();
    for (i, s) in sources.iter().enumerate() {
        match score_of(s) {
            Some(v) => scored.push((i, s.clone(), v)),
            None => unscored.push((i, s.clone())),
        }
    }
    // 有分的按分数降序；并列时按**原始下标**升序（确定性，且尊重上游顺序）。
    scored.sort_by(|a, b| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut out: Vec<String> = scored.into_iter().map(|(_, s, _)| s).collect();
    out.extend(unscored.into_iter().map(|(_, s)| s));
    out
}

/// 某个来源当前的评分（诊断/测试用）。
///
/// `None` 表示**还没资格参与排名** —— 记录不足 20 条、处于暂停期，或根本没有记录。
/// 这里必须和 [`order_by_score`] 用同一套门槛：否则诊断会给出一个"排序时根本不会用到"
/// 的分数，看日志的人会以为那个源已经参与比较了。
pub fn score_of(url: &str, size_bytes: u64) -> Option<Score> {
    let key = source_key(url);
    let b = board().lock().ok()?;
    let s = b.stats(&key)?;
    if !s.is_ranked(&b.params) {
        return None;
    }
    s.score(size_bytes, now_ms(), &b.params)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 键只取 scheme+host+port：同一主机的不同路径算同一个源，不同端口算不同源。
    #[test]
    fn source_key_is_host_scoped() {
        assert_eq!(
            source_key("https://mirror.example/a/b.iso"),
            "https://mirror.example"
        );
        assert_eq!(
            source_key("https://mirror.example/other.iso?x=1"),
            "https://mirror.example"
        );
        assert_eq!(
            source_key("http://mirror.example:8080/x"),
            "http://mirror.example:8080"
        );
        // 不同 scheme 是不同键（https 与 http 的网络路径可能完全不同）
        assert_ne!(
            source_key("https://mirror.example/x"),
            source_key("http://mirror.example/x")
        );
        // 默认端口会被 `url` 归一化掉（443/https、80/http），所以显式写与省略写法**是同一个键** ——
        // 这比"当作两个源"正确：它们本来就是同一条网络路径。
        assert_eq!(
            source_key("https://mirror.example:443/x"),
            "https://mirror.example"
        );
        assert_eq!(
            source_key("https://mirror.example:443/x"),
            source_key("https://mirror.example/y")
        );
        // 解析不了就退回整串，不丢记录
        assert_eq!(source_key("not a url"), "not a url");
    }

    /// 排序：有分且分高的在前；没分的保持原有相对顺序排后面。
    #[test]
    fn ordering_puts_scored_sources_first_and_keeps_unknowns_stable() {
        let now = now_ms();
        let fast = "http://ord-fast.test/f.iso";
        let slow = "http://ord-slow.test/s.iso";
        // 各喂 20 条（达到入榜门槛）：fast 4 MiB/s、slow 64 KiB/s
        for _ in 0..20 {
            record(fast, 4 * 1024 * 1024, 1000, 30, true, now);
            record(slow, 64 * 1024, 1000, 400, true, now);
        }
        let list = vec![
            slow.to_string(),
            "http://ord-new.test/n.iso".to_string(),
            fast.to_string(),
        ];
        let out = order_by_score(&list, 100 * 1024 * 1024);
        assert_eq!(
            out,
            vec![
                fast.to_string(),
                slow.to_string(),
                "http://ord-new.test/n.iso".to_string()
            ],
            "快的先、慢的后、没数据的最后且保持原相对顺序"
        );

        // 单元素/空列表原样返回（不做无谓的锁与排序）
        assert_eq!(order_by_score(&[], 100), Vec::<String>::new());
        let one = vec!["http://only.test/a".to_string()];
        assert_eq!(order_by_score(&one, 100), one);
    }

    /// 记录不足 20 条时**不参与排序**，但仍留在列表里（探测阶段还要能试到它）。
    #[test]
    fn a_source_below_the_ranking_threshold_stays_but_is_not_prioritized() {
        let now = now_ms();
        let veteran = "http://thr-vet.test/v.iso";
        let rookie = "http://thr-rook.test/r.iso";
        for _ in 0..20 {
            record(veteran, 1024 * 1024, 1000, 50, true, now);
        }
        // rookie 只有 3 条（哪怕它更快）
        for _ in 0..3 {
            record(rookie, 8 * 1024 * 1024, 1000, 10, true, now);
        }
        assert!(
            score_of(rookie, 100 * 1024 * 1024).is_none(),
            "不足 20 条不该有评分"
        );
        let out = order_by_score(
            &[rookie.to_string(), veteran.to_string()],
            100 * 1024 * 1024,
        );
        assert_eq!(out, vec![veteran.to_string(), rookie.to_string()]);
    }

    /// **排序取向：已知（哪怕很差）优先于未知。**
    ///
    /// 这条把决定钉成回归测试：将来若有人加"低于 X 分就退到未知源之后"，
    /// 或者把"未知"当成中性分混排，这里会先红。
    #[test]
    fn a_poorly_scored_source_still_outranks_an_unscored_one() {
        let now = now_ms();
        let bad = "http://ord-bad.test/b.iso";
        let unknown = "http://ord-unknown.test/u.iso";
        // 20 次尝试里 19 次失败 + 1 次极慢的成功 → 总分极低，但**够 20 条**、入榜。
        // 成功必须**最后**记：否则连续失败 3 次会把它推进暂停期，`score_of` 直接回 None，
        // 测的就不是"很差但有分"而是"被暂停"了。
        for i in 0..19 {
            record(bad, 0, 5000, 0, false, now - i);
        }
        record(bad, 8 * 1024, 60_000, 0, true, now);

        let sc = score_of(bad, 100 * 1024 * 1024).expect("够 20 条就该入榜");
        assert!(
            sc.total < 20.0,
            "构造出来的这个源应当确实很差（否则测不出优先级语义）：{sc:?}"
        );

        // 未来源在前、差源在后 → 必须被重排成"差源在前"
        let out = order_by_score(&[unknown.to_string(), bad.to_string()], 100 * 1024 * 1024);
        assert_eq!(
            out,
            vec![bad.to_string(), unknown.to_string()],
            "按用户决定：已知（哪怕很差）优先于未知"
        );
    }
}
