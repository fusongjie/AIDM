//! 来源（镜像/多源）打分与排名：把"哪个源值得用"变成可计算的数。
//!
//! # 规格来源
//!
//! 口径，逐条落实：
//!
//! - 总分 `= 100 × R² × (w_v·V + w_s·S + w_l·L)`，三项分值与 R 都限制在 0..=1。
//! - `R`：**保守成功率** —— 计入失败与超时后的 **Wilson 95% 置信下界**。
//! - `V`：持续速度分 —— **中位吞吐量**按基准带宽归一化，**对数压缩**。
//! - `S`：稳定性分 —— **速度 P10 ÷ 中位速度**。
//! - `L`：响应速度分 —— `500 / (500 + 首字节耗时 P90 毫秒)`。
//! - 大文件权重 `(V,S,L) = (0.80, 0.15, 0.05)`；小文件 `(0.35, 0.15, 0.50)`；
//!   中间**平滑调整**（本模块按文件大小在两端点之间线性插值）。
//! - 采集口径：最近 **24 小时**；失败与超时**计入总尝试**；分位数**只统计成功传输**；
//!   新源 **≥20 条**记录才进入正式排名；**连续失败 3 次暂停选择 5 分钟**
//!   （暂停期满后仍需先探测才能恢复参与）。
//!
//! # 为什么这些参数是"可注入"的
//!
//! 规格里有几处只能由实测标定、不能拍脑袋定死：**基准带宽**（归一化的分母）、
//! **小文件阈值**（原文写作"小于 0MB"，显然笔误）、对数压缩的**曲率**、以及
//! 地区/运营商的分桶方式。它们全部做成 [`ScoreParams`] 的字段并给一个**明确标注为
//! 待标定**的缺省值，而不是散落在公式里的魔法数 —— 这样调参不用改公式，
//! 也让"哪些数是猜的"一眼可见。

use std::collections::HashMap;

/// 一次传输尝试的记录（成功或失败都算一次尝试）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attempt {
    /// 本次实际传输的字节数（失败时是已传部分）。
    pub bytes: u64,
    /// 本次传输耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 首字节耗时（毫秒）——包含连接建立过程。
    pub ttfb_ms: u64,
    /// 是否成功完成（失败与超时都算 `false`）。
    pub ok: bool,
    /// 记录时刻（毫秒时间戳，用于 24 小时窗口）。
    pub at_ms: i64,
}

impl Attempt {
    /// 本次尝试的吞吐量（B/s）。耗时按 **0 毫秒**出现时回 0，避免除零造出无穷大。
    pub fn bps(&self) -> f64 {
        if self.elapsed_ms == 0 || !self.ok {
            return 0.0;
        }
        self.bytes as f64 * 1000.0 / self.elapsed_ms as f64
    }
}

/// 打分参数（可注入；带"待标定"标注的缺省值见各字段注释）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoreParams {
    /// 基准带宽（B/s）：持续速度分归一化的分母。**待标定**。
    ///
    /// 缺省 12.5 MiB/s ≈ 100 Mbps —— 取"百兆宽带"这个常见档位当锚点，
    /// 只为让分值落在可比较的量级上，不代表任何实测结论。
    pub reference_bps: f64,
    /// 小文件阈值（字节）。小于它按小文件权重，`large_at` 及以上按大文件权重，
    /// 之间线性插值。
    ///
    /// 口径：**小于 5 MB 为小文件**。
    /// 单位按 1024 进制取 MiB。
    pub small_at: u64,
    /// 大文件阈值（字节）：最终定为 **500 MB**（
    /// 已按最新决定改为 500 MB）。单位按 1024 进制取 MiB。
    pub large_at: u64,
    /// 对数压缩曲率：`V = ln(1 + k·x) / ln(1 + k)` 里的 `k`。**待标定**。
    ///
    /// `k` 越大，低带宽段的区分度越高（小水管之间分得开），高带宽段越压得平。
    pub log_curve_k: f64,
    /// Wilson 置信水平对应的 z 值：95% 双侧 → 1.96。
    pub wilson_z: f64,
    /// 正式排名的**最少记录数**：规格明确给了 20。
    pub min_attempts_to_rank: usize,
    /// 连续失败多少次后暂停选择：规格明确给了 3。
    pub pause_after_failures: u32,
    /// 暂停时长（毫秒）：规格明确给了 5 分钟。
    pub pause_ms: i64,
    /// 统计窗口（毫秒）：规格明确给了 24 小时。
    pub window_ms: i64,
}

impl Default for ScoreParams {
    fn default() -> Self {
        Self {
            reference_bps: 12.5 * 1024.0 * 1024.0,
            small_at: 5 * 1024 * 1024,
            large_at: 500 * 1024 * 1024,
            log_curve_k: 4.0,
            wilson_z: 1.96,
            min_attempts_to_rank: 20,
            pause_after_failures: 3,
            pause_ms: 5 * 60 * 1000,
            window_ms: 24 * 60 * 60 * 1000,
        }
    }
}

/// 一个来源的**内存**统计（进程内，不落库：这是"最近 24 小时"的滚动窗口，
/// 重启后重新累积即可，落库反而要处理迁移与清理）。
#[derive(Debug, Default, Clone)]
pub struct SourceStats {
    /// 滚动窗口内的尝试记录（升序时间）。
    attempts: Vec<Attempt>,
    /// 连续失败次数（成功即清零）。
    consecutive_failures: u32,
    /// 最近一次失败的时刻（用于暂停判定）。
    last_failure_ms: Option<i64>,
    /// **见过的最大时间戳**（裁剪水位线）。
    ///
    /// 不能用"本次插入记录的时间戳"当水位线：下载是并发的，各连接的完成顺序天然乱序，
    /// 后插入的记录可能**比已存在的更早**，那样就会把刚记进来的较新记录当成"未来"
    /// 丢掉 —— 统计会悄悄少记，`≥20 条才入榜`可能永远达不到。
    watermark_ms: i64,
    /// 已经为**哪一次暂停**做过恢复探测（存的是那次的 `last_failure_ms`）。
    last_probe_ms: Option<i64>,
    /// 最近一次探测的时刻（仅诊断用）。
    last_probe_at_ms: Option<i64>,
}

impl SourceStats {
    /// 记录一次尝试，并顺手丢掉窗口之外的旧记录。
    pub fn record(&mut self, a: Attempt, p: &ScoreParams) {
        if a.ok {
            self.consecutive_failures = 0;
        } else {
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            self.last_failure_ms = Some(a.at_ms);
        }
        self.watermark_ms = self.watermark_ms.max(a.at_ms);
        self.attempts.push(a);
        // 用**水位线**裁剪，而不是本次记录自己的时间戳：乱序插入（并发连接完成顺序不定）
        // 不该误删较新的记录。见 `watermark_ms` 的注释。
        self.prune(self.watermark_ms, p);
    }

    /// 丢掉窗口之外的记录（`now_ms` 之后的一并丢掉：时钟回拨不该让窗口变宽）。
    ///
    /// `now_ms` 应当传**水位线**（见过的最大时间戳），见 `watermark_ms`。
    pub fn prune(&mut self, now_ms: i64, p: &ScoreParams) {
        let floor = now_ms - p.window_ms;
        self.attempts
            .retain(|a| a.at_ms > floor && a.at_ms <= now_ms);
    }

    /// 窗口内的尝试数（**含失败与超时**）。
    pub fn total(&self) -> usize {
        self.attempts.len()
    }

    /// 窗口内的成功数。
    pub fn successes(&self) -> usize {
        self.attempts.iter().filter(|a| a.ok).count()
    }

    /// 是否处于"连续失败 3 次"的暂停期。
    ///
    /// 暂停期满后**不能直接恢复参与排名**，仍要先经有效性探测（由调用方决定），
    /// 本函数只回答"现在是不是还在暂停里"。
    pub fn is_paused(&self, now_ms: i64, p: &ScoreParams) -> bool {
        if self.consecutive_failures < p.pause_after_failures {
            return false;
        }
        match self.last_failure_ms {
            Some(t) => now_ms - t < p.pause_ms,
            None => false,
        }
    }

    /// 记录数是否够进入**正式排名**（新源先走探测，不足 20 条不参与排序）。
    pub fn is_ranked(&self, p: &ScoreParams) -> bool {
        self.total() >= p.min_attempts_to_rank
    }

    /// 暂停期满后**是否该给它一次探测机会**。
    ///
    /// 规格原文：「连续失败 3 次可暂停选择 5 分钟，**之后探测恢复**」。
    /// "暂停"只是"不再参与**排名**"，不是"永远不再用它"：期满后要能拿一次探测把状态
    /// 试探回来，否则一个曾经抖动过的镜像会永久出局。
    ///
    /// 判定三件事同时成立：① 曾经进入过暂停（连续失败达标）；② 暂停期已过；
    /// ③ **自那以后还没有探测过**（`last_probe_ms` 早于暂停起点）—— 否则每次调度
    /// 都会把它当成"该探测"，等于没暂停。
    pub fn is_due_for_probe(&self, now_ms: i64, p: &ScoreParams) -> bool {
        if self.consecutive_failures < p.pause_after_failures {
            return false;
        }
        let Some(failed_at) = self.last_failure_ms else {
            return false;
        };
        if now_ms - failed_at < p.pause_ms {
            return false; // 还在暂停期里
        }
        // 期满后已经探测过一次就不再重复"该探测"；那一次的结果会通过 record() 走进
        // 连续失败计数（成功则清零、失败则重新计时）。
        self.last_probe_ms != Some(failed_at)
    }

    /// 记一次**探测**（不是正常下载尝试）：只标记"已经探过"，不改成功率与分位数。
    ///
    /// 与 [`Self::record`] 分开是刻意的：探测带着"我知道它可能不行"的意图，
    /// 把它混进成功率统计会污染排名（一次探测成功不该让一个烂源看起来变好）。
    pub fn mark_probed(&mut self, at_ms: i64) {
        self.last_probe_ms = self.last_failure_ms;
        self.last_probe_at_ms = Some(at_ms);
    }

    /// 最近一次探测的时刻（诊断用）。
    pub fn last_probe_at_ms(&self) -> Option<i64> {
        self.last_probe_at_ms
    }

    /// 窗口内成功传输的吞吐量样本（B/s），升序。
    fn bps_samples(&self) -> Vec<f64> {
        let mut v: Vec<f64> = self
            .attempts
            .iter()
            .filter(|a| a.ok && a.elapsed_ms > 0)
            .map(|a| a.bps())
            .collect();
        v.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
        v
    }

    /// 窗口内成功传输的首字节耗时样本（毫秒），升序。
    ///
    /// **`ttfb_ms == 0` 视为"没测到"，不计入样本** —— 有些调用路径（例如 worker 的
    /// 分段循环）拿不到首字节时刻。若把"没测到"当成 0 毫秒，`L = 500/(500+0) = 1.0`，
    /// 每个源都会伪装成响应满分，这一项就废了。宁可样本少，也不要有假样本。
    fn ttfb_samples(&self) -> Vec<f64> {
        let mut v: Vec<f64> = self
            .attempts
            .iter()
            .filter(|a| a.ok && a.ttfb_ms > 0)
            .map(|a| a.ttfb_ms as f64)
            .collect();
        v.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
        v
    }

    /// 完整评分。记录不足或处于暂停期时返回 `None` —— **不参与排序**，
    /// 而不是给一个低分（低分会污染"按总分降序"的结果）。
    pub fn score(&self, size_bytes: u64, now_ms: i64, p: &ScoreParams) -> Option<Score> {
        if self.is_paused(now_ms, p) {
            return None;
        }
        let total = self.total();
        if total == 0 {
            return None;
        }
        let successes = self.successes();
        let r = wilson_lower_bound(successes, total, p.wilson_z);

        let bps = self.bps_samples();
        let median = quantile(&bps, 0.5).unwrap_or(0.0);
        let speed = speed_score(median, p.reference_bps, p.log_curve_k);
        let stability = stability_score(quantile(&bps, 0.10).unwrap_or(0.0), median);
        let ttfb_p90 = quantile(&self.ttfb_samples(), 0.90);
        // 没有成功样本时**不给响应分**，而不是当成"0 毫秒"——那会伪装成满分。
        // （此时成功率下界 R 也是 0，总分本来就是 0；这里只是不让单项分说谎。）
        let response = ttfb_p90.map(response_score).unwrap_or(0.0);

        let w = weights_for(size_bytes, ttfb_p90, median, p);
        let total_score =
            100.0 * r * r * (w.speed * speed + w.stability * stability + w.response * response);
        Some(Score {
            total: total_score,
            success_lower_bound: r,
            speed,
            stability,
            response,
            weights: w,
            attempts: total,
        })
    }
}

/// 三档权重（各分项都在 0..=1，三者之和为 1）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Weights {
    pub speed: f64,
    pub stability: f64,
    pub response: f64,
}

/// 一次评分的完整结果（便于测试与诊断逐项对照，而不是只看一个总分）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Score {
    pub total: f64,
    pub success_lower_bound: f64,
    pub speed: f64,
    pub stability: f64,
    pub response: f64,
    pub weights: Weights,
    pub attempts: usize,
}

/// 成功率的 **Wilson 95% 置信下界**（保守成功率）。
///
/// 用下界而不是点估计：3 次里成功 3 次（点估计 1.0）不该压过 200 次里成功 180 次。
pub fn wilson_lower_bound(successes: usize, total: usize, z: f64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let n = total as f64;
    let phat = successes as f64 / n;
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let centre = phat + z2 / (2.0 * n);
    let margin = z * (phat * (1.0 - phat) / n + z2 / (4.0 * n * n)).sqrt();
    ((centre - margin) / denom).clamp(0.0, 1.0)
}

/// 分位数（**线性插值**，与常见数值库一致：`q` 为 0..=1）。
///
/// 空样本回 `None`（不是 0）——"没有数据"与"速度是 0"必须分得开，否则一个新源
/// 会被算成"极慢"，而它其实只是还没跑过。
pub fn quantile(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    if sorted.len() == 1 {
        return Some(sorted[0]);
    }
    let q = q.clamp(0.0, 1.0);
    let pos = q * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        return Some(sorted[lo]);
    }
    let frac = pos - lo as f64;
    Some(sorted[lo] * (1.0 - frac) + sorted[hi] * frac)
}

/// 持续速度分：中位吞吐量按基准带宽归一化后做**对数压缩**，结果落在 0..=1。
pub fn speed_score(median_bps: f64, reference_bps: f64, k: f64) -> f64 {
    if reference_bps <= 0.0 || median_bps <= 0.0 {
        return 0.0;
    }
    let x = median_bps / reference_bps;
    let num = (1.0 + k * x).ln();
    let den = (1.0 + k).ln();
    if den <= 0.0 {
        return 0.0;
    }
    (num / den).clamp(0.0, 1.0)
}

/// 稳定性分：速度 **P10 ÷ 中位速度**，落在 0..=1（中位为 0 时回 0）。
pub fn stability_score(p10_bps: f64, median_bps: f64) -> f64 {
    if median_bps <= 0.0 {
        return 0.0;
    }
    (p10_bps / median_bps).clamp(0.0, 1.0)
}

/// 响应速度分：`500 / (500 + 首字节 P90 毫秒)`，落在 0..1（无样本时给 0）。
pub fn response_score(ttfb_p90_ms: f64) -> f64 {
    if ttfb_p90_ms < 0.0 {
        return 0.0;
    }
    500.0 / (500.0 + ttfb_p90_ms)
}

/// 按文件大小（并在有数据时按实测网络）算三档权重。
///
/// **两步，规格里都写了**：
/// 1. 先按文件大小在「小文件权重」与「大文件权重」之间线性插值
///    （≤ `small_at` 全小文件档；≥ `large_at` 全大文件档）。
/// 2. 再按实测网络校准：用"文件大小 ÷ 中位吞吐量"估算传输时间 `est`，与首字节耗时
///    `ttfb` 比较 —— `est ≤ ttfb` 时偏重**响应速度**，`est > 10×ttfb` 时偏重
///    **持续吞吐量**，中间线性过渡。校准把 `V` 与 `L` 之间的比例拉开/压平，
///    并保持 `S` 的比例不变、三者之和仍为 1。
///
/// 没有任何速度样本（`median_bps <= 0` 或没有 ttfb 样本）时**只做第 1 步** ——
/// 用不存在的实测数据去"校准"等于无中生有。
pub fn weights_for(
    size_bytes: u64,
    ttfb_p90_ms: Option<f64>,
    median_bps: f64,
    p: &ScoreParams,
) -> Weights {
    // 规格给出的两个端点（原文数字）。
    const SMALL: Weights = Weights {
        speed: 0.35,
        stability: 0.15,
        response: 0.50,
    };
    const LARGE: Weights = Weights {
        speed: 0.80,
        stability: 0.15,
        response: 0.05,
    };

    let t = if size_bytes <= p.small_at {
        0.0
    } else if size_bytes >= p.large_at {
        1.0
    } else {
        (size_bytes - p.small_at) as f64 / (p.large_at - p.small_at) as f64
    };
    let mut w = Weights {
        speed: SMALL.speed + (LARGE.speed - SMALL.speed) * t,
        stability: SMALL.stability + (LARGE.stability - SMALL.stability) * t,
        response: SMALL.response + (LARGE.response - SMALL.response) * t,
    };

    if let Some(ttfb) = ttfb_p90_ms {
        if median_bps > 0.0 && ttfb > 0.0 {
            let est_ms = size_bytes as f64 / median_bps * 1000.0;
            // 0 = 偏响应（估算传输时间不长于建连），1 = 偏吞吐（远长于建连）
            let tilt = if est_ms <= ttfb {
                0.0
            } else if est_ms >= 10.0 * ttfb {
                1.0
            } else {
                (est_ms - ttfb) / (9.0 * ttfb)
            };
            // 在 V 与 L 之间重新分配，总量守恒（S 不动）。
            //
            // 两个锚点必须**与文件大小无关**，否则会退化：若拿"当前档位的比例"当锚点，
            // 那么当文件已经落在大文件档（基准权重就是大文件档）时两个锚点重合，
            // tilt 变成空转 —— 实测网络这一层就等于没做。所以用规格给出的**两个端点档**
            // 各自的 V:L 比例当锚点：偏响应时向小文件档的比例靠，偏吞吐时向大文件档靠。
            let vl = w.speed + w.response;
            let share_response_high = SMALL.response / (SMALL.speed + SMALL.response);
            let share_response_low = LARGE.response / (LARGE.speed + LARGE.response);
            let share = share_response_high * (1.0 - tilt) + share_response_low * tilt;
            w.response = vl * share;
            w.speed = vl - w.response;
        }
    }

    // 归一化：浮点插值的舍入不该让三项之和偏离 1（否则总分尺度会漂）。
    let sum = w.speed + w.stability + w.response;
    if sum > 0.0 {
        w.speed /= sum;
        w.stability /= sum;
        w.response /= sum;
    }
    w
}

/// 内存里的来源排行榜。
///
/// 键由调用方给（例如 `"region:cn-telecom|host:mirror.example"`）——本模块**不猜**
/// 怎么划分地区与运营商：那需要 ASN/地理数据，属于采集侧的决定，不是公式的一部分。
#[derive(Debug, Default)]
pub struct SourceScores {
    stats: HashMap<String, SourceStats>,
    pub params: ScoreParams,
}

impl SourceScores {
    pub fn new(params: ScoreParams) -> Self {
        Self {
            stats: HashMap::new(),
            params,
        }
    }

    /// 记录一次尝试（会自动按窗口裁剪）。
    pub fn record(&mut self, key: &str, a: Attempt) {
        let p = self.params;
        self.stats.entry(key.to_string()).or_default().record(a, &p);
    }

    pub fn stats(&self, key: &str) -> Option<&SourceStats> {
        self.stats.get(key)
    }

    /// 按总分**降序**给出可参与排名的来源（记录不足 20 条或被暂停的不入列）。
    ///
    /// 并列时按键名升序 —— 让排序**确定**，否则同一份数据两次调用可能给出不同顺序，
    /// 测试与复现都会变得不可靠。
    pub fn ranked(&self, size_bytes: u64, now_ms: i64) -> Vec<(String, Score)> {
        let p = self.params;
        let mut out: Vec<(String, Score)> = self
            .stats
            .iter()
            .filter(|(_, s)| s.is_ranked(&p))
            .filter_map(|(k, s)| s.score(size_bytes, now_ms, &p).map(|sc| (k.clone(), sc)))
            .collect();
        out.sort_by(|a, b| {
            b.1.total
                .partial_cmp(&a.1.total)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(bytes: u64, ms: u64, ttfb: u64, at: i64) -> Attempt {
        Attempt {
            bytes,
            elapsed_ms: ms,
            ttfb_ms: ttfb,
            ok: true,
            at_ms: at,
        }
    }
    fn bad(at: i64) -> Attempt {
        Attempt {
            bytes: 0,
            elapsed_ms: 5000,
            ttfb_ms: 0,
            ok: false,
            at_ms: at,
        }
    }

    /// Wilson 下界的关键性质（不写死记来的常数，改用可推导的性质）。
    ///
    /// 这条是"保守"二字的守门：**全成功时下界必须明显低于 1**，否则 3/3 的新源会
    /// 压过 200 次里成功 190 次的老源 —— 那正是这个公式要防的事。
    #[test]
    fn wilson_lower_bound_is_conservative_and_monotone() {
        assert_eq!(wilson_lower_bound(0, 0, 1.96), 0.0);
        assert_eq!(wilson_lower_bound(0, 10, 1.96), 0.0, "零成功就是零");

        let all3 = wilson_lower_bound(3, 3, 1.96);
        assert!(all3 > 0.0 && all3 < 0.6, "3/3 的下界应当远低于 1：{all3}");

        let all200 = wilson_lower_bound(200, 200, 1.96);
        assert!(
            all200 > all3,
            "同样 100% 成功率，样本多的下界必须更高：{all200} vs {all3}"
        );

        // 固定 n 时随成功数单调不减。
        let mut prev = -1.0;
        for x in 0..=20 {
            let v = wilson_lower_bound(x, 20, 1.96);
            assert!(v >= prev, "x={x} 时下界回落了：{v} < {prev}");
            prev = v;
        }
        // 固定比例时随样本量单调不减（20/20 → 200/200 已在上方断言）。
        assert!(wilson_lower_bound(18, 20, 1.96) < wilson_lower_bound(180, 200, 1.96));
    }

    /// 分位数：线性插值，且"没数据"与"值是 0"必须分得开。
    #[test]
    fn quantile_interpolates_and_distinguishes_empty() {
        assert_eq!(quantile(&[], 0.5), None);
        assert_eq!(quantile(&[7.0], 0.9), Some(7.0));
        let v = [0.0, 10.0, 20.0, 30.0];
        assert_eq!(quantile(&v, 0.0), Some(0.0));
        assert_eq!(quantile(&v, 1.0), Some(30.0));
        assert_eq!(quantile(&v, 0.5), Some(15.0));
        // P10/P90 落在中间：不是端点，也不是被四舍五入到整数下标。
        let p10 = quantile(&v, 0.10).unwrap();
        let p90 = quantile(&v, 0.90).unwrap();
        assert!(p10 > 0.0 && p10 < 10.0, "p10={p10}");
        assert!(p90 > 20.0 && p90 < 30.0, "p90={p90}");
    }

    /// 三个分项都落在 0..=1，且方向正确（越快越高、首字节越慢越低、越稳越高）。
    #[test]
    fn component_scores_are_bounded_and_directional() {
        let p = ScoreParams::default();
        assert_eq!(speed_score(0.0, p.reference_bps, 4.0), 0.0);
        // 饱和点就是基准带宽本身：达到基准带宽即满分（这是"归一化"的定义）。
        assert_eq!(speed_score(p.reference_bps, p.reference_bps, 4.0), 1.0);
        assert_eq!(
            speed_score(p.reference_bps * 100.0, p.reference_bps, 4.0),
            1.0
        );
        // 单调性要在**未饱和区**验证，否则测的只是夹取。
        let s1 = speed_score(p.reference_bps * 0.25, p.reference_bps, 4.0);
        let s2 = speed_score(p.reference_bps * 0.75, p.reference_bps, 4.0);
        assert!((0.0..1.0).contains(&s1) && (0.0..1.0).contains(&s2));
        assert!(s1 < s2, "未饱和区内更快必须分更高：{s1} vs {s2}");

        assert_eq!(response_score(0.0), 1.0, "0 毫秒应当满分");
        assert!(response_score(500.0) < response_score(50.0));
        assert!(response_score(100_000.0) < 0.01);

        assert_eq!(stability_score(10.0, 0.0), 0.0);
        assert_eq!(stability_score(50.0, 100.0), 0.5);
        assert_eq!(stability_score(100.0, 100.0), 1.0, "完全稳定为 1");
        assert_eq!(
            stability_score(200.0, 100.0),
            1.0,
            "P10 不可能高于中位，仍夹到 1"
        );
    }

    /// 权重：两个端点必须是规格给的原文数字，中间单调过渡，且**始终和为 1**。
    #[test]
    fn weights_hit_the_specified_endpoints_and_stay_normalized() {
        let p = ScoreParams::default();
        let small = weights_for(1024, None, 0.0, &p);
        assert!((small.speed - 0.35).abs() < 1e-9, "{small:?}");
        assert!((small.stability - 0.15).abs() < 1e-9, "{small:?}");
        assert!((small.response - 0.50).abs() < 1e-9, "{small:?}");

        let large = weights_for(600 * 1024 * 1024, None, 0.0, &p);
        assert!((large.speed - 0.80).abs() < 1e-9, "{large:?}");
        assert!((large.stability - 0.15).abs() < 1e-9, "{large:?}");
        assert!((large.response - 0.05).abs() < 1e-9, "{large:?}");

        // 中间档：速度分随文件增大单调增加，响应分单调减少，稳定性不变。
        let mid_a = weights_for(10 * 1024 * 1024, None, 0.0, &p);
        let mid_b = weights_for(30 * 1024 * 1024, None, 0.0, &p);
        assert!(mid_a.speed < mid_b.speed, "{mid_a:?} {mid_b:?}");
        assert!(mid_a.response > mid_b.response, "{mid_a:?} {mid_b:?}");
        assert!((mid_a.stability - 0.15).abs() < 1e-9);
        assert!(mid_a.speed >= small.speed && mid_b.speed <= large.speed);

        for w in [small, mid_a, mid_b, large] {
            let sum = w.speed + w.stability + w.response;
            assert!((sum - 1.0).abs() < 1e-9, "权重必须和为 1：{w:?}");
        }
    }

    /// 实测网络校准：传输时间远大于首字节耗时 → 偏吞吐；反之偏响应。
    ///
    /// 这条守的是规格里"若不超过首字节耗时则偏重响应速度，若超过其 10 倍则偏重持续吞吐量"。
    #[test]
    fn network_calibration_tilts_between_response_and_throughput() {
        let p = ScoreParams::default();
        // 取在**大文件档**（≥500 MB）内，否则基准权重落在过渡带，端点断言无从谈起。
        let size = 600 * 1024 * 1024;

        // 同一文件、同一速度，只改**首字节耗时**：这一维才是规格那句
        // "若不超过首字节耗时则偏重响应速度"的直接变量。
        // （拿"快源 vs 慢源"比会失效：600 MB 下即使 200 MiB/s 也要 3 s，
        //   远大于 10×ttfb，两边都饱和到"吞吐主导"，比不出差别。）
        let fast_connect = weights_for(size, Some(10.0), 200.0 * 1024.0 * 1024.0, &p);
        // ttfb = 3 s：估算传输时间（3 s）不超过首字节耗时 → 应当偏**响应**
        let slow_connect = weights_for(size, Some(3000.0), 200.0 * 1024.0 * 1024.0, &p);
        assert!(
            fast_connect.speed > slow_connect.speed,
            "估算传输时间远大于首字节耗时时必须偏吞吐：fast_connect={fast_connect:?} slow_connect={slow_connect:?}"
        );
        assert!(fast_connect.response < slow_connect.response);
        assert!(
            slow_connect.response > slow_connect.speed,
            "传输时间不长于建连耗时时，响应速度应当占主导：{slow_connect:?}"
        );
        assert!(
            (fast_connect.speed + fast_connect.stability + fast_connect.response - 1.0).abs()
                < 1e-9
        );

        // 没有速度样本时不做校准（只按大小），权重仍为规格端点值。
        let no_data = weights_for(size, Some(50.0), 0.0, &p);
        assert!((no_data.speed - 0.80).abs() < 1e-9, "{no_data:?}");
    }

    /// 采集口径：失败与超时计入分母、分位数只用成功样本、24 小时窗口、暂停与排名门槛。
    #[test]
    fn collection_rules_follow_the_specification() {
        let p = ScoreParams::default();
        let now = 1_000_000_000i64;
        let mut s = SourceStats::default();

        // 20 次尝试：18 成功（1 MiB/s）+ 2 失败
        for i in 0..18 {
            s.record(ok(1024 * 1024, 1000, 40, now - 1000 + i), &p);
        }
        s.record(bad(now - 500), &p);
        s.record(bad(now - 400), &p);
        assert_eq!(s.total(), 20, "失败必须计入总尝试");
        assert_eq!(s.successes(), 18);

        let sc = s
            .score(100 * 1024 * 1024, now, &p)
            .expect("够 20 条就该能评分");
        assert!(s.is_ranked(&p));
        assert!(sc.attempts == 20);
        // 保守成功率必须低于 18/20 = 0.9
        assert!(
            sc.success_lower_bound < 0.9,
            "保守下界不该等于点估计：{}",
            sc.success_lower_bound
        );
        assert!(
            (0.0..=100.0).contains(&sc.total),
            "总分应当在 0..=100：{}",
            sc.total
        );

        // 失败样本不得进入速度分位：中位仍是 1 MiB/s 那一档 → P10 == 中位 → 稳定性 1.0
        assert!((sc.stability - 1.0).abs() < 1e-9, "{sc:?}");

        // 24 小时窗口：记录时就会裁，所以插入一条 25 小时前的记录不会留在窗口里
        // （这一点是刻意的：内存占用必须与"跑了多久"无关）。
        let mut s2 = SourceStats::default();
        s2.record(ok(1024, 1000, 10, now - 25 * 60 * 60 * 1000), &p);
        s2.record(ok(1024, 1000, 10, now - 1000), &p);
        assert_eq!(s2.total(), 1, "窗口外的记录应当在插入时就被裁掉");
        s2.prune(now, &p);
        assert_eq!(s2.total(), 1, "显式裁剪不该误删窗口内的记录");

        // 连续失败 3 次 → 暂停；5 分钟后不再暂停
        let mut s3 = SourceStats::default();
        s3.record(bad(now), &p);
        assert!(!s3.is_paused(now, &p), "1 次失败不该暂停");
        s3.record(bad(now), &p);
        assert!(!s3.is_paused(now, &p), "2 次失败不该暂停");
        s3.record(bad(now), &p);
        assert!(s3.is_paused(now, &p), "3 次连续失败应当暂停");
        assert!(
            s3.is_paused(now + p.pause_ms - 1, &p),
            "暂停期内一毫秒都算暂停"
        );
        assert!(!s3.is_paused(now + p.pause_ms, &p), "满 5 分钟即解除");
        // 成功一次即清零连续失败
        s3.record(ok(1024, 100, 10, now), &p);
        assert!(!s3.is_paused(now, &p));

        // 不足 20 条：**不参与排名**（宁可不排，也不给一个低分污染排序）
        let mut s4 = SourceStats::default();
        for i in 0..5 {
            s4.record(ok(1024 * 1024, 100, 10, now), &p);
            let _ = i;
        }
        assert!(!s4.is_ranked(&p));
        let mut all = SourceScores::new(p);
        all.record("new", ok(1024 * 1024, 100, 10, now));
        assert!(all.ranked(1024, now).is_empty(), "新源不该出现在排名里");
    }

    /// 排行榜：按总分降序、并列按键名升序（确定性），且被暂停的来源不入列。
    #[test]
    fn ranking_is_descending_and_deterministic() {
        let p = ScoreParams::default();
        let now = 1_000_000_000i64;
        let mut all = SourceScores::new(p);

        // fast：20 次成功、1 MiB/s、ttfb 20ms
        for _ in 0..20 {
            all.record("fast", ok(4 * 1024 * 1024, 1000, 20, now));
        }
        // slow：20 次成功但只有 64 KiB/s
        for _ in 0..20 {
            all.record("slow", ok(64 * 1024, 1000, 300, now));
        }
        // paused：连续失败 3 次
        for _ in 0..3 {
            all.record("paused", bad(now));
        }
        let r = all.ranked(100 * 1024 * 1024, now);
        let keys: Vec<&str> = r.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["fast", "slow"], "快的在前，暂停的不入列");
        assert!(r[0].1.total > r[1].1.total);

        // 确定性：同数据重复调用顺序一致（并列时按键名）
        let a = all.ranked(100 * 1024 * 1024, now);
        let b = all.ranked(100 * 1024 * 1024, now);
        assert_eq!(
            a.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>(),
            b.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>()
        );
    }

    /// 暂停期满后的**探测恢复**：期满即可探一次，探过就不再重复"该探测"。
    ///
    /// 规格原文「连续失败 3 次可暂停选择 5 分钟，之后探测恢复」。这条守的是
    /// "暂停不等于永久出局"，以及"探测不污染成功率统计"。
    #[test]
    fn a_paused_source_becomes_due_for_a_probe_once_the_pause_expires() {
        let p = ScoreParams::default();
        let now = 1_000_000_000i64;
        let mut s = SourceStats::default();
        for _ in 0..3 {
            s.record(bad(now), &p);
        }
        assert!(s.is_paused(now, &p));
        assert!(!s.is_due_for_probe(now, &p), "暂停期内不该被要求探测");
        assert!(!s.is_due_for_probe(now + p.pause_ms - 1, &p));
        assert!(
            s.is_due_for_probe(now + p.pause_ms, &p),
            "期满应当给一次探测机会"
        );

        s.mark_probed(now + p.pause_ms);
        assert!(
            !s.is_due_for_probe(now + p.pause_ms, &p),
            "探过一次就不该重复要求探测（否则等于没暂停）"
        );
        assert!(!s.is_due_for_probe(now + p.pause_ms + 1, &p));
        assert_eq!(s.total(), 3, "探测不该被算进尝试次数");
        assert_eq!(
            s.successes(),
            0,
            "探测不该被算成成功（否则烂源会因探测而看起来变好）"
        );
        assert_eq!(s.last_probe_at_ms(), Some(now + p.pause_ms));

        // 探测成功 → 连续失败清零 → 既不暂停、也不再要求探测
        s.record(ok(1024, 100, 10, now + p.pause_ms + 2), &p);
        assert!(!s.is_paused(now + p.pause_ms + 2, &p));
        assert!(!s.is_due_for_probe(now + p.pause_ms + 2, &p));

        // 从未失败过的源永远不需要"恢复探测"
        let fresh = SourceStats::default();
        assert!(!fresh.is_due_for_probe(now, &p));
    }

    /// **没测到首字节耗时的尝试不得伪装成"响应满分"**。
    /// worker 的分段循环拿不到首字节时刻（只记 0）；若把 0 当样本，`L = 500/(500+0) = 1.0`，
    /// 这一项对所有源都是满分，等于没有响应速度这一维。
    #[test]
    fn attempts_without_a_ttfb_sample_do_not_fake_a_perfect_response() {
        let p = ScoreParams::default();
        let now = 1_000_000_000i64;
        let mut s = SourceStats::default();
        for _ in 0..20 {
            // ttfb = 0 表示"没测到"
            s.record(ok(1024 * 1024, 1000, 0, now), &p);
        }
        let sc = s.score(100 * 1024 * 1024, now, &p).unwrap();
        assert_eq!(sc.response, 0.0, "无样本时响应分应当是 0，而不是 1：{sc:?}");

        // 有真实样本时按公式算：ttfb P90 = 500ms → 500/(500+500) = 0.5
        let mut s2 = SourceStats::default();
        for _ in 0..20 {
            s2.record(ok(1024 * 1024, 1000, 500, now), &p);
        }
        let sc2 = s2.score(100 * 1024 * 1024, now, &p).unwrap();
        assert!((sc2.response - 0.5).abs() < 1e-9, "{sc2:?}");
    }
}
