//! 剪贴板「下载提示」的三层策略：**链接识别 → 下载目标判定 → 提示策略**。
//!
//! 设计动机：把协议头判断与提示策略压在一层时，文本只要含协议头就弹，误触发多。
//! 因此拆成三层，每层可独立测试：
//!
//! * [`extract`] 只回答"文本里有没有候选地址"，不做价值判断；
//! * [`judge`] 回答"这个地址有多少证据算下载资源"，**协议头不再是充分条件，
//!   扩展名也不再是唯一依据**（网页扩展名直接否定，未知扩展名只给弱分）；
//! * [`PromptDecider`] 回答"现在该不该弹"，负责防抖、去重、取消后抑制与已存在任务过滤。
//!
//! 全部参数集中在 [`ClipboardPolicy`]，没有散落在调用点的魔法值。
//! 本模块是纯逻辑（不读时间、不发网络），时间由调用方传入，便于回归测试。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::content_check::url_extension;
use crate::link_decode;

/// 网页/脚本类扩展名：地址以它们结尾时**直接否定**（与 `browser.skip_html` 取向一致）。
const HTML_EXTS: &[&str] = &[
    "html", "htm", "xhtml", "shtml", "php", "php3", "php4", "php5", "phtml", "asp", "aspx", "jsp",
    "jspx", "do", "action", "cgi", "pl",
];

/// 路径或查询里出现这些片段，说明"这是给人下载用的入口"。
const DOWNLOAD_HINTS: &[&str] = &[
    "download",
    "/dl/",
    "/d/",
    "/file/",
    "/files/",
    "/attach",
    "/get/",
    "/fetch",
    "/resource/",
    "/media/",
    "/soft",
    "/setup",
    "/patch",
    "filename=",
    "response-content-disposition",
];

/// 签名/时效参数：对象存储与网盘的直链几乎都带这些，属于"资源地址"的旁证。
const SIGNED_HINTS: &[&str] = &[
    "x-amz-signature",
    "x-amz-credential",
    "x-obs-",
    "signature=",
    "sig=",
    "token=",
    "expires=",
    "auth_key=",
    "response-content-disposition",
];

/// 集中配置：剪贴板监视的全部可调参数。
///
/// 默认值取"宁可少弹一次，也不要把普通网页弹出来"的取向；扩展名表由设置
/// （`browser.auto_catch_exts`）注入，其余为 AIDM 自身策略。
#[derive(Debug, Clone, PartialEq)]
pub struct ClipboardPolicy {
    /// 超过这个长度的剪贴板文本不当链接列表处理（避免复制大段正文时卡顿）。
    pub max_text_chars: usize,
    /// 单次文本最多解析出的候选数。
    pub max_candidates: usize,
    /// 单次提示最多展示的链接数（其余留给用户手动添加）。
    pub max_prompt_links: usize,
    /// 同一段文本在这个窗口内不重复处理（有的程序一次复制会写两遍剪贴板）。
    pub same_text_cooldown: Duration,
    /// 同一个地址在这个窗口内不重复提示。
    pub url_cooldown: Duration,
    /// 用户在候选框里取消后，对这批地址的抑制窗口。
    pub dismiss_suppress: Duration,
    /// 记忆表容量上限，防止长时间运行后无界增长。
    pub seen_capacity: usize,
    /// 提示阈值：得分达到它才认为"有足够依据是下载资源"。
    pub min_score: i32,
    /// 监视扩展名（含 `r0*` 这类前缀通配）；由设置注入。
    pub watched_exts: Vec<String>,
    /// 网络探测参数（探测永不阻塞调用方；失败只当"未知"）。
    pub probe: ProbeConfig,
}

/// 探测参数。UI 侧通过引擎 IPC 探测时使用；本模块只定义参数与融合规则。
#[derive(Debug, Clone, PartialEq)]
pub struct ProbeConfig {
    pub enabled: bool,
    pub timeout: Duration,
    pub max_parallel: usize,
    /// 探测出"明确是 HTML 页面"时扣的分（不足以推翻扩展名/关键词等强证据）。
    pub html_penalty: i32,
    /// 探测出"像下载"（非 HTML 内容类型 / 附件 / 有长度）时加的分。
    pub like_bonus: i32,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout: Duration::from_millis(2500),
            max_parallel: 2,
            html_penalty: 3,
            like_bonus: 2,
        }
    }
}

impl Default for ClipboardPolicy {
    fn default() -> Self {
        Self {
            max_text_chars: 64 * 1024,
            max_candidates: 32,
            max_prompt_links: 20,
            same_text_cooldown: Duration::from_secs(2),
            url_cooldown: Duration::from_secs(60),
            dismiss_suppress: Duration::from_secs(600),
            seen_capacity: 512,
            min_score: 2,
            watched_exts: Vec::new(),
            probe: ProbeConfig::default(),
        }
    }
}

impl ClipboardPolicy {
    /// 设置里的扩展名串 → 规范化列表（空白/逗号分号分隔，去掉前导点，统一小写）。
    pub fn parse_exts(raw: &str) -> Vec<String> {
        raw.split(|c: char| c.is_whitespace() || ",，;；".contains(c))
            .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// 扩展名是否命中监视表；表项以 `*` 结尾表示前缀匹配（`r0*` 命中 `r01`）。
    pub fn ext_matches(&self, ext: &str) -> bool {
        !ext.is_empty()
            && self.watched_exts.iter().any(|p| match p.strip_suffix('*') {
                Some(prefix) => ext.starts_with(prefix),
                None => p == ext,
            })
    }

    /// 用设置里的扩展名串更新监视表。
    pub fn set_watched_exts(&mut self, raw: &str) {
        self.watched_exts = Self::parse_exts(raw);
    }
}

/// 候选地址的协议族。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    Http,
    Ftp,
    Magnet,
    Ed2k,
    /// 封装链接：真实协议要看**解码后**的目标。
    Wrapped,
}

/// 从文本里切出来的候选地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// 剪贴板里的原始写法（提示与新建任务都用它，保证签名 URL 不被规范化破坏）。
    pub raw: String,
    /// 用于判定的地址：封装链接是解码后的真实地址，其余等于 `raw`。
    pub decoded: String,
    pub kind: LinkKind,
}

/// 下载目标判定结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// 强证据（命中监视扩展名 / 种子 / 合法的 magnet、eD2k 文件链接）。
    Strong,
    /// 证据够用（达到阈值）。
    Likely,
    /// 有地址形状但没有下载证据 —— 默认不提示。
    Weak,
    /// 确定不是下载目标（网页地址、格式错误的封装链接等）。
    Rejected,
}

impl Verdict {
    /// 是否足以触发提示（阈值已在 `verdict_of` 用过，这里只看结论）。
    pub fn promptable(self) -> bool {
        matches!(self, Verdict::Strong | Verdict::Likely)
    }
}

/// 单条候选的判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    pub url: String,
    pub kind: LinkKind,
    pub verdict: Verdict,
    pub score: i32,
    /// 判定依据（进诊断日志；不含敏感值）。
    pub reasons: Vec<&'static str>,
}

/// 探测结论。`Unknown` 是缺省：**探测没做、超时或失败都不等于链接无效**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Unknown,
    /// 明确像下载：非 HTML 内容类型、带附件头或有明确长度。
    LooksDownloadable {
        content_type: Option<String>,
    },
    /// 明确是 HTML 页面（错误页/落地页）。
    HtmlPage,
}

/// 提示决策结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptDecision {
    Show {
        links: Vec<String>,
        reason: &'static str,
    },
    Suppress {
        reason: &'static str,
    },
}

/// 把剪贴板文本切成候选地址。
///
/// 按**协议头**切分、对每段做类型化裁剪；**不**把 40/32 位裸哈希补成
/// `magnet:?xt=urn:btih:`（纯文本里噪声太大，最容易误触发）。
pub fn extract(text: &str, policy: &ClipboardPolicy) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    if text.is_empty() || text.len() > policy.max_text_chars {
        return out;
    }
    // 带 "(*)" 的文本（错误页/占位符标记）整段丢：廉价的否定条件。
    if text.contains("(*)") {
        return out;
    }
    for piece in split_by_protocol(text) {
        if out.len() >= policy.max_candidates {
            break;
        }
        let piece = trim_piece(piece);
        if piece.is_empty() {
            continue;
        }
        let Some(kind) = kind_of(piece) else {
            continue;
        };
        let decoded = match kind {
            LinkKind::Wrapped => match link_decode::decode_link(piece) {
                Ok(Some(d)) => d.url.unwrap_or_default(),
                _ => String::new(),
            },
            _ => piece.to_string(),
        };
        let cand = Candidate {
            raw: piece.to_string(),
            decoded,
            kind,
        };
        if !out.iter().any(|c| c.raw == cand.raw) {
            out.push(cand);
        }
    }
    out
}

/// 判定一条候选是不是下载资源。
pub fn judge(cand: &Candidate, policy: &ClipboardPolicy) -> Judgement {
    match cand.kind {
        LinkKind::Magnet => judge_magnet(&cand.raw),
        LinkKind::Ed2k => judge_ed2k(&cand.raw),
        LinkKind::Wrapped => {
            if cand.decoded.is_empty() {
                Judgement {
                    url: cand.raw.clone(),
                    kind: cand.kind,
                    verdict: Verdict::Rejected,
                    score: i32::MIN,
                    reasons: vec!["wrapped_undecodable"],
                }
            } else {
                let inner_kind = kind_of(&cand.decoded).unwrap_or(LinkKind::Http);
                let inner = Candidate {
                    raw: cand.decoded.clone(),
                    decoded: cand.decoded.clone(),
                    kind: inner_kind,
                };
                let mut j = judge(&inner, policy);
                // 提示与新建任务仍用原始封装串，避免丢失用户给的那一层。
                j.url = cand.raw.clone();
                j.kind = cand.kind;
                j.reasons.push("wrapped_decoded");
                j
            }
        }
        LinkKind::Http | LinkKind::Ftp => judge_plain(&cand.raw, policy),
    }
}

/// 探测结论融合进判定分。`Unknown` 不改变任何东西。
pub fn apply_probe(j: &mut Judgement, outcome: &ProbeOutcome, policy: &ClipboardPolicy) {
    match outcome {
        ProbeOutcome::Unknown => {}
        ProbeOutcome::LooksDownloadable { .. } => {
            j.score += policy.probe.like_bonus;
            j.reasons.push("probe_downloadable");
        }
        ProbeOutcome::HtmlPage => {
            // 只有"地址本身已经像文件"时才让 HTML 探测把它按下去；
            // 一个没有扩展名的地址被探测成 HTML，也只是回到"证据不足"。
            if j.score >= policy.min_score {
                j.score -= policy.probe.html_penalty;
                j.reasons.push("probe_html_page");
            }
        }
    }
    j.verdict = verdict_of(j.score, policy.min_score);
}

fn verdict_of(score: i32, min_score: i32) -> Verdict {
    if score >= min_score + 2 {
        Verdict::Strong
    } else if score >= min_score {
        Verdict::Likely
    } else if score > 0 {
        Verdict::Weak
    } else {
        Verdict::Rejected
    }
}

fn judge_plain(url: &str, policy: &ClipboardPolicy) -> Judgement {
    let mut reasons: Vec<&'static str> = Vec::new();
    let mut score = 0i32;

    let lower = url.to_ascii_lowercase();
    let (scheme, rest) = match lower.split_once("://") {
        Some((s, r)) => (s, r),
        None => {
            return Judgement {
                url: url.to_string(),
                kind: LinkKind::Http,
                verdict: Verdict::Rejected,
                score: i32::MIN,
                reasons: vec!["no_scheme"],
            }
        }
    };
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@') // 去掉 user@ 前缀（userinfo 不参与判定）
        .next()
        .unwrap_or("");
    if host.is_empty() || host.contains(char::is_whitespace) || host.chars().any(char::is_control) {
        return rejected(url, LinkKind::Http, "bad_host");
    }
    // 单标签主机名（`http://fileserver/a.iso`）是合法的内网下载场景，不因"没有点"否定；
    // 真正无意义的地址由下面的路径/目录页判定与证据阈值挡掉。
    let kind = if scheme == "ftp" {
        LinkKind::Ftp
    } else {
        LinkKind::Http
    };

    let ext = url_extension(url).unwrap_or_default();
    if !ext.is_empty() {
        if HTML_EXTS.contains(&ext.as_str()) {
            return rejected(url, kind, "web_page_ext");
        }
        if ext == "torrent" {
            score += 3;
            reasons.push("torrent_ext");
        } else if policy.ext_matches(&ext) {
            score += 3;
            reasons.push("watched_ext");
        } else {
            // 未知扩展名只是**弱**证据：普通站点也可能有 `news.example/a.b`。
            score += 1;
            reasons.push("unknown_ext");
        }
    }

    if DOWNLOAD_HINTS.iter().any(|h| lower.contains(h)) {
        score += 2;
        reasons.push("download_hint");
    }
    if SIGNED_HINTS.iter().any(|h| lower.contains(h)) {
        score += 1;
        reasons.push("signed_url");
    }

    // 站点根 / 目录页：更像"某个网页"，扣分但不一票否决。
    let path = rest.find('/').map(|i| &rest[i..]).unwrap_or("/");
    let path_only = path.split(['?', '#']).next().unwrap_or(path);
    if path_only == "/" || path_only.is_empty() {
        score -= 2;
        reasons.push("site_root");
    } else if path_only.ends_with('/') {
        score -= 1;
        reasons.push("dir_path");
    }

    Judgement {
        url: url.to_string(),
        kind,
        verdict: verdict_of(score, policy.min_score),
        score,
        reasons,
    }
}

fn judge_magnet(url: &str) -> Judgement {
    let rest = &url["magnet:?".len()..];
    let mut btih: Option<&str> = None;
    let mut has_name = false;
    let mut has_tracker = false;
    for param in rest.split('&') {
        let (k, v) = match param.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if k.eq_ignore_ascii_case("dn") {
            has_name = true;
        } else if k.eq_ignore_ascii_case("tr") {
            has_tracker = true;
        } else if k.eq_ignore_ascii_case("xt") || k.to_ascii_lowercase().starts_with("xt.") {
            if let Some(h) = v.strip_prefix("urn:btih:") {
                btih = Some(h);
            }
        }
    }
    let Some(hash) = btih else {
        return rejected(url, LinkKind::Magnet, "magnet_no_btih");
    };
    let ok = (hash.len() == 40 && hash.chars().all(|c| c.is_ascii_hexdigit()))
        || (hash.len() == 32 && hash.chars().all(|c| c.is_ascii_alphanumeric()));
    if !ok {
        return rejected(url, LinkKind::Magnet, "magnet_bad_hash");
    }
    let mut score = 3;
    let mut reasons = vec!["magnet_btih"];
    if has_name {
        score += 1;
        reasons.push("magnet_dn");
    }
    if has_tracker {
        score += 1;
        reasons.push("magnet_tr");
    }
    Judgement {
        url: url.to_string(),
        kind: LinkKind::Magnet,
        verdict: Verdict::Strong,
        score,
        reasons,
    }
}

fn judge_ed2k(url: &str) -> Judgement {
    let lower = url.to_ascii_lowercase();
    let body = &lower["ed2k://".len()..];
    if body.starts_with("|server|") || body.starts_with("|serverlist|") {
        return rejected(url, LinkKind::Ed2k, "ed2k_not_file");
    }
    let Some(rest) = body.strip_prefix("|file|") else {
        return rejected(url, LinkKind::Ed2k, "ed2k_malformed");
    };
    let rest = rest
        .strip_suffix("|/")
        .unwrap_or(rest)
        .trim_end_matches('/');
    let fields: Vec<&str> = rest.split('|').collect();
    if fields.len() < 3 {
        return rejected(url, LinkKind::Ed2k, "ed2k_malformed");
    }
    let name = fields[0];
    let size = fields[1];
    let hash = fields[2];
    if name.is_empty() || size.is_empty() || !size.chars().all(|c| c.is_ascii_digit()) {
        return rejected(url, LinkKind::Ed2k, "ed2k_malformed");
    }
    if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return rejected(url, LinkKind::Ed2k, "ed2k_bad_hash");
    }
    Judgement {
        url: url.to_string(),
        kind: LinkKind::Ed2k,
        verdict: Verdict::Strong,
        score: 3,
        reasons: vec!["ed2k_file"],
    }
}

fn rejected(url: &str, kind: LinkKind, reason: &'static str) -> Judgement {
    Judgement {
        url: url.to_string(),
        kind,
        verdict: Verdict::Rejected,
        score: i32::MIN,
        reasons: vec![reason],
    }
}

// ---------------- 文本切分 ----------------

const SPLIT_PROTOCOLS: [&str; 6] = ["https:", "http:", "ftp:", "thunder:", "ed2k:", "magnet:"];
const PLAIN_PREFIXES: [&str; 3] = ["http://", "https://", "ftp://"];
const MAGNET_PREFIX: &str = "magnet:?";
const DELIMITED_PREFIX: &str = "thunder://";
const ED2K_PREFIX: &str = "ed2k://";

fn kind_of(piece: &str) -> Option<LinkKind> {
    let lower = piece.to_ascii_lowercase();
    if PLAIN_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return Some(if lower.starts_with("ftp://") {
            LinkKind::Ftp
        } else {
            LinkKind::Http
        });
    }
    if lower.starts_with(MAGNET_PREFIX) {
        return Some(LinkKind::Magnet);
    }
    if lower.starts_with(ED2K_PREFIX) {
        return Some(LinkKind::Ed2k);
    }
    if lower.starts_with(DELIMITED_PREFIX)
        || lower.starts_with("thunders://")
        || lower.starts_with("qqdl://")
        || lower.starts_with("flashget://")
        || lower.starts_with("fs2you://")
    {
        return Some(LinkKind::Wrapped);
    }
    None
}

/// 在每个协议头处切开（磁力链接 `&tr=` 后面的 tracker 不算新链接）。
fn split_by_protocol(text: &str) -> Vec<&str> {
    let mut starts = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let rest = &text[i..];
        if let Some(p) = SPLIT_PROTOCOLS.iter().find(|p| rest.starts_with(**p)) {
            let in_tracker = p.starts_with("http") && text[..i].ends_with("&tr=");
            if !in_tracker {
                starts.push(i);
            }
            i += p.len();
        } else {
            i += rest.chars().next().map_or(1, char::len_utf8);
        }
    }
    starts
        .iter()
        .enumerate()
        .map(|(n, &s)| &text[s..starts.get(n + 1).copied().unwrap_or(text.len())])
        .collect()
}

/// 去掉一段候选周围的杂质：空白、中英文标点、引号与括号。
fn trim_piece(piece: &str) -> &str {
    let end = piece
        .find(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    ',' | ';'
                        | '"'
                        | '\''
                        | '<'
                        | '>'
                        | '）'
                        | '】'
                        | '》'
                        | '，'
                        | '。'
                        | '、'
                        | '；'
                        | '：'
                )
        })
        .map_or(piece, |n| &piece[..n]);
    let end = match end.as_bytes().first() {
        Some(_) => end,
        None => return "",
    };
    trim_typed(end)
}

/// 按协议类型裁掉尾部粘连的文本（同时保住签名 URL 的查询串）。
fn trim_typed(link: &str) -> &str {
    let lower = link.to_ascii_lowercase();
    if lower.starts_with(MAGNET_PREFIX) {
        trim_magnet(link)
    } else if lower.starts_with(DELIMITED_PREFIX) || lower.starts_with("thunders://") {
        trim_base64(link, link.find("://").map_or(0, |i| i + 3))
    } else if lower.starts_with(ED2K_PREFIX) {
        match link[ED2K_PREFIX.len()..].find("|/") {
            Some(n) => &link[..ED2K_PREFIX.len() + n + 2],
            None => link,
        }
    } else {
        link
    }
}

fn trim_base64(link: &str, from: usize) -> &str {
    match link[from..].find(|c: char| !(c.is_ascii_alphanumeric() || "=+/-_".contains(c))) {
        Some(n) => &link[..from + n],
        None => link,
    }
}

/// 磁力链接截到 btih 哈希为止（tracker 参数保留），丢掉紧跟哈希的杂字符。
fn trim_magnet(link: &str) -> &str {
    for param in link[MAGNET_PREFIX.len()..].split('&') {
        let Some((key, value)) = param.split_once('=') else {
            continue;
        };
        if key != "xt" && !key.starts_with("xt.") {
            continue;
        }
        let Some(hash) = value.strip_prefix("urn:btih:") else {
            break;
        };
        if hash.len() <= 32 || hash.len() == 40 {
            break;
        }
        for len in [40, 32] {
            if hash.len() >= len && hash.as_bytes()[..len].iter().all(u8::is_ascii_alphanumeric) {
                let at = link.find(hash).unwrap_or(0);
                return &link[..at + len];
            }
        }
        break;
    }
    link
}

// ---------------- 提示策略 ----------------

/// 提示决策器：防抖、去重、取消后抑制。
#[derive(Debug)]
pub struct PromptDecider {
    policy: ClipboardPolicy,
    last_text: Option<(String, Instant)>,
    last_shown: HashMap<String, Instant>,
    dismissed: HashMap<String, Instant>,
}

impl PromptDecider {
    pub fn new(policy: ClipboardPolicy) -> Self {
        Self {
            policy,
            last_text: None,
            last_shown: HashMap::new(),
            dismissed: HashMap::new(),
        }
    }

    pub fn policy(&self) -> &ClipboardPolicy {
        &self.policy
    }

    pub fn policy_mut(&mut self) -> &mut ClipboardPolicy {
        &mut self.policy
    }

    /// 同一段文本的防抖：窗口内返回 `false`（不处理这次剪贴板变化）。
    pub fn accept_text(&mut self, text: &str, now: Instant) -> bool {
        if let Some((prev, at)) = &self.last_text {
            if prev == text && now.duration_since(*at) < self.policy.same_text_cooldown {
                return false;
            }
        }
        self.last_text = Some((text.to_string(), now));
        true
    }

    /// 记录"用户放弃了这个提示"。同一批地址在抑制窗口内不再弹。
    pub fn dismiss(&mut self, urls: &[String], now: Instant) {
        for u in urls {
            self.dismissed.insert(u.clone(), now);
        }
        self.shrink();
    }

    /// 该地址此刻是否仍被用户取消所抑制。
    pub fn is_dismissed(&self, url: &str, now: Instant) -> bool {
        self.dismissed
            .get(url)
            .is_some_and(|at| now.duration_since(*at) < self.policy.dismiss_suppress)
    }

    /// 综合判定 → 是否提示。
    ///
    /// `existing` 是引擎里已在下载/已完成的同地址任务；命中即抑制（不再提示重复任务），
    /// 但查询失败时调用方应传空切片：**拿不到任务列表不等于该链接不能下**。
    pub fn decide(
        &mut self,
        judged: Vec<Judgement>,
        existing: &[String],
        now: Instant,
    ) -> PromptDecision {
        let mut links: Vec<String> = Vec::new();
        let mut skipped_existing = false;
        let mut skipped_cooldown = false;
        let mut skipped_dismissed = false;
        for j in judged {
            if !j.verdict.promptable() {
                continue;
            }
            if existing.iter().any(|e| e == &j.url) {
                skipped_existing = true;
                continue;
            }
            if self.is_dismissed(&j.url, now) {
                skipped_dismissed = true;
                continue;
            }
            if let Some(at) = self.last_shown.get(&j.url) {
                if now.duration_since(*at) < self.policy.url_cooldown {
                    skipped_cooldown = true;
                    continue;
                }
            }
            links.push(j.url);
        }
        if links.is_empty() {
            let reason = if skipped_existing {
                "already_in_tasks"
            } else if skipped_dismissed {
                "dismissed_recently"
            } else if skipped_cooldown {
                "cooldown"
            } else {
                "no_download_evidence"
            };
            return PromptDecision::Suppress { reason };
        }
        links.truncate(self.policy.max_prompt_links);
        for u in &links {
            self.last_shown.insert(u.clone(), now);
        }
        self.shrink();
        PromptDecision::Show {
            links,
            reason: "download_evidence",
        }
    }

    /// 记忆表有界化：超容量时先淘汰过期项，其次淘汰最久的。
    fn shrink(&mut self) {
        if self.last_shown.len() <= self.policy.seen_capacity
            && self.dismissed.len() <= self.policy.seen_capacity
        {
            return;
        }
        let cap = self.policy.seen_capacity;
        if self.last_shown.len() > cap {
            let mut items: Vec<(String, Instant)> = self.last_shown.drain().collect();
            items.sort_by_key(|(_, at)| *at);
            let keep = items.split_off(items.len() - cap);
            self.last_shown = keep.into_iter().collect();
        }
        if self.dismissed.len() > cap {
            let mut items: Vec<(String, Instant)> = self.dismissed.drain().collect();
            items.sort_by_key(|(_, at)| *at);
            let keep = items.split_off(items.len() - cap);
            self.dismissed = keep.into_iter().collect();
        }
    }
}

/// 诊断日志用的脱敏地址（`redact` 负责查询串里的凭据类取值）。
pub fn redacted(url: &str) -> String {
    crate::redact::redact_url(url).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ClipboardPolicy {
        let mut p = ClipboardPolicy::default();
        p.set_watched_exts("iso zip exe rar 7z r0*");
        p
    }

    fn exts() -> ClipboardPolicy {
        policy()
    }

    fn promptable_urls(text: &str, policy: &ClipboardPolicy) -> Vec<String> {
        extract(text, policy)
            .iter()
            .map(|c| judge(c, policy))
            .filter(|j| j.verdict.promptable())
            .map(|j| j.url)
            .collect()
    }

    // ---------- 识别 ----------

    #[test]
    fn splits_multiple_links_and_trims_punctuation() {
        let text = "1. http://a.example/x.zip 下载\n2.https://b.example/y.exe,备用\nhttp://a.example/x.zip";
        assert_eq!(
            promptable_urls(text, &exts()),
            ["http://a.example/x.zip", "https://b.example/y.exe"]
        );
    }

    #[test]
    fn keeps_tracker_in_magnet_and_drops_trailing_text() {
        let policy = exts();
        let hash = "0123456789abcdef0123456789abcdef01234567";
        let full = format!("magnet:?xt=urn:btih:{hash}&tr=http://t.example/announce");
        assert_eq!(promptable_urls(&full, &policy), std::slice::from_ref(&full));
        let glued = format!("magnet:?xt=urn:btih:{hash}复制自网页");
        assert_eq!(
            promptable_urls(&glued, &policy),
            [format!("magnet:?xt=urn:btih:{hash}")]
        );
    }

    #[test]
    fn ed2k_is_cut_at_its_terminator() {
        let text = "看这个 ed2k://|file|a.iso|4478906368|E7C526499308841A4A6D116C857DB669|/ 很快";
        assert_eq!(
            promptable_urls(text, &exts()),
            ["ed2k://|file|a.iso|4478906368|E7C526499308841A4A6D116C857DB669|/"]
        );
    }

    // ---------- 判定：不再"见协议头就提示" ----------

    #[test]
    fn plain_web_pages_are_rejected() {
        let p = exts();
        for text in [
            "https://example.com/article.html",
            "http://news.example/post.php?id=3",
            "https://example.com/",
            "https://example.com/section/",
            "https://example.com/about",
        ] {
            assert!(
                promptable_urls(text, &p).is_empty(),
                "普通网页不该触发提示: {text}"
            );
        }
    }

    #[test]
    fn watched_extension_and_torrent_still_prompt() {
        let p = exts();
        assert_eq!(
            promptable_urls("https://cdn.example/a/b.iso?sig=1", &p),
            ["https://cdn.example/a/b.iso?sig=1"]
        );
        assert_eq!(promptable_urls("http://x/p.r01", &p), ["http://x/p.r01"]);
        assert_eq!(
            promptable_urls("http://x/seed.torrent", &p),
            ["http://x/seed.torrent"]
        );
    }

    #[test]
    fn extensionless_download_entry_is_detected_by_path_evidence() {
        let p = exts();
        // 无扩展名但路径明确是下载入口 → 提示
        assert_eq!(
            promptable_urls("https://pan.example/download/9f8c1?token=abc", &p),
            ["https://pan.example/download/9f8c1?token=abc"]
        );
        // 同样无扩展名、也无下载线索 → 不提示
        assert!(promptable_urls("https://example.com/p/9f8c1", &p).is_empty());
    }

    #[test]
    fn unknown_extension_alone_is_not_enough() {
        let p = exts();
        // `news.example/a.b` 只有一个弱证据，不该弹提示
        assert!(promptable_urls("https://news.example/story.b", &p).is_empty());
    }

    #[test]
    fn signed_links_survive_normalization() {
        let p = exts();
        let url =
            "https://bucket.example/key/file.zip?X-Amz-Signature=deadbeef&X-Amz-Credential=k%2F1";
        assert_eq!(promptable_urls(url, &p), [url]);
    }

    // ---------- 判定：封装协议先解码再判断 ----------

    #[test]
    fn wrapped_links_are_judged_by_decoded_target() {
        let p = exts();
        let encode = |s: &str| {
            const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for chunk in s.as_bytes().chunks(3) {
                let n = chunk
                    .iter()
                    .enumerate()
                    .fold(0u32, |a, (i, &v)| a | (u32::from(v) << (16 - 8 * i)));
                for i in 0..4 {
                    let c = if i <= chunk.len() {
                        T[((n >> (18 - 6 * i)) & 63) as usize]
                    } else {
                        b'='
                    };
                    out.push(c as char);
                }
            }
            out
        };
        let iso = format!("thunder://{}", encode("AAhttp://x/a.isoZZ"));
        assert_eq!(promptable_urls(&format!("{iso}，复制"), &p), [iso.clone()]);
        let page = format!("thunder://{}", encode("AAhttp://x/a.htmlZZ"));
        assert!(promptable_urls(&page, &p).is_empty());
        assert!(promptable_urls("thunder://不是base64!!", &p).is_empty());
    }

    // ---------- 判定：magnet / ed2k 形状校验 ----------

    #[test]
    fn malformed_magnet_is_rejected() {
        let p = exts();
        assert!(promptable_urls("magnet:?xt=urn:btih:short", &p).is_empty());
        assert!(promptable_urls("magnet:?dn=name-only", &p).is_empty());
        let good32 = "magnet:?xt=urn:btih:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        assert_eq!(promptable_urls(good32, &p), [good32]);
    }

    #[test]
    fn malformed_ed2k_is_rejected() {
        let p = exts();
        assert!(promptable_urls("ed2k://|file|a.iso|", &p).is_empty());
        assert!(promptable_urls(
            "ed2k://|file|a.iso|notanumber|E7C526499308841A4A6D116C857DB669|/",
            &p
        )
        .is_empty());
        assert!(promptable_urls("ed2k://|file|a.iso|100|TOOSHORT|/", &p).is_empty());
        assert!(promptable_urls("ed2k://|server|1.2.3.4|4661|/", &p).is_empty());
    }

    #[test]
    fn error_page_marker_disables_the_whole_text() {
        let p = exts();
        assert!(promptable_urls("http://x/list(*).zip", &p).is_empty());
        assert!(promptable_urls("没有链接的普通文字", &p).is_empty());
    }

    // ---------- 提示策略 ----------

    #[test]
    fn same_text_is_debounced_but_new_text_passes() {
        let p = exts();
        let mut d = PromptDecider::new(p);
        let t0 = Instant::now();
        assert!(d.accept_text("a", t0));
        assert!(!d.accept_text("a", t0 + Duration::from_millis(500)));
        assert!(d.accept_text("b", t0 + Duration::from_millis(600)));
        assert!(d.accept_text("a", t0 + Duration::from_secs(5)));
    }

    /// 按给定策略判一条文本；不借用决策器，避免与 `decide(&mut self)` 冲突。
    fn judge_text(policy: &ClipboardPolicy, text: &str) -> Vec<Judgement> {
        extract(text, policy)
            .iter()
            .map(|c| judge(c, policy))
            .collect()
    }

    #[test]
    fn cooldown_and_dismiss_suppress_repeats() {
        let p = exts();
        let mut d = PromptDecider::new(p);
        let t0 = Instant::now();
        let url = "https://cdn.example/a.iso";

        // 首次提示
        match d.decide(judge_text(d.policy(), url), &[], t0) {
            PromptDecision::Show { links, .. } => assert_eq!(links, [url]),
            other => panic!("首次应提示: {other:?}"),
        }
        // 冷却窗口内重复 → 抑制
        match d.decide(
            judge_text(d.policy(), url),
            &[],
            t0 + Duration::from_secs(5),
        ) {
            PromptDecision::Suppress { reason } => assert_eq!(reason, "cooldown"),
            other => panic!("冷却期内应抑制: {other:?}"),
        }
        // 冷却过后，用户取消 → 长抑制
        let t1 = t0 + Duration::from_secs(120);
        assert!(matches!(
            d.decide(judge_text(d.policy(), url), &[], t1),
            PromptDecision::Show { .. }
        ));
        d.dismiss(&[url.to_string()], t1);
        match d.decide(
            judge_text(d.policy(), url),
            &[],
            t1 + Duration::from_secs(30),
        ) {
            PromptDecision::Suppress { reason } => assert_eq!(reason, "dismissed_recently"),
            other => panic!("取消后应抑制: {other:?}"),
        }
        // 抑制窗口过后可以再提示
        assert!(matches!(
            d.decide(
                judge_text(d.policy(), url),
                &[],
                t1 + Duration::from_secs(700)
            ),
            PromptDecision::Show { .. }
        ));
    }

    #[test]
    fn existing_task_suppresses_and_unknown_engine_does_not() {
        let p = exts();
        let mut d = PromptDecider::new(p);
        let t0 = Instant::now();
        let url = "https://cdn.example/a.iso";
        match d.decide(judge_text(d.policy(), url), &[url.to_string()], t0) {
            PromptDecision::Suppress { reason } => assert_eq!(reason, "already_in_tasks"),
            other => panic!("已有任务应抑制: {other:?}"),
        }
        // 拿不到任务列表（引擎离线）时按"没有"处理，不能因此判定链接无效
        assert!(matches!(
            d.decide(judge_text(d.policy(), url), &[], t0),
            PromptDecision::Show { .. }
        ));
    }

    #[test]
    fn no_evidence_is_reported_as_such() {
        let p = exts();
        let mut d = PromptDecider::new(p);
        let judged: Vec<Judgement> = extract("https://example.com/about", d.policy())
            .iter()
            .map(|c| judge(c, d.policy()))
            .collect();
        match d.decide(judged, &[], Instant::now()) {
            PromptDecision::Suppress { reason } => assert_eq!(reason, "no_download_evidence"),
            other => panic!("无证据应抑制: {other:?}"),
        }
    }

    #[test]
    fn prompt_list_is_capped() {
        let mut p = exts();
        p.max_prompt_links = 2;
        let mut d = PromptDecider::new(p);
        let judged: Vec<Judgement> =
            extract("http://x/a.iso http://x/b.zip http://x/c.exe", d.policy())
                .iter()
                .map(|c| judge(c, d.policy()))
                .collect();
        match d.decide(judged, &[], Instant::now()) {
            PromptDecision::Show { links, .. } => assert_eq!(links.len(), 2),
            other => panic!("应展示但被截断: {other:?}"),
        }
    }

    // ---------- 探测融合 ----------

    #[test]
    fn probe_results_shift_but_never_invalidate_alone() {
        let p = exts();
        let cand = &extract("https://cdn.example/download/9f8c1", &p)[0];
        let mut j = judge(cand, &p);
        assert!(j.verdict.promptable());
        let before = j.score;
        apply_probe(&mut j, &ProbeOutcome::Unknown, &p);
        assert_eq!(j.score, before, "未探测/探测失败不得改变判定");
        apply_probe(&mut j, &ProbeOutcome::HtmlPage, &p);
        assert!(j.score < before, "明确的 HTML 页面应降级证据");
    }

    #[test]
    fn probe_bonus_can_rescue_an_unknown_extension() {
        let p = exts();
        let cand = &extract("https://host.example/thing.bin", &p)[0];
        let mut j = judge(cand, &p);
        assert!(!j.verdict.promptable());
        apply_probe(
            &mut j,
            &ProbeOutcome::LooksDownloadable {
                content_type: Some("application/octet-stream".into()),
            },
            &p,
        );
        assert!(j.verdict.promptable());
    }

    #[test]
    fn redaction_hides_credentials_but_keeps_host() {
        let out = redacted("https://user:pass@cdn.example/a.iso?token=SECRET&x=1");
        assert!(out.contains("cdn.example"), "{out}");
        assert!(!out.contains("SECRET"), "{out}");
        assert!(!out.contains("pass"), "{out}");
    }
}
