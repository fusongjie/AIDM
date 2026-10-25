//! `SourceProvider` 抽象与 HTTP 实现（`docs/source-discovery.md` §4.9、§5.1–§5.4）。
//!
//! 调度器只认识这一层：能力、读取、刷新、单源版本、健康。**本批次不接线 worker**，
//! 因此新增本模块不改变任何现有下载行为（`worker.rs` / `manager.rs` 无改动）。
//!
//! 三条硬性边界：
//!
//! 1. 不支持随机读的协议必须回 [`ProviderError::SequentialOnly`]，**不得**假装支持分段
//!    （§5.2）；
//! 2. 服务器忽略 `Range`（`200`）时**不得**把整个响应写进分块位置，回
//!    [`ProviderError::RangeIgnored`]，由调度侧按 `degrade_single` 处理（§5.3）；
//! 3. `ETag` / `Last-Modified` 只属于「某个地址的某个版本」，[`VersionToken`] 是**单源**
//!    语义，不得跨源比较（§5.4）。

use std::io::Read;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use aidm_core::http_profile::RequestProfile;
use aidm_core::segment::parse_content_range;
use aidm_core::source::SourceCapabilities;

use crate::http_util::{apply_common, header_owned};

/// 供外部（含集成测试）构造 [`ProbeResult`] 用：`probe` 模块本身是 crate 私有，
/// 但类型是 `pub`，这里做一次公开再导出，不改动 `lib.rs`。
pub use crate::probe::ProbeResult;

/// 每个源允许的并发连接默认值（§5.6 的每源上限）。
const DEFAULT_CONNS_MAX: u16 = 4;

/// 源的身份：**不含凭据与查询串的稳定摘要**（§4.9「出处」、§8.2）。
///
/// HTTP 实现里用**原始候选地址**（不是跳转后的地址）作哈希输入，这样刷新重定向后
/// 身份不漂移；但派生结果只有 `u:<sha256 hex>`，原始 URL 只留在 [`HttpProvider`]
/// 的私有字段与 [`HttpProvider::url`] 访问器里。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderId(pub String);

impl ProviderId {
    /// 由候选地址派生身份：`u:<sha256(url) 的小写 hex>`。
    ///
    /// 哈希不可逆，所以 userinfo、签名参数、查询串都不会出现在 id 里。
    pub fn for_url(url: &str) -> Self {
        ProviderId(format!("u:{}", aidm_core::hash::sha256_hex(url.as_bytes())))
    }
}

/// 单源版本标识。取值形如 `etag:<值>` / `lm:<值>`，只在**同一个源**内可比。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VersionToken(pub String);

/// 一次读取请求（§5.1 通用解释器）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    pub source_id: ProviderId,
    pub offset: u64,
    pub len: u64,
    /// 调度侧记录的版本；与当前 token 都有值且不等 ⇒ [`ProviderError::VersionChanged`]。
    pub expected_version: Option<VersionToken>,
}

/// 一次读取的结果。`offset` 必须回填请求的偏移，由响应校验器再核一次（§4.9）。
#[derive(Debug, Clone)]
pub struct RangeChunk {
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// 源的健康度（§5.6：`Suspended` 不参与分配）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Observing,
    Suspended,
}

impl Health {
    fn as_u8(self) -> u8 {
        match self {
            Health::Healthy => 0,
            Health::Observing => 1,
            Health::Suspended => 2,
        }
    }

    fn from_u8(v: u8) -> Health {
        match v {
            1 => Health::Observing,
            2 => Health::Suspended,
            _ => Health::Healthy,
        }
    }
}

/// 读取/刷新失败的分类。**不**映射到 `TaskView.error_code`（那是闭集），
/// 只在引擎内部与事件 `detail` 里使用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// 该协议/实现根本不支持读取。
    Unsupported,
    /// 只能顺序读（§5.2 降级路径）。
    SequentialOnly,
    /// 服务器忽略了 `Range`：回了 `200`，或 `206` 但缺 `Content-Range`（§5.3）。
    RangeIgnored,
    /// `206` 但 `Content-Range` 起止与请求不符（§5.3）：该段失败，重探长度与版本。
    RangeMismatch {
        expected_start: u64,
        expected_end: u64,
        got_start: u64,
        got_end: u64,
    },
    /// `416`：请求区间越界；`total` 来自 `Content-Range: bytes */total`。
    RangeNotSatisfiable { total: Option<u64> },
    /// `401` / `403`：需要凭据或凭据失效。
    Auth { status: u16 },
    /// 其它非 2xx。
    Http { status: u16 },
    /// 连接/读取层面的失败（ureq 的 transport 错误）。字符串已过 `redact_text`（§8.2）。
    Network(String),
    /// 签名地址/临时地址过期。
    Expired,
    /// 单源版本变化（§5.4）。
    VersionChanged,
    /// 实际字节数与请求/`Content-Range` 不一致（§5.3）。
    ShortRead { expected: u64, got: u64 },
    /// `206` 带回非 `identity` 的 `Content-Encoding`（§5.3）：字节偏移不可信，拒绝。
    UnsupportedEncoding(String),
    /// 调用参数或配置不合法。
    Config(String),
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderError::Unsupported => write!(f, "unsupported"),
            ProviderError::SequentialOnly => write!(f, "sequential_only"),
            ProviderError::RangeIgnored => write!(f, "range_ignored"),
            ProviderError::RangeMismatch {
                expected_start,
                expected_end,
                got_start,
                got_end,
            } => write!(
                f,
                "range_mismatch expected={expected_start}-{expected_end} got={got_start}-{got_end}"
            ),
            ProviderError::RangeNotSatisfiable { total } => match total {
                Some(t) => write!(f, "range_not_satisfiable total={t}"),
                None => write!(f, "range_not_satisfiable"),
            },
            ProviderError::Auth { status } => write!(f, "auth status={status}"),
            ProviderError::Http { status } => write!(f, "http status={status}"),
            ProviderError::Network(d) => write!(f, "network {d}"),
            ProviderError::Expired => write!(f, "expired"),
            ProviderError::VersionChanged => write!(f, "version_changed"),
            ProviderError::ShortRead { expected, got } => {
                write!(f, "short_read expected={expected} got={got}")
            }
            ProviderError::UnsupportedEncoding(e) => write!(f, "unsupported_encoding {e}"),
            ProviderError::Config(d) => write!(f, "config {d}"),
        }
    }
}

impl std::error::Error for ProviderError {}

/// 调度器唯一认识的源接口（§4.9）。
pub trait SourceProvider: Send + Sync {
    fn id(&self) -> ProviderId;
    fn capabilities(&self) -> SourceCapabilities;
    fn read_range(&self, req: &ReadRequest) -> Result<RangeChunk, ProviderError>;
    /// 重新探测/重新解析地址，成功后更新能力与版本 token。
    fn refresh(&self) -> Result<(), ProviderError>;
    fn version_token(&self) -> Option<VersionToken>;
    fn health(&self) -> Health;
}

/// 内部可变状态：`refresh()` 要能被 `&self` 调用。
struct State {
    capabilities: SourceCapabilities,
    version: Option<VersionToken>,
    /// 探测得到的最终地址；没有探测过时等于构造时的 URL。
    final_url: String,
}

/// HTTP(S) 源实现：`Range` 读取 + 单源版本 + 探测刷新。
///
/// 请求头与探测共用 [`apply_common`]，保证「探测」与「真正读取」两跳的请求头一致。
pub struct HttpProvider {
    url: String,
    agent: ureq::Agent,
    profile: RequestProfile,
    referer: Option<String>,
    cookies: Option<String>,
    custom_headers: Vec<aidm_core::headers::HeaderLine>,
    state: Mutex<State>,
    health: AtomicU8,
}

impl HttpProvider {
    /// 直接用已知信息构造（未探测）：能力取保守缺省，版本未知。
    pub fn new(
        url: String,
        agent: ureq::Agent,
        profile: RequestProfile,
        referer: Option<String>,
        cookies: Option<String>,
        custom_headers: Vec<aidm_core::headers::HeaderLine>,
    ) -> Self {
        HttpProvider {
            state: Mutex::new(State {
                capabilities: SourceCapabilities::default(),
                version: None,
                final_url: url.clone(),
            }),
            url,
            agent,
            profile,
            referer,
            cookies,
            custom_headers,
            health: AtomicU8::new(Health::Healthy.as_u8()),
        }
    }

    /// 用一次探测结果构造：能力与版本都来自探测（§3.3「协议允许 ≠ 运行时可用」）。
    pub fn from_probe(
        url: String,
        probe: &ProbeResult,
        agent: ureq::Agent,
        profile: RequestProfile,
        referer: Option<String>,
        cookies: Option<String>,
        custom_headers: Vec<aidm_core::headers::HeaderLine>,
    ) -> Self {
        let capabilities = Self::capabilities_from_probe(probe);
        let version = version_from_probe(probe);
        let final_url = if probe.final_url.is_empty() {
            url.clone()
        } else {
            probe.final_url.clone()
        };
        HttpProvider {
            state: Mutex::new(State {
                capabilities,
                version,
                final_url,
            }),
            url,
            agent,
            profile,
            referer,
            cookies,
            custom_headers,
            health: AtomicU8::new(Health::Healthy.as_u8()),
        }
    }

    /// 探测结果 → 运行时能力（§3.3）。探测失败的能力项一律为 `false`。
    pub fn capabilities_from_probe(p: &ProbeResult) -> SourceCapabilities {
        SourceCapabilities {
            random_read: p.range_ok,
            resume: p.range_ok,
            length_query: p.total.is_some(),
            version_check: p.etag.is_some() || p.last_modified.is_some(),
            conns_max: DEFAULT_CONNS_MAX,
        }
    }

    /// 原始候选地址：**只给网络层用**，不得进日志/事件/`ProviderId`（§8.2）。
    pub fn url(&self) -> &str {
        &self.url
    }

    /// 设置健康度（供调度侧/结果处理器调用；默认 `Healthy`）。
    pub fn set_health(&self, health: Health) {
        self.health.store(health.as_u8(), Ordering::Relaxed);
    }

    /// 刷新失败后把能力与版本退回"未验证"（§3.3）：地址仍保留，供下次重试。
    fn mark_unverified(&self) {
        let mut st = self.lock_state();
        st.capabilities = SourceCapabilities::default();
        st.version = None;
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, State> {
        // 中毒只会发生在持有者 panic 时；状态是纯数据，取回继续用比 panic 更安全。
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl SourceProvider for HttpProvider {
    fn id(&self) -> ProviderId {
        // 身份只用摘要，原始 URL 不进 id/Debug/事件（§4.9、§8.2）。
        ProviderId::for_url(&self.url)
    }

    fn capabilities(&self) -> SourceCapabilities {
        self.lock_state().capabilities
    }

    fn read_range(&self, req: &ReadRequest) -> Result<RangeChunk, ProviderError> {
        if req.len == 0 {
            return Err(ProviderError::Config("len 必须大于 0".into()));
        }
        let end = req
            .offset
            .checked_add(req.len - 1)
            .ok_or_else(|| ProviderError::Config("Range 上界溢出".into()))?;

        // 先在本地挡掉已知的版本变化，避免把过期段读回来（§5.4）。
        let (url, current_version) = {
            let st = self.lock_state();
            (st.final_url.clone(), st.version.clone())
        };
        if let (Some(expected), Some(current)) = (&req.expected_version, &current_version) {
            if expected != current {
                return Err(ProviderError::VersionChanged);
            }
        }

        let range = format!("bytes={}-{}", req.offset, end);
        let mut request = apply_common(
            self.agent.get(&url),
            &self.profile,
            &url,
            self.referer.as_deref(),
            self.cookies.as_deref(),
            &self.custom_headers,
        )
        .set("Range", &range);
        // §5.2/§5.4：续传按期望版本加 `If-Range`。本地还没有 token 时也照发，
        // 让服务器决定（否则远端版本变化会被静默接受）；未知前缀不加条件头。
        if let Some(value) = req.expected_version.as_ref().and_then(if_range_value) {
            request = request.set("If-Range", value);
        }

        match request.call() {
            Ok(resp) => {
                let status = resp.status();
                if status == 206 {
                    // §5.3：非 identity 的 Content-Encoding 会让字节偏移错位，直接拒绝。
                    if let Some(enc) = header_owned(&resp, "content-encoding") {
                        let enc = enc.trim();
                        if !enc.eq_ignore_ascii_case("identity") {
                            drop(resp);
                            return Err(ProviderError::UnsupportedEncoding(enc.to_string()));
                        }
                    }
                    // 206 必须有合法 Content-Range，且起止与请求一致（§5.3）。
                    let parsed = header_owned(&resp, "content-range")
                        .as_deref()
                        .and_then(parse_content_range);
                    let Some(cr) = parsed else {
                        // §5.3：缺 Content-Range = 服务器未正确支持 Range → 降级单源顺序。
                        drop(resp);
                        return Err(ProviderError::RangeIgnored);
                    };
                    if cr.start != req.offset || cr.end != end {
                        drop(resp);
                        return Err(ProviderError::RangeMismatch {
                            expected_start: req.offset,
                            expected_end: end,
                            got_start: cr.start,
                            got_end: cr.end,
                        });
                    }
                    let body = read_body(resp, req.len)?;
                    return Ok(RangeChunk {
                        offset: req.offset,
                        bytes: body,
                    });
                }
                if status == 200 {
                    drop(resp);
                    // 带了版本条件（`expected_version` ⇒ `If-Range`）却回 200：
                    // 远端版本已变（§5.3/§5.4）；否则只是服务器忽略了 Range。
                    // 两种情况都**不能**把整个响应当这段数据。
                    return Err(if req.expected_version.is_some() {
                        ProviderError::VersionChanged
                    } else {
                        ProviderError::RangeIgnored
                    });
                }
                drop(resp);
                Err(ProviderError::Http { status })
            }
            Err(ureq::Error::Status(status, resp)) => {
                let total = if status == 416 {
                    header_owned(&resp, "content-range")
                        .as_deref()
                        .and_then(parse_unsatisfied_total)
                } else {
                    None
                };
                drop(resp);
                match status {
                    416 => Err(ProviderError::RangeNotSatisfiable { total }),
                    401 | 403 => Err(ProviderError::Auth { status }),
                    _ => Err(ProviderError::Http { status }),
                }
            }
            // ureq 的 `Transport` Display 会带完整请求 URL（含签名查询串）→ 必须脱敏。
            Err(ureq::Error::Transport(t)) => Err(net_err(t.to_string())),
        }
    }

    fn refresh(&self) -> Result<(), ProviderError> {
        let url = self.lock_state().final_url.clone();
        let probed = match crate::probe::probe(
            &self.agent,
            &url,
            &self.profile,
            self.referer.as_deref(),
            self.cookies.as_deref(),
            &self.custom_headers,
        ) {
            Ok(p) => p,
            Err(e) => {
                // §3.3：探测失败一律按"未验证"处理，不得残留旧的 `random_read=true`。
                self.mark_unverified();
                return Err(map_probe_error(&e));
            }
        };
        // `probe()` 把 401/407 当"挑战"返回 Ok，这里仍要按认证失败上报。
        if probed.status == 401 || probed.status == 403 {
            self.mark_unverified();
            return Err(ProviderError::Auth {
                status: probed.status,
            });
        }
        let mut st = self.lock_state();
        st.capabilities = Self::capabilities_from_probe(&probed);
        st.version = version_from_probe(&probed);
        if !probed.final_url.is_empty() {
            st.final_url = probed.final_url;
        }
        Ok(())
    }

    fn version_token(&self) -> Option<VersionToken> {
        self.lock_state().version.clone()
    }

    fn health(&self) -> Health {
        Health::from_u8(self.health.load(Ordering::Relaxed))
    }
}

/// 按 `len` 读 body，必须**正好** `len` 字节（§5.3「实际字节数 ≠ 请求长度」）。
///
/// 多读 1 字节用于区分「正好读完」与「响应比声明的长」。
fn read_body(resp: ureq::Response, len: u64) -> Result<Vec<u8>, ProviderError> {
    let cap = len.min(1024 * 1024) as usize;
    let mut buf = Vec::with_capacity(cap);
    // `into_reader` 取走响应；多读 1 字节用于识别「比声明的长」。
    let read = resp
        .into_reader()
        .take(len.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| net_err(format!("read: {e}")))?;
    let got = read as u64;
    if got != len {
        return Err(ProviderError::ShortRead { expected: len, got });
    }
    Ok(buf)
}

/// `Content-Range: bytes */1234`（`416` 的总长形态）。
fn parse_unsatisfied_total(header: &str) -> Option<u64> {
    let rest = header.trim();
    let rest = rest
        .strip_prefix("bytes")
        .or_else(|| rest.strip_prefix("BYTES"))?
        .trim();
    rest.strip_prefix("*/")?.trim().parse().ok()
}

/// 探测结果 → 单源版本 token。ETag 优先，其次 `Last-Modified`（§5.4）。
fn version_from_probe(p: &ProbeResult) -> Option<VersionToken> {
    if let Some(etag) = p.etag.as_deref().filter(|v| !v.is_empty()) {
        return Some(VersionToken(format!("etag:{etag}")));
    }
    p.last_modified
        .as_deref()
        .filter(|v| !v.is_empty())
        .map(|lm| VersionToken(format!("lm:{lm}")))
}

/// 网络层错误串必须过 `redact_text`（§4.9/§8.2）：ureq 的错误 Display 会带完整
/// 请求 URL（userinfo、签名查询串），不能原样进事件 `detail`。
fn net_err(msg: impl AsRef<str>) -> ProviderError {
    ProviderError::Network(aidm_core::redact::redact_text(msg.as_ref()).into_owned())
}

/// `expected_version` → `If-Range` 头值：`etag:<v>` / `lm:<v>` 取 `<v>`；
/// 其它前缀（平台版本等）不发条件头（§5.2/§5.4）。
fn if_range_value(token: &VersionToken) -> Option<&str> {
    let raw = token.0.as_str();
    raw.strip_prefix("etag:")
        .or_else(|| raw.strip_prefix("lm:"))
        .filter(|v| !v.is_empty())
}

/// `probe()` 的错误串 → 分类。`probe()` 的形态是 `http_<code>` / `connect: …` / 判定串。
fn map_probe_error(msg: &str) -> ProviderError {
    if let Some(rest) = msg.strip_prefix("http_") {
        let code = rest
            .split_whitespace()
            .next()
            .and_then(|c| c.parse::<u16>().ok());
        if let Some(code) = code {
            return match code {
                401 | 403 => ProviderError::Auth { status: code },
                416 => ProviderError::RangeNotSatisfiable { total: None },
                _ => ProviderError::Http { status: code },
            };
        }
    }
    if msg.starts_with("connect:") {
        return net_err(msg);
    }
    // 其余（如 `html_not_file`）是探测判定失败，归参数/配置类，供上层决定是否换源。
    ProviderError::Config(msg.to_string())
}
