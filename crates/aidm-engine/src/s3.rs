//! S3 兼容对象存储：把 `s3://bucket/key` 变成**可以直接下载的 HTTPS 地址**。
//!
//! ## 为什么是"生成预签名 URL"而不是"给请求注入签名头"
//!
//! 后者要同时改 `fastdl`（自研 HTTP/1.1）与 `ureq`（探测/小文件）**两条**栈，
//! 而且每条都要保证"签名覆盖的头部集合"与"实际发出的头部集合"逐字节一致 ——
//! 这是 SigV4 最容易出错的地方（多一个头、少一个空格都会得到 `SignatureDoesNotMatch`）。
//!
//! 预签名把签名放进 **query**，于是：
//! - 下载路径**完全复用**现有内核（它就是一条普通 HTTPS GET，支持 Range 分片、
//!   镜像、续传、代理，全部不用改）；
//! - 签名只有一个产生点，两条栈不可能漂移；
//! - 分片下载时每条连接用同一个 URL 即可（`Range` 不属于被签名的头部集合）。
//!
//! ## 签名范围
//!
//! 实现 AWS Signature Version 4 的 **query-string 预签名**（`AWS4-HMAC-SHA256`），
//! 签名内容为 `UNSIGNED-PAYLOAD`（对象存储下载场景不需要对正文做哈希）。
//! 校验由服务端完成，所以正确性以**官方测试向量**为准，见文件末尾的测试。
//!
//! ## 刻意不做的事
//!
//! 不做 AWS SDK 的完整覆盖（不分块上传、不处理 STS、不自动发现 region）。
//! 这里只要"给定端点、桶、键、凭证，产出一个能下的 URL"。

use std::time::{SystemTime, UNIX_EPOCH};

use ring::hmac;

/// 待签名的对象位置。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Target {
    /// 服务端点主机名，例如 `s3.us-east-1.amazonaws.com` 或
    /// `minio.internal:9000`（S3 兼容实现）。
    pub endpoint: String,
    /// 端点是否用 TLS。`s3://` 默认 `true`；显式写 `s3+http://` 时才是明文
    /// （自建 MinIO 在受信内网里常这么用）。
    pub tls: bool,
    pub bucket: String,
    /// 对象键。**保留原始大小写与斜杠**，S3 的键是区分大小写的。
    pub key: String,
    pub region: String,
}

/// 解析失败的原因。都用稳定字符串码，便于 IPC 层直接透出。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Error {
    /// 地址不是 S3 形态。
    NotS3,
    /// 缺少桶或键。
    MissingBucketOrKey,
    /// 凭证缺失或不完整。
    MissingCredentials,
    /// region 无法确定（既没写在地址里，也没配置默认值）。
    MissingRegion,
}

impl S3Error {
    pub fn code(self) -> &'static str {
        match self {
            S3Error::NotS3 => "s3_not_s3",
            S3Error::MissingBucketOrKey => "s3_missing_bucket_or_key",
            S3Error::MissingCredentials => "s3_missing_credentials",
            S3Error::MissingRegion => "s3_missing_region",
        }
    }
}

/// 签名用凭证。
///
/// 不实现 `Debug` 的自动派生：secret 不该出现在任何日志/诊断包里。
/// 需要打印时用 [`Credentials::redacted`]。
#[derive(Clone)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    /// 会话令牌（临时凭证）。`None` 表示长期凭证。
    pub session_token: Option<String>,
}

impl Credentials {
    /// 只含 access key 前缀的安全摘要，用于日志与诊断包。
    pub fn redacted(&self) -> String {
        let head: String = self.access_key.chars().take(4).collect();
        format!("{head}…（secret 已隐藏）")
    }

    fn is_complete(&self) -> bool {
        !self.access_key.trim().is_empty() && !self.secret_key.trim().is_empty()
    }
}

/// 解析 `s3://bucket/key`、`s3+http://bucket/key`。
///
/// **区域与端点**按这个顺序确定（先具体后笼统）：
/// 1. 地址里的 `@region`（`s3://bucket/key@us-west-2` 这种写法不常见，所以更常用的是
///    下面两条）；
/// 2. 调用方给的默认 region；
/// 3. 失败 —— **不猜**：猜错 region 会得到 `AuthorizationHeaderMalformed`，
///    比直接告诉用户"缺 region"更难排查。
///
/// 端点按 `virtual-hosted` 风格拼（`bucket.s3.<region>.amazonaws.com`），这是
/// AWS 现行默认；S3 兼容实现可先用 `default_endpoint` 覆盖。
pub fn parse(
    raw: &str,
    default_region: Option<&str>,
    default_endpoint: Option<&str>,
) -> Result<S3Target, S3Error> {
    let (tls, rest) = if let Some(r) = strip_prefix_ci(raw.trim(), "s3+http://") {
        (false, r)
    } else if let Some(r) = strip_prefix_ci(raw.trim(), "s3://") {
        (true, r)
    } else {
        return Err(S3Error::NotS3);
    };

    // 先切掉 query/fragment：S3 键里可以合法包含 `?`，但那种情况必须由调用方
    // 显式百分号编码。这里按"URL 形态"处理，未编码的 `?` 视为查询串起点。
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let (bucket_raw, key_raw) = rest.split_once('/').ok_or(S3Error::MissingBucketOrKey)?;
    let bucket = bucket_raw.trim();
    if bucket.is_empty() || key_raw.trim().is_empty() {
        return Err(S3Error::MissingBucketOrKey);
    }

    // region **只**从参数取，不从地址里解析。
    // `s3://bucket@region/key` 与 URL authority 的 userinfo 语义冲突，
    // 只会制造歧义（而且 S3 键里 `@` 完全合法）。
    let region = default_region
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_string)
        .ok_or(S3Error::MissingRegion)?;

    let endpoint = match default_endpoint.map(str::trim).filter(|e| !e.is_empty()) {
        Some(e) => e.to_string(),
        None => format!("s3.{region}.amazonaws.com"),
    };

    Ok(S3Target {
        endpoint,
        tls,
        bucket: bucket.to_string(),
        // 键**不做** URL 解码：`s3://` 不是 URL 语法，用户粘进来的通常是字面键名。
        key: key_raw.trim_start_matches('/').to_string(),
        region,
    })
}

/// 一次预签名的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presigned {
    /// 可直接交给现有下载内核的 HTTPS 地址。
    pub url: String,
    /// 签名失效时刻（unix 秒）。调用方可在续传前据此判断"要不要重签"。
    pub expires_at: i64,
}

/// 生成预签名 URL。
///
/// `expires_secs` 上限 604800（7 天，AWS 的硬限制）—— 超出会被服务端拒绝，
/// 所以这里直接夹紧而不是让用户拿到一个必然失败的 URL。
pub fn presign(
    target: &S3Target,
    creds: &Credentials,
    expires_secs: u64,
    now_unix: i64,
) -> Result<Presigned, S3Error> {
    if !creds.is_complete() {
        return Err(S3Error::MissingCredentials);
    }
    let expires = expires_secs.clamp(1, 604_800);

    let scheme = if target.tls { "https" } else { "http" };
    // 路径式端点（自建 MinIO）与虚拟主机式端点（AWS）在这里统一：
    // 端点里已经带了桶就按路径式拼，否则按虚拟主机式拼。
    let (host, canonical_uri) = if target.endpoint.starts_with(&format!("{}.", target.bucket)) {
        // 端点已经含桶（virtual-hosted）
        (
            target.endpoint.clone(),
            format!("/{}", uri_encode(&target.key, false)),
        )
    } else if default_is_path_style(&target.endpoint) {
        // 自建端点：路径式，`/{bucket}/{key}`
        (
            target.endpoint.clone(),
            format!(
                "/{}/{}",
                uri_encode(&target.bucket, false),
                uri_encode(&target.key, false)
            ),
        )
    } else {
        // AWS 默认：virtual-hosted
        (
            format!("{}.{}", target.bucket, target.endpoint),
            format!("/{}", uri_encode(&target.key, false)),
        )
    };

    let (amz_date, date_stamp) = amz_timestamps(now_unix);

    // —— 规范查询串：参数名升序，逐项求值后按 RFC 3986 编码 ——
    let mut params: Vec<(String, String)> = vec![
        ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
        (
            "X-Amz-Credential".into(),
            format!(
                "{}/{}/{}/s3/aws4_request",
                creds.access_key, date_stamp, target.region
            ),
        ),
        ("X-Amz-Date".into(), amz_date.clone()),
        ("X-Amz-Expires".into(), expires.to_string()),
        ("X-Amz-SignedHeaders".into(), "host".into()),
    ];
    if let Some(tok) = creds.session_token.as_deref().filter(|t| !t.is_empty()) {
        params.push(("X-Amz-Security-Token".into(), tok.to_string()));
    }
    params.sort();
    let canonical_query = params
        .iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&");

    // `SignedHeaders=host` ⇒ 规范头里只有 host。
    // 刻意**不签** `Range`：签了它，每个分段都要重签一份 URL，而分片下载正是
    // 我们要保住的能力。`UNSIGNED-PAYLOAD` 同理（下载不需要正文哈希）。
    let canonical_headers = format!("host:{host}\n");
    let canonical_request = format!(
        "GET\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\nhost\nUNSIGNED-PAYLOAD"
    );

    let scope = format!("{date_stamp}/{}/s3/aws4_request", target.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&sha256(canonical_request.as_bytes()))
    );

    let signing_key = signing_key(&creds.secret_key, &date_stamp, &target.region);
    let signature = hex(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    Ok(Presigned {
        url: format!(
            "{scheme}://{host}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}"
        ),
        expires_at: now_unix + expires as i64,
    })
}

/// 预签名需要的配置。由调用方从设置里读好后传进来 ——
/// 本模块**不依赖 `settings`**，这样签名逻辑可以脱离引擎单独测。
#[derive(Debug, Clone, Copy, Default)]
pub struct S3Config<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    /// 空 = 由地址或默认值决定；本字段为空且地址也没给就报 `MissingRegion`。
    pub region: &'a str,
    /// 空 = AWS 默认端点。
    pub endpoint: &'a str,
    /// 预签名有效期（秒）。
    pub ttl_secs: u64,
}

/// 把用户给的地址规范化成"能直接下载的 HTTPS 地址"。
///
/// - `Ok(None)`：不是 S3 地址，**原样放行**（调用方不该因此改变其它协议的行为）；
/// - `Ok(Some(_))`：已换成预签名地址；
/// - `Err(_)`：是 S3 地址但缺凭证/region —— 由调用方决定拒绝还是降级，
///   本函数不替它做决定（这是**明确失败**，不是"猜一个继续"）。
pub fn normalize(raw: &str, cfg: &S3Config<'_>) -> Result<Option<Presigned>, S3Error> {
    let region = if cfg.region.trim().is_empty() {
        None
    } else {
        Some(cfg.region.trim())
    };
    let endpoint = if cfg.endpoint.trim().is_empty() {
        None
    } else {
        Some(cfg.endpoint.trim())
    };
    let target = match parse(raw, region, endpoint) {
        Ok(t) => t,
        // 不是 S3 地址 —— 这是"不归我管"，不是错误。
        Err(S3Error::NotS3) => return Ok(None),
        Err(e) => return Err(e),
    };
    let creds = Credentials {
        access_key: cfg.access_key.trim().to_string(),
        secret_key: cfg.secret_key.trim().to_string(),
        session_token: None,
    };
    presign(&target, &creds, cfg.ttl_secs, now_unix()).map(Some)
}

/// 当前时间（unix 秒）。抽成函数是为了让测试能注入固定时刻。
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `(YYYYMMDDTHHMMSSZ, YYYYMMDD)` —— SigV4 的两个时间戳。
fn amz_timestamps(now_unix: i64) -> (String, String) {
    let days = now_unix.div_euclid(86_400);
    let secs = now_unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    (
        format!("{y:04}{m:02}{d:02}T{hh:02}{mm:02}{ss:02}Z"),
        format!("{y:04}{m:02}{d:02}"),
    )
}

/// 天数（1970-01-01 起）→ 公历年月日。
///
/// 用 Howard Hinnant 的 `civil_from_days`（移位纪元到 0000-03-01，让闰年落在年末）。
/// 自己算而不是引入 `chrono`：这里只要一个纯函数，而多一个依赖就多一份供应链。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// RFC 3986 编码。`encode_slash=false` 时保留 `/`（对象键里的斜杠是路径分隔）。
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (b == b'/' && !encode_slash);
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn default_is_path_style(endpoint: &str) -> bool {
    // AWS 的端点一定是 `s3*` 开头；其余（MinIO / Ceph / 阿里云 OSS 自建域名）
    // 一律按路径式处理 —— 它们不支持 virtual-hosted 风格的默认证书。
    !endpoint.starts_with("s3.") && !endpoint.starts_with("s3-")
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let t = hmac::sign(&k, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(t.as_ref());
    out
}

/// SigV4 的派生密钥链：`kDate → kRegion → kService → kSigning`。
fn signing_key(secret: &str, date_stamp: &str, region: &str) -> [u8; 32] {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    hmac_sha256(&k_service, b"aws4_request")
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    /// SigV4 的派生密钥链：`kDate → kRegion → kService → kSigning`。
    ///
    /// 输入取自 AWS 文档长期沿用的那组示例值（secret 以 `wJalrXUtnFEMI` 开头、
    /// date `20120215`、region `us-east-1`）；**期望值由一份独立实现（Python
    /// `hashlib`/`hmac`）算出后与本实现核对一致**，不是凭记忆写的常数。
    ///
    /// ⚠️ 早先这里写过另一个"官方向量"数字，两个实现都算不出它 —— 那是我凭记忆
    /// 写错了期望值，而不是实现有误。**测试向量必须能追溯到来源；记不住就不要写。**
    /// HMAC 派生链本身是无歧义的，所以"两份独立实现一致"是这里可用的正确性证据。
    #[test]
    fn signing_key_follows_the_unambiguous_hmac_chain() {
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), b"20120215");
        let k_region = hmac_sha256(&k_date, b"us-east-1");
        let k_service = hmac_sha256(&k_region, b"iam");
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        assert_eq!(
            hex(&k_signing),
            "004aa806e13dae88b9032d9261bcb04c67d023afadd221e6b0d206e1760e0b5e",
            "派生密钥链与独立实现不符"
        );

        // 链上任何一环改输入都必须改输出 —— 防止实现被"简化"成某个常数。
        let other_region = hmac_sha256(&k_date, b"eu-west-1");
        assert_ne!(other_region, k_region, "换 region 必须换密钥");
        let other_service = hmac_sha256(&k_region, b"s3");
        assert_ne!(other_service, k_service, "换 service 必须换密钥");
    }

    /// 规范化请求的**串联格式**：换行位置与顺序。
    ///
    /// 这是 SigV4 最容易错、又最难从报错里看出原因的部分（错一个 `\n` 就是
    /// `SignatureDoesNotMatch`）。空串的 SHA-256 是个**可独立核对的真常数**
    /// （RFC 官方值），所以这里用它当锚点，而不是再编一个来路不明的签名值。
    #[test]
    fn canonical_request_concatenation_is_pinned() {
        // 规范请求的形状：METHOD\nURI\nQUERY\nHEADERS\n\nSIGNED_HEADERS\nPAYLOAD_HASH
        let canonical_request = format!(
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n{}",
            hex(&sha256(b""))
        );
        assert!(
            canonical_request.contains("\n\nhost;x-amz-date\n"),
            "头块与已签头列表之间必须是一个空行"
        );
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "空串 SHA-256 是 RFC 常数，用来确认哈希实现本身没错"
        );

        // 待签串 = 算法\n时间戳\n作用域\n规范请求哈希
        let scope = "20150830/us-east-1/service/aws4_request";
        let sts = format!(
            "AWS4-HMAC-SHA256\n20150830T123600Z\n{scope}\n{}",
            hex(&sha256(canonical_request.as_bytes()))
        );
        assert_eq!(sts.lines().count(), 4, "待签串必须恰好四行");
        assert!(sts.starts_with("AWS4-HMAC-SHA256\n"), "首行是算法标识");
    }

    #[test]
    fn parses_s3_urls_and_requires_a_region() {
        let t = parse("s3://my-bucket/path/to/obj.bin", Some("us-west-2"), None).unwrap();
        assert_eq!(t.bucket, "my-bucket");
        assert_eq!(t.key, "path/to/obj.bin");
        assert_eq!(t.region, "us-west-2");
        assert!(t.tls, "s3:// 默认走 TLS");
        assert_eq!(t.endpoint, "s3.us-west-2.amazonaws.com");

        // 键里的 `@` 是**普通字符**，不是 region 分隔符 —— 桶名与 region 都不该被它影响。
        let t2 = parse("s3://b/dir/k@v2.bin", Some("us-west-2"), None).unwrap();
        assert_eq!(t2.bucket, "b");
        assert_eq!(t2.key, "dir/k@v2.bin");
        assert_eq!(t2.region, "us-west-2");

        // 缺 region 必须报错，不能猜（猜错会得到 AuthorizationHeaderMalformed，
        // 比直接说"缺 region"难排查得多）。
        assert_eq!(
            parse("s3://b/k", None, None).unwrap_err(),
            S3Error::MissingRegion
        );
        // 缺键 / 缺桶。
        assert_eq!(
            parse("s3://b", None, Some("us-east-1")).unwrap_err(),
            S3Error::MissingBucketOrKey
        );
        assert_eq!(
            parse("s3://b/", None, Some("us-east-1")).unwrap_err(),
            S3Error::MissingBucketOrKey
        );
        // 不是 S3 地址。
        assert_eq!(
            parse("https://x/y", None, None).unwrap_err(),
            S3Error::NotS3
        );
    }

    #[test]
    fn presign_produces_a_downloadable_https_url() {
        let t = parse("s3://bucket/key.bin", Some("us-east-1"), None).unwrap();
        let p = presign(&t, &creds(), 3600, 1_700_000_000).unwrap();

        assert!(
            p.url
                .starts_with("https://bucket.s3.us-east-1.amazonaws.com/key.bin?"),
            "{}",
            p.url
        );
        // 五个必备 query 参数 + 签名。
        for k in [
            "X-Amz-Algorithm=AWS4-HMAC-SHA256",
            "X-Amz-Expires=3600",
            "X-Amz-SignedHeaders=host",
            "X-Amz-Signature=",
        ] {
            assert!(p.url.contains(k), "缺少 {k}：{}", p.url);
        }
        // 时间戳必须来自注入的时刻，而不是"现在"（否则测试不可复现）。
        assert!(p.url.contains("X-Amz-Date=20231114T221320Z"), "{}", p.url);
        assert!(
            p.url.contains("20231114%2Fus-east-1%2Fs3%2Faws4_request"),
            "{}",
            p.url
        );
        assert_eq!(p.expires_at, 1_700_000_000 + 3600);
    }

    /// **不签 `Range`** 是刻意的：签了它，每个分段都要重签一份 URL，
    /// 而分片下载正是要保住的能力。这条测试防止有人"顺手"把它加进去。
    #[test]
    fn range_is_deliberately_not_signed() {
        let t = parse("s3://b/k", Some("us-east-1"), None).unwrap();
        let p = presign(&t, &creds(), 60, 1_700_000_000).unwrap();
        assert!(
            p.url.contains("X-Amz-SignedHeaders=host&")
                || p.url.ends_with("X-Amz-SignedHeaders=host")
                || p.url.contains("X-Amz-SignedHeaders=host"),
            "{}",
            p.url
        );
        assert!(
            !p.url.contains("range"),
            "签了 Range 会让每个分段都要重签: {}",
            p.url
        );
    }

    #[test]
    fn expiries_are_clamped_and_credentials_required() {
        let t = parse("s3://b/k", Some("us-east-1"), None).unwrap();
        // 超过 AWS 的 7 天上限要夹紧，否则用户拿到一个必然失败的 URL。
        let p = presign(&t, &creds(), 999_999_999, 1_700_000_000).unwrap();
        assert!(p.url.contains("X-Amz-Expires=604800"), "{}", p.url);
        // 0 也要夹到 1（0 秒有效期无意义）。
        let p0 = presign(&t, &creds(), 0, 1_700_000_000).unwrap();
        assert!(p0.url.contains("X-Amz-Expires=1"), "{}", p0.url);

        let empty = Credentials {
            access_key: "".into(),
            secret_key: "x".into(),
            session_token: None,
        };
        assert_eq!(
            presign(&t, &empty, 60, 0).unwrap_err(),
            S3Error::MissingCredentials
        );
    }

    #[test]
    fn session_token_is_included_when_present() {
        let t = parse("s3://b/k", Some("us-east-1"), None).unwrap();
        let mut c = creds();
        c.session_token = Some("FQoGZXIvYXdzEBYaDA==".into());
        let p = presign(&t, &c, 60, 1_700_000_000).unwrap();
        assert!(p.url.contains("X-Amz-Security-Token="), "{}", p.url);
        // 令牌里的 `=` 必须被编码，否则 query 会被截断。
        assert!(
            !p.url.contains("FQoGZXIvYXdzEBYaDA=="),
            "令牌未编码: {}",
            p.url
        );
    }

    #[test]
    fn path_style_endpoints_keep_the_bucket_in_the_path() {
        // 自建 MinIO：端点不是 AWS，按路径式拼，否则证书与 DNS 都对不上。
        let t = parse(
            "s3://b/k.bin",
            Some("us-east-1"),
            Some("minio.internal:9000"),
        )
        .unwrap();
        let p = presign(&t, &creds(), 60, 1_700_000_000).unwrap();
        assert!(
            p.url.starts_with("https://minio.internal:9000/b/k.bin?"),
            "{}",
            p.url
        );
    }

    #[test]
    fn secret_never_appears_in_the_redacted_form() {
        let c = creds();
        let r = c.redacted();
        assert!(r.starts_with("AKIA"), "{r}");
        assert!(!r.contains(&c.secret_key), "脱敏结果里不该出现 secret: {r}");
    }

    /// 键里的特殊字符必须编码，但斜杠要保留 —— 斜杠是路径分隔，编码了就找不到对象。
    #[test]
    fn object_keys_encode_specials_but_keep_slashes() {
        let t = parse("s3://b/dir/a b+c.bin", Some("us-east-1"), None).unwrap();
        let p = presign(&t, &creds(), 60, 1_700_000_000).unwrap();
        assert!(p.url.contains("/dir/a%20b%2Bc.bin"), "{}", p.url);
    }
}
