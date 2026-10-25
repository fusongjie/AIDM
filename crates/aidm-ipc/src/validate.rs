//! 扩展 / 引擎共享的 URL 与字段上限（开发文档 §6）。

use crate::{
    OfferItem, LIMIT_COOKIES, LIMIT_FILENAME, LIMIT_OFFER_ITEMS, LIMIT_REFERRER, LIMIT_URL,
};

/// 校验失败时的稳定错误码（宿主 `code` / 引擎 `error`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldError {
    BadUrl,
    TooLong,
    /// 备用地址列表里有一条不合法（不是 HTTP(S) 绝对地址、含控制字符或超长）。
    BadAltUrl,
}

impl FieldError {
    pub fn as_str(self) -> &'static str {
        match self {
            FieldError::BadUrl => "bad_url",
            FieldError::TooLong => "too_long",
            FieldError::BadAltUrl => "bad_alt_url",
        }
    }
}

pub fn validate_url(url: &str) -> Result<(), FieldError> {
    if url.len() > LIMIT_URL {
        return Err(FieldError::TooLong);
    }
    if url.chars().any(|c| c.is_control()) {
        return Err(FieldError::BadUrl);
    }
    if !scheme_allowed(url) {
        return Err(FieldError::BadUrl);
    }
    Ok(())
}

pub fn scheme_allowed(url: &str) -> bool {
    let u = url.trim();
    // eD2k 链接没有 host；权威解析在 aidm-core::ed2k，这里只做形状闸门
    // （aidm-ipc 是协议契约层，不反向依赖 aidm-core）
    if is_ed2k_link(u) {
        return is_ed2k_file_url(u);
    }
    if is_magnet_url(u) {
        return true;
    }
    // 封装链接由引擎解码后再校验
    if is_wrapped_scheme(u) {
        return true;
    }
    // S3 兼容对象存储：形状是 `s3://bucket/key`，**桶与键都不可省**。
    // 它没有 host（端点由 region/设置决定），所以不能走下面的 host 那条路。
    if is_s3_url(u) {
        return true;
    }
    // 开发工具坐标：`npm:` / `pnpm:` / `cargo:` / `crates:` / `pip:`。
    //
    // 这些**不是 URL**，而是包坐标；引擎在执行期把它们换算成 registry 直链
    //（npm/cargo 在建任务时就换完，pip 要查一次接口所以留到执行期）。
    // 形状闸门只判"有前缀且有包名"，具体语法归 `aidm_core::devtools`。
    if is_devtool_spec(u) {
        return true;
    }
    for scheme in ["http://", "https://", "ftp://", "ftps://"] {
        if let Some(rest) = strip_prefix_ci(u, scheme) {
            return !rest.is_empty()
                && !rest.starts_with('/')
                && !rest.starts_with('?')
                && !rest.starts_with('#');
        }
    }
    false
}

/// S3 对象地址（`s3://` 或明文自建端点的 `s3+http://`）的形状闸门。
///
/// 只判"有桶、有键"这一层：region/端点的**解析**归 `aidm_engine::s3`，
/// 那里还要跟设置里的凭证一起看，不是契约层能决定的。
pub fn is_s3_url(url: &str) -> bool {
    let u = url.trim();
    let Some(rest) = strip_prefix_ci(u, "s3+http://").or_else(|| strip_prefix_ci(u, "s3://"))
    else {
        return false;
    };
    // 查询串/片段不参与形状判断（键里可以合法含 `?`，但那种情况要显式编码）。
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    match rest.split_once('/') {
        Some((bucket, key)) => !bucket.trim().is_empty() && !key.trim().is_empty(),
        None => false,
    }
}

/// 开发工具坐标（`npm:lodash@4.17.21`、`pip:requests==2.31.0`）的形状闸门。
///
/// **必须是已知前缀**，这是刻意的：`user@host`（SCP 风格）与 `lodash@4.17.21`
/// 形状相同，若允许"没前缀就当 npm"，前者会被静默拼成一条 npm registry 地址。
/// 具体语法（版本分隔符、scope 包、范围说明符）归 `aidm_core::devtools`。
pub fn is_devtool_spec(spec: &str) -> bool {
    let u = spec.trim();
    let Some((prefix, body)) = u.split_once(':') else {
        return false;
    };
    matches!(
        prefix.trim().to_ascii_lowercase().as_str(),
        "npm" | "pnpm" | "cargo" | "crates" | "pip"
    ) && !body.trim().is_empty()
}

/// Magnet 只在本层校验 BTIH 形状；tracker、参数解码与元数据校验交给 BT 引擎。
pub fn is_magnet_url(url: &str) -> bool {
    let Some(query) = strip_prefix_ci(url.trim(), "magnet:?") else {
        return false;
    };
    query.split('&').any(|item| {
        let Some((key, value)) = item.split_once('=') else {
            return false;
        };
        if !key.eq_ignore_ascii_case("xt") {
            return false;
        }
        let Some(hash) = strip_prefix_ci(value, "urn:btih:") else {
            return false;
        };
        (hash.len() == 40 && hash.chars().all(|c| c.is_ascii_hexdigit()))
            || (hash.len() == 32
                && hash.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        && !matches!(c.to_ascii_uppercase(), '0' | '1' | '8' | '9')
                }))
    })
}

/// HTTP(S) 种子元数据 URL。查询串不参与后缀判断。
pub fn is_torrent_url(url: &str) -> bool {
    let u = url.trim();
    let Some(rest) = strip_prefix_ci(u, "http://").or_else(|| strip_prefix_ci(u, "https://"))
    else {
        return false;
    };
    rest.split(['?', '#'])
        .next()
        .is_some_and(|path| path.to_ascii_lowercase().ends_with(".torrent"))
}

pub fn is_bittorrent_url(url: &str) -> bool {
    is_magnet_url(url) || is_torrent_url(url)
}

/// 是否 `ed2k://` 链接（大小写不敏感）。
pub fn is_ed2k_link(url: &str) -> bool {
    strip_prefix_ci(url.trim(), "ed2k://").is_some()
}

/// eD2k **文件**链接的形状检查：`ed2k://|file|<名>|<字节>|<32 位十六进制哈希>|…`
///
/// 只要形状对就放行——真正解析（含 sources/AICH/其它类型）由引擎用
/// `aidm_core::ed2k::parse_link` 做，避免两处实现漂移。
pub fn is_ed2k_file_url(url: &str) -> bool {
    let Some(rest) = strip_prefix_ci(url.trim(), "ed2k://") else {
        return false;
    };
    let t: Vec<&str> = rest.split('|').collect();
    t.len() >= 5
        && t[1].eq_ignore_ascii_case("file")
        && !t[2].trim().is_empty()
        && t[3].trim().parse::<u64>().is_ok()
        && is_hex32(t[4].trim())
}

/// 封装协议前缀（专用链、早期专用链、裸地址、带标记地址、网盘资源标识）。
pub fn is_wrapped_scheme(url: &str) -> bool {
    let u = url.trim();
    [
        "thunder://",
        "thunders://",
        "qqdl://",
        "flashget://",
        "fs2you://",
    ]
    .iter()
    .any(|p| strip_prefix_ci(u, p).is_some())
}

fn is_hex32(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// §6 宿主白名单含 ftp；引擎尚未实现 FTP 传输，`add` 回 [`crate::ERR_UNSUPPORTED_SCHEME`]。
pub fn is_ftp_url(url: &str) -> bool {
    strip_prefix_ci(url.trim(), "ftp://").is_some()
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() {
        return None;
    }
    if s.get(..prefix.len())?.eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

pub fn validate_referrer(referrer: Option<&str>) -> Result<(), FieldError> {
    match referrer {
        Some(r) if r.len() > LIMIT_REFERRER => Err(FieldError::TooLong),
        _ => Ok(()),
    }
}

pub fn validate_cookies(cookies: Option<&str>) -> Result<(), FieldError> {
    match cookies {
        Some(c) if c.len() > LIMIT_COOKIES => Err(FieldError::TooLong),
        Some(c) if c.chars().any(|ch| ch == '\0' || ch == '\n' || ch == '\r') => {
            Err(FieldError::TooLong)
        }
        _ => Ok(()),
    }
}

pub fn validate_filename(filename: Option<&str>) -> Result<(), FieldError> {
    match filename {
        Some(f) if f.chars().count() > LIMIT_FILENAME => Err(FieldError::TooLong),
        _ => Ok(()),
    }
}

/// `rename {filename}`：非空、≤ [`LIMIT_FILENAME`]、不含 `/` `\\` 或 `..`。
pub fn is_valid_rename_filename(filename: &str) -> bool {
    !filename.is_empty()
        && !filename.trim().is_empty()
        && filename.chars().count() <= LIMIT_FILENAME
        && !filename.contains('/')
        && !filename.contains('\\')
        && !filename.contains("..")
}

/// 截断 offer 条目到 [`LIMIT_OFFER_ITEMS`]；超限返回 `truncated=true`。
pub fn truncate_offer_items(mut items: Vec<OfferItem>) -> (Vec<OfferItem>, bool) {
    if items.len() > LIMIT_OFFER_ITEMS {
        items.truncate(LIMIT_OFFER_ITEMS);
        (items, true)
    } else {
        (items, false)
    }
}

pub fn validate_add_fields(
    url: &str,
    referrer: Option<&str>,
    filename: Option<&str>,
    cookies: Option<&str>,
) -> Result<(), FieldError> {
    validate_url(url)?;
    validate_referrer(referrer)?;
    validate_filename(filename)?;
    validate_cookies(cookies)?;
    Ok(())
}

/// 备用地址条数上限（与 `aidm_core::alt::ALT_MAX` 同值；契约层不依赖 core）。
pub const LIMIT_ALT_URLS: usize = 8;

/// 备用地址（镜像）列表：按空白分隔的 HTTP(S) 绝对地址，每行一个。
///
/// 与主地址的差别：备用地址**只认 HTTP(S)**。FTP 的备用地址需要另一套登录/续传
/// 语义，eD2k/BT 走各自的源发现，把它们的链接塞进这里只会得到一个永远失败的候选。
/// 与主地址相同的条目不算错误（去重在引擎侧做），但形状非法就整体拒绝——
/// 静默丢掉一条用户明确填写的地址，比报错更难排查。
pub fn validate_alt_urls(alt: Option<&str>) -> Result<(), FieldError> {
    let Some(raw) = alt else {
        return Ok(());
    };
    let mut count = 0usize;
    for line in raw.lines() {
        // 整行注释：`#` 后面可以跟空格与说明文字（按空白切分会把说明文字当成地址）。
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for item in line.split_whitespace() {
            count += 1;
            if count > LIMIT_ALT_URLS {
                return Err(FieldError::BadAltUrl);
            }
            if item.len() > LIMIT_URL || item.chars().any(|c| c.is_control()) {
                return Err(FieldError::BadAltUrl);
            }
            let rest =
                strip_prefix_ci(item, "https://").or_else(|| strip_prefix_ci(item, "http://"));
            match rest {
                Some(rest)
                    if !rest.is_empty()
                        && !rest.starts_with('/')
                        && !rest.starts_with('?')
                        && !rest.starts_with('#') => {}
                _ => return Err(FieldError::BadAltUrl),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_objects_pass_but_need_both_bucket_and_key() {
        // 形状：`s3://bucket/key`。桶与键都不可省 —— 少了任何一个都不是对象地址。
        assert!(validate_url("s3://bucket/key.bin").is_ok());
        assert!(
            validate_url("S3://BUCKET/dir/key.bin").is_ok(),
            "scheme 大小写不敏感"
        );
        // 自建端点的明文写法（受信内网里的 MinIO）。
        assert!(validate_url("s3+http://bucket/key.bin").is_ok());

        assert!(is_s3_url("s3://b/k"));
        assert!(!is_s3_url("s3://b"), "缺键");
        assert!(!is_s3_url("s3://b/"), "缺键");
        assert!(!is_s3_url("s3:///k"), "缺桶");
        assert!(
            !is_s3_url("https://bucket.s3.amazonaws.com/k"),
            "那是 HTTP，不是 s3://"
        );
        assert_eq!(validate_url("s3://bucket/"), Err(FieldError::BadUrl));
        assert_eq!(validate_url("s3://bucket"), Err(FieldError::BadUrl));

        // 键里的点/斜杠/百分号都是**普通字符**，不参与形状判断。
        assert!(is_s3_url("s3://b/a/b/c.tar.gz"));
        assert!(is_s3_url("s3://b/a%20b.bin"));
        // 键里带查询串（显式编码那种）也不该被判成缺键。
        assert!(is_s3_url("s3://b/k.bin?versionId=abc"));
    }

    #[test]
    fn scheme_http_https_ftp_and_bittorrent() {
        assert!(validate_url("https://x/a").is_ok());
        assert!(validate_url("http://x/a").is_ok());
        assert!(validate_url("ftp://x/a").is_ok());
        assert!(is_ftp_url("ftp://x/a"));
        assert!(is_ftp_url("FTP://x/a"));
        assert!(!is_ftp_url("https://x/a"));
        let magnet = "magnet:?xt=urn:btih:0123456789012345678901234567890123456789";
        assert!(validate_url(magnet).is_ok());
        assert!(is_magnet_url(magnet));
        assert!(is_magnet_url(
            "MAGNET:?dn=x&xt=URN:BTIH:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        ));
        assert!(!is_magnet_url("magnet:?dn=missing-info-hash"));
        assert!(is_torrent_url("https://x/path/file.TORRENT?token=x"));
        assert!(!is_torrent_url("https://x/path/file.bin"));
        assert_eq!(validate_url("file:///tmp/a"), Err(FieldError::BadUrl));
        // eD2k：文件链接放行，其它类型与坏哈希拒绝
        let file = "ed2k://|file|a.bin|1024|965c013e991ee246d63d45ea71954c4d|/";
        assert!(validate_url(file).is_ok(), "eD2k 文件链接应放行");
        assert!(validate_url("ED2K://|file|a.bin|1024|965C013E991EE246D63D45EA71954C4D|/").is_ok());
        assert_eq!(
            validate_url("ed2k://|server|1.2.3.4|4242|/"),
            Err(FieldError::BadUrl),
            "服务器链接不是下载任务"
        );
        assert_eq!(
            validate_url("ed2k://|file|a.bin|1024|zzzz|/"),
            Err(FieldError::BadUrl)
        );
        // 私有封装协议：形状放行，交给引擎解码
        assert!(validate_url("thunder://QUFodHRwOi8veC9hLmJpblpa").is_ok());
        assert!(validate_url("thunders://QUFodHRwOi8veC9hLmJpblpa").is_ok());
        assert!(validate_url("qqdl://aHR0cDovL3gvYS5iaW4=").is_ok());
        assert!(is_ed2k_link(
            "ed2k://|file|x|1|965c013e991ee246d63d45ea71954c4d|/"
        ));
        assert!(!is_ed2k_link("http://x/a"));
        assert!(is_wrapped_scheme("FlashGet://xx"));
        assert!(!is_wrapped_scheme("https://x"));
        assert_eq!(validate_url("javascript:alert(1)"), Err(FieldError::BadUrl));
        assert_eq!(validate_url("https://"), Err(FieldError::BadUrl));
    }

    #[test]
    fn url_length_and_controls() {
        let long = format!("https://x/{}", "a".repeat(LIMIT_URL));
        assert_eq!(validate_url(&long), Err(FieldError::TooLong));
        assert_eq!(validate_url("https://x/\u{0001}"), Err(FieldError::BadUrl));
    }

    #[test]
    fn optional_field_limits() {
        let r = "r".repeat(LIMIT_REFERRER + 1);
        assert_eq!(validate_referrer(Some(&r)), Err(FieldError::TooLong));
        let c = "c".repeat(LIMIT_COOKIES + 1);
        assert_eq!(validate_cookies(Some(&c)), Err(FieldError::TooLong));
        let f = "n".repeat(LIMIT_FILENAME + 1);
        assert_eq!(validate_filename(Some(&f)), Err(FieldError::TooLong));
        assert!(validate_filename(Some(&"n".repeat(LIMIT_FILENAME))).is_ok());
    }

    #[test]
    fn rename_filename_rejects_empty_long_and_path() {
        assert!(!is_valid_rename_filename(""));
        assert!(!is_valid_rename_filename("   "));
        assert!(!is_valid_rename_filename(&"n".repeat(LIMIT_FILENAME + 1)));
        assert!(is_valid_rename_filename(&"n".repeat(LIMIT_FILENAME)));
        assert!(!is_valid_rename_filename("a/b.bin"));
        assert!(!is_valid_rename_filename("a\\b.bin"));
        assert!(!is_valid_rename_filename(".."));
        assert!(!is_valid_rename_filename("foo..bar"));
        assert!(is_valid_rename_filename("ok.bin"));
        assert!(is_valid_rename_filename("中文.bin"));
    }
}
