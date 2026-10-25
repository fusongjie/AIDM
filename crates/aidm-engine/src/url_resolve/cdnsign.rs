//! 目标站点 CDN 直链（`qqdl.gtimg.cn`）的签名。
//!
//! ## 实测背景
//!
//! 未签名的 `https://qqdl.gtimg.cn/qqfile/...` 现在一律 403；必须先向官网的
//! `trpc.qqntv2.urlsign.UrlSign/GetSign` POST 一条 `{"url":"<原始地址>"}`，拿回
//! 带 `sign`/`t` 的临时地址（实测签名后 200/206，支持 Range）。`t` 是 Unix 秒，
//! 约 10 分钟后过期 —— 所以签名结果只适合"马上用"，不能长期缓存。
//!
//! ## 安全边界（重要）
//!
//! 这里**刻意不用** [`http_util::apply_common`](crate::http_util::apply_common)：
//! 那个 helper 会带上用户的 Cookie / Referer / 每任务自定义头，而签名接口只需要
//! 一个 URL。把用户的登录态送去一个不需要它的 RPC，既是最小权限问题，也会让
//! Cookie 有机会出现在对方的签名日志里。因此只发三个头：`Content-Type`、`x-oidb`
//! 和内置 UA；目标地址也**写死**成官网域名，不从输入地址推导。

use std::io::Read;
use std::time::Duration;

use aidm_core::setting_spec::DEFAULT_USER_AGENT;
use url::Url;

use super::{ResolvedUrl, UrlAdapter};

/// 签名接口所在源。既用于选择 Agent（走项目代理设置），也是请求目标的固定前缀。
const SIGN_ORIGIN: &str = "https://im.qq.com";
const SIGN_ENDPOINT: &str =
    "https://im.qq.com/http2rpc/gotrpc/noauth/trpc.qqntv2.urlsign.UrlSign/GetSign";

/// 正文上限。实测签名响应约 300 字节；64 KiB 足够吸收将来新增字段，
/// 又不会让异常大的响应（错误页、中间人页面）把下载主路径卡住。
const MAX_BODY: u64 = 64 * 1024;

/// 签名是"下载前的一小步"，不能像下载那样慢慢等；10 秒足够一次 RPC 往返。
const TIMEOUT: Duration = Duration::from_secs(10);

/// 服务端要求的 OIDB 路由头。去掉它会被判无效请求（实测必须原样带上）。
const OIDB: &str = r#"{"uint32_command":"0x9b8e","uint32_service_type":1}"#;

/// 注册表里的单例：适配器无状态，全局共享一份即可。
pub(super) static CDN_SIGN: CdnSign = CdnSign;

pub(super) struct CdnSign;

impl UrlAdapter for CdnSign {
    fn id(&self) -> &'static str {
        "cdn_sign"
    }

    fn matches(&self, u: &Url) -> bool {
        // 只认官网 CDN 上 `/qqfile/` 下的 HTTPS 直链：其它路径是官网页面/资源，
        // 不该被签名逻辑改写成"临时下载地址"。
        u.scheme() == "https"
            && u.host_str()
                .is_some_and(|h| h.eq_ignore_ascii_case("qqdl.gtimg.cn"))
            && u.path().starts_with("/qqfile/")
    }

    fn resolve(&self, http: &crate::http_util::HttpRuntime, u: &Url) -> Option<ResolvedUrl> {
        // 已签名就不要再签：重复签名会把 `t` 往后推，同一次任务里探测、分片、
        // 重试拿到的地址会不一致；而且白跑一次 RPC。
        if has_sign(u) {
            return None;
        }

        // 用 serde_json 构造请求体，保证 URL 里的引号/反斜杠被正确转义。
        let body = serde_json::json!({ "url": u.as_str() }).to_string();
        let resp = http
            .agent_for(SIGN_ORIGIN)
            .post(SIGN_ENDPOINT)
            .timeout(TIMEOUT)
            .set("Content-Type", "application/json")
            .set("x-oidb", OIDB)
            .set("User-Agent", DEFAULT_USER_AGENT)
            .send_string(&body)
            .ok()?;
        if !(200..300).contains(&resp.status()) {
            log::debug!("cdn_sign: 签名接口返回 {}", resp.status());
            return None;
        }

        // 先按上限读：签名响应很小，读超上限只可能是故障或错误页面。
        let mut raw = Vec::new();
        resp.into_reader()
            .take(MAX_BODY + 1)
            .read_to_end(&mut raw)
            .ok()?;
        if raw.len() as u64 > MAX_BODY {
            log::debug!("cdn_sign: 响应超过 {MAX_BODY} 字节，放弃");
            return None;
        }
        // 接口约定是 JSON，合法 UTF-8 是前提；非法字节按失败处理。
        let text = String::from_utf8(raw).ok()?;

        let (url, expires_at) = parse_sign_response(u.as_str(), &text)?;
        Some(ResolvedUrl {
            url,
            expires_at,
            via: self.id(),
        })
    }
}

/// URL 上是否已经带了**非空** `sign`。
///
/// 空值（`?sign=`）不算已签名：那种地址多半是手工拼出来的坏链接，仍需要换一次。
fn has_sign(u: &Url) -> bool {
    u.query_pairs()
        .any(|(k, v)| k == "sign" && !v.trim().is_empty())
}

/// 解析签名接口的响应体，并校验返回地址确实是**同目标的临时地址**。
///
/// 抽成纯函数是为了能脱离网络单测：响应形状、错误码、以及"签名后地址不能换
/// host/path/协议"这条安全约束都在这里，用字符串就能覆盖。
///
/// 返回 `(签名后地址, 过期时刻)`；过期时刻来自 query 的 `t`（解析不出就是 `None`）。
fn parse_sign_response(input_url: &str, body: &str) -> Option<(String, Option<i64>)> {
    let input = Url::parse(input_url.trim()).ok()?;
    let v: serde_json::Value = serde_json::from_str(body).ok()?;

    // `retcode` 必须存在且为 0；实测 `error.code` 同时存在，两处都要为 0 才算成功，
    // 避免只改一处错误码就骗过校验。
    if v.get("retcode").and_then(serde_json::Value::as_i64) != Some(0) {
        return None;
    }
    if let Some(code) = v
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(serde_json::Value::as_i64)
    {
        if code != 0 {
            return None;
        }
    }

    let signed_raw = v.get("data")?.get("url")?.as_str()?.trim();
    if signed_raw.is_empty() {
        return None;
    }
    let signed = Url::parse(signed_raw).ok()?;

    // 只接受"同一份文件的临时地址"：非 https、换 host、换 path 都说明这串东西
    // 不是我们要的下载链接（可能是错误页、跳转或伪造响应），宁可失败也不让
    // 下载器去追一个陌生地址。
    if signed.scheme() != "https" {
        return None;
    }
    if !input.host_str()?.eq_ignore_ascii_case(signed.host_str()?) {
        return None;
    }
    if input.path() != signed.path() {
        return None;
    }

    let mut expires_at = None;
    for (k, v) in signed.query_pairs() {
        if k == "t" {
            expires_at = v.parse::<i64>().ok();
            break;
        }
    }
    Some((signed.to_string(), expires_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 走一次真实签名（不计网络）：签名请求本身要 `HttpRuntime`，但本文件只测
    /// 纯函数与规则，绝不触网。运行时的构造用内存库，不落盘。
    fn runtime() -> std::sync::Arc<crate::http_util::HttpRuntime> {
        let conn = aidm_core::db::open_db(std::path::Path::new(":memory:")).unwrap();
        aidm_core::settings::ensure_defaults(&conn).unwrap();
        crate::http_util::HttpRuntime::from_db(&std::sync::Mutex::new(conn))
    }

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// 规则匹配：只有 `https://qqdl.gtimg.cn/qqfile/...` 归本适配器管。
    #[test]
    fn only_cdn_qqfile_https_is_matched() {
        let a = CdnSign;
        assert!(a.matches(&u(
            "https://qqdl.gtimg.cn/qqfile/QQNTV2/9.9.36/release/e8e54bbb/QQ_9.9.36_260924_x64_01.exe"
        )));
        // host 大小写不敏感（url 解析已规范化为小写，这里再做一次显式覆盖）。
        assert!(a.matches(&u("https://QQDL.GTIMG.CN/qqfile/x.exe")));

        // 域名不对 / 后缀伪装 / 路径不在 /qqfile/ 下 / 非 https：都不命中。
        for bad in [
            "https://dl.qq.com/qqfile/x.exe",
            "https://qqdl.gtimg.cn.evil.test/qqfile/x.exe",
            "https://qqdl.gtimg.cn/other/x.exe",
            "https://qqdl.gtimg.cn/qqfile",
            "http://qqdl.gtimg.cn/qqfile/x.exe",
        ] {
            assert!(!a.matches(&u(bad)), "不该命中: {bad}");
        }
    }

    /// 已经带签名（非空 `sign`）时不重复签名；空的 `sign=` 不算已签。
    #[test]
    fn signed_urls_are_not_signed_again() {
        assert!(has_sign(&u(
            "https://qqdl.gtimg.cn/qqfile/x.exe?sign=fff1&t=1792490749"
        )));
        assert!(!has_sign(&u("https://qqdl.gtimg.cn/qqfile/x.exe")));
        assert!(
            !has_sign(&u("https://qqdl.gtimg.cn/qqfile/x.exe?sign=&t=1")),
            "空 sign 是坏链接，仍需换一次"
        );

        // 走公开的解析入口：已签名地址必须在发请求之前就返回 None。
        let rt = runtime();
        assert!(
            CdnSign
                .resolve(
                    &rt,
                    &u("https://qqdl.gtimg.cn/qqfile/x.exe?sign=fff1&t=1792490749")
                )
                .is_none(),
            "已签名地址不该再发起签名请求"
        );
    }

    /// 正常响应：地址原样带签名返回，`t` 解析成过期时刻。
    #[test]
    fn parses_a_successful_sign_response() {
        let body = r#"{"error":{"code":0,"message":""},"cost":69,"data":{"url":"https://qqdl.gtimg.cn/qqfile/QQNTV2/9.9.36/release/e8e54bbb/QQ_9.9.36_260924_x64_01.exe?sign=fff1&t=1792490749"},"retcode":0,"message":""}"#;
        let input = "https://qqdl.gtimg.cn/qqfile/QQNTV2/9.9.36/release/e8e54bbb/QQ_9.9.36_260924_x64_01.exe";
        let (url, expires_at) = parse_sign_response(input, body).expect("正常响应要能解析");
        assert!(
            url.starts_with("https://qqdl.gtimg.cn/qqfile/QQNTV2/9.9.36/"),
            "{url}"
        );
        assert!(url.contains("sign=fff1"), "{url}");
        assert_eq!(expires_at, Some(1_792_490_749));

        // `t` 缺失/非数字：地址仍可用，只是过期时间未知。
        let no_t = body.replace("&t=1792490749", "");
        let (_, exp) = parse_sign_response(input, &no_t).expect("没有 t 也应当能拿到地址");
        assert_eq!(exp, None);
        let bad_t = body.replace("t=1792490749", "t=soon");
        let (_, exp) = parse_sign_response(input, &bad_t).expect("t 非数字不该让整条响应失败");
        assert_eq!(exp, None);
    }

    /// 各种"成功形状但内容不可信"的响应都必须拒绝。
    #[test]
    fn rejects_untrustworthy_sign_responses() {
        let input = "https://qqdl.gtimg.cn/qqfile/x.exe";
        let ok_url = "https://qqdl.gtimg.cn/qqfile/x.exe?sign=fff1&t=1792490749";
        let template =
            format!(r#"{{"retcode":0,"error":{{"code":0}},"data":{{"url":"{ok_url}"}}}}"#);

        // 基线：模板本身是能通过的（否则下面的用例测不到目标约束）。
        assert!(parse_sign_response(input, &template).is_some());

        // retcode 非 0。
        let bad_retcode = template.replace(r#""retcode":0"#, r#""retcode":1"#);
        assert_eq!(parse_sign_response(input, &bad_retcode), None);
        // error.code 非 0：即使 retcode 是 0 也不能信。
        let bad_error = template.replace(r#""code":0"#, r#""code":-1"#);
        assert_eq!(parse_sign_response(input, &bad_error), None);
        // data.url 缺失 / data 缺失 / url 为空串。
        assert_eq!(
            parse_sign_response(input, r#"{"retcode":0,"data":{}}"#),
            None
        );
        assert_eq!(parse_sign_response(input, r#"{"retcode":0}"#), None);
        assert_eq!(
            parse_sign_response(input, r#"{"retcode":0,"data":{"url":"   "}}"#),
            None
        );
        // 跨 host。
        let cross = template.replace(
            "https://qqdl.gtimg.cn/qqfile/x.exe",
            "https://evil.test/qqfile/x.exe",
        );
        assert_eq!(parse_sign_response(input, &cross), None, "跨 host 必须拒绝");
        // 非 https。
        let plain = template.replace(
            "https://qqdl.gtimg.cn/qqfile/x.exe",
            "http://qqdl.gtimg.cn/qqfile/x.exe",
        );
        assert_eq!(
            parse_sign_response(input, &plain),
            None,
            "非 https 必须拒绝"
        );
        // path 被改写。
        let other_path = template.replace("/qqfile/x.exe", "/qqfile/other.exe");
        assert_eq!(
            parse_sign_response(input, &other_path),
            None,
            "path 不一致必须拒绝"
        );
        // 输入地址本身非法。
        assert_eq!(parse_sign_response("not a url", &template), None);
    }

    /// 真实联网冒烟：默认不跑，手动验证"签名接口被 ureq 接受 + 签名地址可下载"。
    ///
    /// 运行方式：`cargo test -p aidm-engine --lib cdn_sign_live -- --ignored --nocapture`
    /// 需要公网；失败多半是网络/代理不可用，不代表代码路径有问题。
    #[test]
    #[ignore = "需要公网，手动运行以验证真实签名与下载链路"]
    fn cdn_sign_live() {
        let rt = runtime();
        let input = "https://qqdl.gtimg.cn/qqfile/QQNTV2/9.9.36/release/e8e54bbb/QQ_9.9.36_260924_x64_01.exe";
        let u = Url::parse(input).unwrap();
        let r = CdnSign.resolve(&rt, &u).expect("真实签名应成功");
        assert!(r.url.contains("sign="), "签名地址缺少 sign: {}", r.url);
        assert!(r.expires_at.is_some(), "签名地址缺少 t");

        // 用同一个 Agent 拉 1 字节：签名地址必须可下载（200/206）。
        let resp = rt
            .agent_for(&r.url)
            .get(&r.url)
            .set("Range", "bytes=0-0")
            .timeout(Duration::from_secs(20))
            .call()
            .expect("签名地址应可下载");
        let status = resp.status();
        assert!(status == 206 || status == 200, "status={status}");
    }

    /// 非法/空响应不得 panic（签名接口抖动时可能回空体或 HTML 错误页）。
    #[test]
    fn malformed_bodies_do_not_panic() {
        let input = "https://qqdl.gtimg.cn/qqfile/x.exe";
        for body in [
            "",
            " ",
            "{",
            "null",
            "[]",
            "\"text\"",
            "<html>502 Bad Gateway</html>",
            r#"{"retcode":"0","data":{"url":"https://qqdl.gtimg.cn/qqfile/x.exe?sign=a"}}"#,
        ] {
            assert_eq!(
                parse_sign_response(input, body),
                None,
                "不该接受非法响应: {body:?}"
            );
        }
    }
}
