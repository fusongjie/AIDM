//! 下载前地址解析/签名：把"需要临时签名才能下"的直链换成当下可用的地址。
//!
//! ## 为什么单独成模块，而不是写进 worker
//!
//! 部分站点（首例是 `qqdl.gtimg.cn`）不再对未签名地址回文件字节，而是要求
//! 先向官网的签名接口换一条带 `sign`/`t` 的临时地址，未签名的原始链接一律 403。
//! 这类"先换地址再下载"的规则每家都不一样，如果把判断与请求直接塞进 worker，
//! 下载主循环就会逐渐粘满各站点的私有协议与反爬细节。这里用**适配器注册表**把它
//! 隔离出来：worker 只需在探测/下载前调用一次 [`resolve`]，未命中就按原 URL 继续，
//! 新增站点 = 新写一个适配器 + 在注册表里加一行。
//!
//! ## 失败语义
//!
//! 命中规则但签名失败时**同样返回 `None`**，调用方保留原 URL —— 与"未命中"走同一
//! 出口。签名服务本身会抖，一次失败不该把整个任务判死；退回原地址后仍有既有的
//! 403/诊断路径可走。
//!
//! ## 安全边界
//!
//! 适配器只拿到 [`HttpRuntime`](crate::http_util::HttpRuntime) 的只读引用，由自己
//! 决定用哪个 Agent；签名/换链请求**不得**带上用户的 Cookie、Authorization、Referer
//! 或每任务自定义头（具体保证见各适配器文件头的说明）。

// worker 已接入 `resolve`（预解析 + 候选级解析 + 403 自愈）；`expires_at` 与
// 适配器扩展接口目前只被测试/日志使用，是为后续"长任务签名刷新"预留的，
// 故保留模块级 allow，而不是删掉字段或收紧可见性。
#![allow(dead_code)]

use url::Url;

mod cdnsign;

/// 一次成功解析的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedUrl {
    /// 可直接交给下载内核的地址（已带临时签名）。
    pub url: String,
    /// 临时地址的失效时刻（Unix 秒）；`None` 表示未知（响应里没有可用的过期信息）。
    pub expires_at: Option<i64>,
    /// 命中的适配器 id，如 `"cdn_sign"`。排障时用来回答"这条地址是谁换的"。
    pub via: &'static str,
}

/// 站点适配器：一条"什么样的地址、怎么换"的规则。
///
/// `Send + Sync` 是注册表放进 `static` 的前提（全局共享的适配器必须线程安全）；
/// 适配器本身应为无状态类型，配置不该藏在实例里 —— 需要设置时从调用参数传。
pub trait UrlAdapter: Send + Sync {
    /// 稳定 id；会出现在 [`ResolvedUrl::via`] 与日志里，不随文案调整。
    fn id(&self) -> &'static str;
    /// 是否归本适配器管。**只看地址形态，不发请求**（便于单测与快速排除）。
    fn matches(&self, u: &Url) -> bool;
    /// 换地址。失败返回 `None`（调用方保留原 URL）。
    fn resolve(&self, http: &crate::http_util::HttpRuntime, u: &Url) -> Option<ResolvedUrl>;
}

/// 注册表：按顺序匹配，首个"命中且解析成功"的适配器生效。
///
/// 用固定顺序的切片而不是 map：将来可能有多个站点共用域名，顺序本身就是语义。
fn adapters() -> &'static [&'static dyn UrlAdapter] {
    static ADAPTERS: &[&dyn UrlAdapter] = &[&cdnsign::CDN_SIGN];
    ADAPTERS
}

/// 命中注册规则则返回签名/解析后的地址；未命中或失败返回 `None`（调用方保留原 URL）。
pub fn resolve(http: &crate::http_util::HttpRuntime, url: &str) -> Option<ResolvedUrl> {
    // 只处理绝对 URL：相对地址与非 http(s) 根本不在适配器管辖内，
    // 解析失败直接放过，不打断调用方的正常流程。
    let u = Url::parse(url.trim()).ok()?;
    for a in adapters() {
        if !a.matches(&u) {
            continue;
        }
        match a.resolve(http, &u) {
            Some(r) => {
                // 刻意不打印地址本体：解析结果里带着临时签名/令牌。
                log::debug!("url_resolve: {} 生效（过期 {:?}）", a.id(), r.expires_at);
                return Some(r);
            }
            None => log::debug!("url_resolve: {} 命中但解析失败，保留原地址", a.id()),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// 注册表的顺序与命中面：签名直链归 `cdn_sign`，普通 HTTPS 地址谁都不接手。
    #[test]
    fn registry_routes_signed_links_to_the_cdn_adapter_only() {
        let hit = adapters()
            .iter()
            .find(|a| a.matches(&u("https://qqdl.gtimg.cn/qqfile/QQNTV2/x.exe")))
            .map(|a| a.id());
        assert_eq!(hit, Some("cdn_sign"), "签名直链应当唯一命中签名适配器");

        for other in [
            "https://example.com/qqfile/x.exe",
            "https://qqdl.gtimg.cn/other/x.exe",
            "http://qqdl.gtimg.cn/qqfile/x.exe",
        ] {
            assert!(
                adapters().iter().all(|a| !a.matches(&u(other))),
                "不该被任何适配器命中: {other}"
            );
        }
    }
}
