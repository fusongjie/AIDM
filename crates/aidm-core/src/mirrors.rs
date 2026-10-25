//! 已知镜像族：同一路径命名空间下若干互为镜像的站点（L3 静态表）。
//!
//! 用途：主地址坏掉时，把「同一路径换 host」的候选补进候选序列，让下载能自动换到
//! 别的镜像站，而不必用户手工去查。
//!
//! 三条边界，改动前请先读：
//!
//! 1. **表里每一项都必须实测验证过。** 验证方法见 [`tests`] 与
//!    `docs/alternate-urls.md` §7：逐条 `curl -r 0-0` 并**带上错误信息**。
//!    并发批量取数在这件事上不可信 —— 实测同一批地址并发跑会整行缺失，
//!    据此建表会漏掉可用镜像（曾漏掉 `mirrors.zju.edu.cn` 与
//!    `mirrors.sjtug.sjtu.edu.cn`）。
//! 2. **只在已知命名空间下派生**，所以不会把任意下载悄悄发往陌生主机；
//!    不在表里的路径一律不派生。
//! 3. **派生必须是纯函数 + 编译期常量**：`alt_cursor` 落库的是下标，
//!    候选序列跨运行必须一模一样，否则 cursor 会指向另一个地址。
//!    网络发现出来的镜像列表做不到这一点（那是另一条路线，需要任务级落库）。
//!
//! 命中率本身是不稳定的：同一个路径在有些镜像上是 404，有些镜像还会时好时坏。
//! 所以这里只是"**多几个候选**"，正确性仍然靠探测与长度/哈希对账把关。

/// 每个命名空间最多派生几个候选。
///
/// 定成 8（覆盖整张表）而不是 4，是实测教训：AlmaLinux 那条真实坏链上，
/// 表里前 4 家里有 **3 家在这套 UA 下不可用**（nju 系列重定向循环、sjtug 回反爬 HTML 页），
/// 只剩 huaweicloud 一根独苗 —— 一旦它也抽风，任务就彻底没源。而排在后面的
/// tencent / zju / repo.almalinux.org 经代理实测都是 206。
///
/// 代价：失败路径上每个候选还会再派生"另一协议 / 302 目标"两次尝试，8 个候选约 24 次
/// 探测请求（都是 `Range: 0-0` 的小请求）。真实坏链在第 5 个候选上就成功了，
/// 所以这个上限只在"整条链都坏"时才会走满。
pub const MIRROR_MAX: usize = 8;

/// `(路径前缀, 该命名空间下**实测**可用的镜像 host)`。
///
/// 顺序即尝试顺序：靠前的更容易给满速。原始地址自身由调用方排除。
pub const FAMILIES: &[(&str, &[&str])] = &[(
    "/almalinux/",
    &[
        "mirrors.nju.edu.cn",
        "mirror.nju.edu.cn",
        "mirrors.sjtug.sjtu.edu.cn",
        "mirrors.huaweicloud.com",
        "mirrors.cloud.tencent.com",
        "mirrors.zju.edu.cn",
        "repo.almalinux.org",
    ],
)];

/// 从主地址派生镜像候选：同一路径换 host，保留 scheme、路径、查询串与片段。
///
/// 与主地址同 host 的条目会被跳过；最多返回 [`MIRROR_MAX`] 条。
/// 路径不在任何已知命名空间下时返回空 Vec。
pub fn derive(primary: &str) -> Vec<String> {
    let Some((scheme, authority, rest)) = split_url(primary.trim()) else {
        return Vec::new();
    };
    let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let path = &rest[..path_end];
    let tail = &rest[path_end..];
    let Some((_, hosts)) = FAMILIES.iter().find(|(prefix, _)| path.starts_with(prefix)) else {
        return Vec::new();
    };
    // 原始 authority 可能带端口；派生地址一律用 scheme 默认端口，不继承端口。
    let origin_host = authority_host(authority);
    let mut out: Vec<String> = Vec::new();
    for host in hosts.iter() {
        if host.eq_ignore_ascii_case(origin_host) {
            continue;
        }
        let url = format!("{scheme}://{host}{path}{tail}");
        if !out.iter().any(|u| u.eq_ignore_ascii_case(&url)) {
            out.push(url);
        }
        if out.len() == MIRROR_MAX {
            break;
        }
    }
    out
}

/// 拆成 `(scheme, authority, 其余)`；只认 HTTP(S)。
fn split_url(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return None;
    }
    Some((scheme, authority, &rest[end..]))
}

/// 去掉 userinfo 与端口，留下主机名（IPv6 字面量保留方括号内的内容）。
fn authority_host(authority: &str) -> &str {
    let after_userinfo = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    if let Some(inner) = after_userinfo.strip_prefix('[') {
        return inner.split_once(']').map(|(h, _)| h).unwrap_or(inner);
    }
    match after_userinfo.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => after_userinfo,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 实测用例：这条主地址会 302 到一个不可达主机（本次调查的起点）。
    const ALIYUN: &str =
        "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-dvd.iso";

    #[test]
    fn derives_same_path_mirrors_and_excludes_the_origin() {
        let got = derive(ALIYUN);
        // 不变量：派生**原 host 之外的整张表**，且不超过上限。
        // （目前表比上限短，所以上限不生效；表长大之后这条会开始约束。）
        assert_eq!(
            got.len(),
            FAMILIES[0].1.len(),
            "应当派生整张表（原 host 不在表里）: {got:?}"
        );
        assert!(got.len() <= MIRROR_MAX, "不能超过上限: {got:?}");
        for u in &got {
            assert!(u.starts_with("https://"), "{u}");
            assert!(
                u.ends_with("/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-dvd.iso"),
                "路径必须原样保留: {u}"
            );
            assert!(
                !u.contains("mirrors.aliyun.com"),
                "不能把原 host 再派生一遍: {u}"
            );
        }
        // 表头顺序即尝试顺序
        assert_eq!(
            got[0],
            "https://mirrors.nju.edu.cn/almalinux/9/isos/x86_64/AlmaLinux-9-latest-x86_64-dvd.iso"
        );
    }

    #[test]
    fn keeps_scheme_and_tail_but_drops_the_port() {
        let u = "http://mirrors.aliyun.com:8080/almalinux/9/x.iso?a=1#frag";
        let got = derive(u);
        assert!(!got.is_empty());
        for one in &got {
            assert!(one.starts_with("http://"), "scheme 要保留: {one}");
            assert!(!one.contains(":8080"), "派生地址不该继承端口: {one}");
            assert!(
                one.ends_with("/almalinux/9/x.iso?a=1#frag"),
                "查询串要保留: {one}"
            );
        }
    }

    #[test]
    fn ignores_unknown_namespaces_and_non_http() {
        assert!(derive("https://example.com/whatever/a.iso").is_empty());
        // 前缀必须从路径开头匹配，不能是路径中间的子串
        assert!(derive("https://example.com/pub/almalinux/a.iso").is_empty());
        assert!(derive("ftp://mirrors.aliyun.com/almalinux/a.iso").is_empty());
        assert!(derive("ed2k://|file|a|1|b|/").is_empty());
        assert!(derive("").is_empty());
        assert!(derive("https://").is_empty());
    }

    #[test]
    fn skips_the_origin_when_it_is_itself_in_the_table() {
        let u = "https://mirrors.nju.edu.cn/almalinux/9/x.iso";
        let got = derive(u);
        assert!(!got.is_empty());
        assert!(
            !got.iter().any(|x| x.contains("mirrors.nju.edu.cn")),
            "{got:?}"
        );
        // 表里还有 mirror.nju.edu.cn（不同 host）应当被派生出来
        assert!(got[0].contains("mirror.nju.edu.cn"), "{got:?}");
    }

    #[test]
    fn derivation_is_deterministic_because_alt_cursor_depends_on_it() {
        // `alt_cursor` 落库的是下标：同样的输入必须每次得到同样的序列，
        // 否则换镜像后 cursor 会指向另一个地址。
        assert_eq!(derive(ALIYUN), derive(ALIYUN));
        assert_eq!(derive(ALIYUN), derive(ALIYUN));
    }
}
