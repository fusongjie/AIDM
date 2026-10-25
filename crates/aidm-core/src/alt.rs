//! 备用地址（镜像）：主地址失败时按序接管。
//!
//! 一个任务可以挂多个候选 URL，主地址不可用时换下一个。
//!
//! 候选序列 = `[主地址] + 备用地址`，`downloads.alt_cursor` 记录当前生效者的序号。
//! 边界（同见 `docs/alternate-urls.md`）：
//!
//! - 只在**同一份文件的镜像**之间切换，所以换镜像时必须与已落库的大小一致；
//!   长度对不上就跳过该候选并留痕，而不是把两个不同文件的字节拼在一个文件里。
//! - 换到别的镜像后，原镜像的 `ETag` / `Last-Modified` 不再适用，因此不再做
//!   校验器比对（那是"同一地址上的远端被换掉"的判定）；已下好的分段保留，
//!   它们是内容，不依赖校验器。
//! - 备用地址只对 HTTP(S) 有意义：FTP 有自己的登录/续传语义，eD2k/BT 走源发现，
//!   都不参与这条链路。

/// 备用地址条数上限。按任务挂一串镜像，
/// 上限取 8：再多也只是把同一批镜像重复一遍，反而拖慢故障判定。
pub const ALT_MAX: usize = 8;

/// 单条 URL 长度上限（与 `aidm_ipc::LIMIT_URL` 同量级；core 不依赖 ipc）。
pub const ALT_URL_MAX: usize = 8 * 1024;

/// 拆分并净化用户给的备用地址文本：一行一个（一行里多写几个也行），
/// 整行以 `#` 开头当注释；剔除空串、与主地址相同的项、超长项与非 HTTP(S) 项，
/// 去重后截到 [`ALT_MAX`]。
pub fn parse(raw: &str, primary: &str) -> Vec<String> {
    let primary = primary.trim();
    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for item in line.split_whitespace() {
            if !is_http_url(item) || item.len() > ALT_URL_MAX || same_url(item, primary) {
                continue;
            }
            if out.iter().any(|u| same_url(u, item)) {
                continue;
            }
            out.push(item.to_string());
            if out.len() == ALT_MAX {
                return out;
            }
        }
    }
    out
}

/// 候选序列（主地址在前）。`alt_urls` 是落库的原文（可能多行）。
pub fn candidates(primary: &str, alt_urls: Option<&str>) -> Vec<String> {
    let primary = primary.trim();
    let mut out = vec![primary.to_string()];
    if let Some(raw) = alt_urls {
        for alt in parse(raw, primary) {
            if !out.iter().any(|u| same_url(u, &alt)) {
                out.push(alt);
            }
        }
    }
    out
}

/// 候选序列（主地址 + 用户备用地址 + **自动镜像**）。
///
/// `auto_mirrors` 为 false 时与 [`candidates`] 逐字一致（因此调用方可以按设置开关）。
///
/// 自动镜像放在**最后**：用户显式填的地址优先，而且它们占用的是稳定下标 ——
/// 派生表是编译期常量、派生是纯函数，所以跨运行序列一致，`alt_cursor` 才有意义。
/// 与主地址或用户备用地址重复的派生项会被去掉。
pub fn candidates_with_mirrors(
    primary: &str,
    alt_urls: Option<&str>,
    auto_mirrors: bool,
) -> Vec<String> {
    let mut out = candidates(primary, alt_urls);
    if !auto_mirrors {
        return out;
    }
    for m in crate::mirrors::derive(primary) {
        if !out.iter().any(|u| same_url(u, &m)) {
            out.push(m);
        }
    }
    out
}

/// 把备用地址序列化成落库文本（每行一个）。
pub fn encode(list: &[String]) -> String {
    list.join("\n")
}

/// 从 `from` 开始、按顺序绕一圈的候选序号。`from` 越界等价于 0。
///
/// 绕圈是为了"当前生效的镜像坏了"时还能回头用主地址——但它只决定**尝试顺序**，
/// 切换本身仍要过 [`size_compatible`] 这一关。
pub fn try_order(len: usize, from: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }
    let from = from % len;
    (0..len).map(|i| (from + i) % len).collect()
}

/// 换镜像时的大小对账：记录里已有大小就必须与探测到的大小一致。
///
/// 记录为空（新任务）时不做约束——此时还没有可比对的基准；但只要磁盘上已经有
/// 这个任务的字节（分段表非空），`size_total` 必然已由首轮探测写入。
pub fn size_compatible(recorded: Option<i64>, probed: Option<u64>) -> bool {
    match recorded {
        None => true,
        Some(old) if old <= 0 => true,
        Some(old) => probed == Some(old as u64),
    }
}

/// 是否为可用的 HTTP(S) 绝对地址（备用地址只认这两种）。
pub fn is_http_url(url: &str) -> bool {
    let lower = url.trim().to_ascii_lowercase();
    let Some(rest) = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
    else {
        return false;
    };
    !rest.is_empty() && !rest.starts_with('/')
}

/// 从粘贴文本里抽出第一个 HTTP(S) 绝对地址。
///
/// 实测成因：从镜像站/下载页**整行**复制时会带上页面注释，形如
/// `…/AlmaLinux-9-latest-x86_64-dvd.iso  ✅  (stable "latest" name)`。
/// 只做 `trim()` 会把整串当 URL 发出去 → 必然 404。此函数只取地址本身。
///
/// 整串本来就是一个地址时原样返回，不改变既有行为；否则从第一个 `http(s)://`
/// 起取到下一个空白，再剥掉紧跟在后面的标点（兼容 Markdown 链接与中文句读）。
pub fn extract_http_url(raw: &str) -> Option<String> {
    let start = find_scheme(raw)?;
    let rest = &raw[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let candidate = trim_trailing_junk(&rest[..end]);
    is_http_url(candidate).then(|| candidate.to_string())
}

/// 第一个 `http://` / `https://` 的字节位置（大小写不敏感）。
///
/// 用 `to_ascii_lowercase` 做检索：它只改 ASCII 大写字母，非 ASCII 字节长度不变，
/// 因此小写串上的下标在原文里同样成立。
fn find_scheme(s: &str) -> Option<usize> {
    let lower = s.to_ascii_lowercase();
    match (lower.find("https://"), lower.find("http://")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// 同一地址的另一协议形态（`https://` ↔ `http://`）；非 HTTP(S) 返回 None。
///
/// 实测用处：镜像的 https 可能因证书链不可信而失败（`SEC_E_UNTRUSTED_ROOT`），
/// 换 http 却能正常 206。这不是网络抖动，只能靠试另一协议发现。
/// 由于明文传输不可信，调用方**只在已有内容哈希可比对时**才应采用 http 结果。
pub fn scheme_swap(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if let Some(rest) = strip_prefix_ci(trimmed, "https://") {
        return (!rest.is_empty()).then(|| format!("http://{rest}"));
    }
    if let Some(rest) = strip_prefix_ci(trimmed, "http://") {
        return (!rest.is_empty()).then(|| format!("https://{rest}"));
    }
    None
}

/// 剥掉紧跟在地址后面的成对/句读标点（`…a.iso)`、`…a.iso，` 之类）。
/// 只剥结尾，且只剥一份；不碰路径内部的字符。
fn trim_trailing_junk(token: &str) -> &str {
    const JUNK: &[char] = &[
        ',', ';', ':', '!', '?', ')', ']', '}', '>', '"', '\'', '，', '。', '；', '：', '！', '？',
        '）', '》', '」', '』',
    ];
    token.trim_end_matches(JUNK)
}

pub(crate) fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

/// 去重用的同一性判定：scheme/host 大小写不敏感（RFC 3986），其余逐字符比较。
pub fn same_url(a: &str, b: &str) -> bool {
    match (split_authority(a), split_authority(b)) {
        (Some((sa, ha, ta)), Some((sb, hb, tb))) => {
            sa.eq_ignore_ascii_case(sb) && ha.eq_ignore_ascii_case(hb) && ta == tb
        }
        _ => a == b,
    }
}

fn split_authority(url: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = url.trim().split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some((scheme, &rest[..end], &rest[end..]))
}

/// 地址的主机名：小写、不含端口、不含 userinfo；没有主机时返回 `None`。
///
/// 用于「同一台机器只试一次」的熔断。**必须按主机（而不是 `scheme://host:port`）
/// 归并**：实测 `mirrors.aliyun.com` 会把 ISO 302 到 `iso-osm.mirrors.aliyuncs.com`，
/// 而那台机器 http 与 https 各自要耗满 5 秒才失败 —— 只有按主机归并，
/// 才能把这两个协议变体一起挡掉，而不是为同一台死机器各等一次超时。
pub fn host_of(url: &str) -> Option<String> {
    let (_, authority, _) = split_authority(url)?;
    let after_userinfo = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // IPv6 字面量形如 `[::1]:8080`：主机部分是方括号整体，不能按 `:` 切。
    let host = if after_userinfo.starts_with('[') {
        &after_userinfo[..=after_userinfo.find(']')?]
    } else {
        after_userinfo.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_splits_cleans_and_bounds() {
        let raw = "\
            # 镜像\n\
            https://mirror.test/a.iso\n\
            HTTPS://Mirror.test/a.iso\n\
            \n\
            http://b.test/a.iso?x=1\n\
            ftp://c.test/a.iso\n\
            not-a-url\n";
        assert_eq!(
            parse(raw, "https://origin.test/a.iso"),
            // 第二条与第一条只有 scheme/host 大小写不同 → 视为同一条；
            // `http://` 与 `https://` 是两条不同地址，不去重。
            list(&["https://mirror.test/a.iso", "http://b.test/a.iso?x=1"])
        );
    }

    #[test]
    fn parse_drops_the_primary_and_caps_the_list() {
        let primary = "https://origin.test/a.iso";
        let mut raw = String::from("https://origin.test/a.iso\n");
        for i in 0..12 {
            raw.push_str(&format!("https://m{i}.test/a.iso\n"));
        }
        let alts = parse(&raw, primary);
        assert_eq!(alts.len(), ALT_MAX);
        assert_eq!(alts[0], "https://m0.test/a.iso");
    }

    #[test]
    fn candidates_keep_the_primary_first() {
        let c = candidates("https://origin.test/a", Some("https://m.test/a"));
        assert_eq!(c, list(&["https://origin.test/a", "https://m.test/a"]));
        // 没有备用地址时就是单元素序列（原有行为不变）。
        assert_eq!(candidates("https://o/a", None), list(&["https://o/a"]));
        assert_eq!(
            candidates("https://o/a", Some("   ")),
            list(&["https://o/a"])
        );
    }

    #[test]
    fn try_order_wraps_and_tolerates_stale_cursor() {
        assert_eq!(try_order(3, 0), vec![0, 1, 2]);
        assert_eq!(try_order(3, 2), vec![2, 0, 1]);
        // 落库的序号超出当前候选数（用户删掉了备用地址）时按 0 处理。
        assert_eq!(try_order(2, 7), vec![1, 0]);
        assert!(try_order(0, 3).is_empty());
    }

    #[test]
    fn size_check_requires_equality_once_a_size_is_known() {
        assert!(size_compatible(None, Some(10)));
        assert!(size_compatible(Some(0), None));
        assert!(size_compatible(Some(10), Some(10)));
        assert!(!size_compatible(Some(10), Some(11)));
        // 记录里有大小但镜像没报长度 → 不能证明是同一份文件，拒绝。
        assert!(!size_compatible(Some(10), None));
    }

    #[test]
    fn http_only_and_authority_identity() {
        assert!(is_http_url("https://a/b"));
        assert!(!is_http_url("https://"));
        assert!(!is_http_url("ftp://a/b"));
        assert!(!is_http_url("ed2k://|file|a|1|b|/"));
        // 路径大小写不同是两条地址；scheme/host 不同大小写是同一条。
        assert!(same_url("HTTPS://A.test/x", "https://a.test/x"));
        assert!(!same_url("https://a.test/x", "https://a.test/X"));
    }

    #[test]
    fn encode_is_line_separated() {
        let l = list(&["https://a/1", "https://b/2"]);
        assert_eq!(encode(&l), "https://a/1\nhttps://b/2");
        assert_eq!(
            candidates("https://a/1", Some(&encode(&l)))[1],
            "https://b/2"
        );
    }

    /// 真实成因用例：把镜像页整行（含 ✅ 与 `(stable "latest" name)` 注释）
    /// 粘进「下载链接」框。整串发出去会 404，必须抽出地址本身。
    #[test]
    fn extract_drops_page_annotation_from_pasted_line() {
        let pasted = "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/\
                      AlmaLinux-9-latest-x86_64-dvd.iso  \u{2705}  (stable \"latest\" name)";
        assert_eq!(
            extract_http_url(pasted).as_deref(),
            Some(
                "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/\
                 AlmaLinux-9-latest-x86_64-dvd.iso"
            )
        );
    }

    #[test]
    fn extract_keeps_a_plain_url_untouched() {
        let u = "https://mirror.test/a.iso";
        assert_eq!(extract_http_url(u).as_deref(), Some(u));
        assert_eq!(extract_http_url(&format!("  {u}  ")).as_deref(), Some(u));
        // 查询串属于地址本身，不能被截掉
        let q = "http://b.test/a.iso?x=1&y=2";
        assert_eq!(extract_http_url(q).as_deref(), Some(q));
    }

    #[test]
    fn extract_handles_markdown_and_cjk_punctuation() {
        assert_eq!(
            extract_http_url("点这里下载 [镜像](https://m.test/a.iso) 即可").as_deref(),
            Some("https://m.test/a.iso")
        );
        assert_eq!(
            extract_http_url("地址：https://m.test/a.iso。").as_deref(),
            Some("https://m.test/a.iso")
        );
        assert_eq!(
            extract_http_url("see <https://m.test/a.iso>").as_deref(),
            Some("https://m.test/a.iso")
        );
    }

    #[test]
    fn extract_rejects_text_without_a_url() {
        assert_eq!(extract_http_url(""), None);
        assert_eq!(extract_http_url("   "), None);
        assert_eq!(extract_http_url("AlmaLinux-9-latest-x86_64-dvd.iso"), None);
        assert_eq!(extract_http_url("ftp://m.test/a.iso"), None);
        // 只有 scheme 没有主机名不算地址
        assert_eq!(extract_http_url("https:// 后面没了"), None);
    }

    #[test]
    fn candidates_with_mirrors_appends_derived_after_user_entries() {
        // 这条主地址会 302 到一个不可达主机（本次调查的起点），
        // 所以「自动补镜像」对它是唯一能自动救活的手段。
        let primary = "https://mirrors.aliyun.com/almalinux/9/isos/x86_64/a.iso";
        let user = "https://user.example/a.iso";
        let got = candidates_with_mirrors(primary, Some(user), true);
        assert_eq!(got[0], primary, "主地址永远第一");
        assert_eq!(got[1], user, "用户填的优先于自动派生的");
        // 追加条数 = 派生表给出的条数（不硬编码常量：表会随实测增补）
        let derived = crate::mirrors::derive(primary).len();
        assert!(derived > 0, "这条主地址应当命中镜像族");
        assert_eq!(got.len(), 2 + derived, "自动镜像追加在最后: {got:?}");
        // 关掉开关时与原有行为逐字一致
        assert_eq!(
            candidates_with_mirrors(primary, Some(user), false),
            candidates(primary, Some(user))
        );
    }

    #[test]
    fn candidates_with_mirrors_dedups_against_user_entries() {
        let primary = "https://mirrors.aliyun.com/almalinux/9/a.iso";
        // 用户手填的那条正好是表里的第一项
        let user = "https://mirrors.nju.edu.cn/almalinux/9/a.iso";
        let got = candidates_with_mirrors(primary, Some(user), true);
        let nju = got
            .iter()
            .filter(|u| u.contains("mirrors.nju.edu.cn"))
            .count();
        assert_eq!(nju, 1, "不能因为自动派生而重复: {got:?}");
        // 用户那条与派生表的第一项重合，所以总数 = 主地址 + 用户 + (派生 - 1)
        let derived = crate::mirrors::derive(primary).len();
        assert_eq!(got.len(), 2 + derived - 1, "{got:?}");
    }

    #[test]
    fn host_of_normalizes_and_drops_port_and_userinfo() {
        // 熔断键要让「同一台机器的两个协议形态」归并到一起，
        // 否则 http/https 会各等一次超时（实测 iso-osm 各 5 秒）。
        assert_eq!(
            host_of("https://iso-osm.mirrors.aliyuncs.com/a.iso").as_deref(),
            Some("iso-osm.mirrors.aliyuncs.com")
        );
        assert_eq!(
            host_of("http://ISO-OSM.Mirrors.Aliyuncs.COM/a.iso").as_deref(),
            Some("iso-osm.mirrors.aliyuncs.com"),
            "主机名大小写不敏感"
        );
        assert_eq!(
            host_of("http://mirror.test:8080/a.iso").as_deref(),
            Some("mirror.test"),
            "端口不参与归并"
        );
        assert_eq!(
            host_of("https://user:pw@mirror.test/a.iso").as_deref(),
            Some("mirror.test"),
            "userinfo 不属于主机"
        );
        assert_eq!(
            host_of("http://127.0.0.1:9/never.bin").as_deref(),
            Some("127.0.0.1")
        );
        // IPv6 字面量的主机部分是方括号整体，不能被 `:` 切开
        assert_eq!(host_of("http://[::1]:9/a.bin").as_deref(), Some("[::1]"));
    }

    #[test]
    fn host_of_rejects_urls_without_a_host() {
        assert_eq!(host_of("not-a-url"), None);
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("https:///a.bin"), None);
    }

    #[test]
    fn candidates_with_mirrors_is_inert_for_unknown_namespaces() {
        let primary = "https://example.com/random/a.iso";
        assert_eq!(
            candidates_with_mirrors(primary, None, true),
            candidates(primary, None)
        );
    }

    #[test]
    fn scheme_swap_flips_only_http_family() {
        assert_eq!(
            scheme_swap("https://a.test/x.iso").as_deref(),
            Some("http://a.test/x.iso")
        );
        assert_eq!(
            scheme_swap("http://a.test/x.iso").as_deref(),
            Some("https://a.test/x.iso")
        );
        // 大小写与查询串原样保留
        assert_eq!(
            scheme_swap("HTTPS://A.test/x.iso?q=1").as_deref(),
            Some("http://A.test/x.iso?q=1")
        );
        assert_eq!(scheme_swap("ftp://a.test/x"), None);
        assert_eq!(scheme_swap("ed2k://|file|a|1|b|/"), None);
        assert_eq!(scheme_swap("https://"), None);
    }
}
