//! 文件名解析与净化（开发文档 §3.4）。
//!
//! 优先级：显式指定 > Content-Disposition > 最终 URL 路径 > 兜底名；
//! 净化：剥离路径成分与 Windows 保留字符，防路径穿越。

/// 从 Content-Disposition 头提取 filename（支持 RFC 5987 filename*= 与普通 filename=）。
pub fn content_disposition_filename(header: &str) -> Option<String> {
    // 先找 filename*=（UTF-8 场景优先），退化到 filename=
    for part in header.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("filename*=") {
            if let Some(name) = decode_rfc5987(rest) {
                return Some(name);
            }
        }
    }
    for part in header.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("filename=") {
            let name = rest.trim_matches('"').trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// 解码 RFC 5987（如 `UTF-8''%E4%B8%AD.bin`），失败返回 None。
fn decode_rfc5987(value: &str) -> Option<String> {
    let (_lang, raw) = value.split_once("''")?;
    let decoded: Vec<u8> = {
        let mut out = Vec::new();
        let mut it = raw.as_bytes().iter().copied();
        while let Some(b) = it.next() {
            if b == b'%' {
                let h = it.next()?;
                let l = it.next()?;
                out.push(u8::from_str_radix(std::str::from_utf8(&[h, l]).ok()?, 16).ok()?);
            } else {
                out.push(b);
            }
        }
        out
    };
    String::from_utf8(decoded).ok()
}

/// 从 URL 路径取文件名（去掉 scheme/host/query/片段），失败返回 None。
///
/// 磁力链是**不透明 URI**：没有 host/path 层级，`tr=` 尾巴里的 `/announce` 也不是
/// 文件名（曾把 Debian 任务命名成 `announce`）。磁力链只认 `dn=`；没有就返回
/// `None`，由调用方回退成通用名，等 BT 元数据到手后再按种子里的真实名字修正
/// （见 `bt::download_async`）。
pub fn filename_from_url(url: &str) -> Option<String> {
    let url = url.trim();
    if let Some(rest) = crate::alt::strip_prefix_ci(url, "magnet:?") {
        return magnet_name(rest);
    }
    // 没有 `://` 就没有 host/path（`ed2k:`、`data:`、裸串都属这一类）：不做路径推断。
    let after_scheme = url.split_once("://")?.1;
    let (_host, path) = after_scheme.split_once('/')?;
    let path = path.split(['?', '#']).next()?.trim_end_matches('/');
    let name = path.rsplit(['/', '\\']).next()?;
    let name = percent_decode(name);
    if name.is_empty() || name == "." || name == ".." {
        None
    } else {
        Some(name)
    }
}

/// 磁力链的显示名：取 `dn=` 参数。`+` 按空格处理（站点常用表单编码），再做百分号解码。
fn magnet_name(rest: &str) -> Option<String> {
    for kv in rest.split('&') {
        let (key, value) = kv.split_once('=').unwrap_or((kv, ""));
        if key.eq_ignore_ascii_case("dn") {
            let spaced = value.replace('+', " ");
            let name = percent_decode(&spaced);
            let name = name.trim().to_string();
            return (!name.is_empty()).then_some(name);
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if let (Some(h), Some(l)) = (bytes.get(i + 1), bytes.get(i + 2)) {
                if let Ok(v) =
                    u8::from_str_radix(std::str::from_utf8(&[*h, *l]).unwrap_or("zz"), 16)
                {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 净化文件名：取最后一段路径、替换 Windows 非法字符、去除控制字符与结尾点/空格、
/// 拒绝 Windows 保留设备名、限长 200 字符。空结果返回 None。
pub fn sanitize_filename(name: &str) -> Option<String> {
    // 只保留最后一段，防 `..\..\evil` 穿越
    let last = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let mut cleaned: String = last
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    // Windows 保留名（不区分大小写）
    let stem = cleaned.split('.').next().unwrap_or("").to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    ) {
        cleaned = format!("_{cleaned}");
    }
    while cleaned.ends_with('.') || cleaned.ends_with(' ') {
        cleaned.pop();
    }
    if cleaned.chars().count() > 200 {
        cleaned = cleaned.chars().take(200).collect();
    }
    if cleaned.is_empty() || cleaned == "_" {
        None
    } else {
        Some(cleaned)
    }
}

/// 按「显式指定 > Content-Disposition > URL 路径 > 兜底」解析并净化最终文件名。
pub fn resolve_filename(
    explicit: Option<&str>,
    content_disposition: Option<&str>,
    final_url: &str,
) -> String {
    let url_name = filename_from_url(final_url).and_then(|n| sanitize_filename(&n));
    let explicit = explicit.and_then(sanitize_filename).filter(|name| {
        // 调用方常把「从 URL 自动解析的名字」回填成显式名（新建对话框预填）。
        // 它与 URL 尾名一致时不算用户改名，不能让服务器给的 Content-Disposition
        // 失效（微软 CDN 的 `.../files/<GUID>` 就是典型：真名只在 CD 里）。
        !(content_disposition.is_some()
            && url_name
                .as_deref()
                .is_some_and(|url_name| name.eq_ignore_ascii_case(url_name)))
    });
    let candidates = [
        explicit,
        content_disposition
            .and_then(content_disposition_filename)
            .and_then(|n| sanitize_filename(&n)),
        url_name,
        None,
    ];
    candidates
        .into_iter()
        .flatten()
        .next()
        .unwrap_or_else(|| "download.bin".to_string())
}

/// 目标文件已存在时的自动重命名：`name.ext` -> `name (1).ext` -> `name (2).ext` …
///
/// 只做「不覆盖本地已有文件」的保护，目录不存在视为无冲突。
/// 同名任务并发下载时最终文件尚未落地，这里不加锁（各任务的临时分片在独立目录）。
pub fn unique_file_name(dir: &std::path::Path, file_name: &str) -> String {
    let name = file_name.trim();
    if name.is_empty() || !dir.join(name).exists() {
        return name.to_string();
    }
    let path = std::path::Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    for n in 1..=9999u32 {
        let candidate = if ext.is_empty() {
            format!("{stem} ({n})")
        } else {
            format!("{stem} ({n}).{ext}")
        };
        if !dir.join(&candidate).exists() {
            return candidate;
        }
    }
    name.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_disposition() {
        assert_eq!(
            content_disposition_filename("attachment; filename=\"setup.exe\""),
            Some("setup.exe".into())
        );
        assert_eq!(
            content_disposition_filename("attachment; filename=a b.zip"),
            Some("a b.zip".into())
        );
        assert_eq!(content_disposition_filename("inline"), None);
    }

    #[test]
    fn parses_rfc5987() {
        assert_eq!(
            content_disposition_filename("attachment; filename*=UTF-8''%E4%B8%AD%E6%96%87.bin"),
            Some("中文.bin".into())
        );
    }

    #[test]
    fn extracts_from_url() {
        assert_eq!(
            filename_from_url("https://x.example/a/b/pkg-1.2.zip?token=1"),
            Some("pkg-1.2.zip".into())
        );
        assert_eq!(
            filename_from_url("https://x.example/%E4%B8%AD.bin"),
            Some("中.bin".into())
        );
        assert_eq!(filename_from_url("https://x.example/"), None);
    }

    #[test]
    fn magnet_name_comes_from_dn_only() {
        // `tr=` 尾巴里的 `/announce` 不是文件名（曾把 Debian 任务命名成 announce）。
        assert_eq!(
            filename_from_url(
                "magnet:?xt=urn:btih:abc&dn=pkg-1.2.iso&tr=http%3A%2F%2Ft.example%3A6969%2Fannounce"
            ),
            Some("pkg-1.2.iso".into())
        );
        // 只有 tracker、没有 dn：交给通用名，等元数据修正。
        assert_eq!(
            filename_from_url("magnet:?xt=urn:btih:abc&tr=http%3A%2F%2Ft.example%2Fannounce"),
            None
        );
        // 表单编码的空格。
        assert_eq!(
            filename_from_url("magnet:?dn=my+movie.mp4"),
            Some("my movie.mp4".into())
        );
        // 先被 `&amp;` 转义的 dn 由收口层还原，这里只看纯 `&` 形态。
        assert_eq!(filename_from_url("magnet:?xt=urn:btih:abc"), None);
    }

    #[test]
    fn opaque_uris_have_no_path_name() {
        assert_eq!(filename_from_url("ed2k://|file|a.iso|1|00|/"), None);
        assert_eq!(filename_from_url("data:text/plain,hello"), None);
        assert_eq!(filename_from_url("no-scheme-here"), None);
    }

    #[test]
    fn sanitizes_traversal_and_illegal_chars() {
        assert_eq!(sanitize_filename("../../etc/passwd"), Some("passwd".into()));
        assert_eq!(
            sanitize_filename("..\\..\\evil.dll"),
            Some("evil.dll".into())
        );
        assert_eq!(sanitize_filename("a<b>:c?.zip"), Some("a_b__c_.zip".into()));
        assert_eq!(sanitize_filename("con"), Some("_con".into()));
        assert_eq!(sanitize_filename("name. "), Some("name".into()));
        assert_eq!(sanitize_filename(""), None);
    }

    #[test]
    fn renames_on_existing_file() {
        // 临时目录由 `tempfile::tempdir()` 提供：绝对路径 + Drop 自动清理。
        let tmp = crate::testsupport::tempdir("filename");
        let dir = tmp.path();

        // 无冲突：原名返回
        assert_eq!(unique_file_name(dir, "a.bin"), "a.bin");

        std::fs::write(dir.join("a.bin"), b"x").unwrap();
        assert_eq!(unique_file_name(dir, "a.bin"), "a (1).bin");
        std::fs::write(dir.join("a (1).bin"), b"x").unwrap();
        assert_eq!(unique_file_name(dir, "a.bin"), "a (2).bin");

        // 无扩展名 / 多段扩展名
        std::fs::write(dir.join("noext"), b"x").unwrap();
        assert_eq!(unique_file_name(dir, "noext"), "noext (1)");
        std::fs::write(dir.join("b.tar.gz"), b"x").unwrap();
        assert_eq!(unique_file_name(dir, "b.tar.gz"), "b.tar (1).gz");
    }

    #[test]
    fn resolves_by_priority() {
        // 显式优先
        assert_eq!(
            resolve_filename(
                Some("mine.zip"),
                Some("attachment; filename=cd.zip"),
                "https://x/u.bin"
            ),
            "mine.zip"
        );
        // 其次 Content-Disposition
        assert_eq!(
            resolve_filename(None, Some("attachment; filename=cd.zip"), "https://x/u.bin"),
            "cd.zip"
        );
        // 再其次 URL
        assert_eq!(resolve_filename(None, None, "https://x/y/u.bin"), "u.bin");
        // 兜底
        assert_eq!(resolve_filename(None, None, "https://x/"), "download.bin");
    }

    #[test]
    fn url_derived_explicit_name_yields_to_content_disposition() {
        // 微软 CDN：URL 尾段是 GUID，真名只在 Content-Disposition 里。
        let url = "http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/\
                   37817b38-0a56-4e32-84fd-7e1053b13317?P1=1";
        let cd = "attachment; filename=OpenAI.CodexBeta_26.727.4816.0_x64__2p2nqsd0c76g0.Msix";
        // 自动回填的 URL 尾名不得压掉 CD 真名。
        assert_eq!(
            resolve_filename(Some("37817b38-0a56-4e32-84fd-7e1053b13317"), Some(cd), url),
            "OpenAI.CodexBeta_26.727.4816.0_x64__2p2nqsd0c76g0.Msix"
        );
        // 用户真正改名时仍以显式名为准。
        assert_eq!(
            resolve_filename(Some("mine.msix"), Some(cd), url),
            "mine.msix"
        );
        // 没有 Content-Disposition 时，回填名保持不变。
        assert_eq!(
            resolve_filename(Some("37817b38-0a56-4e32-84fd-7e1053b13317"), None, url),
            "37817b38-0a56-4e32-84fd-7e1053b13317"
        );
    }
}
