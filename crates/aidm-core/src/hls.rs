//! HLS 清单解析（RFC 8216）。
//!
//! 只做**解析与地址解析**，不碰网络：把一份 m3u8 变成"要下哪些分片、按什么顺序"。
//! 下载与合并由引擎侧完成，这样解析逻辑可以脱离引擎单独测。
//!
//! ## 为什么手写而不引第三方
//!
//! m3u8 是**面向行的纯文本**格式（每条 `#EXT-X-*` 占一行），手写解析器比引入依赖
//! 更小、更可控。项目里的 `metalink.rs` / `mirrorlist.rs` 也是同一取向。
//!
//! ## 三个必须明确回绝的情形
//!
//! 这几条共同点是：**照做会安静地产出一个坏文件**，比直接报错糟糕得多。
//!
//! 1. **加密分片**（`#EXT-X-KEY` 且 `METHOD != NONE`）：分片是密文，直接拼接得到
//!    的是**看起来下完了的垃圾**。本模块如实标出，由调用方回绝。
//! 2. **没有分片**：清单合法但空，多半是解析到了主清单或错误页。
//! 3. **`#EXT-X-MAP` 初始化段缺失**（fMP4）：分片本身不自带解码信息，缺了它同样
//!    拼不出可播文件。

/// 解析结果。`playlist` 为 `None` 表示这是**主清单**（含码率变体），需要再取一层。
#[derive(Debug, Clone, PartialEq)]
pub struct HlsPlaylist {
    /// 媒体分片，按播放顺序。
    pub segments: Vec<HlsSegment>,
    /// 主清单里列出的码率变体（媒体清单里为空）。
    pub variants: Vec<HlsVariant>,
    /// `#EXT-X-MEDIA-SEQUENCE`，缺省为 0。分片序号从这里开始递增。
    pub media_sequence: u64,
    /// 是否出现 `#EXT-X-ENDLIST`。**没有它 = 直播**：分片列表还会增长，
    /// "下完"这个概念不成立。
    pub has_endlist: bool,
    /// 加密方式（`#EXT-X-KEY` 的 `METHOD`）。`None` 或 `"NONE"` 表示明文。
    pub encryption: Option<String>,
    /// `#EXT-X-MAP` 声明的初始化段（fMP4）。下载时需要先取它。
    pub init_segment: Option<String>,
}

impl HlsPlaylist {
    /// 是不是主清单（只有变体、没有分片）。
    pub fn is_master(&self) -> bool {
        self.segments.is_empty() && !self.variants.is_empty()
    }

    /// 可否作为"一个完整文件"下载。
    ///
    /// 三个条件缺一不可：有分片、明文、点播（有 ENDLIST）。
    /// 直播**不在这里回绝**，而是由调用方决定（它可以边下边等新分片），
    /// 所以单独暴露 [`Self::is_live`]。
    pub fn reject_reason(&self) -> Option<&'static str> {
        if self.is_master() {
            return Some("hls_master_playlist");
        }
        if self.segments.is_empty() {
            return Some("hls_no_segments");
        }
        // 加密分片拼起来是密文 —— 必须回绝而不是下出一个坏文件。
        if self
            .encryption
            .as_deref()
            .is_some_and(|m| !m.eq_ignore_ascii_case("NONE"))
        {
            return Some("hls_encrypted");
        }
        None
    }

    /// 直播清单：没有 `#EXT-X-ENDLIST`，分片还会继续增加。
    pub fn is_live(&self) -> bool {
        !self.has_endlist && !self.is_master()
    }

    /// 所有分片时长之和（秒）。`#EXTINF` 缺失的按 0 计。
    pub fn total_duration_s(&self) -> f64 {
        self.segments.iter().filter_map(|s| s.duration_s).sum()
    }

    /// 挑选一个变体：**优先带宽最高**的那个。
    ///
    /// 为什么不是"最低"：作为下载器，用户要的是**最好的那份**；自适应码率是播放器的
    /// 职责，下载器替用户降质没有道理。带宽缺失的变体排在最后（无法比较）。
    pub fn best_variant(&self) -> Option<&HlsVariant> {
        self.variants
            .iter()
            .max_by_key(|v| v.bandwidth.unwrap_or(0))
    }
}

/// 一个媒体分片。
#[derive(Debug, Clone, PartialEq)]
pub struct HlsSegment {
    /// **已解析成绝对地址**（相对 URI 按清单地址补全）。
    pub uri: String,
    pub duration_s: Option<f64>,
    /// `#EXT-X-BYTERANGE:<len>[@<offset>]`：分片是**同一文件的一段字节**。
    /// 值为 `(offset, len)`；未给 offset 时表示"紧接上一个分片"。
    pub byte_range: Option<(u64, u64)>,
    /// 该分片的媒体序号（`media_sequence` + 下标）。
    pub sequence: u64,
    /// `#EXT-X-DISCONTINUITY`：时间轴在此断开（拼接时可能需要处理）。
    pub discontinuity: bool,
}

/// 主清单里的一个码率变体。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HlsVariant {
    pub uri: String,
    pub bandwidth: Option<u64>,
    pub resolution: Option<String>,
}

/// 按行解析一份 m3u8。`base_url` 用于把相对 URI 补成绝对地址。
///
/// 解析**不报错**：m3u8 的容错性很强，遇到不认识的标签就跳过（这是规范的建议做法）。
/// 真正的回绝交给 [`HlsPlaylist::reject_reason`]，这样调用方能拿到**具体原因**，
/// 而不是笼统一句"解析失败"。
pub fn parse(base_url: &str, text: &str) -> HlsPlaylist {
    let mut out = HlsPlaylist {
        segments: Vec::new(),
        variants: Vec::new(),
        media_sequence: 0,
        has_endlist: false,
        encryption: None,
        init_segment: None,
    };

    // 待配对的"下一个 URI"状态。
    let mut pending_duration: Option<f64> = None;
    let mut pending_range: Option<(u64, u64)> = None;
    let mut pending_discontinuity = false;
    // 主清单里 `#EXT-X-STREAM-INF` 的**下一行**才是 URI，所以要把属性暂存。
    let mut pending_variant: Option<(Option<u64>, Option<String>)> = None;
    // BYTERANGE 省略 offset 时"紧接上一个分片"。
    let mut last_range_end: u64 = 0;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(attrs) = line.strip_prefix("#EXT-X-STREAM-INF:") {
            pending_variant = Some((attr_u64(attrs, "BANDWIDTH"), attr_str(attrs, "RESOLUTION")));
            continue;
        }
        if line.starts_with('#') {
            if let Some(v) = line.strip_prefix("#EXTINF:") {
                // `#EXTINF:<duration>,[<title>]`
                let dur = v.split(',').next().unwrap_or("").trim();
                pending_duration = dur.parse::<f64>().ok();
            } else if let Some(v) = line.strip_prefix("#EXT-X-BYTERANGE:") {
                pending_range = parse_byte_range(v.trim(), last_range_end);
            } else if line == "#EXT-X-DISCONTINUITY" {
                pending_discontinuity = true;
            } else if line == "#EXT-X-ENDLIST" {
                out.has_endlist = true;
            } else if let Some(v) = line.strip_prefix("#EXT-X-MEDIA-SEQUENCE:") {
                out.media_sequence = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("#EXT-X-KEY:") {
                // 只记 METHOD：密钥 URI 属于敏感信息，且我们不实现解密。
                if let Some(m) = attr_str(v, "METHOD") {
                    out.encryption = Some(m);
                }
            } else if let Some(v) = line.strip_prefix("#EXT-X-MAP:") {
                if let Some(uri) = attr_str(v, "URI") {
                    out.init_segment = Some(resolve(base_url, &uri));
                }
            }
            continue;
        }

        // 非 `#` 开头 ⇒ 这是一个 URI。
        let abs = resolve(base_url, line);
        if let Some((bw, res)) = pending_variant.take() {
            out.variants.push(HlsVariant {
                uri: abs,
                bandwidth: bw,
                resolution: res,
            });
            continue;
        }
        let sequence = out.media_sequence + out.segments.len() as u64;
        if let Some((off, len)) = pending_range {
            last_range_end = off.saturating_add(len);
        }
        out.segments.push(HlsSegment {
            uri: abs,
            duration_s: pending_duration.take(),
            byte_range: pending_range.take(),
            sequence,
            discontinuity: pending_discontinuity,
        });
        pending_discontinuity = false;
    }

    out
}

/// `#EXT-X-BYTERANGE:<len>[@<offset>]`。省略 `@offset` 时紧接上一个分片。
fn parse_byte_range(v: &str, last_end: u64) -> Option<(u64, u64)> {
    let (len_s, off_s) = match v.split_once('@') {
        Some((l, o)) => (l, Some(o)),
        None => (v, None),
    };
    let len: u64 = len_s.trim().parse().ok()?;
    let off: u64 = match off_s {
        Some(o) => o.trim().parse().ok()?,
        None => last_end,
    };
    Some((off, len))
}

/// 从 `ATTR=value,ATTR="value"` 里取一个整型属性。
fn attr_u64(attrs: &str, key: &str) -> Option<u64> {
    attr_str(attrs, key)?.trim().parse().ok()
}

/// 从属性串里取一个字符串属性，去引号。
fn attr_str(attrs: &str, key: &str) -> Option<String> {
    for item in split_attrs(attrs) {
        let Some((k, v)) = item.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(key) {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// 按逗号切属性，但**不切引号里的逗号**（`CODECS="avc1,mp4a"` 很常见）。
fn split_attrs(attrs: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for ch in attrs.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// 把相对 URI 补成绝对地址。
///
/// 只处理 http(s) 与**协议相对**（`//host/path`）两种；无法解析时原样返回 ——
/// 宁可在下载时报错，也不要在这里猜出一个错的地址。
pub fn resolve(base_url: &str, uri: &str) -> String {
    let uri = uri.trim();
    if uri.starts_with("http://") || uri.starts_with("https://") {
        return uri.to_string();
    }
    let Some((scheme, rest)) = base_url.split_once("://") else {
        return uri.to_string();
    };
    // 协议相对：`//host/path` 继承清单的 scheme。
    if let Some(host_and_path) = uri.strip_prefix("//") {
        return format!("{scheme}://{host_and_path}");
    }
    let Some((authority, path)) = rest.split_once('/') else {
        return format!("{scheme}://{rest}/{uri}");
    };
    if let Some(abs) = uri.strip_prefix('/') {
        // 根相对：只换路径。
        return format!("{scheme}://{authority}/{abs}");
    }
    // 相对：接到清单所在目录后面。
    let dir = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "",
    };
    format!("{scheme}://{authority}/{dir}{uri}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://cdn.example/hls/movie/index.m3u8";

    #[test]
    fn parses_a_media_playlist_with_relative_and_absolute_uris() {
        let text = "\
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:5
#EXTINF:9.009,
seg0.ts
#EXTINF:9.009,
/sub/seg1.ts
#EXTINF:3.003,
https://other.example/seg2.ts
#EXT-X-ENDLIST
";
        let p = parse(BASE, text);
        assert_eq!(p.segments.len(), 3);
        assert_eq!(
            p.segments[0].uri, "https://cdn.example/hls/movie/seg0.ts",
            "相对 URI 应接到清单所在目录"
        );
        assert_eq!(
            p.segments[1].uri, "https://cdn.example/sub/seg1.ts",
            "根相对 URI 只换路径"
        );
        assert_eq!(
            p.segments[2].uri, "https://other.example/seg2.ts",
            "绝对地址原样"
        );
        // 序号从 MEDIA-SEQUENCE 起递增。
        assert_eq!(p.media_sequence, 5);
        assert_eq!(
            p.segments.iter().map(|s| s.sequence).collect::<Vec<_>>(),
            vec![5, 6, 7]
        );
        assert!(p.has_endlist, "有 ENDLIST ⇒ 点播，不是直播");
        assert!(!p.is_live());
        assert!(p.reject_reason().is_none(), "明文点播清单应当可以下");
        assert!((p.total_duration_s() - 21.021).abs() < 1e-6);
    }

    /// 直播清单：没有 ENDLIST，分片还会增长。**不报错**，由调用方决定策略。
    #[test]
    fn live_playlist_is_flagged_not_rejected() {
        let text = "#EXTM3U\n#EXTINF:9.0,\na.ts\n#EXTINF:9.0,\nb.ts\n";
        let p = parse(BASE, text);
        assert!(!p.has_endlist);
        assert!(p.is_live(), "没有 ENDLIST ⇒ 直播");
        assert!(
            p.reject_reason().is_none(),
            "直播不是坏清单，不该在这里被回绝"
        );
    }

    /// **加密分片必须回绝**：拼接密文会得到一个"看起来下完了"的坏文件。
    #[test]
    fn encrypted_playlist_is_rejected() {
        let text = "\
#EXTM3U
#EXT-X-KEY:METHOD=AES-128,URI=\"https://cdn.example/key.bin\",IV=0x1
#EXTINF:9.0,
a.ts
#EXT-X-ENDLIST
";
        let p = parse(BASE, text);
        assert_eq!(p.encryption.as_deref(), Some("AES-128"));
        assert_eq!(p.reject_reason(), Some("hls_encrypted"));
    }

    /// `METHOD=NONE` 是明文，不该被误判成加密。
    #[test]
    fn method_none_is_plaintext() {
        let text = "#EXTM3U\n#EXT-X-KEY:METHOD=NONE\n#EXTINF:1.0,\na.ts\n#EXT-X-ENDLIST\n";
        let p = parse(BASE, text);
        assert!(p.reject_reason().is_none(), "METHOD=NONE 是明文");
    }

    #[test]
    fn master_playlist_yields_variants_and_is_not_downloadable_directly() {
        let text = "\
#EXTM3U
#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360,CODECS=\"avc1.42c01e,mp4a.40.2\"
low/index.m3u8
#EXT-X-STREAM-INF:BANDWIDTH=2400000,RESOLUTION=1280x720
high/index.m3u8
";
        let p = parse(BASE, text);
        assert!(p.is_master());
        assert_eq!(p.variants.len(), 2);
        assert_eq!(
            p.variants[0].uri,
            "https://cdn.example/hls/movie/low/index.m3u8"
        );
        assert_eq!(p.variants[0].bandwidth, Some(800_000));
        assert_eq!(p.variants[0].resolution.as_deref(), Some("640x360"));
        // 主清单本身不是可下的文件，要再取一层。
        assert_eq!(p.reject_reason(), Some("hls_master_playlist"));
        // 选码率取**最高**：下载器不该替用户降质。
        assert_eq!(p.best_variant().unwrap().bandwidth, Some(2_400_000));
    }

    /// `CODECS="avc1,mp4a"` 里的逗号不能把属性切坏 —— 这是最容易踩的一个坑。
    #[test]
    fn quoted_commas_do_not_split_attributes() {
        let attrs = r#"BANDWIDTH=800000,CODECS="avc1.42c01e,mp4a.40.2",RESOLUTION=640x360"#;
        assert_eq!(attr_u64(attrs, "BANDWIDTH"), Some(800_000));
        assert_eq!(attr_str(attrs, "RESOLUTION").as_deref(), Some("640x360"));
        // CODECS 本身没被 attr_str 直接取，但上面两条能通过就说明没被切坏。
        assert_eq!(split_attrs(attrs).len(), 3);
    }

    /// BYTERANGE：分片是**同一文件**的字节区间；省略 offset 时紧接上一个。
    #[test]
    fn byte_range_segments_continue_from_the_previous_one() {
        let text = "\
#EXTM3U
#EXTINF:10.0,
#EXT-X-BYTERANGE:1000@0
all.ts
#EXTINF:10.0,
#EXT-X-BYTERANGE:2000
all.ts
#EXT-X-ENDLIST
";
        let p = parse(BASE, text);
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.segments[0].byte_range, Some((0, 1000)));
        assert_eq!(
            p.segments[1].byte_range,
            Some((1000, 2000)),
            "省略 @offset 时应紧接上一个分片结束处"
        );
        // 两片指向同一个 URI —— 合并时不能当成两份不同文件去下。
        assert_eq!(p.segments[0].uri, p.segments[1].uri);
    }

    /// 空清单 / 只有头的清单：合法但没内容，要能说清是"没有分片"。
    #[test]
    fn empty_playlist_reports_no_segments() {
        for text in ["#EXTM3U\n", ""] {
            let p = parse(BASE, text);
            assert_eq!(p.reject_reason(), Some("hls_no_segments"), "text={text:?}");
        }
    }

    /// fMP4 初始化段要带出来：缺了它分片拼不成可播文件。
    #[test]
    fn fmp4_init_segment_is_recorded() {
        let text = "\
#EXTM3U
#EXT-X-MAP:URI=\"init.mp4\"
#EXTINF:4.0,
seg1.m4s
#EXT-X-ENDLIST
";
        let p = parse(BASE, text);
        assert_eq!(
            p.init_segment.as_deref(),
            Some("https://cdn.example/hls/movie/init.mp4")
        );
        assert_eq!(p.segments.len(), 1);
    }

    /// 未知标签要被跳过而不是让整份清单作废（m3u8 的容错性是规范建议的）。
    #[test]
    fn unknown_tags_are_skipped() {
        let text = "\
#EXTM3U
#EXT-X-SOMETHING-FUTURE:value=1
#EXT-X-PROGRAM-DATE-TIME:2026-10-18T00:00:00Z
#EXTINF:1.0,
a.ts
#EXT-X-ENDLIST
";
        let p = parse(BASE, text);
        assert_eq!(p.segments.len(), 1);
        assert!(p.reject_reason().is_none());
    }

    /// 协议相对地址（`//host/path`）要继承清单的 scheme。
    #[test]
    fn protocol_relative_uri_inherits_scheme() {
        assert_eq!(
            resolve(BASE, "//other.example/a.ts"),
            "https://other.example/a.ts"
        );
        assert_eq!(
            resolve("http://cdn.example/x/index.m3u8", "//other.example/a.ts"),
            "http://other.example/a.ts",
            "明文清单不应把分片悄悄升级成 https"
        );
    }
}
