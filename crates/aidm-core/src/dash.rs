//! MPEG-DASH（ISO/IEC 23009-1）清单解析。
//!
//! 只做**解析与寻址展开**，不碰网络：把一份 MPD 变成"要下哪些分片、按什么顺序"。
//! 与 [`crate::hls`] 的分工一致 —— 解析可脱离引擎单独测。
//!
//! ## 为什么用 `quick-xml` 而 HLS 手写
//!
//! m3u8 是面向行的纯文本，手写解析器更小（见 `hls.rs`）；而 MPD 是**真 XML**：
//! 命名空间、属性转义、深层嵌套都要处理，手写会成为长期维护负担。
//!
//! ## 两个结构，两种职责（这是本模块最要紧的设计）
//!
//! - [`Inherit`]：**会往下传**的东西（`SegmentTemplate` / `BaseURL` / `mimeType`），
//!   随 `Period` / `AdaptationSet` 入栈出栈。
//! - [`RepBuilder`]：**属于某一个表示**的东西（`SegmentList` 的初始化段、
//!   `SegmentURL` 列表、`SegmentBase` 的 indexRange），从进入 `<Representation>`
//!   攒到离开为止。
//!
//! 早先把两者塞进同一个作用域栈，结果 `</SegmentList>` 一出栈就把初始化段丢了
//! —— 因为那个栈的语义是"继承"，而初始化段并不往下传，它只属于当前表示。

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

/// 一个分片的寻址方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DashAddressing {
    /// `SegmentTemplate`：按模板 + 序号生成地址。
    Template {
        /// 初始化段模板（`initialization`），fMP4 必需。
        initialization: Option<String>,
        /// 媒体段模板（`media`）。
        media: String,
        start_number: u64,
        timescale: u64,
        /// 由呈现时长与分片时长推出的分片数；推不出时为 1。
        count: u64,
    },
    /// `SegmentList`：显式列出每个分片。
    List {
        initialization: Option<String>,
        urls: Vec<String>,
    },
    /// `SegmentBase`：整个表示就是那一个文件（`indexRange` 只作记录）。
    Base { index_range: Option<String> },
}

/// 一个表示（码率档）。DASH 的分片列表是按表示给的。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashRepresentation {
    pub id: Option<String>,
    pub bandwidth: Option<u64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub mime_type: Option<String>,
    /// 继承后的 `<BaseURL>`（可能来自 Period / AdaptationSet / Representation）。
    pub base_url: Option<String>,
    pub addressing: DashAddressing,
}

impl DashRepresentation {
    /// 展开成**有序的下载项**：第一项是初始化段（若有），其后是媒体分片。
    ///
    /// `base` 是清单自身的地址，用于补全相对地址。
    pub fn download_items(&self, base: &str) -> Vec<String> {
        let join = |u: &str| crate::hls::resolve(base, u);
        match &self.addressing {
            DashAddressing::Template {
                initialization,
                media,
                start_number,
                count,
                ..
            } => {
                let mut out = Vec::new();
                if let Some(init) = initialization {
                    out.push(join(&expand_template(init, *start_number, None)));
                }
                if !media.is_empty() {
                    for i in 0..*count {
                        out.push(join(&expand_template(media, start_number + i, None)));
                    }
                }
                out
            }
            DashAddressing::List {
                initialization,
                urls,
            } => {
                let mut out = Vec::new();
                if let Some(init) = initialization {
                    out.push(join(init));
                }
                out.extend(urls.iter().map(|u| join(u)));
                out
            }
            DashAddressing::Base { .. } => self
                .base_url
                .as_deref()
                .map(|u| vec![join(u)])
                .unwrap_or_default(),
        }
    }
}

/// 一份 MPD。
///
/// 不含 `Eq`：`duration_s` 是 `f64`，而 `f64` 不实现 `Eq`（`NaN` 使等价关系不成立）。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DashManifest {
    /// `mediaPresentationDuration` 解析出的秒数。
    pub duration_s: Option<f64>,
    pub representations: Vec<DashRepresentation>,
    /// 出现 `ContentProtection` ⇒ 内容加密。
    pub encrypted: bool,
}

impl DashManifest {
    /// 可否作为"一个完整文件"下载。`None` = 可以。
    pub fn reject_reason(&self) -> Option<&'static str> {
        if self.encrypted {
            return Some("dash_encrypted");
        }
        if self.representations.is_empty() {
            return Some("dash_no_representations");
        }
        if self
            .representations
            .iter()
            .all(|r| r.download_items("https://base.invalid/").is_empty())
        {
            return Some("dash_no_segments");
        }
        None
    }

    /// 挑一个表示：**优先带宽最高**（与 HLS 侧同一原则 —— 下载器不替用户降质）。
    pub fn best_representation(&self) -> Option<&DashRepresentation> {
        self.representations
            .iter()
            .max_by_key(|r| r.bandwidth.unwrap_or(0))
    }
}

// ————————————————— 解析 —————————————————

/// `SegmentTemplate` 的属性集。可出现在 `Period`/`AdaptationSet`/`Representation`
/// 任一层，**下层覆盖上层**。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TemplateAttrs {
    initialization: Option<String>,
    media: Option<String>,
    start_number: Option<u64>,
    duration: Option<u64>,
    timescale: Option<u64>,
}

impl TemplateAttrs {
    fn from_start(e: &BytesStart<'_>) -> Self {
        Self {
            initialization: attr_of(e, "initialization"),
            media: attr_of(e, "media"),
            start_number: attr_of(e, "startNumber").and_then(|v| v.trim().parse().ok()),
            duration: attr_of(e, "duration").and_then(|v| v.trim().parse().ok()),
            timescale: attr_of(e, "timescale").and_then(|v| v.trim().parse().ok()),
        }
    }

    /// `self`（下层）覆盖 `parent`（上层）。
    fn overlay(&self, parent: &TemplateAttrs) -> TemplateAttrs {
        TemplateAttrs {
            initialization: self
                .initialization
                .clone()
                .or_else(|| parent.initialization.clone()),
            media: self.media.clone().or_else(|| parent.media.clone()),
            start_number: self.start_number.or(parent.start_number),
            duration: self.duration.or(parent.duration),
            timescale: self.timescale.or(parent.timescale),
        }
    }

    fn to_addressing(&self, presentation_duration_s: Option<f64>) -> DashAddressing {
        let timescale = self.timescale.unwrap_or(1).max(1);
        let count = match (presentation_duration_s, self.duration) {
            (Some(d), Some(sd)) if sd > 0 && d > 0.0 => {
                let seg_s = sd as f64 / timescale as f64;
                ((d / seg_s).ceil() as u64).max(1)
            }
            // 推不出分片数时按 1 —— 至少下第一片，而不是当作"没有分片"。
            _ => 1,
        };
        DashAddressing::Template {
            initialization: self.initialization.clone(),
            media: self.media.clone().unwrap_or_default(),
            start_number: self.start_number.unwrap_or(1),
            timescale,
            count,
        }
    }
}

/// 继承层（`Period` / `AdaptationSet`）：只放**会往下传**的东西。
#[derive(Debug, Clone, Default)]
struct Inherit {
    template: TemplateAttrs,
    base_url: Option<String>,
    mime: Option<String>,
}

/// 正在构建的表示：**它自己的**东西都攒在这里，直到 `</Representation>`。
#[derive(Debug, Default)]
struct RepBuilder {
    id: Option<String>,
    bandwidth: Option<u64>,
    width: Option<u32>,
    height: Option<u32>,
    mime: Option<String>,
    base_url: Option<String>,
    /// 从继承层带下来的模板；`Representation` 内若再给一份则覆盖。
    template: TemplateAttrs,
    list_init: Option<String>,
    list_urls: Vec<String>,
    index_range: Option<String>,
}

impl RepBuilder {
    fn finish(self, presentation_duration_s: Option<f64>) -> DashRepresentation {
        // 寻址优先级：Template > List > Base。前者更具体。
        let addressing = if self.template.media.is_some() {
            self.template.to_addressing(presentation_duration_s)
        } else if self.list_init.is_some() || !self.list_urls.is_empty() {
            DashAddressing::List {
                initialization: self.list_init.clone(),
                urls: self.list_urls.clone(),
            }
        } else {
            DashAddressing::Base {
                index_range: self.index_range.clone(),
            }
        };
        DashRepresentation {
            id: self.id,
            bandwidth: self.bandwidth,
            width: self.width,
            height: self.height,
            mime_type: self.mime,
            base_url: self.base_url,
            addressing,
        }
    }
}

/// 解析一份 MPD。
///
/// 返回 `None` 仅表示**读取 XML 失败**（编码/IO 级）。内容层面的问题（加密、
/// 无分片）不在这里报，交给 [`DashManifest::reject_reason`]，这样调用方能拿到具体
/// 原因而不是笼统一句"解析失败"。
///
/// 注意：**未闭合的标签不会让本函数返回 `None`** —— quick-xml 在输入耗尽时给出
/// `Eof` 而非错误。这类残缺清单会以"没有表示/没有分片"的形态被 `reject_reason`
/// 拦下，不会静默通过。
pub fn parse(base_url: &str, text: &str) -> Option<DashManifest> {
    let _ = base_url; // 地址补全在 `download_items` 里做，解析阶段不需要
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);

    let mut out = DashManifest::default();
    let mut stack: Vec<Inherit> = vec![Inherit::default()];
    let mut period_duration_s: Option<f64> = None;
    let mut cur: Option<RepBuilder> = None;
    let mut in_base_url = false;

    loop {
        let ev = reader.read_event().ok()?;
        // 必须在 `match ev` 之前判断：`Event` 会被 move 进匹配。
        let is_start = matches!(ev, Event::Start(_));
        match ev {
            Event::Start(e) | Event::Empty(e) => {
                let name = e.local_name().as_ref().to_string();
                match name.as_str() {
                    "MPD" => {
                        if let Some(v) = attr_of(&e, "mediaPresentationDuration") {
                            out.duration_s = parse_iso8601_duration(&v);
                        }
                    }
                    "Period" => {
                        period_duration_s =
                            attr_of(&e, "duration").and_then(|v| parse_iso8601_duration(&v));
                        if is_start {
                            stack.push(Inherit::default());
                        }
                    }
                    "AdaptationSet" => {
                        let mut next = stack.last().cloned().unwrap_or_default();
                        if let Some(v) = attr_of(&e, "mimeType") {
                            next.mime = Some(v);
                        }
                        // AdaptationSet 上也可能带模板/BaseURL，供其下表示继承。
                        if let Some(t) = template_if_present(&e) {
                            next.template = t.overlay(&next.template);
                        }
                        if is_start {
                            stack.push(next);
                        } else if let Some(top) = stack.last_mut() {
                            *top = next;
                        }
                    }
                    "Representation" => {
                        let parent = stack.last().cloned().unwrap_or_default();
                        let mut b = RepBuilder {
                            id: attr_of(&e, "id"),
                            bandwidth: attr_of(&e, "bandwidth").and_then(|v| v.trim().parse().ok()),
                            width: attr_of(&e, "width").and_then(|v| v.trim().parse().ok()),
                            height: attr_of(&e, "height").and_then(|v| v.trim().parse().ok()),
                            mime: attr_of(&e, "mimeType").or_else(|| parent.mime.clone()),
                            base_url: parent.base_url.clone(),
                            template: parent.template.clone(),
                            ..Default::default()
                        };
                        if let Some(t) = template_if_present(&e) {
                            b.template = t.overlay(&b.template);
                        }
                        if !is_start {
                            // 自闭合的 `<Representation/>`：当场定稿。
                            out.representations
                                .push(b.finish(period_duration_s.or(out.duration_s)));
                        } else {
                            cur = Some(b);
                        }
                    }
                    "SegmentTemplate" => {
                        let t = TemplateAttrs::from_start(&e);
                        if let Some(b) = cur.as_mut() {
                            b.template = t.overlay(&b.template);
                        } else if let Some(top) = stack.last_mut() {
                            top.template = t.overlay(&top.template);
                        }
                    }
                    "SegmentList" => {
                        if let Some(b) = cur.as_mut() {
                            if let Some(v) = attr_of(&e, "initialization") {
                                b.list_init = Some(v);
                            }
                        }
                    }
                    "SegmentURL" => {
                        if let Some(b) = cur.as_mut() {
                            if let Some(u) = attr_of(&e, "media") {
                                b.list_urls.push(u);
                            }
                        }
                    }
                    "SegmentBase" => {
                        if let Some(b) = cur.as_mut() {
                            b.index_range = attr_of(&e, "indexRange");
                        }
                    }
                    "ContentProtection" => out.encrypted = true,
                    "BaseURL" => in_base_url = true,
                    _ => {}
                }
            }
            Event::Text(t) => {
                if in_base_url {
                    // `xml10_content()`：XML 1.0 的反转义文本。MPD 就是 XML 1.0，
                    // 所以不必走需要显式版本的 `xml_content()`。
                    let raw = t.xml10_content().trim().to_string();
                    if !raw.is_empty() {
                        match cur.as_mut() {
                            Some(b) => b.base_url = Some(raw),
                            None => {
                                if let Some(top) = stack.last_mut() {
                                    top.base_url = Some(raw);
                                }
                            }
                        }
                    }
                }
            }
            Event::End(e) => {
                let name = e.local_name().as_ref().to_string();
                match name.as_str() {
                    "BaseURL" => in_base_url = false,
                    "Representation" => {
                        if let Some(b) = cur.take() {
                            out.representations
                                .push(b.finish(period_duration_s.or(out.duration_s)));
                        }
                    }
                    "AdaptationSet" | "Period" => {
                        stack.pop();
                    }
                    _ => {}
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    // 输入耗尽时仍有一个未收尾的表示（标签未闭合）—— **不静默丢弃**，
    // 按已有信息定稿，让 `reject_reason` 依据内容而不是"被吞掉"来做判断。
    if let Some(b) = cur.take() {
        out.representations
            .push(b.finish(period_duration_s.or(out.duration_s)));
    }
    Some(out)
}

/// 该元素上是否带 `SegmentTemplate` 属性（`Representation`/`AdaptationSet` 上
/// 直接写 `media=` 这种简写形式在真实清单里存在）。
fn template_if_present(e: &BytesStart<'_>) -> Option<TemplateAttrs> {
    let t = TemplateAttrs::from_start(e);
    (t.media.is_some() || t.initialization.is_some() || t.duration.is_some()).then_some(t)
}

/// 取一个属性并反转义。找不到返回 `None`。
///
/// quick-xml 0.42 的 `Attribute::key` 是 `QName`（**`str` 而非 `bytes`**）；
/// 取值用 `normalized_value(XmlVersion::Implicit1_0)` —— `unescape_value()` 在 0.42
/// 已废弃，而 `Implicit1_0` 正是它内部选用的版本（见上游 `attributes.rs`），
/// 所以这次迁移不改变行为。
fn attr_of(e: &BytesStart<'_>, key: &str) -> Option<String> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == key {
            return attr
                .normalized_value(XmlVersion::Implicit1_0)
                .ok()
                .map(|v| v.to_string());
        }
    }
    None
}

/// 展开 `$Number$` / `$Time$` 模板，含 `%0Nd` 补零宽度与 `$$` 转义。
///
/// 只实现下载器需要的这两个变量：`$RepresentationID$` / `$Bandwidth$` 不随分片变化，
/// 应由调用方在更上层替换。**不认识的变量保留原样** —— 静默换成空串会拼出一个
/// 看起来合法、实际 404 的地址。
pub fn expand_template(tpl: &str, number: u64, time: Option<u64>) -> String {
    let mut out = String::with_capacity(tpl.len());
    let bytes = tpl.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        if i + 1 < bytes.len() && bytes[i + 1] == b'$' {
            out.push('$');
            i += 2;
            continue;
        }
        let Some(close) = tpl[i + 1..].find('$') else {
            out.push('$');
            i += 1;
            continue;
        };
        let inner = &tpl[i + 1..i + 1 + close];
        let (var, width) = match inner.split_once('%') {
            Some((v, fmt)) => {
                let w: usize = fmt
                    .trim_start_matches('0')
                    .trim_end_matches('d')
                    .parse()
                    .unwrap_or(0);
                (v, w)
            }
            None => (inner, 0),
        };
        let value = match var {
            "Number" => Some(number),
            "Time" => time,
            _ => None,
        };
        match value {
            Some(v) => {
                if width > 0 {
                    out.push_str(&format!("{v:0width$}"));
                } else {
                    out.push_str(&v.to_string());
                }
            }
            None => out.push_str(&format!("${inner}$")),
        }
        i += close + 2;
    }
    out
}

/// ISO 8601 duration（`PT1H2M3.5S`）→ 秒。
///
/// 只支持 DASH 里实际会出现的 `P[nD]T[nH][nM][nS]` 形态；出现年/月就**如实失败**，
/// 不猜（那两种在 `mediaPresentationDuration` 上不出现，猜错会得到一个离谱的时长）。
pub fn parse_iso8601_duration(s: &str) -> Option<f64> {
    let s = s.trim();
    let rest = s.strip_prefix('P')?;
    let (date, time) = match rest.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (rest, None),
    };
    let mut total = 0f64;
    if !date.is_empty() {
        let mut num = String::new();
        for ch in date.chars() {
            if ch.is_ascii_digit() || ch == '.' {
                num.push(ch);
            } else if ch == 'D' {
                total += num.parse::<f64>().ok()? * 86_400.0;
                num.clear();
            } else {
                return None;
            }
        }
    }
    if let Some(t) = time {
        let mut num = String::new();
        for ch in t.chars() {
            if ch.is_ascii_digit() || ch == '.' {
                num.push(ch);
            } else {
                let v: f64 = num.parse().ok()?;
                match ch {
                    'H' => total += v * 3600.0,
                    'M' => total += v * 60.0,
                    'S' => total += v,
                    _ => return None,
                }
                num.clear();
            }
        }
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "https://cdn.example/dash/stream.mpd";

    /// `SegmentTemplate` 写在 **AdaptationSet** 上（真实清单的常见形态）。
    ///
    /// 只读 `Representation` 上那一份的实现会把这份清单解析成"没有分片" ——
    /// 这是本模块最要紧的一条测试。
    #[test]
    fn template_inherited_from_adaptation_set() {
        let mpd = r#"<?xml version="1.0"?>
<MPD xmlns="urn:mpeg:dash:schema:mpd:2011" mediaPresentationDuration="PT30S">
  <Period>
    <AdaptationSet mimeType="video/mp4">
      <SegmentTemplate initialization="init-$RepresentationID$.mp4"
                       media="chunk-$Number%03d$.m4s"
                       startNumber="1" duration="5" timescale="1"/>
      <Representation id="v0" bandwidth="800000" width="640" height="360"/>
      <Representation id="v1" bandwidth="2400000" width="1280" height="720"/>
    </AdaptationSet>
  </Period>
</MPD>"#;
        let m = parse(BASE, mpd).expect("应当能解析");
        assert_eq!(m.duration_s, Some(30.0));
        assert_eq!(m.representations.len(), 2);
        assert!(m.reject_reason().is_none(), "明文点播清单应当可以下");

        match &m.representations[0].addressing {
            DashAddressing::Template {
                initialization,
                media,
                start_number,
                count,
                ..
            } => {
                assert_eq!(
                    initialization.as_deref(),
                    Some("init-$RepresentationID$.mp4"),
                    "初始化段模板要能从 AdaptationSet 继承下来"
                );
                assert_eq!(media, "chunk-$Number%03d$.m4s");
                assert_eq!(*start_number, 1);
                assert_eq!(*count, 6, "30 秒 / 5 秒每片 = 6 片（时长取自 MPD 级）");
            }
            other => panic!("应当继承出 Template，实际 {other:?}"),
        }
        assert_eq!(m.representations[0].mime_type.as_deref(), Some("video/mp4"));
        assert_eq!(m.best_representation().unwrap().bandwidth, Some(2_400_000));
    }

    /// `<Period duration>` 优先于 `<MPD mediaPresentationDuration>`。
    #[test]
    fn period_duration_wins_over_mpd_duration() {
        let mpd = r#"<MPD mediaPresentationDuration="PT100S">
  <Period duration="PT10S"><AdaptationSet>
    <SegmentTemplate media="s$Number$.m4s" duration="5" timescale="1" startNumber="1"/>
    <Representation id="a" bandwidth="1"/>
  </AdaptationSet></Period></MPD>"#;
        let m = parse(BASE, mpd).unwrap();
        match &m.representations[0].addressing {
            DashAddressing::Template { count, .. } => assert_eq!(*count, 2, "10/5 = 2"),
            other => panic!("{other:?}"),
        }
    }

    /// `Representation` **内部**的 `SegmentTemplate` 覆盖继承来的那一份。
    #[test]
    fn representation_local_template_overrides_inherited() {
        let mpd = r#"<MPD mediaPresentationDuration="PT10S">
  <Period><AdaptationSet>
    <SegmentTemplate media="inherited-$Number$.m4s" duration="5" timescale="1" startNumber="1"/>
    <Representation id="a" bandwidth="1">
      <SegmentTemplate media="own-$Number$.m4s"/>
    </Representation>
  </AdaptationSet></Period></MPD>"#;
        let m = parse(BASE, mpd).unwrap();
        match &m.representations[0].addressing {
            DashAddressing::Template { media, count, .. } => {
                assert_eq!(media, "own-$Number$.m4s", "本层的 media 应当覆盖上层");
                // duration 仍从上层继承 ⇒ 仍能算出分片数。
                assert_eq!(*count, 2, "duration 应当仍从上层的模板继承");
            }
            other => panic!("{other:?}"),
        }
    }

    /// 模板展开：序号补零、`$$` 转义、不认识的变量保留原样。
    #[test]
    fn template_expansion_rules() {
        assert_eq!(expand_template("c-$Number$.m4s", 7, None), "c-7.m4s");
        assert_eq!(
            expand_template("c-$Number%05d$.m4s", 7, None),
            "c-00007.m4s"
        );
        assert_eq!(expand_template("t-$Time$.m4s", 1, Some(9000)), "t-9000.m4s");
        assert_eq!(expand_template("cost$$5", 1, None), "cost$5");
        assert_eq!(
            expand_template("$RepresentationID$/x.m4s", 1, None),
            "$RepresentationID$/x.m4s"
        );
        assert_eq!(expand_template("a$b", 1, None), "a$b");
    }

    /// `download_items` 的顺序：**初始化段在最前**，其后才是媒体分片。
    /// 顺序错了，拼出来的文件无法解码。
    #[test]
    fn download_items_put_initialization_first() {
        let mpd = r#"<MPD mediaPresentationDuration="PT10S">
  <Period><AdaptationSet><SegmentTemplate initialization="init.mp4" media="s$Number$.m4s"
      startNumber="1" duration="5" timescale="1"/>
  <Representation id="a" bandwidth="1"/></AdaptationSet></Period></MPD>"#;
        let m = parse(BASE, mpd).unwrap();
        let items = m.representations[0].download_items(BASE);
        assert_eq!(
            items,
            vec![
                "https://cdn.example/dash/init.mp4",
                "https://cdn.example/dash/s1.m4s",
                "https://cdn.example/dash/s2.m4s",
            ]
        );
    }

    /// `SegmentList` 的显式分片列表 —— **初始化段必须留住**。
    ///
    /// 易错点：`SegmentList` 的属性若放进通用的作用域栈，
    /// `</SegmentList>` 一出栈初始化段就会丢。
    #[test]
    fn segment_list_keeps_initialization_and_order() {
        let mpd = r#"<MPD>
  <Period><AdaptationSet><Representation id="a" bandwidth="1">
    <SegmentList initialization="init.mp4">
      <SegmentURL media="a1.m4s"/>
      <SegmentURL media="a2.m4s"/>
    </SegmentList>
  </Representation></AdaptationSet></Period></MPD>"#;
        let m = parse(BASE, mpd).unwrap();
        match &m.representations[0].addressing {
            DashAddressing::List {
                initialization,
                urls,
            } => {
                assert_eq!(
                    initialization.as_deref(),
                    Some("init.mp4"),
                    "初始化段不能丢"
                );
                assert_eq!(urls, &vec!["a1.m4s".to_string(), "a2.m4s".to_string()]);
            }
            other => panic!("应当是 List，实际 {other:?}"),
        }
        assert_eq!(
            m.representations[0].download_items(BASE),
            vec![
                "https://cdn.example/dash/init.mp4",
                "https://cdn.example/dash/a1.m4s",
                "https://cdn.example/dash/a2.m4s",
            ]
        );
    }

    /// **加密内容必须回绝**：照下会得到"看起来下完了"的垃圾。
    #[test]
    fn content_protection_is_flagged_and_rejected() {
        let mpd = r#"<MPD>
  <Period><AdaptationSet>
    <ContentProtection schemeIdUri="urn:mpeg:dash:mp4protection:2011" value="cenc"/>
    <Representation id="a" bandwidth="1">
      <BaseURL>movie.mp4</BaseURL>
    </Representation>
  </AdaptationSet></Period></MPD>"#;
        let m = parse(BASE, mpd).unwrap();
        assert!(m.encrypted, "应当识别出 ContentProtection");
        assert_eq!(m.reject_reason(), Some("dash_encrypted"));
    }

    /// 完全没有表示 ⇒ 明确回绝，而不是当成"零个分片的成功下载"。
    #[test]
    fn manifest_without_representations_is_rejected() {
        let m = parse(BASE, "<MPD><Period></Period></MPD>").unwrap();
        assert_eq!(m.reject_reason(), Some("dash_no_representations"));
    }

    /// 残缺清单不会**静默通过**。
    ///
    /// 注意这里不假装能检测"标签未闭合"—— quick-xml 在输入耗尽时给 `Eof` 而不是
    /// 错误，所以未闭合的清单会以"没有表示/没有分片"的形态被 `reject_reason` 拦下。
    /// 这条测试钉的是**这个契约**，不是某种 XML 校验能力。
    #[test]
    fn truncated_manifest_is_rejected_by_content_not_swallowed() {
        // 有 Representation 但没给任何寻址信息 ⇒ 无分片。
        let m = parse(BASE, "<MPD><Period><Representation id='a'/>").unwrap();
        assert_eq!(m.reject_reason(), Some("dash_no_segments"));
        // 连 Representation 都没读到。
        let m2 = parse(BASE, "<MPD><Period>").unwrap();
        assert_eq!(m2.reject_reason(), Some("dash_no_representations"));
    }

    /// 命名空间前缀要被剥掉：`mpd:Period` 与 `Period` 等价。
    #[test]
    fn namespaced_elements_are_recognized() {
        let mpd = r#"<mpd:MPD xmlns:mpd="urn:mpeg:dash:schema:mpd:2011"
             mediaPresentationDuration="PT4S">
  <mpd:Period><mpd:AdaptationSet>
    <mpd:SegmentTemplate media="s$Number$.m4s" duration="2" timescale="1" startNumber="1"/>
    <mpd:Representation id="a" bandwidth="1"/>
  </mpd:AdaptationSet></mpd:Period></mpd:MPD>"#;
        let m = parse(BASE, mpd).unwrap();
        assert_eq!(m.duration_s, Some(4.0));
        assert_eq!(m.representations.len(), 1, "带前缀的元素应当被认出");
        let items = m.representations[0].download_items(BASE);
        assert_eq!(items.len(), 2, "4 秒 / 2 秒每片 = 2 片");
    }

    /// 自闭合的 `<Representation/>` 要当场定稿，不能等 `End` 事件（它不会来）。
    #[test]
    fn self_closing_representation_is_finalized() {
        let mpd = r#"<MPD mediaPresentationDuration="PT6S">
  <Period><AdaptationSet>
    <SegmentTemplate media="s$Number$.m4s" duration="3" timescale="1" startNumber="1"/>
    <Representation id="a" bandwidth="100"/>
  </AdaptationSet></Period></MPD>"#;
        let m = parse(BASE, mpd).unwrap();
        assert_eq!(m.representations.len(), 1);
        assert_eq!(m.representations[0].download_items(BASE).len(), 2);
    }

    #[test]
    fn iso8601_durations() {
        assert_eq!(parse_iso8601_duration("PT30S"), Some(30.0));
        assert_eq!(parse_iso8601_duration("PT1H2M3.5S"), Some(3723.5));
        assert_eq!(parse_iso8601_duration("PT1M"), Some(60.0));
        assert_eq!(parse_iso8601_duration("P1DT1S"), Some(86401.0));
        // 年/月不猜。
        assert_eq!(parse_iso8601_duration("P1Y"), None);
        assert_eq!(parse_iso8601_duration("PT"), Some(0.0));
        assert_eq!(parse_iso8601_duration("nonsense"), None);
    }
}
