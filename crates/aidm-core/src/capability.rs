//! 协议能力模型：把一个下载地址拆成四层**正交**属性，并给出**协议允许**的能力上限。
//!
//! 四层各自回答一个不同的问题，谁也替代不了谁：
//!
//! | 层 | 回答的问题 | 基数 |
//! |---|---|---|
//! | [`Transport`] | 字节怎么取（谁在搬） | 恰好 1 个 |
//! | [`Resource`] | 取到的是不是一个"完整文件" | 0..1 个 |
//! | [`Manifest`] | 要不要先解析一份文档才知道下什么 | 0..1 个 |
//! | [`Wrapper`] | 这层外壳剥掉之后是什么 | 0..1 个 |
//!
//! 为什么必须分层，而不是按 scheme 一张大表：`https://x/a.m3u8` 与
//! `https://x/a.iso` 的传输层完全一样，但前者是"清单 + 每片一次独立 GET"，
//! 没有跨分片的随机读，镜像并发也无意义；反过来 `sftp://` 与 `ftp://` 都是
//! "单主机拉文件"，但 SFTP 协议本身没有随机区间读，只能顺序整段读。
//! 任何"是 HTTP 就什么都能干"的假设会同时错这两类，所以能力由
//! **传输层 + 清单层**共同决定，见 [`capabilities_for`]。
//!
//! 这里描述的是**协议允许的上限**，不是引擎当前的实现状态，也不是"这次一定行"：
//! `segment = true` 只表示该协议允许 Range 请求，是否真的分片要运行时探测
//! `206 Partial Content` / `Accept-Ranges`。
//!
//! 本模块**不依赖 `aidm-ipc`**（依赖方向是 ipc → core），所以 URL 形态判定
//! 在这里按前缀自己实现；形状校验（magnet 的 BTIH 位数、ed2k 链接字段完整性）
//! 仍留在 `aidm-ipc::validate`，本模块只做"这是什么协议"的分类。

/// 传输协议：怎么取字节。一个任务恰好有一个。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Http,
    Https,
    Ftp,
    Ftps,
    Sftp,
    BitTorrent,
    Ed2k,
    Quic,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Http => "http",
            Transport::Https => "https",
            Transport::Ftp => "ftp",
            Transport::Ftps => "ftps",
            Transport::Sftp => "sftp",
            Transport::BitTorrent => "bittorrent",
            Transport::Ed2k => "ed2k",
            Transport::Quic => "quic",
        }
    }
}

impl Transport {
    /// 与 [`crate::model::Status::from_str`] 保持同一套写法：只认自己写出的字面量
    /// （大小写敏感），未知输入返回 `None` 而不是兜底值——能力模型里"猜一个协议"
    /// 比"承认不认识"危险得多。
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "http" => Transport::Http,
            "https" => Transport::Https,
            "ftp" => Transport::Ftp,
            "ftps" => Transport::Ftps,
            "sftp" => Transport::Sftp,
            "bittorrent" => Transport::BitTorrent,
            "ed2k" => Transport::Ed2k,
            "quic" => Transport::Quic,
            _ => return None,
        })
    }
}

/// 资源接口：取到的是不是一个"完整文件"。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// 一个字节流就是一个文件（最常见的形态）。
    PlainFile,
    /// WebDAV 挂在 HTTP 之上，但对端是"文件系统"而不是"一个文件"。
    WebDav,
    /// 对象存储（S3 及同类）：键值语义，没有目录与续传承诺，能力仍按 HTTP 算。
    S3Object,
    /// HLS：清单 + 一串独立分片。
    Hls,
    /// DASH：同 HLS，分片描述换成 MPD。
    Dash,
}

impl Resource {
    pub fn as_str(self) -> &'static str {
        match self {
            Resource::PlainFile => "plain_file",
            Resource::WebDav => "webdav",
            Resource::S3Object => "s3_object",
            Resource::Hls => "hls",
            Resource::Dash => "dash",
        }
    }
}

impl Resource {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "plain_file" => Resource::PlainFile,
            "webdav" => Resource::WebDav,
            "s3_object" => Resource::S3Object,
            "hls" => Resource::Hls,
            "dash" => Resource::Dash,
            _ => return None,
        })
    }
}

/// 清单格式：需要先解析才知道下什么。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manifest {
    /// Metalink（RFC 5854 / 3.0）：整文件哈希 + 镜像列表。
    Metalink,
    /// HLS 播放列表。
    M3u8,
    /// DASH 媒体描述。
    Mpd,
    /// zsync：用远端 `.zsync` 里的块校验和做增量。
    Zsync,
    /// 种子文件（`.torrent`）：里面才列出真正要下的内容。
    Torrent,
}

impl Manifest {
    pub fn as_str(self) -> &'static str {
        match self {
            Manifest::Metalink => "metalink",
            Manifest::M3u8 => "m3u8",
            Manifest::Mpd => "mpd",
            Manifest::Zsync => "zsync",
            Manifest::Torrent => "torrent",
        }
    }
}

impl Manifest {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "metalink" => Manifest::Metalink,
            "m3u8" => Manifest::M3u8,
            "mpd" => Manifest::Mpd,
            "zsync" => Manifest::Zsync,
            "torrent" => Manifest::Torrent,
            _ => return None,
        })
    }
}

/// 链接封装：只是外壳，剥掉后是别的协议。
///
/// 变体按载荷格式命名；`as_str` 给出的是外部 scheme 的规范名，
/// 属于互操作契约，不能随内部命名调整。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrapper {
    /// 专用链：Base64(`AA<真实 URL>ZZ`)。
    Delimited,
    /// 早期专用链：载荷格式与 `Delimited` 相同。
    DelimitedLegacy,
    /// 裸地址封装：Base64(`<真实 URL>`)。
    Raw,
    /// 带标记的地址封装：Base64(`[TAG]<真实 URL>[TAG]`)。
    Tagged,
    /// 网盘资源标识：`<哈希>|<文件名>|<字节数>`，不是直链。
    DiskRef,
}

impl Wrapper {
    /// 外部 scheme 的规范名（协议值，不可更改）。
    pub fn as_str(self) -> &'static str {
        match self {
            Wrapper::Delimited => "thunder",
            Wrapper::DelimitedLegacy => "thunders",
            Wrapper::Raw => "qqdl",
            Wrapper::Tagged => "flashget",
            Wrapper::DiskRef => "fs2you",
        }
    }
}

impl Wrapper {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "thunder" => Wrapper::Delimited,
            "thunders" => Wrapper::DelimitedLegacy,
            "qqdl" => Wrapper::Raw,
            "flashget" => Wrapper::Tagged,
            "fs2you" => Wrapper::DiskRef,
            _ => return None,
        })
    }
}

/// 一个协议组合允许的能力集合。
///
/// 每个字段都是"协议层面是否可能"，不是"这次运行是否可用"：真正的可用性取决于
/// 服务端响应（`Accept-Ranges` / 206）、对端是否在线等运行时事实。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// 能否暂停（暂停后任务状态与已下数据都能保住）。
    pub pause: bool,
    /// 能否续传（下次接着上次的偏移继续）。
    pub resume: bool,
    /// 能否把一份内容拆成并行分片。
    pub segment: bool,
    /// 能否在已下载范围内随机定位（边下边播、按块校验都靠它）。
    pub seek: bool,
    /// 能否同时/轮换使用多个来源（镜像、备用地址、P2P 节点）。
    pub multi_source: bool,
    /// 是否需要先解析一份清单文档。
    pub manifest: bool,
    /// 能否做端到端完整性校验（哈希/分片哈希）。
    pub verify: bool,
    /// 下载完成后能否继续为别人提供数据（做种）。
    pub seed: bool,
}

/// 运行期观测到的**降级事实**：协议上界允许，但这一次实际没做到。
///
/// 取值与 `worker` 写进 `degrade_single` 事件的原因字符串一一对应（见
/// [`Degrade::from_reason`]）。刻意只收录"能被观测证明"的几种，而不是把
/// `Capabilities` 再抄一份 —— 抄一份就又成了一个会漂移的上界。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Degrade {
    /// 服务端不支持按范围取（探测没拿到 `206` + 合法 `Content-Range`）。
    NoRange,
    /// 长度未知：分不清第几段从哪开始。
    UnknownSize,
    /// 内容太小、够不上最小段长 —— **这不是协议能力问题**，是这次的内容小。
    MinSegment,
}

impl Degrade {
    /// 从 `degrade_single` 事件的原因串还原；认不出返回 `None`。
    ///
    /// 认不出时**不猜**：猜错会凭空砍掉一个其实可用的能力。
    pub fn from_reason(raw: &str) -> Option<Self> {
        // 事件里是 `reason=no_range` 这种键值形态，也可能只有裸值。
        let v = raw
            .split_whitespace()
            .find_map(|kv| kv.strip_prefix("reason="))
            .unwrap_or(raw)
            .trim();
        match v {
            "no_range" => Some(Degrade::NoRange),
            "unknown_size" => Some(Degrade::UnknownSize),
            "min_segment" => Some(Degrade::MinSegment),
            _ => None,
        }
    }

    /// 该降级对用户可见的解释。**必须能解释"为什么没分段"**，否则界面只能显示
    /// 一个比协议上界更弱的能力值而说不出原因。
    pub fn note(self) -> &'static str {
        match self {
            Degrade::NoRange => "实测：该来源不支持按范围取（未返回 206），本次按单连接下载",
            Degrade::UnknownSize => "实测：长度未知，无法划分分片，本次按单连接下载",
            Degrade::MinSegment => "实测：内容小于最小段长，本次按单连接下载（不是协议能力问题）",
        }
    }
}

/// 用运行期观测**收窄**协议上界。
///
/// 三条不变量：
/// 1. **只减不增**：收窄永远不会把上界为 `false` 的能力变成 `true`（否则"实测"就成了
///    凭空赋予能力，而它恰恰是最没有权威的那一层）。
/// 2. **未知不等于不支持**：没有观测（或认不出的原因）时原样返回上界。
/// 3. **只砍与观测直接相关的位**：`NoRange`/`UnknownSize` 砍 `segment` 与 `seek`
///    （"分片"和"在已下范围内随机定位"都依赖按范围取）；`MinSegment` 什么都不砍。
///    `resume` 刻意**不砍** —— 它不是只有 Range 一条实现路径（FTP 用 `REST`、
///    清单型按分片序号续传），砍掉会把别的路径的能力一起误伤。
pub fn narrow(upper: Capabilities, degrade: Option<Degrade>) -> Capabilities {
    match degrade {
        Some(Degrade::NoRange) | Some(Degrade::UnknownSize) => Capabilities {
            segment: false,
            seek: false,
            ..upper
        },
        Some(Degrade::MinSegment) | None => upper,
    }
}

/// 一次地址解析 + 运行期收窄的完整结果。
pub fn narrow_by_reason(upper: Capabilities, reason: Option<&str>) -> Capabilities {
    narrow(upper, reason.and_then(Degrade::from_reason))
}

/// 一个地址的四层结论 + 由此推出的能力。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolProfile {
    pub transport: Transport,
    pub resource: Resource,
    pub manifest: Option<Manifest>,
    /// 最外层封装（用户看到的那一层）；非封装地址为 `None`。
    pub wrapper: Option<Wrapper>,
    pub capabilities: Capabilities,
    /// 解码器给出的补充说明（例如该封装依赖的服务已停运）。
    ///
    /// 多出来的这一个字段是刻意的：`fs2you://` 这类封装能识别、能给出传输层结论，
    /// 但"下不了"这个事实没有别的字段能承载，丢掉它等于把可用性谎报成可用。
    pub note: Option<String>,
}

/// 识别链接封装（外壳）方案。前缀大小写不敏感，长短前缀各自精确匹配。
///
/// 前缀表与 [`crate::link_decode`] 内部的那张表必须一致：那里只回答"是不是封装"，
/// 这里还要回答"是哪一种"，所以各存一份；`wrapper_prefixes_stay_in_sync_with_link_decode`
/// 测试盯着这个不变量。
pub fn wrapper_of(raw: &str) -> Option<Wrapper> {
    let s = raw.trim();
    for (prefix, wrapper) in [
        ("thunder://", Wrapper::Delimited),
        ("thunders://", Wrapper::DelimitedLegacy),
        ("qqdl://", Wrapper::Raw),
        ("flashget://", Wrapper::Tagged),
        ("fs2you://", Wrapper::DiskRef),
    ] {
        // 用 `get(..n)` 而不是切片下标：非 ASCII 开头时按字节切会 panic。
        if s.get(..prefix.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        {
            return Some(wrapper);
        }
    }
    None
}

/// 判定顺序即优先级：**封装 → 传输 → 资源/清单 → 能力**。
///
/// 顺序不能换：封装串本身看不出载荷协议（封装里可能包着 ed2k、magnet 或 https），
/// 必须先剥壳拿到真实地址；资源/清单层只能对真实地址判，否则封装里的 `.m3u8`
/// 会被当成普通 HTTP 文件。无法识别时返回 `None`——不给兜底协议。
pub fn detect(raw: &str) -> Option<ProtocolProfile> {
    let unwrapped = unwrap_chain(raw)?;
    let transport = match unwrapped.address.as_deref() {
        Some(address) => transport_of_plain(address)?,
        // 网盘资源标识没有可判定的地址；该服务已停运，传输层按 HTTP 记录，
        // 并把不可用原因经 `note` 带出去。
        None => Transport::Http,
    };
    let (resource, manifest) = match unwrapped.address.as_deref() {
        Some(address) => classify(address),
        None => (Resource::PlainFile, None),
    };
    Some(ProtocolProfile {
        transport,
        resource,
        manifest,
        wrapper: unwrapped.wrapper,
        capabilities: capabilities_for(transport, resource, manifest),
        note: unwrapped.note,
    })
}

/// 只要传输层结论（封装会被穿透，含没有直链的网盘资源标识）。
pub fn transport_of_url(raw: &str) -> Option<Transport> {
    let unwrapped = unwrap_chain(raw)?;
    match unwrapped.address.as_deref() {
        Some(address) => transport_of_plain(address),
        None => Some(Transport::Http),
    }
}

/// 按 **传输层 + 清单层** 推出能力。每一条的判据都写在下面，别删注释。
///
/// 注意签名里只有 `manifest` 没有 `resource`：HLS/DASH 这两个"资源不是完整文件"
/// 的情形，恰好各自对应一个清单格式（`.m3u8` / `.mpd`），所以清单层足以表达
/// "分片各自独立、清单即唯一来源列表"这两个后果。资源层与清单层在这一档上是
/// 同一事实的两种写法，不是重复建模。
pub fn capabilities_for(
    transport: Transport,
    resource: Resource,
    manifest: Option<Manifest>,
) -> Capabilities {
    use Resource::{Dash, Hls};
    use Transport::{BitTorrent, Ed2k, Ftp, Ftps, Http, Https, Quic, Sftp};

    // 分片媒体（HLS/DASH）：每片一次独立 GET，没有跨分片的随机读语义；
    // 清单本身又已经是完整的来源列表，镜像并发没有意义。
    //
    // 这里判 `resource` 而不是 `manifest == M3u8|Mpd`：两者在现实中确实总一起出现，
    // 但"资源不是完整文件"是**资源层**的事实，清单只是它的载体 —— 用资源层表达，
    // 将来出现"没有清单的分片资源"时才不用改判据。
    let chunked_media = matches!(resource, Hls | Dash);
    // "协议允许随机区间读"的传输族：HTTP Range、FTP REST、QUIC 流偏移都在此列。
    // 这是**上限**：HTTP 是否真支持要运行时探测 206 / `Accept-Ranges`。
    let range_capable = matches!(transport, Http | Https | Ftp | Ftps | Quic);
    // HTTP/FTP 系：暂停/续传完全依赖区间读（没有 Range 就没有断点位置可存）。
    let http_family = matches!(transport, Http | Https | Ftp | Ftps);
    // P2P：分片是协议内建，分片位图本身就是断点记录，也天然有多个数据来源。
    let p2p = matches!(transport, BitTorrent | Ed2k);

    // SFTP 不在 range_capable 里，**但理由不是"协议不能按偏移读"** ——
    // `SSH_FXP_READ(handle, offset, len)` 恰恰是带偏移的，这一点必须写清楚，
    // 否则以后会有人据此认为 SFTP 分片是免费的。真正的两点是：
    //   ① 没有 `Accept-Ranges` / 206 那样的**可发现性**：下载前无从判断对端支持什么；
    //   ② 实践上是一个 SSH 通道串行发请求，开多通道并发读不是通行做法。
    // 所以取**保守值**：宁可不开分片，也不把对端未必接受的假设变成默认行为。
    let segment = range_capable || p2p;
    // "能存下断点位置" ⟺ "能按偏移重新开始读"：P2P 靠分片位图；SFTP 能用偏移
    // 续传（这是**约定能力**：协议允许按偏移读，能否真的接上还要服务端配合）；
    // 其余能按偏移读的传输族（HTTP/FTP 系与 QUIC 流偏移）一律随 `segment`。
    // 三个分支合起来覆盖了本枚举全部 8 个传输，所以 pause/resume 当前恒为 true。
    //
    // **这是刻意的，但要知道它的含义**：本结构描述的是**协议允许的上限**，
    // 不是"这个任务现在真的能暂停"。运行时是否可暂停还要看探测结果
    // （HTTP 没有 206 就没有断点位置可存）。调用方若要用它控制按钮可用性，
    // 必须先用运行时探测结果**收窄**一次，不能直接拿 true 当"已确认可暂停"。
    let resumable = p2p || transport == Sftp || (range_capable && segment);

    Capabilities {
        pause: resumable,
        resume: resumable,
        segment,
        // 随机定位只有 HTTP/FTP 系有；HLS/DASH 的"位置"是第几个分片，
        // 不存在跨分片的随机读，所以分片媒体一律 false。
        seek: http_family && !chunked_media,
        // 镜像/备用地址（HTTP 系）与 P2P 节点都算多来源；分片媒体是唯一来源列表，
        // 所以为 false。SFTP/QUIC 本模型不假设有镜像。
        //
        // `Resource::S3Object` 走 HTTPS 因而天然落在 `http_family` 里 —— 它确实
        // 是多来源（多 endpoint / 多 region），所以结论不变；但要注意**每个来源
        // 都要各自签名**，"随手换个 host 就下"在 S3 上不成立。能力位不表达签名，
        // 取回路径由调用方按 `resource` 决定（见 `docs/protocol-capabilities.md` §1）。
        multi_source: (http_family || p2p) && !chunked_media,
        // 清单层字段就是"清单层是否非空"，不再重复判协议。
        manifest: manifest.is_some(),
        // 端到端校验：HTTP/FTP 系靠调用方给的哈希（metalink/`Content-MD5`）或
        // 长度 + `ETag`，BT/eD2k 有分片哈希，QUIC 按 HTTP 同族处理。
        // SFTP 只有传输层加密，没有内容校验值，默认校验不了。
        verify: matches!(
            transport,
            Http | Https | Ftp | Ftps | BitTorrent | Ed2k | Quic
        ),
        // 只有 P2P 协议在下载完成后还能为别人提供数据。
        seed: p2p,
    }
}

/// 封装最多剥几层。单层是常态；设上限是为了让构造出来的自嵌套链接
/// 变成"不认识的地址"，而不是把栈/CPU 拖住。
const MAX_WRAPPER_DEPTH: usize = 4;

struct Unwrapped {
    /// 最内层地址；`fs2you://` 这类没有直链的服务为 `None`。
    address: Option<String>,
    /// 最外层封装 —— 用户看到的、界面上该显示的那一层。
    wrapper: Option<Wrapper>,
    note: Option<String>,
}

/// 剥掉全部封装层。载荷解不开（前缀对但 Base64 非法）时返回 `None`：
/// 宁可承认"不认识这个地址"，也不要猜一个协议出来。
fn unwrap_chain(raw: &str) -> Option<Unwrapped> {
    let mut current = raw.trim().to_string();
    if current.is_empty() {
        return None;
    }
    let mut wrapper = None;
    let mut note = None;
    for _ in 0..MAX_WRAPPER_DEPTH {
        let Some(layer) = wrapper_of(&current) else {
            break;
        };
        if wrapper.is_none() {
            wrapper = Some(layer);
        }
        let decoded = crate::link_decode::decode_link(&current).ok().flatten()?;
        if note.is_none() {
            note = decoded.note;
        }
        match decoded.url {
            Some(url) => current = url,
            None => {
                return Some(Unwrapped {
                    address: None,
                    wrapper,
                    note,
                })
            }
        }
    }
    if wrapper_of(&current).is_some() {
        // 到层数上限还套着封装：自嵌套或恶意构造，不判。
        return None;
    }
    Some(Unwrapped {
        address: Some(current),
        wrapper,
        note,
    })
}

/// 传输层判定：只看 scheme（外加 `.torrent` 这个"取回来交给 BT"的特例）。
///
/// 形状校验不在这里：`magnet:` 是否带合法 BTIH 由 `aidm-ipc::validate` 负责，
/// 本函数只回答"这是哪个协议"。
fn transport_of_plain(address: &str) -> Option<Transport> {
    let lower = address.trim().to_ascii_lowercase();
    // magnet 把 info hash 直接带在链接里，本身就是 BT 任务。
    if lower.starts_with("magnet:") {
        return Some(Transport::BitTorrent);
    }
    // eD2k 必须先判：`ed2k://|file|x.torrent|…` 的文件名可能以 .torrent 结尾，
    // 但那是"一个叫 x.torrent 的 eD2k 文件"，真正搬字节的是 eD2k。
    if lower.starts_with("ed2k://") {
        return Some(Transport::Ed2k);
    }
    // `.torrent` 必须早于 http(s)：种子文件确实是用 HTTP 取回来的，
    // 但任务的传输层是 BitTorrent（后续字节由 BT 搬），清单层是 Torrent。
    if path_lower(&lower).ends_with(".torrent") {
        return Some(Transport::BitTorrent);
    }
    for (prefix, transport) in [
        ("https://", Transport::Https),
        ("ftps://", Transport::Ftps),
        ("http://", Transport::Http),
        ("ftp://", Transport::Ftp),
        ("sftp://", Transport::Sftp),
        ("quic://", Transport::Quic),
        // WebDAV 与对象存储是 HTTP 之上的接口约定，传输层仍是 HTTP(S)；
        // 客户端无法在 URL 里看出普通 HTTPS 其实是个 WebDAV 挂载点，
        // 所以只认显式 scheme。
        ("davs://", Transport::Https),
        ("webdavs://", Transport::Https),
        ("dav://", Transport::Http),
        ("webdav://", Transport::Http),
        ("s3://", Transport::Https),
    ] {
        if lower.starts_with(prefix) {
            return Some(transport);
        }
    }
    None
}

/// 资源接口与清单格式判定。扩展名看**路径**，大小写不敏感，忽略 `?query` 与 `#fragment`。
fn classify(address: &str) -> (Resource, Option<Manifest>) {
    let lower = address.trim().to_ascii_lowercase();
    let resource = if lower.starts_with("dav://")
        || lower.starts_with("davs://")
        || lower.starts_with("webdav://")
        || lower.starts_with("webdavs://")
    {
        Resource::WebDav
    } else if lower.starts_with("s3://") {
        Resource::S3Object
    } else {
        Resource::PlainFile
    };

    let path = path_lower(address);
    let manifest = if path.ends_with(".m3u8") {
        Some(Manifest::M3u8)
    } else if path.ends_with(".mpd") {
        Some(Manifest::Mpd)
    } else if path.ends_with(".metalink") || path.ends_with(".meta4") {
        Some(Manifest::Metalink)
    } else if path.ends_with(".zsync") {
        Some(Manifest::Zsync)
    } else if path.ends_with(".torrent") {
        Some(Manifest::Torrent)
    } else {
        None
    };

    // 清单层反过来决定资源层：HLS/DASH 取到的不是"一个文件"，而是清单 + 分片。
    // `.metalink` / `.zsync` / `.torrent` 则相反——它们本身就是一个要下载的文件，
    // 只是描述的内容还需要再解析一层，资源层仍是 PlainFile。
    let resource = match manifest {
        Some(Manifest::M3u8) => Resource::Hls,
        Some(Manifest::Mpd) => Resource::Dash,
        _ => resource,
    };
    (resource, manifest)
}

/// 取地址里"路径"部分的**小写**副本，供扩展名判定用。
///
/// 两个坑：① `?token=1` / `#frag` 之后的内容与文件名无关，必须丢；
/// ② 授权部分（`host:port`）不是路径——`http://x.m3u8/` 的主机名带点号，
/// 若不切掉就会被误判成清单地址。
fn path_lower(address: &str) -> String {
    let s = address.trim();
    let head = s.split(['?', '#']).next().unwrap_or("");
    let path = match head.find("://") {
        Some(i) => {
            let rest = &head[i + 3..];
            match rest.find('/') {
                Some(j) => &rest[j..],
                // 没有 `/`：整个剩余部分是授权部分，没有路径可言。
                None => "",
            }
        }
        // 没有 scheme 的裸文件名（本地/相对地址入口）按整串当路径。
        None => head,
    };
    path.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- 测试辅助 ---------------------------------------------------------

    /// 标准 Base64 编码。生产侧只需要解码，`link_decode` 没有公开编码器；
    /// 测试自备一个，好过手抄一串容易出错的字面量。
    fn b64(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(TABLE[(n >> 18) as usize & 63] as char);
            out.push(TABLE[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                TABLE[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    fn delimited(url: &str) -> String {
        format!("thunder://{}", b64(format!("AA{url}ZZ").as_bytes()))
    }

    fn delimited_legacy(url: &str) -> String {
        format!("thunders://{}", b64(format!("AA{url}ZZ").as_bytes()))
    }

    fn raw_wrapped(url: &str) -> String {
        format!("qqdl://{}", b64(url.as_bytes()))
    }

    fn tagged(url: &str) -> String {
        format!(
            "flashget://{}",
            b64(format!("[FLASHGET]{url}[FLASHGET]").as_bytes())
        )
    }

    const ED2K: &str = "ed2k://|file|a.iso|1024|0123456789abcdef0123456789abcdef|/";
    const MAGNET: &str = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567";

    // ---- 1. 链接封装层 ----------------------------------------------------

    #[test]
    fn wrapper_prefixes_stay_in_sync_with_link_decode() {
        // 前缀表在两处各有一份（link_decode 只要"是不是封装"，这里还要知道是哪一种）。
        // 这条断言保证两边不会悄悄漂移：任何一边漏掉一个 scheme 都会红。
        for prefix in [
            "thunder://",
            "thunders://",
            "qqdl://",
            "flashget://",
            "fs2you://",
        ] {
            assert!(
                crate::link_decode::is_wrapped_scheme(prefix),
                "{prefix} 应被 link_decode 认作封装"
            );
            assert!(
                wrapper_of(prefix).is_some(),
                "{prefix} 应有对应的 Wrapper 变体"
            );
        }
        // 大小写不敏感，且长短前缀互不吃掉。
        assert_eq!(wrapper_of("THUNDER://xxx"), Some(Wrapper::Delimited));
        assert_eq!(wrapper_of("Thunders://xxx"), Some(Wrapper::DelimitedLegacy));
    }

    #[test]
    fn all_five_wrappers_are_classified_and_payload_transport_resolved() {
        // 专用链包 ed2k：外壳与真实传输层各归各位。
        let p = detect(&delimited(ED2K)).expect("专用链封装应被识别");
        assert_eq!(p.wrapper, Some(Wrapper::Delimited));
        assert_eq!(p.transport, Transport::Ed2k);
        assert!(p.capabilities.seed, "eD2k 载荷应保留做种能力");
        assert_eq!(p.note, None);

        let p = detect(&delimited_legacy("http://example.com/a.iso"))
            .expect("早期封装应被识别");
        assert_eq!(p.wrapper, Some(Wrapper::DelimitedLegacy));
        assert_eq!(p.transport, Transport::Http);
        assert_eq!(p.resource, Resource::PlainFile);

        let p = detect(&raw_wrapped("ftp://example.com/a.iso")).expect("裸地址封装应被识别");
        assert_eq!(p.wrapper, Some(Wrapper::Raw));
        assert_eq!(p.transport, Transport::Ftp);

        let p = detect(&tagged("https://example.com/a.iso")).expect("带标记封装应被识别");
        assert_eq!(p.wrapper, Some(Wrapper::Tagged));
        assert_eq!(p.transport, Transport::Https);

        // 封装里包清单：资源/清单层要对**载荷**判，而不是对外壳串判。
        let p = detect(&raw_wrapped("https://cdn.example.com/live/a.M3U8?t=9"))
            .expect("裸地址封装应被识别");
        assert_eq!(p.transport, Transport::Https);
        assert_eq!(p.resource, Resource::Hls);
        assert_eq!(p.manifest, Some(Manifest::M3u8));
        assert!(!p.capabilities.seek);

        // 网盘资源标识不是地址：外壳认出来了，传输层只能记 HTTP，并且必须把
        // "服务已停运"带出来，不能谎报成可用。
        let raw = format!(
            "fs2you://{}",
            b64(b"0123456789abcdef0123456789abcdef|a.iso|1024")
        );
        let p = detect(&raw).expect("网盘资源标识应被识别");
        assert_eq!(p.wrapper, Some(Wrapper::DiskRef));
        assert_eq!(p.transport, Transport::Http);
        assert!(p
            .note
            .as_deref()
            .is_some_and(|n| n.contains("停运") && n.contains("a.iso")));
    }

    // ---- 2. 资源 / 清单层：大小写 + query/fragment -------------------------

    #[test]
    fn manifest_detection_ignores_case_query_and_fragment() {
        let p = detect("HTTPS://X/A.M3U8?t=1").expect("大写 scheme 与扩展名都要认");
        assert_eq!(p.transport, Transport::Https);
        assert_eq!(p.resource, Resource::Hls);
        assert_eq!(p.manifest, Some(Manifest::M3u8));

        let p = detect("http://x/a.M3U8#frag").unwrap();
        assert_eq!(
            (p.resource, p.manifest),
            (Resource::Hls, Some(Manifest::M3u8))
        );

        let p = detect("http://x/live.mpd?tok=2#t").unwrap();
        assert_eq!(
            (p.resource, p.manifest),
            (Resource::Dash, Some(Manifest::Mpd))
        );

        let p = detect("http://x/a.metalink").unwrap();
        assert_eq!(
            (p.resource, p.manifest),
            (Resource::PlainFile, Some(Manifest::Metalink))
        );
        assert_eq!(
            detect("http://x/a.META4").unwrap().manifest,
            Some(Manifest::Metalink)
        );
        assert_eq!(
            detect("http://x/a.zsync").unwrap().manifest,
            Some(Manifest::Zsync)
        );

        // 主机名带 `.m3u8` 不算清单：那是授权部分，不是路径。
        let p = detect("http://x.m3u8/y.iso").unwrap();
        assert_eq!((p.resource, p.manifest), (Resource::PlainFile, None));

        // path_lower 是判定底座，直接对它断言，把裸文件名与 query 的两种形态钉死。
        assert_eq!(path_lower("a.M3U8#f"), "a.m3u8");
        assert_eq!(path_lower("x.iso?token=1"), "x.iso");
        assert_eq!(path_lower("http://x.m3u8/y.iso?q=1#z"), "/y.iso");
        assert_eq!(path_lower("https://x/a.iso"), "/a.iso");
    }

    // ---- 3. magnet / .torrent 都归 BitTorrent ------------------------------

    #[test]
    fn magnet_and_torrent_file_are_bittorrent_tasks() {
        let p = detect(MAGNET).expect("magnet 应被识别");
        assert_eq!(p.transport, Transport::BitTorrent);
        // magnet 把 info hash 直接带在链接里，没有"要先解析的文档"，清单层为空。
        assert_eq!(p.manifest, None);
        assert!(p.capabilities.seed && p.capabilities.pause && p.capabilities.resume);

        let p = detect("http://x/a.torrent").expect("种子文件地址应被识别");
        assert_eq!(p.transport, Transport::BitTorrent);
        assert_eq!(p.manifest, Some(Manifest::Torrent));
        assert!(p.capabilities.seed && p.capabilities.manifest);
        // 取种子走 HTTP，但任务的重试/续传语义是 BT 的，所以传输层不能是 Http。
        assert_ne!(p.transport, Transport::Http);

        assert_eq!(
            transport_of_url("https://x/a.TORRENT?u=1#f"),
            Some(Transport::BitTorrent)
        );

        // eD2k 里一个叫 `x.torrent` 的文件仍是 eD2k 任务（判定顺序不能反）。
        let ed2k_torrent = "ed2k://|file|x.torrent|99|0123456789abcdef0123456789abcdef|/";
        assert_eq!(transport_of_url(ed2k_torrent), Some(Transport::Ed2k));
    }

    // ---- 4. 能力矩阵：反例是重点 -------------------------------------------

    /// 这三条是**防止"假设所有协议能力一致"**的回归测试：能力模型一旦被简化成
    /// "按 scheme 查一张大表"或"都返回 true"，它们必须红。
    #[test]
    fn capability_model_must_not_be_uniform() {
        // 反例一：SFTP 不开分片。**理由不是"协议不能按偏移读"**（`SSH_FXP_READ`
        // 就带偏移），而是没有 `Accept-Ranges` 那种可发现性、且实践上单通道串行。
        let sftp = capabilities_for(Transport::Sftp, Resource::PlainFile, None);
        assert!(
            !sftp.segment,
            "SFTP 取保守值不分片：无可发现性 + 实践上单通道串行"
        );
        assert!(sftp.pause && sftp.resume, "SFTP 可用偏移续传（约定能力）");

        // 反例二：HLS 的分片是各自独立的 GET → 不存在跨分片的随机读。
        // 判据落在 `resource` 上，所以这里必须给 `Resource::Hls`。
        let hls = capabilities_for(Transport::Https, Resource::Hls, Some(Manifest::M3u8));
        assert!(!hls.seek, "HLS 没有跨分片的随机读语义");
        assert!(hls.segment, "HLS 仍然分片并发下载");

        // 反例三：清单本身就是唯一来源列表 → 没有"多来源"可并发。
        assert!(!hls.multi_source, "HLS 的来源由清单唯一确定");
        let dash = capabilities_for(Transport::Https, Resource::Dash, Some(Manifest::Mpd));
        assert!(!dash.seek && !dash.multi_source && dash.segment);
    }

    #[test]
    fn capability_matrix_matches_protocol_facts() {
        // HTTP 系：Range + 镜像 + 校验都在协议里；没有清单，也不做种。
        for t in [
            Transport::Http,
            Transport::Https,
            Transport::Ftp,
            Transport::Ftps,
        ] {
            assert_eq!(
                capabilities_for(t, Resource::PlainFile, None),
                Capabilities {
                    pause: true,
                    resume: true,
                    segment: true,
                    seek: true,
                    multi_source: true,
                    manifest: false,
                    verify: true,
                    seed: false,
                },
                "{t:?} 的能力矩阵与协议事实不符"
            );
        }

        // SFTP：能暂停/续传，其余全否（verify 无内容校验值）。
        assert_eq!(
            capabilities_for(Transport::Sftp, Resource::PlainFile, None),
            Capabilities {
                pause: true,
                resume: true,
                segment: false,
                seek: false,
                multi_source: false,
                manifest: false,
                verify: false,
                seed: false,
            }
        );

        // HTTP + metalink：清单层为真，但它是"一个文件"，所以 seek 不受影响
        // ——只有分片媒体（resource 为 Hls/Dash）才把 seek/multi_source 关掉。
        let metalink = capabilities_for(
            Transport::Http,
            Resource::PlainFile,
            Some(Manifest::Metalink),
        );
        assert!(metalink.manifest && metalink.seek && metalink.multi_source);

        // S3 对象同样走 HTTP 传输，所以能力位与普通文件一致；差别在**取回路径**
        // 要签名，那不是能力位能表达的，由调用方按 `resource` 分支。
        assert_eq!(
            capabilities_for(Transport::Https, Resource::S3Object, None),
            capabilities_for(Transport::Https, Resource::PlainFile, None),
            "S3 对象的能力上限与普通 HTTPS 文件相同（签名是取回路径的事，不是能力）"
        );

        // P2P：分片内建、位图即断点、有分片哈希、下载完能做种；不做跨文件的随机读。
        for t in [Transport::BitTorrent, Transport::Ed2k] {
            assert_eq!(
                capabilities_for(t, Resource::PlainFile, None),
                Capabilities {
                    pause: true,
                    resume: true,
                    segment: true,
                    seek: false,
                    multi_source: true,
                    manifest: false,
                    verify: true,
                    seed: true,
                },
                "{t:?} 的能力矩阵与协议事实不符"
            );
        }
        assert!(
            capabilities_for(
                Transport::BitTorrent,
                Resource::PlainFile,
                Some(Manifest::Torrent)
            )
            .manifest
        );

        // QUIC：流偏移允许分片与续传；本模型不假设它有镜像，也不给随机定位。
        assert_eq!(
            capabilities_for(Transport::Quic, Resource::PlainFile, None),
            Capabilities {
                pause: true,
                resume: true,
                segment: true,
                seek: false,
                multi_source: false,
                manifest: false,
                verify: true,
                seed: false,
            }
        );
    }

    // ---- 5. 未知 scheme ---------------------------------------------------

    #[test]
    fn unknown_or_unusable_input_yields_none() {
        assert_eq!(detect("gopher://x/1"), None);
        assert_eq!(transport_of_url("gopher://x/1"), None);
        assert_eq!(detect(""), None);
        assert_eq!(detect("   "), None);
        assert_eq!(detect("这不是地址"), None);
        // 前缀像封装但载荷解不开：宁可 None，也不要猜一个协议出来。
        assert_eq!(detect("thunder://not-base64!!!?"), None);
        assert_eq!(transport_of_url("qqdl://%%%"), None);
    }

    #[test]
    fn webdav_and_object_storage_ride_on_http_transport() {
        let dav = detect("davs://dav.example.com/pub/a.iso").expect("davs 应被识别");
        assert_eq!(dav.transport, Transport::Https);
        assert_eq!(dav.resource, Resource::WebDav);
        assert!(dav.capabilities.segment && dav.capabilities.seek);

        let dav = detect("dav://dav.example.com/pub/a.iso").unwrap();
        assert_eq!(dav.transport, Transport::Http);
        assert_eq!(dav.resource, Resource::WebDav);

        let s3 = detect("s3://bucket/key/a.iso").expect("s3 应被识别");
        assert_eq!(s3.transport, Transport::Https);
        assert_eq!(s3.resource, Resource::S3Object);
    }

    #[test]
    fn enum_strings_round_trip_and_reject_unknown() {
        for t in [
            Transport::Http,
            Transport::Https,
            Transport::Ftp,
            Transport::Ftps,
            Transport::Sftp,
            Transport::BitTorrent,
            Transport::Ed2k,
            Transport::Quic,
        ] {
            assert_eq!(Transport::from_str(t.as_str()), Some(t));
        }
        for r in [
            Resource::PlainFile,
            Resource::WebDav,
            Resource::S3Object,
            Resource::Hls,
            Resource::Dash,
        ] {
            assert_eq!(Resource::from_str(r.as_str()), Some(r));
        }
        for m in [
            Manifest::Metalink,
            Manifest::M3u8,
            Manifest::Mpd,
            Manifest::Zsync,
            Manifest::Torrent,
        ] {
            assert_eq!(Manifest::from_str(m.as_str()), Some(m));
        }
        for w in [
            Wrapper::Delimited,
            Wrapper::DelimitedLegacy,
            Wrapper::Raw,
            Wrapper::Tagged,
            Wrapper::DiskRef,
        ] {
            assert_eq!(Wrapper::from_str(w.as_str()), Some(w));
        }
        // 与 `Status::from_str` 一致：大小写敏感，未知不给兜底值。
        assert_eq!(Transport::from_str("carrier-pigeon"), None);
        assert_eq!(Transport::from_str("HTTP"), None);
        assert_eq!(Resource::from_str(""), None);
        assert_eq!(Manifest::from_str("M3U8"), None);
        assert_eq!(Wrapper::from_str("Delimited"), None);
    }

    /// 运行期收窄：**只减不增**，认不出就原样。
    ///
    /// 这条守的是"能力模型的两层不能混"：上界说"协议上可能"，收窄说"这一次实测如何"。
    /// 混了的表现是界面显示一个下不动的能力（把上界当真），或者把一次网络抖动永久记成
    /// "这个协议不支持"（把下界当上界）。
    #[test]
    fn runtime_observations_only_narrow_the_upper_bound() {
        let upper = capabilities_for(Transport::Https, Resource::PlainFile, None);
        assert!(upper.segment && upper.seek, "前提：HTTP 上界允许分片与定位");

        // 没观测 / 认不出的原因串：原样返回上界（未知 ≠ 不支持）。
        assert_eq!(narrow_by_reason(upper, None), upper);
        assert_eq!(narrow_by_reason(upper, Some("")), upper);
        assert_eq!(narrow_by_reason(upper, Some("reason=something_new")), upper);
        assert_eq!(Degrade::from_reason("reason=something_new"), None);

        // 只砍与观测直接相关的位：分片与定位没了，暂停/续传/多源/校验都不受影响。
        for raw in ["reason=no_range", "reason=unknown_size"] {
            let n = narrow_by_reason(upper, Some(raw));
            assert!(!n.segment && !n.seek, "{raw} 应当砍掉 segment/seek");
            assert_eq!(
                (
                    n.pause,
                    n.resume,
                    n.multi_source,
                    n.manifest,
                    n.verify,
                    n.seed
                ),
                (
                    upper.pause,
                    upper.resume,
                    upper.multi_source,
                    upper.manifest,
                    upper.verify,
                    upper.seed
                ),
                "{raw} 不该动其它能力位（尤其 resume：它不只有 Range 一条实现路径）"
            );
        }

        // `min_segment` 是"这次内容小"，不是"协议不支持分片" —— 一个 4 KiB 的文件
        // 不能让该协议的能力被永久记为不可分片。
        assert_eq!(narrow_by_reason(upper, Some("reason=min_segment")), upper);

        // 事件里的形态是键值串，也可能只有裸值；两种都要认。
        assert_eq!(
            Degrade::from_reason("reason=no_range"),
            Some(Degrade::NoRange)
        );
        assert_eq!(Degrade::from_reason("no_range"), Some(Degrade::NoRange));
        assert_eq!(
            Degrade::from_reason("reason=unknown_size"),
            Some(Degrade::UnknownSize)
        );

        // **只减不增**：上界已经为 false 的位，收窄后不能变成 true。
        let no_seg = Capabilities {
            segment: false,
            seek: false,
            ..upper
        };
        assert!(!narrow(no_seg, Some(Degrade::MinSegment)).segment);
        assert!(!narrow(no_seg, None).segment);

        // 每种降级都要有面向用户的解释 —— 否则界面只能显示一个更弱的能力值而说不出原因。
        for d in [Degrade::NoRange, Degrade::UnknownSize, Degrade::MinSegment] {
            assert!(!d.note().is_empty(), "{d:?} 缺少解释文案");
        }
    }
}
