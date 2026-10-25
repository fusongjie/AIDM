//! 任务失败码（§12）。
//!
//! `downloads.error_code` 存机器码；`error_message` 存人类可读说明；
//! `http_status` 仅在 `http_*` 码时有值。旧行可能只有混杂的 `error_code`
//! （如 `http_404` / `connect: …`），读取时用 [`classify`] 回填。

/// 断网 / DNS / 复位 / 超时，且任务级重试已用尽。
pub const CODE_NETWORK: &str = "network";
/// 目标域名被本机 hosts / DNS 屏蔽（解析为 `0.0.0.0` / 环回地址）。
/// 这不是"网络抖动"，重试没有意义，因此不进退避队列。
pub const CODE_BLOCKED_BY_HOSTS: &str = "blocked_by_hosts";
/// 磁盘已满（含 ENOSPC / Windows 112）。
pub const CODE_DISK_FULL: &str = "disk_full";
/// 无写入权限。
pub const CODE_NO_PERMISSION: &str = "no_permission";
/// ETag / Last-Modified / 大小与已存校验不一致。
pub const CODE_REMOTE_CHANGED: &str = "remote_changed";
pub const CODE_HTTP_401: &str = "http_401";
pub const CODE_HTTP_403: &str = "http_403";
pub const CODE_HTTP_404: &str = "http_404";
pub const CODE_HTTP_4XX: &str = "http_4xx";
/// 服务器要求跳转。下载路径上最常见的原因是**反爬挑战**（详见 `http_code_for_status`）。
pub const CODE_HTTP_3XX: &str = "http_3xx";
pub const CODE_HTTP_5XX: &str = "http_5xx";
/// 引擎尚未实现的 scheme（目前 ftp）。
pub const CODE_UNSUPPORTED_SCHEME: &str = "unsupported_scheme";
/// 引擎崩溃重启：原 running 任务重新入队，不是 failed。
pub const CODE_INTERRUPTED: &str = "interrupted";
/// FTP 相关失败统一前缀：`ftp_login_530` / `ftp_cwd_550` / `ftp_retr_550` /
/// `ftp_pasv_502` / `ftp_connect_failed` / `ftp_data_connect_failed` / `ftp_incomplete`。
pub const FTP_CODE_PREFIX: &str = "ftp_";
/// eD2k（电驴）相关失败/等待码统一前缀。
pub const ED2K_CODE_PREFIX: &str = "ed2k_";
/// 还没有可用源（服务器/Kad 正在查或网络里暂时没有源）：不是用户错误，按较长间隔重排。
pub const CODE_ED2K_NO_SOURCES: &str = "ed2k_no_sources";
/// 有候选源、但对端窗口满/ACK 超时/本轮未完成：不是"没有源"。
///
/// 与 `ed2k_no_sources` 分开是为了让界面/诊断能回答"到底有没有源"：
/// 这条码出现时日志里能看到 peer 实际传输过字节，只是没凑满本轮分片。
pub const CODE_ED2K_INCOMPLETE: &str = "ed2k_incomplete";
/// 本地已有同名文件，但内容与链接里的 eD2k 哈希不符。
pub const CODE_ED2K_HASH_MISMATCH: &str = "ed2k_hash_mismatch";
/// 本地已有同名文件且哈希相符 —— 无需下载，直接完成。
pub const CODE_ED2K_ALREADY_HAVE: &str = "ed2k_already_have";
/// 流量配额用尽且动作是“停止”：任务保留进度，但不再自动排队，等用户手动继续。
pub const CODE_QUOTA_EXCEEDED: &str = "quota_exceeded";
/// 下载完成后的整文件 SHA-256 与上游 `CHECKSUM` 声明不符。
///
/// 出现在"换过镜像"或"走明文 http"的任务上：长度对得上但内容不同。
/// 重试没有意义（远端内容确实不同），因此不进网络退避。
pub const CODE_SHA256_MISMATCH: &str = "sha256_mismatch";

/// S3（对象存储）接入失败统一前缀：`s3_not_s3` / `s3_missing_bucket_or_key` /
/// `s3_missing_credentials` / `s3_missing_region`。
///
/// 这一族全部发生在**换地址**这一步（`s3://` → 预签名 HTTPS），所以它们的共同含义是
/// "任务还没开始下载就已经注定下不了"：必须明确回绝，而不是把 `s3://` 当普通地址发出去
/// 换回一个离原因很远的 404/403。
pub const S3_CODE_PREFIX: &str = "s3_";
/// PyPI 坐标解析失败统一前缀：`pypi_version_not_found` / `pypi_no_files` /
/// `pypi_lookup` / `pypi_read` / `pypi_status_<HTTP 码>`。
///
/// 与 `s3_` 的区别在于**必须分开两类**：`pypi_version_not_found` 是"用户改版本即可"，
/// 重试没有意义；`pypi_lookup` / `pypi_status_5xx` 是"上游/网络抖动"，重试才有意义。
pub const PYPI_CODE_PREFIX: &str = "pypi_";
/// 开发工具坐标接入失败统一前缀：`devtool_missing_version` / `devtool_bad_name` /
/// `devtool_unknown`。
///
/// 坐标换算发生在**建任务**这一步（与协议无关），失败时不该留下任务。
pub const DEVTOOL_CODE_PREFIX: &str = "devtool_";
/// HLS（`.m3u8`）清单型媒体失败统一前缀：`hls_encrypted` /
/// `hls_master_playlist` / `hls_no_segments`。
pub const HLS_CODE_PREFIX: &str = "hls_";
/// MPEG-DASH（`.mpd`）清单型媒体失败统一前缀：`dash_encrypted` /
/// `dash_no_representations` / `dash_no_segments`。
pub const DASH_CODE_PREFIX: &str = "dash_";
/// 清单（HLS / DASH 共用）取回与展开层失败统一前缀：`manifest_too_large` /
/// `manifest_no_segments` / `manifest_status_<HTTP 码>` / `manifest_fetch` /
/// `manifest_read`。
///
/// 与 `hls_` / `dash_` 分开的理由：那两族是"**清单内容**说明了不该下"（加密、无分片），
/// 这一族是"**清单本身没拿到或没法展开**"。前者用户改地址即可，后者重试才有意义。
///
/// 另有一个同前缀但不同来源的码：`manifest_base_url_invalid` 来自 `settings.rs` 的
/// **设置校验**（基地址必须是 http(s)），不是这里的取回失败 —— 同前缀是为了让
/// `is_known_code` 一次收编，文案在 `human_message` 里各写各的。
pub const MANIFEST_CODE_PREFIX: &str = "manifest_";
/// zsync 控制文件（`.zsync`）失败统一前缀：`zsync_header_too_large` /
/// `zsync_invalid_header` / `zsync_missing_field` / `zsync_bad_blocksize` /
/// `zsync_bad_hash_lengths` / `zsync_bad_length` / `zsync_bad_sha1` /
/// `zsync_too_many_blocks` / `zsync_truncated`。
pub const ZSYNC_CODE_PREFIX: &str = "zsync_";

/// 接入层（换地址 / 换协议 / 展开清单）失败码的全部前缀。
///
/// 单独列出是为了让 `classify` 只写一遍判定 —— 新增一个接入层协议时，
/// 前缀常量与这张表同时加，机器码的截取规则不会各写一份。
pub const INGRESS_CODE_PREFIXES: &[&str] = &[
    S3_CODE_PREFIX,
    PYPI_CODE_PREFIX,
    DEVTOOL_CODE_PREFIX,
    HLS_CODE_PREFIX,
    DASH_CODE_PREFIX,
    MANIFEST_CODE_PREFIX,
    ZSYNC_CODE_PREFIX,
];

/// 已知机器码（旧行若不在此列，视为待分类的原始串）。
pub const KNOWN_CODES: &[&str] = &[
    CODE_NETWORK,
    CODE_BLOCKED_BY_HOSTS,
    CODE_DISK_FULL,
    CODE_NO_PERMISSION,
    CODE_REMOTE_CHANGED,
    CODE_HTTP_401,
    CODE_HTTP_403,
    CODE_HTTP_404,
    CODE_HTTP_3XX,
    CODE_HTTP_4XX,
    CODE_HTTP_5XX,
    CODE_UNSUPPORTED_SCHEME,
    CODE_INTERRUPTED,
    CODE_SHA256_MISMATCH,
    CODE_QUOTA_EXCEEDED,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedError {
    pub code: String,
    pub message: String,
    pub http_status: Option<u16>,
}

impl ClassifiedError {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        http_status: Option<u16>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            http_status,
        }
    }
}

pub fn is_known_code(code: &str) -> bool {
    // FTP 码是动态生成的（`ftp_<动作>_<服务器码>`），按前缀认作已知机器码，
    // 否则界面拿不到它、只能显示笼统的"下载失败"。
    KNOWN_CODES.contains(&code)
        || code.starts_with(FTP_CODE_PREFIX)
        || code.starts_with(ED2K_CODE_PREFIX)
        // 接入层（S3 / PyPI / 开发工具坐标 / HLS / DASH）同理按前缀收编：它们的码也是
        // "前缀 + 具体原因"，逐个列进 `KNOWN_CODES` 只会漏（R-OBS-08 要求新码**必须**
        // 经本函数判定为已知，否则界面只能回落到"下载失败"）。
        || INGRESS_CODE_PREFIXES.iter().any(|p| code.starts_with(p))
}

/// 是否"被屏蔽地址"：未指定地址（`0.0.0.0` / `::`）或环回（`127.0.0.0/8` / `::1`）。
/// 本机 hosts 屏蔽常见写法就是把这些域名指向 `0.0.0.0`。
pub fn is_blocked_addr(ip: &std::net::IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() {
        return true;
    }
    match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(|v4| v4.is_unspecified() || v4.is_loopback())
            .unwrap_or(false),
        std::net::IpAddr::V4(_) => false,
    }
}

/// 从 `scheme://host[:port]/...` 取端口（缺省按 scheme 推断：https=443，其余=80）。
fn url_port(url: &str) -> u16 {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let explicit = if let Some(inner) = hostport.strip_prefix('[') {
        inner
            .split_once(']')
            .and_then(|(_, after)| after.strip_prefix(':'))
            .and_then(|p| p.parse::<u16>().ok())
    } else {
        hostport
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
    };
    explicit.unwrap_or(if url.starts_with("https://") { 443 } else { 80 })
}

/// 目标域名是否被本机 hosts / DNS 屏蔽：**解析结果全部**是屏蔽地址时返回其解析详情。
///
/// 解析失败（真正的 DNS 故障）返回 `None`，仍按普通 [`CODE_NETWORK`] 处理。
pub fn blocked_host(url: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    let host = crate::sched::url_host(url);
    if host.is_empty() {
        return None;
    }
    // URL 直接写 IP 字面量（127.0.0.1 / ::1 / 0.0.0.0）时不存在 hosts 改写，
    // 不属于「域名被屏蔽」；否则访问本机服务（含回环测试服务器）会被误判。
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let addrs: Vec<std::net::SocketAddr> = (host.as_str(), url_port(url))
        .to_socket_addrs()
        .ok()?
        .collect();
    if addrs.is_empty() || !addrs.iter().all(|a| is_blocked_addr(&a.ip())) {
        return None;
    }
    let ips: Vec<String> = addrs.iter().map(|a| a.ip().to_string()).collect();
    Some(format!("{host} -> {}", ips.join(", ")))
}

pub fn human_message(code: &str, http_status: Option<u16>) -> String {
    match code {
        CODE_NETWORK => "网络中断，重试已用尽".into(),
        CODE_BLOCKED_BY_HOSTS => "域名被本机 hosts/DNS 屏蔽，请检查 hosts 文件或改用代理".into(),
        CODE_DISK_FULL => "磁盘空间不足".into(),
        CODE_NO_PERMISSION => "没有写入权限".into(),
        CODE_REMOTE_CHANGED => "远程文件已变化，无法续传".into(),
        CODE_HTTP_401 => "远程返回 HTTP 401".into(),
        CODE_HTTP_403 => "远程返回 HTTP 403".into(),
        CODE_HTTP_404 => "远程返回 HTTP 404".into(),
        CODE_HTTP_3XX => format!(
            "远程要求跳转（HTTP {}）：通常是服务器的反爬/防直链挑战，换一个来源或稍后重试",
            http_status.unwrap_or(302)
        ),
        CODE_HTTP_4XX => format!("远程返回 HTTP {}", http_status.unwrap_or(400)),
        CODE_HTTP_5XX => format!("远程返回 HTTP {}", http_status.unwrap_or(500)),
        CODE_UNSUPPORTED_SCHEME => "不支持的协议".into(),
        CODE_INTERRUPTED => "引擎异常退出，任务已重新排队".into(),
        // FTP：把动作 + 服务器码翻成人话
        c if c.starts_with("ftp_login_") => {
            let s = c.trim_start_matches("ftp_login_");
            format!("FTP 登录失败（{s}）：请检查站点凭据里的用户名/密码")
        }
        c if c.starts_with("ftp_cwd_") => format!(
            "FTP 无法进入目录（{}）：路径可能不存在",
            c.trim_start_matches("ftp_cwd_")
        ),
        c if c.starts_with("ftp_retr_") => format!(
            "FTP 拒绝下载（{}）：文件可能不存在或无权限",
            c.trim_start_matches("ftp_retr_")
        ),
        c if c.starts_with("ftp_pasv_") => format!(
            "FTP 被动模式不可用（{}）：服务器可能只支持主动模式",
            c.trim_start_matches("ftp_pasv_")
        ),
        c if c.starts_with("ftp_transfer_") => format!(
            "FTP 传输未正常结束（{}）",
            c.trim_start_matches("ftp_transfer_")
        ),
        "ftp_connect_failed" => "FTP 连接失败：请检查地址与端口".into(),
        "ftp_resolve" => "FTP 域名解析失败".into(),
        "ftp_data_connect_failed" => "FTP 数据连接失败：可能被防火墙拦截".into(),
        "ftp_incomplete" => "FTP 传输不完整，长度与服务器声明不符".into(),
        "ftp_no_filename" => "FTP 地址里没有文件名".into(),
        // eD2k
        CODE_ED2K_NO_SOURCES => "暂无可用源：正在通过服务器/Kad 查源，稍后自动重试".into(),
        CODE_ED2K_INCOMPLETE => "仍有可用源，但本轮传输未完成（对端窗口/超时），稍后继续".into(),
        CODE_ED2K_HASH_MISMATCH => "本地同名文件与 eD2k 哈希不符：请改名保留或删除后重下".into(),
        CODE_ED2K_ALREADY_HAVE => "本地已有相同文件（eD2k 哈希一致）".into(),
        CODE_SHA256_MISMATCH => {
            "下载内容与上游声明的 SHA-256 不符：镜像内容不同或被中间人替换".into()
        }
        CODE_QUOTA_EXCEEDED => {
            "已达到本周期流量配额：任务已停止并保留进度，可在配额重置后手动继续".into()
        }
        c if c.starts_with("ed2k_not_file") => "这是 eD2k 服务器/节点链接，不是下载任务".into(),
        c if c.starts_with("ed2k_bad_") => "eD2k 链接格式不正确".into(),
        // 接入层：对象存储（`s3://` → 预签名 HTTPS）
        "s3_not_s3" => "不是有效的 S3 对象地址（应形如 s3://<桶名>/<对象键>）".into(),
        "s3_missing_bucket_or_key" => "S3 地址缺少桶名或对象键".into(),
        "s3_missing_credentials" => {
            "未配置 S3 访问凭证（Access Key / Secret Key）：请在设置里补齐".into()
        }
        "s3_missing_region" => {
            "未配置 S3 区域（region）：不猜，猜错只会得到更难排查的签名错误".into()
        }
        // 接入层：开发工具坐标
        "devtool_missing_version" => {
            "开发工具坐标缺少版本号：本工具不替你猜 latest，请补上 @<版本>".into()
        }
        "devtool_bad_name" => "开发工具坐标里的包名不合法".into(),
        "devtool_unknown" => "认不出的开发工具前缀".into(),
        // 接入层：PyPI 元数据查询。**版本不存在与上游抖动必须分开**：
        // 前者改版本即可（重试无意义），后者重试才有意义。
        "pypi_version_not_found" => "PyPI 上没有这个包或这个版本：请核对后改版本再试".into(),
        "pypi_no_files" => "PyPI 上这个版本没有可下载的文件（只有元数据）".into(),
        "pypi_lookup" => "查询 PyPI 元数据失败：多为网络/代理问题，重试即可".into(),
        "pypi_read" => "读取 PyPI 元数据响应失败（响应被截断或不是 JSON）".into(),
        c if c.starts_with("pypi_status_") => format!(
            "PyPI 返回 HTTP {}：上游临时故障，稍后重试",
            c.trim_start_matches("pypi_status_")
        ),
        // 接入层：清单型媒体（HLS / DASH）。这一族全部是"清单本身说明了不该下"，
        // 所以文案要给出**下一步动作**，而不是笼统的"下载失败"。
        "hls_encrypted" => "HLS 清单带加密（DRM）：本工具不下载加密流".into(),
        "hls_master_playlist" => "这是 HLS 主清单，里面没有可直接下载的分片".into(),
        "hls_no_segments" => "HLS 清单里没有分片".into(),
        "hls_master_without_variant" => "HLS 主清单里没有可选的码率（variant）".into(),
        "hls_too_many_hops" => "HLS 主清单嵌套层数过多（疑似循环引用），已停止".into(),
        "dash_encrypted" => "DASH 清单带 DRM 保护（ContentProtection）：本工具不下载加密流".into(),
        "dash_no_representations" => "DASH 清单里没有可下载的表示（Representation）".into(),
        "dash_no_segments" => "DASH 清单里没有分片".into(),
        "dash_parse_failed" => "DASH 清单（MPD）解析失败：不是合法 XML 或结构不符".into(),
        // 这一条来自**设置校验**（settings.rs），不是清单解析：基地址必须是 http(s)
        // 且不含空白/控制字符。
        "manifest_base_url_invalid" => {
            "设置里的基地址不合法：必须是 http:// 或 https://，且不含空白或控制字符".into()
        }
        "manifest_no_segments" => "清单展开后没有任何分片".into(),
        "manifest_too_large" => "清单体积超出上限（疑似不是清单，或服务器回了一份大文件）".into(),
        // 接入层：zsync 控制文件。这一族全部是"远端给的 .zsync 不可用"，
        // 用户能做的通常是换一个 `.zsync`（或改回直接下整份）。
        "zsync_header_too_large" => {
            "zsync 控制文件的头部超出上限（疑似不是控制文件，或对手在灌数据）".into()
        }
        "zsync_invalid_header" => "zsync 控制文件头部不是 `键: 值` 形态".into(),
        "zsync_missing_field" => "zsync 控制文件缺少必需字段（Blocksize / Length）".into(),
        "zsync_bad_blocksize" => "zsync 的 Blocksize 非法（必须是非零的 2 的幂）".into(),
        "zsync_bad_hash_lengths" => "zsync 的 Hash-Lengths 非法（长度或取值越界）".into(),
        "zsync_bad_length" => "zsync 的 Length 不是合法数字".into(),
        "zsync_bad_sha1" => "zsync 的 SHA-1 不是 40 位十六进制".into(),
        "zsync_too_many_blocks" => "zsync 声明的块数超出上限（不采信）".into(),
        "zsync_truncated" => "zsync 控制文件的块表被截断（下载不完整）".into(),
        // 运行期（取回缺块 / 整文件校验）的 zsync 码
        "zsync_no_content_url" => {
            "zsync 控制文件里没有可用的内容地址（`URL:` 缺失，且地址里推导不出）".into()
        }
        "zsync_control_too_large" => "zsync 控制文件体积超出上限（不采信）".into(),
        "zsync_fetch_read" => "读取 zsync 控制文件的响应失败（连接中断或响应被截断）".into(),
        "zsync_short_range" => "远端对某个区间的响应提前结束（该段没写全）".into(),
        "zsync_read" => "读取 zsync 缺块区间的响应失败（连接中断）".into(),
        "zsync_incomplete" => {
            "zsync 结束后仍有块与块校验和对不上：内容不完整，已丢弃不产出最终文件".into()
        }
        "zsync_sha1_mismatch" => "zsync 整文件 SHA-1 与控制文件声明不符：内容不对，已丢弃".into(),
        other => other.to_string(),
    }
}

pub fn http_code_for_status(status: u16) -> &'static str {
    match status {
        401 => CODE_HTTP_401,
        403 => CODE_HTTP_403,
        404 => CODE_HTTP_404,
        // 3xx 单独一档：它**不是** 4xx（原来是落到 `_` 里被标成 http_4xx，
        // 于是日志与文案说"4xx"而状态码写着 302，排查时很误导）。
        // 对下载而言 3xx 的含义很具体：服务器在要求跳转 —— 常见成因是反爬挑战
        // （实测 mirrors.sjtug.sjtu.edu.cn / mirrors.nju.edu.cn 对"自称浏览器"的
        // 请求回 302；fastdl 这条自有 HTTP/1.1 栈不跟随跳转，于是直接失败）。
        300..=399 => CODE_HTTP_3XX,
        400..=499 => CODE_HTTP_4XX,
        500..=599 => CODE_HTTP_5XX,
        _ => CODE_HTTP_4XX,
    }
}

/// 从 worker / 旧库原始串得到机器码 + 可读说明。
/// 去掉失败文本开头的阶段标记，得到纯原因文本。
///
/// 标记只服务于**阶段归因**，不该影响机器码分类与展示文案：`phase=transfer: read: ...`
/// 与 `read: ...` 必须归一到同一个码。
fn strip_phase_marker(raw: &str) -> &str {
    if let Some(rest) = raw.strip_prefix(PHASE_PREFIX) {
        if let Some((_, tail)) = rest.split_once(':') {
            return tail.trim_start();
        }
    }
    raw
}

pub fn classify(raw: &str) -> ClassifiedError {
    let raw = strip_phase_marker(raw.trim());
    if raw.is_empty() {
        return ClassifiedError::new(CODE_NETWORK, human_message(CODE_NETWORK, None), None);
    }
    if is_known_code(raw) {
        let http = http_status_from_code(raw);
        return ClassifiedError::new(raw, human_message(raw, http), http);
    }
    // eD2k：`ed2k_<原因>`，码即原始串
    if raw.starts_with(ED2K_CODE_PREFIX) {
        let code = raw.split(':').next().unwrap_or(raw).trim();
        return ClassifiedError::new(code, human_message(code, None), None);
    }
    // FTP：`ftp_<动作>_<服务器码>` 或 `ftp_<原因>`，码就是原始串本身
    if raw.starts_with(FTP_CODE_PREFIX) {
        let code = raw.split(':').next().unwrap_or(raw).trim();
        return ClassifiedError::new(code, human_message(code, None), None);
    }
    // 内容校验：`sha256_mismatch` 或 `sha256_mismatch: expected=… got=…`。
    // 机器码固定、详情放事件里，界面才能稳定映射文案。
    if raw.starts_with(CODE_SHA256_MISMATCH) {
        return ClassifiedError::new(
            CODE_SHA256_MISMATCH,
            human_message(CODE_SHA256_MISMATCH, None),
            None,
        );
    }
    if raw == "unsupported_scheme" {
        return ClassifiedError::new(
            CODE_UNSUPPORTED_SCHEME,
            human_message(CODE_UNSUPPORTED_SCHEME, None),
            None,
        );
    }

    if let Some(status) = extract_http_status(raw) {
        let code = http_code_for_status(status);
        return ClassifiedError::new(code, human_message(code, Some(status)), Some(status));
    }

    let lower = raw.to_ascii_lowercase();
    if is_disk_full_text(&lower) {
        return ClassifiedError::new(CODE_DISK_FULL, human_message(CODE_DISK_FULL, None), None);
    }
    if is_permission_text(&lower) {
        return ClassifiedError::new(
            CODE_NO_PERMISSION,
            human_message(CODE_NO_PERMISSION, None),
            None,
        );
    }
    if is_remote_changed_text(&lower) {
        return ClassifiedError::new(
            CODE_REMOTE_CHANGED,
            human_message(CODE_REMOTE_CHANGED, None),
            None,
        );
    }
    if is_network_text(&lower) {
        return ClassifiedError::new(CODE_NETWORK, human_message(CODE_NETWORK, None), None);
    }

    ClassifiedError::new(raw, raw, None)
}

pub fn classify_io(err: &std::io::Error) -> ClassifiedError {
    match err.kind() {
        std::io::ErrorKind::PermissionDenied => ClassifiedError::new(
            CODE_NO_PERMISSION,
            human_message(CODE_NO_PERMISSION, None),
            None,
        ),
        std::io::ErrorKind::StorageFull => {
            ClassifiedError::new(CODE_DISK_FULL, human_message(CODE_DISK_FULL, None), None)
        }
        _ => classify(&format!("{err}")),
    }
}

fn http_status_from_code(code: &str) -> Option<u16> {
    match code {
        CODE_HTTP_401 => Some(401),
        CODE_HTTP_403 => Some(403),
        CODE_HTTP_404 => Some(404),
        _ => None,
    }
}

fn extract_http_status(raw: &str) -> Option<u16> {
    let lower = raw.to_ascii_lowercase();
    for needle in ["http_", "http ", "http/", "status "] {
        if let Some(idx) = lower.find(needle) {
            let rest = &raw[idx + needle.len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = digits.parse::<u16>() {
                if (100..600).contains(&n) {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn is_disk_full_text(lower: &str) -> bool {
    lower.contains("no space")
        || lower.contains("not enough space")
        || lower.contains("disk full")
        || lower.contains("os error 28")
        || lower.contains("os error 112")
        || lower.contains("enospc")
}

fn is_permission_text(lower: &str) -> bool {
    lower.contains("permission denied")
        || lower.contains("access is denied")
        || lower.contains("os error 13")
        || lower.contains("os error 5")
        || lower.contains("eacces")
        || lower.contains("eperm")
}

fn is_remote_changed_text(lower: &str) -> bool {
    lower.contains("remote_changed")
        || lower.contains("validator_changed")
        || lower.contains("etag")
        || lower.contains("last-modified")
        || lower.contains("size_mismatch")
        || lower.contains("range_ignored")
}

fn is_network_text(lower: &str) -> bool {
    lower.starts_with("connect:")
        || lower.starts_with("connect ")
        || lower.starts_with("read:")
        || lower.starts_with("read ")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("connection reset")
        || lower.contains("connection refused")
        || lower.contains("broken pipe")
        || lower.contains("unexpected eof")
        || lower.contains("dns")
        || lower.contains("name or service not known")
        || lower.contains("failed to lookup")
        || lower.contains("network is unreachable")
        || lower.contains("no route to host")
        || lower == CODE_NETWORK
}

/// 任务级是否应按网络错误退避（用尽后转对应机器码，5xx 仍是 `http_5xx`）。
pub fn is_retryable_network(raw: &str) -> bool {
    let c = classify(raw);
    matches!(c.code.as_str(), CODE_NETWORK | CODE_HTTP_5XX)
        || matches!(c.http_status, Some(408 | 429 | 503))
}

// ---------------------------------------------------------------- 类型化错误层
//
// 规格 §5：字符串机器码继续落库（UI 与既有数据兼容），但**失败必须可归因**——
// `phase()` 把失败钉到七个阶段之一，`chain()` 给出完整原因链（根因在链尾），
// `#[source]` 保留底层 io/协议错误。`from_code()` 负责从字符串码还原。

/// 失败发生所在的阶段（规格 §3.2 的七个阶段 + 任务级）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Resolve,
    Connect,
    Auth,
    Transfer,
    Resume,
    Verify,
    Store,
    /// 不属于任何传输阶段（取消、内部错误）。
    Task,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Resolve => "resolve",
            Phase::Connect => "connect",
            Phase::Auth => "auth",
            Phase::Transfer => "transfer",
            Phase::Resume => "resume",
            Phase::Verify => "verify",
            Phase::Store => "store",
            Phase::Task => "task",
        }
    }
}

/// 失败文本里可携带的阶段标记（形态 `phase=transfer: <原因>`）。
///
/// 为什么需要它：机器码 `network` 同时覆盖「建连失败」和「读中途断流」，
/// 光看码无法归因到阶段。产生失败的那一行知道自己在哪个阶段，就顺手标出来，
/// 落库的机器码、退避判定、UI 展示全都不变（`classify` 仍按关键词归一化）。
pub const PHASE_PREFIX: &str = "phase=";

/// 从失败文本里解析阶段标记（标记可出现在文本中任意位置：
/// 失败码里是前置的 `phase=transfer: ...`，事件 detail 里是尾随的 `network phase=transfer`）。
pub fn phase_from_text(raw: &str) -> Option<Phase> {
    let at = raw.find(PHASE_PREFIX)?;
    let rest = &raw[at + PHASE_PREFIX.len()..];
    let name = rest.split([':', ' ', ';']).next()?;
    match name {
        "resolve" => Some(Phase::Resolve),
        "connect" => Some(Phase::Connect),
        "auth" => Some(Phase::Auth),
        "transfer" => Some(Phase::Transfer),
        "resume" => Some(Phase::Resume),
        "verify" => Some(Phase::Verify),
        "store" => Some(Phase::Store),
        "task" => Some(Phase::Task),
        _ => None,
    }
}

/// 类型化下载错误。
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    /// 带**显式阶段**的一般失败：机器码取自 `classify`，阶段取自失败文本的标记。
    #[error("{message}")]
    At {
        code: String,
        phase: Phase,
        message: String,
    },
    #[error("解析地址失败：{host}")]
    Resolve {
        host: String,
        blocked_by_hosts: bool,
        #[source]
        source: Option<std::io::Error>,
    },
    #[error("建立连接失败：{peer}")]
    Connect {
        peer: String,
        #[source]
        source: Option<std::io::Error>,
    },
    #[error("TLS 握手失败：{sni}（{reason}）")]
    Tls { sni: String, reason: String },
    #[error("鉴权失败：{scheme}")]
    Auth { scheme: String, status: Option<u16> },
    #[error("HTTP 状态 {status}")]
    Http {
        status: u16,
        retry_after_s: Option<u64>,
    },
    #[error("FTP {verb} 失败：{code} {reply}")]
    Ftp {
        verb: String,
        code: u16,
        reply: String,
    },
    #[error("eD2k {op} 失败：{code}")]
    Ed2k { op: String, code: String },
    #[error("BitTorrent 失败：{kind}")]
    Bt { kind: String },
    #[error("校验不符：期望 {expected}，实际 {actual}")]
    Verify {
        algo: String,
        expected: String,
        actual: String,
    },
    #[error("写盘失败：{kind}")]
    Disk {
        kind: String,
        #[source]
        source: Option<std::io::Error>,
    },
    #[error("远端内容已变化")]
    RemoteChanged {
        etag_before: Option<String>,
        etag_now: Option<String>,
    },
    #[error("任务已取消")]
    Cancelled,
    #[error("{message}")]
    Other { code: String, message: String },
}

impl DownloadError {
    /// 落库/事件用的机器码 —— 与旧字符串码完全兼容。
    pub fn code(&self) -> String {
        match self {
            DownloadError::At { code, .. } => return code.clone(),
            DownloadError::Resolve {
                blocked_by_hosts, ..
            } => {
                if *blocked_by_hosts {
                    CODE_BLOCKED_BY_HOSTS
                } else {
                    CODE_NETWORK
                }
            }
            DownloadError::Connect { .. } | DownloadError::Tls { .. } => CODE_NETWORK,
            DownloadError::Auth { status, .. } => match status {
                Some(401) => CODE_HTTP_401,
                Some(403) => CODE_HTTP_403,
                _ => "auth_failed",
            },
            DownloadError::Http { status, .. } => http_code_for_status(*status),
            DownloadError::Ftp { verb, code, .. } => return format!("ftp_{verb}_{code}"),
            DownloadError::Ed2k { code, .. } => return code.clone(),
            DownloadError::Bt { .. } => "bt_error",
            DownloadError::Verify { algo, .. } => {
                if algo.contains("md4") || algo.contains("ed2k") {
                    CODE_ED2K_HASH_MISMATCH
                } else {
                    CODE_SHA256_MISMATCH
                }
            }
            DownloadError::Disk { kind, .. } => {
                if kind == "disk_full" {
                    CODE_DISK_FULL
                } else {
                    CODE_NO_PERMISSION
                }
            }
            DownloadError::RemoteChanged { .. } => CODE_REMOTE_CHANGED,
            DownloadError::Cancelled => CODE_INTERRUPTED,
            DownloadError::Other { code, .. } => return code.clone(),
        }
        .to_string()
    }

    pub fn phase(&self) -> Phase {
        match self {
            DownloadError::At { phase, .. } => *phase,
            DownloadError::Resolve { .. } => Phase::Resolve,
            DownloadError::Connect { .. } | DownloadError::Tls { .. } => Phase::Connect,
            DownloadError::Auth { .. } => Phase::Auth,
            DownloadError::Http { .. }
            | DownloadError::Ftp { .. }
            | DownloadError::Ed2k { .. }
            | DownloadError::Bt { .. } => Phase::Transfer,
            DownloadError::Verify { .. } => Phase::Verify,
            DownloadError::Disk { .. } => Phase::Store,
            DownloadError::RemoteChanged { .. } => Phase::Resume,
            DownloadError::Cancelled | DownloadError::Other { .. } => Phase::Task,
        }
    }

    /// 是否值得重试（决定进退避队列还是直接判失败）。
    pub fn retryable(&self) -> bool {
        match self {
            DownloadError::At { code, .. } => code == CODE_NETWORK,
            DownloadError::Connect { .. } | DownloadError::Tls { .. } => true,
            DownloadError::Http { status, .. } => {
                *status >= 500 || *status == 408 || *status == 429
            }
            _ => false,
        }
    }

    /// 原因链（最外层在前，**根因在最后**）。
    pub fn chain(&self) -> Vec<String> {
        chain_of(self)
    }

    /// 从字符串机器码还原类型化错误（`classify` 会先做归一化）。
    pub fn from_code(raw: &str) -> Self {
        let c = classify(raw);
        // 文本里带了阶段标记就以它为准（见 `phase_from_text`）。
        if let Some(phase) = phase_from_text(raw) {
            return DownloadError::At {
                code: c.code,
                phase,
                message: c.message,
            };
        }
        match c.code.as_str() {
            CODE_BLOCKED_BY_HOSTS => DownloadError::Resolve {
                host: String::new(),
                blocked_by_hosts: true,
                source: None,
            },
            CODE_NETWORK => DownloadError::Connect {
                peer: String::new(),
                source: None,
            },
            CODE_DISK_FULL => DownloadError::Disk {
                kind: "disk_full".into(),
                source: None,
            },
            CODE_NO_PERMISSION => DownloadError::Disk {
                kind: "no_permission".into(),
                source: None,
            },
            CODE_REMOTE_CHANGED => DownloadError::RemoteChanged {
                etag_before: None,
                etag_now: None,
            },
            CODE_SHA256_MISMATCH => DownloadError::Verify {
                algo: "sha256".into(),
                expected: String::new(),
                actual: String::new(),
            },
            CODE_INTERRUPTED => DownloadError::Cancelled,
            CODE_HTTP_401 | CODE_HTTP_403 => DownloadError::Auth {
                scheme: "http".into(),
                status: http_status_from_code(&c.code),
            },
            other if other.starts_with(FTP_CODE_PREFIX) => DownloadError::Ftp {
                verb: other
                    .trim_start_matches(FTP_CODE_PREFIX)
                    .rsplit_once('_')
                    .map(|(v, _)| v.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                code: other
                    .rsplit_once('_')
                    .and_then(|(_, tail)| tail.parse::<u16>().ok())
                    .unwrap_or(0),
                reply: String::new(),
            },
            other if other.starts_with(ED2K_CODE_PREFIX) => DownloadError::Ed2k {
                op: other.trim_start_matches(ED2K_CODE_PREFIX).to_string(),
                code: other.to_string(),
            },
            other if other.starts_with("http_") => DownloadError::Http {
                status: http_status_from_code(other).unwrap_or(0),
                retry_after_s: None,
            },
            other => DownloadError::Other {
                code: other.to_string(),
                message: c.message,
            },
        }
    }
}

/// 逐层展开任意错误的原因链，最多 8 层（防止深链把日志撑爆）。
pub fn chain_of(err: &(dyn std::error::Error + 'static)) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if out.len() >= 8 {
            break;
        }
        out.push(e.to_string());
        cur = e.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_blocked_by_hosts() {
        let e = classify(CODE_BLOCKED_BY_HOSTS);
        assert_eq!(e.code, CODE_BLOCKED_BY_HOSTS);
        assert!(e.message.contains("hosts"));
        assert!(e.http_status.is_none());
        // 屏蔽不是"抖动"：不参与退避重试
        assert!(!is_retryable_network(CODE_BLOCKED_BY_HOSTS));
        // 读取时保留机器码（旧行回填）
        assert!(is_known_code(CODE_BLOCKED_BY_HOSTS));
    }

    #[test]
    fn ip_literal_urls_are_not_blocked_hosts() {
        assert!(blocked_host("http://127.0.0.1:8080/x.bin").is_none());
        assert!(blocked_host("http://[::1]:8080/x.bin").is_none());
        assert!(blocked_host("http://0.0.0.0/x.bin").is_none());
    }

    #[test]
    fn detects_blocked_addresses() {
        use std::net::IpAddr;
        for s in ["0.0.0.0", "127.0.0.1", "::", "::1"] {
            assert!(
                is_blocked_addr(&s.parse::<IpAddr>().unwrap()),
                "{s} 应视为屏蔽地址"
            );
        }
        for s in ["111.2.79.9", "2409:8087:2806:16::41"] {
            assert!(
                !is_blocked_addr(&s.parse::<IpAddr>().unwrap()),
                "{s} 不应视为屏蔽地址"
            );
        }
    }

    #[test]
    fn parses_url_port() {
        assert_eq!(url_port("https://a.example/x"), 443);
        assert_eq!(url_port("http://a.example:8080/x?y=1"), 8080);
        assert_eq!(url_port("https://[2409:8087::41]:8443/x"), 8443);
        assert_eq!(url_port("https://[2409:8087::41]/x"), 443);
    }

    #[test]
    fn classifies_http_family() {
        let e = classify("http_404");
        assert_eq!(e.code, CODE_HTTP_404);
        assert_eq!(e.http_status, Some(404));
        assert!(e.message.contains("404"));
        let e = classify("segment_1 http_503");
        assert_eq!(e.code, CODE_HTTP_5XX);
        assert_eq!(e.http_status, Some(503));
        let e = classify("http_429 retry-after=2");
        assert_eq!(e.code, CODE_HTTP_4XX);
        assert_eq!(e.http_status, Some(429));
        let e = classify("http_401");
        assert_eq!(e.code, CODE_HTTP_401);
        assert_eq!(e.http_status, Some(401));
        // 302 必须自成一档：它既不是 4xx 也不该退避重试（实测的成因是反爬挑战，
        // 换一个来源才有用）。原来落到 `_ => http_4xx`，日志会说"4xx"而状态码是 302。
        let e = classify("http_302");
        assert_eq!(e.code, CODE_HTTP_3XX);
        assert_eq!(e.http_status, Some(302));
        assert!(e.message.contains("302"), "{}", e.message);
        assert!(
            !crate::error::is_retryable_network("http_302"),
            "3xx 不该按网络错误退避"
        );
    }

    #[test]
    fn classifies_io_and_network() {
        assert_eq!(classify("connect: dns error").code, CODE_NETWORK);
        assert_eq!(
            classify("write: No space left on device (os error 28)").code,
            CODE_DISK_FULL
        );
        assert_eq!(
            classify("create: Permission denied (os error 13)").code,
            CODE_NO_PERMISSION
        );
        assert_eq!(classify("size_mismatch 10/20").code, CODE_REMOTE_CHANGED);
        assert_eq!(classify(CODE_INTERRUPTED).code, CODE_INTERRUPTED);
        assert!(is_retryable_network("connect: reset"));
        assert!(is_retryable_network("http_503"));
        assert!(!is_retryable_network("http_404"));
        assert!(!is_retryable_network("write: No space left on device"));
        assert!(!is_retryable_network("mkdir: denied"));
    }

    #[test]
    fn quota_exceeded_is_known_and_not_retryable() {
        assert!(is_known_code(CODE_QUOTA_EXCEEDED));
        let e = classify(CODE_QUOTA_EXCEEDED);
        assert_eq!(e.code, CODE_QUOTA_EXCEEDED);
        assert!(e.message.contains("配额"));
        assert!(!is_retryable_network(CODE_QUOTA_EXCEEDED));
    }

    #[test]
    fn classifies_sha256_mismatch_without_retrying() {
        let e = classify(CODE_SHA256_MISMATCH);
        assert_eq!(e.code, CODE_SHA256_MISMATCH);
        assert!(e.message.contains("SHA-256"));
        assert!(e.http_status.is_none());
        // 带详情的形式仍归一到同一个机器码
        let e = classify("sha256_mismatch: expected=aa got=bb");
        assert_eq!(e.code, CODE_SHA256_MISMATCH);
        // 内容不同不是网络抖动：不进网络退避
        assert!(!is_retryable_network(CODE_SHA256_MISMATCH));
        assert!(!is_retryable_network("sha256_mismatch: expected=aa got=bb"));
    }

    #[test]
    fn old_known_code_roundtrip() {
        for code in KNOWN_CODES {
            let e = classify(code);
            assert_eq!(e.code, *code);
            assert!(!e.message.is_empty());
        }
    }

    #[test]
    fn typed_error_maps_to_legacy_code_and_phase() {
        // 机器码兼容：类型化错误生成的码必须与旧字符串码逐字一致。
        let disk = DownloadError::Disk {
            kind: "disk_full".into(),
            source: None,
        };
        assert_eq!(disk.code(), CODE_DISK_FULL);
        assert_eq!(disk.phase(), Phase::Store);
        assert!(!disk.retryable());

        let net = DownloadError::Connect {
            peer: "h:80".into(),
            source: None,
        };
        assert_eq!(net.code(), CODE_NETWORK);
        assert_eq!(net.phase().as_str(), "connect");
        assert!(net.retryable());

        assert_eq!(
            DownloadError::Http {
                status: 404,
                retry_after_s: None
            }
            .code(),
            CODE_HTTP_404
        );
        assert_eq!(
            DownloadError::Http {
                status: 503,
                retry_after_s: Some(30)
            }
            .phase(),
            Phase::Transfer
        );
        assert!(DownloadError::Http {
            status: 503,
            retry_after_s: None
        }
        .retryable());
        assert_eq!(
            DownloadError::Ftp {
                verb: "login".into(),
                code: 530,
                reply: "no".into()
            }
            .code(),
            "ftp_login_530"
        );
        assert_eq!(
            DownloadError::Verify {
                algo: "md4".into(),
                expected: "a".into(),
                actual: "b".into()
            }
            .code(),
            CODE_ED2K_HASH_MISMATCH
        );
    }

    #[test]
    fn typed_error_chain_puts_root_cause_last() {
        let err = DownloadError::Disk {
            kind: "disk_full".into(),
            source: Some(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "no space left on device",
            )),
        };
        let chain = err.chain();
        assert!(chain.len() >= 2, "原因链应含底层 io 错误：{chain:?}");
        assert!(chain.last().unwrap().contains("no space left"));
    }

    #[test]
    fn from_code_bridges_legacy_strings() {
        // 旧字符串码（含带详情的混杂形式）都能还原成有阶段的类型化错误。
        let cases: &[(&str, &str, &str)] = &[
            (CODE_DISK_FULL, CODE_DISK_FULL, "store"),
            (CODE_NETWORK, CODE_NETWORK, "connect"),
            ("connect: timed out", CODE_NETWORK, "connect"),
            (CODE_SHA256_MISMATCH, CODE_SHA256_MISMATCH, "verify"),
            (CODE_HTTP_404, CODE_HTTP_404, "transfer"),
            (CODE_BLOCKED_BY_HOSTS, CODE_BLOCKED_BY_HOSTS, "resolve"),
            ("ftp_login_530", "ftp_login_530", "transfer"),
            ("ed2k_no_sources", "ed2k_no_sources", "transfer"),
        ];
        for (raw, want_code, want_phase) in cases {
            let e = DownloadError::from_code(raw);
            assert_eq!(&e.code(), want_code, "raw={raw}");
            assert_eq!(e.phase().as_str(), *want_phase, "raw={raw}");
        }
    }

    #[test]
    fn phase_marker_overrides_the_code_mapping() {
        // 没有标记：按机器码映射（`network` 只能给 connect）。
        assert_eq!(
            DownloadError::from_code(CODE_NETWORK).phase(),
            Phase::Connect
        );
        // 有标记：以标记为准 —— 读中途断流与建连失败共用 `network` 码。
        let e = DownloadError::from_code("phase=transfer: read: connection reset by peer");
        assert_eq!(
            e.code(),
            CODE_NETWORK,
            "机器码必须保持不变（退避/UI 都依赖它）"
        );
        assert_eq!(e.phase(), Phase::Transfer);
        assert!(e.retryable());

        // 标记与码的分类互不干扰：磁盘满仍是 disk_full + store。
        let e = DownloadError::from_code("phase=store: write: no space left on device");
        assert_eq!(e.code(), CODE_DISK_FULL);
        assert_eq!(e.phase(), Phase::Store);
        assert!(!e.retryable());

        assert_eq!(
            phase_from_text("phase=verify: bad hash"),
            Some(Phase::Verify)
        );
        assert_eq!(phase_from_text("phase=bogus: x"), None);
        assert_eq!(phase_from_text("no marker here"), None);

        // 分类不受标记影响：同一原因文本，加不加标记必须归一到同一个机器码
        // （否则"带标记后就不再是 network"会让退避与 UI 文案全乱）。
        for raw in [
            "read: connection reset by peer",
            "read: unexpected EOF",
            "connect: timed out",
            "phase-lookalike: not a marker",
        ] {
            let marked = format!("{PHASE_PREFIX}transfer: {raw}");
            assert_eq!(classify(&marked).code, classify(raw).code, "raw={raw}");
        }
    }

    /// 接入层（S3 / PyPI / 开发工具坐标 / HLS / DASH）的机器码必须被判为**已知**。
    ///
    /// R-OBS-08 要求新码"**必须**加入 `is_known_code` 或使用既有前缀"：漏了这一步的
    /// 后果不是报错而是**静默降级** —— `classify` 落到最后一行 `other => other`，
    /// 界面拿不到文案、只能显示生码串。所以这条守的是"注册过"，不是"能跑"。
    #[test]
    fn ingress_codes_are_registered_as_known() {
        for code in [
            "s3_not_s3",
            "s3_missing_bucket_or_key",
            "s3_missing_credentials",
            "s3_missing_region",
            "pypi_version_not_found",
            "pypi_no_files",
            "pypi_lookup",
            "pypi_status_503",
            "devtool_missing_version",
            "devtool_bad_name",
            "hls_encrypted",
            "hls_no_segments",
            "dash_encrypted",
            "dash_no_segments",
            "manifest_too_large",
            "zsync_bad_blocksize",
            "zsync_truncated",
            "zsync_incomplete",
            "zsync_sha1_mismatch",
        ] {
            assert!(is_known_code(code), "{code} 必须判为已知机器码");
            // 已知码要能给出**面向用户**的文案：等于原样回显就是没登记文案。
            let c = classify(code);
            assert_eq!(c.code, code, "{code} 的机器码不该被改写");
            assert_ne!(c.message, code, "{code} 缺少 human_message 文案");
        }
        // 阶段标记必须先被剥掉再判定，否则 `phase=resolve: s3_not_s3` 会被当成未知码。
        let marked = classify("phase=resolve: s3_missing_credentials");
        assert_eq!(marked.code, "s3_missing_credentials");
        assert_eq!(
            DownloadError::from_code("phase=resolve: s3_missing_credentials").phase(),
            Phase::Resolve
        );
        // 反向：前缀不是"万能已知"——认不出的码仍应原样透出（不臆造文案）。
        assert!(!is_known_code("gopher_unknown_thing"));
    }
}
