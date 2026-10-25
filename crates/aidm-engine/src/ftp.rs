//! 最小 FTP 客户端。
//!
//! | 场景 | 规则 |
//! |---|---|
//! | 登录 | `USER` / `PASS`（匿名或凭据库里的账号） |
//! | 目录与模式 | `CWD` 切目录 + `TYPE I` 二进制模式 |
//! | 取总长 | 优先 `SIZE`；失败时从 `RETR` 的 150 回复里解析 |
//! | 续传 | `REST <offset>` |
//! | 传输 | 默认被动模式，从 `227 (h1,h2,h3,h4,p1,p2)` 解析数据地址；不支持 PASV 时明确失败（PORT 未实现） |
//! | 时间戳 | `MDTM` 取服务器端时间，用于变化检测 |
//! | 下载 | `RETR` |
//!
//! ## 显式 FTPS（RFC 4217）
//!
//! `ftps://` = 连上明文端口后 `AUTH TLS`（234）→ 控制连接整体升级为 TLS →
//! `USER`/`PASS` → `PBSZ 0` → `PROT P` → 数据连接也用 TLS。
//!
//! 两条硬规则：
//! - **不做"降级"**：`PROT P` 失败就是失败，绝不退回明文数据连接（那等于把文件内容
//!   暴露在中间人面前，却让用户以为在用 FTPS）。
//! - **证书必须校验**：根证书用 webpki 内置清单，**不提供"忽略证书错误"的开关**。
//!   自签证书的服务器需要把根证书装进系统信任库；想跳过校验的下载器是中间人的温床。
//! - 数据连接复用同一个 `Arc<ClientConfig>`，从而复用控制连接的 TLS 会话
//!   （rustls 的会话存储负责这件事）。部分服务器（如 vsftpd `require_ssl_reuse=YES`）
//!   会拒绝没有复用会话的数据连接。
//!
//! 尚未实现：隐式 FTPS（990 端口上来就 TLS）、主动模式 PORT、`CCC`（传完数据后回到明文）。

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// 解析后的 FTP 目标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpTarget {
    pub host: String,
    pub port: u16,
    /// 登录用户名；`ftp://host/...` 时为 `anonymous`。
    pub user: String,
    pub password: String,
    /// 目标文件所在目录（`/` 表示根；RETR 前会 `CWD` 过去）。
    pub dir: String,
    /// 文件名（已百分号解码）。
    pub name: String,
    /// `ftps://` = 显式 FTPS（`AUTH TLS` + `PROT P`）。
    pub tls: bool,
}

/// 百分号解码（FTP URL 里的路径常用到）。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 解析 `ftp://[user[:pass]@]host[:port]/path`。
pub fn parse(url: &str) -> Result<FtpTarget, String> {
    let (scheme, rest) = url
        .trim()
        .split_once("://")
        .ok_or_else(|| "bad_url".to_string())?;
    let tls = if scheme.eq_ignore_ascii_case("ftp") {
        false
    } else if scheme.eq_ignore_ascii_case("ftps") {
        true
    } else {
        return Err("bad_url".into());
    };
    // 去掉 `;type=i` 之类的参数尾巴
    let rest = rest.split([';', '#']).next().unwrap_or(rest);
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        None => (rest, ""),
    };
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (user, password) = match userinfo {
        Some(ui) => match ui.split_once(':') {
            Some((u, p)) => (percent_decode(u), percent_decode(p)),
            None => (percent_decode(ui), String::new()),
        },
        None => ("anonymous".to_string(), "anonymous@".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') && p.chars().all(|c| c.is_ascii_digit()) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| "bad_url".to_string())?,
        ),
        _ => (hostport.to_string(), 21u16),
    };
    if host.is_empty() {
        return Err("bad_url".into());
    }
    // 路径 → 目录 + 文件名
    let decoded = percent_decode(path);
    let trimmed = decoded.trim_end_matches('/');
    let (dir, name) = match trimmed.rsplit_once('/') {
        Some((d, n)) => (format!("/{d}"), n.to_string()),
        None => ("/".to_string(), trimmed.to_string()),
    };
    if name.is_empty() {
        return Err("ftp_no_filename".into());
    }
    Ok(FtpTarget {
        host,
        port,
        user,
        password,
        dir,
        name,
        tls,
    })
}

/// 控制/数据连接的统一抽象：明文或 TLS。
///
/// 显式 FTPS 要求"先明文发 `AUTH TLS`，再原地升级"，所以两种形态必须能被同一段
/// 读写代码使用——这就是这个枚举的全部理由。
enum Stream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// 默认 TLS 配置：webpki 内置根证书，**没有跳过校验的开关**。
///
/// 显式用 `builder_with_provider` 指定 ring，而不是让 rustls 自己猜：依赖图里同时有
/// `ring` 和 librqbit 带来的 aws-lc-rs feature 时，rustls 会拒绝自动选择并 panic
/// （与 `fastdl::net::tls_config` 同样的处理）。
fn client_config(
    extra_roots: Option<&[CertificateDer<'static>]>,
) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(extra) = extra_roots {
        roots.add_parsable_certificates(extra.iter().cloned());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("ftp_tls_versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// 用同一份配置升级/新建 TLS 流。
///
/// 复用同一个 `Arc<ClientConfig>`（而不是每次新建）是**必需**的：rustls 的会话存储挂在
/// 配置上，数据连接因此能复用控制连接的 TLS 会话（RFC 4217 要求，部分服务器强制）。
fn tls_wrap(config: Arc<ClientConfig>, host: &str, tcp: TcpStream) -> Result<Stream, String> {
    let name =
        ServerName::try_from(host.to_string()).map_err(|_| format!("ftp_tls_bad_name: {host}"))?;
    let conn = ClientConnection::new(config, name).map_err(|e| format!("ftp_tls_config: {e}"))?;
    Ok(Stream::Tls(Box::new(StreamOwned::new(conn, tcp))))
}

/// 读一条回复；多行回复（`230-` 连续）读到 `230 ` 为止。
fn read_reply(reader: &mut impl BufRead) -> Result<(u16, String), String> {
    let mut all = String::new();
    for _ in 0..64 {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("ftp_read: {e}"))?;
        if n == 0 {
            return Err("ftp_closed".into());
        }
        let t = line.trim_end_matches(['\r', '\n']);
        if all.is_empty() {
            all.push_str(t);
        } else {
            all.push('\n');
            all.push_str(t);
        }
        if t.len() >= 4 {
            let bytes = t.as_bytes();
            // "230-" 是续行，"230 " 是结束
            if bytes[3] == b' ' {
                let code: u16 = t[..3].parse().unwrap_or(0);
                return Ok((code, all));
            }
        }
    }
    Err("ftp_reply_too_long".into())
}

fn write_line(w: &mut impl Write, line: &str) -> Result<(), String> {
    w.write_all(line.as_bytes())
        .and_then(|_| w.write_all(b"\r\n"))
        .and_then(|_| w.flush())
        .map_err(|e| format!("ftp_write: {e}"))
}

/// 控制连接：一行命令 + 一条（可能多行的）回复。
struct Control {
    reader: BufReader<Stream>,
    /// 已握手过的 TLS 配置；数据连接复用它来复用会话（明文时为 None）。
    tls: Option<Arc<ClientConfig>>,
    /// 控制连接使用的主机名。**数据连接的 TLS 也必须用这个名字**：
    /// `PASV` 回复里给的是 IP（甚至可能是内网 IP），拿它去校验证书等于必然失败。
    tls_name: String,
}

impl Control {
    fn connect(target: &FtpTarget, timeout: Duration) -> Result<(Self, String), String> {
        Self::connect_with(target, timeout, None)
    }

    /// `extra_roots` 只给测试用（受信任的自签根）；生产路径传 None。
    fn connect_with(
        target: &FtpTarget,
        timeout: Duration,
        extra_roots: Option<&[CertificateDer<'static>]>,
    ) -> Result<(Self, String), String> {
        let addrs: Vec<_> = (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(|e| format!("ftp_resolve: {e}"))?
            .collect();
        let tcp = addrs
            .iter()
            .find_map(|a| TcpStream::connect_timeout(a, timeout).ok())
            .ok_or_else(|| "ftp_connect_failed".to_string())?;
        tcp.set_read_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        tcp.set_write_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        tcp.set_nodelay(true).ok();

        let mut reader = BufReader::new(Stream::Plain(tcp));
        let (code, text) = read_reply(&mut reader)?;
        if code / 100 != 2 {
            return Err(format!("ftp_greeting_{code}"));
        }
        if !target.tls {
            return Ok((
                Control {
                    reader,
                    tls: None,
                    tls_name: target.host.clone(),
                },
                text,
            ));
        }

        // 显式 FTPS：明文发 AUTH TLS，收到 234 后原地升级。
        write_line(reader.get_mut(), "AUTH TLS")?;
        let (code, text) = read_reply(&mut reader)?;
        if code != 234 {
            return Err(format!("ftp_auth_tls_{code}"));
        }
        let config = client_config(extra_roots)?;
        let tcp = match reader.into_inner() {
            Stream::Plain(s) => s,
            Stream::Tls(_) => return Err("ftp_tls_state".into()),
        };
        let stream = tls_wrap(config.clone(), &target.host, tcp)?;
        Ok((
            Control {
                reader: BufReader::new(stream),
                tls: Some(config),
                tls_name: target.host.clone(),
            },
            text,
        ))
    }

    fn read_reply(&mut self) -> Result<(u16, String), String> {
        read_reply(&mut self.reader)
    }

    fn cmd(&mut self, line: &str) -> Result<(u16, String), String> {
        write_line(self.reader.get_mut(), line)?;
        self.read_reply()
    }

    /// 打开数据连接；FTPS 时用同一个配置再握手一次（会话复用见 [`tls_wrap`]）。
    fn open_data(&self, host: &str, port: u16, timeout: Duration) -> Result<Stream, String> {
        let addrs: Vec<_> = (host, port)
            .to_socket_addrs()
            .map_err(|e| format!("ftp_resolve_data: {e}"))?
            .collect();
        let tcp = addrs
            .iter()
            .find_map(|a| TcpStream::connect_timeout(a, timeout).ok())
            .ok_or_else(|| "ftp_data_connect_failed".to_string())?;
        tcp.set_read_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        tcp.set_write_timeout(Some(timeout))
            .map_err(|e| e.to_string())?;
        match &self.tls {
            // 数据连接的 TLS 名字必须用控制连接的主机名：`PASV` 回复里给的是 IP
            // （还可能是内网 IP），拿它去校验证书必然失败。
            Some(config) => tls_wrap(config.clone(), &self.tls_name, tcp),
            None => Ok(Stream::Plain(tcp)),
        }
    }

    fn quit(&mut self) {
        let _ = self.cmd("QUIT");
    }
}

/// 登录后的加密参数协商（只有 FTPS 才需要）。
///
/// `PROT P` 失败**必须失败**：退回明文数据连接等于欺骗用户。
fn setup_protection(ctrl: &mut Control) -> Result<(), String> {
    let (code, _) = ctrl.cmd("PBSZ 0")?;
    if code / 100 != 2 {
        return Err(format!("ftp_pbsz_{code}"));
    }
    let (code, _) = ctrl.cmd("PROT P")?;
    if code / 100 != 2 {
        return Err(format!("ftp_prot_{code}"));
    }
    Ok(())
}

/// 探测结果：总长与服务器时间戳（都可能是 None）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FtpProbe {
    pub total: Option<u64>,
    pub last_modified: Option<String>,
}

/// 登录并取元信息（SIZE / MDTM）。
pub fn probe(target: &FtpTarget, timeout: Duration) -> Result<FtpProbe, String> {
    let (mut ctrl, _) = Control::connect(target, timeout)?;
    login(&mut ctrl, target)?;
    let mut out = FtpProbe::default();
    if let Err(e) = enter_dir(&mut ctrl, target) {
        ctrl.quit();
        return Err(e);
    }
    out.total = size_of(&mut ctrl, &target.name);
    out.last_modified = mdtm_of(&mut ctrl, &target.name);
    ctrl.quit();
    Ok(out)
}

fn login(ctrl: &mut Control, target: &FtpTarget) -> Result<(), String> {
    let (code, _) = ctrl.cmd(&format!("USER {}", target.user))?;
    match code {
        // 服务器直接放行（匿名常见）；**也要走到下面的保护协商**。
        230 => {}
        331 => {
            let (code, _) = ctrl.cmd(&format!("PASS {}", target.password))?;
            if code / 100 != 2 {
                return Err(format!("ftp_login_{code}"));
            }
        }
        // 530 等：登录被拒
        other => return Err(format!("ftp_login_{other}")),
    }
    // FTPS：登录成功后立刻协商加密参数；`PROT P` 失败就是失败，不退回明文数据连接。
    // 放在这里而不是各个 return 之前：若在 230 分支提前 return，
    // "不需要密码的服务器"会永远收不到 PROT P，从而明文传文件。
    if target.tls {
        setup_protection(ctrl)?;
    }
    Ok(())
}

fn enter_dir(ctrl: &mut Control, target: &FtpTarget) -> Result<(), String> {
    if target.dir != "/" && !target.dir.is_empty() {
        let (code, _) = ctrl.cmd(&format!("CWD {}", target.dir))?;
        if code / 100 != 2 {
            return Err(format!("ftp_cwd_{code}"));
        }
    }
    // 二进制模式：统一置 `TYPE I`
    let (code, _) = ctrl.cmd("TYPE I")?;
    if code / 100 != 2 {
        return Err(format!("ftp_type_{code}"));
    }
    Ok(())
}

fn size_of(ctrl: &mut Control, name: &str) -> Option<u64> {
    let (code, text) = ctrl.cmd(&format!("SIZE {name}")).ok()?;
    if code != 213 {
        return None;
    }
    text.lines()
        .next_back()
        .and_then(|l| l.split_whitespace().last())
        .and_then(|v| v.parse::<u64>().ok())
}

fn mdtm_of(ctrl: &mut Control, name: &str) -> Option<String> {
    let (code, text) = ctrl.cmd(&format!("MDTM {name}")).ok()?;
    if code != 213 {
        return None;
    }
    // 213 YYYYMMDDHHMMSS（可能带毫秒）
    let stamp = text
        .lines()
        .next_back()?
        .split_whitespace()
        .last()?
        .chars()
        .take(14)
        .collect::<String>();
    if stamp.len() == 14 && stamp.chars().all(|c| c.is_ascii_digit()) {
        Some(stamp)
    } else {
        None
    }
}

/// 从 `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` 解析数据地址。
fn parse_pasv(text: &str) -> Option<(String, u16)> {
    let start = text.find('(')?;
    let end = text[start..].find(')')? + start;
    let nums: Vec<u16> = text[start + 1..end]
        .split(',')
        .filter_map(|v| v.trim().parse::<u16>().ok())
        .collect();
    if nums.len() != 6 {
        return None;
    }
    let host = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]);
    let port = nums[4] * 256 + nums[5];
    Some((host, port))
}

/// 从 `150 Opening BINARY mode data connection for x (12345 bytes)` 里解析大小。
///
/// 有些服务器不支持 `SIZE`，但会在 RETR 的 150 回复里带上字节数。
fn parse_retr_size(text: &str) -> Option<u64> {
    let open = text.find('(')?;
    let close = text[open..].find(')')? + open;
    let inner = &text[open + 1..close];
    let digits: String = inner
        .split_whitespace()
        .find(|w| w.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("")
        .to_string();
    if digits.is_empty() {
        None
    } else {
        digits.parse().ok()
    }
}

/// 下载结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpOutcome {
    /// 最终写入的总字节数（含续传前已有的部分）。
    pub total_written: u64,
    /// 是否用了 REST 续传。
    pub resumed: bool,
    /// 调用方要求提前结束（暂停/取消）——此时不校验总长。
    pub stopped_early: bool,
    /// 实际使用的总长：`SIZE` 或 `RETR` 回复兜底得到的值。
    pub total: Option<u64>,
    /// 写盘累计耗时（毫秒）。只统计 `write_all`，不含网络读与 flush。
    pub write_ms: u64,
}

/// 下载到 `save_path`（可续传）。
///
/// `on_progress` 收到**累计**字节数，返回 `false` 表示要求停止（暂停/取消）；
/// 停止时不校验总长，由调用方决定后续状态。
/// 与 [`download`] 相同，但允许注入额外的受信任根证书。
///
/// 只给测试用（自签证书的本地 FTPS 服务器）；生产路径没有"忽略证书错误"的入口。
#[doc(hidden)]
pub fn download(
    target: &FtpTarget,
    save_path: &Path,
    resume_from: u64,
    expected_total: Option<u64>,
    on_progress: impl FnMut(u64) -> bool,
) -> Result<FtpOutcome, String> {
    download_with_roots(
        target,
        save_path,
        resume_from,
        expected_total,
        None,
        on_progress,
    )
}

/// 与 [`download`] 相同，但允许注入额外的受信任根证书。
///
/// 只给测试用（自签证书的本地 FTPS 服务器）。生产路径**没有**"忽略证书错误"的入口。
#[doc(hidden)]
pub fn download_with_roots(
    target: &FtpTarget,
    save_path: &Path,
    resume_from: u64,
    expected_total: Option<u64>,
    extra_roots: Option<&[CertificateDer<'static>]>,
    mut on_progress: impl FnMut(u64) -> bool,
) -> Result<FtpOutcome, String> {
    let timeout = Duration::from_secs(60);
    let (mut ctrl, _) = Control::connect_with(target, timeout, extra_roots)?;
    if let Err(e) = login(&mut ctrl, target) {
        ctrl.quit();
        return Err(e);
    }
    if let Err(e) = enter_dir(&mut ctrl, target) {
        ctrl.quit();
        return Err(e);
    }

    // 打开目标文件：续传时定位到 offset 之后继续写
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(save_path)
        .map_err(|e| format!("ftp_open_file: {e}"))?;
    let mut offset = resume_from;
    let mut resumed = false;
    if offset > 0 {
        let (code, _) = ctrl.cmd(&format!("REST {offset}"))?;
        if (300..400).contains(&code) {
            resumed = true;
        } else {
            // 服务器不支持 REST：从头开始，并把文件截断
            offset = 0;
            file.set_len(0).map_err(|e| format!("ftp_truncate: {e}"))?;
        }
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("ftp_seek: {e}"))?;

    // 进被动模式
    let (code, text) = ctrl.cmd("PASV")?;
    if code != 227 {
        ctrl.quit();
        return Err(format!("ftp_pasv_{code}"));
    }
    let (data_host, data_port) = parse_pasv(&text).ok_or_else(|| "ftp_pasv_parse".to_string())?;
    let mut data = ctrl.open_data(&data_host, data_port, timeout)?;

    // RETR，并用 150 回复里的字节数兜底总长
    let (code, text) = ctrl.cmd(&format!("RETR {}", target.name))?;
    if !(100..200).contains(&code) {
        ctrl.quit();
        return Err(format!("ftp_retr_{code}"));
    }
    let total = expected_total.or_else(|| parse_retr_size(&text));

    let mut buf = vec![0u8; 256 * 1024];
    let mut written = offset;
    let mut write_ns = 0u128;
    loop {
        let n = match data.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                ctrl.quit();
                return Err(format!("ftp_read_data: {e}"));
            }
        };
        let write_t = Instant::now();
        file.write_all(&buf[..n])
            .map_err(|e| format!("ftp_write_file: {e}"))?;
        write_ns += write_t.elapsed().as_nanos();
        written += n as u64;
        if !on_progress(written) {
            // 提前停止：关掉数据连接（触发服务端收尾）并退出，不做长度校验
            let _ = file.flush();
            drop(data);
            let _ = ctrl.cmd("ABOR");
            ctrl.quit();
            return Ok(FtpOutcome {
                total_written: written,
                resumed,
                stopped_early: true,
                total,
                write_ms: (write_ns / 1_000_000) as u64,
            });
        }
    }
    file.flush().map_err(|e| format!("ftp_flush: {e}"))?;
    drop(data);

    // 收尾回复（226 Transfer complete）
    let (code, _) = ctrl.read_reply()?;
    ctrl.quit();
    if code / 100 != 2 {
        return Err(format!("ftp_transfer_{code}"));
    }
    if let Some(t) = total {
        if written != t {
            return Err(format!("ftp_incomplete: got={written} want={t}"));
        }
    }
    Ok(FtpOutcome {
        total_written: written,
        resumed,
        stopped_early: false,
        total,
        write_ms: (write_ns / 1_000_000) as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_explicit_ftps_and_keeps_plain_ftp_unchanged() {
        let plain = parse("ftp://example.com/pub/file.iso").unwrap();
        assert!(!plain.tls, "ftp:// 必须是明文");
        let tls = parse("FTPS://example.com/pub/file.iso").unwrap();
        assert!(tls.tls, "ftps:// 走显式 AUTH TLS");
        assert_eq!(tls.host, "example.com");
        assert_eq!(tls.port, 21, "显式 FTPS 仍走标准端口（隐式 990 未实现）");
        assert_eq!((tls.dir.as_str(), tls.name.as_str()), ("/pub", "file.iso"));
        // 其它 scheme 仍然拒绝
        assert_eq!(parse("sftp://example.com/a"), Err("bad_url".to_string()));
        assert_eq!(parse("https://example.com/a"), Err("bad_url".to_string()));
    }

    #[test]
    fn parses_mixed_case_ftp_scheme() {
        let expected = parse("ftp://alice:s3cret@example.com:2121/pub/file.bin").unwrap();
        for scheme in ["FTP", "FtP", "fTp", "ftP"] {
            assert_eq!(
                parse(&format!(
                    "{scheme}://alice:s3cret@example.com:2121/pub/file.bin"
                )),
                Ok(expected.clone())
            );
        }
    }

    #[test]
    fn parses_ftp_urls() {
        let t = parse("ftp://example.com/pub/file.iso").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 21);
        assert_eq!(t.user, "anonymous");
        assert_eq!(t.dir, "/pub");
        assert_eq!(t.name, "file.iso");

        let t2 = parse("ftp://alice:s3cret@ftp.example.com:2121/a/b/c.bin").unwrap();
        assert_eq!(t2.port, 2121);
        assert_eq!(t2.user, "alice");
        assert_eq!(t2.password, "s3cret");
        assert_eq!(t2.dir, "/a/b");
        assert_eq!(t2.name, "c.bin");

        // 根目录下的文件
        let t3 = parse("ftp://h/x.bin").unwrap();
        assert_eq!(t3.dir, "/");
        assert_eq!(t3.name, "x.bin");

        // 百分号解码 + `;type=i` 尾巴
        let t4 = parse("ftp://h/a%20b/%E4%B8%AD.bin;type=i").unwrap();
        assert_eq!(t4.dir, "/a b");
        assert_eq!(t4.name, "中.bin");

        assert_eq!(parse("http://x/y"), Err("bad_url".into()));
        assert_eq!(parse("ftp://h/"), Err("ftp_no_filename".into()));
        assert_eq!(parse("ftp:///a.bin"), Err("bad_url".into()));
    }

    #[test]
    fn parses_pasv_and_retr_size() {
        assert_eq!(
            parse_pasv("227 Entering Passive Mode (127,0,0,1,195,80)."),
            Some(("127.0.0.1".into(), 195 * 256 + 80))
        );
        assert_eq!(parse_pasv("227 no parens here"), None);
        assert_eq!(parse_pasv("227 (1,2,3,4,5)"), None);

        assert_eq!(
            parse_retr_size("150 Opening BINARY mode data connection for f.bin (1048576 bytes)"),
            Some(1048576)
        );
        assert_eq!(parse_retr_size("150 Opening data connection"), None);
    }
}
