//! 自带 HTTP/1.1 客户端：完全掌控 socket 选项、Range 语义与连接复用。
//!
//! 为什么不用 `ureq`：需要设置接收缓冲区、关闭 Nagle，并让一条 TCP 连接连续
//! 处理多个 Range 请求（连接复用）。`ureq` 不暴露底层 socket。
//!
//! 支持：http / https（rustls + ring，与本仓库既有 `ureq` 共用同一套依赖）、
//! 直连 / HTTP 代理（https 走 CONNECT、http 走 absolute-form）/ SOCKS5。

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

/// 默认接收缓冲区：256 KiB。在用户态把接收缓冲区提到带宽时延积之上，
/// 避免长肥管道下 TCP 窗口成为瓶颈。
pub const DEFAULT_RCVBUF: usize = 256 * 1024;

// ---------------------------------------------------------------- 代理

#[derive(Clone, Debug)]
pub enum ProxyCfg {
    Http {
        host: String,
        port: u16,
        /// 已编码好的 `Basic xxx`（若有）
        auth: Option<String>,
    },
    Socks5 {
        host: String,
        port: u16,
        user: Option<String>,
        pass: Option<String>,
    },
}

impl ProxyCfg {
    /// 解析 `http://user:pass@host:port` / `socks5://...`；`none` / 空 → None。
    pub fn parse(url: &str) -> Option<Self> {
        let url = url.trim();
        if url.is_empty() {
            return None;
        }
        let (scheme, rest) = url.split_once("://")?;
        let (auth, hostport) = match rest.rsplit_once('@') {
            Some((a, h)) => (Some(a), h),
            None => (None, rest),
        };
        let (host, port) = split_host_port(hostport)?;
        let (user, pass) = match auth {
            Some(a) => match a.split_once(':') {
                Some((u, p)) => (Some(pct_decode(u)), Some(pct_decode(p))),
                None => (Some(pct_decode(a)), None),
            },
            None => (None, None),
        };
        match scheme.to_ascii_lowercase().as_str() {
            "http" | "https" => Some(ProxyCfg::Http {
                host,
                port: if port == 0 { 8080 } else { port },
                auth: user.map(|u| {
                    format!(
                        "Basic {}",
                        base64(format!("{u}:{}", pass.unwrap_or_default()).as_bytes())
                    )
                }),
            }),
            "socks5" | "socks5h" | "socks" => Some(ProxyCfg::Socks5 {
                host,
                port: if port == 0 { 1080 } else { port },
                user,
                pass,
            }),
            _ => None,
        }
    }
}

fn split_host_port(s: &str) -> Option<(String, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        return Some((host.to_string(), port));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            Some((h.to_string(), p.parse().ok()?))
        }
        _ => Some((s.to_string(), 0)),
    }
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8 as char);
                i += 3;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((b.len() + 2) / 3 * 4);
    for chunk in b.chunks(3) {
        let n = chunk.len();
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let v = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(v >> 18) as usize & 63] as char);
        out.push(T[(v >> 12) as usize & 63] as char);
        out.push(if n > 1 {
            T[(v >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if n > 2 {
            T[v as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

// ---------------------------------------------------------------- URL

#[derive(Clone, Debug)]
pub struct Target {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// `/path?query`
    pub origin: String,
    pub tls: bool,
}

impl Target {
    pub fn parse(url: &str) -> Result<Self, String> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| format!("bad url: {url}"))?;
        let scheme = scheme.to_ascii_lowercase();
        let tls = match scheme.as_str() {
            "https" => true,
            "http" => false,
            other => return Err(format!("unsupported scheme: {other}")),
        };
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let hostport = hostport
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(hostport);
        let path = path.split('#').next().unwrap_or(path);
        let (host, mut port) = split_host_port(hostport).ok_or("bad host")?;
        if port == 0 {
            port = if tls { 443 } else { 80 };
        }
        let origin = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        Ok(Target {
            scheme,
            host,
            port,
            origin,
            tls,
        })
    }

    /// HTTP `Host` 头：默认端口必须省略。
    ///
    /// 城通等签名 CDN 会对 `Host: host:443` 直接返回 503，而同样的请求用
    /// `Host: host` 是 206；探测走 ureq（默认省略端口）所以一直看起来正常。
    pub fn authority(&self) -> String {
        let default_port = if self.tls { 443 } else { 80 };
        if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// 代理 `CONNECT` 的目标：必须带显式端口，即使它是默认端口。
    pub fn connect_authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Clone)]
pub struct NetCfg {
    /// 任务 id：连接线程不在 `enter_task` 作用域内，日志需自带 `task` 字段（R-OBS-01）。
    pub task: i64,
    /// 请求头配置（UA / Accept 系列 / Referer 兜底），见
    /// `docs/http-profile.md` 的实测对照。
    pub profile: aidm_core::http_profile::RequestProfile,
    pub referer: Option<String>,
    pub cookies: Option<String>,
    /// 每任务自定义请求头：在标准头之后、Range 之前输出
    pub custom_headers: Vec<aidm_core::headers::HeaderLine>,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub recv_buf: usize,
    pub proxy: Option<ProxyCfg>,
}

impl Default for NetCfg {
    fn default() -> Self {
        Self {
            task: 0,
            profile: aidm_core::http_profile::RequestProfile::default(),
            referer: None,
            cookies: None,
            custom_headers: Vec::new(),
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(60),
            recv_buf: DEFAULT_RCVBUF,
            proxy: None,
        }
    }
}

// ---------------------------------------------------------------- 读缓冲

struct Rbuf {
    buf: Vec<u8>,
    pos: usize,
    cap: usize,
}

impl Rbuf {
    fn new(n: usize) -> Self {
        Self {
            buf: vec![0u8; n],
            pos: 0,
            cap: 0,
        }
    }

    #[inline]
    fn avail(&self) -> usize {
        self.cap - self.pos
    }

    #[inline]
    fn take(&mut self, dst: &mut [u8]) -> usize {
        let n = self.avail().min(dst.len());
        dst[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        n
    }

    /// 丢弃已缓存数据并再读一次。
    fn fill<R: Read>(&mut self, io: &mut R) -> io::Result<usize> {
        self.pos = 0;
        self.cap = 0;
        let n = io.read(&mut self.buf)?;
        self.cap = n;
        Ok(n)
    }

    fn read_byte<R: Read>(&mut self, io: &mut R) -> io::Result<Option<u8>> {
        if self.avail() == 0 && self.fill(io)? == 0 {
            return Ok(None);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(Some(b))
    }

    /// 读到 CRLF（不含）；返回是否成功。用于状态行与头字段。
    fn read_line<R: Read>(
        &mut self,
        io: &mut R,
        out: &mut Vec<u8>,
        limit: usize,
    ) -> io::Result<bool> {
        out.clear();
        loop {
            if self.avail() == 0 && self.fill(io)? == 0 {
                return Ok(false);
            }
            while self.pos < self.cap {
                let b = self.buf[self.pos];
                self.pos += 1;
                if b == b'\n' {
                    if out.last() == Some(&b'\r') {
                        out.pop();
                    }
                    return Ok(true);
                }
                if out.len() >= limit {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "header line too long",
                    ));
                }
                out.push(b);
            }
        }
    }
}

// ---------------------------------------------------------------- 响应头

#[derive(Debug, Clone, Default)]
pub struct ResponseHead {
    pub status: u16,
    pub content_length: Option<u64>,
    /// `(start, end, total)`，来自 Content-Range
    pub content_range: Option<(u64, u64, u64)>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub location: Option<String>,
    pub chunked: bool,
    pub keep_alive: bool,
    pub accept_ranges: bool,
}

/// 构造请求头。
///
/// 头集合与顺序固定（顺序不影响服务器行为，但保持一致能少一层
/// 指纹差异，也便于对着抓包回归）：
/// `Accept` / `Accept-Charset` / `Accept-Encoding` / `Accept-Language` /
/// `Host` / `Referer` / `User-Agent` / `Cookie` / `Range`。
fn build_request_head(
    cfg: &NetCfg,
    method: &str,
    uri: &str,
    authority: &str,
    range: Option<(u64, Option<u64>)>,
) -> String {
    let p = &cfg.profile;
    let mut req = String::with_capacity(640);
    req.push_str(method);
    req.push(' ');
    req.push_str(uri);
    req.push_str(" HTTP/1.1\r\n");
    let push = |req: &mut String, name: &str, value: &str| {
        if !value.is_empty() {
            req.push_str(name);
            req.push_str(": ");
            req.push_str(value);
            req.push_str("\r\n");
        }
    };
    push(&mut req, "Accept", &p.accept);
    push(&mut req, "Accept-Charset", &p.accept_charset);
    push(&mut req, "Accept-Encoding", &p.accept_encoding);
    push(&mut req, "Accept-Language", &p.accept_language);
    push(&mut req, "Host", authority);
    if let Some(r) = cfg.referer.as_deref().filter(|r| !r.is_empty()) {
        push(&mut req, "Referer", r);
    }
    // UA 为空说明设置被清空，退回内置默认（等价于对方清掉 szCustomUserAgent）。
    // 派生镜像候选换成客户端自报标识（见 `RequestProfile::no_browser_ua`）。
    if p.no_browser_ua {
        push(
            &mut req,
            "User-Agent",
            aidm_core::http_profile::ANON_USER_AGENT,
        );
    } else {
        let ua = if p.user_agent.trim().is_empty() {
            aidm_core::setting_spec::DEFAULT_USER_AGENT
        } else {
            p.user_agent.as_str()
        };
        push(&mut req, "User-Agent", ua);
    }
    if let Some(c) = cfg.cookies.as_deref().filter(|c| !c.is_empty()) {
        push(&mut req, "Cookie", c);
    }
    // 每任务自定义头：解析阶段已挡掉受管头与控制字符，这里只做最后一道防线
    for h in &cfg.custom_headers {
        if !aidm_core::headers::is_managed_header(&h.name)
            && !h.value.chars().any(|c| c.is_control())
        {
            push(&mut req, &h.name, &h.value);
        }
    }
    match range {
        Some((s, Some(e))) => push(&mut req, "Range", &format!("bytes={s}-{e}")),
        Some((s, None)) => push(&mut req, "Range", &format!("bytes={s}-")),
        None => {}
    }
    req.push_str("\r\n");
    req
}

fn read_head<R: Read>(io: &mut R, rb: &mut Rbuf) -> io::Result<ResponseHead> {
    let mut line = Vec::with_capacity(128);
    if !rb.read_line(io, &mut line, 8 * 1024)? {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no status line",
        ));
    }
    let text = String::from_utf8_lossy(&line).to_string();
    let mut parts = text.split_whitespace();
    let _ver = parts.next();
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("bad status: {text}")))?;

    let mut head = ResponseHead {
        status,
        keep_alive: true,
        ..Default::default()
    };
    if status == 204 || status == 304 || (100..200).contains(&status) {
        head.keep_alive = false;
    }
    let mut keep_alive_seen = false;
    let mut connection_close = false;

    let mut lines = 0usize;
    loop {
        if !rb.read_line(io, &mut line, 8 * 1024)? {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated headers",
            ));
        }
        if line.is_empty() {
            break;
        }
        lines += 1;
        if lines > 200 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many headers",
            ));
        }
        let s = String::from_utf8_lossy(&line).to_string();
        let Some((name, value)) = s.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "content-length" => head.content_length = value.parse().ok(),
            "content-range" => head.content_range = parse_content_range(value),
            "etag" => head.etag = Some(value.to_string()),
            "last-modified" => head.last_modified = Some(value.to_string()),
            "location" => head.location = Some(value.to_string()),
            "accept-ranges" => head.accept_ranges = value.eq_ignore_ascii_case("bytes"),
            "transfer-encoding" => head.chunked = value.to_ascii_lowercase().contains("chunked"),
            "connection" => {
                keep_alive_seen = true;
                connection_close = value.to_ascii_lowercase().contains("close");
            }
            _ => {}
        }
    }
    if keep_alive_seen {
        head.keep_alive = !connection_close;
    }
    if head.chunked {
        head.keep_alive = head.keep_alive && !connection_close;
    }
    Ok(head)
}

fn parse_content_range(v: &str) -> Option<(u64, u64, u64)> {
    let rest = v.trim();
    let rest = rest
        .strip_prefix("bytes")
        .or_else(|| rest.strip_prefix("BYTES"))?
        .trim();
    let (range, total) = rest.split_once('/')?;
    let (s, e) = range.split_once('-')?;
    let s: u64 = s.trim().parse().ok()?;
    let e: u64 = e.trim().parse().ok()?;
    if e < s {
        return None;
    }
    let total: u64 = total.trim().parse().ok()?;
    Some((s, e, total))
}

// ---------------------------------------------------------------- 连接

enum Io {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Read for Io {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Io::Plain(s) => s.read(buf),
            Io::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Io {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Io::Plain(s) => s.write(buf),
            Io::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Io::Plain(s) => s.flush(),
            Io::Tls(s) => s.flush(),
        }
    }
}

/// 当前响应体的剩余状态；`None` 表示这条连接干净、可以发下一个请求。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Expect {
    None,
    Len(u64),
    Chunked,
    /// 无 Content-Length 且非 chunked：读到 EOF（连接不可复用）
    Eof,
}

pub struct Conn {
    io: Io,
    origin: String,
    authority: String,
    absolute_form: bool,
    rb: Rbuf,
    expect: Expect,
    chunk_left: u64,
    /// 上一次响应的 keep-alive 判定
    pub keep_alive: bool,
    /// 已在该连接上完成的请求数（诊断用）
    pub requests: u32,
    /// 最近一次实际写出去的请求头（诊断用）。
    ///
    /// 卡点已经在 `Conn::request` 上（`req_wait_max_ms` 涨到数秒，而建连与读正文都是 0），
    /// 而 curl 对同一目标 0.26 s 就响应 —— 差异只能在这些字节里，所以把它留给人看。
    pub last_head: Option<String>,
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("tls protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

impl Conn {
    pub fn open(target: &Target, cfg: &NetCfg) -> io::Result<Self> {
        let (tcp_host, tcp_port) = match &cfg.proxy {
            Some(ProxyCfg::Http { host, port, .. }) => (host.clone(), *port),
            Some(ProxyCfg::Socks5 { host, port, .. }) => (host.clone(), *port),
            None => (target.host.clone(), target.port),
        };
        let stream = connect_tcp(&tcp_host, tcp_port, cfg)?;
        let mut rb = Rbuf::new(64 * 1024);
        let mut io = Io::Plain(stream);
        let mut absolute_form = false;
        match &cfg.proxy {
            Some(ProxyCfg::Http { auth, .. }) => {
                if target.tls {
                    http_connect(&mut io, &mut rb, target, auth.as_deref())?;
                } else {
                    absolute_form = true;
                }
            }
            Some(ProxyCfg::Socks5 { user, pass, .. }) => {
                socks5_connect(&mut io, target, user.as_deref(), pass.as_deref())?;
            }
            None => {}
        }
        let io = if target.tls {
            let Io::Plain(tcp) = io else {
                unreachable!("prelude leaves the connection in plaintext mode")
            };
            let _ = tcp.set_read_timeout(Some(cfg.read_timeout));
            let name = rustls::pki_types::ServerName::try_from(target.host.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("sni: {e}")))?;
            let session = rustls::ClientConnection::new(tls_config(), name)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tls: {e}")))?;
            let mut tls = Io::Tls(Box::new(rustls::StreamOwned::new(session, tcp)));
            // 立即握手：失败就不要留着这条连接。握手是同步的（`flush` 内部做完
            // `complete_io`），所以这里拿到的是**真实握手耗时**（规格 §3.2 connect）。
            let tls_t = std::time::Instant::now();
            if let Err(err) = tls.flush() {
                tracing::warn!(
                    event = "net.tls",
                    phase = "connect",
                    outcome = "fail",
                    task = cfg.task,
                    sni = target.host.as_str(),
                    dur_ms = tls_t.elapsed().as_millis() as u64,
                    err = %err,
                );
                return Err(err);
            }
            tracing::info!(
                event = "net.tls",
                phase = "connect",
                outcome = "ok",
                task = cfg.task,
                sni = target.host.as_str(),
                dur_ms = tls_t.elapsed().as_millis() as u64,
            );
            rb.pos = 0;
            rb.cap = 0;
            tls
        } else {
            io
        };
        Ok(Conn {
            io,
            origin: target.origin.clone(),
            authority: target.authority(),
            absolute_form,
            rb,
            expect: Expect::None,
            chunk_left: 0,
            keep_alive: true,
            requests: 0,
            last_head: None,
        })
    }

    /// 发一次请求并读回响应头。要求上一个响应体已经读干净。
    pub fn request(
        &mut self,
        cfg: &NetCfg,
        method: &str,
        range: Option<(u64, Option<u64>)>,
    ) -> io::Result<ResponseHead> {
        if self.expect != Expect::None {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "previous body not drained",
            ));
        }
        let uri = if self.absolute_form {
            format!("http://{}{}", self.authority, self.origin)
        } else {
            self.origin.clone()
        };
        let head = build_request_head(cfg, method, &uri, &self.authority, range);
        // 只留第一条（诊断用），避免每次请求都多一次分配。
        if self.last_head.is_none() {
            self.last_head = Some(head.clone());
        }
        self.io.write_all(head.as_bytes())?;
        self.io.flush()?;
        let head = read_head(&mut self.io, &mut self.rb)?;
        self.requests += 1;
        self.keep_alive = head.keep_alive;
        self.expect = if head.chunked {
            Expect::Chunked
        } else {
            match head.content_length {
                Some(0) => Expect::None,
                Some(n) => Expect::Len(n),
                // 无长度且非 chunked：读到 EOF 为止（连接不可复用）
                None => {
                    if head.status == 204 || head.status == 304 || (100..200).contains(&head.status)
                    {
                        Expect::None
                    } else {
                        self.keep_alive = false;
                        Expect::Eof
                    }
                }
            }
        };
        self.chunk_left = 0;
        Ok(head)
    }

    pub fn body(&mut self) -> Body<'_> {
        Body { conn: self }
    }

    /// 连接是否还能安全复用（响应体读完 + keep-alive）。
    pub fn reusable(&self) -> bool {
        self.expect == Expect::None && self.keep_alive
    }

    fn read_chunked(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if self.chunk_left == 0 {
            // 读 chunk size 行（忽略扩展）
            let mut line = Vec::new();
            if !self.rb.read_line(&mut self.io, &mut line, 1024)? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "chunk size"));
            }
            let s = String::from_utf8_lossy(&line);
            let hex = s.split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(hex, 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk size"))?;
            if size == 0 {
                // trailer 段，读到空行为止
                let mut t = Vec::new();
                loop {
                    if !self.rb.read_line(&mut self.io, &mut t, 8 * 1024)? || t.is_empty() {
                        break;
                    }
                }
                self.expect = Expect::None;
                return Ok(0);
            }
            self.chunk_left = size;
        }
        let want = dst.len().min(self.chunk_left as usize);
        let n = if self.rb.avail() > 0 {
            self.rb.take(&mut dst[..want])
        } else {
            let k = self.io.read(&mut dst[..want])?;
            if k == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "chunk body"));
            }
            k
        };
        self.chunk_left -= n as u64;
        if self.chunk_left == 0 {
            // 吃掉 chunk 数据后的 CRLF（容忍裸 LF）
            loop {
                match self.rb.read_byte(&mut self.io)? {
                    Some(b'\n') | None => break,
                    Some(_) => {}
                }
            }
        }
        Ok(n)
    }
}

/// HTTP 代理隧道（https 目标走 CONNECT）。
fn http_connect(io: &mut Io, rb: &mut Rbuf, target: &Target, auth: Option<&str>) -> io::Result<()> {
    let mut req = format!(
        "CONNECT {a} HTTP/1.1\r\nHost: {a}\r\nProxy-Connection: Keep-Alive\r\n",
        a = target.connect_authority()
    );
    if let Some(a) = auth {
        req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
    }
    req.push_str("\r\n");
    io.write_all(req.as_bytes())?;
    io.flush()?;
    let head = read_head(io, rb)?;
    if !(200..300).contains(&head.status) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("proxy CONNECT {}", head.status),
        ));
    }
    rb.pos = 0;
    rb.cap = 0;
    Ok(())
}

/// SOCKS5 握手 + CONNECT（域名交给代理解析）。
fn socks5_connect(
    io: &mut Io,
    target: &Target,
    user: Option<&str>,
    pass: Option<&str>,
) -> io::Result<()> {
    let want_auth = user.is_some();
    let mut greet = vec![0x05u8, if want_auth { 2 } else { 1 }, 0x00];
    if want_auth {
        greet.push(0x02);
    }
    io.write_all(&greet)?;
    io.flush()?;
    let mut r = [0u8; 2];
    io.read_exact(&mut r)?;
    if r[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::Other, "socks5 version"));
    }
    match r[1] {
        0x00 => {}
        0x02 => {
            let u = user.unwrap_or("").as_bytes();
            let p = pass.unwrap_or("").as_bytes();
            let mut m = vec![0x01u8, u.len() as u8];
            m.extend_from_slice(u);
            m.push(p.len() as u8);
            m.extend_from_slice(p);
            io.write_all(&m)?;
            io.flush()?;
            let mut a = [0u8; 2];
            io.read_exact(&mut a)?;
            if a[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socks5 auth",
                ));
            }
        }
        m => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("socks5 method {m}"),
            ))
        }
    }
    let h = target.host.as_bytes();
    let mut c = vec![0x05u8, 0x01, 0x00, 0x03, h.len() as u8];
    c.extend_from_slice(h);
    c.extend_from_slice(&target.port.to_be_bytes());
    io.write_all(&c)?;
    io.flush()?;
    let mut hdr = [0u8; 4];
    io.read_exact(&mut hdr)?;
    if hdr[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("socks5 connect {}", hdr[1]),
        ));
    }
    let skip = match hdr[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            io.read_exact(&mut l)?;
            l[0] as usize + 2
        }
        _ => return Err(io::Error::new(io::ErrorKind::Other, "socks5 atyp")),
    };
    let mut junk = vec![0u8; skip];
    io.read_exact(&mut junk)?;
    Ok(())
}

/// 响应体读取器：直接借用连接，因此「读完才能复用连接」由类型系统保证。
pub struct Body<'a> {
    conn: &'a mut Conn,
}

impl Body<'_> {
    /// 读最多 `dst.len()` 字节；返回 0 表示响应体结束。
    ///
    /// 热路径（`dst` 足够大且缓冲已空）直接读进调用方缓冲区，只做一次拷贝。
    pub fn read_up_to(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        match self.conn.expect {
            Expect::None => Ok(0),
            Expect::Chunked => self.conn.read_chunked(dst),
            Expect::Eof => {
                let n = self.conn.io.read(dst)?;
                if n == 0 {
                    self.conn.expect = Expect::None;
                }
                Ok(n)
            }
            Expect::Len(rem) => {
                let want = dst.len().min(rem.min(usize::MAX as u64) as usize);
                if want == 0 {
                    self.conn.expect = Expect::None;
                    return Ok(0);
                }
                let n = if self.conn.rb.avail() > 0 {
                    self.conn.rb.take(&mut dst[..want])
                } else if want >= 4096 {
                    let k = self.conn.io.read(&mut dst[..want])?;
                    if k == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "connection closed early",
                        ));
                    }
                    k
                } else {
                    if self.conn.rb.fill(&mut self.conn.io)? == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "connection closed early",
                        ));
                    }
                    self.conn.rb.take(&mut dst[..want])
                };
                self.conn.expect = {
                    let left = rem - n as u64;
                    if left == 0 {
                        Expect::None
                    } else {
                        Expect::Len(left)
                    }
                };
                Ok(n)
            }
        }
    }

    /// 把剩余体读干净，使连接可复用。
    pub fn drain(&mut self) -> io::Result<()> {
        let mut sink = [0u8; 16 * 1024];
        loop {
            match self.read_up_to(&mut sink) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
    }
}

// ---------------------------------------------------------------- TCP

fn connect_tcp(host: &str, port: u16, cfg: &NetCfg) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no address"));
    }
    let mut last: Option<io::Error> = None;
    for addr in addrs {
        match connect_one(addr, cfg) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::Other, "connect failed")))
}

fn connect_one(addr: SocketAddr, cfg: &NetCfg) -> io::Result<TcpStream> {
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // 显式设置接收缓冲区会关掉 Windows 的接收窗口自动调优，所以只在调用方
    // 明确给了值时设置（`recv_buf == 0` 表示交给操作系统自己调）。
    if cfg.recv_buf > 0 {
        let _ = sock.set_recv_buffer_size(cfg.recv_buf);
    }
    let _ = sock.set_tcp_nodelay(true);
    let _ = sock.set_keepalive(true);
    sock.connect_timeout(&addr.into(), cfg.connect_timeout)?;
    let stream: TcpStream = sock.into();
    stream.set_read_timeout(Some(cfg.read_timeout))?;
    stream.set_write_timeout(Some(cfg.read_timeout))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 请求头必须与文档中的观测 profile 一致（见 docs/http-profile.md）。
    #[test]
    fn request_head_matches_observed_profile() {
        let cfg = NetCfg {
            referer: Some("http://127.0.0.1:8899/".into()),
            ..Default::default()
        };
        let head = build_request_head(
            &cfg,
            "GET",
            "/probe.bin",
            "127.0.0.1:8899",
            Some((233600, Some(1048575))),
        );
        let lines: Vec<&str> = head.split("\r\n").collect();
        assert_eq!(lines[0], "GET /probe.bin HTTP/1.1");
        // 头名与顺序都对着抓包
        let names: Vec<&str> = lines[1..]
            .iter()
            .take_while(|l| !l.is_empty())
            .map(|l| l.split(':').next().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                "Accept",
                "Accept-Charset",
                "Accept-Encoding",
                "Accept-Language",
                "Host",
                "Referer",
                "User-Agent",
                "Range"
            ]
        );
        assert!(head.contains("Accept: */*\r\n"));
        assert!(head.contains("Accept-Charset: *\r\n"));
        assert!(head.contains("Accept-Encoding: identity\r\n"));
        assert!(head.contains(&format!(
            "User-Agent: {}\r\n",
            aidm_core::setting_spec::DEFAULT_USER_AGENT
        )));
        assert!(head.contains("Range: bytes=233600-1048575\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn default_ports_are_omitted_from_host_but_kept_for_connect() {
        let https = Target::parse("https://example.com/a?b=1").unwrap();
        assert_eq!(https.authority(), "example.com");
        assert_eq!(https.connect_authority(), "example.com:443");
        let http = Target::parse("http://example.com:8080/a").unwrap();
        assert_eq!(http.authority(), "example.com:8080");
        assert_eq!(http.connect_authority(), "example.com:8080");
    }

    /// UA 被清空时退回内置默认（等价于对方清掉 szCustomUserAgent）。
    #[test]
    fn empty_user_agent_falls_back_to_default() {
        let cfg = NetCfg {
            profile: aidm_core::http_profile::RequestProfile {
                user_agent: String::new(),
                ..Default::default()
            },
            ..Default::default()
        };
        let head = build_request_head(&cfg, "GET", "/a", "h", None);
        assert!(head.contains(aidm_core::setting_spec::DEFAULT_USER_AGENT));
    }

    /// 派生镜像候选走"不声明客户端身份"时，fastdl 自己的协议栈必须真的不发 UA。
    ///
    /// 注意两套实现在这一点上**表达方式不同、效果等价**：
    /// - ureq 在 `unit.rs:459` 一定会写这个头，所以那边只能发**空值**；
    /// - 本栈的 `push` 会跳过空值，于是这里直接**不发这个头**。
    ///
    /// 两种形态实测都能过镜像的 WAF（不发头对 7 家全部 206）；要挡住的是"自称浏览器"。
    /// 任何一边漏改，都会出现"探测 206、下载被 WAF 挡成 302"的自相矛盾失败。
    #[test]
    fn anon_user_agent_sends_no_user_agent_header_at_all() {
        let cfg = NetCfg {
            profile: aidm_core::http_profile::RequestProfile::default().without_browser_ua(),
            ..Default::default()
        };
        let head = build_request_head(&cfg, "GET", "/a", "h", None);
        assert!(
            !head.to_ascii_lowercase().contains("user-agent:"),
            "不该出现 User-Agent 头: {head}"
        );
        assert!(
            !head.contains(aidm_core::setting_spec::DEFAULT_USER_AGENT),
            "更不能退回浏览器串（那正是被挑战的原因）: {head}"
        );
        assert!(
            !head.contains("Trident"),
            "任何浏览器标识都不该出现: {head}"
        );
        // 其余头一个都不能少（只换 UA 这一项）
        assert!(head.contains("Accept: */*\r\n"), "{head}");
        assert!(head.contains("Accept-Encoding: identity\r\n"), "{head}");
    }

    /// 每任务自定义头：在标准头之后发出；受管头即使混进来也不会被写出。
    #[test]
    fn custom_headers_are_emitted_and_managed_ones_filtered() {
        let cfg = NetCfg {
            custom_headers: aidm_core::headers::parse_custom_headers(
                "X-Api-Key: k\nSec-Fetch-Site: cross-site",
            )
            .unwrap(),
            ..Default::default()
        };
        let head = build_request_head(&cfg, "GET", "/a", "h", None);
        assert!(head.contains("X-Api-Key: k\r\n"));
        assert!(head.contains("Sec-Fetch-Site: cross-site\r\n"));
        // 最后一道防线：受管头与含控制字符的值不会被写出
        let bad = NetCfg {
            custom_headers: vec![
                aidm_core::headers::HeaderLine {
                    name: "Range".into(),
                    value: "bytes=0-1".into(),
                },
                aidm_core::headers::HeaderLine {
                    name: "X-Evil".into(),
                    value: "a\rb".into(),
                },
            ],
            ..Default::default()
        };
        let bad_head = build_request_head(&bad, "GET", "/a", "h", None);
        assert!(!bad_head.contains("Range: bytes=0-1"));
        assert!(!bad_head.contains("X-Evil"));
    }

    /// Cookie 只在有值时出现，避免空 `Cookie:` 头。
    #[test]
    fn cookie_only_when_present() {
        let cfg = NetCfg::default();
        let head = build_request_head(&cfg, "GET", "/a", "h", None);
        assert!(!head.contains("Cookie:"));
        let cfg2 = NetCfg {
            cookies: Some("a=1".into()),
            ..Default::default()
        };
        assert!(build_request_head(&cfg2, "GET", "/a", "h", None).contains("Cookie: a=1\r\n"));
    }

    #[test]
    fn parses_targets() {
        let t = Target::parse("https://example.com/a/b.iso?x=1#frag").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
        assert!(t.tls);
        assert_eq!(t.origin, "/a/b.iso?x=1");
        let t = Target::parse("http://127.0.0.1:8080/f").unwrap();
        assert_eq!(t.port, 8080);
        assert!(!t.tls);
        let t = Target::parse("https://h").unwrap();
        assert_eq!(t.origin, "/");
    }

    #[test]
    fn parses_proxies() {
        match ProxyCfg::parse("http://127.0.0.1:7897").unwrap() {
            ProxyCfg::Http { host, port, auth } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 7897);
                assert!(auth.is_none());
            }
            _ => panic!("expected http proxy"),
        }
        match ProxyCfg::parse("socks5://u:p%40ss@127.0.0.1:1080").unwrap() {
            ProxyCfg::Socks5 {
                user, pass, port, ..
            } => {
                assert_eq!(user.as_deref(), Some("u"));
                assert_eq!(pass.as_deref(), Some("p@ss"));
                assert_eq!(port, 1080);
            }
            _ => panic!("expected socks5"),
        }
        assert!(ProxyCfg::parse("").is_none());
        assert!(ProxyCfg::parse("none").is_none());
    }

    #[test]
    fn basic_auth_is_encoded() {
        assert_eq!(
            base64(b"Aladdin:open sesame"),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
        assert_eq!(base64(b"a"), "YQ==");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
    }

    #[test]
    fn parses_content_range() {
        assert_eq!(parse_content_range("bytes 0-99/1000"), Some((0, 99, 1000)));
        assert!(parse_content_range("bytes 100-0/1000").is_none());
    }
}
