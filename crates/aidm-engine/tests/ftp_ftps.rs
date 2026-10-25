//! 显式 FTPS 端到端：本地自签证书 + rustls 的最小 FTP 服务器。
//!
//! 覆盖的是**真实 TLS** 这条路径，而不是"命令序列像不像"：
//! 1. 控制连接：明文 `AUTH TLS` → 234 → 之后的命令全部走 TLS；
//! 2. `PBSZ 0` + `PROT P` 被接受后，数据连接也必须走 TLS；
//! 3. 服务器拒绝 `PROT P` 时必须**整单失败**，绝不退回明文数据连接。
//!
//! 证书用 rcgen 现签一个 CA + 叶子（SAN = localhost），测试通过
//! `ftp::download_with_roots` 把 CA 当作受信任根注入——生产路径没有这个入口。

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use aidm_engine::ftp;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

struct TempFile {
    /// 持有 tempdir：Drop 时自动删除整个目录。
    _tmp: tempfile::TempDir,
    path: PathBuf,
}

impl TempFile {
    fn new() -> Self {
        let tmp = common::tempdir("ftps");
        let path = tmp.path().join("download.bin");
        Self { _tmp: tmp, path }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.path.parent().unwrap());
    }
}

/// 测试服务器观测到的事实（断言用）。
#[derive(Default)]
struct Observed {
    commands: Mutex<Vec<String>>,
    control_tls: AtomicBool,
    data_tls: AtomicBool,
}

impl Observed {
    fn saw(&self, command: &str) -> bool {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.eq_ignore_ascii_case(command))
    }
}

/// 控制/数据连接的统一抽象（与客户端同样的理由：明文起手，`AUTH TLS` 后原地升级）。
enum Srv {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ServerConnection, TcpStream>>),
}

impl Read for Srv {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Srv::Plain(s) => s.read(buf),
            Srv::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Srv {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Srv::Plain(s) => s.write(buf),
            Srv::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Srv::Plain(s) => s.flush(),
            Srv::Tls(s) => s.flush(),
        }
    }
}

fn read_line(stream: &mut impl Read) -> Option<String> {
    let mut out: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => {}
            Err(_) => return None,
        }
        if byte[0] == b'\n' {
            return Some(String::from_utf8_lossy(&out).into_owned());
        }
        if byte[0] != b'\r' {
            out.push(byte[0]);
        }
    }
}

fn reply(stream: &mut impl Write, line: &str) {
    let _ = stream.write_all(line.as_bytes());
    let _ = stream.write_all(b"\r\n");
    let _ = stream.flush();
}

/// 自签 CA + 叶子证书 →（客户端要信任的 CA、服务器配置）。
fn tls_pair() -> (CertificateDer<'static>, Arc<ServerConfig>) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut leaf_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    // rustls 的默认校验要求服务器证书带 serverAuth EKU（rcgen 默认**不带**）。
    leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    // 与引擎侧一致：显式指定 ring provider，不依赖 rustls 的 feature 自动检测
    // （依赖图里同时有 ring 与 aws-lc-rs 时 rustls 会直接 panic）。
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    (ca_cert.der().clone(), Arc::new(config))
}

/// 起一个显式 FTPS 服务器：`accept_prot_p = false` 时对 `PROT P` 回 534；
/// `password_required = false` 时对 `USER` 直接回 230（免密服务器）。
fn spawn_server(
    payload: Arc<Vec<u8>>,
    accept_prot_p: bool,
    password_required: bool,
) -> (CertificateDer<'static>, u16, Arc<Observed>, JoinHandle<()>) {
    let (ca, config) = tls_pair();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let observed = Arc::new(Observed::default());
    let seen = observed.clone();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut stream = Srv::Plain(tcp);
        reply(&mut stream, "220 aidm ftps test server");

        let mut data_listener: Option<TcpListener> = None;
        while let Some(line) = read_line(&mut stream) {
            let upper = line.to_ascii_uppercase();
            seen.commands.lock().unwrap().push(line.clone());
            if upper.starts_with("AUTH TLS") {
                reply(&mut stream, "234 proceed with TLS");
                let sock = match stream {
                    Srv::Plain(s) => s,
                    Srv::Tls(_) => unreachable!("AUTH TLS 只发一次"),
                };
                let conn = ServerConnection::new(config.clone()).unwrap();
                let mut tls = StreamOwned::new(conn, sock);
                tls.conn.complete_io(&mut tls.sock).unwrap();
                seen.control_tls.store(true, Ordering::SeqCst);
                stream = Srv::Tls(Box::new(tls));
            } else if upper.starts_with("PBSZ") {
                reply(&mut stream, "200 PBSZ 0 ok");
            } else if upper.starts_with("PROT") {
                if accept_prot_p {
                    reply(&mut stream, "200 PROT P ok");
                } else {
                    reply(&mut stream, "534 no private data connections");
                }
            } else if upper.starts_with("USER") {
                // 走"要密码"的正常流程：USER → 331，PASS → 230。
                if password_required {
                    reply(&mut stream, "331 need password");
                } else {
                    reply(&mut stream, "230 logged in");
                }
            } else if upper.starts_with("PASS") {
                reply(&mut stream, "230 logged in");
            } else if upper.starts_with("TYPE") || upper.starts_with("CWD") {
                reply(&mut stream, "200 ok");
            } else if upper.starts_with("SIZE") {
                reply(&mut stream, &format!("213 {}", payload.len()));
            } else if upper.starts_with("PASV") {
                let data = TcpListener::bind("127.0.0.1:0").unwrap();
                let p = data.local_addr().unwrap().port();
                data_listener = Some(data);
                reply(
                    &mut stream,
                    &format!(
                        "227 Entering Passive Mode (127,0,0,1,{},{}).",
                        p / 256,
                        p % 256
                    ),
                );
            } else if upper.starts_with("RETR") {
                reply(&mut stream, "150 opening data connection");
                let data = data_listener.take().unwrap().accept().unwrap().0;
                let conn = ServerConnection::new(config.clone()).unwrap();
                let mut tls = StreamOwned::new(conn, data);
                tls.conn.complete_io(&mut tls.sock).unwrap();
                seen.data_tls.store(true, Ordering::SeqCst);
                tls.write_all(&payload).unwrap();
                tls.flush().unwrap();
                let _ = tls.conn.send_close_notify();
                let _ = tls.conn.complete_io(&mut tls.sock);
                drop(tls);
                reply(&mut stream, "226 transfer complete");
            } else if upper.starts_with("QUIT") {
                reply(&mut stream, "221 bye");
                break;
            } else {
                reply(&mut stream, "200 ok");
            }
        }
    });
    (ca, port, observed, handle)
}

fn content(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 256) as u8).collect()
}

#[test]
fn explicit_ftps_downloads_over_tls_control_and_data() {
    let payload = Arc::new(content(300_000));
    let (ca, port, observed, server) = spawn_server(payload.clone(), true, true);
    let file = TempFile::new();
    let target = ftp::parse(&format!("ftps://localhost:{port}/data.bin")).unwrap();
    assert!(target.tls, "ftps:// 必须置 tls");

    let outcome = ftp::download_with_roots(
        &target,
        &file.path,
        0,
        None,
        Some(std::slice::from_ref(&ca)),
        |_| true,
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(outcome.total_written, payload.len() as u64);
    assert!(!outcome.resumed);
    assert_eq!(std::fs::read(&file.path).unwrap(), *payload, "字节必须一致");
    assert!(
        observed.control_tls.load(Ordering::SeqCst),
        "控制连接必须升级到 TLS"
    );
    assert!(observed.saw("AUTH TLS"), "必须先发 AUTH TLS");
    assert!(observed.saw("PBSZ 0"), "必须协商 PBSZ 0");
    assert!(observed.saw("PROT P"), "必须要求私有数据连接");
    assert!(
        observed.data_tls.load(Ordering::SeqCst),
        "数据连接必须走 TLS"
    );
}

#[test]
fn ftps_refusing_prot_p_fails_whole_download_instead_of_falling_back_to_cleartext() {
    let payload = Arc::new(content(4096));
    let (ca, port, observed, server) = spawn_server(payload, false, true);
    let file = TempFile::new();
    let target = ftp::parse(&format!("ftps://localhost:{port}/data.bin")).unwrap();

    let err = ftp::download_with_roots(
        &target,
        &file.path,
        0,
        None,
        Some(std::slice::from_ref(&ca)),
        |_| true,
    )
    .unwrap_err();
    server.join().unwrap();

    assert_eq!(err, "ftp_prot_534", "PROT P 被拒必须整单失败");
    assert!(
        !observed.data_tls.load(Ordering::SeqCst),
        "不能开明文数据连接"
    );
    assert!(!observed.saw("RETR"), "连 RETR 都不该发");
    let written = std::fs::metadata(&file.path).map(|m| m.len()).unwrap_or(0);
    assert_eq!(written, 0, "不能留下半个文件");
}

/// 服务器直接接受 `USER`（230，不要密码）时，**仍然必须**协商 `PROT P`。
///
/// 这是一条真实缺陷的回归测试：早期 `login()` 在 `230 => return Ok(())` 提前返回，
/// 于是"免密服务器"永远收不到 `PROT P`，数据连接会退回明文。
#[test]
fn ftps_without_password_still_negotiates_prot_p() {
    let payload = Arc::new(content(4096));
    let (ca, port, observed, server) = spawn_server(payload.clone(), true, false);
    let file = TempFile::new();
    let target = ftp::parse(&format!("ftps://localhost:{port}/data.bin")).unwrap();

    let outcome = ftp::download_with_roots(
        &target,
        &file.path,
        0,
        None,
        Some(std::slice::from_ref(&ca)),
        |_| true,
    )
    .unwrap();
    server.join().unwrap();

    assert!(
        !observed.saw("PASS"),
        "服务器没要密码就发 PASS 是本测试的前置错误"
    );
    assert!(observed.saw("PBSZ 0"), "免密也要协商 PBSZ 0");
    assert!(observed.saw("PROT P"), "免密也要协商 PROT P");
    assert!(
        observed.data_tls.load(Ordering::SeqCst),
        "数据连接必须走 TLS"
    );
    assert_eq!(outcome.total_written, payload.len() as u64);
    assert_eq!(std::fs::read(&file.path).unwrap(), *payload);
}
