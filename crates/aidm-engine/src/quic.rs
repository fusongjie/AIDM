//! 最小 QUIC 文件传输客户端。
//!
//! QUIC 只定义传输，不定义“下载 URL”。这里明确采用可测试的 HTTP/0.9-over-QUIC
//! 子协议（ALPN `hq-29`）：双向流发送 `GET <path>\r\n`，服务端在同一流返回原始文件字节。

use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use tokio::io::AsyncWriteExt;

const ALPN: &[u8] = b"hq-29";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicTarget {
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_uri(uri: &str) -> Result<QuicTarget, String> {
    let url = url::Url::parse(uri).map_err(|_| "quic_bad_uri")?;
    if url.scheme() != "quic" || url.query().is_some() || url.fragment().is_some() {
        return Err("quic_bad_uri".into());
    }
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or("quic_bad_host")?;
    let path = url.path();
    if path.is_empty() || path == "/" {
        return Err("quic_bad_path".into());
    }
    Ok(QuicTarget {
        host: host.to_string(),
        port: url.port().unwrap_or(4433),
        path: path.to_string(),
    })
}

fn public_client_config() -> Result<quinn::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    client_config(roots)
}

fn client_config(roots: rustls::RootCertStore) -> Result<quinn::ClientConfig, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicClientConfig::try_from(tls).map_err(|e| format!("quic_tls: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

pub async fn download_uri(uri: &str, target: &Path) -> Result<u64, String> {
    download_uri_with_config(uri, target, public_client_config()?).await
}

async fn download_uri_with_config(
    uri: &str,
    target_path: &Path,
    config: quinn::ClientConfig,
) -> Result<u64, String> {
    let target = parse_uri(uri)?;
    let remote = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|e| format!("quic_dns: {e}"))?
        .next()
        .ok_or("quic_dns_empty")?;
    let bind = if remote.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let mut endpoint = quinn::Endpoint::client(bind).map_err(|e| format!("quic_bind: {e}"))?;
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect(remote, &target.host)
        .map_err(|e| format!("quic_connect: {e}"))?
        .await
        .map_err(|e| format!("quic_handshake: {e}"))?;
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| format!("quic_stream: {e}"))?;
    send.write_all(format!("GET {}\r\n", target.path).as_bytes())
        .await
        .map_err(|e| format!("quic_request: {e}"))?;
    send.finish().map_err(|e| format!("quic_finish: {e}"))?;

    let part = target_path.with_extension("aidm-quic-part");
    let mut file = tokio::fs::File::create(&part)
        .await
        .map_err(|e| format!("quic_create: {e}"))?;
    let bytes = tokio::io::copy(&mut recv, &mut file)
        .await
        .map_err(|e| format!("quic_read: {e}"))?;
    file.flush().await.map_err(|e| format!("quic_flush: {e}"))?;
    drop(file);
    tokio::fs::rename(&part, target_path)
        .await
        .map_err(|e| format!("quic_commit: {e}"))?;
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    #[test]
    fn uri_shape_is_fail_closed() {
        assert_eq!(
            parse_uri("quic://example.test:9443/files/a.bin").unwrap(),
            QuicTarget {
                host: "example.test".into(),
                port: 9443,
                path: "/files/a.bin".into(),
            }
        );
        for bad in [
            "https://example.test/a",
            "quic:///a",
            "quic://example.test/",
            "quic://example.test/a?token=x",
        ] {
            assert!(parse_uri(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn loopback_hq_downloads_and_commits_file() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let cert =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                    .unwrap();
            let cert_der: CertificateDer<'static> = cert.cert.der().clone();
            let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
            let mut server_tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der.clone()], key.into())
                .unwrap();
            server_tls.alpn_protocols = vec![ALPN.to_vec()];
            let server = quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(server_tls).unwrap(),
            ));
            let endpoint =
                quinn::Endpoint::server(server, SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
            let port = endpoint.local_addr().unwrap().port();
            let payload = b"aidm-quic-loopback".to_vec();
            let server_task = tokio::spawn(async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let request = recv.read_to_end(1024).await.unwrap();
                assert_eq!(request, b"GET /fixture.bin\r\n");
                send.write_all(&payload).await.unwrap();
                send.finish().unwrap();
                connection.closed().await;
            });

            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert_der).unwrap();
            let _tmp = crate::testsupport::tempdir("quic");
            let dir = _tmp.path().to_path_buf();
            let target = dir.join("fixture.bin");
            let bytes = download_uri_with_config(
                &format!("quic://127.0.0.1:{port}/fixture.bin"),
                &target,
                client_config(roots).unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(bytes, 18);
            assert_eq!(std::fs::read(&target).unwrap(), b"aidm-quic-loopback");
            server_task.await.unwrap();
            let _ = std::fs::remove_dir_all(dir);
        });
    }
}
