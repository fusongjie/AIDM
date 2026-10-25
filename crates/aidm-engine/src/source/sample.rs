//! 抽样读取（`docs/source-discovery.md` §4.7 S1 / §4.8 探测）。
//!
//! 只负责"按抽样计划取字节并算指纹"；比较与淘汰在
//! `aidm_core::source::verify` 里做（纯逻辑，便于单测）。
//!
//! 抽样失败不升级为任务失败：调用方把该候选排除出"可比对集合"即可，
//! 单源下载仍然可以继续。

use std::sync::Arc;
use std::time::Instant;

use aidm_core::http_profile::RequestProfile;
use aidm_core::source::verify::{fingerprint, sample_ranges, SampleSet};
use aidm_core::source::SourceCapabilities;

use crate::http_util::HttpRuntime;
use crate::source::adapter::AdapterError;
use crate::source::provider::{HttpProvider, ProviderError, ReadRequest, SourceProvider};

/// 一次抽样读取的结果 + 时间样本（用于诊断/后续评分接入）。
#[derive(Debug, Clone)]
pub struct SampleFetch {
    pub set: SampleSet,
    /// 第一次读取的 TTFB（毫秒）。
    pub ttfb_ms: u64,
    /// 全部抽样读取的总耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 实际读取的字节数。
    pub bytes: u64,
}

/// 取一组抽样。`size` 必须是已知的总长度；`size == 0` 返回空指纹。
pub fn fetch_samples(
    http: &Arc<HttpRuntime>,
    profile: &RequestProfile,
    url: &str,
    size: u64,
    referer: Option<&str>,
    cookies: Option<&str>,
    custom_headers: &[aidm_core::headers::HeaderLine],
) -> Result<SampleFetch, AdapterError> {
    let ranges = sample_ranges(size);
    if ranges.is_empty() {
        let set = fingerprint(size, &[], &[])
            .ok_or_else(|| AdapterError::Malformed("empty sample set".into()))?;
        return Ok(SampleFetch {
            set,
            ttfb_ms: 0,
            elapsed_ms: 0,
            bytes: 0,
        });
    }

    let provider = HttpProvider::new(
        url.to_string(),
        http.agent_for(url),
        profile.clone(),
        referer.map(str::to_string),
        cookies.map(str::to_string),
        custom_headers.to_vec(),
    );
    let source_id = provider.id();
    let started = Instant::now();
    let mut ttfb_ms = 0u64;
    let mut bytes = 0u64;
    let mut samples: Vec<Vec<u8>> = Vec::with_capacity(ranges.len());
    for range in &ranges {
        let t0 = Instant::now();
        let chunk = provider
            .read_range(&ReadRequest {
                source_id: source_id.clone(),
                offset: range.offset,
                len: range.len,
                expected_version: None,
            })
            .map_err(map_provider_error)?;
        if ttfb_ms == 0 {
            ttfb_ms = t0.elapsed().as_millis() as u64;
        }
        bytes += chunk.bytes.len() as u64;
        samples.push(chunk.bytes);
    }
    let set = fingerprint(size, &ranges, &samples)
        .ok_or_else(|| AdapterError::Malformed("sample length mismatch".into()))?;
    Ok(SampleFetch {
        set,
        ttfb_ms,
        elapsed_ms: started.elapsed().as_millis() as u64,
        bytes,
    })
}

/// 采样只需要"能按区间读"；把 ProviderError 映射为找源层的错误分类。
fn map_provider_error(err: ProviderError) -> AdapterError {
    match err {
        ProviderError::Network(msg) => AdapterError::Network(msg),
        ProviderError::Auth { status } | ProviderError::Http { status } => {
            AdapterError::from_status(status)
        }
        ProviderError::Unsupported
        | ProviderError::SequentialOnly
        | ProviderError::RangeIgnored => AdapterError::Unsupported,
        ProviderError::RangeNotSatisfiable { .. }
        | ProviderError::RangeMismatch { .. }
        | ProviderError::ShortRead { .. }
        | ProviderError::Expired
        | ProviderError::VersionChanged
        | ProviderError::UnsupportedEncoding(_)
        | ProviderError::Config(_) => AdapterError::Malformed(format!("sample: {err}")),
    }
}

/// 测试/诊断用的能力查询：采样源至少要求运行时支持区间读。
pub fn sampled_capabilities() -> SourceCapabilities {
    SourceCapabilities {
        random_read: true,
        resume: true,
        length_query: true,
        version_check: false,
        conns_max: 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    fn dummy_http() -> Arc<HttpRuntime> {
        HttpRuntime::from_db(&std::sync::Mutex::new(
            rusqlite::Connection::open_in_memory().unwrap(),
        ))
    }

    /// 起一个能处理 `requests` 次 Range 请求的服务器。
    fn serve_ranges(
        body: Vec<u8>,
        requests: usize,
        honor_range: bool,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let range = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("range:"))
                    .and_then(|l| l.split_once('='))
                    .and_then(|(_, r)| r.split_once('-'))
                    .and_then(|(a, b)| {
                        Some((
                            a.trim().parse::<usize>().ok()?,
                            b.trim().parse::<usize>().ok()?,
                        ))
                    });
                if !honor_range {
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&body);
                    continue;
                }
                let Some((start, end)) = range else {
                    let _ = stream.write_all(
                        b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n",
                    );
                    continue;
                };
                let end = end.min(body.len().saturating_sub(1));
                let slice = &body[start..=end];
                let head = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{}\r\nContent-Length: {}\r\n\r\n",
                    body.len(),
                    slice.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(slice);
            }
        });
        (format!("http://{addr}/f.bin"), handle)
    }

    #[test]
    fn fetches_three_ranges_and_matches_core_fingerprint() {
        let size = 200_000usize;
        let body: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let (url, handle) = serve_ranges(body.clone(), 3, true);
        let got = fetch_samples(
            &dummy_http(),
            &RequestProfile::default(),
            &url,
            size as u64,
            None,
            None,
            &[],
        )
        .unwrap();
        let expected_ranges = sample_ranges(size as u64);
        let expected_samples: Vec<Vec<u8>> = expected_ranges
            .iter()
            .map(|r| body[r.offset as usize..(r.offset + r.len) as usize].to_vec())
            .collect();
        let expected = fingerprint(size as u64, &expected_ranges, &expected_samples).unwrap();
        assert_eq!(got.set, expected);
        assert_eq!(
            got.bytes,
            expected_ranges.iter().map(|r| r.len).sum::<u64>()
        );
        handle.join().unwrap();
    }

    #[test]
    fn range_ignored_is_unsupported_for_sampling() {
        let body = vec![7u8; 200_000];
        let (url, handle) = serve_ranges(body, 1, false);
        let err = fetch_samples(
            &dummy_http(),
            &RequestProfile::default(),
            &url,
            200_000,
            None,
            None,
            &[],
        )
        .unwrap_err();
        assert_eq!(err, AdapterError::Unsupported);
        handle.join().unwrap();
    }

    #[test]
    fn zero_size_is_empty_fingerprint() {
        let got = fetch_samples(
            &dummy_http(),
            &RequestProfile::default(),
            "http://127.0.0.1:9/never.bin",
            0,
            None,
            None,
            &[],
        )
        .unwrap();
        assert_eq!(got.bytes, 0);
        assert!(got.set.ranges.is_empty());
    }
}
