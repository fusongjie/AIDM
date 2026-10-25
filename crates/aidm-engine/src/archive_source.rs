//! eD2k 任务的 HTTP 备用源发现：当前实现查询 archive.org。
//!
//! 目标不是"把任意 HTTP 地址当镜像"：只返回 archive.org 上**文件名与大小都对得上**的
//! 文件，下载完成后仍由 worker 用 eD2k 整包 MD4 验收。解析函数是纯函数，便于离线
//! 单测；网络失败一律返回空列表，不影响 eD2k 原任务。

use std::io::Read;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;
use url::Url;

use crate::http_util::HttpRuntime;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct HttpSource {
    pub url: String,
    pub label: String,
    pub size: Option<u64>,
    pub provider: &'static str,
}

const SEARCH_URL: &str = "https://archive.org/advancedsearch.php";
const METADATA_PREFIX: &str = "https://archive.org/metadata/";
const DOWNLOAD_PREFIX: &str = "https://archive.org/download/";
const SEARCH_TIMEOUT: Duration = Duration::from_secs(6);
const META_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_IDENTIFIERS: usize = 20;
const MAX_BODY: u64 = 2 * 1024 * 1024;

/// 带硬截止时间的版本：每处理一个 identifier 前检查一次，供 60 s 找源硬顶使用。
pub fn discover_checked_until(
    http: &HttpRuntime,
    file_name: &str,
    size: Option<u64>,
    deadline: Option<Instant>,
) -> Result<Vec<HttpSource>, String> {
    // 三个搜索条件并行：完整文件名 / 关键词+语言词 / 纯关键词。
    // 并行后最坏约 6 s，且仍按优先级取第一个非空结果。
    let mut results: Vec<(u8, Result<Vec<String>, String>)> = Vec::with_capacity(3);
    std::thread::scope(|scope| {
        let (tx, rx) = mpsc::channel();
        let tx0 = tx.clone();
        let tx1 = tx.clone();
        let tx2 = tx.clone();
        scope.spawn(move || {
            let _ = tx0.send((0, search_identifiers(http, file_name)));
        });
        scope.spawn(move || {
            let _ = tx1.send((1, search_keyword_identifiers(http, file_name, true)));
        });
        scope.spawn(move || {
            let _ = tx2.send((2, search_keyword_identifiers(http, file_name, false)));
        });
        drop(tx);
        results.extend(rx.iter());
    });
    results.sort_by_key(|(priority, _)| *priority);
    let mut last_err: Option<String> = None;
    let mut any_success = false;
    let mut ids = Vec::new();
    for (_, result) in results {
        match result {
            Ok(v) => {
                any_success = true;
                if !v.is_empty() {
                    ids = v;
                    break;
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    let mut out = Vec::new();
    for id in ids.into_iter().take(MAX_IDENTIFIERS) {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
        if let Some(src) = metadata_source(http, &id, file_name, size) {
            out.push(src);
        }
    }
    if out.is_empty() && !any_success {
        if let Some(e) = last_err {
            return Err(e);
        }
    }
    Ok(out)
}

fn search_identifiers(http: &HttpRuntime, file_name: &str) -> Result<Vec<String>, String> {
    let mut url = Url::parse(SEARCH_URL).map_err(|e| e.to_string())?;
    let query = format!("filename:\"{}\"", file_name.replace('"', " "));
    url.query_pairs_mut()
        .append_pair("q", &query)
        .append_pair("fl[]", "identifier")
        .append_pair("rows", "8")
        .append_pair("page", "1")
        .append_pair("output", "json");
    let body = get_limited(http, url.as_str(), SEARCH_TIMEOUT)?;
    Ok(parse_identifiers(&body))
}

/// 回退搜索：用文件名里的产品名/版本号查标题。
///
/// 例：`cn_windows_10_education_version_1607_updated_jul_2016_x64_dvd_9056220.iso`
/// → `"windows" AND "10" AND "education" AND "1607"`。最终仍要求 metadata 里的
/// 文件名与大小都对得上，所以宽搜不会把同版本的其他语言 ISO 误当成目标。
fn search_keyword_identifiers(
    http: &HttpRuntime,
    file_name: &str,
    with_language: bool,
) -> Result<Vec<String>, String> {
    let mut words = keywords(file_name);
    if with_language {
        if let Some(lang) = language_word(file_name) {
            words.push(lang.to_string());
        }
    }
    if words.is_empty() {
        return Ok(Vec::new());
    }
    let query = words
        .iter()
        .map(|w| format!("\"{w}\""))
        .collect::<Vec<_>>()
        .join(" AND ");
    let mut url = Url::parse(SEARCH_URL).map_err(|e| e.to_string())?;
    url.query_pairs_mut()
        .append_pair("q", &query)
        .append_pair("fl[]", "identifier")
        .append_pair("rows", "20")
        .append_pair("page", "1")
        .append_pair("output", "json");
    let body = get_limited(http, url.as_str(), SEARCH_TIMEOUT)?;
    Ok(parse_identifiers(&body))
}

/// 文件名前缀的语言代码 → archive.org 标题里常见的英文语言词。
fn language_word(file_name: &str) -> Option<&'static str> {
    let prefix = file_name.split('_').next()?.to_ascii_lowercase();
    Some(match prefix.as_str() {
        "cn" | "zh" | "chs" => "chinese",
        "en" | "enu" => "english",
        "de" | "deu" => "german",
        "es" | "esp" => "spanish",
        "fr" | "fra" => "french",
        "it" | "ita" => "italian",
        "ja" | "jpn" => "japanese",
        "ko" | "kor" => "korean",
        "nl" | "nld" => "dutch",
        "pl" | "pol" => "polish",
        "pt" | "pp" | "ptg" => "portuguese",
        "ru" | "rus" => "russian",
        "tr" | "trk" => "turkish",
        "sr" | "srp" => "serbian",
        "lt" | "ltu" => "lithuanian",
        _ => return None,
    })
}

/// 从文件名提取用于标题搜索的关键词；过滤语言前缀、版本修饰、架构、月份和哈希数字。
fn keywords(file_name: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "cn", "en", "de", "es", "fr", "it", "ja", "ko", "nl", "pl", "pt", "pp", "ru", "tr", "sr",
        "lt", "iso", "version", "updated", "update", "client", "dvd", "dvd9", "vl", "eval", "x64",
        "x86", "amd64", "arm64", "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep",
        "oct", "nov", "dec",
    ];
    let stem = file_name
        .rsplit_once('.')
        .map(|(s, _)| s)
        .unwrap_or(file_name);
    let mut out = Vec::new();
    for raw in stem.split(|c: char| !c.is_ascii_alphanumeric()) {
        let w = raw.to_ascii_lowercase();
        if w.len() < 2 || STOP.contains(&w.as_str()) {
            continue;
        }
        // 长数字多半是微软的文件编号（9056220），标题里通常不出现；保留 4 位版本号，
        // 但年份（2016）不参与标题搜索。
        if w.chars().all(|c| c.is_ascii_digit()) {
            if w.len() > 4 {
                continue;
            }
            if w.len() == 4 && w.parse::<u32>().is_ok_and(|n| (1900..=2100).contains(&n)) {
                continue;
            }
        }
        if !out.contains(&w) {
            out.push(w);
        }
        if out.len() == 5 {
            break;
        }
    }
    out
}

fn metadata_source(
    http: &HttpRuntime,
    identifier: &str,
    file_name: &str,
    size: Option<u64>,
) -> Option<HttpSource> {
    let mut url = Url::parse(METADATA_PREFIX).ok()?;
    url.path_segments_mut().ok()?.push(identifier);
    let body = get_limited(http, url.as_str(), META_TIMEOUT).ok()?;
    parse_metadata_source(identifier, &body, file_name, size)
}

fn get_limited(http: &HttpRuntime, url: &str, timeout: Duration) -> Result<String, String> {
    let resp = http
        .agent_for(url)
        .get(url)
        .timeout(timeout)
        .call()
        .map_err(|e| format!("archive_http: {e}"))?;
    if !(200..300).contains(&resp.status()) {
        return Err(format!("archive_http_{}", resp.status()));
    }
    let mut raw = Vec::new();
    resp.into_reader()
        .take(MAX_BODY + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("archive_read: {e}"))?;
    if raw.len() as u64 > MAX_BODY {
        return Err("archive_body_too_large".into());
    }
    String::from_utf8(raw).map_err(|_| "archive_body_not_utf8".into())
}

/// `advancedsearch.php` 的响应：`response.docs[].identifier`。
fn parse_identifiers(body: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    v.pointer("/response/docs")
        .and_then(Value::as_array)
        .map(|docs| {
            docs.iter()
                .filter_map(|d| d.get("identifier")?.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// metadata 响应里找到同名同大小的文件，并拼出 download URL。
fn parse_metadata_source(
    identifier: &str,
    body: &str,
    file_name: &str,
    size: Option<u64>,
) -> Option<HttpSource> {
    let v = serde_json::from_str::<Value>(body).ok()?;
    let files = v.get("files")?.as_array()?;
    for file in files {
        let Some(name) = file.get("name").and_then(Value::as_str) else {
            continue;
        };
        if !same_file_name(name, file_name) {
            continue;
        }
        let got_size = file.get("size").and_then(parse_size);
        if let (Some(want), Some(got)) = (size, got_size) {
            if want != got {
                continue;
            }
        }
        let url = download_url(identifier, name)?;
        return Some(HttpSource {
            url,
            label: format!("archive.org / {identifier}"),
            size: got_size,
            provider: "archive.org",
        });
    }
    None
}

fn same_file_name(candidate: &str, wanted: &str) -> bool {
    let base = candidate.rsplit('/').next().unwrap_or(candidate);
    base.eq_ignore_ascii_case(wanted)
}

fn parse_size(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn download_url(identifier: &str, name: &str) -> Option<String> {
    let mut url = Url::parse(DOWNLOAD_PREFIX.trim_end_matches('/')).ok()?;
    {
        let mut seg = url.path_segments_mut().ok()?;
        seg.push(identifier);
        // archive.org 的 `name` 可能带子目录；按 `/` 分段 push，避免把斜杠
        // 编成 `%2F` 后服务器找不到文件。
        for part in name.split('/').filter(|p| !p.is_empty()) {
            seg.push(part);
        }
    }
    Some(url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyword_fallback_extracts_product_and_version() {
        let words =
            keywords("cn_windows_10_education_version_1607_updated_jul_2016_x64_dvd_9056220.iso");
        assert_eq!(words, vec!["windows", "10", "education", "1607"]);
        assert_eq!(
            language_word("cn_windows_10_education_version_1607.iso"),
            Some("chinese")
        );
        assert_eq!(language_word("ubuntu-24.04.iso"), None);
        assert!(keywords("x.iso").is_empty());
    }

    #[test]
    fn parses_identifiers_and_tolerates_bad_json() {
        let body = r#"{"response":{"numFound":2,"docs":[{"identifier":"win10iso"},{"identifier":"other"}]}}"#;
        assert_eq!(parse_identifiers(body), vec!["win10iso", "other"]);
        assert!(parse_identifiers("<html>502</html>").is_empty());
        assert!(parse_identifiers("{}").is_empty());
    }

    #[test]
    fn metadata_requires_same_name_and_size_and_builds_encoded_url() {
        let body = r#"{"files":[
            {"name":"readme.txt","size":"10"},
            {"name":"sub/cn windows.iso","size":"4150953984"}
        ]}"#;
        let src = parse_metadata_source("win10iso", body, "cn windows.iso", Some(4_150_953_984))
            .expect("同名同大小应命中");
        assert_eq!(src.provider, "archive.org");
        assert_eq!(src.size, Some(4_150_953_984));
        assert!(src.url.contains("/download/win10iso/"), "{}", src.url);
        assert!(src.url.contains("cn%20windows.iso"), "{}", src.url);

        assert!(parse_metadata_source("win10iso", body, "cn windows.iso", Some(1)).is_none());
        assert!(parse_metadata_source("win10iso", body, "missing.iso", None).is_none());
    }
}
