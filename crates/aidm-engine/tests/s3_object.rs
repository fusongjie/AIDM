//! `s3://` 接入的端到端契约：引擎把对象地址换成预签名 HTTPS，下载路径复用既有内核。
//!
//! 这里不连真的 S3：签名由服务端裁决，本地无法自证；本文件守的是**接入层的
//! 语义**——`url_orig` 保持稳定标识、`url_final` 换成预签名、缺参数时明确回绝、
//! 以及**凭证不落日志**。签名算法本身由 `s3.rs` 的单元测试覆盖。

mod common;

use std::sync::{Arc, Mutex};

use aidm_core::{open_db, settings};

/// 低层夹具：显式写出要落库的 S3 设置，`None` 的项**不写**。
///
/// 为什么不让 `TestEnv::new` 包办：有两条用例要"只缺一样"（只有凭证没 region、
/// 只有 region 没凭证），三样同给的夹具测不到它们 —— 一次只让一个条件缺失。
/// 临时目录一律走 `tests/common`，落 `%TEMP%\aidm-tests\aidm-s3-<tag>-XXXXXX`。
fn manager_with(
    tag: &str,
    region: Option<&str>,
    creds: Option<(&str, &str)>,
) -> (aidm_engine::DownloadManager, tempfile::TempDir) {
    let tmp = common::tempdir(&format!("s3-{tag}"));
    let root = tmp.path().to_path_buf();
    let db = open_db(&root.join("db.sqlite")).unwrap();
    settings::ensure_defaults(&db).unwrap();
    if let Some(r) = region {
        settings::set(&db, "s3.region", r).unwrap();
    }
    if let Some((ak, sk)) = creds {
        settings::set(&db, "s3.access_key", ak).unwrap();
        settings::set(&db, "s3.secret_key", sk).unwrap();
    }
    let manager = aidm_engine::DownloadManager::new(Arc::new(Mutex::new(db)), root.join("dl"));
    (manager, tmp)
}

struct TestEnv {
    manager: aidm_engine::DownloadManager,
    db_path: std::path::PathBuf,
    /// 持有 tempdir：Drop 时自动删除。
    _tmp: tempfile::TempDir,
}

impl TestEnv {
    /// `creds` 为 `None` 时不写任何 S3 设置。
    fn new(tag: &str, creds: Option<(&str, &str, &str)>) -> Self {
        let (region, pair) = match creds {
            Some((ak, sk, region)) => (Some(region), Some((ak, sk))),
            None => (None, None),
        };
        let (manager, tmp) = manager_with(tag, region, pair);
        let db_path = tmp.path().join("db.sqlite");
        Self {
            manager,
            db_path,
            _tmp: tmp,
        }
    }

    /// 读某一行的 `(url_orig, url_final)`。
    fn urls(&self, id: i64) -> (String, Option<String>) {
        let conn = open_db(&self.db_path).unwrap();
        conn.query_row(
            "SELECT url_orig, url_final FROM downloads WHERE id=?1",
            [id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
        )
        .unwrap()
    }
}

/// 配好凭证后，`s3://` 能被接成一条**可下载的预签名 HTTPS 地址**。
#[test]
fn s3_url_becomes_a_presigned_https_target() {
    let env = TestEnv::new(
        "ok",
        Some((
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
        )),
    );
    let id = env
        .manager
        .add(
            "s3://my-bucket/path/obj.bin",
            None,
            Some("obj.bin"),
            None,
            0,
        )
        .unwrap();
    let (orig, fin) = env.urls(id);

    assert_eq!(
        orig, "s3://my-bucket/path/obj.bin",
        "url_orig 必须保持稳定标识：预签名地址会过期，续传与能力查询都要靠它"
    );
    let fin = fin.expect("url_final 应当已是预签名地址");
    assert!(
        fin.starts_with("https://my-bucket.s3.us-east-1.amazonaws.com/path/obj.bin?"),
        "预签名地址形态不对：{fin}"
    );
    assert!(
        fin.contains("X-Amz-Signature="),
        "必须带上签名，否则服务端会回 403：{fin}"
    );
    assert!(
        fin.contains("X-Amz-SignedHeaders=host"),
        "签名范围应当只有 host（不签 Range 才能保住分片下载）：{fin}"
    );
    assert!(
        !fin.contains("range"),
        "签了 Range 会让每个分段都要重签一份 URL：{fin}"
    );
}

/// 缺凭证要**明确回绝**，不能把 `s3://` 当普通 URL 发出去。
///
/// 后者会得到一个离原因很远的 404/403，用户无从知道"是没配凭证"。
/// 注意这里**显式配好 region**：两样都缺时会先报 region（`parse` 在 `presign`
/// 之前跑），那样就测不到凭证这一条了 —— 一次只让一个条件缺失。
#[test]
fn missing_credentials_are_refused_with_a_stable_code() {
    // 特意不设 access_key / secret_key
    let (manager, _tmp) = manager_with("nocred", Some("us-east-1"), None);

    let err = manager
        .add("s3://bucket/key.bin", None, None, None, 0)
        .unwrap_err();
    assert_eq!(err, "s3_missing_credentials", "缺凭证必须给出稳定错误码");
    assert!(manager.list().unwrap().is_empty(), "失败时不该留下任务");
}

/// 有凭证但没 region：同样明确回绝，**不猜**。
///
/// 猜错 region 得到的是 `AuthorizationHeaderMalformed`，比直说"缺 region"难排查得多。
#[test]
fn missing_region_is_refused_rather_than_guessed() {
    // 特意不设 s3.region
    let (manager, _tmp) = manager_with("noregion", None, Some(("AKIAIOSFODNN7EXAMPLE", "secret")));

    let err = manager
        .add("s3://bucket/key.bin", None, None, None, 0)
        .unwrap_err();
    assert_eq!(err, "s3_missing_region");
}

/// 自建端点（MinIO 这类）按**路径式**拼，桶在路径里而不是子域里。
#[test]
fn custom_endpoint_uses_path_style() {
    let env = TestEnv::new("minio", Some(("AK", "SK", "us-east-1")));
    {
        let conn = open_db(&env.db_path).unwrap();
        settings::set(&conn, "s3.endpoint", "minio.internal:9000").unwrap();
    }
    let id = env
        .manager
        .add("s3://b/k.bin", None, None, None, 0)
        .unwrap();
    let (_, fin) = env.urls(id);
    let fin = fin.unwrap();
    assert!(
        fin.starts_with("https://minio.internal:9000/b/k.bin?"),
        "自建端点应当走路径式（virtual-hosted 的默认证书在那类端点上不成立）：{fin}"
    );
}

/// **凭证绝不落日志**：预签名地址本身含签名，不该出现在事件里。
#[test]
fn secret_never_reaches_the_event_log() {
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let env = TestEnv::new("nolog", Some(("AKIAIOSFODNN7EXAMPLE", secret, "us-east-1")));
    let id = env
        .manager
        .add("s3://bucket/obj.bin", None, None, None, 0)
        .unwrap();

    let conn = open_db(&env.db_path).unwrap();
    let mut stmt = conn
        .prepare("SELECT kind, coalesce(detail,'') FROM events WHERE download_id=?1")
        .unwrap();
    let rows: Vec<(String, String)> = stmt
        .query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    assert!(
        rows.iter().any(|(k, _)| k == "s3_presigned"),
        "应当留下一条 s3_presigned 事件（否则排查时看不出这是 S3 任务）"
    );
    for (kind, detail) in &rows {
        assert!(
            !detail.contains(secret),
            "{kind} 的日志里出现了 secret：{detail}"
        );
        assert!(
            !detail.contains("X-Amz-Signature="),
            "{kind} 的日志里出现了预签名 URL（签名属于凭证）：{detail}"
        );
    }
}
