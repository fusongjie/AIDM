//! 为 MCP 预留的接口：批量创建与诊断导出。
//!
//! 这两条是「把下载管理能力从 UI 里分出来」所缺的最后两块（其余子项——稳定任务
//! id、结构化结果、能力查询、事件订阅、请求去重——此前已经存在）。本文件守的是
//! 它们的**语义边界**，不是"接口存在"：
//!
//! - 批量创建**不做整批回滚**，逐条给结果且**顺序与输入一致**；
//! - 诊断导出与 CLI 共用同一条实现，**脱敏只有一处**。

mod common;

use std::sync::{Arc, Mutex};

use aidm_core::{open_db, settings};

struct TestEnv {
    manager: aidm_engine::DownloadManager,
    /// 持有 tempdir：Drop 时自动删除。目录落在
    /// `%TEMP%\aidm-tests\aidm-reserved-<tag>-XXXXXX`（见 `tests/common`）。
    _tmp: tempfile::TempDir,
    /// 该用例的临时根目录（诊断包的落点也必须在它下面）。
    root: std::path::PathBuf,
}

impl TestEnv {
    fn new(tag: &str) -> Self {
        let tmp = common::tempdir(&format!("reserved-{tag}"));
        let root = tmp.path().to_path_buf();
        let db = open_db(&root.join("db.sqlite")).unwrap();
        settings::ensure_defaults(&db).unwrap();
        let manager = aidm_engine::DownloadManager::new(Arc::new(Mutex::new(db)), root.join("dl"));
        Self {
            manager,
            _tmp: tmp,
            root,
        }
    }
}

/// 一批里混着"能建的""不支持的""重复的"——这是批量导入的真实形状。
///
/// 三条语义一次钉住：① 不整批失败；② 成功项真的落库；③ **顺序与输入一致**
/// （调用方按序对账，顺序错了就全对不上）。
#[test]
fn batch_add_reports_per_item_without_rolling_back() {
    let env = TestEnv::new("batch");
    let urls = vec![
        "https://mirrors.example/one.iso".to_string(),
        "gopher://old.example/1/nope".to_string(), // 不支持的 scheme
        "https://mirrors.example/two.iso".to_string(),
    ];
    let out = env.manager.add_batch(&urls, None, Some("manual"));

    assert_eq!(out.len(), urls.len(), "结果必须与输入等长");
    for (i, item) in out.iter().enumerate() {
        assert_eq!(item.url, urls[i], "第 {i} 项顺序错了，调用方将无法对账");
    }

    // 能建的两条：给了 id、没有 code。
    assert!(out[0].id.is_some(), "第一条应当建成");
    assert!(out[0].code.is_none());
    assert!(out[2].id.is_some(), "第三条应当建成");
    assert!(out[2].code.is_none());
    // 不支持的那条：只给 code，且**不影响**其它两条。
    assert!(out[1].id.is_none(), "不支持的 scheme 不该拿到 id");
    assert!(out[1].code.is_some(), "失败项必须给出原因码");

    // 落库核对：成功的确实在库里。
    let listed = env.manager.list().unwrap();
    let urls_in_db: Vec<Option<&str>> = listed.iter().map(|t| t.url.as_deref()).collect();
    assert!(
        urls_in_db.contains(&Some("https://mirrors.example/one.iso")),
        "第一条应当真的落库"
    );
    assert!(
        urls_in_db.contains(&Some("https://mirrors.example/two.iso")),
        "第三条应当真的落库（前面的失败不能中断整批）"
    );
    assert_eq!(listed.len(), 2, "只应落库两条");
}

/// 重复项在批量里同样要被逐条标出来，而不是让整批失败。
///
/// 注意 `ui.duplicate_action` 的**默认值是 `allow`**（重复 URL 允许建新任务），
/// 所以这里必须显式改成 `skip` 才能验证"重复被标出"这条语义 —— 否则测的是
/// "允许重复"，与批量语义无关。
#[test]
fn batch_add_flags_duplicates_per_item() {
    let env = TestEnv::new("dup");
    env.manager
        .settings_set("ui.duplicate_action", "skip")
        .unwrap();

    let url = "https://mirrors.example/same.iso".to_string();
    // 先单独建一条，制造"已存在"。
    env.manager
        .add(&url, None, Some("same.iso"), None, 0)
        .unwrap();

    let out = env
        .manager
        .add_batch(&[url.clone(), url.clone()], None, None);
    assert_eq!(out.len(), 2);
    for (i, item) in out.iter().enumerate() {
        assert!(
            item.id.is_none(),
            "第 {i} 条是重复项，不该再建一个任务: {item:?}"
        );
        let code = item
            .code
            .as_deref()
            .unwrap_or_else(|| panic!("第 {i} 条必须给出原因码"));
        assert!(
            code.starts_with("duplicate_"),
            "第 {i} 条的原因码应当指明重复，实际是 {code}"
        );
    }
    // 只有最初那一条，没有多出来。
    assert_eq!(env.manager.list().unwrap().len(), 1, "重复项不该真的建任务");
}

/// 空批次是合法的（返回空表），不该报错 —— 批量导入上游给空列表是正常的。
#[test]
fn batch_add_of_nothing_is_ok() {
    let env = TestEnv::new("empty");
    assert!(env.manager.add_batch(&[], None, None).is_empty());
}

/// 诊断导出必须有目标；缺目标要回稳定错误码，而不是导出一个空包。
#[test]
fn diag_export_requires_a_target() {
    let env = TestEnv::new("diag-missing");
    assert_eq!(
        env.manager.diag_export(None, None).unwrap_err(),
        "missing_target"
    );
}

/// 导出成功要真的落盘，并回报路径。
///
/// 这条同时守着"与 CLI 共用一条实现"：如果哪天有人为了 IPC 另写一份导出，
/// 这里的产出形状（真实文件 + 路径可读）就会先坏掉。
#[test]
fn diag_export_writes_a_real_bundle() {
    let env = TestEnv::new("diag");
    let id = env
        .manager
        .add(
            "https://mirrors.example/a.iso",
            None,
            Some("a.iso"),
            None,
            0,
        )
        .unwrap();

    // 诊断包也必须落在本用例的临时目录里（不碰 `%TEMP%` 根、不碰真实数据目录）。
    let dir = env.root.join("diag-out");
    std::fs::create_dir_all(&dir).unwrap();
    let path = env
        .manager
        .diag_export(Some(id as u64), Some(&dir.to_string_lossy()))
        .unwrap();

    let p = std::path::Path::new(&path);
    assert!(p.exists(), "回报的路径必须真的存在: {path}");
    let meta = std::fs::metadata(p).unwrap();
    assert!(meta.len() > 0, "诊断包不该是空文件: {path}");
    assert_eq!(
        p.parent().map(|x| x.to_path_buf()),
        Some(dir.clone()),
        "应当落在调用方指定的目录里"
    );
}
