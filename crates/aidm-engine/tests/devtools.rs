//! 开发工具坐标接入的端到端契约。
//!
//! 引擎把 `npm:lodash@4.17.21` 这类坐标换算成 registry 直链再建任务。本文件守的是
//! **接入层的语义**：换成了什么、文件名从哪来、留了什么痕、以及**不该被换算的输入
//! 一个都不能被误伤**（后者比前者更要紧 —— 静默改写用户的输入是最糟的失败模式）。

mod common;

use std::sync::{Arc, Mutex};

use aidm_core::open_db;

struct TestEnv {
    manager: aidm_engine::DownloadManager,
    db_path: std::path::PathBuf,
    /// 持有 tempdir：Drop 时自动删除。目录落在
    /// `%TEMP%\aidm-tests\aidm-devtools-<tag>-XXXXXX`（见 `tests/common`）。
    _tmp: tempfile::TempDir,
}

impl TestEnv {
    fn new(tag: &str) -> Self {
        let tmp = common::tempdir(&format!("devtools-{tag}"));
        let root = tmp.path().to_path_buf();
        let db_path = root.join("db.sqlite");
        let db = open_db(&db_path).unwrap();
        aidm_core::settings::ensure_defaults(&db).unwrap();
        // 与 integration.rs 的夹具对齐：关掉 Kad，避免测试去碰公网。
        aidm_core::settings::set(&db, "ed2k.kad_enabled", "false").unwrap();
        let manager = aidm_engine::DownloadManager::new(Arc::new(Mutex::new(db)), root.join("dl"));
        Self {
            manager,
            db_path,
            _tmp: tmp,
        }
    }

    /// `(url_orig, file_name, created 事件的 detail)`。
    fn row(&self, id: i64) -> (String, String, String) {
        let conn = open_db(&self.db_path).unwrap();
        let (url, name): (String, String) = conn
            .query_row(
                "SELECT url_orig, file_name FROM downloads WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let detail: String = conn
            .query_row(
                "SELECT coalesce(detail,'') FROM events WHERE download_id=?1 AND kind='created'",
                [id],
                |r| r.get(0),
            )
            .unwrap_or_default();
        (url, name, detail)
    }
}

#[test]
fn npm_coordinate_becomes_a_registry_url_with_its_own_filename() {
    let env = TestEnv::new("npm");
    let id = env
        .manager
        .add("npm:lodash@4.17.21", None, None, None, 0)
        .unwrap();
    let (url, name, detail) = env.row(id);

    assert_eq!(
        url, "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        "落库的必须是换算后的直链，否则下载时没人知道要去哪"
    );
    assert_eq!(
        name, "lodash-4.17.21.tgz",
        "文件名应当来自坐标，而不是从 URL 尾巴猜"
    );
    assert!(
        detail.contains("devtool=npm"),
        "必须留痕：用户输入的是包坐标，落库的是别的地址，不说明白就无从解释: {detail}"
    );
}

/// 显式 `filename` 优先于坐标自带的那个 —— 用户说了算。
#[test]
fn explicit_filename_wins_over_the_coordinate_guess() {
    let env = TestEnv::new("explicit");
    let id = env
        .manager
        .add("cargo:serde@1.0.0", None, Some("mine.crate"), None, 0)
        .unwrap();
    let (url, name, _) = env.row(id);
    assert_eq!(
        url,
        "https://static.crates.io/crates/serde/serde-1.0.0.crate"
    );
    assert_eq!(name, "mine.crate");
}

/// **不该被换算的输入一个都不能被误伤。**
///
/// 这条是**安全网**：换算发生在建任务的必经路径上，误伤意味着用户想下的东西
/// 被静默换成了别处的一个包。
#[test]
fn ordinary_urls_and_scp_style_are_never_rewritten() {
    let env = TestEnv::new("untouched");
    for original in [
        "https://mirrors.example/path/a.iso",
        "http://example.com/b.bin",
        "ftp://ftp.example/pub/c.iso",
        // scp 风格：与 `lodash@4.17.21` 形状相同，**绝不能**变成 npm 下载。
        "user@host",
        // 认不出的工具前缀。
        "gem:rails@7.0.0",
    ] {
        match env.manager.add(original, None, None, None, 0) {
            // 被接受的：URL 必须原样。
            Ok(id) => {
                let (url, _, _) = env.row(id);
                assert_eq!(url, original, "{original} 不该被改写");
            }
            // 被拒绝的（如 `user@host` 不是合法 URL）也是可接受的结果 ——
            // 要点是**不能变成一条 npm 地址**。
            Err(e) => assert!(
                !e.contains("registry.npmjs.org"),
                "{original} 被拒绝可以，但错误里不该出现 registry: {e}"
            ),
        }
    }
}

/// 缺版本要明确回绝，**不能猜 `latest`**。
#[test]
fn missing_version_is_a_clean_refusal() {
    let env = TestEnv::new("noversion");
    let err = env
        .manager
        .add("npm:lodash", None, None, None, 0)
        .unwrap_err();
    assert_eq!(err, "devtool_missing_version");
    assert!(env.manager.list().unwrap().is_empty(), "失败时不该留下任务");
}

/// 带前缀的坐标同样要过重复检查 —— 换算发生在判重**之前**，
/// 所以两次提交同一坐标会被认成重复（而不是因为地址不同而各建一个）。
#[test]
fn same_coordinate_is_detected_as_a_duplicate() {
    let env = TestEnv::new("dup");
    env.manager
        .settings_set("ui.duplicate_action", "skip")
        .unwrap();
    let first = env
        .manager
        .add("npm:lodash@4.17.21", None, None, None, 0)
        .unwrap();
    let err = env
        .manager
        .add("npm:lodash@4.17.21", None, None, None, 0)
        .unwrap_err();
    assert_eq!(err, format!("duplicate_skipped:{first}"));
    assert_eq!(env.manager.list().unwrap().len(), 1);
}

/// 一个够用的 HTTP stub：**每个连接一个线程**。
///
/// 串行 accept 会让下载器的第二条连接排队到超时 —— 下载器会并发开多条连接
/// （探测 + 分片），所以这不是优化而是正确性要求。返回 None 表示 404。
///
/// **返回地址而不再返回 `JoinHandle`**：accept 循环没有停机信号，`join()` 会一直
/// 等到有下一条连接为止 —— 测试跑完后再 join 就是永久挂起（这个坑踩过一次：
/// 下载早已 `done`，进程却停在收尾）。线程随测试进程退出而结束，端口是临时端口，
/// 不会影响其他用例。
fn spawn_stub(
    handler: impl Fn(&str) -> Option<Vec<u8>> + Send + Sync + 'static,
) -> std::net::SocketAddr {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = std::sync::Arc::new(handler);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { break };
            let h = handler.clone();
            std::thread::spawn(move || {
                let Ok(clone) = s.try_clone() else { return };
                let mut reader = BufReader::new(clone);
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    return;
                }
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                loop {
                    let mut h2 = String::new();
                    if reader.read_line(&mut h2).is_err() || h2.trim().is_empty() {
                        break;
                    }
                }
                match h(&path) {
                    Some(body) => {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = s.write_all(resp.as_bytes());
                        let _ = s.write_all(&body);
                    }
                    None => {
                        let _ = s.write_all(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                }
                let _ = s.flush();
                let _ = s.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    addr
}

/// PyPI：坐标 → 查一次元数据接口 → 拿真实文件地址 → 下载。
///
/// PyPI 与 npm/cargo 的区别在于**文件地址构造不出来**（路径含上传时算的哈希目录），
/// 所以这条路径多了一次查询。测试用 `devtools.pypi_api_base` 指向本地 stub ——
/// 这样它不依赖外网、可复现（那个设置项存在的两个理由之一就是这个）。
#[test]
fn pypi_coordinate_is_looked_up_then_downloaded() {
    let wheel: Vec<u8> = (0..4096u32).map(|i| (i % 253) as u8).collect();
    let wheel_for_server = wheel.clone();
    // 闭包在 spawn_stub 返回前就建好了，那时还不知道端口 —— 用 OnceLock 把地址
    // 传进去。处理器只会在 spawn_stub 返回之后被调用，所以读到的必然已设置。
    let addr_cell: std::sync::Arc<std::sync::OnceLock<std::net::SocketAddr>> =
        std::sync::Arc::new(std::sync::OnceLock::new());
    let cell = addr_cell.clone();
    let addr = spawn_stub(move |path: &str| {
        let a = cell.get().expect("地址已设置");
        if path.ends_with("/json") {
            // wheel 与 sdist 都给，验证挑选规则真的生效（应当选纯 wheel）。
            let body = format!(
                r#"{{"urls":[
                   {{"filename":"requests-2.31.0.tar.gz","url":"http://{a}/files/sdist.tar.gz","packagetype":"sdist"}},
                   {{"filename":"requests-2.31.0-py3-none-any.whl","url":"http://{a}/files/requests-2.31.0-py3-none-any.whl","packagetype":"bdist_wheel"}}
                ]}}"#
            );
            Some(body.into_bytes())
        } else if path.contains("requests-2.31.0-py3-none-any.whl") {
            Some(wheel_for_server.clone())
        } else {
            None
        }
    });
    addr_cell.set(addr).ok();

    let env = TestEnv::new("pypi");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    env.manager
        .settings_set("devtools.pypi_api_base", &format!("http://{addr}/pypi"))
        .unwrap();
    let id = env
        .manager
        .add("pip:requests==2.31.0", None, None, None, 0)
        .unwrap();

    // 等完成（最多 40 秒）。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    let mut state = String::new();
    while std::time::Instant::now() < deadline {
        // 必须驱动调度：不 tick，任务永远停在 queued（worker 不会被派发）。
        env.manager.tick();
        if let Ok(Some(t)) = env.manager.status(id) {
            state = t.state.clone();
            if state == "done" || state == "error" {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
    let (url_orig, file_name, detail) = env.row(id);
    if state != "done" {
        // 派发被闸门拦住时，原因会写在事件里 —— 失败时把它带出来，
        // 否则只知道"没动"，不知道"为什么不动"。
        let conn = aidm_core::open_db(&env.db_path).unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT kind, coalesce(detail,'') FROM events WHERE download_id=?1 ORDER BY id",
            )
            .unwrap();
        let evs: Vec<String> = stmt
            .query_map([id], |r| {
                Ok(format!(
                    "{}: {}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        panic!("应当下完，实际 state={state}；created={detail}；事件={evs:?}");
    }
    assert_eq!(state, "done", "应当下完；created={detail}");
    assert_eq!(
        url_orig, "pip:requests==2.31.0",
        "url_orig 必须保留坐标形态：它是稳定标识，真实地址是它的派生物"
    );
    assert_eq!(
        file_name, "requests-2.31.0-py3-none-any.whl",
        "应当选纯 wheel 并用它自带的名字"
    );

    // 内容核对：必须是我们给的那个 wheel 的字节。
    let saved = env.db_path.parent().unwrap().join("dl").join(&file_name);
    assert_eq!(std::fs::read(&saved).unwrap(), wheel);

    // 换算过程要留痕（否则"这个任务在下什么"无从解释）。
    let conn = aidm_core::open_db(&env.db_path).unwrap();
    let ev: String = conn
        .query_row(
            "SELECT coalesce(detail,'') FROM events WHERE download_id=?1 AND kind='pypi_resolved'",
            [id],
            |r| r.get(0),
        )
        .unwrap_or_default();
    assert!(
        ev.contains("py3-none-any.whl"),
        "应当记一条 pypi_resolved 事件: {ev}"
    );
}

/// PyPI 说"这个版本不存在"（404）时，错误码要能区分于"PyPI 出错"。
#[test]
fn pypi_missing_version_has_its_own_code() {
    // 一律 404：模拟"这个版本不存在"。
    let addr = spawn_stub(|_path: &str| None);

    let env = TestEnv::new("pypi404");
    env.manager.settings_set("proxy.mode", "none").unwrap();
    env.manager
        .settings_set("devtools.pypi_api_base", &format!("http://{addr}/pypi"))
        .unwrap();
    let id = env
        .manager
        .add("pip:nosuchpkg==9.9.9", None, None, None, 0)
        .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
    let mut state = String::new();
    while std::time::Instant::now() < deadline {
        // 必须驱动调度：不 tick，任务永远停在 queued（worker 不会被派发）。
        env.manager.tick();
        if let Ok(Some(t)) = env.manager.status(id) {
            state = t.state.clone();
            if state == "error" {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
    assert_eq!(state, "error", "版本不存在就该失败");
    let conn = aidm_core::open_db(&env.db_path).unwrap();
    let row = aidm_core::model::get_download(&conn, id).unwrap().unwrap();
    let err = row.error_code.clone().unwrap_or_default();
    assert!(
        err.contains("pypi_version_not_found"),
        "404 要能与'PyPI 出错'区分开（前者改版本即可，后者重试才有意义）: {err}"
    );
}
