//! 引擎 IPC 服务：回环 TCP 上的单行 JSON（协议 v1，开发文档 §2/§6/§9）。
//!
//! 端口写在 `<应用数据目录>/engine.port`，UI / ext-host 启动后读取并连接。
//! 短连接逐请求处理；`subscribe` 升级为长连接，接收 `EngineEvent` 推送。

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use aidm_ipc::{EngineEvent, EngineRequest, EngineResponse, SUBSCRIBE_HEARTBEAT_SECS};

use crate::manager::DownloadManager;

pub fn serve(manager: Arc<DownloadManager>) -> Result<u16, String> {
    serve_inner(manager, true)
}

/// 测试用：不写全局 `engine.port`，避免污染本机数据目录。
pub fn serve_ephemeral(manager: Arc<DownloadManager>) -> Result<u16, String> {
    serve_inner(manager, false)
}

fn serve_inner(manager: Arc<DownloadManager>, persist_port: bool) -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind loopback: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    if persist_port {
        let port_file = aidm_core::app_data_dir().join(aidm_ipc::PORT_FILE);
        if let Some(parent) = port_file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create data dir: {e}"))?;
        }
        std::fs::write(&port_file, port.to_string())
            .map_err(|e| format!("write port file: {e}"))?;
        log::info!(
            "engine ipc listening on 127.0.0.1:{port} (port file: {})",
            port_file.display()
        );
        // 端口文件自愈：被外部误删或改写时写回，UI 才能重新发现本进程。
        // （UI 只读端口文件来定位引擎；文件丢了会误判引擎离线并反复拉起新进程。）
        {
            let port_file = port_file.clone();
            let want = port.to_string();
            let _ = std::thread::Builder::new()
                .name("aidm-port-file".into())
                .spawn(move || loop {
                    std::thread::sleep(Duration::from_secs(5));
                    if std::fs::read_to_string(&port_file)
                        .map(|s| s.trim() == want)
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    match std::fs::write(&port_file, &want) {
                        Ok(_) => log::info!("engine port file restored: {}", port_file.display()),
                        Err(e) => log::warn!("engine port file rewrite failed: {e}"),
                    }
                });
        }
    } else {
        log::info!("engine ipc listening on 127.0.0.1:{port} (ephemeral)");
    }

    crate::manager::DownloadManager::spawn_scheduler(manager.clone());
    crate::update::spawn_auto_check(manager.clone());
    spawn_stats_ticker(manager.clone());

    std::thread::Builder::new()
        .name("aidm-ipc".into())
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let manager = manager.clone();
                        let loopback = stream
                            .peer_addr()
                            .map(|a| a.ip().is_loopback())
                            .unwrap_or(false);
                        if !loopback {
                            log::warn!("ipc rejected non-loopback peer");
                            continue;
                        }
                        let _ = std::thread::Builder::new()
                            .name("aidm-ipc-conn".into())
                            .spawn(move || handle_conn(stream, manager));
                    }
                    Err(e) => log::warn!("ipc accept failed: {e}"),
                }
            }
        })
        .map_err(|e| format!("spawn ipc thread: {e}"))?;
    Ok(port)
}

fn spawn_stats_ticker(manager: Arc<DownloadManager>) {
    let _ = std::thread::Builder::new()
        .name("aidm-stats".into())
        .spawn(move || {
            let mut was_active = false;
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let snap = manager.stats_snapshot();
                if snap.active {
                    manager.emit_event(EngineEvent::Stats {
                        total_speed: snap.total_speed,
                        active_conns: snap.active_conns,
                        speed_limit: snap.speed_limit,
                    });
                    was_active = true;
                } else if was_active {
                    manager.emit_event(EngineEvent::Stats {
                        total_speed: 0,
                        active_conns: 0,
                        speed_limit: 0,
                    });
                    was_active = false;
                }
            }
        });
}

fn handle_conn(stream: TcpStream, manager: Arc<DownloadManager>) {
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let req = match serde_json::from_str::<EngineRequest>(line.trim()) {
            Ok(req) => req,
            Err(e) => {
                if write_resp(&reader, EngineResponse::err(format!("bad_request: {e}"))).is_err() {
                    break;
                }
                continue;
            }
        };
        if matches!(req, EngineRequest::Subscribe) {
            if write_resp(&reader, EngineResponse::ok()).is_err() {
                break;
            }
            // 长连接：不设读超时，靠 heartbeat 探活。
            let sock = reader.get_ref();
            let _ = sock.set_read_timeout(None);
            let _ = sock.set_write_timeout(None);
            let rx = manager.events().subscribe();
            let mut out = match sock.try_clone() {
                Ok(s) => s,
                Err(_) => break,
            };
            loop {
                let ev = match rx.recv_timeout(Duration::from_secs(SUBSCRIBE_HEARTBEAT_SECS)) {
                    Ok(ev) => ev,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => EngineEvent::Heartbeat,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                };
                let Ok(mut line) = serde_json::to_string(&ev) else {
                    continue;
                };
                line.push('\n');
                if out
                    .write_all(line.as_bytes())
                    .and_then(|_| out.flush())
                    .is_err()
                {
                    break;
                }
            }
            break;
        }
        let resp = dispatch(req, &manager);
        if write_resp(&reader, resp).is_err() {
            break;
        }
    }
}

fn write_resp(reader: &BufReader<TcpStream>, resp: EngineResponse) -> std::io::Result<()> {
    let mut out = serde_json::to_string(&resp)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    out.push('\n');
    reader.get_ref().write_all(out.as_bytes())?;
    reader.get_ref().flush()
}

fn dispatch(req: EngineRequest, manager: &DownloadManager) -> EngineResponse {
    match req {
        EngineRequest::Ping => {
            // 功能协商（文档 10 节）：旧客户端不带 features 字段也能正常解析；
            // 新客户端据 `features` 判定是否读统一视图，不拿超时猜版本。
            let mut resp = EngineResponse::ok();
            resp.features = Some(vec![
                aidm_ipc::FEATURE_UNIFIED_DOWNLOAD_V1.to_owned(),
            ]);
            resp
        }
        EngineRequest::TaskSnapshot {
            id,
            section,
            cursor,
            limit,
        } => {
            match manager.unified_snapshot(
                id as i64,
                section.as_deref(),
                cursor.as_deref(),
                limit,
            ) {
                Ok(snapshot) => {
                    let mut resp = EngineResponse::ok();
                    resp.id = Some(id);
                    resp.snapshot = Some(snapshot);
                    resp
                }
                Err(err) => {
                    // 结构化错误：码在 `code`，不进 `error` 自由文本。
                    let mut resp = EngineResponse::err_code(err.code());
                    resp.id = Some(id);
                    resp.error = Some(err.message());
                    resp
                }
            }
        }
        EngineRequest::Add {
            url,
            dir,
            filename,
            referrer,
            cookies,
            user_agent,
            custom_headers,
            alt_urls,
            offer_id,
            source,
            speed_limit_kbps,
            start,
        } => {
            match manager.add_spec(crate::manager::AddSpec {
                user_agent: user_agent.as_deref(),
                custom_headers: custom_headers.as_deref(),
                alt_urls: alt_urls.as_deref(),
                url: &url,
                dir: dir.as_deref(),
                filename: filename.as_deref(),
                referrer: referrer.as_deref(),
                cookies: cookies.as_deref(),
                offer_id: offer_id.as_deref(),
                speed_limit_kbps,
                source: source.as_deref(),
                start: start.as_deref(),
            }) {
                Ok(id) => {
                    let mut resp = EngineResponse::ok();
                    resp.id = Some(id as u64);
                    resp
                }
                Err(e) if e == aidm_ipc::ERR_OFFER_EXPIRED => EngineResponse::err_code(e),
                Err(e) => EngineResponse::err(e),
            }
        }
        EngineRequest::Offer {
            page_url,
            title,
            items,
            truncated,
            cookies,
        } => match manager.offer(page_url, title, items, truncated, cookies) {
            Ok((offer_id, truncated)) => {
                let mut resp = EngineResponse::ok();
                resp.offer_id = Some(offer_id);
                if truncated {
                    resp.truncated = Some(true);
                }
                resp
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::HostStatus => {
            let mut resp = EngineResponse::ok();
            resp.registered = Some(manager.host_registered());
            resp
        }
        EngineRequest::HostRegister { register } => match manager.host_register(register) {
            Ok(()) => {
                let mut resp = EngineResponse::ok();
                resp.registered = Some(manager.host_registered());
                resp
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Status { id } => match manager.status(id as i64) {
            Ok(Some(task)) => {
                let mut resp = EngineResponse::ok();
                resp.task = Some(task);
                resp
            }
            Ok(None) => EngineResponse::err("task_not_found"),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::TaskEvents { id, limit, offset, filter } => {
            match manager.task_events(id as i64, limit, offset, filter.as_deref()) {
                Ok((events, total)) => {
                    let mut resp = EngineResponse::ok();
                    resp.task_events = Some(events);
                    resp.task_events_total = Some(total);
                    resp
                }
                Err(e) if e == "not_found" => EngineResponse::err_code(e),
                Err(e) => EngineResponse::err(e),
            }
        }
        EngineRequest::TaskEventsClear { id } => match manager.clear_task_events(id as i64) {
            Ok(n) => {
                let mut resp = EngineResponse::ok();
                resp.count = Some(n);
                resp
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::List => match manager.list() {
            Ok(tasks) => {
                let mut resp = EngineResponse::ok();
                resp.tasks = Some(tasks);
                resp
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Capabilities { id, url } => {
            match manager.capabilities(id, url.as_deref()) {
                Ok(caps) => {
                    let mut resp = EngineResponse::ok();
                    resp.capabilities = Some(caps);
                    resp
                }
                // 结构化码：`unsupported_scheme` / `not_found` / `missing_target`
                // 都是调用方能据以分支的稳定标识，不该被塞进 `error` 文本里。
                Err(e)
                    if e == "unsupported_scheme" || e == "not_found" || e == "missing_target" =>
                {
                    EngineResponse::err_code(e)
                }
                Err(e) => EngineResponse::err(e),
            }
        }
        EngineRequest::AddBatch { urls, dir, source } => {
            // 逐条结果，**不整批回滚**：部分失败是批量导入的常态，
            // 整批失败会让用户一条都建不上。所以这里恒回 `ok`，
            // 成败看每一条的 `code`。
            let mut resp = EngineResponse::ok();
            resp.added = Some(manager.add_batch(&urls, dir.as_deref(), source.as_deref()));
            resp
        }
        EngineRequest::DiagExport { id, dir } => match manager.diag_export(id, dir.as_deref()) {
            Ok(path) => {
                let mut resp = EngineResponse::ok();
                resp.diag_path = Some(path);
                resp
            }
            Err(e) if e == "missing_target" => EngineResponse::err_code(e),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Cancel { id } => match manager.cancel(id as i64) {
            Ok(()) => EngineResponse::ok(),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Pause { id } => match manager.pause(id as i64) {
            Ok(()) => EngineResponse::ok(),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Resume { id } => match manager.resume(id as i64) {
            Ok(()) => EngineResponse::ok(),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Restart { id } => match manager.restart(id as i64) {
            Ok(()) => EngineResponse::ok(),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Ed2kHttpSources { id } => match manager.ed2k_http_sources(id) {
            Ok(sources) => {
                let mut resp = EngineResponse::ok();
                resp.http_sources = Some(sources);
                resp
            }
            Err(e) if e == "not_ed2k_task" => EngineResponse::err_code(e),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Ed2kSwitchHttp { id, url } => match manager.switch_ed2k_to_http(id, &url) {
            Ok(task) => {
                let mut resp = EngineResponse::ok();
                resp.task = Some(task);
                resp
            }
            Err(e) if e == "not_ed2k_task" || e == "invalid_url" || e == "already_done" => {
                EngineResponse::err_code(e)
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Rename { id, filename } => match manager.rename(id as i64, &filename) {
            Ok(task) => {
                let mut resp = EngineResponse::ok();
                resp.task = Some(task);
                resp
            }
            Err(e) if e == aidm_ipc::ERR_INVALID_FILENAME || e == aidm_ipc::ERR_NAME_TAKEN => {
                EngineResponse::err_code(e)
            }
            Err(e) => EngineResponse::err(e),
        },
        // 「在磁盘上查找」：名字+大小对上才算命中；截断时如实回 `truncated`
        EngineRequest::FindFile { id } => match manager.find_file(id as i64) {
            Ok(report) => {
                let mut resp = EngineResponse::ok();
                resp.hits = Some(
                    report
                        .hits
                        .iter()
                        .map(|h| aidm_ipc::FindHit {
                            path: h.path.to_string_lossy().into_owned(),
                            size: h.size,
                            modified: h.modified,
                        })
                        .collect(),
                );
                resp.truncated = Some(report.truncated);
                resp
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Relocate { id, path } => match manager.relocate(id as i64, &path) {
            Ok(task) => {
                let mut resp = EngineResponse::ok();
                resp.task = Some(task);
                resp
            }
            Err(e) if e == "file_missing" || e == "size_mismatch" || e == "bad_path" => {
                EngineResponse::err_code(e)
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Ed2kUploadStatus => {
            let mut resp = EngineResponse::ok();
            resp.ed2k_upload = manager.ed2k_upload_status();
            resp
        }
        EngineRequest::QueuesList => match manager.queues_list() {
            Ok(queues) => {
                let mut resp = EngineResponse::ok();
                resp.queues = Some(queues);
                resp
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::QueueCreate {
            name,
            default_dir,
            schedule_cron,
        } => match manager.queue_create(
            &name,
            default_dir.as_deref(),
            schedule_cron.as_deref(),
        ) {
            Ok(queues) => {
                let mut resp = EngineResponse::ok();
                resp.queues = Some(queues);
                resp
            }
            Err(e) if e.starts_with("queue_") => EngineResponse::err_code(e),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::QueueUpdate {
            id,
            name,
            enabled,
            default_dir,
            schedule_cron,
        } => match manager.queue_update(
            id,
            name.as_deref(),
            enabled,
            default_dir.as_deref().map(Some),
            schedule_cron
                .as_deref()
                .map(|c| if c.trim().is_empty() { None } else { Some(c) }),
        ) {
            Ok(queues) => {
                let mut resp = EngineResponse::ok();
                resp.queues = Some(queues);
                resp
            }
            Err(e) if e.starts_with("queue_") => EngineResponse::err_code(e),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::QueueDelete { id } => match manager.queue_delete(id) {
            Ok(queues) => {
                let mut resp = EngineResponse::ok();
                resp.queues = Some(queues);
                resp
            }
            Err(e) if e.starts_with("queue_") => EngineResponse::err_code(e),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::BtFiles { id } => match manager.bt_files(id as i64) {
            Ok((files, _selected)) => {
                let mut resp = EngineResponse::ok();
                resp.bt_files = Some(files);
                resp
            }
            Err(e) if e == "task_not_found" => EngineResponse::err_code(e),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::BtSetFiles { id, indices } => {
            match manager.bt_set_files(id as i64, &indices) {
                Ok(files) => {
                    let mut resp = EngineResponse::ok();
                    resp.bt_files = Some(files);
                    resp
                }
                Err(e) if e == "task_not_found" => EngineResponse::err_code(e),
                Err(e) => EngineResponse::err(e),
            }
        }

        EngineRequest::TaskSetQueue { ids, queue } => match manager.task_set_queue(&ids, queue) {
            Ok(moved) => {
                let mut resp = EngineResponse::ok();
                resp.moved = Some(moved as u64);
                resp
            }
            Err(e) if e == "queue_not_found" || e == "empty_ids" => EngineResponse::err_code(e),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::SettingsGet => match manager.settings_get() {
            Ok(settings) => {
                let mut resp = EngineResponse::ok();
                resp.settings = Some(settings);
                resp
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::SettingsSet { key, value } => match manager.settings_set(&key, &value) {
            Ok(()) => EngineResponse::ok(),
            Err(e) => {
                let mut resp = EngineResponse::err(e.code.clone());
                resp.code = Some(e.code);
                resp.key = e.key;
                resp.min = e.min;
                resp.max = e.max;
                resp
            }
        },
        EngineRequest::RetryFailed => match manager.retry_failed() {
            Ok(count) => {
                let mut resp = EngineResponse::ok();
                resp.count = Some(count);
                resp
            }
            Err(e) => EngineResponse::err(e),
        },
        // 刷新公共源列表。失败时把稳定错误码放进 `code`（`nodes_dat_*` / `server_met_*`），
        // 界面据此给可操作文案，而不是把引擎错误串直接摊给用户。
        EngineRequest::Ed2kNodesRefresh => match manager.ed2k_nodes_refresh() {
            Ok(nodes) => {
                let mut resp = EngineResponse::ok();
                resp.nodes = Some(nodes);
                resp
            }
            Err(e) => {
                let mut resp = EngineResponse::err(e.clone());
                resp.code = Some(e);
                resp
            }
        },
        EngineRequest::Ed2kServersRefresh => match manager.ed2k_servers_refresh() {
            Ok(servers) => {
                let mut resp = EngineResponse::ok();
                resp.servers = Some(servers);
                resp
            }
            Err(e) => {
                let mut resp = EngineResponse::err(e.clone());
                resp.code = Some(e);
                resp
            }
        },
        EngineRequest::SchedStatus => {
            let (next, queued, active) = manager.sched_status();
            let mut resp = EngineResponse::ok();
            resp.next_start_at = Some(match next {
                Some(ms) => serde_json::json!(ms),
                None => serde_json::Value::Null,
            });
            resp.queued = Some(queued);
            resp.active = Some(active);
            resp
        }
        EngineRequest::SystemProxyGet => {
            let mut resp = EngineResponse::ok();
            resp.system_proxy = Some(manager.system_proxy_get());
            resp
        }
        EngineRequest::SettingsSchema => {
            let mut resp = EngineResponse::ok();
            resp.schema = Some(manager.settings_schema());
            resp
        }
        EngineRequest::HostConnsList => {
            let mut resp = EngineResponse::ok();
            resp.hosts = Some(manager.host_conns_list());
            resp
        }
        EngineRequest::SiteLoginsList => match manager.site_logins_list() {
            Ok(logins) => {
                let mut resp = EngineResponse::ok();
                resp.logins = Some(logins);
                resp
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::SiteLoginsSet {
            host,
            username,
            password,
        } => match manager.site_logins_set(&host, &username, &password) {
            Ok(()) => match manager.site_logins_list() {
                Ok(logins) => {
                    let mut resp = EngineResponse::ok();
                    resp.logins = Some(logins);
                    resp
                }
                Err(e) => EngineResponse::err(e),
            },
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::SiteLoginsRemove { host } => match manager.site_logins_remove(&host) {
            Ok(_) => match manager.site_logins_list() {
                Ok(logins) => {
                    let mut resp = EngineResponse::ok();
                    resp.logins = Some(logins);
                    resp
                }
                Err(e) => EngineResponse::err(e),
            },
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::HostConnsSet {
            host,
            max_conns,
            speed_limit_kbps,
        } => match manager.host_conns_set(&host, max_conns, speed_limit_kbps) {
            Ok(hosts) => {
                let mut resp = EngineResponse::ok();
                resp.hosts = Some(hosts);
                resp
            }
            Err(e) => EngineResponse::err_code(e),
        },
        EngineRequest::HostConnsRemove { host } => match manager.host_conns_remove(&host) {
            Ok(hosts) => {
                let mut resp = EngineResponse::ok();
                resp.hosts = Some(hosts);
                resp
            }
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::Delete { ids, delete_files } => match manager.delete(&ids, delete_files) {
            Ok(()) => EngineResponse::ok(),
            Err(e) => EngineResponse::err(e),
        },
        EngineRequest::UpdateCheck => {
            manager.update_check();
            EngineResponse::ok()
        }
        EngineRequest::UpdateDownloadApply => match manager.update_download_apply() {
            Ok(()) => EngineResponse::ok(),
            Err(e) => {
                let mut resp = EngineResponse::err(e);
                resp.code = Some(aidm_ipc::ERR_UPDATE_FAILED.into());
                resp
            }
        },
        // 托盘「完全退出」：先回包，再由短延迟线程退出进程。延迟是为了让本线程
        // 先把 `{ok:true}` 写到 socket（`handle_conn` 在 dispatch 返回后立即写），
        // 避免调用方把「引擎已退出」误判成请求超时。
        EngineRequest::Shutdown => {
            if let Err(e) = std::thread::Builder::new()
                .name("aidm-engine-shutdown".into())
                .spawn(|| {
                    std::thread::sleep(Duration::from_millis(300));
                    log::info!("engine shutdown requested via ipc");
                    std::process::exit(0);
                })
            {
                log::error!("spawn shutdown thread failed: {e}");
            }
            EngineResponse::ok()
        }
        EngineRequest::Subscribe => EngineResponse::ok(),
    }
}
