//! 任务失败文案：只按 `TaskView.error_code` 映射，永不匹配 `error` 文本。
//!
//! 字段与码来自 `aidm-ipc`（#15）：`error_code: Option<String>`、
//! `http_status: Option<u16>`、`EngineResponse.code`（如 `ERR_OFFER_EXPIRED`）。
//! 与 `ui/lib/errors.js` 对齐，无 IO。

// 本模块是 `ui/app.js` 对应逻辑的 Rust 规格镜像：二进制只消费其中少数入口
// （见 `main.rs` 的模块注释），其余条目只被本文件的 `#[cfg(test)] mod tests`
// 使用。这里显式声明，避免每条规格都报 `never used` 把真正的告警淹掉。
#![allow(dead_code)]

use aidm_ipc::{
    EngineResponse, TaskView, ERR_BLOCKED_BY_HOSTS, ERR_DISK_FULL, ERR_HTTP_401, ERR_HTTP_403,
    ERR_HTTP_404, ERR_HTTP_4XX, ERR_HTTP_5XX, ERR_INTERRUPTED, ERR_NETWORK, ERR_NO_PERMISSION,
    ERR_OFFER_EXPIRED, ERR_REMOTE_CHANGED, ERR_UNSUPPORTED_SCHEME,
};

pub const FAIL_GENERIC: &str = "下载失败";
pub const FAIL_NETWORK: &str = "网络连接失败，请检查网络后重试";
pub const FAIL_BLOCKED_BY_HOSTS: &str =
    "域名被本机 hosts/DNS 屏蔽（解析为 0.0.0.0），请检查 hosts 文件或改用代理";
pub const FAIL_DISK_FULL: &str = "磁盘空间不足，请清理后重试";
pub const FAIL_NO_PERMISSION: &str = "没有权限写入保存位置，请换一个文件夹";
pub const FAIL_REMOTE_CHANGED: &str = "服务器上的文件已更新，需要重新下载";
pub const EXT_AUTH_EXPIRED: &str = "登录信息已失效，请回到网页重新点下载";
pub const FAIL_HTTP_401: &str = "需要登录（401）";
pub const FAIL_HTTP_403: &str = "服务器拒绝访问（403）";
pub const FAIL_HTTP_404: &str = "文件不存在或链接已失效";
pub const FAIL_UNSUPPORTED_SCHEME: &str = "暂不支持该类型的链接";
pub const INTERRUPTED_TOOLTIP: &str = "程序意外退出，已自动重新排队";
pub const ENGINE_OFFLINE_BANNER: &str = "无法连接下载引擎，正在重新连接…";
pub const LIST_LOAD_FAIL: &str = "无法连接下载引擎，请确认 AIDM 正在运行后重试";
pub const ADD_DOWNLOAD_FAIL: &str = "添加下载失败，请重试";
pub const PROPS_LOAD_FAIL: &str = "无法获取任务信息，请稍后重试";
pub const OP_FAIL: &str = "操作失败，请重试";
pub const SETTINGS_LOAD_FAIL: &str = "无法读取设置，请重试";
pub const OPEN_DIR_FAIL: &str = "无法打开目录";
pub const OPEN_INSTALL_FAIL: &str = "无法打开安装说明";
pub const COPY_ERROR_DETAIL: &str = "复制错误详情";
pub const DISCARD_SETTINGS: &str = "放弃未保存的修改？";
pub const MOVE_MULTI_TIP: &str = "请只选择一个排队中的任务";
pub const ACTION_CHANGE_LOCATION: &str = "更改位置";
pub const ACTION_REDOWNLOAD: &str = "重新下载";
pub const URL_EMPTY: &str = "请输入下载链接";
pub const URL_SCHEME: &str = "仅支持 http:// 或 https://";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskErrorAction {
    ChangeLocation,
    Redownload,
}

impl TaskErrorAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::ChangeLocation => ACTION_CHANGE_LOCATION,
            Self::Redownload => ACTION_REDOWNLOAD,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskErrorView {
    pub code: Option<String>,
    pub sentence: String,
    pub raw: Option<String>,
    pub action: Option<TaskErrorAction>,
    pub is_failure: bool,
    pub is_interrupted: bool,
}

/// 只认数值字段 `http_status`，不从 `error` 文本解析。
pub fn normalize_http_status(http_status: Option<u16>) -> Option<u16> {
    http_status.filter(|n| (100..=599).contains(n))
}

fn normalize_code(error_code: Option<&str>) -> Option<&str> {
    let code = error_code?.trim();
    if code.is_empty() {
        None
    } else {
        Some(code)
    }
}

fn auth_sentence(code: &str, source: Option<&str>) -> String {
    if source == Some("ext") {
        return EXT_AUTH_EXPIRED.into();
    }
    if code == ERR_HTTP_401 {
        FAIL_HTTP_401.into()
    } else {
        FAIL_HTTP_403.into()
    }
}

fn http_range_sentence(kind: &str, http_status: Option<u16>) -> String {
    match (kind == ERR_HTTP_5XX, normalize_http_status(http_status)) {
        (true, Some(n)) => format!("服务器返回错误（{n}），请稍后重试"),
        (false, Some(n)) if kind == ERR_HTTP_4XX => format!("服务器返回错误（{n}）"),
        (true, None) => "服务器返回错误，请稍后重试".into(),
        _ => "服务器返回错误".into(),
    }
}

/// 只按 `error_code` 映射。`http_status` 仅用于 http_4xx/http_5xx 展示数字。
/// `error` 只出现在属性面板原文，不参与分类。
pub fn describe_task_error(
    error_code: Option<&str>,
    source: Option<&str>,
    error: Option<&str>,
    http_status: Option<u16>,
) -> TaskErrorView {
    let raw = error
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let Some(code) = normalize_code(error_code) else {
        return TaskErrorView {
            code: None,
            sentence: FAIL_GENERIC.into(),
            raw,
            action: None,
            is_failure: true,
            is_interrupted: false,
        };
    };
    if code == ERR_INTERRUPTED {
        return TaskErrorView {
            code: Some(code.into()),
            sentence: "排队中".into(),
            raw,
            action: None,
            is_failure: false,
            is_interrupted: true,
        };
    }
    let (sentence, action) = if code == ERR_BLOCKED_BY_HOSTS {
        (FAIL_BLOCKED_BY_HOSTS.into(), None)
    } else if code == ERR_NETWORK {
        (FAIL_NETWORK.into(), None)
    } else if code == ERR_DISK_FULL {
        (FAIL_DISK_FULL.into(), None)
    } else if code == ERR_NO_PERMISSION {
        (
            FAIL_NO_PERMISSION.into(),
            Some(TaskErrorAction::ChangeLocation),
        )
    } else if code == ERR_REMOTE_CHANGED {
        (
            FAIL_REMOTE_CHANGED.into(),
            Some(TaskErrorAction::Redownload),
        )
    } else if code == ERR_HTTP_401 || code == ERR_HTTP_403 {
        (auth_sentence(code, source), None)
    } else if code == ERR_HTTP_404 {
        (FAIL_HTTP_404.into(), None)
    } else if code == ERR_HTTP_4XX {
        (http_range_sentence(ERR_HTTP_4XX, http_status), None)
    } else if code == ERR_HTTP_5XX {
        (http_range_sentence(ERR_HTTP_5XX, http_status), None)
    } else if code == ERR_UNSUPPORTED_SCHEME {
        (FAIL_UNSUPPORTED_SCHEME.into(), None)
    } else if code.starts_with("ftp_") {
        // FTP 的失败原因由引擎给出（已含服务器码与处置建议），
        // 直接用原文比在界面里再翻一遍更准确、也不会漏新码。
        (
            raw.clone().unwrap_or_else(|| "FTP 传输失败".to_string()),
            None,
        )
    } else {
        (FAIL_GENERIC.into(), None)
    };
    TaskErrorView {
        code: Some(code.into()),
        sentence,
        raw,
        action,
        is_failure: true,
        is_interrupted: false,
    }
}

/// 按 `aidm-ipc::TaskView` 字段分类（`error_code` / `http_status` / `source` / `error`）。
pub fn describe_task_view(task: &TaskView) -> TaskErrorView {
    describe_task_error(
        task.error_code.as_deref(),
        task.source.as_deref(),
        task.error.as_deref(),
        task.http_status,
    )
}

pub fn task_fail_reason(
    error_code: Option<&str>,
    source: Option<&str>,
    error: Option<&str>,
) -> String {
    describe_task_error(error_code, source, error, None).sentence
}

/// `{ok:false, code:"offer_expired"}`；只读 `EngineResponse.code`，不看 `error` 文本。
pub fn is_offer_expired(ok: Option<bool>, code: Option<&str>) -> bool {
    ok == Some(false) && normalize_code(code) == Some(ERR_OFFER_EXPIRED)
}

pub fn is_offer_expired_resp(resp: &EngineResponse) -> bool {
    is_offer_expired(Some(resp.ok), resp.code.as_deref())
}

pub fn is_interrupted_code(error_code: Option<&str>) -> bool {
    normalize_code(error_code) == Some(ERR_INTERRUPTED)
}

pub fn empty_category_title(cat: &str) -> &'static str {
    match cat {
        "active" => "暂无未完成的任务",
        "done" => "暂无已完成的任务",
        "queue" => "暂无队列中的任务",
        "error" => "暂无失败的任务",
        _ => "暂无下载任务",
    }
}

pub fn settings_page_for_key(key: &str) -> &'static str {
    if key.starts_with("paths.") {
        "paths"
    } else if key.starts_with("conn.") || key.starts_with("sched.max_tasks") {
        "conn"
    } else if key.starts_with("sched.") {
        "sched"
    } else if key.starts_with("speed.") {
        "speed"
    } else if key.starts_with("proxy.") {
        "proxy"
    } else if key.starts_with("browser.") {
        "browser"
    } else if key.starts_with("update.") {
        "update"
    } else {
        "general"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(
        code: Option<&str>,
        source: Option<&str>,
        error: Option<&str>,
        http_status: Option<u16>,
    ) -> TaskErrorView {
        describe_task_error(code, source, error, http_status)
    }

    #[test]
    fn every_error_code_maps() {
        assert_eq!(
            view(Some("network"), None, None, None).sentence,
            FAIL_NETWORK
        );
        assert_eq!(
            view(Some(ERR_BLOCKED_BY_HOSTS), None, None, None).sentence,
            FAIL_BLOCKED_BY_HOSTS
        );
        assert_eq!(
            view(Some("disk_full"), None, None, None).sentence,
            FAIL_DISK_FULL
        );
        let perm = view(Some("no_permission"), None, None, None);
        assert_eq!(perm.sentence, FAIL_NO_PERMISSION);
        assert_eq!(perm.action, Some(TaskErrorAction::ChangeLocation));
        assert_eq!(perm.action.unwrap().label(), "更改位置");
        let remote = view(Some("remote_changed"), None, None, None);
        assert_eq!(remote.sentence, FAIL_REMOTE_CHANGED);
        assert_eq!(remote.action, Some(TaskErrorAction::Redownload));
        assert_eq!(remote.action.unwrap().label(), "重新下载");
        assert_eq!(
            view(Some("http_401"), Some("ext"), None, None).sentence,
            EXT_AUTH_EXPIRED
        );
        assert_eq!(
            view(Some("http_403"), Some("ext"), None, None).sentence,
            EXT_AUTH_EXPIRED
        );
        assert_eq!(
            view(Some("http_401"), Some("manual"), None, None).sentence,
            FAIL_HTTP_401
        );
        assert_eq!(
            view(Some("http_403"), Some("manual"), None, None).sentence,
            FAIL_HTTP_403
        );
        assert_eq!(
            view(Some("http_401"), None, None, None).sentence,
            FAIL_HTTP_401
        );
        assert_eq!(
            view(Some("http_404"), None, None, None).sentence,
            FAIL_HTTP_404
        );
        assert_eq!(
            view(Some("http_4xx"), None, Some("ignore me"), Some(418)).sentence,
            "服务器返回错误（418）"
        );
        assert_eq!(
            view(Some("http_5xx"), None, Some("ignore me"), Some(503)).sentence,
            "服务器返回错误（503），请稍后重试"
        );
        assert_eq!(
            view(Some("http_5xx"), None, Some("HTTP 502"), None).sentence,
            "服务器返回错误，请稍后重试"
        );
        assert_eq!(
            view(Some("unsupported_scheme"), None, None, None).sentence,
            FAIL_UNSUPPORTED_SCHEME
        );
        let interrupted = view(Some("interrupted"), None, Some("crash"), None);
        assert!(!interrupted.is_failure);
        assert!(interrupted.is_interrupted);
        assert_eq!(interrupted.sentence, "排队中");
        assert_eq!(INTERRUPTED_TOOLTIP, "程序意外退出，已自动重新排队");
        assert_eq!(
            view(None, None, Some("http_401"), Some(401)).sentence,
            FAIL_GENERIC
        );
        assert_eq!(
            view(Some(""), None, Some("disk full"), None).sentence,
            FAIL_GENERIC
        );
        assert_eq!(
            view(Some("mystery"), None, None, None).sentence,
            FAIL_GENERIC
        );
        assert_eq!(ENGINE_OFFLINE_BANNER, "无法连接下载引擎，正在重新连接…");
        assert_eq!(
            LIST_LOAD_FAIL,
            "无法连接下载引擎，请确认 AIDM 正在运行后重试"
        );
        assert_eq!(ADD_DOWNLOAD_FAIL, "添加下载失败，请重试");
        assert_eq!(URL_EMPTY, "请输入下载链接");
        assert_eq!(OPEN_INSTALL_FAIL, "无法打开安装说明");
        assert_eq!(COPY_ERROR_DETAIL, "复制错误详情");
        assert_eq!(DISCARD_SETTINGS, "放弃未保存的修改？");
        assert_eq!(MOVE_MULTI_TIP, "请只选择一个排队中的任务");
    }

    #[test]
    fn never_matches_error_text() {
        assert_eq!(
            view(None, Some("ext"), Some("http_401"), None).sentence,
            FAIL_GENERIC
        );
        assert_eq!(
            view(None, Some("ext"), Some("401 Unauthorized"), Some(401)).sentence,
            FAIL_GENERIC
        );
        assert_eq!(
            view(Some("http_4xx"), None, Some("418 I'm a teapot"), None).sentence,
            "服务器返回错误"
        );
        assert_eq!(
            view(Some("network"), None, Some("http_401"), Some(401)).sentence,
            FAIL_NETWORK
        );
        assert_eq!(
            task_fail_reason(
                Some("http_401"),
                Some("ext"),
                Some("totally different text")
            ),
            EXT_AUTH_EXPIRED
        );
    }

    fn sample_task(
        error_code: Option<&str>,
        http_status: Option<u16>,
        error: Option<&str>,
        source: Option<&str>,
    ) -> TaskView {
        TaskView {
            id: 1,
            name: "a.bin".into(),
            state: "error".into(),
            done: 0,
            total: None,
            speed: 0,
            pct: None,
            save_path: "/tmp/a.bin".into(),
            url: None,
            error: error.map(str::to_string),
            error_code: error_code.map(str::to_string),
            http_status,
            mode: None,
            p2p: None,
            segments: None,
            source: source.map(str::to_string),
            retry_at: None,
            referrer: None,
            alt_urls: None,
            alt_cursor: None,
            created_at_ms: None,
            queue: None,
            finished_at_ms: None,
            active_ms: None,
            unified_download: None,
        }
    }

    #[test]
    fn task_view_fields_match_aidm_ipc() {
        let v = describe_task_view(&sample_task(
            Some(ERR_HTTP_5XX),
            Some(502),
            Some("do-not-parse-me 418"),
            Some("manual"),
        ));
        assert_eq!(v.sentence, "服务器返回错误（502），请稍后重试");
        assert_eq!(v.raw.as_deref(), Some("do-not-parse-me 418"));
        let old = describe_task_view(&sample_task(None, None, Some("http_401"), None));
        assert_eq!(old.sentence, FAIL_GENERIC);
        assert!(old.code.is_none());
        let json =
            serde_json::to_value(sample_task(Some(ERR_HTTP_404), Some(404), None, None)).unwrap();
        assert_eq!(json["error_code"], "http_404");
        assert_eq!(json["http_status"], 404);
        let back: TaskView = serde_json::from_value(json).unwrap();
        assert_eq!(back.error_code.as_deref(), Some(ERR_HTTP_404));
        assert_eq!(back.http_status, Some(404));
    }

    #[test]
    fn properties_keep_raw_error() {
        let v = view(Some("disk_full"), None, Some("ENOSPC"), None);
        assert_eq!(v.sentence, FAIL_DISK_FULL);
        assert_eq!(v.raw.as_deref(), Some("ENOSPC"));
        assert!(v.is_failure);
    }

    #[test]
    fn offer_expired_requires_ok_false_and_code() {
        assert!(is_offer_expired(Some(false), Some(ERR_OFFER_EXPIRED)));
        assert!(!is_offer_expired(Some(true), Some(ERR_OFFER_EXPIRED)));
        assert!(!is_offer_expired(None, Some(ERR_OFFER_EXPIRED)));
        assert!(!is_offer_expired(Some(false), Some("disabled")));
        assert!(!is_offer_expired(Some(false), None));
        assert!(!is_offer_expired(Some(false), Some("offer_expired text")));
        let expired = EngineResponse::err_code(ERR_OFFER_EXPIRED);
        assert!(is_offer_expired_resp(&expired));
        assert!(expired.error.is_none());
        assert_eq!(expired.code.as_deref(), Some(ERR_OFFER_EXPIRED));
        let via_error = EngineResponse::err(ERR_OFFER_EXPIRED);
        assert!(!is_offer_expired_resp(&via_error));
        let restart =
            serde_json::from_str::<aidm_ipc::EngineRequest>(r#"{"op":"restart","id":9}"#).unwrap();
        assert_eq!(restart, aidm_ipc::EngineRequest::Restart { id: 9 });
        let check =
            serde_json::from_str::<aidm_ipc::EngineRequest>(r#"{"op":"update_check"}"#).unwrap();
        assert_eq!(check, aidm_ipc::EngineRequest::UpdateCheck);
        let apply =
            serde_json::from_str::<aidm_ipc::EngineRequest>(r#"{"op":"update_download_apply"}"#)
                .unwrap();
        assert_eq!(apply, aidm_ipc::EngineRequest::UpdateDownloadApply);
        let ev: aidm_ipc::EngineEvent = serde_json::from_str(
            r#"{"event":"update","phase":"up_to_date","current_version":"0.1.0"}"#,
        )
        .unwrap();
        match ev {
            aidm_ipc::EngineEvent::Update { phase, .. } => {
                assert_eq!(phase, aidm_ipc::UPDATE_PHASE_UP_TO_DATE);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn interrupted_is_not_a_failure() {
        assert!(is_interrupted_code(Some("interrupted")));
        assert!(!is_interrupted_code(Some("network")));
        assert!(!is_interrupted_code(None));
        assert!(!is_interrupted_code(Some("  ")));
    }

    #[test]
    fn empty_titles_and_settings_pages() {
        assert_eq!(empty_category_title("done"), "暂无已完成的任务");
        assert_eq!(empty_category_title("error"), "暂无失败的任务");
        assert_eq!(empty_category_title("all"), "暂无下载任务");
        assert_eq!(settings_page_for_key("proxy.host"), "proxy");
        assert_eq!(settings_page_for_key("conn.global_conn_cap"), "conn");
        assert_eq!(settings_page_for_key("ui.confirm_on_delete"), "general");
        assert_eq!(settings_page_for_key("sched.start_cron"), "sched");
        assert_eq!(settings_page_for_key("update.channel"), "update");
        assert_eq!(settings_page_for_key("update.auto_check"), "update");
    }
}
