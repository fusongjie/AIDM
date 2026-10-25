//! MCP 工具表：每个工具都是某个 `EngineRequest` 变体的薄映射。
//!
//! 三条硬约束（14-mcp-service.md R-MCPS-05）：
//! 1. 工具名 = `aidm_` + op 的 snake_case；
//! 2. 参数名与 `EngineRequest` 字段**逐字相同**，不改名、不拆包；
//! 3. 每个工具都必须能构造出一个真实的 `EngineRequest`（由测试穷举）。
//!
//! 未知参数在这里就被拒绝（`additionalProperties: false` 的运行时对应物）：
//! 否则 serde 会静默忽略拼错的字段，模型得到"成功"却什么都没设。

use serde_json::{json, Map, Value};

use aidm_ipc::EngineRequest;

/// 读写分类：决定默认是否暴露（R-MCPS-11）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Read,
    Write,
}

/// 参数类型。故意不含 `Number`（浮点）：引擎参数全是整数或字符串。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Str,
    U64,
    I64,
    I32,
    U32,
    Bool,
    Strs,
    U64s,
}

pub struct ParamSpec {
    pub name: &'static str,
    pub ty: Ty,
    pub required: bool,
    /// 补进 JSON Schema 的 `description`（空串则不写）。
    pub note: &'static str,
}

impl ParamSpec {
    pub const fn req(name: &'static str, ty: Ty) -> Self {
        Self {
            name,
            ty,
            required: true,
            note: "",
        }
    }

    pub const fn opt(name: &'static str, ty: Ty) -> Self {
        Self {
            name,
            ty,
            required: false,
            note: "",
        }
    }

    pub const fn opt_note(name: &'static str, ty: Ty, note: &'static str) -> Self {
        Self {
            name,
            ty,
            required: false,
            note,
        }
    }
}

pub struct ToolSpec {
    pub name: &'static str,
    pub op: &'static str,
    pub class: Class,
    pub summary: &'static str,
    pub params: &'static [ParamSpec],
    /// `annotations.destructiveHint`（只对写工具输出）。
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
}

const DIR_NOTE: &str = "绝对目录路径。相对路径会被拒绝：引擎按自己的进程工作目录解释相对路径。";
const DEFAULT_DIR_NOTE: &str = "队列的默认下载目录，必须是绝对路径。";
const LIMIT_NOTE: &str = "最多返回多少条最近事件（引擎默认 50、上限 200）。";
const SOURCE_NOTE: &str = "任务来源标记，通常是 manual。";
const START_NOTE: &str = "now（默认，立即可调度）或 queue（若有 cron，等到下次触发）。";

// 顺序按工具名升序：`tools/list` 要求确定性顺序（B-4），这里直接把数据写好，
// 运行时再排一次序作为双保险。
pub const TOOLS: &[ToolSpec] = &[
    ToolSpec {
        name: "aidm_add",
        op: "add",
        class: Class::Write,
        summary: "Create one download task. Returns the task id immediately; poll aidm_status for progress.",
        params: &[
            ParamSpec::req("url", Ty::Str),
            ParamSpec::opt_note("dir", Ty::Str, DIR_NOTE),
            ParamSpec::opt("filename", Ty::Str),
            ParamSpec::opt("referrer", Ty::Str),
            ParamSpec::opt("alt_urls", Ty::Str),
            ParamSpec::opt_note("source", Ty::Str, SOURCE_NOTE),
            ParamSpec::opt("speed_limit_kbps", Ty::U64),
            ParamSpec::opt_note("start", Ty::Str, START_NOTE),
        ],
        destructive: false,
        idempotent: false,
        open_world: true,
    },
    ToolSpec {
        name: "aidm_add_batch",
        op: "add_batch",
        class: Class::Write,
        summary: "Create many download tasks at once. Returns one result per URL, in input order; never rolls back the whole batch.",
        params: &[
            ParamSpec::req("urls", Ty::Strs),
            ParamSpec::opt_note("dir", Ty::Str, DIR_NOTE),
            ParamSpec::opt_note("source", Ty::Str, SOURCE_NOTE),
        ],
        destructive: false,
        idempotent: false,
        open_world: true,
    },
    ToolSpec {
        name: "aidm_bt_files",
        op: "bt_files",
        class: Class::Read,
        summary: "Read the per-file selection table of a BitTorrent task.",
        params: &[ParamSpec::req("id", Ty::U64)],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_cancel",
        op: "cancel",
        class: Class::Write,
        summary: "Cancel a task cooperatively. Deletes the unfinished file and the task record; the final file of a finished task is kept.",
        params: &[ParamSpec::req("id", Ty::U64)],
        destructive: true,
        idempotent: true,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_capabilities",
        op: "capabilities",
        class: Class::Read,
        summary: "Query the four-layer protocol conclusion and the capability upper bound for a URL or an existing task. Always read `note`; the flags are an upper bound, not a promise.",
        params: &[
            ParamSpec::opt_note("id", Ty::U64, "查已有任务时用它的生效地址。"),
            ParamSpec::opt_note("url", Ty::Str, "新建前预检：给地址，不落库。"),
        ],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_diag_export",
        op: "diag_export",
        class: Class::Write,
        summary: "Export a redacted diagnostic bundle for a task. Returns the bundle path. Writes files, so it needs --allow-write.",
        params: &[
            ParamSpec::req("id", Ty::U64),
            ParamSpec::opt_note("dir", Ty::Str, DIR_NOTE),
        ],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_ed2k_http_sources",
        op: "ed2k_http_sources",
        class: Class::Read,
        summary: "Find HTTP mirrors for an eD2k task (currently archive.org).",
        params: &[ParamSpec::req("id", Ty::I64)],
        destructive: false,
        idempotent: false,
        open_world: true,
    },
    ToolSpec {
        name: "aidm_ed2k_upload_status",
        op: "ed2k_upload_status",
        class: Class::Read,
        summary: "Read eD2k inbound upload status (runtime-only numbers).",
        params: &[],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_list",
        op: "list",
        class: Class::Read,
        summary: "List all tasks with their state, progress and save path.",
        params: &[],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_pause",
        op: "pause",
        class: Class::Write,
        summary: "Pause a running task, keeping already written bytes for resume.",
        params: &[ParamSpec::req("id", Ty::U64)],
        destructive: false,
        idempotent: true,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_queue_create",
        op: "queue_create",
        class: Class::Write,
        summary: "Create a named queue (optional cron window / default dir).",
        params: &[
            ParamSpec::req("name", Ty::Str),
            ParamSpec::opt_note("default_dir", Ty::Str, DEFAULT_DIR_NOTE),
            ParamSpec::opt("schedule_cron", Ty::Str),
        ],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_queue_update",
        op: "queue_update",
        class: Class::Write,
        summary: "Update a named queue. Only the fields you send are changed; an empty schedule_cron clears the cron.",
        params: &[
            ParamSpec::req("id", Ty::I64),
            ParamSpec::opt("name", Ty::Str),
            ParamSpec::opt("enabled", Ty::Bool),
            ParamSpec::opt_note("default_dir", Ty::Str, DEFAULT_DIR_NOTE),
            ParamSpec::opt("schedule_cron", Ty::Str),
        ],
        destructive: false,
        idempotent: true,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_queues_list",
        op: "queues_list",
        class: Class::Read,
        summary: "List named queues with their task counts. The default queue is id 1.",
        params: &[],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_rename",
        op: "rename",
        class: Class::Write,
        summary: "Rename the target file of a task. Unfinished tasks only change the DB name; finished tasks rename on disk.",
        params: &[
            ParamSpec::req("id", Ty::U64),
            ParamSpec::req("filename", Ty::Str),
        ],
        destructive: false,
        idempotent: true,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_restart",
        op: "restart",
        class: Class::Write,
        summary: "Restart a task from scratch: drops segments and the .aidm/<id>/ part directory, then requeues the same id.",
        params: &[ParamSpec::req("id", Ty::U64)],
        destructive: true,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_resume",
        op: "resume",
        class: Class::Write,
        summary: "Resume a paused task. If ETag/Last-Modified changed, the engine refuses to resume and starts over.",
        params: &[ParamSpec::req("id", Ty::U64)],
        destructive: false,
        idempotent: true,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_retry_failed",
        op: "retry_failed",
        class: Class::Write,
        summary: "Requeue every failed task. Returns how many were requeued.",
        params: &[],
        destructive: false,
        idempotent: true,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_sched_status",
        op: "sched_status",
        class: Class::Read,
        summary: "Read scheduler status: next cron start (unix ms or null), queued count, active count.",
        params: &[],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_settings_get",
        op: "settings_get",
        class: Class::Read,
        summary: "Read all settings. Secrets are never returned in clear text: proxy.pass becomes proxy.has_password.",
        params: &[],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_settings_set",
        op: "settings_set",
        class: Class::Write,
        summary: "Change one whitelisted download-behaviour setting. Non-whitelisted keys (paths, proxy, s3, update, browser) are rejected.",
        params: &[
            ParamSpec::req("key", Ty::Str),
            ParamSpec::req("value", Ty::Str),
        ],
        destructive: false,
        idempotent: true,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_status",
        op: "status",
        class: Class::Read,
        summary: "Read one task: state, bytes, speed, segments, error_code. This is the polling endpoint for long downloads.",
        params: &[ParamSpec::req("id", Ty::U64)],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_task_events",
        op: "task_events",
        class: Class::Read,
        summary: "Read recent structured events of one task (oldest first). `detail` is already redacted.",
        params: &[
            ParamSpec::req("id", Ty::U64),
            ParamSpec::opt_note("limit", Ty::U32, LIMIT_NOTE),
        ],
        destructive: false,
        idempotent: false,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_task_set_queue",
        op: "task_set_queue",
        class: Class::Write,
        summary: "Move tasks to an existing queue (appended to that queue's tail). Returns how many moved.",
        params: &[
            ParamSpec::req("ids", Ty::U64s),
            ParamSpec::req("queue", Ty::I64),
        ],
        destructive: false,
        idempotent: true,
        open_world: false,
    },
    ToolSpec {
        name: "aidm_wait",
        op: "status",
        class: Class::Read,
        summary: "Wait for a task to reach done/error, sending progress notifications when the client supplied a progressToken. Returns the last observed status (isError=true on timeout). With the Tasks extension it returns a task handle instead of blocking.",
        params: &[
            ParamSpec::req("id", Ty::U64),
            ParamSpec::opt("timeout_s", Ty::U32),
        ],
        destructive: false,
        idempotent: true,
        open_world: false,
    },
];

/// 复合工具：唯一一个不对应独立 `EngineRequest` 变体的工具。
///
/// 它循环调用 `status` 直到终态，用来承载 MCP 的 `notifications/progress`
/// （progress 只能挂在未完成的请求上，而 `add` 必须立即返回）。
/// 它**不改变任何状态**，所以仍是只读工具。
pub const WAIT_TOOL: &str = "aidm_wait";
pub const DEFAULT_WAIT_S: u64 = 30;
pub const MAX_WAIT_S: u64 = 120;

/// 按名字查工具（`tools/call` 用）。
pub fn find(name: &str) -> Option<&'static ToolSpec> {
    TOOLS.iter().find(|t| t.name == name)
}

/// 未暴露的 op 清单（R-MCPS-09）。第二列是文档里的类别：
/// `A` 不可逆删除/结构破坏；`B` 凭据·注册表·代码执行·关进程；
/// `C` 浏览器-UI 专用；`D` 需要用户在场或改变既有任务语义。
///
/// 这张表与 `TOOLS` 的并集**必须**等于 `EngineRequest` 的全部变体，由测试穷举契约源码盯住。
/// 二进制本身不读它（它只服务测试与文档对账），所以显式允许 dead_code。
#[allow(dead_code)]
pub const HIDDEN_OPS: &[(&str, &str)] = &[
    ("bt_set_files", "D"),
    ("delete", "A"),
    ("ed2k_nodes_refresh", "D"),
    ("ed2k_servers_refresh", "D"),
    ("ed2k_switch_http", "D"),
    ("find_file", "D"),
    ("host_conns_list", "D"),
    ("host_conns_remove", "D"),
    ("host_conns_set", "D"),
    ("host_register", "B"),
    ("host_status", "C"),
    ("offer", "C"),
    ("ping", "C"),
    ("queue_delete", "A"),
    ("relocate", "D"),
    ("settings_schema", "C"),
    ("shutdown", "B"),
    ("site_logins_list", "B"),
    ("site_logins_remove", "B"),
    ("site_logins_set", "B"),
    ("subscribe", "C"),
    ("system_proxy_get", "C"),
    // 统一视图分页快照：只读，但属于引擎内部诊断面，不默认暴露给 MCP。
    ("task_snapshot", "C"),
    // 清空任务日志：写操作，不暴露。
    ("task_events_clear", "A"),
    ("update_check", "B"),
    ("update_download_apply", "B"),
];

/// 当前授权下可见的工具，按名字升序（B-4 要求确定性顺序）。
pub fn visible(allow_write: bool) -> Vec<&'static ToolSpec> {
    let mut out: Vec<&'static ToolSpec> = TOOLS
        .iter()
        .filter(|t| allow_write || t.class == Class::Read)
        .collect();
    out.sort_by_key(|t| t.name);
    out
}

/// `settings_set` 的闭集白名单（R-MCPS-11）。新增键必须先改规则。
pub const WRITABLE_SETTINGS: &[&str] = &[
    "sched.window_enabled",
    "sched.window_start",
    "sched.window_end",
    "sched.window_days",
    "conn.speed_limit_default_kbps",
];

/// `aidm_add_batch` 的条数硬限（引擎侧没有上限，见 R-MCPS-11）。
pub const MAX_BATCH_URLS: usize = 100;

fn ty_schema(spec: &ParamSpec) -> Value {
    let mut schema = match spec.ty {
        Ty::Str => json!({"type": "string"}),
        Ty::U64 => json!({"type": "integer", "minimum": 0}),
        Ty::I64 | Ty::I32 => json!({"type": "integer"}),
        Ty::U32 => json!({"type": "integer", "minimum": 0, "maximum": u32::MAX}),
        Ty::Bool => json!({"type": "boolean"}),
        Ty::Strs => json!({"type": "array", "items": {"type": "string"}}),
        Ty::U64s => json!({"type": "array", "items": {"type": "integer", "minimum": 0}}),
    };
    if !spec.note.is_empty() {
        schema["description"] = Value::String(spec.note.to_string());
    }
    schema
}

/// 生成 `tools/list` 里的一项（`inputSchema` + `annotations`）。
pub fn tool_json(tool: &ToolSpec) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for param in tool.params {
        properties.insert(param.name.to_string(), ty_schema(param));
        if param.required {
            required.push(Value::String(param.name.to_string()));
        }
    }

    let mut input_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
    });
    if !required.is_empty() {
        input_schema["required"] = Value::Array(required);
    }

    let annotations = if tool.class == Class::Read {
        json!({"readOnlyHint": true})
    } else {
        json!({
            "readOnlyHint": false,
            "destructiveHint": tool.destructive,
            "idempotentHint": tool.idempotent,
            "openWorldHint": tool.open_world,
        })
    };

    json!({
        "name": tool.name,
        "description": tool.summary,
        "inputSchema": input_schema,
        "annotations": annotations,
    })
}

/// 参数映射失败：由 `server` 转成 `-32602`（R-MCPS-07 的协议层）。
#[derive(Debug, PartialEq, Eq)]
pub struct BuildError {
    pub message: String,
}

impl BuildError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

fn convert(param: &ParamSpec, value: &Value) -> Result<Value, BuildError> {
    let type_error = || {
        BuildError::new(format!(
            "参数 `{}` 类型不符：期望 {}",
            param.name,
            match param.ty {
                Ty::Str => "string",
                Ty::U64 | Ty::I64 | Ty::I32 | Ty::U32 => "integer",
                Ty::Bool => "boolean",
                Ty::Strs => "string[]",
                Ty::U64s => "integer[]",
            }
        ))
    };

    match param.ty {
        Ty::Str => {
            let text = value.as_str().ok_or_else(type_error)?;
            // 目录必须是绝对路径：引擎对相对路径会按它自己的进程 CWD 解释，
            // 位置不可预期（R-MCPS-11、R-CR-15）。错误不回显值，避免把用户路径写进响应。
            if matches!(param.name, "dir" | "default_dir")
                && !std::path::Path::new(text).is_absolute()
            {
                return Err(BuildError::new(format!(
                    "参数 `{}` 必须是绝对路径",
                    param.name
                )));
            }
            Ok(Value::String(text.to_string()))
        }
        Ty::U64 => value.as_u64().map(|n| json!(n)).ok_or_else(type_error),
        Ty::I64 => value.as_i64().map(|n| json!(n)).ok_or_else(type_error),
        Ty::I32 => value
            .as_i64()
            .filter(|n| i32::try_from(*n).is_ok())
            .map(|n| json!(n))
            .ok_or_else(type_error),
        Ty::U32 => value
            .as_u64()
            .filter(|n| u32::try_from(*n).is_ok())
            .map(|n| json!(n))
            .ok_or_else(type_error),
        Ty::Bool => value.as_bool().map(Value::Bool).ok_or_else(type_error),
        Ty::Strs => {
            let items = value.as_array().ok_or_else(type_error)?;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(Value::String(
                    item.as_str().ok_or_else(type_error)?.to_string(),
                ));
            }
            Ok(Value::Array(out))
        }
        Ty::U64s => {
            let items = value.as_array().ok_or_else(type_error)?;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json!(item.as_u64().ok_or_else(type_error)?));
            }
            Ok(Value::Array(out))
        }
    }
}

/// 把工具参数翻译成 `EngineRequest`。
///
/// 未知参数必须在这里拒绝：serde 默认忽略未知字段，静默忽略会让模型以为设置生效。
pub fn build_op(tool: &ToolSpec, args: &Map<String, Value>) -> Result<EngineRequest, BuildError> {
    for key in args.keys() {
        if !tool.params.iter().any(|p| p.name == key) {
            return Err(BuildError::new(format!(
                "未知参数 `{key}`；{} 只接受：{}",
                tool.name,
                tool.params
                    .iter()
                    .map(|p| p.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }

    let mut object = Map::new();
    object.insert("op".into(), Value::String(tool.op.to_string()));
    for param in tool.params {
        match args.get(param.name) {
            Some(value) => {
                object.insert(param.name.to_string(), convert(param, value)?);
            }
            None if param.required => {
                return Err(BuildError::new(format!("缺少必填参数 `{}`", param.name)))
            }
            None => {}
        }
    }

    // 业务侧的额外闸门（R-MCPS-11）：条数上限与设置白名单。
    if tool.op == "add_batch" {
        if let Some(urls) = object.get("urls").and_then(Value::as_array) {
            if urls.len() > MAX_BATCH_URLS {
                return Err(BuildError::new(format!(
                    "urls 最多 {MAX_BATCH_URLS} 条，实际 {} 条",
                    urls.len()
                )));
            }
        }
    }
    if tool.op == "settings_set" {
        if let Some(key) = object.get("key").and_then(Value::as_str) {
            if !WRITABLE_SETTINGS.contains(&key) {
                return Err(BuildError::new(format!(
                    "设置键 `{key}` 不在 MCP 白名单内；允许：{}",
                    WRITABLE_SETTINGS.join(", ")
                )));
            }
        }
    }

    serde_json::from_value(Value::Object(object))
        .map_err(|e| BuildError::new(format!("参数无法映射到 op `{}`: {e}", tool.op)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_follow_the_op_naming_rule() {
        for tool in TOOLS {
            if tool.name == WAIT_TOOL {
                // 复合工具：底层是 `status`，但它不是 1:1 映射（R-MCPS-05 的唯一例外）。
                assert_eq!(tool.op, "status");
                continue;
            }
            assert_eq!(
                tool.name,
                format!("aidm_{}", tool.op),
                "工具名必须是 aidm_<op>"
            );
        }
    }

    #[test]
    fn tools_are_sorted_and_unique() {
        let mut names: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
        let sorted = {
            let mut s = names.clone();
            s.sort_unstable();
            s
        };
        assert_eq!(names, sorted);
        names.dedup();
        assert_eq!(names.len(), TOOLS.len());
    }

    #[test]
    fn build_op_rejects_unknown_missing_and_mistyped_args() {
        let add = find("aidm_add").unwrap();
        let mut args = Map::new();
        args.insert("url".into(), json!("https://example.com/a.bin"));
        assert!(build_op(add, &args).is_ok());

        let mut typo = args.clone();
        typo.insert("speed_limit".into(), json!(1));
        assert!(build_op(add, &typo).unwrap_err().message.contains("未知参数"));

        assert!(build_op(add, &Map::new())
            .unwrap_err()
            .message
            .contains("缺少必填参数"));

        let mut bad_type = args.clone();
        bad_type.insert("url".into(), json!(7));
        assert!(build_op(add, &bad_type).unwrap_err().message.contains("类型不符"));
    }

    #[test]
    fn settings_whitelist_is_closed_and_batch_is_capped() {
        let set = find("aidm_settings_set").unwrap();
        let mut ok = Map::new();
        ok.insert("key".into(), json!("sched.window_enabled"));
        ok.insert("value".into(), json!("true"));
        assert!(build_op(set, &ok).is_ok());

        let mut denied = Map::new();
        denied.insert("key".into(), json!("proxy.pass"));
        denied.insert("value".into(), json!("x"));
        assert!(build_op(set, &denied).unwrap_err().message.contains("白名单"));

        let batch = find("aidm_add_batch").unwrap();
        let urls: Vec<Value> = (0..=MAX_BATCH_URLS)
            .map(|i| json!(format!("https://example.com/{i}.bin")))
            .collect();
        let mut too_many = Map::new();
        too_many.insert("urls".into(), Value::Array(urls));
        assert!(build_op(batch, &too_many).unwrap_err().message.contains("最多"));
    }

    #[test]
    fn every_tool_builds_a_real_engine_request() {
        for tool in TOOLS {
            let mut args = Map::new();
            for param in tool.params {
                let sample = match param.ty {
                    Ty::Str if matches!(param.name, "dir" | "default_dir") => {
                        json!(std::env::temp_dir().to_string_lossy().to_string())
                    }
                    Ty::Str => json!("x"),
                    Ty::U64 | Ty::I64 | Ty::I32 | Ty::U32 => json!(1),
                    Ty::Bool => json!(true),
                    Ty::Strs => json!(["https://example.com/a.bin"]),
                    Ty::U64s => json!([1]),
                };
                args.insert(param.name.to_string(), sample);
            }
            // settings_set 的 value 必须是字符串；白名单键。
            if tool.op == "settings_set" {
                args.insert("key".into(), json!(WRITABLE_SETTINGS[0]));
            }
            let op = build_op(tool, &args).unwrap_or_else(|e| {
                panic!("{} 无法构造 EngineRequest: {}", tool.name, e.message)
            });
            let roundtrip = serde_json::to_value(&op).unwrap();
            assert_eq!(
                roundtrip["op"], tool.op,
                "{} 序列化后的 op 标签必须与工具表一致",
                tool.name
            );
        }
    }

    /// 直接读契约源码，穷举 `EngineRequest` 的变体名。
    fn contract_ops() -> Vec<String> {
        let source = include_str!("../../aidm-ipc/src/lib.rs");
        let start = source
            .find("pub enum EngineRequest {")
            .expect("找不到 EngineRequest 定义");
        let rest = &source[start..];
        let end = rest.find("\n}").expect("找不到 enum 结束");
        rest[..end]
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if !line.starts_with(|c: char| c.is_ascii_uppercase()) {
                    return None;
                }
                let name: String = line
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect();
                if name.is_empty() {
                    None
                } else {
                    Some(to_snake(&name))
                }
            })
            .collect()
    }

    fn to_snake(name: &str) -> String {
        let mut out = String::new();
        for (i, ch) in name.chars().enumerate() {
            if ch.is_ascii_uppercase() {
                if i > 0 {
                    out.push('_');
                }
                out.push(ch.to_ascii_lowercase());
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn exposed_and_hidden_cover_every_contract_op() {
        let mut classified: Vec<String> = TOOLS
            .iter()
            .map(|t| t.op.to_string())
            .chain(HIDDEN_OPS.iter().map(|(op, _)| op.to_string()))
            .collect();
        classified.sort();
        classified.dedup();
        let mut contract = contract_ops();
        contract.sort();

        assert_eq!(
            classified, contract,
            "新增/删除 op 后必须同步 TOOLS 或 HIDDEN_OPS（R-MCPS-09）"
        );
        assert_eq!(TOOLS.len(), 24, "暴露集 24 个（含复合工具 aidm_wait）");
        assert_eq!(HIDDEN_OPS.len(), 26, "不暴露表固定 26 个");
    }

    #[test]
    fn directories_must_be_absolute() {
        let add = find("aidm_add").unwrap();
        let mut args = Map::new();
        args.insert("url".into(), json!("https://example.com/a.bin"));
        args.insert("dir".into(), json!("relative/dir"));
        assert!(build_op(add, &args)
            .unwrap_err()
            .message
            .contains("绝对路径"));

        let mut ok = args.clone();
        ok.insert("dir".into(), json!(std::env::temp_dir().to_string_lossy().to_string()));
        assert!(build_op(add, &ok).is_ok());
    }
}
