//! 协议分发：modern / legacy、`server/discover`、工具调用、Tasks 扩展与订阅推送。
//!
//! 线程模型：
//! - 主线程读 stdin、逐条处理请求；
//! - 所有 stdout 写入走 `mpsc::Sender<String>`，由 main 的 writer 线程串行写（行不交错）；
//! - 后台 tracker 线程每 500ms 轮询引擎 `status`，把 `working` 任务推进到终态并推送
//!   `notifications/tasks`（Tasks 扩展的"完成时主动通知"）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Map, Value};

use aidm_ipc::{EngineRequest, EngineResponse};

use crate::engine::{self, EngineError, DIAG_TIMEOUT, DEFAULT_TIMEOUT};
use crate::jsonrpc::{
    Request, RpcError, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST,
    UNSUPPORTED_PROTOCOL_VERSION,
};
use crate::tasks::{self, TaskStatus, TrackedTask, TTL_MS};
use crate::tools::{self, Class, ToolSpec};

/// modern 版本：只有 `2026-07-28`（无握手、元数据随请求）。
pub const MODERN_VERSIONS: &[&str] = &["2026-07-28"];
/// legacy 版本：按优先级排列，`initialize` 协商时回第一个。
pub const LEGACY_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18"];

pub const SERVER_NAME: &str = "aidm-mcp";
const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
const META_SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";
/// Tasks 扩展标识（B-6）。
pub const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

/// tracker 调 `status` 的超时。比普通调用短：引擎挂了不能让循环卡 5 秒。
const TRACK_TIMEOUT: Duration = Duration::from_secs(2);
const TRACK_INTERVAL: Duration = Duration::from_millis(500);

const INSTRUCTIONS: &str = "AIDM is a download manager. Creating a task returns an id immediately; \
poll aidm_status with that id for progress. When the client declares the MCP Tasks extension, \
aidm_add returns a task handle instead, and task status changes are pushed on subscriptions/listen. \
Write tools are disabled unless the server was started with --allow-write. Destructive operations \
(cancel, restart) are cooperative and explicit; delete is intentionally not exposed.";

/// 多线程共享状态。
pub struct Shared {
    allow_write: bool,
    /// 所有 stdout 消息都从这里出去（writer 线程串行写）。
    out: Sender<String>,
    /// 被跟踪的 MCP 任务，key = `aidm:<id>`。
    tasks: Mutex<HashMap<String, TrackedTask>>,
    /// 活跃订阅：key = `subscriptions/listen` 的请求 id 序列化后的字符串，value = 关注的 taskId。
    /// 空 vec 表示"全部当前与未来任务"。
    subscriptions: Mutex<HashMap<String, Vec<String>>>,
    legacy: AtomicBool,
    /// 进程即将退出：让 tracker 尽快收手。
    pub shutdown: AtomicBool,
}

impl Shared {
    pub fn new(allow_write: bool, out: Sender<String>) -> Arc<Self> {
        Arc::new(Self {
            allow_write,
            out,
            tasks: Mutex::new(HashMap::new()),
            subscriptions: Mutex::new(HashMap::new()),
            legacy: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
        })
    }
}

#[derive(Debug)]
pub enum HandleOutcome {
    Reply(Value),
    /// 通知，或 `subscriptions/listen`（它只写 acknowledged，不写响应）。
    NoReply,
    /// 响应由后台线程稍后写（`aidm_wait` 的同步等待模式）。
    Deferred,
}

pub struct Server {
    shared: Arc<Shared>,
}

impl Server {
    pub fn new(allow_write: bool, out: Sender<String>) -> Self {
        Self {
            shared: Shared::new(allow_write, out),
        }
    }

    pub fn shared(&self) -> Arc<Shared> {
        self.shared.clone()
    }

    pub fn handle(&self, request: &Request) -> Result<HandleOutcome, RpcError> {
        match request.method.as_str() {
            "initialize" => self.initialize(request),
            "notifications/initialized" | "notifications/cancelled" => Ok(HandleOutcome::NoReply),
            // 探活不要求元数据：传输层健康检查，legacy 客户端也会在握手后 ping。
            "ping" => Ok(HandleOutcome::Reply(json!({}))),
            "server/discover" => Ok(HandleOutcome::Reply(discover())),
            "tools/list" => self.list(request),
            "tools/call" => self.call(request),
            "tasks/get" => self.task_get(request),
            "tasks/cancel" => self.task_cancel(request),
            "subscriptions/listen" => self.subscribe(request),
            other => Err(RpcError::method_not_found(other)),
        }
    }

    fn initialize(&self, request: &Request) -> Result<HandleOutcome, RpcError> {
        let requested = request
            .params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("");
        let version = if LEGACY_VERSIONS.contains(&requested) {
            requested
        } else {
            LEGACY_VERSIONS[0]
        };
        self.shared.legacy.store(true, Ordering::SeqCst);
        Ok(HandleOutcome::Reply(json!({
            "protocolVersion": version,
            "capabilities": server_capabilities(),
            "serverInfo": server_info(),
        })))
    }

    fn list(&self, request: &Request) -> Result<HandleOutcome, RpcError> {
        self.require_modern_meta(&request.params)?;
        let visible: Vec<Value> = tools::visible(self.shared.allow_write)
            .into_iter()
            .map(tools::tool_json)
            .collect();
        Ok(HandleOutcome::Reply(json!({ "tools": visible })))
    }

    fn call(&self, request: &Request) -> Result<HandleOutcome, RpcError> {
        self.require_modern_meta(&request.params)?;

        let name = request
            .params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("缺少工具名 `name`"))?;
        let tool: &'static ToolSpec =
            tools::find(name).ok_or_else(|| RpcError::method_not_found(name))?;

        if tool.class == Class::Write && !self.shared.allow_write {
            return Err(RpcError::new(
                INVALID_PARAMS,
                format!("工具 {name} 未授权：默认只读，写工具需要 --allow-write"),
            )
            .with_data(json!({"code": "not_authorized"})));
        }

        let empty = Map::new();
        let arguments = match request.params.get("arguments") {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(map)) => map,
            Some(_) => return Err(RpcError::invalid_params("`arguments` 必须是对象")),
        };

        // 复合工具：显式等待，是 `notifications/progress` 的合法载体。
        if tool.name == tools::WAIT_TOOL {
            return self.wait(request, arguments);
        }

        let op = tools::build_op(tool, arguments)
            .map_err(|e| RpcError::invalid_params(e.message))?;

        let timeout = if tool.op == "diag_export" {
            DIAG_TIMEOUT
        } else {
            DEFAULT_TIMEOUT
        };
        let response = engine::call_once(&op, timeout).map_err(|e| engine_error(&e))?;

        // Tasks 扩展：只有"新建下载"会变成一个可跟踪任务。
        // add_batch 不包 task——一次请求多个任务，语义无法一一对应（R-MCPS-08）。
        if tool.op == "add" && client_supports_tasks(&request.params) {
            if let (true, Some(id)) = (response.ok, response.id) {
                let task = TrackedTask::new(id, "queued");
                // 不在这里 publish：创建结果本身已经带 working 状态。先推通知会让
                // 客户端在 `tools/call` 的响应之前收到一条通知，把简单的请求/响应
                // 客户端搞乱。状态变化由 tracker 推送。
                self.shared
                    .tasks
                    .lock()
                    .unwrap()
                    .insert(task.id.clone(), task.clone());
                return Ok(HandleOutcome::Reply(task.create_result()));
            }
        }

        let modern = request.params.contains_key("_meta");
        Ok(HandleOutcome::Reply(tool_result(response, modern)))
    }

    fn task_get(&self, request: &Request) -> Result<HandleOutcome, RpcError> {
        self.require_modern_meta(&request.params)?;
        let task_id = request
            .params
            .get("taskId")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("缺少 `taskId`"))?;
        // 只认本服务自己的 id 形状；外部 id 直接当未知任务。
        if tasks::parse_task_id(task_id).is_none() {
            return Err(unknown_task());
        }
        let task = {
            let tasks = self.shared.tasks.lock().unwrap();
            tasks.get(task_id).cloned()
        }
        .filter(|task| !expired(task))
        .ok_or_else(unknown_task)?;

        let mut value = task.detail();
        value["resultType"] = json!("complete");
        Ok(HandleOutcome::Reply(value))
    }

    fn task_cancel(&self, request: &Request) -> Result<HandleOutcome, RpcError> {
        self.require_modern_meta(&request.params)?;
        let task_id = request
            .params
            .get("taskId")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid_params("缺少 `taskId`"))?;
        if tasks::parse_task_id(task_id).is_none() {
            return Err(unknown_task());
        }

        let updated = {
            let mut tasks = self.shared.tasks.lock().unwrap();
            match tasks.get_mut(task_id) {
                None => None,
                Some(task) => {
                    // 只取消"跟踪"，不取消下载：下载任务由引擎持有，取消它要用工具
                    // aidm_cancel（R-MCPS-08 的语义边界）。
                    if !task.status.is_terminal() {
                        task.status = TaskStatus::Cancelled;
                        task.status_message = "cancelled by client (download continues)".into();
                        task.updated_at = SystemTime::now();
                    }
                    Some(task.clone())
                }
            }
        }
        .ok_or_else(unknown_task)?;

        publish_task(&self.shared, &updated);
        Ok(HandleOutcome::Reply(json!({"resultType": "complete"})))
    }

    /// `aidm_wait`：等到终态。
    ///
    /// - 声明 Tasks 扩展的客户端：返回**同一个**任务句柄（`aidm:<id>`），不阻塞；
    /// - 其它客户端：后台线程每 250 ms 查一次 `status`，期间发 `notifications/progress`
    ///   （仅当请求带 `progressToken`），最后写响应。主线程继续处理别的请求。
    fn wait(&self, request: &Request, arguments: &Map<String, Value>) -> Result<HandleOutcome, RpcError> {
        let aidm_id = arguments
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::invalid_params("缺少必填参数 `id`"))?;
        let timeout_s = arguments
            .get("timeout_s")
            .and_then(Value::as_u64)
            .unwrap_or(tools::DEFAULT_WAIT_S)
            .min(tools::MAX_WAIT_S);

        if client_supports_tasks(&request.params) {
            let task_id = tasks::task_id(aidm_id);
            let task = {
                let mut tracked = self.shared.tasks.lock().unwrap();
                tracked
                    .entry(task_id)
                    .or_insert_with(|| TrackedTask::new(aidm_id, "queued"))
                    .clone()
            };
            return Ok(HandleOutcome::Reply(task.create_result()));
        }

        let request_id = request
            .id
            .clone()
            .ok_or_else(|| RpcError::new(INVALID_REQUEST, "aidm_wait 必须带 id"))?;
        let progress_token = request
            .params
            .get("_meta")
            .and_then(|meta| meta.get("progressToken"))
            .cloned();
        spawn_wait(
            self.shared.clone(),
            request_id,
            progress_token,
            aidm_id,
            Duration::from_secs(timeout_s),
        );
        Ok(HandleOutcome::Deferred)
    }

    /// `subscriptions/listen`：注册订阅、回 acknowledged，然后**不写响应**（流保持打开）。
    fn subscribe(&self, request: &Request) -> Result<HandleOutcome, RpcError> {
        self.require_modern_meta(&request.params)?;
        let id = request
            .id
            .clone()
            .ok_or_else(|| RpcError::new(INVALID_REQUEST, "subscriptions/listen 必须带 id"))?;

        let filter = request
            .params
            .get("notifications")
            .and_then(Value::as_object)
            .ok_or_else(|| RpcError::invalid_params("缺少 `notifications` 对象"))?;

        // 只支持 tasks 的 taskIds 过滤器；其它类型未实现，acknowledged 里不回。
        let task_ids: Vec<String> = match filter.get("taskIds") {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| RpcError::invalid_params("`taskIds` 必须是字符串数组"))
                })
                .collect::<Result<_, _>>()?,
            Some(_) => return Err(RpcError::invalid_params("`taskIds` 必须是字符串数组")),
        };

        self.shared
            .subscriptions
            .lock()
            .unwrap()
            .insert(id.to_string(), task_ids.clone());

        let ack = json!({
            "jsonrpc": "2.0",
            "method": "notifications/subscriptions/acknowledged",
            "params": {
                "_meta": { (META_SUBSCRIPTION_ID): id },
                "notifications": { "taskIds": task_ids },
            },
        });
        let _ = self.shared.out.send(ack.to_string());
        Ok(HandleOutcome::NoReply)
    }

    /// modern 请求必须带版本与客户端能力；legacy 会话内允许不带（B-7）。
    fn require_modern_meta(&self, params: &Map<String, Value>) -> Result<(), RpcError> {
        if params.get("_meta").is_none() && self.shared.legacy.load(Ordering::SeqCst) {
            return Ok(());
        }
        let meta = params
            .get("_meta")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                RpcError::new(
                    INVALID_REQUEST,
                    "缺少 params._meta：modern MCP 请求必须带协议版本与客户端能力",
                )
            })?;

        let version = meta.get(META_VERSION).and_then(Value::as_str).ok_or_else(|| {
            RpcError::new(INVALID_REQUEST, format!("缺少 {META_VERSION}"))
        })?;
        if !MODERN_VERSIONS.contains(&version) {
            return Err(RpcError::new(
                UNSUPPORTED_PROTOCOL_VERSION,
                "unsupported protocol version",
            )
            .with_data(json!({"supported": MODERN_VERSIONS, "requested": version})));
        }
        if !meta.get(META_CAPABILITIES).map(Value::is_object).unwrap_or(false) {
            return Err(RpcError::new(
                INVALID_REQUEST,
                format!("缺少或非法：{META_CAPABILITIES} 必须是对象"),
            ));
        }
        Ok(())
    }
}

fn client_supports_tasks(params: &Map<String, Value>) -> bool {
    params
        .get("_meta")
        .and_then(|meta| meta.get(META_CAPABILITIES))
        .and_then(|caps| caps.get("extensions"))
        .and_then(|extensions| extensions.get(TASKS_EXTENSION))
        .map(Value::is_object)
        .unwrap_or(false)
}

fn server_capabilities() -> Value {
    json!({
        "tools": {},
        "extensions": { (TASKS_EXTENSION): {} },
    })
}

fn discover() -> Value {
    json!({
        "resultType": "complete",
        // 只列 modern 版本：legacy 不是通过 discover 协商的（R-MCPS-02 ③）。
        "supportedVersions": MODERN_VERSIONS,
        "capabilities": server_capabilities(),
        "_meta": { (META_SERVER_INFO): server_info() },
        "instructions": INSTRUCTIONS,
    })
}

fn server_info() -> Value {
    json!({
        "name": SERVER_NAME,
        "version": env!("CARGO_PKG_VERSION"),
    })
}

fn unknown_task() -> RpcError {
    RpcError::new(INVALID_PARAMS, "unknown task")
        .with_data(json!({"code": "unknown_task"}))
}

fn expired(task: &TrackedTask) -> bool {
    SystemTime::now()
        .duration_since(task.updated_at)
        .map(|age| age.as_millis() as u64 > TTL_MS)
        .unwrap_or(false)
}

fn engine_error(error: &EngineError) -> RpcError {
    RpcError::new(INTERNAL_ERROR, error.to_string())
        .with_data(json!({ "code": error.code() }))
}

/// `CallToolResult`（不含 `resultType`）：Tasks 的 `result` 字段要的形状。
fn call_tool_result(response: &EngineResponse) -> Value {
    let structured = serde_json::to_value(response).unwrap_or(Value::Null);
    let text = serde_json::to_string(&structured).unwrap_or_else(|_| "{}".to_string());
    let mut result = json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
    });
    if !response.ok {
        result["isError"] = json!(true);
    }
    result
}

/// 工具结果：`structuredContent` 原样透传 `EngineResponse`（R-MCPS-06）。
fn tool_result(response: EngineResponse, modern: bool) -> Value {
    let mut result = call_tool_result(&response);
    if modern {
        result["resultType"] = json!("complete");
    }
    result
}

/// 把任务状态变化推给关注它的订阅（R-MCPS-08）。
fn publish_task(shared: &Shared, task: &TrackedTask) {
    let subscriptions: Vec<(String, Vec<String>)> = shared
        .subscriptions
        .lock()
        .unwrap()
        .iter()
        .map(|(key, ids)| (key.clone(), ids.clone()))
        .collect();
    if subscriptions.is_empty() {
        return;
    }

    let detail = task.detail();
    for (subscription_key, task_ids) in subscriptions {
        // 空列表 = 订阅全部当前与未来任务。
        if !task_ids.is_empty() && !task_ids.contains(&task.id) {
            continue;
        }
        let Ok(subscription_id) = serde_json::from_str::<Value>(&subscription_key) else {
            continue;
        };
        let mut params = detail.clone();
        params["_meta"] = json!({ (META_SUBSCRIPTION_ID): subscription_id });
        let message = json!({
            "jsonrpc": "2.0",
            "method": "notifications/tasks",
            "params": params,
        });
        let _ = shared.out.send(message.to_string());
    }
}

fn update_message(shared: &Shared, task_id: &str, message: &str) -> Option<TrackedTask> {
    let mut tasks = shared.tasks.lock().unwrap();
    let task = tasks.get_mut(task_id)?;
    if task.status.is_terminal() || task.status_message == message {
        return None;
    }
    task.status_message = message.to_string();
    task.updated_at = SystemTime::now();
    Some(task.clone())
}

fn finish(shared: &Shared, task_id: &str, status: TaskStatus, result: Option<Value>) -> Option<TrackedTask> {
    let mut tasks = shared.tasks.lock().unwrap();
    let task = tasks.get_mut(task_id)?;
    if task.status.is_terminal() {
        return None;
    }
    task.status = status;
    task.updated_at = SystemTime::now();
    if let Some(result) = result {
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        task.result = Some(result);
        task.status_message = if is_error {
            "finished with an error".into()
        } else {
            "done".into()
        };
    }
    Some(task.clone())
}

fn fail(shared: &Shared, task_id: &str, error: Value) -> Option<TrackedTask> {
    let mut tasks = shared.tasks.lock().unwrap();
    let task = tasks.get_mut(task_id)?;
    if task.status.is_terminal() {
        return None;
    }
    task.status = TaskStatus::Failed;
    task.updated_at = SystemTime::now();
    task.status_message = "engine request failed".into();
    task.error = Some(error);
    Some(task.clone())
}

/// `aidm_wait` 的同步等待线程：查状态 → 发 progress → 终态/超时时写响应。
fn spawn_wait(
    shared: Arc<Shared>,
    request_id: Value,
    progress_token: Option<Value>,
    aidm_id: u64,
    timeout: Duration,
) {
    let _ = thread::Builder::new()
        .name(format!("aidm-mcp-wait-{aidm_id}"))
        .spawn(move || {
            let deadline = Instant::now() + timeout;
            // 初值取 impossible 值，保证第一次一定发一条 progress。
            let mut last_progress = u64::MAX;
            loop {
                // 进程正在关闭：不再等，尽快释放 tx 让 writer 结束。
                if shared.shutdown.load(Ordering::SeqCst) {
                    return;
                }
                let response = match engine::call_once(
                    &EngineRequest::Status { id: aidm_id },
                    TRACK_TIMEOUT,
                ) {
                    Ok(response) => response,
                    Err(error) => {
                        let payload = crate::jsonrpc::error(Some(&request_id), engine_error(&error));
                        let _ = shared.out.send(payload.to_string());
                        return;
                    }
                };

                let state = response
                    .task
                    .as_ref()
                    .map(|task| task.state.clone())
                    .unwrap_or_default();
                let done = response.task.as_ref().map(|task| task.done).unwrap_or(0);
                let total = response.task.as_ref().and_then(|task| task.total);

                if let Some(token) = &progress_token {
                    if done != last_progress {
                        let mut params = json!({
                            "progressToken": token,
                            "progress": done,
                            "message": state,
                        });
                        if let Some(total) = total {
                            params["total"] = json!(total);
                        }
                        let payload = json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/progress",
                            "params": params,
                        });
                        let _ = shared.out.send(payload.to_string());
                        last_progress = done;
                    }
                }

                if matches!(state.as_str(), "done" | "error") {
                    let payload =
                        crate::jsonrpc::result(&request_id, tool_result(response, true));
                    let _ = shared.out.send(payload.to_string());
                    return;
                }

                if Instant::now() >= deadline {
                    // 超时：返回最后一次状态并标 isError（没等到终态 = 工具执行未达成）。
                    let mut result = tool_result(response, true);
                    result["isError"] = json!(true);
                    let payload = crate::jsonrpc::result(&request_id, result);
                    let _ = shared.out.send(payload.to_string());
                    return;
                }

                thread::sleep(Duration::from_millis(250));
            }
        });
}

/// 后台跟踪：轮询引擎，把 `working` 推进到终态并推送。
///
/// 返回的句柄由 main 在 stdin EOF 后 join：不 join 会让进程退出时丢掉最后几条通知。
pub fn spawn_tracker(shared: Arc<Shared>) -> Option<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("aidm-mcp-tasks".into())
        .spawn(move || loop {
            // 分片睡眠：关闭时不必等满一个轮询周期。
            for _ in 0..10 {
                if shared.shutdown.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(TRACK_INTERVAL / 10);
            }
            let now = SystemTime::now();

            // 过期清理（终态任务保留 TTL 后丢弃）。
            {
                let mut tasks = shared.tasks.lock().unwrap();
                tasks.retain(|_, task| {
                    now.duration_since(task.updated_at)
                        .map(|age| age.as_millis() as u64 <= TTL_MS)
                        .unwrap_or(true)
                });
            }

            let working: Vec<(String, u64)> = shared
                .tasks
                .lock()
                .unwrap()
                .values()
                .filter(|task| task.status == TaskStatus::Working)
                .map(|task| (task.id.clone(), task.aidm_id))
                .collect();

            for (task_id, aidm_id) in working {
                let request = EngineRequest::Status { id: aidm_id };
                let response = match engine::call_once(&request, TRACK_TIMEOUT) {
                    Ok(response) => response,
                    Err(error) => {
                        // 引擎临时不可达不等于任务失败：保持 working，只更新说明。
                        if let Some(task) = update_message(&shared, &task_id, error.code()) {
                            publish_task(&shared, &task);
                        }
                        continue;
                    }
                };

                if !response.ok && response.code.as_deref() == Some("task_not_found") {
                    if let Some(task) = fail(
                        &shared,
                        &task_id,
                        json!({"code": -32602, "message": "task_not_found"}),
                    ) {
                        publish_task(&shared, &task);
                    }
                    continue;
                }

                let state = response
                    .task
                    .as_ref()
                    .map(|task| task.state.clone())
                    .unwrap_or_default();
                match state.as_str() {
                    // 下载失败是"任务完成但结果带 isError"，不是协议失败（R-MCPS-07）。
                    "done" | "error" => {
                        let mut result = call_tool_result(&response);
                        if state == "error" {
                            result["isError"] = json!(true);
                        }
                        if let Some(task) =
                            finish(&shared, &task_id, TaskStatus::Completed, Some(result))
                        {
                            publish_task(&shared, &task);
                        }
                    }
                    "queued" | "connecting" | "downloading" | "paused" | "verifying"
                    | "interrupted" => {
                        if let Some(task) = update_message(&shared, &task_id, &state) {
                            publish_task(&shared, &task);
                        }
                    }
                    _ => {}
                }
            }
        })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jsonrpc;
    use std::sync::mpsc::{self, Receiver};

    fn server(allow_write: bool) -> (Server, Receiver<String>) {
        let (tx, rx) = mpsc::channel();
        (Server::new(allow_write, tx), rx)
    }

    fn req(method: &str, params: Value) -> Request {
        let line = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        })
        .to_string();
        jsonrpc::parse(&line).unwrap()
    }

    fn modern(params: Value) -> Value {
        let mut map = params.as_object().cloned().unwrap_or_default();
        map.insert(
            "_meta".into(),
            json!({
                (META_VERSION): "2026-07-28",
                (META_CAPABILITIES): {},
            }),
        );
        Value::Object(map)
    }

    fn modern_tasks(params: Value) -> Value {
        let mut map = modern(params);
        map["_meta"][META_CAPABILITIES] = json!({
            "extensions": { (TASKS_EXTENSION): {} },
        });
        map
    }

    fn reply(outcome: HandleOutcome) -> Value {
        match outcome {
            HandleOutcome::Reply(value) => value,
            HandleOutcome::NoReply => panic!("期望响应，实际是 NoReply"),
            HandleOutcome::Deferred => panic!("期望响应，实际是 Deferred"),
        }
    }

    #[test]
    fn modern_without_meta_is_invalid_request() {
        let (server, _rx) = server(true);
        let err = server.handle(&req("tools/list", json!({}))).unwrap_err();
        assert_eq!(err.code, INVALID_REQUEST);
    }

    #[test]
    fn unsupported_version_reports_supported_list() {
        let (server, _rx) = server(true);
        let params = json!({"_meta": {
            (META_VERSION): "2099-01-01",
            (META_CAPABILITIES): {},
        }});
        let err = server.handle(&req("tools/list", params)).unwrap_err();
        assert_eq!(err.code, UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(err.data.unwrap()["supported"], json!(MODERN_VERSIONS));
    }

    #[test]
    fn legacy_initialize_then_list_without_meta() {
        let (server, _rx) = server(false);
        let init = reply(
            server
                .handle(&req("initialize", json!({"protocolVersion": "2025-06-18"})))
                .unwrap(),
        );
        assert_eq!(init["protocolVersion"], "2025-06-18");
        assert!(matches!(
            server
                .handle(&req("notifications/initialized", json!({})))
                .unwrap(),
            HandleOutcome::NoReply
        ));

        let list = reply(server.handle(&req("tools/list", json!({}))).unwrap());
        assert_eq!(list["tools"].as_array().unwrap().len(), 11);
    }

    #[test]
    fn write_tool_requires_allow_write() {
        let (server, _rx) = server(false);
        let params = modern(json!({"name": "aidm_add", "arguments": {"url": "https://x/a"}}));
        let err = server.handle(&req("tools/call", params)).unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["code"], "not_authorized");
    }

    #[test]
    fn discover_declares_tools_and_tasks_extension() {
        let (server, _rx) = server(false);
        let result = reply(server.handle(&req("server/discover", json!({}))).unwrap());
        assert_eq!(result["supportedVersions"], json!(MODERN_VERSIONS));
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["capabilities"]["extensions"][TASKS_EXTENSION].is_object());
        assert!(result["capabilities"].get("resources").is_none());
        assert_eq!(result["_meta"][META_SERVER_INFO]["name"], SERVER_NAME);
    }

    #[test]
    fn engine_failure_becomes_is_error_not_rpc_error() {
        let response = aidm_ipc::EngineResponse::err_code("bad_url");
        let result = tool_result(response, true);
        assert_eq!(result["isError"], json!(true));
        assert_eq!(result["structuredContent"]["code"], "bad_url");
        assert_eq!(result["resultType"], "complete");
        // Tasks 的 result 不带 resultType。
        let bare = call_tool_result(&aidm_ipc::EngineResponse::err_code("bad_url"));
        assert!(bare.get("resultType").is_none());
    }

    #[test]
    fn unknown_tasks_are_rejected() {
        let (server, _rx) = server(false);
        let params = modern(json!({"taskId": "aidm:999"}));
        let err = server.handle(&req("tasks/get", params)).unwrap_err();
        assert_eq!(err.data.unwrap()["code"], "unknown_task");
    }

    #[test]
    fn listen_acknowledges_and_stays_open() {
        let (server, rx) = server(false);
        let params = modern_tasks(json!({"notifications": {"taskIds": ["aidm:1"]}}));
        let outcome = server.handle(&req("subscriptions/listen", params)).unwrap();
        assert!(matches!(outcome, HandleOutcome::NoReply));

        let ack: Value = serde_json::from_str(&rx.recv_timeout(Duration::from_secs(1)).unwrap()).unwrap();
        assert_eq!(ack["method"], "notifications/subscriptions/acknowledged");
        assert_eq!(ack["params"]["notifications"]["taskIds"], json!(["aidm:1"]));
        assert_eq!(ack["params"]["_meta"][META_SUBSCRIPTION_ID], json!(1));
    }

    #[test]
    fn publish_reaches_only_matching_subscriptions() {
        let (server, rx) = server(false);
        let shared = server.shared();

        let listen = |id: i64, task_ids: Vec<String>| {
            let message = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "subscriptions/listen",
                "params": modern_tasks(json!({"notifications": {"taskIds": task_ids}})),
            })
            .to_string();
            server.handle(&jsonrpc::parse(&message).unwrap()).unwrap();
        };
        listen(10, vec!["aidm:1".into()]);
        listen(11, vec!["aidm:2".into()]);
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let _ = rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let task = TrackedTask::new(1, "downloading");
        publish_task(&shared, &task);

        let message = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let value: Value = serde_json::from_str(&message).unwrap();
        assert_eq!(value["method"], "notifications/tasks");
        assert_eq!(value["params"]["taskId"], "aidm:1");
        assert_eq!(value["params"]["_meta"][META_SUBSCRIPTION_ID], json!(10));
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "不该推给未订阅 aidm:1 的 id=11"
        );
    }

    #[test]
    fn cancel_stops_tracking_but_keeps_working_state_semantics() {
        let (server, _rx) = server(false);
        let shared = server.shared();
        shared
            .tasks
            .lock()
            .unwrap()
            .insert("aidm:5".into(), TrackedTask::new(5, "downloading"));

        let result = reply(
            server
                .handle(&req("tasks/cancel", modern(json!({"taskId": "aidm:5"}))))
                .unwrap(),
        );
        assert_eq!(result["resultType"], "complete");

        let task = shared.tasks.lock().unwrap().get("aidm:5").cloned().unwrap();
        assert_eq!(task.status, TaskStatus::Cancelled);
        // 关键语义：取消的是"等待/跟踪"，不是下载。
        assert!(task.status_message.contains("download continues"));
    }

    #[test]
    fn poll_interval_and_ttl_are_advertised() {
        let value = tasks::TrackedTask::new(1, "queued").create_result();
        assert_eq!(value["resultType"], "task");
        assert_eq!(value["pollIntervalMs"], crate::tasks::POLL_INTERVAL_MS);
        assert_eq!(value["ttlMs"], TTL_MS);
    }
}
