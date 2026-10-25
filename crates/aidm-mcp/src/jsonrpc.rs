//! JSON-RPC 2.0 的最小实现（只覆盖 MCP 用到的部分）。
//!
//! 为什么不用第三方库：v1 刻意零新增依赖（14-mcp-service.md R-MCPS-03），
//! 而 MCP 的消息形状是"一行一个对象"，serde_json 足够。这里只做四件事：
//! 校验信封、区分请求/通知、给出稳定错误码、把结果/错误编码成一行。

use serde_json::{json, Map, Value};

// JSON-RPC 2.0 标准码。
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
/// MCP 规范保留：服务器不支持请求里的协议版本（2026-07-28 起）。
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

pub const JSONRPC_VERSION: &str = "2.0";

#[derive(Debug)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, message)
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("unknown method: {method}"))
    }
}

/// 一条已经通过信封校验的请求。`id = None` 表示通知（不写响应）。
#[derive(Debug)]
pub struct Request {
    pub id: Option<Value>,
    pub method: String,
    pub params: Map<String, Value>,
}

/// 解析一行输入。失败时返回可回写的错误（`id` 未知，因此响应 id 为 null）。
pub fn parse(line: &str) -> Result<Request, RpcError> {
    let value: Value = serde_json::from_str(line)
        .map_err(|e| RpcError::new(PARSE_ERROR, format!("parse error: {e}")))?;

    let object = value.as_object().ok_or_else(|| {
        RpcError::new(INVALID_REQUEST, "request must be a JSON object")
    })?;

    match object.get("jsonrpc").and_then(Value::as_str) {
        Some(JSONRPC_VERSION) => {}
        _ => {
            return Err(RpcError::new(
                INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
            ))
        }
    }

    let method = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|m| !m.trim().is_empty())
        .ok_or_else(|| RpcError::new(INVALID_REQUEST, "method must be a non-empty string"))?
        .to_string();

    let params = match object.get("params") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => {
            return Err(RpcError::new(
                INVALID_PARAMS,
                "params must be a JSON object",
            ))
        }
    };

    let id = match object.get("id") {
        None => None,
        // MCP 明确：与基础 JSON-RPC 不同，id 不许为 null（B-1）。
        Some(Value::Null) => {
            return Err(RpcError::new(
                INVALID_REQUEST,
                "id must not be null (omit it for notifications)",
            ))
        }
        Some(value @ Value::String(_)) => Some(value.clone()),
        Some(value @ Value::Number(_)) => {
            // 只接受整数 id：浮点 id 在 JSON-RPC 里合法，但 MCP 要求 string | integer。
            if !value.is_i64() && !value.is_u64() {
                return Err(RpcError::new(INVALID_REQUEST, "id must be a string or an integer"));
            }
            Some(value.clone())
        }
        Some(_) => {
            return Err(RpcError::new(
                INVALID_REQUEST,
                "id must be a string or an integer",
            ))
        }
    };

    Ok(Request {
        id,
        method,
        params,
    })
}

/// 成功响应。
pub fn result(id: &Value, result: Value) -> Value {
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id,
        "result": result,
    })
}

/// 错误响应。`id = None` 时写 `null`（唯一允许 null 的位置：无法读出错请求 id）。
pub fn error(id: Option<&Value>, err: RpcError) -> Value {
    let mut error = json!({
        "code": err.code,
        "message": err.message,
    });
    if let Some(data) = err.data {
        error["data"] = data;
    }
    json!({
        "jsonrpc": JSONRPC_VERSION,
        "id": id.cloned().unwrap_or(Value::Null),
        "error": error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_and_notification() {
        let req = parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#).unwrap();
        assert_eq!(req.method, "tools/list");
        assert!(req.id.is_some());

        let note = parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap();
        assert!(note.id.is_none());
    }

    #[test]
    fn rejects_null_id_and_bad_envelope() {
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#)
                .unwrap_err()
                .code,
            INVALID_REQUEST
        );
        assert_eq!(
            parse(r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#)
                .unwrap_err()
                .code,
            INVALID_REQUEST
        );
        assert_eq!(parse("not json").unwrap_err().code, PARSE_ERROR);
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[1]}"#)
                .unwrap_err()
                .code,
            INVALID_PARAMS
        );
        // 浮点 id 不算整数 id。
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#)
                .unwrap_err()
                .code,
            INVALID_REQUEST
        );
    }

    #[test]
    fn error_data_is_optional() {
        let plain = error(None, RpcError::new(METHOD_NOT_FOUND, "x"));
        assert!(plain["error"].get("data").is_none());
        assert_eq!(plain["id"], Value::Null);

        let with_data = error(
            Some(&json!(7)),
            RpcError::new(UNSUPPORTED_PROTOCOL_VERSION, "v").with_data(json!({"supported": []})),
        );
        assert_eq!(with_data["error"]["data"]["supported"], json!([]));
    }
}
