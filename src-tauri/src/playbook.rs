//! W6 Playbook：YAML 描述的批量操作序列（CI / 脚本化回归）。
//!
//! 设计取舍：动作**直接复用命令层的服务函数**（`session_ctx` / `with_session` /
//! `connect_shell_impl`），因此授权范围复查、到期检查、审计、会话管理全部沿用
//! 既有门禁，不存在绕过路径；执行在阻塞线程池里同步完成，与 GUI 命令一致。
//!
//! ```yaml
//! name: smoke
//! continue_on_error: false
//! steps:
//!   - id: conn
//!     action: connect
//!     args: { shell_id: "shell-1" }
//!   - id: run
//!     action: exec
//!     args: { session_id: "${conn.sessionId}", command: "id" }
//!     expect:
//!       contains: "uid="
//!   - action: disconnect
//!     args: { session_id: "${conn.sessionId}" }
//! ```
//!
//! 变量替换：`${步骤 id.字段路径}`，取自上一步骤的结果（JSON 路径用 `.` 分隔）。
//! 断言：`contains`（序列化结果包含子串）/ `equals`（对结果做递归子集匹配）。

use std::collections::HashMap;
use std::time::Instant;

use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

use dosword_sdk::FeaturePlugin;
use dosword_sdk::domain::{DbConnection, PlaybookReport, PlaybookStepReport};

use crate::AppState;

/// Playbook 定义（YAML）。
#[derive(Debug, Deserialize)]
pub struct Playbook {
    #[serde(default)]
    pub name: Option<String>,
    /// 单步失败后是否继续（默认 false：失败即中止）。
    #[serde(default)]
    pub continue_on_error: bool,
    pub steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
pub struct Step {
    /// 步骤 id（供后续步骤用 `${id.field}` 引用其结果）。
    #[serde(default)]
    pub id: Option<String>,
    pub action: String,
    #[serde(default)]
    pub args: Value,
    #[serde(default)]
    pub expect: Option<Expect>,
}

#[derive(Debug, Deserialize)]
pub struct Expect {
    /// 序列化后的结果必须包含该子串。
    #[serde(default)]
    pub contains: Option<String>,
    /// 结果必须匹配该 JSON 子集（递归比较对象/数组）。
    #[serde(default)]
    pub equals: Option<Value>,
}

/// 解析并执行 Playbook，返回逐步骤报告。
pub fn run(state: &AppState, yaml: &str) -> Result<PlaybookReport, String> {
    let playbook: Playbook =
        serde_yaml::from_str(yaml).map_err(|error| format!("Playbook YAML 解析失败：{error}"))?;
    if playbook.steps.is_empty() {
        return Err("Playbook 至少需要一个步骤".to_string());
    }
    let started = Instant::now();
    let mut variables: HashMap<String, Value> = HashMap::new();
    let mut steps = Vec::with_capacity(playbook.steps.len());
    let mut all_ok = true;

    for (index, step) in playbook.steps.iter().enumerate() {
        let args = resolve_vars(&step.args, &variables);
        let step_started = Instant::now();
        let outcome = run_step(state, &step.action, &args);
        let (result, mut error) = match outcome {
            Ok(value) => (Some(value), None),
            Err(message) => (None, Some(message)),
        };
        // 断言只在动作成功时执行
        if error.is_none()
            && let Some(expect) = &step.expect
        {
            if let Some(text) = expect.contains.as_deref() {
                let serialized = result.as_ref().map(|v| v.to_string()).unwrap_or_default();
                if !serialized.contains(text) {
                    error = Some(format!("断言失败：结果不包含 {text:?}"));
                }
            }
            if error.is_none()
                && let Some(expected) = &expect.equals
                && !json_subset(result.as_ref().unwrap_or(&Value::Null), expected)
            {
                error = Some("断言失败：结果不匹配 equals".to_string());
            }
        }
        let ok = error.is_none();
        if !ok {
            all_ok = false;
        }
        if let (Some(id), Some(value)) = (&step.id, &result) {
            variables.insert(id.clone(), value.clone());
        }
        steps.push(PlaybookStepReport {
            index,
            id: step.id.clone(),
            action: step.action.clone(),
            ok,
            duration_ms: step_started.elapsed().as_millis() as u64,
            error,
            result,
        });
        if !ok && !playbook.continue_on_error {
            break;
        }
    }

    Ok(PlaybookReport {
        name: playbook.name.unwrap_or_else(|| "playbook".to_string()),
        ok: all_ok,
        duration_ms: started.elapsed().as_millis() as u64,
        steps,
    })
}

/// 单个动作分发。返回 JSON 供断言与后续步骤引用。
fn run_step(state: &AppState, action: &str, args: &Value) -> Result<Value, String> {
    match action {
        "connect" => {
            let shell_id = arg_str(args, "shell_id")?;
            let (result, session_id) = crate::commands::connect_shell_impl(state, shell_id)?;
            Ok(serde_json::json!({
                "sessionId": session_id,
                "server": result.server,
                "runtime": result.runtime,
                "currentDir": result.current_dir,
            }))
        }
        "disconnect" => {
            let session_id = arg_str(args, "session_id")?;
            crate::commands::disconnect_shell_impl(state, session_id)?;
            Ok(serde_json::json!({ "disconnected": true }))
        }
        "exec" => {
            let session_id = arg_str(args, "session_id")?;
            let command = arg_str(args, "command")?;
            let ctx = crate::commands::session_ctx(state, session_id)?;
            let output = crate::commands::with_session(state, session_id, |session| {
                ctx.protocol
                    .execute_command(session, command, &ctx.settings)
            })?;
            Ok(serde_json::json!({
                "stdout": output.stdout,
                "cwd": output.cwd,
                "durationMs": output.duration_ms,
            }))
        }
        "list_dir" => {
            let session_id = arg_str(args, "session_id")?;
            let path = arg_str(args, "path")?;
            let ctx = crate::commands::session_ctx(state, session_id)?;
            let listing = crate::commands::with_session(state, session_id, |session| {
                ctx.protocol.list_dir(session, path, &ctx.settings)
            })?;
            Ok(serde_json::to_value(listing).map_err(|error| error.to_string())?)
        }
        "read_file" => {
            let session_id = arg_str(args, "session_id")?;
            let path = arg_str(args, "path")?;
            let ctx = crate::commands::session_ctx(state, session_id)?;
            let bytes = crate::commands::with_session(state, session_id, |session| {
                ctx.protocol.read_file(session, path, &ctx.settings)
            })?;
            Ok(serde_json::json!({
                "size": bytes.len(),
                "dataB64": base64::engine::general_purpose::STANDARD.encode(&bytes),
            }))
        }
        "write_file" => {
            let session_id = arg_str(args, "session_id")?;
            let path = arg_str(args, "path")?;
            let content = if let Some(text) = args.get("content").and_then(|v| v.as_str()) {
                text.as_bytes().to_vec()
            } else if let Some(encoded) = args.get("contentB64").and_then(|v| v.as_str()) {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| "contentB64 不是合法 Base64".to_string())?
            } else {
                return Err("write_file 需要 content 或 contentB64".to_string());
            };
            let ctx = crate::commands::session_ctx(state, session_id)?;
            crate::commands::with_session(state, session_id, |session| {
                ctx.protocol
                    .write_file(session, path, &content, &ctx.settings)
            })?;
            Ok(serde_json::json!({ "bytes": content.len() }))
        }
        "db_probe" => {
            let session_id = arg_str(args, "session_id")?;
            let connection: DbConnection = serde_json::from_value(
                args.get("connection")
                    .cloned()
                    .ok_or_else(|| "db_probe 需要 connection 对象".to_string())?,
            )
            .map_err(|error| format!("connection 参数不合法：{error}"))?;
            let ctx = crate::commands::session_ctx(state, session_id)?;
            let probe = crate::commands::with_session(state, session_id, |session| {
                ctx.protocol.db_probe(session, &connection, &ctx.settings)
            })?;
            Ok(serde_json::to_value(probe).map_err(|error| error.to_string())?)
        }
        "db_query" => {
            let session_id = arg_str(args, "session_id")?;
            let sql = arg_str(args, "sql")?;
            let connection: DbConnection = serde_json::from_value(
                args.get("connection")
                    .cloned()
                    .ok_or_else(|| "db_query 需要 connection 对象".to_string())?,
            )
            .map_err(|error| format!("connection 参数不合法：{error}"))?;
            let ctx = crate::commands::session_ctx(state, session_id)?;
            let result = crate::commands::with_session(state, session_id, |session| {
                ctx.protocol
                    .db_query(session, &connection, sql, &ctx.settings)
            })?;
            Ok(serde_json::to_value(result).map_err(|error| error.to_string())?)
        }
        "plugin" => {
            let session_id = arg_str(args, "session_id")?;
            let plugin_id = arg_str(args, "plugin_id")?;
            let params = args.get("params").cloned().unwrap_or(Value::Null);
            let ctx = crate::commands::session_ctx(state, session_id)?;
            // 与 run_feature_plugin 命令一致：短锁克隆会话状态后在锁外执行
            let session = {
                let mut sessions = state
                    .sessions
                    .lock()
                    .map_err(|_| "会话锁异常".to_string())?;
                sessions
                    .get_mut(session_id)
                    .map_err(|error| error.to_string())?
                    .state
                    .clone()
            };
            let plugin: std::sync::Arc<dyn FeaturePlugin> = {
                let registry = state
                    .feature_plugins
                    .lock()
                    .map_err(|_| "插件注册表锁异常".to_string())?;
                registry
                    .get(plugin_id)
                    .ok_or_else(|| format!("未知功能插件：{plugin_id}"))?
                    .clone()
            };
            let runtime = if ctx.shell.runtime.is_empty() {
                "php"
            } else {
                ctx.shell.runtime.as_str()
            };
            plugin
                .execute(
                    ctx.protocol,
                    session.as_ref(),
                    runtime,
                    &params,
                    &ctx.settings,
                )
                .map_err(|error| error.to_string())
        }
        other => Err(format!("未知动作：{other}")),
    }
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("缺少字符串参数：{key}"))
}

/// 变量替换：`${step_id.field.path}` → 步骤结果里的 JSON 值。
fn resolve_vars(value: &Value, variables: &HashMap<String, Value>) -> Value {
    match value {
        Value::String(text) => resolve_string(text, variables)
            .map(Value::String)
            .unwrap_or_else(|| Value::String(text.clone())),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| resolve_vars(item, variables))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), resolve_vars(item, variables)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn resolve_string(text: &str, variables: &HashMap<String, Value>) -> Option<String> {
    let inner = text.strip_prefix("${")?.strip_suffix('}')?;
    let (step_id, path) = inner.split_once('.')?;
    let mut current = variables.get(step_id)?;
    for key in path.split('.') {
        current = current.get(key)?;
    }
    Some(match current {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    })
}

/// 递归子集匹配：`expected` 的每个键/元素都在 `actual` 中以相等值存在。
fn json_subset(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => expected
            .iter()
            .all(|(key, value)| actual.get(key).is_some_and(|av| json_subset(av, value))),
        (Value::Array(actual), Value::Array(expected)) => {
            actual.len() == expected.len()
                && actual
                    .iter()
                    .zip(expected)
                    .all(|(av, ev)| json_subset(av, ev))
        }
        _ => actual == expected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_playbook_and_resolves_variables() {
        let yaml = r#"
name: demo
continue_on_error: true
steps:
  - id: conn
    action: connect
    args: { shell_id: shell-1 }
  - id: run
    action: exec
    args: { session_id: "${conn.sessionId}", command: "id" }
    expect: { contains: "uid=" }
"#;
        let playbook: Playbook = serde_yaml::from_str(yaml).expect("解析");
        assert_eq!(playbook.name.as_deref(), Some("demo"));
        assert!(playbook.continue_on_error);
        assert_eq!(playbook.steps.len(), 2);
        assert_eq!(playbook.steps[1].action, "exec");
        let mut vars = HashMap::new();
        vars.insert("conn".to_string(), serde_json::json!({ "sessionId": "s1" }));
        let resolved = resolve_vars(&playbook.steps[1].args, &vars);
        assert_eq!(resolved["session_id"], serde_json::json!("s1"));
        // 未知变量保持原样（便于发现拼写错误时从结果里看出来）
        let unknown = resolve_vars(&serde_json::json!({"x": "${nope.y}"}), &HashMap::new());
        assert_eq!(unknown["x"], serde_json::json!("${nope.y}"));
    }

    #[test]
    fn json_subset_matches_recursively() {
        let actual = serde_json::json!({"a": 1, "b": {"c": [1, 2]}, "d": "text"});
        assert!(json_subset(&actual, &serde_json::json!({"a": 1})));
        assert!(json_subset(
            &actual,
            &serde_json::json!({"b": {"c": [1, 2]}})
        ));
        assert!(!json_subset(&actual, &serde_json::json!({"a": 2})));
        assert!(!json_subset(&actual, &serde_json::json!({"b": {"c": [1]}})));
    }

    /// 端到端：mock 协议（无网络）跑通 connect → exec → list_dir → disconnect。
    #[test]
    fn playbook_runs_against_mock_protocol() {
        let state = crate::test_app_state();
        // 需要一个 Workspace + Shell（mock 协议）
        let workspace_id = {
            let mut database = state.database.lock().unwrap();
            database
                .create_workspace(dosword_sdk::domain::CreateWorkspace {
                    name: "lab".into(),
                    authorization_scope: "127.0.0.1".into(),
                    expires_at: None,
                })
                .unwrap()
                .id
        };
        let shell_id = {
            let mut database = state.database.lock().unwrap();
            database
                .create_shell(
                    dosword_sdk::domain::CreateShell {
                        workspace_id,
                        name: "mock".into(),
                        endpoint: "mock://local".into(),
                        runtime: "php".into(),
                        protocol_id: "builtin.mock.v1".into(),
                        password: Some("secret".into()),
                        protocol_params: None,
                        confirm_network: false,
                        tags: None,
                    },
                    "builtin.mock.v1",
                )
                .unwrap()
                .id
        };
        let yaml = format!(
            r#"
name: mock-smoke
steps:
  - id: conn
    action: connect
    args: {{ shell_id: "{shell_id}" }}
  - id: run
    action: exec
    args: {{ session_id: "${{conn.sessionId}}", command: "whoami" }}
  - action: list_dir
    args: {{ session_id: "${{conn.sessionId}}", path: "." }}
  - action: disconnect
    args: {{ session_id: "${{conn.sessionId}}" }}
"#
        );
        let report = run(&state, &yaml).expect("执行 playbook");
        assert!(report.ok, "{:?}", report.steps);
        assert_eq!(report.steps.len(), 4);
        assert!(
            report.steps.iter().all(|step| step.ok),
            "{:?}",
            report.steps
        );
        assert!(report.steps[1].result.is_some());
    }

    /// 断言失败 → 默认中止后续步骤。
    #[test]
    fn failed_expectation_stops_playbook() {
        let state = crate::test_app_state();
        let workspace_id = {
            let mut database = state.database.lock().unwrap();
            database
                .create_workspace(dosword_sdk::domain::CreateWorkspace {
                    name: "lab".into(),
                    authorization_scope: "127.0.0.1".into(),
                    expires_at: None,
                })
                .unwrap()
                .id
        };
        let shell_id = {
            let mut database = state.database.lock().unwrap();
            database
                .create_shell(
                    dosword_sdk::domain::CreateShell {
                        workspace_id,
                        name: "mock".into(),
                        endpoint: "mock://local".into(),
                        runtime: "php".into(),
                        protocol_id: "builtin.mock.v1".into(),
                        password: Some("secret".into()),
                        protocol_params: None,
                        confirm_network: false,
                        tags: None,
                    },
                    "builtin.mock.v1",
                )
                .unwrap()
                .id
        };
        let yaml = format!(
            r#"
steps:
  - id: conn
    action: connect
    args: {{ shell_id: "{shell_id}" }}
  - action: exec
    args: {{ session_id: "${{conn.sessionId}}", command: "whoami" }}
    expect: {{ contains: "definitely-not-in-output" }}
  - action: disconnect
    args: {{ session_id: "${{conn.sessionId}}" }}
"#
        );
        let report = run(&state, &yaml).expect("执行 playbook");
        assert!(!report.ok);
        assert_eq!(report.steps.len(), 2, "默认应在失败步骤中止");
        assert!(!report.steps[1].ok);
        assert!(
            report.steps[1]
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("断言失败")
        );
    }
}
