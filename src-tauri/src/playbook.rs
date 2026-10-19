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
//!   # 条件：为假时跳过（skipped=true，不算失败）
//!   - action: exec
//!     when: { ref: "${conn.runtime}", equals: "php" }
//!     args: { session_id: "${conn.sessionId}", command: "php -v" }
//!   # 循环：repeat 重复执行；foreach 遍历数组（变量或内联）
//!   - id: repeat3
//!     action: exec
//!     repeat: 3
//!     args: { session_id: "${conn.sessionId}", command: "date" }
//!   - id: each
//!     action: exec
//!     foreach: { source: "${repeat3.iterations}", as: "item" }
//!     args: { session_id: "${conn.sessionId}", command: "echo ${item.durationMs}" }
//!   - action: disconnect
//!     args: { session_id: "${conn.sessionId}" }
//! ```
//!
//! 变量替换：`${步骤 id.字段路径}` / `${item.字段}`（循环变量），支持内嵌插值。
//! 断言：`contains`（序列化结果包含子串）/ `equals`（对结果做递归子集匹配）。
//! 循环：`repeat: N` 或 `foreach: { source, as }`，结果聚合为 `{"iterations":[...]}`。

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
    /// 条件：为假时跳过该步骤（`skipped=true`，不算失败）。
    #[serde(default)]
    pub when: Option<When>,
    /// 重复执行次数（与 `foreach` 互斥；上限 1000）。
    #[serde(default)]
    pub repeat: Option<u32>,
    /// 遍历一个数组（来自变量或内联数组）。结果聚合为 `{"iterations":[...]}`。
    #[serde(default)]
    pub foreach: Option<Foreach>,
}

/// 步骤条件。
#[derive(Debug, Deserialize)]
pub struct When {
    /// 引用表达式：`${步骤id.字段}`（支持 `!` 前缀取反）。
    #[serde(rename = "ref")]
    pub reference: String,
    /// 与引用值精确相等。
    #[serde(default)]
    pub equals: Option<Value>,
    /// 与引用值不相等。
    #[serde(default)]
    pub not_equals: Option<Value>,
}

/// 循环遍历。
#[derive(Debug, Deserialize)]
pub struct Foreach {
    /// 数组来源：`${步骤id.字段}` 或内联数组。
    pub source: Value,
    /// 循环变量名（默认 `item`），在 `args` 里用 `${item.字段}` 引用。
    #[serde(default = "default_loop_var", rename = "as")]
    pub loop_var: String,
}

fn default_loop_var() -> String {
    "item".to_string()
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
        let step_started = Instant::now();
        // 条件为假：跳过（不算失败，也不写入变量）
        if let Some(when) = &step.when
            && !eval_when(when, &variables)
        {
            steps.push(PlaybookStepReport {
                index,
                id: step.id.clone(),
                action: step.action.clone(),
                ok: true,
                skipped: true,
                duration_ms: step_started.elapsed().as_millis() as u64,
                error: None,
                result: None,
            });
            continue;
        }

        let (result, error) = if let Some(foreach) = &step.foreach {
            run_foreach(state, step, foreach, &variables)
        } else if let Some(repeat) = step.repeat {
            run_repeat(state, step, repeat, &variables)
        } else {
            let args = resolve_vars(&step.args, &variables, &HashMap::new());
            run_one(state, step, &args)
        };
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
            skipped: false,
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

/// 执行一次动作并检查断言。
fn run_one(state: &AppState, step: &Step, args: &Value) -> (Option<Value>, Option<String>) {
    match run_step(state, &step.action, args) {
        Ok(result) => {
            let error = check_expect(step.expect.as_ref(), &result);
            (Some(result), error)
        }
        Err(message) => (None, Some(message)),
    }
}

/// 断言检查：`contains` 对序列化结果做子串匹配；`equals` 做递归子集匹配。
fn check_expect(expect: Option<&Expect>, result: &Value) -> Option<String> {
    let expect = expect?;
    if let Some(text) = expect.contains.as_deref()
        && !result.to_string().contains(text)
    {
        return Some(format!("断言失败：结果不包含 {text:?}"));
    }
    if let Some(expected) = &expect.equals
        && !json_subset(result, expected)
    {
        return Some("断言失败：结果不匹配 equals".to_string());
    }
    None
}

/// `repeat: N`：重复执行同一动作（上限 1000），结果聚合为 `{"iterations":[...]}`。
fn run_repeat(
    state: &AppState,
    step: &Step,
    repeat: u32,
    variables: &HashMap<String, Value>,
) -> (Option<Value>, Option<String>) {
    if repeat > 1000 {
        return (None, Some("repeat 上限为 1000".to_string()));
    }
    let mut iterations = Vec::with_capacity(repeat as usize);
    let mut error = None;
    for _ in 0..repeat {
        let args = resolve_vars(&step.args, variables, &HashMap::new());
        let (result, err) = run_one(state, step, &args);
        iterations.push(result.unwrap_or(Value::Null));
        if let Some(err) = err {
            error = Some(err);
            break;
        }
    }
    (Some(serde_json::json!({ "iterations": iterations })), error)
}

/// `foreach`：遍历数组（变量或内联），每轮把 `as`（默认 `item`）注入 args。
fn run_foreach(
    state: &AppState,
    step: &Step,
    foreach: &Foreach,
    variables: &HashMap<String, Value>,
) -> (Option<Value>, Option<String>) {
    let source = match &foreach.source {
        Value::String(text) => match resolve_ref_value(text, variables, &HashMap::new()) {
            Some(value) => value,
            None => return (None, Some(format!("无法解析 foreach.source：{text}"))),
        },
        other => other.clone(),
    };
    let Some(items) = source.as_array() else {
        return (None, Some("foreach.source 必须是数组".to_string()));
    };
    if items.len() > 1000 {
        return (None, Some("foreach 上限为 1000 项".to_string()));
    }
    let mut iterations = Vec::with_capacity(items.len());
    let mut error = None;
    for item in items {
        let mut loop_vars = HashMap::new();
        loop_vars.insert(foreach.loop_var.clone(), item.clone());
        let args = resolve_vars(&step.args, variables, &loop_vars);
        let (result, err) = run_one(state, step, &args);
        iterations.push(result.unwrap_or(Value::Null));
        if let Some(err) = err {
            error = Some(err);
            break;
        }
    }
    (Some(serde_json::json!({ "iterations": iterations })), error)
}

/// 条件求值：引用真值 / 相等 / 不等，支持 `!` 前缀取反。
fn eval_when(when: &When, variables: &HashMap<String, Value>) -> bool {
    let mut reference = when.reference.trim();
    let negate = reference.starts_with('!');
    if negate {
        reference = reference[1..].trim();
    }
    let value = resolve_ref_value(reference, variables, &HashMap::new()).unwrap_or(Value::Null);
    let matched = if let Some(expected) = &when.equals {
        value == *expected
    } else if let Some(expected) = &when.not_equals {
        value != *expected
    } else {
        truthy(&value)
    };
    if negate { !matched } else { matched }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(item) => *item,
        Value::Number(item) => item.as_f64().is_some_and(|number| number != 0.0),
        Value::String(item) => !item.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
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

/// 变量替换：`${step_id.field.path}` / `${item.字段}` → JSON 值（字符串化）。
fn resolve_vars(
    value: &Value,
    variables: &HashMap<String, Value>,
    loop_vars: &HashMap<String, Value>,
) -> Value {
    match value {
        Value::String(text) => resolve_string(text, variables, loop_vars)
            .map(Value::String)
            .unwrap_or_else(|| Value::String(text.clone())),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| resolve_vars(item, variables, loop_vars))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), resolve_vars(item, variables, loop_vars)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// 字符串插值：支持整串与内嵌引用（`echo ${item.name}`）。
/// 未知引用保持原样（便于从结果里发现拼写错误）。
fn resolve_string(
    text: &str,
    variables: &HashMap<String, Value>,
    loop_vars: &HashMap<String, Value>,
) -> Option<String> {
    if let Some(inner) = text
        .strip_prefix("${")
        .and_then(|item| item.strip_suffix('}'))
    {
        return lookup_ref(inner, variables, loop_vars).map(value_to_string);
    }
    if !text.contains("${") {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}')?;
        let inner = &after[..end];
        match lookup_ref(inner, variables, loop_vars) {
            Some(value) => out.push_str(&value_to_string(value)),
            None => {
                out.push_str("${");
                out.push_str(inner);
                out.push('}');
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

fn value_to_string(value: Value) -> String {
    match value {
        Value::String(text) => text,
        other => other.to_string(),
    }
}

/// 引用表达式求值：整个字符串是 `${...}` 时返回原始 JSON 值，否则返回字符串。
fn resolve_ref_value(
    text: &str,
    variables: &HashMap<String, Value>,
    loop_vars: &HashMap<String, Value>,
) -> Option<Value> {
    match text
        .strip_prefix("${")
        .and_then(|item| item.strip_suffix('}'))
    {
        Some(inner) => lookup_ref(inner, variables, loop_vars),
        None => Some(Value::String(text.to_string())),
    }
}

/// `根.路径` 查找：根优先查循环变量，再查步骤结果；路径按 `.` 逐级下钻。
fn lookup_ref(
    inner: &str,
    variables: &HashMap<String, Value>,
    loop_vars: &HashMap<String, Value>,
) -> Option<Value> {
    let (root, path) = match inner.split_once('.') {
        Some((root, path)) => (root, Some(path)),
        None => (inner, None),
    };
    let mut current = loop_vars.get(root).or_else(|| variables.get(root))?.clone();
    if let Some(path) = path {
        for key in path.split('.') {
            current = current.get(key)?.clone();
        }
    }
    Some(current)
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
        let resolved = resolve_vars(&playbook.steps[1].args, &vars, &HashMap::new());
        assert_eq!(resolved["session_id"], serde_json::json!("s1"));
        // 未知变量保持原样（便于发现拼写错误时从结果里看出来）
        let unknown = resolve_vars(
            &serde_json::json!({"x": "${nope.y}"}),
            &HashMap::new(),
            &HashMap::new(),
        );
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

    /// 建立 mock 协议环境：内存库 + Workspace + Shell，返回 (state, shell_id)。
    fn mock_state() -> (AppState, String) {
        let state = crate::test_app_state();
        let workspace_id = {
            let mut database = state.database().lock().unwrap();
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
            let mut database = state.database().lock().unwrap();
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
        (state, shell_id)
    }

    /// 端到端：mock 协议（无网络）跑通 connect → exec → list_dir → disconnect。
    #[test]
    fn playbook_runs_against_mock_protocol() {
        let (state, shell_id) = mock_state();
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
        let (state, shell_id) = mock_state();
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

    /// `when` 条件：为假时跳过（不算失败、后续步骤继续）。
    #[test]
    fn when_condition_skips_step() {
        let (state, shell_id) = mock_state();
        let yaml = format!(
            r#"
steps:
  - id: conn
    action: connect
    args: {{ shell_id: "{shell_id}" }}
  - action: exec
    args: {{ session_id: "${{conn.sessionId}}", command: "echo skipped" }}
    when: {{ ref: "${{conn.sessionId}}", equals: "definitely-not" }}
  - action: exec
    args: {{ session_id: "${{conn.sessionId}}", command: "echo ran" }}
    when: {{ ref: "${{conn.sessionId}}" }}
  - action: exec
    args: {{ session_id: "${{conn.sessionId}}", command: "echo negated" }}
    when: {{ ref: "!${{conn.sessionId}}" }}
"#
        );
        let report = run(&state, &yaml).expect("执行 playbook");
        assert!(report.ok, "{:?}", report.steps);
        assert_eq!(report.steps.len(), 4);
        assert!(report.steps[1].skipped, "equals 不匹配应跳过");
        assert!(!report.steps[2].skipped, "真值条件应执行");
        assert!(report.steps[3].skipped, "取反条件应跳过");
    }

    /// `repeat`：重复执行并把结果聚合到 iterations。
    #[test]
    fn repeat_runs_n_times() {
        let (state, shell_id) = mock_state();
        let yaml = format!(
            r#"
steps:
  - id: conn
    action: connect
    args: {{ shell_id: "{shell_id}" }}
  - id: loop
    action: exec
    repeat: 3
    args: {{ session_id: "${{conn.sessionId}}", command: "echo x" }}
    expect: {{ contains: "Mock 执行成功" }}
"#
        );
        let report = run(&state, &yaml).expect("执行 playbook");
        assert!(report.ok, "{:?}", report.steps);
        let result = report.steps[1].result.as_ref().expect("结果");
        assert_eq!(result["iterations"].as_array().unwrap().len(), 3);
    }

    /// `foreach`：内联数组 + 循环变量注入 args。
    #[test]
    fn foreach_binds_loop_variable() {
        let (state, shell_id) = mock_state();
        let yaml = format!(
            r#"
steps:
  - id: conn
    action: connect
    args: {{ shell_id: "{shell_id}" }}
  - id: each
    action: exec
    foreach: {{ source: ["alpha", "beta"], as: "name" }}
    args: {{ session_id: "${{conn.sessionId}}", command: "echo ${{name}}" }}
"#
        );
        let report = run(&state, &yaml).expect("执行 playbook");
        assert!(report.ok, "{:?}", report.steps);
        let iterations = report.steps[1].result.as_ref().unwrap()["iterations"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(iterations.len(), 2);
        assert!(
            iterations[0]["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("echo alpha")
        );
        assert!(
            iterations[1]["stdout"]
                .as_str()
                .unwrap_or_default()
                .contains("echo beta")
        );
    }

    /// `foreach.source` 不是数组时给出明确错误。
    #[test]
    fn foreach_requires_array_source() {
        let (state, shell_id) = mock_state();
        let yaml = format!(
            r#"
steps:
  - id: conn
    action: connect
    args: {{ shell_id: "{shell_id}" }}
  - action: exec
    foreach: {{ source: "${{conn.server}}" }}
    args: {{ session_id: "${{conn.sessionId}}", command: "echo x" }}
"#
        );
        let report = run(&state, &yaml).expect("执行 playbook");
        assert!(!report.ok);
        assert!(
            report.steps[1]
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("必须是数组")
        );
    }
}
