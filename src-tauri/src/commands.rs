use base64::Engine;
use std::sync::Arc;
use tauri::{AppHandle, Manager, State};
use url::Url;

use dosword_sdk::domain::{
    AppSettings, AuditFilter, AuditPage, CommandOutput, ConnectResult, CreateShell,
    CreateWorkspace, Dashboard, DbConnection, DbProbeResult, DbQueryResult, DirListing,
    FileContent, GenerateShellResult, HttpSendResult, ImportResult, ProbeResult,
    ProtocolMeta, RequestRecord, SessionInfo,
    ShellProfile, UpdateShell, UpdateWorkspace, Workspace,
};
use dosword_sdk::encoder::{EncoderRegistry, STUB_LANGUAGES};
use dosword_sdk::{PluginManifest, Protocol, ProtocolError, SessionState};

use crate::auth;
use crate::AppState;

fn validate_text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} 不能为空"))
    } else {
        Ok(())
    }
}

/// 解析并验证 Shell 的 endpoint。
fn parse_endpoint(endpoint: &str) -> Result<Url, String> {
    Url::parse(endpoint).map_err(|_| "Endpoint 必须是有效 URL".to_string())
}

// --- 通用辅助：锁内取数，锁外网络 ---

/// 命令统一调度：把同步命令体放到阻塞线程池执行，避免主线程冻结。
/// 命令层因此可以自由持有 `std::sync::Mutex` 而不会跨越 await。
async fn blocking<T, F>(app: AppHandle, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&AppState) -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        f(&state)
    })
    .await
    .map_err(|error| format!("任务调度失败：{error}"))?
}

/// 读取 Shell 配置与全局设置（锁内完成，不跨网络）。
fn load_shell_and_settings(state: &AppState, shell_id: &str) -> Result<(ShellProfile, AppSettings), String> {
    let database = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?;
    let shell = database
        .shell(shell_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Shell 不存在".to_string())?;
    let settings = database.get_settings().map_err(|error| error.to_string())?;
    Ok((shell, settings))
}

/// 审计辅助：成功/失败事件落库（失败审计吞掉写库错误，不掩盖原始错误）。
fn audit(
    state: &AppState,
    workspace_id: &str,
    shell_id: Option<&str>,
    action: &str,
    outcome: &str,
    detail: &str,
) {
    let _ = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())
        .and_then(|database| {
            database
                .record_audit(Some(workspace_id), shell_id, action, outcome, detail)
                .map_err(|error| error.to_string())
        });
}

/// 审计失败并把协议错误转成 String。
fn audit_fail(
    state: &AppState,
    shell: &ShellProfile,
    action: &str,
    error: ProtocolError,
) -> String {
    let message = error.to_string();
    audit(state, &shell.workspace_id, Some(&shell.id), action, "error", &message);
    message
}

/// 对真实网络协议做完整授权检查；Mock 协议直接放行。
/// 返回校验方式说明（供审计追溯）。
fn require_authorized_for(state: &AppState, shell: &ShellProfile, settings: &AppSettings) -> Result<String, String> {
    let protocol = state
        .protocols
        .get(&shell.protocol_id)
        .ok_or_else(|| format!("未知协议：{}", shell.protocol_id))?;
    if protocol.requires_network() {
        if !settings.http_enabled {
            return Err("真实网络协议未启用：请先在「设置」中开启并确认授权声明".into());
        }
        let database = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?;
        auth::require_authorized(&database, shell)
    } else {
        Ok("Mock 协议（本地）".to_string())
    }
}

// --- 基础 CRUD ---

#[tauri::command]
pub async fn dashboard(app: AppHandle) -> Result<Dashboard, String> {
    blocking(app, move |state| {
        state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .dashboard()
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub async fn create_workspace(
    input: CreateWorkspace,
    app: AppHandle,
) -> Result<Workspace, String> {
    blocking(app, move |state| {
        validate_text(&input.name, "名称")?;
        validate_text(&input.authorization_scope, "授权范围")?;
        state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .create_workspace(input)
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub async fn create_shell(
    input: CreateShell,
    app: AppHandle,
) -> Result<ShellProfile, String> {
    blocking(app, move |state| {
        validate_text(&input.name, "名称")?;
        validate_text(&input.workspace_id, "Workspace")?;
        let endpoint = parse_endpoint(&input.endpoint)?;

        let protocol = state
            .protocols
            .get(&input.protocol_id)
            .ok_or_else(|| format!("未知协议：{}", input.protocol_id))?;

        // 安全门：真实网络协议必须全局开启 + 授权范围覆盖 + 勾选确认
        if protocol.requires_network() {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            let settings = database.get_settings().map_err(|error| error.to_string())?;
            if !settings.http_enabled {
                return Err("真实网络协议未启用：请先在「设置」中开启并确认授权声明".into());
            }
            let workspace = database
                .workspace(&input.workspace_id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "Workspace 不存在".to_string())?;
            auth::check_workspace_authorized(Some(&workspace))?;
            let (allowed, _reason) = auth::scope_allows(&workspace.authorization_scope, &endpoint);
            if !allowed {
                return Err("目标不在 Workspace 授权范围内，请检查授权范围或端点地址".into());
            }
            if !input.confirm_network {
                return Err("请勾选「我已确认目标位于授权范围内」后再登记 Shell".into());
            }
        }

        let profile = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .create_shell(input, protocol.id())
            .map_err(|error| error.to_string())?;
        audit(
            state,
            &profile.workspace_id,
            Some(&profile.id),
            "shell.create",
            "success",
            &format!("登记 Shell：{}（协议 {}）", profile.endpoint, profile.protocol_id),
        );
        Ok(profile)
    })
    .await
}

#[tauri::command]
pub async fn update_workspace(
    input: UpdateWorkspace,
    app: AppHandle,
) -> Result<Workspace, String> {
    blocking(app, move |state| {
        validate_text(&input.name, "名称")?;
        validate_text(&input.authorization_scope, "授权范围")?;
        let workspace = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .update_workspace(&input)
            .map_err(|error| error.to_string())?;
        audit(
            state,
            &workspace.id,
            None,
            "workspace.update",
            "success",
            &format!("更新 Workspace：{}（范围 {}）", workspace.name, workspace.authorization_scope),
        );
        Ok(workspace)
    })
    .await
}

#[tauri::command]
pub async fn delete_workspace(workspace_id: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        let name = {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            let workspace = database
                .workspace(&workspace_id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "Workspace 不存在".to_string())?;
            database
                .delete_workspace(&workspace_id)
                .map_err(|error| error.to_string())?;
            workspace.name
        };
        // 清理该 Workspace 下的全部活跃会话
        state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?
            .remove_by_workspace(&workspace_id);
        audit(state, &workspace_id, None, "workspace.delete", "success", &format!("删除 Workspace：{name}"));
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn update_shell(input: UpdateShell, app: AppHandle) -> Result<ShellProfile, String> {
    blocking(app, move |state| {
        validate_text(&input.name, "名称")?;
        let previous = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .shell(&input.id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Shell 不存在".to_string())?;

        // 端点变更时重跑授权范围校验（真实网络协议）
        if previous.endpoint != input.endpoint {
            let endpoint = parse_endpoint(&input.endpoint)?;
            let protocol = state
                .protocols
                .get(&previous.protocol_id)
                .ok_or_else(|| format!("未知协议：{}", previous.protocol_id))?;
            if protocol.requires_network() {
                let database = state
                    .database
                    .lock()
                    .map_err(|_| "数据库锁异常".to_string())?;
                let settings = database.get_settings().map_err(|error| error.to_string())?;
                if !settings.http_enabled {
                    return Err("真实网络协议未启用：请先在「设置」中开启并确认授权声明".into());
                }
                let workspace = database
                    .workspace(&previous.workspace_id)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "Workspace 不存在".to_string())?;
                auth::check_workspace_authorized(Some(&workspace))?;
                let (allowed, _reason) = auth::scope_allows(&workspace.authorization_scope, &endpoint);
                if !allowed {
                    return Err("目标不在 Workspace 授权范围内，请检查授权范围或端点地址".into());
                }
            }
        }

        let profile = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .update_shell(&input)
            .map_err(|error| error.to_string())?;
        audit(
            state,
            &profile.workspace_id,
            Some(&profile.id),
            "shell.update",
            "success",
            &format!("更新 Shell：{} → {}", previous.endpoint, profile.endpoint),
        );
        Ok(profile)
    })
    .await
}

#[tauri::command]
pub async fn delete_shell(shell_id: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        let (workspace_id, endpoint) = {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            let shell = database
                .shell(&shell_id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "Shell 不存在".to_string())?;
            database
                .delete_shell(&shell_id)
                .map_err(|error| error.to_string())?;
            (shell.workspace_id, shell.endpoint)
        };
        // 清理该 Shell 的活跃会话
        state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?
            .remove_by_profile(&shell_id);
        audit(state, &workspace_id, None, "shell.delete", "success", &format!("删除 Shell：{endpoint}"));
        Ok(())
    })
    .await
}

/// 登记前连通性测试：用表单中的临时配置（不落库）对目标执行一次探测。
#[tauri::command]
pub async fn test_connection(
    endpoint: String,
    password: String,
    protocol_id: String,
    protocol_params: Option<String>,
    runtime: Option<String>,
    app: AppHandle,
) -> Result<ProbeResult, String> {
    blocking(app, move |state| {
        test_connection_impl(state, &endpoint, &password, &protocol_id, protocol_params.as_deref(), runtime.as_deref())
    })
    .await
}

fn test_connection_impl(
    state: &AppState,
    endpoint: &str,
    password: &str,
    protocol_id: &str,
    protocol_params: Option<&str>,
    runtime: Option<&str>,
) -> Result<ProbeResult, String> {
    let settings = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?
        .get_settings()
        .map_err(|error| error.to_string())?;
    let protocol = state
        .protocols
        .get(protocol_id)
        .ok_or_else(|| format!("未知协议：{protocol_id}"))?;
    if protocol.requires_network() && !settings.http_enabled {
        return Err("真实网络协议尚未在「设置」中开启授权声明".to_string());
    }
    parse_endpoint(endpoint)?;
    validate_text(password, "连接密码")?;
    let profile = ShellProfile {
        id: String::new(),
        workspace_id: String::new(),
        name: "连接测试".into(),
        endpoint: endpoint.to_string(),
        runtime: runtime.unwrap_or("php").to_string(),
        protocol_id: protocol_id.to_string(),
        password: password.to_string(),
        protocol_params: protocol_params.unwrap_or("{}").to_string(),
        authorization_ack: true,
        status: String::new(),
        last_connected_at: None,
        created_at: String::new(),
        tags: Vec::new(),
    };
    protocol
        .probe(&profile, &settings)
        .map_err(|error| format!("连接失败：{error}"))
}

#[tauri::command]
pub async fn probe_shell(shell_id: String, app: AppHandle) -> Result<ProbeResult, String> {
    blocking(app, move |state| {
        let (shell, settings) = load_shell_and_settings(state, &shell_id)?;
        let _auth_reason = require_authorized_for(state, &shell, &settings)?;

        let protocol = state
            .protocols
            .get(&shell.protocol_id)
            .ok_or_else(|| format!("未知协议：{}", shell.protocol_id))?;

        let result = protocol.probe(&shell, &settings).map_err(|error| {
            // 失败也更新状态并记录审计
            let _ = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())
                .and_then(|database| {
                    database
                        .record_probe(&shell, "error", &error.to_string())
                        .map_err(|db_error| db_error.to_string())
                });
            audit_fail(state, &shell, "shell.probe", error)
        })?;

        state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .record_probe(&shell, "online", &result.message)
            .map_err(|error| error.to_string())?;
        audit(state, &shell.workspace_id, Some(&shell.id), "shell.probe", "success", &result.message);
        Ok(result)
    })
    .await
}

// --- 设置 ---

/// 生成服务端 Webshell stub（本地生成，不产生网络流量）。
/// `language` 白名单：php / asp / aspx / jsp；`encoder_id`：xor_base64 / base64。
#[tauri::command]
pub async fn generate_shell(
    language: String,
    encoder_id: String,
    password: String,
    session: bool,
    app: AppHandle,
) -> Result<GenerateShellResult, String> {
    blocking(app, move |state| {
        if !STUB_LANGUAGES.contains(&language.as_str()) {
            return Err(format!(
                "不支持的语言：{language}（支持 {}）",
                STUB_LANGUAGES.join(" / ")
            ));
        }
        let encoder = EncoderRegistry::global()
            .get(&encoder_id)
            .ok_or_else(|| format!("未知编码器：{encoder_id}"))?;
        let content = if session {
            encoder
                .stub_session(&language, &password)
                .map_err(|error| error.to_string())?
        } else {
            encoder
                .stub(&language, &password)
                .map_err(|error| error.to_string())?
        };
        let filename = format!("shell_{}_{}.{}", language, encoder_id, language);
        audit(
            state,
            "system",
            None,
            "shell.generate",
            "success",
            &format!("生成 Webshell：{filename}（{} 字节）", content.len()),
        );
        Ok(GenerateShellResult { filename, content })
    })
    .await
}

#[tauri::command]
pub async fn list_encoders(app: AppHandle) -> Vec<(String, String)> {
    blocking(app, |_state| Ok(EncoderRegistry::global().list()))
        .await
        .unwrap_or_default()
}

/// 读取本地文件（Shell 导入用）。
#[tauri::command]
pub async fn read_local_file(path: String, app: AppHandle) -> Result<String, String> {
    blocking(app, move |_state| {
        std::fs::read(&path)
            .map_err(|error| format!("读取本地文件失败：{error}"))
            .map(|bytes| {
                base64::engine::general_purpose::STANDARD.encode(bytes)
            })
    })
    .await
}

/// 导出全部 Shell 配置（JSON 数组，含密码——请妥善保管导出文件）。
#[tauri::command]
pub fn export_shells(state: State<'_, AppState>) -> Result<String, String> {
    export_shells_impl(&state)
}

fn export_shells_impl(state: &AppState) -> Result<String, String> {
    let database = state.database.lock().map_err(|_| "数据库锁异常".to_string())?;
    let shells = database.list_shells().map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&shells).map_err(|error| error.to_string())
}

/// 批量导入 Shell 配置（JSON 数组）。endpoint 已存在或协议不存在时跳过。
#[tauri::command]
pub async fn import_shells(
    payload: String,
    workspace_id: String,
    app: AppHandle,
) -> Result<ImportResult, String> {
    blocking(app, move |state| {
        import_shells_impl(&state, &payload, &workspace_id)
    })
    .await
}

fn import_shells_impl(state: &AppState, payload: &str, workspace_id: &str) -> Result<ImportResult, String> {
    {
        let items: Vec<serde_json::Value> =
            serde_json::from_str(payload).map_err(|error| format!("导入文件不是合法 JSON：{error}"))?;
        let mut imported = 0usize;
        let mut skipped = 0usize;
        let mut database = state.database.lock().map_err(|_| "数据库锁异常".to_string())?;
        let _workspace = database
            .workspace(workspace_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "目标 Workspace 不存在".to_string())?;
        let existing: Vec<String> = database
            .list_shells()
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|shell| shell.endpoint)
            .collect();
        for item in items {
            let endpoint = item.get("endpoint").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let protocol_id = item
                .get("protocol_id")
                .or_else(|| item.get("protocolId"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if endpoint.trim().is_empty()
                || existing.contains(&endpoint)
                || state.protocols.get(&protocol_id).is_none()
            {
                skipped += 1;
                continue;
            }
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let runtime = item
                .get("runtime")
                .and_then(|v| v.as_str())
                .unwrap_or("php")
                .to_string();
            let password = item
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let protocol_params = item
                .get("protocol_params")
                .or_else(|| item.get("protocolParams"))
                .and_then(|v| v.as_str())
                .unwrap_or("{}")
                .to_string();
            let tags: Vec<String> = item
                .get("tags")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|tag| tag.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let create = CreateShell {
                workspace_id: workspace_id.to_string(),
                name: if name.trim().is_empty() { endpoint.clone() } else { name },
                endpoint: endpoint.clone(),
                runtime,
                protocol_id: protocol_id.clone(),
                password: Some(password),
                protocol_params: Some(protocol_params),
                confirm_network: false,
                tags: Some(tags),
            };
            match database.create_shell(create, &protocol_id) {
                Ok(_) => imported += 1,
                Err(_) => skipped += 1,
            }
        }
        Ok(ImportResult { imported, skipped })
    }
}

#[tauri::command]
pub async fn write_local_file(path: String, content_b64: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |_state| {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&content_b64)
            .map_err(|_| "内容不是合法 Base64".to_string())?;
        std::fs::write(&path, &bytes).map_err(|error| format!("写入本地文件失败：{error}"))
    })
    .await
}

#[tauri::command]
pub async fn list_audit(filter: AuditFilter, app: AppHandle) -> Result<AuditPage, String> {
    blocking(app, move |state| {
        let database = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?;
        let (total, events) = database
            .query_audit(&filter)
            .map_err(|error| error.to_string())?;
        Ok(AuditPage { total, events })
    })
    .await
}

#[tauri::command]
pub fn list_protocols(state: State<'_, AppState>) -> Vec<ProtocolMeta> {
    state.protocols.protocol_metas()
}

/// 功能插件列表（ZIP / 进程 / 端口扫描 / bypass 等）。
#[tauri::command]
pub fn list_feature_plugins(state: State<'_, AppState>) -> Vec<dosword_sdk::FeatureManifest> {
    state.feature_plugins.list()
}

/// 在已连接会话上执行功能插件。
#[tauri::command]
pub async fn run_feature_plugin(
    session_id: String,
    plugin_id: String,
    params: serde_json::Value,
    app: AppHandle,
) -> Result<serde_json::Value, String> {
    blocking(app, move |state| {
        let (session, protocol_id, runtime) = {
            let mut sessions = state.sessions.lock().map_err(|_| "会话锁异常".to_string())?;
            let session = sessions
                .get_mut(&session_id)
                .map_err(|error| error.to_string())?;
            let runtime = {
                let database = state.database.lock().map_err(|_| "数据库锁异常".to_string())?;
                database
                    .shell(&session.profile_id)
                    .map_err(|error| error.to_string())?
                    .map(|shell| shell.runtime)
                    .unwrap_or_else(|| "php".to_string())
            };
            (
                session.state.clone(),
                session.protocol_id.clone(),
                runtime,
            )
        };
        let protocol = state
            .protocols
            .get(&protocol_id)
            .ok_or_else(|| format!("未知协议：{protocol_id}"))?;
        let plugin = state
            .feature_plugins
            .get(&plugin_id)
            .ok_or_else(|| format!("未知功能插件：{plugin_id}"))?;
        let settings = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .get_settings()
            .map_err(|error| error.to_string())?;
        plugin
            .execute(protocol, session.as_ref(), &runtime, &params, &settings)
            .map_err(|error| format!("插件执行失败：{error}"))
    })
    .await
}

/// 刷新全部 Shell 状态（逐个探测，更新 status / last_connected_at），返回最新列表。
#[tauri::command]
pub async fn refresh_shell_status(app: AppHandle) -> Result<Vec<ShellProfile>, String> {
    blocking(app, move |state| {
        let (shells, settings) = {
            let database = state.database.lock().map_err(|_| "数据库锁异常".to_string())?;
            let shells = database.list_shells().map_err(|error| error.to_string())?;
            let settings = database.get_settings().map_err(|error| error.to_string())?;
            (shells, settings)
        };
        for shell in &shells {
            let protocol = state
                .protocols
                .get(&shell.protocol_id)
                .ok_or_else(|| format!("未知协议：{}", shell.protocol_id))?;
            let status = match protocol.probe(shell, &settings) {
                Ok(_) => "online".to_string(),
                Err(_) => "error".to_string(),
            };
            let _ = state.database.lock().map_err(|_| "数据库锁异常".to_string()).and_then(
                |database| {
                    database
                        .update_shell_status(&shell.id, &status)
                        .map_err(|error| error.to_string())
                },
            );
        }
        let database = state.database.lock().map_err(|_| "数据库锁异常".to_string())?;
        database.list_shells().map_err(|error| error.to_string())
    })
    .await
}

/// 批量更新 Shell：批量设置标签 / 密码（其余字段保持）。
#[tauri::command]
pub async fn batch_update_shells(
    ids: Vec<String>,
    tags: Option<Vec<String>>,
    password: Option<String>,
    app: AppHandle,
) -> Result<usize, String> {
    blocking(app, move |state| {
        batch_update_shells_impl(&state, &ids, tags, password)
    })
    .await
}

fn batch_update_shells_impl(
    state: &AppState,
    ids: &[String],
    tags: Option<Vec<String>>,
    password: Option<String>,
) -> Result<usize, String> {
    let mut updated = 0usize;
    let database = state.database.lock().map_err(|_| "数据库锁异常".to_string())?;
    for id in ids {
        if let Ok(Some(shell)) = database.shell(id) {
            let input = UpdateShell {
                id: id.clone(),
                name: shell.name.clone(),
                endpoint: shell.endpoint.clone(),
                password: password.clone().or(Some(shell.password)),
                tags: tags.clone().or(Some(shell.tags)),
            };
            if database.update_shell(&input).is_ok() {
                updated += 1;
            }
        }
    }
    Ok(updated)
}

/// Repeater：手工构造并发送一次 HTTP 请求（不经协议，仅走传输层）。
#[tauri::command]
pub async fn http_send(
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
    app: AppHandle,
) -> Result<HttpSendResult, String> {
    blocking(app, move |state| {
        parse_endpoint(&url)?;
        let settings = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .get_settings()
            .map_err(|error| error.to_string())?;
        if !settings.http_enabled {
            return Err("真实网络协议尚未在「设置」中开启授权声明".to_string());
        }
        let client = crate::protocol::transport::build_client(&settings);
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| format!("不支持的请求方法：{method}"))?;
        let mut request = client.request(method, &url);
        for (name, value) in &headers {
            if !name.trim().is_empty() {
                request = request.header(name.trim(), value);
            }
        }
        if !body.is_empty()
            && !headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
        {
            request = request.header("Content-Type", "application/x-www-form-urlencoded");
        }
        let start = std::time::Instant::now();
        let response = request
            .body(body)
            .send()
            .map_err(|error| format!("请求失败：{error}"))?;
        let status = response.status();
        let status_text = status.canonical_reason().unwrap_or("").to_string();
        let resp_headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or("?").to_string(),
                )
            })
            .collect();
        let resp_body = response
            .text()
            .unwrap_or_else(|_| "（响应体读取失败）".to_string());
        Ok(HttpSendResult {
            status: status.as_u16(),
            status_text,
            headers: resp_headers,
            body: resp_body,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    })
    .await
}

#[tauri::command]
pub fn list_plugins(state: State<'_, AppState>) -> Vec<PluginManifest> {
    state.protocols.plugin_manifests()
}

#[tauri::command]
pub async fn get_settings(app: AppHandle) -> Result<AppSettings, String> {
    blocking(app, move |state| {
        state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .get_settings()
            .map_err(|error| error.to_string())
    })
    .await
}

#[tauri::command]
pub async fn update_settings(input: AppSettings, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        let previous = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .get_settings()
            .map_err(|error| error.to_string())?;
        state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .update_settings(&input)
            .map_err(|error| error.to_string())?;
        // 网络开关状态变化记入审计（系统级事件，无 Workspace 归属）
        if previous.http_enabled != input.http_enabled {
            let detail = if input.http_enabled {
                "真实网络协议已启用（授权声明已确认）".to_string()
            } else {
                "真实网络协议已关闭".to_string()
            };
            audit(state, "system", None, "settings.update", "success", &detail);
        }
        Ok(())
    })
    .await
}

// --- 会话 ---

#[tauri::command]
pub async fn connect_shell(shell_id: String, app: AppHandle) -> Result<ConnectResult, String> {
    blocking(app, move |state| {
        let (shell, settings) = load_shell_and_settings(state, &shell_id)?;
        let _auth_reason = require_authorized_for(state, &shell, &settings)?;

        let protocol = state
            .protocols
            .get(&shell.protocol_id)
            .ok_or_else(|| format!("未知协议：{}", shell.protocol_id))?;

        let (session_state, probe) = protocol
            .connect(&shell, &settings)
            .map_err(|error| audit_fail(state, &shell, "shell.connect", error))?;

        let session_id = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?
            .insert(
                &shell.id,
                &shell.workspace_id,
                &shell.protocol_id,
                Arc::from(session_state),
                probe.clone(),
            );

        // 连接成功刷新在线状态
        let _ = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())
            .and_then(|database| {
                database
                    .record_probe(&shell, "online", "连接成功")
                    .map_err(|error| error.to_string())
            });
        audit(state, &shell.workspace_id, Some(&shell.id), "shell.connect", "success", &format!("连接成功：{}", shell.endpoint));

        Ok(ConnectResult::from_probe(session_id, probe))
    })
    .await
}

#[tauri::command]
pub async fn disconnect_shell(session_id: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        if let Some(session) = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?
            .remove(&session_id)
        {
            audit(
                state,
                &session.workspace_id,
                Some(&session.profile_id),
                "shell.disconnect",
                "success",
                "断开连接",
            );
        }
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn list_sessions(app: AppHandle) -> Result<Vec<SessionInfo>, String> {
    blocking(app, move |state| {
        let sessions = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?;
        Ok(sessions
            .list()
            .into_iter()
            .map(|(session_id, profile_id, server, last_used_at)| SessionInfo {
                session_id,
                profile_id,
                server,
                last_used_at,
            })
            .collect())
    })
    .await
}

// --- 命令执行与文件操作 ---
//
// 统一模式：锁内取出会话 + Shell + 设置，并做授权轻量复查；锁外执行网络调用；
// 最后锁内写审计。

/// 会话命令上下文：会话、所属 Shell 与全局设置（已通过授权复查）。
struct SessionCtx<'a> {
    workspace_id: String,
    shell: ShellProfile,
    settings: AppSettings,
    protocol: &'a dyn Protocol,
}

/// 从会话 ID 解析出会话命令上下文。
/// 锁内完成：会话取出 → Shell 查询 → 授权轻量复查（仅过期检查）→ 协议解析。
fn session_ctx<'a>(state: &'a AppState, session_id: &str) -> Result<SessionCtx<'a>, String> {
    let (profile_id, protocol_id) = {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?;
        let session = sessions.get_mut(session_id)?;
        (session.profile_id.clone(), session.protocol_id.clone())
    };

    let database = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?;
    let shell = database
        .shell(&profile_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Shell 配置不存在".to_string())?;
    auth::require_session_alive(&database, &shell)?;
    let settings = database.get_settings().map_err(|error| error.to_string())?;
    drop(database);

    let protocol = state
        .protocols
        .get(&protocol_id)
        .ok_or_else(|| format!("未知协议：{protocol_id}"))?;

    Ok(SessionCtx {
        workspace_id: shell.workspace_id.clone(),
        shell,
        settings,
        protocol,
    })
}

/// 短锁取出会话的协议状态（`Arc` 克隆），在锁外执行 `f`。
/// 网络调用不持有全局会话锁：单个慢请求不再阻塞其他会话。
fn with_session<T>(
    state: &AppState,
    session_id: &str,
    f: impl FnOnce(&dyn SessionState) -> Result<T, ProtocolError>,
) -> Result<T, String> {
    let session = {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?;
        let session = sessions.get_mut(session_id)?;
        session.state.clone()
    };
    f(session.as_ref()).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn execute_command(
    session_id: String,
    command: String,
    app: AppHandle,
) -> Result<CommandOutput, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        let output = with_session(state, &session_id, |session| {
            ctx.protocol.execute_command(session, &command, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "shell.exec", "error", &error);
            error
        })?;
        audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "shell.exec", "success", &format!("执行命令：{command}"));
        Ok(output)
    })
    .await
}

#[tauri::command]
pub async fn list_dir(
    session_id: String,
    path: String,
    app: AppHandle,
) -> Result<DirListing, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        let listing = with_session(state, &session_id, |session| {
            ctx.protocol.list_dir(session, &path, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.list", "error", &error);
            error
        })?;
        audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.list", "success", &format!("浏览目录：{path}"));
        Ok(listing)
    })
    .await
}

#[tauri::command]
pub async fn read_file(
    session_id: String,
    path: String,
    app: AppHandle,
) -> Result<FileContent, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        let bytes = with_session(state, &session_id, |session| {
            ctx.protocol.read_file(session, &path, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.read", "error", &error);
            error
        })?;
        let content_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let name = path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&path)
            .to_string();
        audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.read", "success", &format!("读取文件：{path}"));
        Ok(FileContent {
            name,
            size: bytes.len() as u64,
            content_b64,
        })
    })
    .await
}

#[tauri::command]
pub async fn write_file(
    session_id: String,
    path: String,
    content_b64: String,
    app: AppHandle,
) -> Result<(), String> {
    blocking(app, move |state| {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&content_b64)
            .map_err(|_| "文件内容不是合法 Base64".to_string())?;
        let ctx = session_ctx(state, &session_id)?;
        with_session(state, &session_id, |session| {
            ctx.protocol.write_file(session, &path, &bytes, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.write", "error", &error);
            error
        })?;
        audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.write", "success", &format!("写入文件：{path}（{} 字节）", bytes.len()));
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn upload_file(
    session_id: String,
    remote_path: String,
    content_b64: String,
    app: AppHandle,
) -> Result<(), String> {
    blocking(app, move |state| {
        // 上传复用写入通道，审计动作修正为 file.upload
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&content_b64)
            .map_err(|_| "文件内容不是合法 Base64".to_string())?;
        let ctx = session_ctx(state, &session_id)?;
        with_session(state, &session_id, |session| {
            ctx.protocol.write_file(session, &remote_path, &bytes, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.upload", "error", &error);
            error
        })?;
        audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.upload", "success", &format!("上传文件：{remote_path}（{} 字节）", bytes.len()));
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn write_chunk(
    session_id: String,
    path: String,
    content_b64: String,
    offset: u64,
    app: AppHandle,
) -> Result<(), String> {
    blocking(app, move |state| {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&content_b64)
            .map_err(|_| "文件内容不是合法 Base64".to_string())?;
        let ctx = session_ctx(state, &session_id)?;
        with_session(state, &session_id, |session| {
            ctx.protocol.write_chunk(session, &path, &bytes, offset, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.write", "error", &error);
            error
        })?;
        audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.write", "success", &format!("写入文件：{path}（偏移 {offset}，{} 字节）", bytes.len()));
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn download_file(
    session_id: String,
    remote_path: String,
    local_path: String,
    app: AppHandle,
) -> Result<u64, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        // 分块拉取（每块 4MB），避免大文件一次性占用内存与超时
        const CHUNK: u64 = 4 * 1024 * 1024;
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            let chunk = with_session(state, &session_id, |session| {
                ctx.protocol
                    .read_chunk(session, &remote_path, bytes.len() as u64, CHUNK, &ctx.settings)
            })
            .map_err(|error| {
                audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.download", "error", &error);
                error
            })?;
            if chunk.is_empty() {
                break;
            }
            bytes.extend_from_slice(&chunk);
            if (chunk.len() as u64) < CHUNK {
                break;
            }
        }
        std::fs::write(&local_path, &bytes)
            .map_err(|error| format!("写入本地文件失败：{error}"))?;
        audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.download", "success", &format!("下载文件：{remote_path} → {local_path}（{} 字节）", bytes.len()));
        Ok(bytes.len() as u64)
    })
    .await
}

#[tauri::command]
pub async fn delete_path(
    session_id: String,
    path: String,
    app: AppHandle,
) -> Result<(), String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        with_session(state, &session_id, |session| {
            ctx.protocol.delete_path(session, &path, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.delete", "error", &error);
            error
        })?;
        audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.delete", "success", &format!("删除：{path}"));
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn rename_path(
    session_id: String,
    from: String,
    to: String,
    app: AppHandle,
) -> Result<(), String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        with_session(state, &session_id, |session| {
            ctx.protocol.rename_path(session, &from, &to, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.rename", "error", &error);
            error
        })?;
        audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.rename", "success", &format!("重命名：{from} → {to}"));
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn create_dir(
    session_id: String,
    path: String,
    app: AppHandle,
) -> Result<(), String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        with_session(state, &session_id, |session| {
            ctx.protocol.create_dir(session, &path, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.mkdir", "error", &error);
            error
        })?;
        audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "file.mkdir", "success", &format!("新建目录：{path}"));
        Ok(())
    })
    .await
}

// --- 数据库管理 ---

#[tauri::command]
pub async fn list_request_log(
    endpoint: Option<String>,
    app: AppHandle,
) -> Result<Vec<RequestRecord>, String> {
    blocking(app, move |_state| {
        Ok(crate::protocol::php::list_requests(endpoint.as_deref()))
    })
    .await
}

#[tauri::command]
pub async fn clear_request_log(app: AppHandle) -> Result<(), String> {
    blocking(app, move |_state| {
        crate::protocol::php::clear_requests();
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn db_probe(
    session_id: String,
    connection: DbConnection,
    app: AppHandle,
) -> Result<DbProbeResult, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        let result = with_session(state, &session_id, |session| {
            ctx.protocol.db_probe(session, &connection, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "db.probe", "error", &error);
            error
        })?;
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "db.probe",
            "success",
            &format!("探测数据库：{}@{}（{} 个库）", connection.driver, connection.host.as_deref().unwrap_or("localhost"), result.databases.len()),
        );
        Ok(result)
    })
    .await
}

#[tauri::command]
pub async fn db_query(
    session_id: String,
    connection: DbConnection,
    sql: String,
    app: AppHandle,
) -> Result<DbQueryResult, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        let result = with_session(state, &session_id, |session| {
            ctx.protocol.db_query(session, &connection, &sql, &ctx.settings)
        })
        .map_err(|error| {
            audit(state, &ctx.workspace_id, Some(&ctx.shell.id), "db.query", "error", &error);
            error
        })?;
        let sql_preview: String = sql.chars().take(120).collect();
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "db.query",
            "success",
            &format!("数据库查询（{}）：{}", connection.driver, sql_preview),
        );
        Ok(result)
    })
    .await
}

// ---------------------------------------------------------------------------
// 命令层测试：直接构造 AppState（内存库 + 会话管理器 + 内置协议），
// 验证统一流程：会话上下文解析、授权门、锁外执行。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use dosword_sdk::domain::{CreateShell, CreateWorkspace};
    use crate::protocol::{MOCK_PROTOCOL_ID, ProtocolRegistry};
    use crate::session::SessionManager;
    use crate::storage::Database;
    use std::sync::Mutex;

    fn app_state() -> AppState {
        AppState {
            database: Mutex::new(Database::open(":memory:").unwrap()),
            sessions: Mutex::new(SessionManager::new()),
            protocols: ProtocolRegistry::builtin(),
            feature_plugins: dosword_sdk::FeaturePluginRegistry::builtin(),
        }
    }

    fn add_workspace(db: &mut Database, scope: &str, expires_at: Option<String>) -> String {
        db.create_workspace(CreateWorkspace {
            name: "Lab".into(),
            authorization_scope: scope.into(),
            expires_at,
        })
        .unwrap()
        .id
    }

    fn add_shell(state: &AppState, workspace_id: &str, protocol_id: &str) -> ShellProfile {
        state
            .database
            .lock()
            .unwrap()
            .create_shell(
                CreateShell {
                    workspace_id: workspace_id.into(),
                    name: "t".into(),
                    endpoint: "mock://local".into(),
                    runtime: "php".into(),
                    protocol_id: protocol_id.into(),
                    password: Some("secret".into()),
                    protocol_params: None,
                    confirm_network: false,
                    tags: None,
                },
                protocol_id,
            )
            .unwrap()
    }

    #[test]
    fn test_connection_mock_protocol_ok() {
        let state = app_state();
        let result = test_connection_impl(
            &state,
            "mock://local",
            "secret",
            MOCK_PROTOCOL_ID,
            None,
            None,
        );
        assert!(result.is_ok(), "mock 协议探测应成功：{result:?}");
        assert_eq!(result.unwrap().status, "online");
    }

    #[test]
    fn test_connection_unknown_protocol_rejected() {
        let state = app_state();
        let result = test_connection_impl(
            &state,
            "mock://local",
            "secret",
            "unknown.v1",
            None,
            None,
        );
        assert!(result.is_err(), "未知协议应报错");
        assert!(result.unwrap_err().contains("未知协议"));
    }

    #[test]
    fn test_connection_invalid_endpoint_rejected() {
        let state = app_state();
        let result = test_connection_impl(
            &state,
            "not-a-url",
            "secret",
            MOCK_PROTOCOL_ID,
            None,
            None,
        );
        assert!(result.is_err(), "非法 URL 应报错");
    }

    #[test]
    fn export_shells_returns_json_array() {
        let state = app_state();
        let wid = add_workspace(&mut state.database.lock().unwrap(), "scope-a", None);
        add_shell(&state, &wid, MOCK_PROTOCOL_ID);
        let json = export_shells_impl(&state).unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(items.len(), 1);
        assert!(items[0]["endpoint"].as_str().is_some());
    }

    #[test]
    fn import_shells_dedupes_endpoint() {
        let state = app_state();
        let wid = add_workspace(&mut state.database.lock().unwrap(), "scope-a", None);
        add_shell(&state, &wid, MOCK_PROTOCOL_ID);
        let payload = serde_json::json!([
            {
                "name": "dup",
                "endpoint": "mock://local",
                "runtime": "php",
                "protocol_id": MOCK_PROTOCOL_ID,
                "password": "x",
                "protocol_params": "{}",
                "tags": []
            },
            {
                "name": "new",
                "endpoint": "mock://remote",
                "runtime": "php",
                "protocol_id": MOCK_PROTOCOL_ID,
                "password": "y",
                "protocol_params": "{}",
                "tags": ["t"]
            },
            {
                "name": "bad",
                "endpoint": "mock://bad",
                "runtime": "php",
                "protocol_id": "unknown.v1",
                "password": "z",
                "protocol_params": "{}",
                "tags": []
            }
        ]);
        let result = import_shells_impl(&state, &payload.to_string(), &wid).unwrap();
        assert_eq!(result.imported, 1, "仅有效且不重复的应导入");
        assert_eq!(result.skipped, 2, "重复 endpoint 与未知协议应跳过");
    }

    #[test]
    fn batch_update_shells_sets_tags() {
        let state = app_state();
        let wid = add_workspace(&mut state.database.lock().unwrap(), "scope-a", None);
        let shell = add_shell(&state, &wid, MOCK_PROTOCOL_ID);
        let count = batch_update_shells_impl(&state, &[shell.id.clone()], Some(vec!["prod".to_string()]), None).unwrap();
        assert_eq!(count, 1);
        let updated = state.database.lock().unwrap().shell(&shell.id).unwrap().unwrap();
        assert_eq!(updated.tags, vec!["prod"]);
    }

    fn register_session(state: &AppState, shell: &ShellProfile) -> String {
        let protocol = state.protocols.get(&shell.protocol_id).unwrap();
        let settings = state
            .database
            .lock()
            .unwrap()
            .get_settings()
            .unwrap();
        let (session, probe) = protocol.connect(shell, &settings).unwrap();
        state
            .sessions
            .lock()
            .unwrap()
            .insert(
                &shell.id,
                &shell.workspace_id,
                &shell.protocol_id,
                Arc::from(session),
                probe,
            )
    }

    #[test]
    fn with_session_runs_outside_lock() {
        let state = app_state();
        let workspace_id = add_workspace(&mut state.database.lock().unwrap(), "localhost", None);
        let shell = add_shell(&state, &workspace_id, MOCK_PROTOCOL_ID);
        let session_id = register_session(&state, &shell);

        // f 在会话锁释放后执行（锁内仅取出 Arc 克隆）
        let result = with_session(&state, &session_id, |_session| Ok(42u8));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn with_session_missing_is_rejected() {
        let state = app_state();
        let result = with_session(&state, "s0", |_| Ok(()));
        assert!(result.is_err(), "不存在的会话应报错");
        assert!(result.unwrap_err().contains("会话不存在"));
    }

    #[test]
    fn session_ctx_resolves_shell_and_settings() {
        let state = app_state();
        let workspace_id = add_workspace(&mut state.database.lock().unwrap(), "localhost", None);
        let shell = add_shell(&state, &workspace_id, MOCK_PROTOCOL_ID);
        let session_id = register_session(&state, &shell);

        let ctx = session_ctx(&state, &session_id).expect("上下文解析应成功");
        assert_eq!(ctx.shell.id, shell.id);
        assert_eq!(ctx.workspace_id, workspace_id);
        assert_eq!(ctx.protocol.id(), MOCK_PROTOCOL_ID);
    }

    #[test]
    fn session_ctx_rejects_expired_workspace() {
        let state = app_state();
        let workspace_id = add_workspace(
            &mut state.database.lock().unwrap(),
            "localhost",
            Some("2000-01-01T00:00:00+08:00".into()),
        );
        let shell = add_shell(&state, &workspace_id, MOCK_PROTOCOL_ID);
        let session_id = register_session(&state, &shell);

        match session_ctx(&state, &session_id) {
            Err(message) => assert!(message.contains("过期"), "应提示过期：{message}"),
            Ok(_) => panic!("过期 Workspace 应禁止会话操作"),
        }
    }

    #[test]
    fn require_authorized_for_gates_real_network() {
        let state = app_state();
        let workspace_id = add_workspace(&mut state.database.lock().unwrap(), "localhost", None);
        let shell = add_shell(&state, &workspace_id, "builtin.php.v1");
        let settings = AppSettings { http_enabled: false, ..AppSettings::default() };

        // 网络协议 + 全局开关关闭 → 拒绝
        let result = require_authorized_for(&state, &shell, &settings);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("真实网络协议未启用"));

        // Mock 协议 → 直接放行
        let shell_mock = add_shell(&state, &workspace_id, MOCK_PROTOCOL_ID);
        let result = require_authorized_for(&state, &shell_mock, &settings);
        assert!(result.is_ok());
    }

    #[test]
    fn require_authorized_for_checks_scope() {
        let state = app_state();
        let workspace_id = add_workspace(&mut state.database.lock().unwrap(), "other.example", None);
        let shell = add_shell(&state, &workspace_id, "builtin.php.v1");
        // PHP 协议 shell 端点不在授权范围内，即使开关开启也会被拒绝
        let settings = AppSettings { http_enabled: true, ..AppSettings::default() };
        let result = require_authorized_for(&state, &shell, &settings);
        assert!(result.is_err(), "越界端点应被拒绝");
        assert!(result.unwrap_err().contains("授权范围"));
    }

    #[test]
    fn load_shell_and_settings_missing_shell() {
        let state = app_state();
        let result = load_shell_and_settings(&state, "nope");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("不存在"));
    }
}
