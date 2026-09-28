use base64::Engine;
use std::io::Write;
use std::sync::Arc;
use tauri::{AppHandle, Manager, State};
use url::Url;

use dosword_sdk::domain::{
    AppSettings, AuditFilter, AuditPage, CommandOutput, ConnectResult, CreateShell,
    CreateWorkspace, Dashboard, DbConnection, DbProbeResult, DbQueryResult, DirListing,
    FileContent, GenerateShellResult, HttpSendResult, ImportResult, ProbeResult, ProtocolMeta,
    RequestRecord, SessionInfo, ShellProfile, UpdateShell, UpdateWorkspace, Workspace,
};
use dosword_sdk::encoder::{EncoderRegistry, STUB_LANGUAGES};
use dosword_sdk::plugin::FeaturePlugin;
use dosword_sdk::{PluginManifest, Protocol, ProtocolError, SessionState};

use crate::AppState;
use crate::auth;

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
fn load_shell_and_settings(
    state: &AppState,
    shell_id: &str,
) -> Result<(ShellProfile, AppSettings), String> {
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
    audit(
        state,
        &shell.workspace_id,
        Some(&shell.id),
        action,
        "error",
        &message,
    );
    message
}

/// 对真实网络协议做完整授权检查；Mock 协议直接放行。
/// 返回校验方式说明（供审计追溯）。
fn require_authorized_for(
    state: &AppState,
    shell: &ShellProfile,
    settings: &AppSettings,
) -> Result<String, String> {
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
pub async fn create_workspace(input: CreateWorkspace, app: AppHandle) -> Result<Workspace, String> {
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
pub async fn create_shell(input: CreateShell, app: AppHandle) -> Result<ShellProfile, String> {
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
            &format!(
                "登记 Shell：{}（协议 {}）",
                profile.endpoint, profile.protocol_id
            ),
        );
        Ok(profile)
    })
    .await
}

#[tauri::command]
pub async fn update_workspace(input: UpdateWorkspace, app: AppHandle) -> Result<Workspace, String> {
    blocking(app, move |state| {
        validate_text(&input.name, "名称")?;
        validate_text(&input.authorization_scope, "授权范围")?;
        let (workspace, scope_changed) = {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            let previous = database
                .workspace(&input.id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| "Workspace 不存在".to_string())?;
            let updated = database
                .update_workspace(&input)
                .map_err(|error| error.to_string())?;
            let changed = previous.authorization_scope != updated.authorization_scope;
            (updated, changed)
        };
        // S7：授权范围收窄后，该 Workspace 的活跃会话全部失效（断开 + 级联清理 PTY）
        if scope_changed {
            let removed = state
                .sessions
                .lock()
                .map_err(|_| "会话锁异常".to_string())?
                .remove_by_workspace(&workspace.id);
            for session_id in removed {
                state.ptys.close_for_session(&session_id);
            }
        } else if let Ok(mut sessions) = state.sessions.lock() {
            // 仅过期时间变化：失效快照（下次复查回退查库）
            sessions.invalidate_workspace_expiry(&workspace.id);
        }
        audit(
            state,
            &workspace.id,
            None,
            "workspace.update",
            "success",
            &format!(
                "更新 Workspace：{}（范围 {}）",
                workspace.name, workspace.authorization_scope
            ),
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
        // 清理该 Workspace 下的全部活跃会话（级联清理 PTY 流）
        let removed = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?
            .remove_by_workspace(&workspace_id);
        for session_id in removed {
            state.ptys.close_for_session(&session_id);
        }
        audit(
            state,
            &workspace_id,
            None,
            "workspace.delete",
            "success",
            &format!("删除 Workspace：{name}"),
        );
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
                let (allowed, _reason) =
                    auth::scope_allows(&workspace.authorization_scope, &endpoint);
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
        // P6：更新后失效会话上下文缓存（下次使用重查）
        if let Ok(mut sessions) = state.sessions.lock() {
            sessions.invalidate_context(&profile.id);
        }
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
        // 清理该 Shell 的活跃会话（级联清理 PTY 流）
        let removed = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?
            .remove_by_profile(&shell_id);
        for session_id in removed {
            state.ptys.close_for_session(&session_id);
        }
        audit(
            state,
            &workspace_id,
            None,
            "shell.delete",
            "success",
            &format!("删除 Shell：{endpoint}"),
        );
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
        test_connection_impl(
            state,
            &endpoint,
            &password,
            &protocol_id,
            protocol_params.as_deref(),
            runtime.as_deref(),
        )
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
                .and_then(|mut database| {
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
        audit(
            state,
            &shell.workspace_id,
            Some(&shell.id),
            "shell.probe",
            "success",
            &result.message,
        );
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

/// 自动备份：导出全部 Shell 配置到指定目录（带时间戳文件名），返回备份文件路径。
#[tauri::command]
pub async fn backup_shells(backup_dir: String, app: AppHandle) -> Result<String, String> {
    blocking(app, move |state| backup_shells_impl(state, &backup_dir)).await
}

fn backup_shells_impl(state: &AppState, backup_dir: &str) -> Result<String, String> {
    let json = export_shells_impl(state)?;
    let dir = std::path::Path::new(backup_dir);
    std::fs::create_dir_all(dir).map_err(|error| format!("备份目录创建失败：{error}"))?;
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let file = dir.join(format!("dosword-backup-{stamp}.json"));
    std::fs::write(&file, &json).map_err(|error| format!("备份写入失败：{error}"))?;
    Ok(file.to_string_lossy().into_owned())
}

/// 按编码把文本编码为字节（GBK 等浏览器 TextEncoder 不支持的编码）。
#[tauri::command]
pub async fn encode_text(text: String, encoding: String, app: AppHandle) -> Result<String, String> {
    blocking(app, move |_state| encode_text_impl(&text, &encoding)).await
}

fn encode_text_impl(text: &str, encoding: &str) -> Result<String, String> {
    let (bytes, _, had_errors) = match encoding {
        "gbk" => encoding_rs::GBK.encode(text),
        "big5" => encoding_rs::BIG5.encode(text),
        other => return Err(format!("不支持的编码：{other}（支持 gbk / big5）")),
    };
    if had_errors {
        return Err("文本包含无法用该编码表示的字符".to_string());
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
}

/// 读取本地文件（Shell 导入用）。
#[tauri::command]
/// S4：本地路径安全校验——规范化并拒绝敏感系统目录（防止被攻破的前端读写任意本地文件）。
fn sanitize_local_path(path: &str, for_write: bool) -> Result<std::path::PathBuf, String> {
    let deny = [
        "/etc", "/proc", "/sys", "/root", "/boot", "/dev", "/var/lib", "/usr",
    ];
    if for_write {
        let p = std::path::Path::new(path);
        let parent = p.parent().ok_or_else(|| "路径缺少父目录".to_string())?;
        let canon_parent =
            std::fs::canonicalize(parent).map_err(|error| format!("路径无效：{error}"))?;
        for prefix in deny {
            if canon_parent.starts_with(prefix) {
                return Err(format!("拒绝访问敏感目录：{prefix}"));
            }
        }
        Ok(canon_parent.join(p.file_name().unwrap_or_default()))
    } else {
        let canonical =
            std::fs::canonicalize(path).map_err(|error| format!("路径无效：{error}"))?;
        for prefix in deny {
            if canonical.starts_with(prefix) {
                return Err(format!("拒绝访问敏感目录：{prefix}"));
            }
        }
        Ok(canonical)
    }
}

#[tauri::command]
pub async fn read_local_file(path: String, app: AppHandle) -> Result<String, String> {
    blocking(app, move |_state| {
        let safe = sanitize_local_path(&path, false)?;
        std::fs::read(&safe)
            .map_err(|error| format!("读取本地文件失败：{error}"))
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
    })
    .await
}

/// 导出全部 Shell 配置（JSON 数组，含密码——请妥善保管导出文件）。
#[tauri::command]
pub fn export_shells(state: State<'_, AppState>) -> Result<String, String> {
    export_shells_impl(&state)
}

fn export_shells_impl(state: &AppState) -> Result<String, String> {
    let database = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?;
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
        import_shells_impl(state, &payload, &workspace_id)
    })
    .await
}

fn import_shells_impl(
    state: &AppState,
    payload: &str,
    workspace_id: &str,
) -> Result<ImportResult, String> {
    {
        let items: Vec<serde_json::Value> = serde_json::from_str(payload)
            .map_err(|error| format!("导入文件不是合法 JSON：{error}"))?;
        let mut imported = 0usize;
        let mut skipped = 0usize;
        let mut database = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?;
        let workspace = database
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
            let endpoint = item
                .get("endpoint")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
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
            // S2：真实网络协议的导入项同样受授权范围约束（与 create_shell 门一致）
            let protocol = state.protocols.get(&protocol_id).expect("已确认协议存在");
            if protocol.requires_network() {
                let parsed = match url::Url::parse(&endpoint) {
                    Ok(parsed) => parsed,
                    Err(_) => {
                        skipped += 1;
                        continue;
                    }
                };
                let (allowed, _reason) =
                    auth::scope_allows(&workspace.authorization_scope, &parsed);
                if !allowed {
                    skipped += 1;
                    continue;
                }
            }
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
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
                name: if name.trim().is_empty() {
                    endpoint.clone()
                } else {
                    name
                },
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
pub async fn write_local_file(
    path: String,
    content_b64: String,
    app: AppHandle,
) -> Result<(), String> {
    blocking(app, move |_state| {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&content_b64)
            .map_err(|_| "内容不是合法 Base64".to_string())?;
        let safe = sanitize_local_path(&path, true)?;
        std::fs::write(&safe, &bytes).map_err(|error| format!("写入本地文件失败：{error}"))
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
    state
        .feature_plugins
        .lock()
        .map(|registry| registry.list())
        .unwrap_or_default()
}

/// 安装二进制 .plugin（Rust cdylib）：复制到数据目录并动态加载注册。
#[tauri::command]
pub async fn install_native_plugin(source_path: String, app: AppHandle) -> Result<(), String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let plugins_dir = data_dir.join("plugins");
    std::fs::create_dir_all(&plugins_dir).map_err(|error| error.to_string())?;
    // 先加载校验（含 manifest id），再落盘
    let plugin =
        crate::native_plugin::NativeFeaturePlugin::load(std::path::Path::new(&source_path))?;
    let id = plugin.abi_manifest()?.id.clone();
    dosword_sdk::validate_plugin_id(&id).map_err(|error| format!("插件 id 非法：{error}"))?;
    let ext = std::path::Path::new(&source_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("so")
        .to_string();
    let target = plugins_dir.join(format!("{id}.native.{ext}"));
    std::fs::copy(&source_path, &target).map_err(|error| format!("插件文件复制失败：{error}"))?;
    blocking(app, move |state| {
        let mut registry = state
            .feature_plugins
            .lock()
            .map_err(|_| "插件注册表锁异常".to_string())?;
        registry
            .register(Box::new(plugin))
            .map_err(|error| format!("注册失败：{error}"))?;
        registry.installed.insert(id);
        Ok(())
    })
    .await
}

/// 安装外部 .plugin 插件（JSON 清单 + 执行定义），持久化到数据目录。
#[tauri::command]
pub async fn install_plugin(content: String, app: AppHandle) -> Result<(), String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    blocking(app, move |state| {
        let plugin = dosword_sdk::ScriptFeaturePlugin::from_json(&content)?;
        let id = plugin.manifest().id.clone();
        let plugins_dir = data_dir.join("plugins");
        std::fs::create_dir_all(&plugins_dir).map_err(|error| error.to_string())?;
        std::fs::write(plugins_dir.join(format!("{id}.plugin")), &content)
            .map_err(|error| format!("插件文件写入失败：{error}"))?;
        let mut registry = state
            .feature_plugins
            .lock()
            .map_err(|_| "插件注册表锁异常".to_string())?;
        registry
            .register(Box::new(plugin))
            .map_err(|error| format!("注册失败：{error}"))?;
        registry.installed.insert(id);
        Ok(())
    })
    .await
}

/// 卸载外部插件（删除注册与数据目录文件）。
#[tauri::command]
pub async fn uninstall_plugin(plugin_id: String, app: AppHandle) -> Result<(), String> {
    // plugin_id 由前端直接传入，且下面会拼进文件路径，必须先校验（防路径穿越）
    dosword_sdk::validate_plugin_id(&plugin_id)?;
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    blocking(app, move |state| {
        let _ = std::fs::remove_file(data_dir.join("plugins").join(format!("{plugin_id}.plugin")));
        if let Ok(entries) = std::fs::read_dir(data_dir.join("plugins")) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name == format!("{plugin_id}.plugin")
                    || name.starts_with(&format!("{plugin_id}.native."))
                {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        let mut registry = state
            .feature_plugins
            .lock()
            .map_err(|_| "插件注册表锁异常".to_string())?;
        registry.unregister(&plugin_id);
        Ok(())
    })
    .await
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
            let mut sessions = state
                .sessions
                .lock()
                .map_err(|_| "会话锁异常".to_string())?;
            let session = sessions
                .get_mut(&session_id)
                .map_err(|error| error.to_string())?;
            let runtime = {
                let database = state
                    .database
                    .lock()
                    .map_err(|_| "数据库锁异常".to_string())?;
                database
                    .shell(&session.profile_id)
                    .map_err(|error| error.to_string())?
                    .map(|shell| shell.runtime)
                    .unwrap_or_else(|| "php".to_string())
            };
            (session.state.clone(), session.protocol_id.clone(), runtime)
        };
        let protocol = state
            .protocols
            .get(&protocol_id)
            .ok_or_else(|| format!("未知协议：{protocol_id}"))?;
        let plugin = {
            let registry_guard = state
                .feature_plugins
                .lock()
                .map_err(|_| "插件注册表锁异常".to_string())?;
            registry_guard
                .get(&plugin_id)
                .ok_or_else(|| format!("未知功能插件：{plugin_id}"))?
                .clone()
        };
        let settings = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .get_settings()
            .map_err(|error| error.to_string())?;
        let output = plugin
            .execute(protocol, session.as_ref(), &runtime, &params, &settings)
            .map_err(|error| format!("插件执行失败：{error}"))?;
        // S9：插件执行审计（含参数摘要，不含代码体）
        let summary: String = params
            .as_object()
            .map(|obj| {
                obj.iter()
                    .map(|(key, value)| {
                        let text = match value {
                            serde_json::Value::String(s) => {
                                if s.len() > 64 {
                                    format!("{}…", &s[..64])
                                } else {
                                    s.clone()
                                }
                            }
                            other => other.to_string(),
                        };
                        format!("{key}={text}")
                    })
                    .collect::<Vec<_>>()
                    .join("&")
            })
            .unwrap_or_default();
        if let Ok(mut sessions) = state.sessions.lock()
            && let Ok(session) = sessions.get_mut(&session_id)
        {
            let _ = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())
                .and_then(|database| {
                    database
                        .record_audit(
                            Some(&session.workspace_id),
                            Some(&session.profile_id),
                            "plugin.run",
                            "success",
                            &format!("插件：{plugin_id}（{summary}）"),
                        )
                        .map_err(|error| error.to_string())
                });
        }
        Ok(output)
    })
    .await
}

/// 刷新全部 Shell 状态（逐个探测，更新 status / last_connected_at），返回最新列表。
#[tauri::command]
pub async fn refresh_shell_status(app: AppHandle) -> Result<Vec<ShellProfile>, String> {
    blocking(app, move |state| {
        let (shells, settings) = {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            let shells = database.list_shells().map_err(|error| error.to_string())?;
            let settings = database.get_settings().map_err(|error| error.to_string())?;
            (shells, settings)
        };
        // S6：授权门——真实网络协议未启用或超出授权范围（scope 过滤）的 Shell 不探测
        if !settings.http_enabled {
            return Ok(shells);
        }
        let allowed: Vec<ShellProfile> = {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            shells
                .into_iter()
                .filter(|shell| {
                    let protocol = state.protocols.get(&shell.protocol_id);
                    match protocol {
                        Some(protocol) if protocol.requires_network() => {
                            auth::require_authorized(&database, shell).is_ok()
                        }
                        _ => true,
                    }
                })
                .collect()
        };
        // P6：并行探测（上限 8 并发，逐壳错误互不影响），避免 100 个 Shell 串行累加超时；
        // P3：全量探测复用同一 client（共享连接池），写回合并为单事务
        let shells = allowed;
        let workers = shells.len().clamp(1, 8);
        let results: Vec<(String, String)> = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for worker in 0..workers {
                let shells = &shells;
                let settings = &settings;
                handles.push(scope.spawn(move || {
                    let mut out = Vec::new();
                    let mut index = worker;
                    while index < shells.len() {
                        let shell = &shells[index];
                        let status = match state.protocols.get(&shell.protocol_id) {
                            Some(protocol) => match protocol.probe(shell, settings) {
                                Ok(_) => "online".to_string(),
                                Err(_) => "error".to_string(),
                            },
                            None => "error".to_string(),
                        };
                        out.push((shell.id.clone(), status));
                        index += workers;
                    }
                    out
                }));
            }
            handles
                .into_iter()
                .flat_map(|handle| handle.join().unwrap_or_default())
                .collect()
        });
        {
            let mut database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            database
                .batch_update_shell_status(&results)
                .map_err(|error| error.to_string())?;
        }
        let database = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?;
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
        batch_update_shells_impl(state, &ids, tags, password)
    })
    .await
}

fn batch_update_shells_impl(
    state: &AppState,
    ids: &[String],
    tags: Option<Vec<String>>,
    password: Option<String>,
) -> Result<usize, String> {
    let mut database = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?;
    database
        .batch_update_shells(ids, tags.as_ref(), password.as_deref())
        .map_err(|e| e.to_string())
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
        let method_str = method;
        let method = reqwest::Method::from_bytes(method_str.as_bytes())
            .map_err(|_| format!("不支持的请求方法：{method_str}"))?;
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
        let response = request.body(body).send().map_err(|error| {
            audit(
                state,
                "system",
                None,
                "http.send",
                "error",
                &format!("{method_str} {url}：{error}"),
            );
            format!("请求失败：{error}")
        })?;
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
        // S1：响应体受 max_file_size_mb 上限约束（避免超大响应撑爆内存）
        let bytes = response
            .bytes()
            .map_err(|error| format!("读取响应失败：{error}"))?;
        let max_bytes = settings.max_file_size_mb.saturating_mul(1024 * 1024) as usize;
        if bytes.len() > max_bytes {
            let detail = format!(
                "{method_str} {url}：响应超过大小上限（{}MB）",
                settings.max_file_size_mb
            );
            audit(state, "system", None, "http.send", "error", &detail);
            return Err(detail);
        }
        let resp_body = String::from_utf8_lossy(&bytes).into_owned();
        let duration_ms = start.elapsed().as_millis() as u64;
        audit(
            state,
            "system",
            None,
            "http.send",
            "success",
            &format!(
                "{method_str} {url} → HTTP {status}（{} 字节，{duration_ms}ms）",
                bytes.len()
            ),
        );
        Ok(HttpSendResult {
            status: status.as_u16(),
            status_text,
            headers: resp_headers,
            body: resp_body,
            duration_ms,
        })
    })
    .await
}

#[tauri::command]
pub fn list_plugins(state: State<'_, AppState>) -> Vec<PluginManifest> {
    state.protocols.plugin_manifests()
}

/// P16：高频微操作改同步 command（免 spawn_blocking 调度开销）。
#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Result<AppSettings, String> {
    state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?
        .get_settings()
        .map_err(|error| error.to_string())
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
        // P6：设置变更后失效全部会话上下文缓存
        if let Ok(mut sessions) = state.sessions.lock() {
            sessions.invalidate_context_all();
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

        let session_id = {
            let mut sessions = state
                .sessions
                .lock()
                .map_err(|_| "会话锁异常".to_string())?;
            // S8：同 Shell 重连替换旧会话前，级联清理其 PTY 流
            if let Some(old_session_id) = sessions.session_id_for_profile(&shell.id) {
                state.ptys.close_for_session(&old_session_id);
            }
            let session_id = sessions.insert(
                &shell.id,
                &shell.workspace_id,
                &shell.protocol_id,
                Arc::from(session_state),
                probe.clone(),
            );
            // P6：连接时缓存上下文（避免每命令重复查库）；P5：快照授权过期时间
            let expires_snapshot = {
                let database = state
                    .database
                    .lock()
                    .map_err(|_| "数据库锁异常".to_string())?;
                database
                    .workspace(&shell.workspace_id)
                    .ok()
                    .flatten()
                    .and_then(|workspace| workspace.expires_at)
            };
            if let Ok(session) = sessions.get_mut(&session_id) {
                session.profile = Some(shell.clone());
                session.settings = Some(settings.clone());
                session.workspace_expires_at = expires_snapshot;
            }
            session_id
        };

        // 连接成功刷新在线状态
        let _ = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())
            .and_then(|mut database| {
                database
                    .record_probe(&shell, "online", "连接成功")
                    .map_err(|error| error.to_string())
            });
        audit(
            state,
            &shell.workspace_id,
            Some(&shell.id),
            "shell.connect",
            "success",
            &format!("连接成功：{}", shell.endpoint),
        );

        Ok(ConnectResult::from_probe(session_id, probe))
    })
    .await
}

/// 建立交互式 PTY 会话：目标反弹回连后返回 ptyId（失败则报错，前端降级为命令模式）。
/// E3：注册自定义编码器 stub（自定义 stub + XOR 载荷，生成 Shell 时可选 "custom"）。
#[tauri::command]
pub async fn register_custom_encoder(stub: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        dosword_sdk::encoder::set_custom_stub(&stub).map_err(|error| error.to_string())?;
        audit(
            state,
            "system",
            None,
            "encoder.register",
            "success",
            "注册自定义编码器 stub",
        );
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn start_pty_session(
    session_id: String,
    app: AppHandle,
) -> Result<serde_json::Value, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        let (session, _) = {
            let mut sessions = state
                .sessions
                .lock()
                .map_err(|_| "会话锁异常".to_string())?;
            let shell = sessions
                .get(&session_id)
                .ok_or_else(|| "会话不存在或已过期，请重新连接".to_string())?;
            (shell.state.clone(), ())
        };
        // 1) 本地监听随机端口
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .map_err(|error| format!("PTY 监听绑定失败：{error}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| format!("PTY 监听设置失败：{error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("PTY 监听地址获取失败：{error}"))?
            .port();
        // 2) 目标执行 PTY 反弹载荷（后台模式）
        let protocol = state
            .protocols
            .get(&ctx.shell.protocol_id)
            .ok_or_else(|| format!("未知协议：{}", ctx.shell.protocol_id))?;
        // A2：运行时取自会话上下文（PHP 会话走 PHP 载荷，JSP 等协议按自身 run_code 通道）
        let runtime = if ctx.shell.runtime.is_empty() {
            "php"
        } else {
            &ctx.shell.runtime
        };
        let out = <dosword_sdk::feature_plugins::SuperTerminalPlugin as FeaturePlugin>::execute(
            &dosword_sdk::feature_plugins::SuperTerminalPlugin,
            protocol,
            session.as_ref(),
            runtime,
            &serde_json::json!({"host": "127.0.0.1", "port": port, "background": true}),
            &ctx.settings,
        )
        .map_err(|error| format!("PTY 反弹载荷执行失败：{error}"))?;
        if out.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(format!(
                "PTY 反弹未启动：{}",
                out.get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("未知错误")
            ));
        }
        // 3) 等待目标回连（最长 12 秒）
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let pty_id = state.ptys.insert(&session_id, stream);
                    // S9：PTY 会话建立审计
                    let _ = state
                        .database
                        .lock()
                        .map_err(|_| "会话锁异常".to_string())
                        .and_then(|database| {
                            database
                                .record_audit(
                                    None,
                                    Some(&session_id),
                                    "pty.start",
                                    "success",
                                    "建立交互式 PTY 会话",
                                )
                                .map_err(|error| error.to_string())
                        });
                    return Ok(serde_json::json!({ "ptyId": pty_id, "port": port }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() > deadline {
                        return Err(
                            "PTY 会话建立超时（目标未回连，可能缺少可执行命令通道）".to_string()
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(120));
                }
                Err(error) => return Err(format!("PTY 接受连接失败：{error}")),
            }
        }
    })
    .await
}

/// 向 PTY 会话写入数据（base64）。
#[tauri::command]
pub async fn pty_write(pty_id: String, data_b64: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|error| format!("PTY 输入解码失败：{error}"))?;
        state.ptys.write(&pty_id, &bytes)
    })
    .await
}

/// 非阻塞读取 PTY 输出（base64）。
#[tauri::command]
pub async fn pty_read(pty_id: String, app: AppHandle) -> Result<serde_json::Value, String> {
    blocking(app, move |state| match state.ptys.read(&pty_id) {
        Ok(bytes) => Ok(serde_json::json!({
            "data": base64::engine::general_purpose::STANDARD.encode(bytes),
            "closed": false,
        })),
        Err(error) => Ok(serde_json::json!({
            "data": "",
            "closed": true,
            "error": error,
        })),
    })
    .await
}

/// 关闭 PTY 会话。
#[tauri::command]
pub async fn pty_close(pty_id: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        state.ptys.close(&pty_id);
        Ok(())
    })
    .await
}

/// 读取活跃会话缓存的环境信息（供详情页从列表进入时补全连接信息）。
#[tauri::command]
pub async fn get_session_probe(session_id: String, app: AppHandle) -> Result<ProbeResult, String> {
    blocking(app, move |state| {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?;
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| "会话不存在或已过期".to_string())?;
        Ok(session.info.clone())
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
            // F2：断开会话时级联清理其全部 PTY 流
            state.ptys.close_for_session(&session_id);
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
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?;
        Ok(sessions
            .list()
            .into_iter()
            .map(
                |(session_id, profile_id, server, last_used_at)| SessionInfo {
                    session_id,
                    profile_id,
                    server,
                    last_used_at,
                },
            )
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
    let (profile_id, protocol_id, cached_profile, cached_settings, cached_workspace_expires) = {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?;
        let session = sessions.get_mut(session_id)?;
        (
            session.profile_id.clone(),
            session.protocol_id.clone(),
            session.profile.clone(),
            session.settings.clone(),
            session.workspace_expires_at.clone(),
        )
    };

    let database = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?;
    let shell = match cached_profile {
        Some(profile) => profile,
        None => database
            .shell(&profile_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Shell 配置不存在".to_string())?,
    };
    // P5：授权复查优先用会话内快照（免查库）；快照失效/缺失时回退查库
    if cached_workspace_expires.is_some() {
        auth::workspace_alive_from_snapshot(cached_workspace_expires.as_deref())?;
    } else {
        auth::require_session_alive(&database, &shell)?;
    }
    let settings = match cached_settings {
        Some(settings) => settings,
        None => database.get_settings().map_err(|error| error.to_string())?,
    };
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
    mut f: impl FnMut(&dyn SessionState) -> Result<T, ProtocolError>,
) -> Result<T, String> {
    let session = {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?;
        let session = sessions.get_mut(session_id)?;
        session.state.clone()
    };
    match f(session.as_ref()) {
        Ok(value) => Ok(value),
        // E4：网络类错误自动重连一次（目标短暂不可达/重启后 stub 仍在）
        Err(error) if is_reconnectable(&error) => match reconnect_session(state, session_id) {
            Ok(()) => {
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
            Err(_) => Err(error.to_string()),
        },
        Err(error) => Err(error.to_string()),
    }
}

/// S11：判断错误是否值得自动重连——仅网络层失败（业务错误如密码错误/404/服务端报错不重连）。
fn is_reconnectable(error: &ProtocolError) -> bool {
    matches!(error, ProtocolError::Network(_))
}

/// E4：重建协议会话（连接成功则替换 SessionManager 中的状态与信息）。
fn reconnect_session(state: &AppState, session_id: &str) -> Result<(), String> {
    let (profile_id, protocol_id, cached_profile) = {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?;
        let session = sessions.get_mut(session_id)?;
        (
            session.profile_id.clone(),
            session.protocol_id.clone(),
            session.profile.clone(),
        )
    };
    let database = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?;
    let profile = match cached_profile {
        Some(profile) => profile,
        None => database
            .shell(&profile_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "Shell 配置不存在".to_string())?,
    };
    let settings = database.get_settings().map_err(|error| error.to_string())?;
    drop(database);
    let protocol = state
        .protocols
        .get(&protocol_id)
        .ok_or_else(|| format!("未知协议：{protocol_id}"))?;
    let (new_state, probe) = protocol
        .connect(&profile, &settings)
        .map_err(|error| format!("自动重连失败：{error}"))?;
    let mut sessions = state
        .sessions
        .lock()
        .map_err(|_| "会话锁异常".to_string())?;
    if let Ok(session) = sessions.get_mut(session_id) {
        session.state = Arc::from(new_state);
        session.info = probe;
    }
    Ok(())
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
            ctx.protocol
                .execute_command(session, &command, &ctx.settings)
        })
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "shell.exec",
                "error",
                error,
            )
        })?;
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "shell.exec",
            "success",
            &format!("执行命令：{command}"),
        );
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
        // 目录缓存（TTL 5s）：命中直接返回，避免大目录重复网络往返
        let cache_key = (session_id.clone(), path.clone());
        if let Ok(mut cache) = state.dir_cache.lock()
            && let Some(listing) = cache.get(&cache_key, std::time::Duration::from_secs(5))
        {
            return Ok((*listing).clone());
        }
        let listing = with_session(state, &session_id, |session| {
            ctx.protocol.list_dir(session, &path, &ctx.settings)
        })
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "file.list",
                "error",
                error,
            )
        })?;
        let listing_arc = std::sync::Arc::new(listing);
        if let Ok(mut cache) = state.dir_cache.lock() {
            cache.insert(
                cache_key,
                (
                    std::time::Instant::now(),
                    std::sync::Arc::clone(&listing_arc),
                ),
            );
        }
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "file.list",
            "success",
            &format!("浏览目录：{path}"),
        );
        Ok((*listing_arc).clone())
    })
    .await
}

/// 写操作后失效该会话的全部目录缓存（保证一致性）。
fn invalidate_dir_cache(state: &AppState, session_id: &str) {
    if let Ok(mut cache) = state.dir_cache.lock() {
        cache.invalidate_session(session_id);
    }
}

/// E2：批量目录浏览（一次往返返回多个目录，减少 RPC 次数）。
#[tauri::command]
pub async fn batch_list_dir(
    session_id: String,
    paths: Vec<String>,
    app: AppHandle,
) -> Result<serde_json::Value, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        // P4：并行拉取（上限 4 线程），避免 N 个目录串行网络往返
        let workers = paths.len().clamp(1, 4);
        let path_list = &paths;
        let session_id_ref = &session_id;
        let settings_ref = &ctx.settings;
        let collected: Vec<(String, Result<serde_json::Value, String>)> =
            std::thread::scope(|scope| {
                let mut handles = Vec::with_capacity(workers);
                for worker in 0..workers {
                    let session_id = session_id_ref;
                    let settings = settings_ref;
                    handles.push(scope.spawn(move || {
                        let mut out = Vec::new();
                        let mut index = worker;
                        while index < path_list.len() {
                            let path = &path_list[index];
                            // 批量浏览同样命中目录缓存（避免重复网络往返）
                            let cache_key = (session_id.clone(), path.clone());
                            let listing = {
                                let cache_hit =
                                    state.dir_cache.lock().ok().and_then(|mut cache| {
                                        cache.get(&cache_key, std::time::Duration::from_secs(5))
                                    });
                                match cache_hit {
                                    Some(listing) => (*listing).clone(),
                                    None => {
                                        let listing = with_session(state, session_id, |session| {
                                            ctx.protocol.list_dir(session, path, settings)
                                        })
                                        .map_err(|error| format!("浏览 {path} 失败：{error}"));
                                        match listing {
                                            Ok(listing) => {
                                                let listing_arc = std::sync::Arc::new(listing);
                                                if let Ok(mut cache) = state.dir_cache.lock() {
                                                    cache.insert(
                                                        cache_key,
                                                        (
                                                            std::time::Instant::now(),
                                                            std::sync::Arc::clone(&listing_arc),
                                                        ),
                                                    );
                                                }
                                                (*listing_arc).clone()
                                            }
                                            Err(error) => {
                                                out.push((path.clone(), Err(error)));
                                                index += workers;
                                                continue;
                                            }
                                        }
                                    }
                                }
                            };
                            out.push((
                                path.clone(),
                                serde_json::to_value(listing).map_err(|error| error.to_string()),
                            ));
                            index += workers;
                        }
                        out
                    }));
                }
                handles
                    .into_iter()
                    .flat_map(|handle| handle.join().unwrap_or_default())
                    .collect()
            });
        let mut results = serde_json::Map::new();
        for (path, value) in collected {
            results.insert(path, value?);
        }
        Ok(serde_json::Value::Object(results))
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
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "file.read",
                "error",
                error,
            )
        })?;
        let content_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let name = path.rsplit(['/', '\\']).next().unwrap_or(&path).to_string();
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "file.read",
            "success",
            &format!("读取文件：{path}"),
        );
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
            ctx.protocol
                .write_file(session, &path, &bytes, &ctx.settings)
        })
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "file.write",
                "error",
                error,
            )
        })?;
        invalidate_dir_cache(state, &session_id);
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "file.write",
            "success",
            &format!("写入文件：{path}（{} 字节）", bytes.len()),
        );
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
        let ctx = session_ctx(state, &session_id)?;
        // P7：流式 base64 解码分块（每块解码 chunk_size_mb 对应长度后立即发送，
        // 内存峰值从「整文件×2」降到单块；base64 按 4 字符对齐切片）
        let chunk_bytes = ctx.settings.chunk_size_mb.max(1) * 1024 * 1024;
        let b64_per_chunk = (chunk_bytes / 3 * 4) as usize;
        let total = content_b64.len();
        let mut b64_offset = 0usize;
        let mut byte_offset = 0u64;
        while b64_offset < total {
            let mut end = (b64_offset + b64_per_chunk).min(total);
            end -= (end - b64_offset) % 4;
            if end <= b64_offset {
                break;
            }
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&content_b64[b64_offset..end])
                .map_err(|_| "文件内容不是合法 Base64".to_string())?;
            with_session(state, &session_id, |session| {
                ctx.protocol.write_chunk(
                    session,
                    &remote_path,
                    &decoded,
                    byte_offset,
                    &ctx.settings,
                )
            })
            .inspect_err(|error| {
                audit(
                    state,
                    &ctx.workspace_id,
                    Some(&ctx.shell.id),
                    "file.upload",
                    "error",
                    error,
                )
            })?;
            byte_offset += decoded.len() as u64;
            b64_offset = end;
        }
        // 尾部不足 4 字符的残余
        if b64_offset < total {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&content_b64[b64_offset..])
                .map_err(|_| "文件内容不是合法 Base64".to_string())?;
            with_session(state, &session_id, |session| {
                ctx.protocol.write_chunk(
                    session,
                    &remote_path,
                    &decoded,
                    byte_offset,
                    &ctx.settings,
                )
            })
            .inspect_err(|error| {
                audit(
                    state,
                    &ctx.workspace_id,
                    Some(&ctx.shell.id),
                    "file.upload",
                    "error",
                    error,
                )
            })?;
        }
        invalidate_dir_cache(state, &session_id);
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "file.upload",
            "success",
            &format!("上传文件：{remote_path}（{} 字节）", byte_offset),
        );
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
            ctx.protocol
                .write_chunk(session, &path, &bytes, offset, &ctx.settings)
        })
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "file.write",
                "error",
                error,
            )
        })?;
        invalidate_dir_cache(state, &session_id);
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "file.write",
            "success",
            &format!("写入文件：{path}（偏移 {offset}，{} 字节）", bytes.len()),
        );
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
        // S4：下载目标必须是用户选定（save 对话框）的普通路径，拒绝敏感目录
        let safe = sanitize_local_path(&local_path, true)?;
        // 分块拉取（块大小由设置配置，默认 4MB），避免大文件一次性占用内存与超时；
        // P3：逐块流式写盘（不再整文件累积在内存后一次性写入）
        let chunk_size = ctx.settings.chunk_size_mb.max(1) * 1024 * 1024;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&safe)
            .map_err(|error| format!("创建本地文件失败：{error}"))?;
        let mut written = 0u64;
        loop {
            let chunk = with_session(state, &session_id, |session| {
                ctx.protocol
                    .read_chunk(session, &remote_path, written, chunk_size, &ctx.settings)
            })
            .inspect_err(|error| {
                audit(
                    state,
                    &ctx.workspace_id,
                    Some(&ctx.shell.id),
                    "file.download",
                    "error",
                    error,
                )
            })?;
            if chunk.is_empty() {
                break;
            }
            file.write_all(&chunk)
                .map_err(|error| format!("写入本地文件失败：{error}"))?;
            written += chunk.len() as u64;
            if (chunk.len() as u64) < chunk_size {
                break;
            }
        }
        file.flush()
            .map_err(|error| format!("刷新本地文件失败：{error}"))?;
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "file.download",
            "success",
            &format!("下载文件：{remote_path} → {local_path}（{written} 字节）"),
        );
        Ok(written)
    })
    .await
}

#[tauri::command]
pub async fn delete_path(session_id: String, path: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        with_session(state, &session_id, |session| {
            ctx.protocol.delete_path(session, &path, &ctx.settings)
        })
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "file.delete",
                "error",
                error,
            )
        })?;
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "file.delete",
            "success",
            &format!("删除：{path}"),
        );
        invalidate_dir_cache(state, &session_id);
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
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "file.rename",
                "error",
                error,
            )
        })?;
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "file.rename",
            "success",
            &format!("重命名：{from} → {to}"),
        );
        invalidate_dir_cache(state, &session_id);
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn touch_path(
    session_id: String,
    path: String,
    timestamp: u64,
    app: AppHandle,
) -> Result<(), String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        with_session(state, &session_id, |session| {
            ctx.protocol
                .touch_path(session, &path, timestamp, &ctx.settings)
        })
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "file.touch",
                "error",
                error,
            )
        })?;
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "file.touch",
            "success",
            &format!("touch：{path}"),
        );
        invalidate_dir_cache(state, &session_id);
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn create_dir(session_id: String, path: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        with_session(state, &session_id, |session| {
            ctx.protocol.create_dir(session, &path, &ctx.settings)
        })
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "file.mkdir",
                "error",
                error,
            )
        })?;
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "file.mkdir",
            "success",
            &format!("新建目录：{path}"),
        );
        invalidate_dir_cache(state, &session_id);
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
        Ok(crate::protocol::reqlog::list_requests(
            endpoint.as_deref(),
            None,
        ))
    })
    .await
}

#[tauri::command]
pub async fn clear_request_log(app: AppHandle) -> Result<(), String> {
    blocking(app, move |_state| {
        crate::protocol::reqlog::clear_requests();
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
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "db.probe",
                "error",
                error,
            )
        })?;
        audit(
            state,
            &ctx.workspace_id,
            Some(&ctx.shell.id),
            "db.probe",
            "success",
            &format!(
                "探测数据库：{}@{}（{} 个库）",
                connection.driver,
                connection.host.as_deref().unwrap_or("localhost"),
                result.databases.len()
            ),
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
            ctx.protocol
                .db_query(session, &connection, &sql, &ctx.settings)
        })
        .inspect_err(|error| {
            audit(
                state,
                &ctx.workspace_id,
                Some(&ctx.shell.id),
                "db.query",
                "error",
                error,
            )
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
    use crate::protocol::{MOCK_PROTOCOL_ID, ProtocolRegistry};
    use crate::session::SessionManager;
    use crate::storage::Database;
    use dosword_sdk::domain::{CreateShell, CreateWorkspace};
    use std::sync::Mutex;

    fn app_state() -> AppState {
        AppState {
            database: Mutex::new(Database::open(":memory:").unwrap()),
            sessions: Mutex::new(SessionManager::new()),
            protocols: ProtocolRegistry::builtin(),
            feature_plugins: std::sync::Mutex::new(dosword_sdk::FeaturePluginRegistry::builtin()),
            ptys: crate::pty::PtyRegistry::new(),
            dir_cache: Mutex::new(crate::DirCache::new()),
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
    fn encode_text_gbk_round_trip() {
        // "中文" 的 GBK 编码（浏览器 TextEncoder 不支持，走后端）
        let encoded = encode_text_impl("中文测试", "gbk").unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert_eq!(bytes, b"\xd6\xd0\xce\xc4\xb2\xe2\xca\xd4", "GBK 字节应正确");
        // 用 encoding_rs 解码验证往返
        let (decoded, _, _) = encoding_rs::GBK.decode(&bytes);
        assert_eq!(decoded, "中文测试");
        // 不支持编码
        assert!(encode_text_impl("x", "utf-16").is_err());
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
        let result =
            test_connection_impl(&state, "mock://local", "secret", "unknown.v1", None, None);
        assert!(result.is_err(), "未知协议应报错");
        assert!(result.unwrap_err().contains("未知协议"));
    }

    #[test]
    fn test_connection_invalid_endpoint_rejected() {
        let state = app_state();
        let result =
            test_connection_impl(&state, "not-a-url", "secret", MOCK_PROTOCOL_ID, None, None);
        assert!(result.is_err(), "非法 URL 应报错");
    }

    #[test]
    fn backup_shells_writes_timestamped_file() {
        let state = app_state();
        let wid = add_workspace(&mut state.database.lock().unwrap(), "scope-a", None);
        add_shell(&state, &wid, MOCK_PROTOCOL_ID);
        let dir = std::env::temp_dir().join("dosword-backup-test");
        let _ = std::fs::remove_dir_all(&dir);
        let file = backup_shells_impl(&state, &dir.to_string_lossy()).unwrap();
        assert!(std::path::Path::new(&file).exists(), "备份文件应存在");
        let content = std::fs::read_to_string(&file).unwrap();
        assert!(content.contains("mock://local"), "备份应包含 Shell 配置");
        let _ = std::fs::remove_dir_all(&dir);
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
    fn import_shells_enforces_workspace_scope() {
        let state = app_state();
        let wid = add_workspace(&mut state.database.lock().unwrap(), "localhost", None);
        let payload = serde_json::json!([
            {
                "name": "in-scope",
                "endpoint": "http://localhost/shell.php",
                "runtime": "php",
                "protocol_id": "builtin.php.v1",
                "password": "x",
                "protocol_params": "{}",
                "tags": []
            },
            {
                "name": "out-of-scope",
                "endpoint": "http://evil.example/shell.php",
                "runtime": "php",
                "protocol_id": "builtin.php.v1",
                "password": "y",
                "protocol_params": "{}",
                "tags": []
            }
        ]);
        let result = import_shells_impl(&state, &payload.to_string(), &wid).unwrap();
        assert_eq!(result.imported, 1, "仅授权范围内的应导入");
        assert_eq!(result.skipped, 1, "越界 endpoint 应被跳过");
        let shells = state.database.lock().unwrap().list_shells().unwrap();
        assert!(shells.iter().all(|s| !s.endpoint.contains("evil.example")));
    }

    #[test]
    fn batch_update_shells_sets_tags() {
        let state = app_state();
        let wid = add_workspace(&mut state.database.lock().unwrap(), "scope-a", None);
        let shell = add_shell(&state, &wid, MOCK_PROTOCOL_ID);
        let count = batch_update_shells_impl(
            &state,
            std::slice::from_ref(&shell.id),
            Some(vec!["prod".to_string()]),
            None,
        )
        .unwrap();
        assert_eq!(count, 1);
        let updated = state
            .database
            .lock()
            .unwrap()
            .shell(&shell.id)
            .unwrap()
            .unwrap();
        assert_eq!(updated.tags, vec!["prod"]);
    }

    fn register_session(state: &AppState, shell: &ShellProfile) -> String {
        let protocol = state.protocols.get(&shell.protocol_id).unwrap();
        let settings = state.database.lock().unwrap().get_settings().unwrap();
        let (session, probe) = protocol.connect(shell, &settings).unwrap();
        state.sessions.lock().unwrap().insert(
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
        let settings = AppSettings {
            http_enabled: false,
            ..AppSettings::default()
        };

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
        let workspace_id =
            add_workspace(&mut state.database.lock().unwrap(), "other.example", None);
        let shell = add_shell(&state, &workspace_id, "builtin.php.v1");
        // PHP 协议 shell 端点不在授权范围内，即使开关开启也会被拒绝
        let settings = AppSettings {
            http_enabled: true,
            ..AppSettings::default()
        };
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
