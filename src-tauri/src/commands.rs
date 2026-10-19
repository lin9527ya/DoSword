use base64::Engine;
use std::io::Write;
use std::sync::Arc;
use tauri::{AppHandle, Manager, State};
use url::Url;

use dosword_sdk::domain::{
    AppSettings, AuditFilter, AuditPage, CommandOutput, ConnectResult, CreateShell,
    CreateWorkspace, Dashboard, DbConnection, DbProbeResult, DbQueryResult, DirListing, FileChunk,
    FileContent, GenerateShellResult, HttpSendResult, ImportResult, MemoryShell,
    MemshellCapability, ProbeResult, ProtocolMeta, ProxyTestResult, RequestRecord, SessionInfo,
    ShellProfile, UpdateShell, UpdateWorkspace, Workspace,
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

/// 按**字符**截断（不是字节）：`str::len()` 是字节数，`&s[..64]` 会落在多字节
/// 字符中间并 panic——release 构建 `panic = "abort"`（Cargo.toml）会终止整个
/// 进程并丢失全部活动会话。超出时追加省略号。
fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let head: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

/// base64 载荷切片：非 ASCII 输入按字节边界切会 panic，这里返回显式错误。
fn base64_slice(value: &str, start: usize, end: usize) -> Result<&str, String> {
    value
        .get(start..end)
        .ok_or_else(|| "文件内容不是合法 Base64（含非 ASCII 字符）".to_string())
}

/// 审计用 URL：去掉 query 与 fragment（可能含密码 / token），只留 scheme://host/path。
fn redact_url(value: &str) -> String {
    match Url::parse(value) {
        Ok(mut url) => {
            url.set_query(None);
            url.set_fragment(None);
            url.to_string()
        }
        Err(_) => value.to_string(),
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
///
/// 真实网络协议同样受授权范围约束（联合范围，`allow_unscoped` 显式覆盖）。
#[tauri::command]
pub async fn test_connection(
    endpoint: String,
    password: String,
    protocol_id: String,
    protocol_params: Option<String>,
    runtime: Option<String>,
    allow_unscoped: Option<bool>,
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
            allow_unscoped.unwrap_or(false),
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
    allow_unscoped: bool,
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
    if protocol.requires_network() {
        let scope_result = {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            auth::require_in_any_scope(&database, endpoint)
        };
        match scope_result {
            Ok(reason) => {
                audit(
                    state,
                    "system",
                    None,
                    "shell.test_connection",
                    "success",
                    &format!("{endpoint}（{reason}）"),
                );
            }
            Err(error) if allow_unscoped => {
                audit(
                    state,
                    "system",
                    None,
                    "shell.test_connection",
                    "override",
                    &format!("{endpoint}（{error}；用户显式覆盖授权范围）"),
                );
            }
            Err(error) => {
                return Err(format!(
                    "{error}：请先把目标登记到某个 Workspace 的授权范围，\
                     或勾选「允许未授权范围目标」（会记入审计）"
                ));
            }
        }
    }
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

/// S4：本地路径安全校验（跨平台）。
///
/// 历史实现只拒绝 `/etc`、`/proc` 等 POSIX 前缀——在 Windows 上
/// `canonicalize()` 返回 `\\?\C:\…`，字符串前缀永不匹配，等于**没有校验**：
/// 被攻破的前端（或恶意插件）可读写任意用户文件（含存明文密码的 SQLite）。
///
/// 现行策略：
/// 1. 必须绝对路径；拒绝 UNC（`\\server\share`）、设备/扩展长度前缀与 ADS（`name:stream`）；
/// 2. 规范化后按**路径组件**比较，拒绝系统目录；
/// 3. 默认只允许用户主目录 / 系统临时目录之内，越界需显式开启
///    `allow_arbitrary_local_paths`（设置 → 安全门禁）。
fn sanitize_local_path(
    state: &AppState,
    path: &str,
    for_write: bool,
) -> Result<std::path::PathBuf, String> {
    let raw = std::path::Path::new(path);
    if !raw.is_absolute() {
        return Err("必须使用绝对路径".to_string());
    }
    let normalized = path.replace('/', "\\");
    if normalized.starts_with("\\\\") || normalized.starts_with("\\?\\") {
        return Err("拒绝 UNC / 设备路径".to_string());
    }
    if let Some(name) = raw.file_name().and_then(|name| name.to_str())
        && name.contains(':')
    {
        return Err("拒绝备用数据流（ADS）路径".to_string());
    }

    let resolved = if for_write {
        let parent = raw.parent().ok_or_else(|| "路径缺少父目录".to_string())?;
        let canon_parent =
            std::fs::canonicalize(parent).map_err(|error| format!("路径无效：{error}"))?;
        canon_parent.join(raw.file_name().unwrap_or_default())
    } else {
        let canonical = std::fs::canonicalize(raw).map_err(|error| format!("路径无效：{error}"))?;
        if !canonical.is_file() {
            return Err("仅支持读取普通文件".to_string());
        }
        canonical
    };

    for denied in denied_local_roots() {
        if resolved.starts_with(&denied) {
            return Err(format!("拒绝访问系统目录：{}", denied.display()));
        }
    }

    let allow_outside = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?
        .get_settings()
        .map_err(|error| error.to_string())?
        .allow_arbitrary_local_paths;
    if !allow_outside {
        let allowed = allowed_local_roots();
        if !allowed.is_empty() && !allowed.iter().any(|root| resolved.starts_with(root)) {
            return Err(format!(
                "路径不在允许范围内（默认仅限用户目录 / 系统临时目录）：{}；\
                 如确需其他目录，请在「设置 → 安全门禁」开启「允许任意本地路径」",
                resolved.display()
            ));
        }
    }
    Ok(resolved)
}

/// 一律拒绝的系统目录（按平台）。
fn denied_local_roots() -> Vec<std::path::PathBuf> {
    #[cfg(windows)]
    {
        let mut roots = Vec::new();
        for key in [
            "SystemRoot",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramData",
        ] {
            if let Ok(value) = std::env::var(key) {
                roots.push(std::path::PathBuf::from(value));
            }
        }
        roots
    }
    #[cfg(not(windows))]
    {
        [
            "/etc", "/proc", "/sys", "/root", "/boot", "/dev", "/var/lib", "/usr",
        ]
        .iter()
        .map(std::path::PathBuf::from)
        .collect()
    }
}

/// 默认允许的根目录：用户主目录 + 系统临时目录。
fn allowed_local_roots() -> Vec<std::path::PathBuf> {
    let mut roots = Vec::new();
    for key in ["USERPROFILE", "HOME"] {
        if let Ok(value) = std::env::var(key)
            && !value.trim().is_empty()
            && let Ok(canonical) = std::fs::canonicalize(&value)
        {
            roots.push(canonical);
        }
    }
    if let Ok(temp) = std::fs::canonicalize(std::env::temp_dir()) {
        roots.push(temp);
    }
    roots.sort();
    roots.dedup();
    roots
}

#[tauri::command]
pub async fn read_local_file(path: String, app: AppHandle) -> Result<String, String> {
    blocking(app, move |state| {
        let safe = sanitize_local_path(state, &path, false)?;
        // 读取前先看大小：避免把一个 10GB 文件整块读进内存再 base64（×1.33）
        let limit = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .get_settings()
            .map_err(|error| error.to_string())?
            .max_file_size_mb
            .saturating_mul(1024 * 1024);
        if let Ok(metadata) = std::fs::metadata(&safe)
            && metadata.len() > limit
        {
            return Err(format!(
                "本地文件超过大小上限（{}MB），请提高上限或改用命令行导入",
                limit / 1024 / 1024
            ));
        }
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
    blocking(app, move |state| {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&content_b64)
            .map_err(|_| "内容不是合法 Base64".to_string())?;
        let safe = sanitize_local_path(state, &path, true)?;
        std::fs::write(&safe, &bytes).map_err(|error| format!("写入本地文件失败：{error}"))?;
        audit(
            state,
            "system",
            None,
            "local.write",
            "success",
            &format!("写入本地文件：{}（{} 字节）", safe.display(), bytes.len()),
        );
        Ok(())
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
///
/// 走 `session_ctx`（与文件/命令操作同一套检查）：授权范围、Workspace 到期、
/// 真实网络开关都会复查——插件此前绕过了这些门，可在授权过期后继续执行。
#[tauri::command]
pub async fn run_feature_plugin(
    session_id: String,
    plugin_id: String,
    params: serde_json::Value,
    app: AppHandle,
) -> Result<serde_json::Value, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        let session = {
            let mut sessions = state
                .sessions
                .lock()
                .map_err(|_| "会话锁异常".to_string())?;
            sessions
                .get_mut(&session_id)
                .map_err(|error| error.to_string())?
                .state
                .clone()
        };
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
        let runtime = if ctx.shell.runtime.is_empty() {
            "php"
        } else {
            ctx.shell.runtime.as_str()
        };
        let output = plugin
            .execute(
                ctx.protocol,
                session.as_ref(),
                runtime,
                &params,
                &ctx.settings,
            )
            .map_err(|error| format!("插件执行失败：{error}"))?;
        // S9：插件执行审计（含参数摘要，不含代码体）
        let summary: String = params
            .as_object()
            .map(|obj| {
                obj.iter()
                    .map(|(key, value)| {
                        let text = match value {
                            serde_json::Value::String(s) => truncate_chars(s, 64),
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
    let updated = {
        let mut database = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?;
        database
            .batch_update_shells(ids, tags.as_ref(), password.as_deref())
            .map_err(|e| e.to_string())?
    };
    // P6：与单条 update_shell 一致 —— 更新后失效会话上下文缓存，否则已建会话仍用旧密码
    if let Ok(mut sessions) = state.sessions.lock() {
        for id in ids {
            sessions.invalidate_context(id);
        }
    }
    // 全量审计：批量改密码此前完全不留痕
    if let Ok(database) = state.database.lock() {
        let _ = database.record_audit(
            None,
            None,
            "shell.batch_update",
            "success",
            &format!(
                "批量更新 {} 个 Shell；标签：{}；密码：{}",
                updated,
                if tags.is_some() {
                    "已更新"
                } else {
                    "未变更"
                },
                if password.is_some() {
                    "已更新"
                } else {
                    "未变更"
                }
            ),
        );
    }
    Ok(updated)
}

/// Repeater：手工构造并发送一次 HTTP 请求（不经协议，仅走传输层）。
///
/// 默认要求目标命中**任一** Workspace 的授权范围；`allow_unscoped` 为显式覆盖
/// （审计 outcome 记 `override`）。此前该入口只检查全局开关，可打任意主机。
#[tauri::command]
pub async fn http_send(
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: String,
    allow_unscoped: Option<bool>,
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
        let allow_unscoped = allow_unscoped.unwrap_or(false);
        let scope_result = {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            auth::require_in_any_scope(&database, &url)
        };
        match scope_result {
            Ok(_) => {}
            Err(error) if allow_unscoped => {
                audit(
                    state,
                    "system",
                    None,
                    "http.send",
                    "override",
                    &format!(
                        "{method} {}（{error}；用户显式覆盖授权范围）",
                        redact_url(&url)
                    ),
                );
            }
            Err(error) => {
                return Err(format!(
                    "{error}：请先把目标登记到某个 Workspace 的授权范围，\
                     或勾选「允许未授权范围目标」（会记入审计）"
                ));
            }
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
                &format!("{method_str} {}：{error}", redact_url(&url)),
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
                "{method_str} {}：响应超过大小上限（{}MB）",
                redact_url(&url),
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
                "{method_str} {} → HTTP {status}（{} 字节，{duration_ms}ms）",
                redact_url(&url),
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

/// 代理探测的默认目标：返回纯文本出口 IP。
const DEFAULT_PROXY_PROBE_URL: &str = "https://api.ipify.org";

/// 代理连通性测试：用当前设置（可被入参临时覆盖）构建客户端访问探测地址。
///
/// 该命令**会产生真实外网流量**，因此写审计（`settings.proxy_test`）；
/// 不携带任何 Shell 凭据。网络失败返回 `ok=false` 而非 Err，便于前端展示原因。
#[tauri::command]
pub async fn test_proxy_upstream(
    proxy: Option<String>,
    timeout_secs: Option<u64>,
    probe_url: Option<String>,
    app: AppHandle,
) -> Result<ProxyTestResult, String> {
    blocking(app, move |state| {
        test_proxy_upstream_impl(state, proxy.as_deref(), timeout_secs, probe_url.as_deref())
    })
    .await
}

fn test_proxy_upstream_impl(
    state: &AppState,
    proxy: Option<&str>,
    timeout_secs: Option<u64>,
    probe_url: Option<&str>,
) -> Result<ProxyTestResult, String> {
    let mut settings = state
        .database
        .lock()
        .map_err(|_| "数据库锁异常".to_string())?
        .get_settings()
        .map_err(|error| error.to_string())?;
    // 表单里可能刚改过代理/超时但尚未保存：以入参为准
    settings.proxy = proxy
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    settings.default_timeout_secs = timeout_secs
        .unwrap_or(settings.default_timeout_secs)
        .clamp(1, 60);

    let target = probe_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_PROXY_PROBE_URL);
    let url = parse_endpoint(target)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("探测地址仅支持 http / https".to_string());
    }
    // 代理地址格式错误必须是硬错误：本命令的目的就是验证代理，静默直连会误导用户
    if let Some(proxy) = settings.proxy.as_deref() {
        reqwest::Proxy::all(proxy).map_err(|error| format!("代理地址无效：{error}"))?;
    }

    let client = crate::protocol::transport::build_client(&settings);
    let started = std::time::Instant::now();
    let response = match client.get(url.as_str()).send() {
        Ok(response) => response,
        Err(error) => {
            let message = format!("代理测试失败：{error}");
            audit(
                state,
                "system",
                None,
                "settings.proxy_test",
                "error",
                &message,
            );
            return Ok(ProxyTestResult {
                ok: false,
                latency_ms: started.elapsed().as_millis() as u64,
                message,
                exit_ip: None,
            });
        }
    };
    let status = response.status();
    let bytes = crate::protocol::transport::read_limited(response, 64 * 1024)
        .map_err(|error| format!("读取响应失败：{error}"))?;
    let latency_ms = started.elapsed().as_millis() as u64;
    if !status.is_success() {
        let message = format!("上游返回 HTTP {}", status.as_u16());
        audit(
            state,
            "system",
            None,
            "settings.proxy_test",
            "error",
            &format!("{message}（{latency_ms}ms）"),
        );
        return Ok(ProxyTestResult {
            ok: false,
            latency_ms,
            message,
            exit_ip: None,
        });
    }
    let text = String::from_utf8_lossy(&bytes).trim().to_string();
    // 仅当响应本身就是一行 IP 时才回填出口 IP（兼容任意探测地址）
    let exit_ip = if text.len() <= 64 && text.parse::<std::net::IpAddr>().is_ok() {
        Some(text)
    } else {
        None
    };
    let via = settings.proxy.as_deref().unwrap_or("直连");
    let message = match &exit_ip {
        Some(ip) => format!("代理连通正常（{via}），出口 IP {ip}"),
        None => format!("连通正常（{via}）"),
    };
    audit(
        state,
        "system",
        None,
        "settings.proxy_test",
        "success",
        &format!("{message}（{latency_ms}ms）"),
    );
    Ok(ProxyTestResult {
        ok: true,
        latency_ms,
        message,
        exit_ip,
    })
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

/// 设置保存后按最新设置同步 MCP 服务（启用→重启，关闭→停止）。
#[cfg(feature = "mcp")]
fn schedule_mcp_sync(app: AppHandle, settings: AppSettings) {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<crate::mcp::McpState>();
        if settings.mcp_enabled {
            if let Err(error) = state.start(app.clone(), &settings).await {
                state.set_error(Some(error));
            }
        } else {
            state.stop();
        }
    });
}

#[tauri::command]
pub async fn update_settings(input: AppSettings, app: AppHandle) -> Result<(), String> {
    #[cfg(feature = "mcp")]
    let mcp_handle = app.clone();
    blocking(app, move |state| {
        // 设置范围钳位：此前完全不校验，chunk > max_file_size 会让**每次分块读取**
        // 都被响应上限拒绝（下载必失败），0 秒超时会让请求立即失败。
        let mut input = input;
        input.default_timeout_secs = input.default_timeout_secs.clamp(1, 600);
        input.chunk_size_mb = input.chunk_size_mb.clamp(1, 64);
        input.max_file_size_mb = input.max_file_size_mb.clamp(1, 512);
        input.audit_retention_days = input.audit_retention_days.min(3650);
        // MCP：端口与限流钳位；启用但无令牌时自动生成（避免"启用了却连不上"）
        input.mcp_port = input.mcp_port.clamp(1024, 65535);
        input.mcp_max_calls_per_min = input.mcp_max_calls_per_min.clamp(1, 6000);
        input.mcp_token = input.mcp_token.trim().to_string();
        #[cfg(feature = "mcp")]
        if input.mcp_enabled && input.mcp_token.is_empty() {
            input.mcp_token = crate::mcp::generate_token();
        }
        if input.chunk_size_mb > input.max_file_size_mb {
            input.chunk_size_mb = input.max_file_size_mb;
        }
        // 代理地址格式错误必须是硬错误：静默直连会让用户以为流量走了代理（去匿名化）
        if let Some(proxy) = input
            .proxy
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            reqwest::Proxy::all(proxy).map_err(|error| format!("代理地址无效：{error}"))?;
        } else {
            input.proxy = None;
        }
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
        // 关闭真实网络 = 立即失效全部活跃会话（含其 PTY 流）：
        // 否则已建立的会话会绕过总开关继续发包
        if previous.http_enabled && !input.http_enabled {
            let removed = {
                let mut sessions = state
                    .sessions
                    .lock()
                    .map_err(|_| "会话锁异常".to_string())?;
                let ids: Vec<String> = sessions.list_ids();
                for id in &ids {
                    sessions.remove(id);
                }
                ids
            };
            for session_id in &removed {
                state.ptys.close_for_session(session_id);
            }
            // 关闭真实网络 = 同时关闭全部多跳代理链（否则链会继续转发流量）
            let chain_count = {
                let mut chains = state
                    .proxy_chains
                    .lock()
                    .map_err(|_| "代理链注册表锁异常".to_string())?;
                let count = chains.len();
                for (_, chain) in chains.drain() {
                    chain.stop();
                }
                count
            };
            if !removed.is_empty() || chain_count > 0 {
                audit(
                    state,
                    "system",
                    None,
                    "settings.update",
                    "success",
                    &format!(
                        "已关闭真实网络：强制断开 {} 个活跃会话及其 PTY，关闭 {} 条代理链",
                        removed.len(),
                        chain_count
                    ),
                );
            }
        }

        // MCP：任何 mcp_* 字段变化都同步服务状态（启用→重启，关闭→停止）。
        // 此处位于阻塞线程、不能跨 await 持锁，故交给异步运行时调度。
        #[cfg(feature = "mcp")]
        {
            let mcp_changed = previous.mcp_enabled != input.mcp_enabled
                || previous.mcp_port != input.mcp_port
                || previous.mcp_token != input.mcp_token
                || previous.mcp_tier_read != input.mcp_tier_read
                || previous.mcp_tier_write != input.mcp_tier_write
                || previous.mcp_tier_exec != input.mcp_tier_exec
                || previous.mcp_require_confirm != input.mcp_require_confirm
                || previous.mcp_max_calls_per_min != input.mcp_max_calls_per_min;
            if mcp_changed {
                schedule_mcp_sync(mcp_handle, input.clone());
            }
        }
        Ok(())
    })
    .await
}

// --- 会话 ---

#[tauri::command]
pub async fn connect_shell(shell_id: String, app: AppHandle) -> Result<ConnectResult, String> {
    blocking(app, move |state| {
        connect_shell_impl(state, &shell_id).map(|(result, _)| result)
    })
    .await
}

/// 建立会话的内部实现，返回 `(探测结果, session_id)`。供命令层与批量编排复用。
fn connect_shell_impl(state: &AppState, shell_id: &str) -> Result<(ConnectResult, String), String> {
    let (shell, settings) = load_shell_and_settings(state, shell_id)?;
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

    let result = ConnectResult::from_probe(session_id.clone(), probe);
    Ok((result, session_id))
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
    callback_host: Option<String>,
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
        // 回调地址：目标从**它的**网络位置回连本机，因此必须是目标可达的地址
        // （默认 127.0.0.1 仅适用于本机目标/端口转发场景）。
        let callback = callback_host
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("127.0.0.1")
            .to_string();
        dosword_sdk::feature_plugins::validate_host_arg(&callback)
            .map_err(|error| format!("回调地址无效：{error}"))?;
        let loopback = matches!(callback.as_str(), "127.0.0.1" | "localhost" | "::1");
        let bind_addr = if loopback { "127.0.0.1:0" } else { "0.0.0.0:0" };
        // 1) 本地监听随机端口
        let listener = std::net::TcpListener::bind(bind_addr)
            .map_err(|error| format!("PTY 监听绑定失败（{bind_addr}）：{error}"))?;
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
            &serde_json::json!({"host": callback, "port": port, "background": true}),
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
                Ok((stream, peer)) => {
                    let pty_id = state.ptys.insert(&session_id, stream);
                    // S9：PTY 会话建立审计
                    let _ = state
                        .database
                        .lock()
                        .map_err(|_| "数据库锁异常".to_string())
                        .and_then(|database| {
                            database
                                .record_audit(
                                    None,
                                    Some(&session_id),
                                    "pty.start",
                                    "success",
                                    &format!(
                                        "建立交互式 PTY 会话（回调 {callback}:{port}，来源 {peer}）"
                                    ),
                                )
                                .map_err(|error| error.to_string())
                        });
                    return Ok(serde_json::json!({
                        "ptyId": pty_id,
                        "port": port,
                        "callbackHost": callback,
                    }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() > deadline {
                        return Err(format!(
                            "PTY 会话建立超时（目标未回连 {callback}:{port}）：\
                             请确认回调地址是目标可达的本机地址（跨网段/NAT 场景需端口转发）"
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(120));
                }
                Err(error) => return Err(format!("PTY 接受连接失败：{error}")),
            }
        }
    })
    .await
}

/// 复检 PTY 归属会话是否仍然存活（过期/断开的会话不得继续操作其 PTY 流）。
///
/// 会话 TTL 到期或 `http_enabled` 被关闭时，PTY 必须一并失效，
/// 否则交互式 shell 会绕过授权门继续可用。
fn require_pty_owner_alive(state: &AppState, pty_id: &str) -> Result<String, String> {
    let owner = state
        .ptys
        .owner_of(pty_id)
        .ok_or_else(|| "PTY 会话不存在或已关闭".to_string())?;
    let mut sessions = state
        .sessions
        .lock()
        .map_err(|_| "会话锁异常".to_string())?;
    if sessions.get(&owner).is_none() {
        drop(sessions);
        state.ptys.close(pty_id);
        return Err("PTY 所属会话已过期或已断开，交互式终端已失效".to_string());
    }
    Ok(owner)
}

/// 向 PTY 会话写入数据（base64）。
#[tauri::command]
pub async fn pty_write(pty_id: String, data_b64: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        require_pty_owner_alive(state, &pty_id)?;
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
    blocking(app, move |state| {
        if let Err(error) = require_pty_owner_alive(state, &pty_id) {
            return Ok(serde_json::json!({
                "data": "",
                "closed": true,
                "error": error,
            }));
        }
        match state.ptys.read(&pty_id) {
            Ok(bytes) => Ok(serde_json::json!({
                "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                "closed": false,
            })),
            Err(error) => Ok(serde_json::json!({
                "data": "",
                "closed": true,
                "error": error,
            })),
        }
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
        // 与文件/命令操作一致：过期检查（快照优先，缺失时回退查库）
        let _ctx = session_ctx(state, &session_id)?;
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
///
/// 重连同样要过授权门：目标可能已超出授权范围、Workspace 可能已到期、
/// 真实网络开关可能已被关闭——此前直接 `protocol.connect` 会绕过全部检查。
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
    require_authorized_for(state, &profile, &settings)?;
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
                .decode(base64_slice(&content_b64, b64_offset, end)?)
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
                .decode(base64_slice(&content_b64, b64_offset, total)?)
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

/// 分块读取远端文件（`length = 0` 表示读到文件尾）。
///
/// 与 `write_chunk` 对称：MCP 的 `fs_read` 用它做偏移读取，避免把整个文件
/// 读进上下文；前端后续做分块预览也可复用。
///
/// 只对**失败**写审计：成功读取由调用方（MCP 工具层）统一记 `mcp.<tool>`，
/// 否则 agent 轮询读会瞬间冲垮审计表。
#[tauri::command]
pub async fn read_chunk(
    session_id: String,
    path: String,
    offset: u64,
    length: u64,
    app: AppHandle,
) -> Result<FileChunk, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        let data = with_session(state, &session_id, |session| {
            ctx.protocol
                .read_chunk(session, &path, offset, length, &ctx.settings)
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
        let size = data.len() as u64;
        Ok(FileChunk {
            data_b64: base64::engine::general_purpose::STANDARD.encode(&data),
            offset,
            size,
            // length = 0 表示"一直读到文件尾"，本次已读完；否则不足请求长度即到尾
            eof: length == 0 || size < length,
        })
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
        let safe = sanitize_local_path(state, &local_path, true)?;
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
            // 护栏：返回块大于请求长度说明目标忽略了偏移（旧版 stub），
            // 此时"短块 = EOF"永不成立 → 会无限追加写满本地磁盘，必须立即中止。
            if chunk.len() as u64 > chunk_size {
                return Err(format!(
                    "下载中止：目标返回 {} 字节，超过单块请求长度 {chunk_size} 字节；\
                     可能是目标 stub 不支持偏移读取，请重新生成并上传 stub",
                    chunk.len()
                ));
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
// MCP 服务端控制（cargo feature `mcp`）。
//
// 这些命令在关闭 feature 时仍保留定义：前端调用面保持稳定，仅返回明确错误，
// 避免出现「前端有调用、后端无此命令」的契约缺口。
// ---------------------------------------------------------------------------

/// 读取 MCP 设置（若令牌为空则生成一个并落库：启用前必须先有令牌）。
///
/// 注意：`audit()` 内部会再取一次数据库锁，因此此处**不能**在持有 guard 时调用，
/// 否则 std::sync::Mutex 非重入会直接死锁。
#[cfg(feature = "mcp")]
fn ensure_mcp_settings(state: &AppState) -> Result<AppSettings, String> {
    let mut settings = {
        let database = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?;
        database.get_settings().map_err(|error| error.to_string())?
    };
    if settings.mcp_token.trim().is_empty() {
        settings.mcp_token = crate::mcp::generate_token();
        {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            database
                .update_settings(&settings)
                .map_err(|error| error.to_string())?;
        }
        audit(
            state,
            "system",
            None,
            "mcp.token",
            "success",
            "首次启用 MCP：已生成访问令牌",
        );
    }
    Ok(settings)
}

#[tauri::command]
pub async fn mcp_status(app: AppHandle) -> Result<dosword_sdk::domain::McpStatus, String> {
    #[cfg(feature = "mcp")]
    {
        Ok(app.state::<crate::mcp::McpState>().status())
    }
    #[cfg(not(feature = "mcp"))]
    {
        let _ = app;
        Err("本构建未启用 MCP 支持（cargo feature `mcp`）".to_string())
    }
}

#[tauri::command]
pub async fn mcp_start(app: AppHandle) -> Result<dosword_sdk::domain::McpStatus, String> {
    #[cfg(feature = "mcp")]
    {
        // 令牌与端口：锁作用域内读取，避免跨 await 持有数据库锁
        let settings = {
            let state = app.state::<AppState>();
            let mut settings = ensure_mcp_settings(&state)?;
            settings.mcp_enabled = true;
            state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?
                .update_settings(&settings)
                .map_err(|error| error.to_string())?;
            audit(
                &state,
                "system",
                None,
                "mcp.start",
                "success",
                &format!("启动 MCP 服务：127.0.0.1:{}", settings.mcp_port),
            );
            settings
        };

        let state = app.state::<crate::mcp::McpState>();
        state.start(app.clone(), &settings).await?;
        Ok(state.status())
    }
    #[cfg(not(feature = "mcp"))]
    {
        let _ = app;
        Err("本构建未启用 MCP 支持（cargo feature `mcp`）".to_string())
    }
}

#[tauri::command]
pub async fn mcp_stop(app: AppHandle) -> Result<dosword_sdk::domain::McpStatus, String> {
    #[cfg(feature = "mcp")]
    {
        {
            let state = app.state::<AppState>();
            let mut settings = ensure_mcp_settings(&state)?;
            settings.mcp_enabled = false;
            state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?
                .update_settings(&settings)
                .map_err(|error| error.to_string())?;
            audit(
                &state,
                "system",
                None,
                "mcp.stop",
                "success",
                "停止 MCP 服务",
            );
        }
        let state = app.state::<crate::mcp::McpState>();
        state.stop();
        Ok(state.status())
    }
    #[cfg(not(feature = "mcp"))]
    {
        let _ = app;
        Err("本构建未启用 MCP 支持（cargo feature `mcp`）".to_string())
    }
}

/// 轮换访问令牌并返回新令牌（服务运行中会以新令牌重启）。
#[tauri::command]
pub async fn mcp_rotate_token(app: AppHandle) -> Result<String, String> {
    #[cfg(feature = "mcp")]
    {
        let (settings, running) = {
            let state = app.state::<AppState>();
            let mut settings = ensure_mcp_settings(&state)?;
            settings.mcp_token = crate::mcp::generate_token();
            state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?
                .update_settings(&settings)
                .map_err(|error| error.to_string())?;
            audit(
                &state,
                "system",
                None,
                "mcp.token",
                "override",
                "轮换 MCP 访问令牌（旧令牌立即失效）",
            );
            let running = app.state::<crate::mcp::McpState>().is_running();
            (settings, running)
        };

        if running {
            let state = app.state::<crate::mcp::McpState>();
            state.start(app.clone(), &settings).await?;
        }
        Ok(settings.mcp_token)
    }
    #[cfg(not(feature = "mcp"))]
    {
        let _ = app;
        Err("本构建未启用 MCP 支持（cargo feature `mcp`）".to_string())
    }
}

#[tauri::command]
pub async fn mcp_recent_calls(
    limit: Option<u32>,
    app: AppHandle,
) -> Result<Vec<dosword_sdk::domain::McpCallRecord>, String> {
    #[cfg(feature = "mcp")]
    {
        let limit = limit.unwrap_or(50).clamp(1, 200) as usize;
        Ok(app.state::<crate::mcp::McpState>().recent(limit))
    }
    #[cfg(not(feature = "mcp"))]
    {
        let _ = (limit, app);
        Err("本构建未启用 MCP 支持（cargo feature `mcp`）".to_string())
    }
}

#[tauri::command]
pub async fn mcp_clear_log(app: AppHandle) -> Result<(), String> {
    #[cfg(feature = "mcp")]
    {
        app.state::<crate::mcp::McpState>().clear_log();
        Ok(())
    }
    #[cfg(not(feature = "mcp"))]
    {
        let _ = app;
        Err("本构建未启用 MCP 支持（cargo feature `mcp`）".to_string())
    }
}

/// 待人工确认的执行级操作。
#[tauri::command]
pub async fn mcp_pending_approvals(
    app: AppHandle,
) -> Result<Vec<dosword_sdk::domain::McpPendingApproval>, String> {
    #[cfg(feature = "mcp")]
    {
        Ok(app.state::<crate::mcp::McpState>().pending_approvals())
    }
    #[cfg(not(feature = "mcp"))]
    {
        let _ = app;
        Err("本构建未启用 MCP 支持（cargo feature `mcp`）".to_string())
    }
}

/// 批准或拒绝一个执行级操作。批准后 120 秒内、参数完全一致的重试才会生效（一次性）。
#[tauri::command]
pub async fn mcp_resolve_approval(
    id: String,
    approve: bool,
    app: AppHandle,
) -> Result<dosword_sdk::domain::McpPendingApproval, String> {
    #[cfg(feature = "mcp")]
    {
        let (record, approved) = app
            .state::<crate::mcp::McpState>()
            .resolve_approval(&id, approve)?;
        {
            let state = app.state::<AppState>();
            audit(
                &state,
                "system",
                None,
                "mcp.approval",
                if approved { "success" } else { "denied" },
                &format!(
                    "执行级操作{}：{}｜{}",
                    if approved { "已批准" } else { "已拒绝" },
                    record.tool,
                    record.summary
                ),
            );
        }
        Ok(record)
    }
    #[cfg(not(feature = "mcp"))]
    {
        let _ = (id, approve, app);
        Err("本构建未启用 MCP 支持（cargo feature `mcp`）".to_string())
    }
}

// ---------------------------------------------------------------------------
// 命令层测试：直接构造 AppState（内存库 + 会话管理器 + 内置协议），
// 验证统一流程：会话上下文解析、授权门、锁外执行。
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 内存马（后渗透）。所有会改变目标状态的路径都必须：授权门 → 审计 → 可卸载。
// 两种形态：
//   php_user_ini —— 写 .user.ini + 载荷文件（持久，需卸载；有 cache_ttl 延迟）
//   php_fcgi     —— 直连 FPM 逐请求执行（零落盘、无延迟、无残留需清理）
// ---------------------------------------------------------------------------

/// 查询当前目标支持的内存马形态。
#[tauri::command]
pub async fn memshell_capabilities(
    session_id: String,
    app: AppHandle,
) -> Result<Vec<MemshellCapability>, String> {
    blocking(app, move |state| {
        let info = {
            let mut sessions = state
                .sessions
                .lock()
                .map_err(|_| "会话锁异常".to_string())?;
            sessions.get_mut(&session_id)?.info.clone()
        };
        let verdict = crate::memshell::php_user_ini_preconditions(&info);
        Ok(vec![
            MemshellCapability {
                kind: crate::memshell::KIND_PHP_USER_INI.to_string(),
                runtime: "php".to_string(),
                feasible: verdict.is_ok(),
                reason: verdict.err(),
            },
            // FPM 直连不依赖目标 SAPI 配置，但要求客户端能连到 FPM 端口；
            // 可达性由安装时的 ping 实测，这里不做网络探测。
            MemshellCapability {
                kind: crate::memshell::KIND_PHP_FCGI.to_string(),
                runtime: "php".to_string(),
                feasible: true,
                reason: None,
            },
        ])
    })
    .await
}

/// 注入内存马。`kind = php_user_ini` 时用 install_dir/trigger_url；
/// `kind = php_fcgi` 时用 fpm_target/script_filename。
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn memshell_install(
    session_id: String,
    kind: String,
    install_dir: Option<String>,
    trigger_url: Option<String>,
    fpm_target: Option<String>,
    script_filename: Option<String>,
    app: AppHandle,
) -> Result<MemoryShell, String> {
    blocking(app, move |state| {
        let ctx = session_ctx(state, &session_id)?;
        if !ctx.settings.http_enabled {
            return Err("真实网络协议未开启，禁止注入内存马".to_string());
        }
        let (session, info) = {
            let mut sessions = state
                .sessions
                .lock()
                .map_err(|_| "会话锁异常".to_string())?;
            let session = sessions.get_mut(&session_id)?;
            (session.state.clone(), session.info.clone())
        };
        let shell_id = ctx.shell.id.clone();
        let workspace_id = ctx.shell.workspace_id.clone();
        {
            let existing = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?
                .list_memory_shells(None, Some(&shell_id))
                .map_err(|error| error.to_string())?;
            if crate::memshell::has_orphan(&existing) {
                return Err("该目标存在无法卸载的内存马残留，请先人工清理后再注入".to_string());
            }
        }

        let token = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("m{}", &token[..8]);
        let now = chrono::Utc::now().to_rfc3339();

        let handle = if kind == crate::memshell::KIND_PHP_FCGI {
            let target_value = fpm_target
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "缺少 FPM 地址（例如 127.0.0.1:9000）".to_string())?;
            let script = script_filename
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "缺少 SCRIPT_FILENAME（目标上已存在的 PHP 文件）".to_string())?;
            let target = crate::memshell::fcgi::FcgiTarget::parse(target_value)?;
            let alive = crate::memshell::fcgi::check(&ctx.settings, &target, script, &token, &name);
            MemoryShell {
                id: uuid::Uuid::new_v4().to_string(),
                workspace_id: workspace_id.clone(),
                shell_id: Some(shell_id.clone()),
                runtime: "php".to_string(),
                kind: crate::memshell::KIND_PHP_FCGI.to_string(),
                name,
                token,
                // endpoint 字段存 FPM 地址，保证句柄自足
                endpoint: target.to_string_value(),
                install_path: script.to_string(),
                artifact: serde_json::json!({
                    "target": target.to_string_value(),
                    "script": script,
                })
                .to_string(),
                status: if alive { "active" } else { "pending" }.to_string(),
                installed_at: now.clone(),
                last_check_at: if alive { Some(now) } else { None },
                last_check_ok: alive,
                uninstall_attempts: 0,
                notes: if alive {
                    "FPM 直连，零落盘、无残留需清理".to_string()
                } else {
                    "FPM 未响应：请确认端口可达、SCRIPT_FILENAME 存在".to_string()
                },
            }
        } else if kind == crate::memshell::KIND_PHP_USER_INI {
            crate::memshell::php_user_ini_preconditions(&info)?;
            let dir = install_dir
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "缺少安装目录".to_string())?;
            let trigger = trigger_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "缺少触发 URL".to_string())?;
            let artifact = crate::memshell::php::install(
                ctx.protocol,
                session.as_ref(),
                &ctx.settings,
                dir,
                &name,
                &token,
            )
            .map_err(|error| format!("注入失败：{error}"))?;
            let alive =
                crate::memshell::php::check(&ctx.settings, trigger, &token, &name);
            MemoryShell {
                id: uuid::Uuid::new_v4().to_string(),
                workspace_id: workspace_id.clone(),
                shell_id: Some(shell_id.clone()),
                runtime: "php".to_string(),
                kind: crate::memshell::KIND_PHP_USER_INI.to_string(),
                name,
                token,
                endpoint: trigger.to_string(),
                install_path: artifact.payload_path.clone(),
                artifact: serde_json::to_string(&artifact).map_err(|error| error.to_string())?,
                status: if alive { "active" } else { "pending" }.to_string(),
                installed_at: now.clone(),
                last_check_at: if alive { Some(now) } else { None },
                last_check_ok: alive,
                uninstall_attempts: 0,
                notes: if alive {
                    String::new()
                } else {
                    "尚未生效：目标 PHP 会缓存 .user.ini（user_ini.cache_ttl，默认 300s），请稍后重试检测"
                        .to_string()
                },
            }
        } else {
            return Err(format!("不支持的内存马形态：{kind}"));
        };

        {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            database
                .insert_memory_shell(&handle)
                .map_err(|error| error.to_string())?;
            database
                .record_audit(
                    Some(&workspace_id),
                    Some(&shell_id),
                    "memshell.inject",
                    if handle.last_check_ok { "success" } else { "pending" },
                    &format!(
                        "形态：{}；目标：{}；位置：{}",
                        handle.kind, handle.endpoint, handle.install_path
                    ),
                )
                .map_err(|error| error.to_string())?;
        }
        Ok(handle)
    })
    .await
}

/// 存活检测。可反复调用（`pending` 状态会因 cache_ttl 过期而转为 active）。
#[tauri::command]
pub async fn memshell_check(handle_id: String, app: AppHandle) -> Result<bool, String> {
    blocking(app, move |state| {
        let (handle, settings) = {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            let handle = database
                .memory_shell(&handle_id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("内存马句柄不存在：{handle_id}"))?;
            let settings = database.get_settings().map_err(|error| error.to_string())?;
            (handle, settings)
        };
        if !settings.http_enabled {
            return Err("真实网络协议未开启，无法检测".to_string());
        }
        let alive = if handle.kind == crate::memshell::KIND_PHP_FCGI {
            let target = crate::memshell::fcgi::FcgiTarget::parse(&handle.endpoint)?;
            crate::memshell::fcgi::check(
                &settings,
                &target,
                &handle.install_path,
                &handle.token,
                &handle.name,
            )
        } else {
            crate::memshell::php::check(&settings, &handle.endpoint, &handle.token, &handle.name)
        };
        let status = if alive {
            "active".to_string()
        } else if handle.status == "orphaned" {
            "orphaned".to_string()
        } else {
            "stale".to_string()
        };
        {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            database
                .update_memory_shell_check(&handle.id, &status, alive)
                .map_err(|error| error.to_string())?;
            database
                .record_audit(
                    Some(&handle.workspace_id),
                    handle.shell_id.as_deref(),
                    "memshell.check",
                    if alive { "success" } else { "failed" },
                    &format!("句柄：{}；状态：{status}", handle.id),
                )
                .map_err(|error| error.to_string())?;
        }
        Ok(alive)
    })
    .await
}

/// 中和内存马。
///
/// - `php_fcgi`：零落盘，无残留，直接标记为已卸载；
/// - `php_user_ini`：改写为无害占位 + 摘除 `.user.ini`。**不删除载荷文件** ——
///   目标 PHP 会缓存 `.user.ini` 的 prepend 路径，文件缺失会让站点在 TTL 内每个
///   请求 500（已实测）。
#[tauri::command]
pub async fn memshell_uninstall(handle_id: String, app: AppHandle) -> Result<String, String> {
    blocking(app, move |state| {
        let (handle, settings) = {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            let handle = database
                .memory_shell(&handle_id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("内存马句柄不存在：{handle_id}"))?;
            let settings = database.get_settings().map_err(|error| error.to_string())?;
            (handle, settings)
        };

        let database = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?;

        if handle.kind == crate::memshell::KIND_PHP_FCGI {
            database
                .update_memory_shell_check(&handle.id, "uninstalled", false)
                .map_err(|error| error.to_string())?;
            database
                .record_audit(
                    Some(&handle.workspace_id),
                    handle.shell_id.as_deref(),
                    "memshell.uninstall",
                    "success",
                    &format!("句柄：{}；FPM 直连形态零落盘，无残留", handle.id),
                )
                .map_err(|error| error.to_string())?;
            return Ok("FPM 直连形态不落盘，已直接关闭记录（目标上无残留）".to_string());
        }

        let outcome =
            crate::memshell::php::uninstall_via_payload(&settings, &handle.endpoint, &handle.token);
        match outcome {
            Ok(()) => {
                database
                    .update_memory_shell_check(&handle.id, "neutered", false)
                    .map_err(|error| error.to_string())?;
                database
                    .record_audit(
                        Some(&handle.workspace_id),
                        handle.shell_id.as_deref(),
                        "memshell.uninstall",
                        "success",
                        &format!(
                            "句柄：{}；载荷已中和，待 user_ini.cache_ttl 过后可删除 {}",
                            handle.id, handle.install_path
                        ),
                    )
                    .map_err(|error| error.to_string())?;
                Ok(
                    "载荷已中和；为免目标站点在缓存窗口内 500，文件暂留，请在 TTL 后清理"
                        .to_string(),
                )
            }
            Err(error) => {
                database
                    .mark_memory_shell_uninstall_failed(&handle.id, "orphaned", &error)
                    .map_err(|inner| inner.to_string())?;
                database
                    .record_audit(
                        Some(&handle.workspace_id),
                        handle.shell_id.as_deref(),
                        "memshell.uninstall",
                        "failed",
                        &format!("句柄：{}；{error}", handle.id),
                    )
                    .map_err(|inner| inner.to_string())?;
                Err(format!("中和失败，句柄已标记为 orphaned：{error}"))
            }
        }
    })
    .await
}

/// 列出内存马句柄（可按 Workspace / Shell 过滤）。
#[tauri::command]
pub async fn memshell_list(
    workspace_id: Option<String>,
    shell_id: Option<String>,
    app: AppHandle,
) -> Result<Vec<MemoryShell>, String> {
    blocking(app, move |state| {
        state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .list_memory_shells(workspace_id.as_deref(), shell_id.as_deref())
            .map_err(|error| error.to_string())
    })
    .await
}

/// 经内存马执行命令（验证通道可用 / 临时取用）。
#[tauri::command]
pub async fn memshell_exec(
    handle_id: String,
    command: String,
    app: AppHandle,
) -> Result<String, String> {
    blocking(app, move |state| {
        let (handle, settings) = {
            let database = state
                .database
                .lock()
                .map_err(|_| "数据库锁异常".to_string())?;
            let handle = database
                .memory_shell(&handle_id)
                .map_err(|error| error.to_string())?
                .ok_or_else(|| format!("内存马句柄不存在：{handle_id}"))?;
            let settings = database.get_settings().map_err(|error| error.to_string())?;
            (handle, settings)
        };
        if !settings.http_enabled {
            return Err("真实网络协议未开启".to_string());
        }
        let output = if handle.kind == crate::memshell::KIND_PHP_FCGI {
            let target = crate::memshell::fcgi::FcgiTarget::parse(&handle.endpoint)?;
            crate::memshell::fcgi::exec(
                &settings,
                &target,
                &handle.install_path,
                &handle.token,
                &handle.name,
                &command,
            )?
        } else {
            crate::memshell::php::exec(&settings, &handle.endpoint, &handle.token, &command)?
        };
        state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .record_audit(
                Some(&handle.workspace_id),
                handle.shell_id.as_deref(),
                "memshell.exec",
                "success",
                &format!(
                    "句柄：{}；命令：{}",
                    handle.id,
                    truncate_chars(&command, 200)
                ),
            )
            .map_err(|error| error.to_string())?;
        Ok(output)
    })
    .await
}

// ---------------------------------------------------------------------------
// 批量与多目标编排
//
// 设计取向：编排放在后端，以保证会话生命周期可控（只断开自己建立的会话）、
// 并发受限、审计可汇总；每个目标的授权检查仍由 require_authorized_for 逐个完成。
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrchestrationSpec {
    pub shell_ids: Vec<String>,
    pub op: OrchestrationOp,
    #[serde(default = "default_orchestration_concurrency")]
    pub concurrency: u32,
    #[serde(default)]
    pub stop_on_error: bool,
    #[serde(default = "default_true")]
    pub auto_connect: bool,
    #[serde(default)]
    pub disconnect_after: bool,
}

#[derive(serde::Deserialize)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum OrchestrationOp {
    Command {
        command: String,
    },
    Plugin {
        plugin_id: String,
        #[serde(default)]
        params: serde_json::Value,
    },
    ListDir {
        path: String,
    },
}

fn default_orchestration_concurrency() -> u32 {
    4
}

fn default_true() -> bool {
    true
}

fn orchestration_op_label(op: &OrchestrationOp) -> String {
    match op {
        OrchestrationOp::Command { command } => format!("命令：{}", truncate_chars(command, 80)),
        OrchestrationOp::Plugin { plugin_id, .. } => format!("插件：{plugin_id}"),
        OrchestrationOp::ListDir { path } => format!("列目录：{path}"),
    }
}

fn execute_orchestration_op(
    state: &AppState,
    session_id: &str,
    shell: &ShellProfile,
    settings: &AppSettings,
    op: &OrchestrationOp,
) -> Result<String, String> {
    let (session_state, protocol_id) = {
        let mut sessions = state
            .sessions
            .lock()
            .map_err(|_| "会话锁异常".to_string())?;
        let session = sessions.get_mut(session_id)?;
        (session.state.clone(), session.protocol_id.clone())
    };
    let protocol = state
        .protocols
        .get(&protocol_id)
        .ok_or_else(|| format!("未知协议：{protocol_id}"))?;
    match op {
        OrchestrationOp::Command { command } => protocol
            .execute_command(session_state.as_ref(), command, settings)
            .map(|output| output.stdout)
            .map_err(|error| error.to_string()),
        OrchestrationOp::ListDir { path } => protocol
            .list_dir(session_state.as_ref(), path, settings)
            .map(|listing| serde_json::to_string(&listing).unwrap_or_default())
            .map_err(|error| error.to_string()),
        OrchestrationOp::Plugin { plugin_id, params } => {
            let plugin = {
                let registry = state
                    .feature_plugins
                    .lock()
                    .map_err(|_| "插件注册表锁异常".to_string())?;
                registry
                    .get(plugin_id)
                    .ok_or_else(|| format!("未知功能插件：{plugin_id}"))?
                    .clone()
            };
            let runtime = if shell.runtime.is_empty() {
                "php"
            } else {
                shell.runtime.as_str()
            };
            plugin
                .execute(protocol, session_state.as_ref(), runtime, params, settings)
                .map(|value| value.to_string())
                .map_err(|error| error.to_string())
        }
    }
}

fn run_orchestration_target(
    state: &AppState,
    shell_id: &str,
    spec: &OrchestrationSpec,
) -> serde_json::Value {
    let started = std::time::Instant::now();
    let mut created_session = false;
    let mut session_id_opt: Option<String> = None;

    let result = (|| -> Result<(String, String), String> {
        let (shell, settings) = load_shell_and_settings(state, shell_id)?;
        require_authorized_for(state, &shell, &settings)?;
        let existing = {
            let sessions = state
                .sessions
                .lock()
                .map_err(|_| "会话锁异常".to_string())?;
            sessions.session_id_for_profile(&shell.id)
        };
        let session_id = match existing {
            Some(id) => id,
            None => {
                if !spec.auto_connect {
                    return Err("目标未连接，且未开启自动连接".to_string());
                }
                let (_result, id) = connect_shell_impl(state, &shell.id)?;
                created_session = true;
                id
            }
        };
        session_id_opt = Some(session_id.clone());
        let output = execute_orchestration_op(state, &session_id, &shell, &settings, &spec.op)?;
        Ok((shell.name.clone(), output))
    })();

    // 只断开本次任务自己建立的会话，绝不碰用户手动建立的会话
    if created_session
        && spec.disconnect_after
        && let Some(session_id) = &session_id_opt
        && let Ok(mut sessions) = state.sessions.lock()
    {
        sessions.remove(session_id);
    }

    let elapsed_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok((name, output)) => serde_json::json!({
            "shellId": shell_id,
            "shellName": name,
            "ok": true,
            "elapsedMs": elapsed_ms,
            "output": truncate_chars(&output, 4000),
            "error": "",
        }),
        Err(error) => serde_json::json!({
            "shellId": shell_id,
            "shellName": shell_id,
            "ok": false,
            "elapsedMs": elapsed_ms,
            "output": "",
            "error": error,
        }),
    }
}

fn orchestrate_run_impl(
    state: &AppState,
    spec: OrchestrationSpec,
) -> Result<serde_json::Value, String> {
    if spec.shell_ids.is_empty() {
        return Err("请至少选择一个目标 Shell".to_string());
    }
    if spec.shell_ids.len() > 200 {
        return Err("单次最多 200 个目标".to_string());
    }
    let workers = (spec.concurrency as usize)
        .clamp(1, 8)
        .min(spec.shell_ids.len());
    let stop = std::sync::atomic::AtomicBool::new(false);

    let outcomes: Vec<serde_json::Value> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for worker in 0..workers {
            let ids = &spec.shell_ids;
            let spec_ref = &spec;
            let stop_ref = &stop;
            handles.push(scope.spawn(move || {
                let mut local = Vec::new();
                let mut index = worker;
                while index < ids.len() {
                    if stop_ref.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    let outcome = run_orchestration_target(state, &ids[index], spec_ref);
                    if spec_ref.stop_on_error && outcome["ok"] == false {
                        stop_ref.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    local.push(outcome);
                    index += workers;
                }
                local
            }));
        }
        let mut all = Vec::new();
        for handle in handles {
            if let Ok(items) = handle.join() {
                all.extend(items);
            }
        }
        all
    });

    // 按输入顺序输出，便于前端对齐
    let mut ordered = Vec::with_capacity(spec.shell_ids.len());
    for id in &spec.shell_ids {
        if let Some(item) = outcomes.iter().find(|item| item["shellId"] == *id) {
            ordered.push(item.clone());
        }
    }
    let ok = ordered.iter().filter(|item| item["ok"] == true).count();
    let failed = ordered.len() - ok;

    if let Ok(database) = state.database.lock() {
        let _ = database.record_audit(
            None,
            None,
            "orchestrate.run",
            if failed == 0 { "success" } else { "partial" },
            &format!(
                "{}；目标 {}，成功 {ok}，失败 {failed}",
                orchestration_op_label(&spec.op),
                spec.shell_ids.len()
            ),
        );
        // 只为失败目标写明细，避免 N 个成功目标淹没审计表
        for item in &ordered {
            if item["ok"] == false {
                let _ = database.record_audit(
                    None,
                    None,
                    "orchestrate.target",
                    "failed",
                    &format!(
                        "目标 {}：{}",
                        item["shellId"].as_str().unwrap_or(""),
                        item["error"].as_str().unwrap_or("")
                    ),
                );
            }
        }
    }

    Ok(serde_json::json!({
        "total": ordered.len(),
        "ok": ok,
        "failed": failed,
        "outcomes": ordered,
    }))
}

/// 批量执行：命令 / 功能插件 / 列目录（多目标）。
#[tauri::command]
pub async fn orchestrate_run(
    spec: OrchestrationSpec,
    app: AppHandle,
) -> Result<serde_json::Value, String> {
    blocking(app, move |state| orchestrate_run_impl(state, spec)).await
}

// ---------------------------------------------------------------------------
// 多跳代理链
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyHopSpec {
    /// 该跳对应的 Shell（用于逐个做授权复查与审计）。
    pub shell_id: String,
    /// 从前一跳看该 SOCKS5 的地址（第一跳是从操作机看）。
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyChainSpec {
    pub hops: Vec<ProxyHopSpec>,
    /// 本地监听端口，0 = 随机。
    #[serde(default)]
    pub local_port: u16,
    /// 固定转发目标；留空则为动态 SOCKS5（客户端自行指定目标）。
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
}

/// 启动多跳代理链，返回本地 SOCKS5 地址。
#[tauri::command]
pub async fn proxy_chain_start(
    spec: ProxyChainSpec,
    app: AppHandle,
) -> Result<serde_json::Value, String> {
    blocking(app, move |state| {
        if spec.hops.is_empty() {
            return Err("请至少配置一跳".to_string());
        }
        if spec.hops.len() > 8 {
            return Err("代理链最多 8 跳".to_string());
        }
        let settings = state
            .database
            .lock()
            .map_err(|_| "数据库锁异常".to_string())?
            .get_settings()
            .map_err(|error| error.to_string())?;
        if !settings.http_enabled {
            return Err("真实网络协议未开启".to_string());
        }

        // 每一跳都必须通过授权复查（与其它目标操作同一把尺子）
        let mut hops = Vec::with_capacity(spec.hops.len());
        for hop in &spec.hops {
            let (shell, settings) = load_shell_and_settings(state, &hop.shell_id)?;
            require_authorized_for(state, &shell, &settings)?;
            hops.push(crate::proxy_chain::ChainHop {
                host: hop.host.clone(),
                port: hop.port,
                auth: match (&hop.username, &hop.password) {
                    (Some(user), Some(pass)) if !user.is_empty() => {
                        Some((user.clone(), pass.clone()))
                    }
                    _ => None,
                },
            });
        }

        let fixed = match (&spec.target_host, spec.target_port) {
            (Some(host), Some(port)) if !host.trim().is_empty() => {
                Some((host.trim().to_string(), port))
            }
            _ => None,
        };
        let timeout = std::time::Duration::from_secs(settings.default_timeout_secs.clamp(1, 300));
        let chain =
            crate::proxy_chain::start_local_listener(hops, fixed, spec.local_port, timeout)?;
        let chain_id = uuid::Uuid::new_v4().to_string();
        let local_addr = chain.addr();
        state
            .proxy_chains
            .lock()
            .map_err(|_| "代理链注册表锁异常".to_string())?
            .insert(chain_id.clone(), chain);

        if let Ok(database) = state.database.lock() {
            let _ = database.record_audit(
                None,
                None,
                "proxy.chain.start",
                "success",
                &format!("链路：{chain_id}；{local_addr}；{} 跳", spec.hops.len()),
            );
        }
        Ok(serde_json::json!({
            "chainId": chain_id,
            "localAddr": local_addr,
            "hops": spec.hops.len(),
        }))
    })
    .await
}

#[tauri::command]
pub async fn proxy_chain_stop(chain_id: String, app: AppHandle) -> Result<(), String> {
    blocking(app, move |state| {
        let chain = state
            .proxy_chains
            .lock()
            .map_err(|_| "代理链注册表锁异常".to_string())?
            .remove(&chain_id)
            .ok_or_else(|| format!("代理链不存在：{chain_id}"))?;
        chain.stop();
        if let Ok(database) = state.database.lock() {
            let _ = database.record_audit(
                None,
                None,
                "proxy.chain.stop",
                "success",
                &format!("链路：{chain_id}"),
            );
        }
        Ok(())
    })
    .await
}

#[tauri::command]
pub async fn proxy_chain_list(app: AppHandle) -> Result<Vec<serde_json::Value>, String> {
    blocking(app, move |state| {
        let chains = state
            .proxy_chains
            .lock()
            .map_err(|_| "代理链注册表锁异常".to_string())?;
        Ok(chains
            .iter()
            .map(|(id, chain)| serde_json::json!({ "chainId": id, "localAddr": chain.addr() }))
            .collect())
    })
    .await
}

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
            proxy_chains: Mutex::new(std::collections::HashMap::new()),
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
            false,
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
            false,
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
            false,
        );
        assert!(result.is_err(), "非法 URL 应报错");
    }

    /// 回归：登记前的连通性测试此前只检查全局开关，可探测任意主机（SSRF）。
    ///
    /// 用 TEST-NET-1（192.0.2.1，RFC 5737 黑洞地址）避免依赖真实外网；
    /// 超时压到 1 秒，保证用例快速失败。
    #[test]
    fn test_connection_requires_scope_unless_overridden() {
        let enable_network = |state: &AppState| {
            state
                .database
                .lock()
                .unwrap()
                .update_settings(&AppSettings {
                    http_enabled: true,
                    default_timeout_secs: 1,
                    ..AppSettings::default()
                })
                .unwrap();
        };

        // 开启真实网络但没有 Workspace → 必须被范围校验拒绝
        let state = app_state();
        enable_network(&state);
        let denied = test_connection_impl(
            &state,
            "http://192.0.2.1/shell.php",
            "secret",
            "builtin.php.v1",
            None,
            None,
            false,
        );
        let message = denied.unwrap_err();
        assert!(
            message.contains("不在任何 Workspace"),
            "越界目标应被范围校验拒绝：{message}"
        );

        // 显式覆盖 → 通过范围校验，仅因目标不可达而失败（错误不应再是范围拒绝）
        let state2 = app_state();
        enable_network(&state2);
        let overridden = test_connection_impl(
            &state2,
            "http://192.0.2.1/shell.php",
            "secret",
            "builtin.php.v1",
            None,
            None,
            true,
        );
        let err = overridden.expect_err("不可达目标应连接失败");
        assert!(
            !err.contains("不在任何 Workspace"),
            "显式覆盖后不应再被范围拒绝：{err}"
        );
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

    /// 回归：本地路径策略（此前只拒 POSIX 前缀，Windows 上等于没有校验）。
    #[test]
    fn sanitize_local_path_enforces_policy() {
        let state = app_state();

        // 相对路径一律拒绝
        assert!(sanitize_local_path(&state, "relative.txt", false).is_err());
        // UNC / 设备路径拒绝
        assert!(sanitize_local_path(&state, r"\\server\share\a.txt", false).is_err());
        assert!(sanitize_local_path(&state, r"\\?\C:\Windows\win.ini", false).is_err());
        // 备用数据流（ADS）拒绝
        let ads = std::env::temp_dir().join("dosword-ads:secret");
        let err = sanitize_local_path(&state, &ads.to_string_lossy(), true).unwrap_err();
        assert!(err.contains("ADS"), "{err}");

        // 系统临时目录属于默认允许根
        let writable = std::env::temp_dir().join("dosword-policy-write.txt");
        assert!(
            sanitize_local_path(&state, &writable.to_string_lossy(), true).is_ok(),
            "临时目录应在默认允许范围内"
        );

        // 读取必须是已存在的普通文件
        let missing = std::env::temp_dir().join("dosword-policy-missing.txt");
        let _ = std::fs::remove_file(&missing);
        assert!(sanitize_local_path(&state, &missing.to_string_lossy(), false).is_err());
        std::fs::write(&missing, b"x").unwrap();
        assert!(sanitize_local_path(&state, &missing.to_string_lossy(), false).is_ok());
        let _ = std::fs::remove_file(&missing);

        // 目录不能当作文件读取
        let dir = std::env::temp_dir();
        assert!(sanitize_local_path(&state, &dir.to_string_lossy(), false).is_err());

        // 系统目录始终拒绝（写入路径按父目录判定）
        #[cfg(windows)]
        if let Ok(root) = std::env::var("SystemRoot") {
            let target = std::path::Path::new(&root).join("dosword-should-not-write.txt");
            let err = sanitize_local_path(&state, &target.to_string_lossy(), true).unwrap_err();
            assert!(err.contains("系统目录"), "{err}");
        }
        #[cfg(not(windows))]
        assert!(sanitize_local_path(&state, "/etc/dosword-test", true).is_err());
    }

    /// 回归：插件参数摘要曾用 `&s[..64]`（字节切片）截断，中文等多字节字符
    /// 落在第 64 字节中间会 panic；release `panic="abort"` 会终止整个进程。
    #[test]
    fn truncate_chars_never_splits_multibyte() {
        // 62 个 ASCII + 中文：第 64 字节落在「中」的中间（旧实现此处 panic）
        let value = format!("{}中文测试", "a".repeat(62));
        let out = truncate_chars(&value, 64);
        assert!(out.ends_with('…'), "超长应截断：{out}");
        assert_eq!(out.chars().count(), 65, "64 字符 + 省略号");

        // 纯中文（每字符 3 字节）
        let chinese = "中".repeat(100);
        assert_eq!(truncate_chars(&chinese, 64).chars().count(), 65);

        // 恰好 64 字符不截断、无省略号
        let exact = "b".repeat(64);
        assert_eq!(truncate_chars(&exact, 64), exact);

        // 空串与多字节边界
        assert_eq!(truncate_chars("", 64), "");
        assert_eq!(truncate_chars("中文", 64), "中文");
    }

    /// 回归：上传分块曾用 `&content_b64[a..b]`（字节切片），非 ASCII 输入 panic。
    #[test]
    fn base64_slice_rejects_non_ascii_instead_of_panicking() {
        // 合法 ASCII 分块照常返回
        assert_eq!(base64_slice("QUJDRA==", 0, 4).unwrap(), "QUJD");
        assert_eq!(base64_slice("QUJDRA==", 4, 8).unwrap(), "RA==");
        // 多字节字符边界 → 显式错误而非 panic
        let cjk = "中文中文";
        assert!(base64_slice(cjk, 0, 2).is_err(), "非字符边界必须报错");
        assert!(base64_slice(cjk, 1, 3).is_err());
        // 越界同样报错
        assert!(base64_slice("QUJD", 0, 99).is_err());
        // 整串区间（0..len）永远是合法字符边界，不应报错
        assert_eq!(base64_slice(cjk, 0, cjk.len()).unwrap(), cjk);
    }
}
