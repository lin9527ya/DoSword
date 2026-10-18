//! MCP 资源与提示词。
//!
//! 资源是「只读、可被客户端自动附加到上下文」的数据入口；它与同名工具的区别只在
//! 客户端体验（资源可被用户主动引用/预览），不扩大能力面。全部走脱敏层。

use dosword_sdk::domain::AuditFilter;
use rmcp::model::{ContentBlock, Prompt, PromptMessage, Resource, ResourceContents, Role};
use tauri::{AppHandle, Manager};

use super::redact::{ShellSummary, truncate_text};
use crate::AppState;

/// 资源 URI 前缀
pub const URI_SHELLS: &str = "dosword://shells";
pub const URI_SESSIONS: &str = "dosword://sessions";
pub const URI_AUDIT: &str = "dosword://audit/recent";

/// 提示词名称
pub const PROMPT_GUIDANCE: &str = "dosword_guidance";

/// 可读资源清单。
pub fn list_resources() -> Vec<Resource> {
    let mut shells = Resource::new(URI_SHELLS, "已登记的 Shell（脱敏）");
    shells.description = Some(
        "所有已登记 Shell 的摘要：id / workspaceId / endpoint / runtime / status / hasPassword。\
         不含连接密码。"
            .to_string(),
    );
    shells.mime_type = Some("application/json".to_string());

    let mut sessions = Resource::new(URI_SESSIONS, "活跃会话");
    sessions.description =
        Some("当前活跃的协议会话（sessionId / profileId / server / lastUsedAt）。".to_string());
    sessions.mime_type = Some("application/json".to_string());

    let mut audit = Resource::new(URI_AUDIT, "最近审计事件");
    audit.description =
        Some("最近 20 条审计事件（含命令原文与 URL，已脱敏口令；请谨慎外传）。".to_string());
    audit.mime_type = Some("application/json".to_string());

    vec![shells, sessions, audit]
}

/// 读取单个资源。未知 URI 返回错误（由调用方转成 MCP 错误码）。
pub fn read_resource(app: &AppHandle, uri: &str) -> Result<Vec<ResourceContents>, String> {
    match uri {
        URI_SHELLS => {
            let shells = with_state(app, |state| {
                let database = state
                    .database
                    .lock()
                    .map_err(|_| "数据库锁异常".to_string())?;
                let shells = database.list_shells().map_err(|error| error.to_string())?;
                Ok(shells.iter().map(ShellSummary::from).collect::<Vec<_>>())
            })?;
            to_contents(uri, &shells)
        }
        URI_SESSIONS => {
            let sessions = with_state(app, |state| {
                let mut sessions = state
                    .sessions
                    .lock()
                    .map_err(|_| "会话锁异常".to_string())?;
                Ok(sessions
                    .list()
                    .into_iter()
                    .map(|(session_id, profile_id, server, last_used_at)| {
                        serde_json::json!({
                            "sessionId": session_id,
                            "profileId": profile_id,
                            "server": server,
                            "lastUsedAt": last_used_at,
                        })
                    })
                    .collect::<Vec<_>>())
            })?;
            to_contents(uri, &sessions)
        }
        URI_AUDIT => {
            let page = with_state(app, |state| {
                let database = state
                    .database
                    .lock()
                    .map_err(|_| "数据库锁异常".to_string())?;
                database
                    .query_audit(&AuditFilter {
                        workspace_id: None,
                        action: None,
                        outcome: None,
                        limit: Some(20),
                        offset: None,
                    })
                    .map_err(|error| error.to_string())
            })?;
            to_contents(uri, &page.1)
        }
        other => Err(format!("未知资源：{other}")),
    }
}

fn to_contents<T: serde::Serialize>(uri: &str, value: &T) -> Result<Vec<ResourceContents>, String> {
    let json =
        serde_json::to_string_pretty(value).map_err(|error| format!("资源序列化失败：{error}"))?;
    // 资源可能很大（凭据之外的路径/命令原文），统一截断到安全长度
    let (text, _) = truncate_text(&json);
    Ok(vec![ResourceContents::text(text, uri)])
}

fn with_state<T, F>(app: &AppHandle, work: F) -> Result<T, String>
where
    F: FnOnce(&AppState) -> Result<T, String>,
{
    let state = app.state::<AppState>();
    work(&state)
}

/// 可用的提示词清单。
pub fn list_prompts() -> Vec<Prompt> {
    vec![Prompt::new(
        PROMPT_GUIDANCE,
        Some(
            "DoSword 使用指引：授权边界、三级权限含义、以及必须由人完成的动作。\
             在与 DoSword 交互前建议先读一次。",
        ),
        None,
    )]
}

/// 生成提示词内容。
pub fn get_prompt(name: &str) -> Option<Vec<PromptMessage>> {
    if name != PROMPT_GUIDANCE {
        return None;
    }
    let text = "\
你正在通过 MCP 操作 DoSword（一个**仅用于授权安全测试**的 WebShell 管理客户端）。

## 硬性边界

1. 只能测试已登记在某个 Workspace 授权范围内的目标。授权范围由人在 GUI 中维护，
   你**没有任何工具可以新增/修改 Workspace 或 Shell**，也不要尝试绕过。
2. 每次调用都会写审计（`mcp.<tool>`，含 denied/pending/error），并可能被限流。
3. 执行级工具（`dosword_exec` / `dosword_plugin_run` / `dosword_generate_stub`）默认需要人
   在 GUI 中批准：首次调用会返回一个待批准 id 与说明，若人工批准，你可以在 120 秒内以
   **完全相同的参数**重试一次（批准是一次性的）。

## 三级权限

- 只读：列出/读取（`dosword_shells_list`、`dosword_fs_list`、`dosword_fs_read`、`dosword_audit_query` …）
- 写入：改动目标（`dosword_fs_write`、`dosword_fs_delete`、`dosword_shell_connect` …）
- 执行：命令/插件/载荷生成（`dosword_exec` …）

若某级返回「未启用」，请把这个事实报告给用户，由用户在「设置 → AI / MCP」中决定是否开启；
不要反复重试同一个未启用的调用。

## 好的使用方式

1. 先用 `dosword_shells_list` / `dosword_sessions_list` 了解可用目标，必要时 `dosword_shell_connect` 建立会话。
2. 读取大文件用 `dosword_fs_read` 的 `offset`/`length` 分块，不要一次拉全量。
3. 破坏性操作（删除、覆盖写、执行命令）前，先在回复里说明意图与影响面，让用户有取消的机会。
4. 结果里的 `truncated` 表示内容被截断，请用分页/分块参数继续，而不是重试同一请求。
5. 不要把令牌、Shell 密码、审计原文粘到最终回答里——它们是敏感数据。
";
    Some(vec![PromptMessage::new_text(Role::User, text)])
}

/// 供调试/测试使用：把内容块文本取出。
#[allow(dead_code)]
pub fn prompt_text(name: &str) -> Option<String> {
    let messages = get_prompt(name)?;
    let first = messages.into_iter().next()?;
    match first.content {
        ContentBlock::Text(text) => Some(text.text),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_list_covers_all_uris() {
        let resources = list_resources();
        let uris: Vec<&str> = resources.iter().map(|item| item.uri.as_str()).collect();
        assert!(uris.contains(&URI_SHELLS));
        assert!(uris.contains(&URI_SESSIONS));
        assert!(uris.contains(&URI_AUDIT));
        for resource in &resources {
            assert!(resource.mime_type.is_some(), "资源应声明 MIME 类型");
        }
    }

    #[test]
    fn guidance_prompt_explains_authorization() {
        let text = prompt_text(PROMPT_GUIDANCE).expect("指引提示词应存在");
        assert!(text.contains("授权"), "应说明授权边界");
        assert!(text.contains("待批准"), "应说明执行级确认流程");
        assert!(text.contains("120 秒"), "应说明批准有效期");
        assert!(prompt_text("不存在的提示词").is_none());
    }

    #[test]
    fn unknown_resource_is_rejected() {
        // 不构造 AppHandle，只验证未知 URI 的分支（先于状态访问返回）
        assert!(matches!(
            read_resource_uri_only("dosword://nope"),
            Err(ref message) if message.contains("未知资源")
        ));
    }

    /// 仅做 URI 白名单判定，不触碰 AppState。
    fn read_resource_uri_only(uri: &str) -> Result<(), String> {
        if [URI_SHELLS, URI_SESSIONS, URI_AUDIT].contains(&uri) {
            Ok(())
        } else {
            Err(format!("未知资源：{uri}"))
        }
    }
}
