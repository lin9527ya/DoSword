use std::path::Path;

use chrono::{Local, NaiveDate, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use dosword_sdk::domain::{
    AppSettings, AuditEvent, AuditFilter, CreateShell, CreateWorkspace, Dashboard, ShellProfile,
    UpdateShell, UpdateWorkspace, Workspace,
};

/// 迁移脚本：`MIGRATIONS[i]` 把数据库从 user_version i 升级到 i+1。
/// 新增迁移时**追加**到数组末尾，不要修改已发布的条目。
const MIGRATIONS: &[&str] = &[
    // v1: 第一阶段初始结构（workspaces / shell_profiles / audit_events）
    "CREATE TABLE workspaces (
       id TEXT PRIMARY KEY,
       name TEXT NOT NULL,
       authorization_scope TEXT NOT NULL,
       expires_at TEXT,
       created_at TEXT NOT NULL
     );
     CREATE TABLE shell_profiles (
       id TEXT PRIMARY KEY,
       workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
       name TEXT NOT NULL,
       endpoint TEXT NOT NULL,
       runtime TEXT NOT NULL,
       protocol_id TEXT NOT NULL,
       status TEXT NOT NULL,
       last_connected_at TEXT,
       created_at TEXT NOT NULL
     );
     CREATE TABLE audit_events (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
       shell_id TEXT REFERENCES shell_profiles(id) ON DELETE SET NULL,
       action TEXT NOT NULL,
       outcome TEXT NOT NULL,
       detail TEXT NOT NULL,
       created_at TEXT NOT NULL
     );",
    // v2: 第二阶段 — 协议参数列 + 全局设置表
    "ALTER TABLE shell_profiles ADD COLUMN password TEXT NOT NULL DEFAULT '';
     ALTER TABLE shell_profiles ADD COLUMN protocol_params TEXT NOT NULL DEFAULT '{}';
     ALTER TABLE shell_profiles ADD COLUMN authorization_ack INTEGER NOT NULL DEFAULT 0;
     CREATE TABLE app_settings (
       key TEXT PRIMARY KEY,
       value TEXT NOT NULL
     );",
    // v3: 审计事件不再强制归属 Workspace（设置变更等系统级事件可空），
    //     删除 Workspace 时保留审计记录并置空归属。
    "CREATE TABLE audit_events_new (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       workspace_id TEXT REFERENCES workspaces(id) ON DELETE SET NULL,
       shell_id TEXT REFERENCES shell_profiles(id) ON DELETE SET NULL,
       action TEXT NOT NULL,
       outcome TEXT NOT NULL,
       detail TEXT NOT NULL,
       created_at TEXT NOT NULL
     );
     INSERT INTO audit_events_new (id, workspace_id, shell_id, action, outcome, detail, created_at)
       SELECT id, workspace_id, shell_id, action, outcome, detail, created_at FROM audit_events;
     DROP TABLE audit_events;
     ALTER TABLE audit_events_new RENAME TO audit_events;",
    // v4: Shell 标签（JSON 数组字符串，如 ["web","test"]）
    "ALTER TABLE shell_profiles ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';",
];

const SETTINGS_KEY: &str = "app";

/// 规范化授权到期时间：前端日期输入是 `YYYY-MM-DD`，而授权校验用 RFC3339。
/// 纯日期转成当天 23:59:59 + 本地时区（到期日当天仍有效）；已是 RFC3339 的原样保留。
fn normalize_expiry(expires_at: Option<String>) -> Option<String> {
    let value = expires_at?;
    let is_date_only = value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-');
    if is_date_only {
        if let Some(dt) = NaiveDate::parse_from_str(&value, "%Y-%m-%d")
            .ok()
            .and_then(|date| date.and_hms_opt(23, 59, 59))
            .and_then(|naive| naive.and_local_timezone(Local).single())
        {
            return Some(dt.to_rfc3339());
        }
    }
    Some(value)
}

pub struct Database {
    connection: Connection,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let mut connection = Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;",
        )?;
        migrate(&mut connection)?;
        Ok(Self { connection })
    }

    pub fn dashboard(&self) -> rusqlite::Result<Dashboard> {
        Ok(Dashboard {
            workspaces: self.list_workspaces()?,
            shells: self.list_shells()?,
            audit_events: self.list_audit_events()?,
        })
    }

    pub fn create_workspace(&mut self, input: CreateWorkspace) -> rusqlite::Result<Workspace> {
        let workspace = Workspace {
            id: Uuid::new_v4().to_string(),
            name: input.name,
            authorization_scope: input.authorization_scope,
            expires_at: normalize_expiry(input.expires_at),
            created_at: Utc::now().to_rfc3339(),
        };
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO workspaces (id, name, authorization_scope, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                workspace.id,
                workspace.name,
                workspace.authorization_scope,
                workspace.expires_at,
                workspace.created_at
            ],
        )?;
        transaction.execute(
            "INSERT INTO audit_events (workspace_id, action, outcome, detail, created_at)
             VALUES (?1, 'workspace.create', 'success', 'Workspace created', ?2)",
            params![workspace.id, Utc::now().to_rfc3339()],
        )?;
        transaction.commit()?;
        Ok(workspace)
    }

    pub fn create_shell(
        &mut self,
        input: CreateShell,
        protocol_id: &str,
    ) -> rusqlite::Result<ShellProfile> {
        let profile = ShellProfile {
            id: Uuid::new_v4().to_string(),
            workspace_id: input.workspace_id,
            name: input.name,
            endpoint: input.endpoint,
            runtime: input.runtime,
            protocol_id: protocol_id.into(),
            password: input.password.unwrap_or_default(),
            protocol_params: input.protocol_params.unwrap_or_else(|| "{}".into()),
            authorization_ack: input.confirm_network,
            status: "unknown".into(),
            last_connected_at: None,
            created_at: Utc::now().to_rfc3339(),
            tags: input.tags.unwrap_or_default(),
        };
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO shell_profiles
             (id, workspace_id, name, endpoint, runtime, protocol_id, password, protocol_params,
              authorization_ack, status, created_at, tags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                profile.id,
                profile.workspace_id,
                profile.name,
                profile.endpoint,
                profile.runtime,
                profile.protocol_id,
                profile.password,
                profile.protocol_params,
                profile.authorization_ack,
                profile.status,
                profile.created_at,
                serde_json::to_string(&profile.tags).unwrap_or_else(|_| "[]".into()),
            ],
        )?;
        transaction.execute(
            "INSERT INTO audit_events (workspace_id, shell_id, action, outcome, detail, created_at)
             VALUES (?1, ?2, 'shell.create', 'success', 'Shell profile created', ?3)",
            params![profile.workspace_id, profile.id, Utc::now().to_rfc3339()],
        )?;
        transaction.commit()?;
        Ok(profile)
    }

    pub fn shell(&self, id: &str) -> rusqlite::Result<Option<ShellProfile>> {
        self.connection
            .query_row(
                "SELECT id, workspace_id, name, endpoint, runtime, protocol_id, password,
                        protocol_params, authorization_ack, status, last_connected_at, created_at,
                        tags
                 FROM shell_profiles WHERE id = ?1",
                [id],
                map_shell,
            )
            .optional()
    }

    pub fn update_workspace(&self, input: &UpdateWorkspace) -> rusqlite::Result<Workspace> {
        self.connection.execute(
            "UPDATE workspaces SET name = ?1, authorization_scope = ?2, expires_at = ?3
             WHERE id = ?4",
            params![
                input.name,
                input.authorization_scope,
                normalize_expiry(input.expires_at.clone()),
                input.id
            ],
        )?;
        self.workspace(&input.id)?.ok_or_else(|| {
            rusqlite::Error::QueryReturnedNoRows
        })
    }

    pub fn delete_workspace(&self, id: &str) -> rusqlite::Result<()> {
        self.connection
            .execute("DELETE FROM workspaces WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn update_shell(&self, input: &UpdateShell) -> rusqlite::Result<ShellProfile> {
        if let Some(tags) = &input.tags {
            self.connection.execute(
                "UPDATE shell_profiles SET name = ?1, endpoint = ?2, password = ?3, tags = ?4
                 WHERE id = ?5",
                params![
                    input.name,
                    input.endpoint,
                    input.password.clone().unwrap_or_default(),
                    serde_json::to_string(tags).unwrap_or_else(|_| "[]".into()),
                    input.id
                ],
            )?;
        } else {
            self.connection.execute(
                "UPDATE shell_profiles SET name = ?1, endpoint = ?2, password = ?3 WHERE id = ?4",
                params![
                    input.name,
                    input.endpoint,
                    input.password.clone().unwrap_or_default(),
                    input.id
                ],
            )?;
        }
        self.shell(&input.id)?.ok_or_else(|| {
            rusqlite::Error::QueryReturnedNoRows
        })
    }

    pub fn delete_shell(&self, id: &str) -> rusqlite::Result<()> {
        self.connection
            .execute("DELETE FROM shell_profiles WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn workspace(&self, id: &str) -> rusqlite::Result<Option<Workspace>> {
        self.connection
            .query_row(
                "SELECT id, name, authorization_scope, expires_at, created_at
                 FROM workspaces WHERE id = ?1",
                [id],
                |row| {
                    Ok(Workspace {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        authorization_scope: row.get(2)?,
                        expires_at: row.get(3)?,
                        created_at: row.get(4)?,
                    })
                },
            )
            .optional()
    }

    /// 更新 Shell 状态（online / error）与最近连接时间。
    pub fn update_shell_status(&self, id: &str, status: &str) -> rusqlite::Result<()> {
        self.connection.execute(
            "UPDATE shell_profiles SET status = ?1, last_connected_at = datetime('now')
             WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    pub fn record_probe(
        &self,
        shell: &ShellProfile,
        outcome: &str,
        detail: &str,
    ) -> rusqlite::Result<()> {
        let now = Utc::now().to_rfc3339();
        self.connection.execute(
            "UPDATE shell_profiles SET status = ?1, last_connected_at = ?2 WHERE id = ?3",
            params![outcome, now, shell.id],
        )?;
        self.connection.execute(
            "INSERT INTO audit_events (workspace_id, shell_id, action, outcome, detail, created_at)
             VALUES (?1, ?2, 'shell.probe', ?3, ?4, ?5)",
            params![shell.workspace_id, shell.id, outcome, detail, now],
        )?;
        Ok(())
    }

    /// 记录一条通用审计事件（会话操作 / 文件操作 / 设置变更等）。
    /// `workspace_id` 为 None 时表示系统级事件（如设置变更）。
    pub fn record_audit(
        &self,
        workspace_id: Option<&str>,
        shell_id: Option<&str>,
        action: &str,
        outcome: &str,
        detail: &str,
    ) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO audit_events (workspace_id, shell_id, action, outcome, detail, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                workspace_id,
                shell_id,
                action,
                outcome,
                detail,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    // --- 设置 ---

    pub fn get_settings(&self) -> rusqlite::Result<AppSettings> {
        let value: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM app_settings WHERE key = ?1",
                [SETTINGS_KEY],
                |row| row.get(0),
            )
            .optional()?;
        match value {
            Some(json) => serde_json::from_str(&json)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error))),
            None => Ok(AppSettings::default()),
        }
    }

    pub fn update_settings(&self, settings: &AppSettings) -> rusqlite::Result<()> {
        let json = serde_json::to_string(settings)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        self.connection.execute(
            "INSERT INTO app_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![SETTINGS_KEY, json],
        )?;
        Ok(())
    }

    fn list_workspaces(&self) -> rusqlite::Result<Vec<Workspace>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, authorization_scope, expires_at, created_at
             FROM workspaces ORDER BY created_at DESC",
        )?;
        statement
            .query_map([], |row| {
                Ok(Workspace {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    authorization_scope: row.get(2)?,
                    expires_at: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?
            .collect()
    }

    pub fn list_shells(&self) -> rusqlite::Result<Vec<ShellProfile>> {
        let mut statement = self.connection.prepare(
            "SELECT id, workspace_id, name, endpoint, runtime, protocol_id, password,
                    protocol_params, authorization_ack, status, last_connected_at, created_at,
                    tags
             FROM shell_profiles ORDER BY created_at DESC",
        )?;
        statement.query_map([], map_shell)?.collect()
    }

    fn list_audit_events(&self) -> rusqlite::Result<Vec<AuditEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT id, workspace_id, shell_id, action, outcome, detail, created_at
             FROM audit_events ORDER BY id DESC LIMIT 20",
        )?;
        statement
            .query_map([], |row| {
                Ok(AuditEvent {
                    id: row.get(0)?,
                    workspace_id: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    shell_id: row.get(2)?,
                    action: row.get(3)?,
                    outcome: row.get(4)?,
                    detail: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?
            .collect()
    }

    /// 按过滤条件分页查询审计事件，返回 (总数, 当前页)。
    pub fn query_audit(&self, filter: &AuditFilter) -> rusqlite::Result<(u64, Vec<AuditEvent>)> {
        let mut clauses: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(workspace_id) = &filter.workspace_id {
            clauses.push("workspace_id = ?".into());
            params.push(Box::new(workspace_id.clone()));
        }
        if let Some(action) = &filter.action {
            clauses.push("action = ?".into());
            params.push(Box::new(action.clone()));
        }
        if let Some(outcome) = &filter.outcome {
            clauses.push("outcome = ?".into());
            params.push(Box::new(outcome.clone()));
        }
        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", clauses.join(" AND "))
        };

        let total: u64 = self
            .connection
            .query_row(
                &format!("SELECT COUNT(*) FROM audit_events{where_sql}"),
                rusqlite::params_from_iter(params.iter().map(|param| param.as_ref())),
                |row| row.get(0),
            )?;

        let limit = filter.limit.unwrap_or(50).min(500);
        let offset = filter.offset.unwrap_or(0);
        // limit/offset 为 u64 常量内联，无注入风险；where 参数统一走占位符
        let mut statement = self.connection.prepare(&format!(
            "SELECT id, workspace_id, shell_id, action, outcome, detail, created_at
             FROM audit_events{where_sql} ORDER BY id DESC LIMIT {limit} OFFSET {offset}"
        ))?;
        let events = statement
            .query_map(
                rusqlite::params_from_iter(params.iter().map(|param| param.as_ref())),
                |row| {
                    Ok(AuditEvent {
                        id: row.get(0)?,
                        workspace_id: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        shell_id: row.get(2)?,
                        action: row.get(3)?,
                        outcome: row.get(4)?,
                        detail: row.get(5)?,
                        created_at: row.get(6)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((total, events))
    }
}

/// 按 `user_version` 顺序执行未应用的迁移脚本。
fn migrate(connection: &mut Connection) -> rusqlite::Result<()> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let version = version as usize;
    if version > MIGRATIONS.len() {
        return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
            std::io::Error::other(format!(
                "数据库版本（v{version}）高于程序支持的版本（v{}）",
                MIGRATIONS.len()
            )),
        )));
    }
    for (index, script) in MIGRATIONS.iter().enumerate().skip(version) {
        let transaction = connection.transaction()?;
        transaction.execute_batch(script)?;
        transaction.execute_batch(&format!(
            "PRAGMA user_version = {}",
            index + 1
        ))?;
        transaction.commit()?;
    }
    Ok(())
}

fn map_shell(row: &rusqlite::Row<'_>) -> rusqlite::Result<ShellProfile> {
    let tags_json: String = row.get(12)?;
    Ok(ShellProfile {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        name: row.get(2)?,
        endpoint: row.get(3)?,
        runtime: row.get(4)?,
        protocol_id: row.get(5)?,
        password: row.get(6)?,
        protocol_params: row.get(7)?,
        authorization_ack: row.get(8)?,
        status: row.get(9)?,
        last_connected_at: row.get(10)?,
        created_at: row.get(11)?,
        tags: serde_json::from_str(&tags_json).unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_workspace() -> CreateWorkspace {
        CreateWorkspace {
            name: "Lab".into(),
            authorization_scope: "localhost".into(),
            expires_at: None,
        }
    }

    fn sample_shell(workspace_id: String) -> CreateShell {
        CreateShell {
            workspace_id,
            name: "Mock".into(),
            endpoint: "mock://local".into(),
            runtime: "php".into(),
            protocol_id: "builtin.mock.v1".into(),
            password: Some("secret".into()),
            protocol_params: None,
            confirm_network: true,
            tags: Some(vec!["test".into()]),
        }
    }

    #[test]
    fn fresh_database_migrates_to_latest() {
        let db = Database::open(":memory:").unwrap();
        let version: i64 = db
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64, "新库应迁移到最新版本");
    }

    #[test]
    fn v1_database_upgrades_in_place() {
        // 构造一个 v1 数据库（只有第一阶段三张表，user_version = 1），验证打开时无损升级
        let path = std::env::temp_dir().join(format!("dosword-test-{}.sqlite3", Uuid::new_v4()));
        {
            let raw = Connection::open(&path).unwrap();
            raw.execute_batch(&MIGRATIONS[0]).unwrap();
            raw.execute_batch("PRAGMA user_version = 1").unwrap();
            raw.execute(
                "INSERT INTO workspaces (id, name, authorization_scope, created_at)
                 VALUES ('ws-old', 'Legacy', 'localhost', '2026-01-01')",
                [],
            )
            .unwrap();
        }
        let db = Database::open(&path).unwrap();
        let version: i64 = db
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64, "旧库应升级到最新版本");
        let workspace = db.workspace("ws-old").unwrap().unwrap();
        assert_eq!(workspace.name, "Legacy", "旧数据应保留");
        assert_eq!(db.get_settings().unwrap().max_file_size_mb, 32, "默认设置应可读");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn persists_workspace_and_shell_with_audit_events() {
        let mut db = Database::open(":memory:").unwrap();
        let workspace = db.create_workspace(sample_workspace()).unwrap();
        db.create_shell(sample_shell(workspace.id.clone()), "builtin.mock.v1")
            .unwrap();
        let dashboard = db.dashboard().unwrap();
        assert_eq!(dashboard.workspaces.len(), 1);
        assert_eq!(dashboard.shells.len(), 1);
        assert_eq!(dashboard.audit_events.len(), 2);
        let shell = &dashboard.shells[0];
        assert_eq!(shell.password, "secret");
        assert!(shell.authorization_ack);
    }

    #[test]
    fn settings_round_trip() {
        let db = Database::open(":memory:").unwrap();
        let defaults = db.get_settings().unwrap();
        assert!(!defaults.http_enabled);

        let updated = AppSettings {
            http_enabled: true,
            default_timeout_secs: 20,
            proxy: Some("http://127.0.0.1:8080".into()),
            max_file_size_mb: 64,
        };
        db.update_settings(&updated).unwrap();
        let loaded = db.get_settings().unwrap();
        assert_eq!(loaded.http_enabled, true);
        assert_eq!(loaded.default_timeout_secs, 20);
        assert_eq!(loaded.proxy.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(loaded.max_file_size_mb, 64);
    }

    #[test]
    fn expiry_date_only_is_normalized_to_rfc3339() {
        let mut db = Database::open(":memory:").unwrap();
        // 前端日期输入：YYYY-MM-DD
        let workspace = db
            .create_workspace(CreateWorkspace {
                name: "Lab".into(),
                authorization_scope: "localhost".into(),
                expires_at: Some("2030-12-31".into()),
            })
            .unwrap();
        // 写入后必须是 RFC3339，可被授权校验解析
        let stored = workspace.expires_at.clone().expect("应有到期日");
        let parsed = chrono::DateTime::parse_from_rfc3339(&stored);
        assert!(parsed.is_ok(), "到期日应规范化为 RFC3339：{workspace:?}");
        assert!(stored.contains("T23:59:59"), "应为当天最后时刻：{stored}");

        // 已规范化的值原样保留
        let normalized = normalize_expiry(Some("2026-01-01T10:00:00+08:00".into()));
        assert_eq!(normalized.as_deref(), Some("2026-01-01T10:00:00+08:00"));
        // None 保持
        assert_eq!(normalize_expiry(None), None);
    }

    #[test]
    fn record_audit_writes_event() {
        let mut db = Database::open(":memory:").unwrap();
        let workspace = db.create_workspace(sample_workspace()).unwrap();
        db.record_audit(Some(&workspace.id), None, "shell.exec", "success", "执行命令: id")
            .unwrap();
        let events = db.dashboard().unwrap().audit_events;
        assert!(events.iter().any(|event| event.action == "shell.exec"));
    }

    #[test]
    fn audit_without_workspace_is_allowed() {
        // v3 之后：系统级事件（无 Workspace 归属）也能落库
        let db = Database::open(":memory:").unwrap();
        db.record_audit(None, None, "settings.update", "success", "真实网络协议已关闭")
            .unwrap();
        let events = db.dashboard().unwrap().audit_events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "settings.update");
    }
}
