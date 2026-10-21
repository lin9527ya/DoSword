use std::path::Path;

use chrono::{Local, NaiveDate, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::secrets::SecretStore;
use dosword_sdk::domain::{
    AppSettings, AuditEvent, AuditFilter, CreateShell, CreateWorkspace, Dashboard, MemoryShell,
    ShellProfile, ShellQuery, ShellStats, UpdateShell, UpdateWorkspace, Workspace,
    WorkspaceShellCount,
};

fn memory_shell_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryShell> {
    Ok(MemoryShell {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        shell_id: row.get(2)?,
        runtime: row.get(3)?,
        kind: row.get(4)?,
        name: row.get(5)?,
        token: row.get(6)?,
        endpoint: row.get(7)?,
        install_path: row.get(8)?,
        artifact: row.get(9)?,
        status: row.get(10)?,
        installed_at: row.get(11)?,
        last_check_at: row.get(12)?,
        last_check_ok: row.get::<_, i64>(13)? != 0,
        uninstall_attempts: row.get(14)?,
        notes: row.get(15)?,
    })
}

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
    // v5: 审计/Shell 查询索引（分页过滤与保留清理从全表扫描变为索引查找）
    "CREATE INDEX idx_audit_workspace ON audit_events(workspace_id);
     CREATE INDEX idx_audit_action ON audit_events(action);
     CREATE INDEX idx_audit_outcome ON audit_events(outcome);
     CREATE INDEX idx_audit_created ON audit_events(created_at);
     CREATE INDEX idx_shell_workspace ON shell_profiles(workspace_id);",
    // v6: 内存马句柄。句柄必须自足 —— 仅凭本表内容（endpoint + token + artifact）
    //     就应能在一个全新的 DoSword 实例上完成卸载；句柄丢失等于留下后门。
    "CREATE TABLE memory_shells (
       id TEXT PRIMARY KEY,
       workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
       shell_id TEXT REFERENCES shell_profiles(id) ON DELETE SET NULL,
       runtime TEXT NOT NULL,
       kind TEXT NOT NULL,
       name TEXT NOT NULL,
       token TEXT NOT NULL,
       endpoint TEXT NOT NULL,
       install_path TEXT NOT NULL DEFAULT '',
       artifact TEXT NOT NULL DEFAULT '{}',
       status TEXT NOT NULL,
       installed_at TEXT NOT NULL,
       last_check_at TEXT,
       last_check_ok INTEGER NOT NULL DEFAULT 0,
       uninstall_attempts INTEGER NOT NULL DEFAULT 0,
       notes TEXT NOT NULL DEFAULT ''
     );
     CREATE INDEX idx_memshell_workspace ON memory_shells(workspace_id);
     CREATE INDEX idx_memshell_shell ON memory_shells(shell_id);
     CREATE INDEX idx_memshell_status ON memory_shells(status);",
    // v7：审计按 Shell 过滤（"这个目标上做过什么"是最常用的排查方式）。
    // 既有 idx_audit_* 覆盖 workspace/action/outcome/created_at，缺 shell_id。
    "CREATE INDEX IF NOT EXISTS idx_audit_shell ON audit_events(shell_id);",
    // v8：Shell 库改为服务端分页 + 过滤（按 created_at DESC 排序、可按 workspace 过滤）。
    // 既有 idx_shell_workspace 只覆盖 workspace_id，翻页排序仍要临时排序。
    "CREATE INDEX IF NOT EXISTS idx_shell_workspace_created
       ON shell_profiles(workspace_id, created_at DESC);",
];

const SETTINGS_KEY: &str = "app";

/// 规范化授权到期时间：前端日期输入是 `YYYY-MM-DD`，而授权校验用 RFC3339。
/// 纯日期转成当天 23:59:59 + 本地时区（到期日当天仍有效）；已是 RFC3339 的原样保留。
fn normalize_expiry(expires_at: Option<String>) -> Option<String> {
    let value = expires_at?;
    let is_date_only = value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-');
    if is_date_only
        && let Some(dt) = NaiveDate::parse_from_str(&value, "%Y-%m-%d")
            .ok()
            .and_then(|date| date.and_hms_opt(23, 59, 59))
            .and_then(|naive| naive.and_local_timezone(Local).single())
    {
        return Some(dt.to_rfc3339());
    }
    Some(value)
}

pub struct Database {
    connection: Connection,
    /// 敏感字段加密（连接密码 / MCP 令牌）。`:memory:` 与测试库为 `None`。
    secrets: Option<SecretStore>,
}

/// 加密字段值（无密钥保管时原样返回）。
fn seal(secrets: Option<&SecretStore>, field: &'static str, value: &str) -> String {
    match secrets {
        Some(store) => store.encrypt(field, value),
        None => value.to_string(),
    }
}

/// 解密字段值；解密失败（换机器 / 丢钥匙 / 密文损坏）返回空串并告警。
fn unseal(secrets: Option<&SecretStore>, field: &'static str, stored: &str) -> String {
    match secrets {
        Some(store) => match store.decrypt(field, stored) {
            Some(value) => value,
            None => {
                eprintln!(
                    "[secrets] 字段 {field} 解密失败（密钥已更换或密文损坏），按空值处理；请重新录入"
                );
                String::new()
            }
        },
        None => stored.to_string(),
    }
}

/// 解密 Shell 的连接密码（其余字段原样）。
fn unseal_shell(secrets: Option<&SecretStore>, mut profile: ShellProfile) -> ShellProfile {
    profile.password = unseal(secrets, "shell.password", &profile.password);
    profile
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        let path = path.as_ref();
        let mut connection = Connection::open(path)?;
        // busy_timeout：桌面端与 dosword-cli 共用同一数据目录 / 同一 SQLite 文件，
        // 并发写（CLI 跑 playbook 时 GUI 记审计）会瞬时拿到 SQLITE_BUSY。
        // 不设超时 → 直接报 "database is locked"；设 5s → 等对方事务提交后重试。
        // synchronous=NORMAL 在 WAL 下已是安全档（断电只丢最后一个事务，不损坏库）。
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA synchronous = NORMAL;",
        )?;
        migrate(&mut connection)?;
        // 密钥保管：钥匙串优先，其次数据目录内的 0600 密钥文件。
        // `:memory:`（测试）不加密 —— 没有可落盘的密钥位置。
        let secrets = if path.to_string_lossy() == ":memory:" {
            None
        } else {
            path.parent().and_then(SecretStore::load)
        };
        let mut database = Self {
            connection,
            secrets,
        };
        database.encrypt_legacy_secrets()?;
        Ok(database)
    }

    /// 把库里尚未加密的密码与 MCP 令牌就地加密（旧版本升级上来的明文）。
    fn encrypt_legacy_secrets(&mut self) -> rusqlite::Result<()> {
        if self.secrets.is_none() {
            return Ok(());
        }
        let secrets = self.secrets.as_ref();
        let transaction = self.connection.transaction()?;
        let rows: Vec<(String, String)> = {
            let mut statement = transaction.prepare("SELECT id, password FROM shell_profiles")?;
            let mapped = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            mapped.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (id, password) in rows {
            if !password.is_empty() && !SecretStore::is_encrypted(&password) {
                transaction.execute(
                    "UPDATE shell_profiles SET password = ?1 WHERE id = ?2",
                    params![seal(secrets, "shell.password", &password), id],
                )?;
            }
        }
        let raw: Option<String> = transaction
            .query_row(
                "SELECT value FROM app_settings WHERE key = ?1",
                [SETTINGS_KEY],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(raw) = raw
            && let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&raw)
            && let Some(token) = value.get("mcpToken").and_then(|v| v.as_str())
            && !token.is_empty()
            && !SecretStore::is_encrypted(token)
        {
            let sealed = seal(secrets, "mcp.token", token);
            value["mcpToken"] = serde_json::json!(sealed);
            transaction.execute(
                "UPDATE app_settings SET value = ?1 WHERE key = ?2",
                params![value.to_string(), SETTINGS_KEY],
            )?;
        }
        transaction.commit()
    }

    /// 看板数据：Workspace 列表 + Shell 库**聚合** + 最近审计。
    ///
    /// 不再返回全量 Shell（历史上每次打开看板/详情都要拉全部 Shell，含明文密码）：
    /// 列表走 [`Self::query_shells`] 分页，单个 Shell 走 `commands::get_shell`，
    /// 卡片计数/指标由 [`Self::shell_stats`] 提供。
    pub fn dashboard(&self) -> rusqlite::Result<Dashboard> {
        Ok(Dashboard {
            workspaces: self.list_workspaces()?,
            shell_stats: self.shell_stats()?,
            audit_events: self.list_audit_events()?,
        })
    }

    /// Shell 库聚合统计（总数 / 在线数 / 最近连接 / 全部标签 / 各 Workspace 计数）。
    pub fn shell_stats(&self) -> rusqlite::Result<ShellStats> {
        let total: u64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM shell_profiles", [], |row| row.get(0))?;
        let online: u64 = self.connection.query_row(
            "SELECT COUNT(*) FROM shell_profiles WHERE status = 'online'",
            [],
            |row| row.get(0),
        )?;
        // ISO8601 字符串按字典序即时间序
        let last_connected_at: Option<String> = self.connection.query_row(
            "SELECT MAX(last_connected_at) FROM shell_profiles",
            [],
            |row| row.get(0),
        )?;
        let mut by_workspace = Vec::new();
        {
            let mut statement = self.connection.prepare(
                "SELECT workspace_id, COUNT(*) FROM shell_profiles GROUP BY workspace_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok(WorkspaceShellCount {
                    workspace_id: row.get(0)?,
                    count: row.get(1)?,
                })
            })?;
            for row in rows {
                by_workspace.push(row?);
            }
        }
        let mut tags = std::collections::BTreeSet::new();
        {
            let mut statement = self.connection.prepare("SELECT tags FROM shell_profiles")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                let raw = row?;
                tags.extend(serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default());
            }
        }
        Ok(ShellStats {
            total,
            online,
            last_connected_at,
            tags: tags.into_iter().collect(),
            by_workspace,
        })
    }

    /// 服务端分页 + 过滤查询 Shell。返回 `(总数, 当页)`。
    ///
    /// 排序 `created_at DESC, id`：只按 `created_at` 排会在批量导入（同一时间戳）时并列，
    /// 翻页可能重复或漏行，`id` 作为稳定次序保证分页自洽。
    pub fn query_shells(&self, query: &ShellQuery) -> rusqlite::Result<(u64, Vec<ShellProfile>)> {
        let mut clauses: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if let Some(workspace_id) = query.workspace_id.as_deref().filter(|v| !v.is_empty()) {
            clauses.push("workspace_id = ?".into());
            params.push(Box::new(workspace_id.to_string()));
        }
        if let Some(status) = query.status.as_deref().filter(|v| !v.is_empty()) {
            clauses.push("status = ?".into());
            params.push(Box::new(status.to_string()));
        }
        // 标签按 JSON 数组元素精确匹配（`"tag"` 连引号一起匹配，避免 prod 命中 production）
        if let Some(tag) = query.tag.as_deref().filter(|v| !v.is_empty()) {
            clauses.push("tags LIKE ? ESCAPE '\\'".into());
            params.push(Box::new(format!("%\"{}\"%", escape_like(tag))));
        }
        if let Some(keyword) = query
            .query
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            let pattern = format!("%{}%", escape_like(keyword));
            clauses.push(
                "(name LIKE ? ESCAPE '\\' OR endpoint LIKE ? ESCAPE '\\' \
                  OR runtime LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\')"
                    .into(),
            );
            for _ in 0..4 {
                params.push(Box::new(pattern.clone()));
            }
        }
        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", clauses.join(" AND "))
        };
        let total: u64 = self.connection.query_row(
            &format!("SELECT COUNT(*) FROM shell_profiles{where_sql}"),
            rusqlite::params_from_iter(params.iter().map(|value| value.as_ref())),
            |row| row.get(0),
        )?;
        let limit = query.limit.unwrap_or(50).min(500);
        let offset = query.offset.unwrap_or(0);
        let mut statement = self.connection.prepare(&format!(
            "SELECT {SHELL_COLUMNS} FROM shell_profiles{where_sql} \
             ORDER BY created_at DESC, id LIMIT ? OFFSET ?"
        ))?;
        let mut bind: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|value| value.as_ref()).collect();
        let limit_param = limit as i64;
        let offset_param = offset as i64;
        bind.push(&limit_param);
        bind.push(&offset_param);
        let items = statement
            .query_map(rusqlite::params_from_iter(bind), map_shell)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((
            total,
            items
                .into_iter()
                .map(|profile| unseal_shell(self.secrets.as_ref(), profile))
                .collect(),
        ))
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
        let profile = shell_profile_from(input, protocol_id);
        let secrets = self.secrets.as_ref();
        let transaction = self.connection.transaction()?;
        insert_shell_row(&transaction, secrets, &profile)?;
        transaction.commit()?;
        Ok(profile)
    }

    /// 批量创建 Shell：**单事务**（N 条插入 + N 条审计只 fsync 一次）。
    ///
    /// 与逐条 `create_shell` 的语义差异：任一条失败则**整批回滚**。导入场景要么全成、
    /// 要么全不成 —— 半截导入会让用户重试时整批被判重复。
    pub fn create_shells_batch(
        &mut self,
        inputs: Vec<(CreateShell, String)>,
    ) -> rusqlite::Result<Vec<ShellProfile>> {
        let profiles: Vec<ShellProfile> = inputs
            .into_iter()
            .map(|(input, protocol_id)| shell_profile_from(input, &protocol_id))
            .collect();
        let secrets = self.secrets.as_ref();
        let transaction = self.connection.transaction()?;
        for profile in &profiles {
            insert_shell_row(&transaction, secrets, profile)?;
        }
        transaction.commit()?;
        Ok(profiles)
    }

    /// 全部已用端点（导入去重用）。不读密码，避免为去重解密整库。
    pub fn existing_endpoints(&self) -> rusqlite::Result<Vec<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT endpoint FROM shell_profiles")?;
        statement.query_map([], |row| row.get(0))?.collect()
    }

    pub fn shell(&self, id: &str) -> rusqlite::Result<Option<ShellProfile>> {
        let profile = self.shell_raw(id)?;
        Ok(profile.map(|profile| unseal_shell(self.secrets.as_ref(), profile)))
    }

    /// 原始读取（密码保持库中形态）。仅供 `shell` 与批量更新内部使用。
    fn shell_raw(&self, id: &str) -> rusqlite::Result<Option<ShellProfile>> {
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
        self.workspace(&input.id)?
            .ok_or_else(|| rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn delete_workspace(&self, id: &str) -> rusqlite::Result<()> {
        self.connection
            .execute("DELETE FROM workspaces WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn update_shell(&self, input: &UpdateShell) -> rusqlite::Result<ShellProfile> {
        // 合并式更新：`None` 表示「保持原值」。协议参数（编码方式 / session 开关）
        // 也在这里更新 —— 此前 protocol_params 只能在创建时写入，
        // 用户重新生成 stub 换了编码器后无法改，只能删了重建 Shell。
        let current = self
            .shell(&input.id)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let password = input
            .password
            .clone()
            .unwrap_or_else(|| current.password.clone());
        let tags = serde_json::to_string(input.tags.as_ref().unwrap_or(&current.tags))
            .unwrap_or_else(|_| "[]".into());
        let protocol_params = input
            .protocol_params
            .clone()
            .unwrap_or_else(|| current.protocol_params.clone());
        self.connection.execute(
            "UPDATE shell_profiles SET name = ?1, endpoint = ?2, password = ?3, tags = ?4,
             protocol_params = ?5 WHERE id = ?6",
            params![
                input.name,
                input.endpoint,
                seal(self.secrets.as_ref(), "shell.password", &password),
                tags,
                protocol_params,
                input.id
            ],
        )?;
        self.shell(&input.id)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)
    }

    /// 批量更新 Shell 标签/密码（单事务，批量场景 fsync 一次）。
    pub fn batch_update_shells(
        &mut self,
        ids: &[String],
        tags: Option<&Vec<String>>,
        password: Option<&str>,
    ) -> rusqlite::Result<usize> {
        let tx = self.connection.transaction()?;
        let mut updated = 0usize;
        for id in ids {
            let shell: Option<ShellProfile> = tx
                .query_row(
                    "SELECT id, workspace_id, name, endpoint, runtime, protocol_id, password,
                            protocol_params, authorization_ack, status, last_connected_at, created_at,
                            tags FROM shell_profiles WHERE id = ?1",
                    [id],
                    |row| {
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
                    },
                )
                .optional()?;
            if let Some(shell) = shell {
                // 未提供新密码时保留库中的原值（已是密文，不能再加密一次）
                let new_password = match password {
                    Some(new) => seal(self.secrets.as_ref(), "shell.password", new),
                    None => shell.password.clone(),
                };
                let new_tags = tags.cloned().unwrap_or(shell.tags);
                let tags_json = serde_json::to_string(&new_tags).unwrap_or_else(|_| "[]".into());
                tx.execute(
                    "UPDATE shell_profiles SET password = ?1, tags = ?2 WHERE id = ?3",
                    params![new_password, tags_json, id],
                )?;
                updated += 1;
            }
        }
        tx.commit()?;
        Ok(updated)
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
    /// P3：批量更新 Shell 在线状态（单事务，避免 N 次独立写 + N 次 fsync）。
    pub fn batch_update_shell_status(
        &mut self,
        results: &[(String, String)],
    ) -> rusqlite::Result<()> {
        let transaction = self.connection.transaction()?;
        {
            let mut stmt =
                transaction.prepare("UPDATE shell_profiles SET status = ?2 WHERE id = ?1")?;
            for (id, status) in results {
                stmt.execute(params![id, status])?;
            }
        }
        transaction.commit()
    }

    /// 更新 Shell 的连接状态与最后连接时间（当前调用点已改为直接写库，保留备用）。
    #[allow(dead_code)]
    pub fn update_shell_status(&self, id: &str, status: &str) -> rusqlite::Result<()> {
        self.connection.execute(
            "UPDATE shell_profiles SET status = ?1, last_connected_at = datetime('now')
             WHERE id = ?2",
            params![status, id],
        )?;
        Ok(())
    }

    pub fn record_probe(
        &mut self,
        shell: &ShellProfile,
        outcome: &str,
        detail: &str,
    ) -> rusqlite::Result<()> {
        // P10：单事务合并两次写（少一次 fsync）
        let now = Utc::now().to_rfc3339();
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE shell_profiles SET status = ?1, last_connected_at = ?2 WHERE id = ?3",
            params![outcome, now, shell.id],
        )?;
        transaction.execute(
            "INSERT INTO audit_events (workspace_id, shell_id, action, outcome, detail, created_at)
             VALUES (?1, ?2, 'shell.probe', ?3, ?4, ?5)",
            params![shell.workspace_id, shell.id, outcome, detail, now],
        )?;
        transaction.commit()
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

    /// 清理早于保留期的审计记录（created_at 统一为 UTC RFC3339，可字典序比较）。
    /// 返回删除的行数。
    pub fn purge_audit(&self, retention_days: u64) -> rusqlite::Result<u64> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = (Utc::now() - chrono::Duration::days(retention_days as i64)).to_rfc3339();
        let rows = self
            .connection
            .execute("DELETE FROM audit_events WHERE created_at < ?1", [cutoff])?;
        Ok(rows as u64)
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
            Some(json) => {
                // MCP 令牌加密存放：读出后先解密再反序列化
                let mut value: serde_json::Value = serde_json::from_str(&json)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
                if let Some(token) = value.get("mcpToken").and_then(|item| item.as_str())
                    && !token.is_empty()
                {
                    let plain = unseal(self.secrets.as_ref(), "mcp.token", token);
                    value["mcpToken"] = serde_json::json!(plain);
                }
                serde_json::from_value(value)
                    .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))
            }
            None => Ok(AppSettings::default()),
        }
    }

    pub fn update_settings(&self, settings: &AppSettings) -> rusqlite::Result<()> {
        // MCP 令牌加密后再整体落盘
        let mut value = serde_json::to_value(settings)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        if let Some(token) = value.get("mcpToken").and_then(|item| item.as_str())
            && !token.is_empty()
        {
            let sealed = seal(self.secrets.as_ref(), "mcp.token", token);
            value["mcpToken"] = serde_json::json!(sealed);
        }
        let json = serde_json::to_string(&value)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
        self.connection.execute(
            "INSERT INTO app_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![SETTINGS_KEY, json],
        )?;
        Ok(())
    }

    // ---- 内存马句柄 ----

    pub fn insert_memory_shell(&self, shell: &MemoryShell) -> rusqlite::Result<()> {
        self.connection.execute(
            "INSERT INTO memory_shells
               (id, workspace_id, shell_id, runtime, kind, name, token, endpoint,
                install_path, artifact, status, installed_at, last_check_at,
                last_check_ok, uninstall_attempts, notes)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            params![
                shell.id,
                shell.workspace_id,
                shell.shell_id,
                shell.runtime,
                shell.kind,
                shell.name,
                shell.token,
                shell.endpoint,
                shell.install_path,
                shell.artifact,
                shell.status,
                shell.installed_at,
                shell.last_check_at,
                shell.last_check_ok as i64,
                shell.uninstall_attempts,
                shell.notes,
            ],
        )?;
        Ok(())
    }

    /// 列出句柄。两个过滤条件均可选（None = 不过滤）。
    pub fn list_memory_shells(
        &self,
        workspace_id: Option<&str>,
        shell_id: Option<&str>,
    ) -> rusqlite::Result<Vec<MemoryShell>> {
        let mut statement = self.connection.prepare(
            "SELECT id, workspace_id, shell_id, runtime, kind, name, token, endpoint,
                    install_path, artifact, status, installed_at, last_check_at,
                    last_check_ok, uninstall_attempts, notes
             FROM memory_shells
             WHERE (?1 IS NULL OR workspace_id = ?1)
               AND (?2 IS NULL OR shell_id = ?2)
             ORDER BY installed_at DESC",
        )?;
        let rows = statement.query_map(params![workspace_id, shell_id], memory_shell_from_row)?;
        rows.collect()
    }

    pub fn memory_shell(&self, id: &str) -> rusqlite::Result<Option<MemoryShell>> {
        self.connection
            .query_row(
                "SELECT id, workspace_id, shell_id, runtime, kind, name, token, endpoint,
                        install_path, artifact, status, installed_at, last_check_at,
                        last_check_ok, uninstall_attempts, notes
                 FROM memory_shells WHERE id = ?1",
                [id],
                memory_shell_from_row,
            )
            .optional()
    }

    /// 更新存活检测结果。
    pub fn update_memory_shell_check(
        &self,
        id: &str,
        status: &str,
        alive: bool,
    ) -> rusqlite::Result<()> {
        self.connection.execute(
            "UPDATE memory_shells
             SET status = ?2, last_check_ok = ?3, last_check_at = ?4
             WHERE id = ?1",
            params![id, status, alive as i64, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// 卸载失败时累加尝试次数并置为指定状态（通常是 orphaned）。
    pub fn mark_memory_shell_uninstall_failed(
        &self,
        id: &str,
        status: &str,
        note: &str,
    ) -> rusqlite::Result<()> {
        self.connection.execute(
            "UPDATE memory_shells
             SET status = ?2,
                 uninstall_attempts = uninstall_attempts + 1,
                 notes = ?3
             WHERE id = ?1",
            params![id, status, note],
        )?;
        Ok(())
    }

    /// 删除句柄记录。**只应在载荷已中和且 TTL 已过（文件已清理）后调用**；
    /// 待接：UI 的「完成清理」入口。
    #[allow(dead_code)]
    pub fn delete_memory_shell(&self, id: &str) -> rusqlite::Result<()> {
        self.connection
            .execute("DELETE FROM memory_shells WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn list_workspaces(&self) -> rusqlite::Result<Vec<Workspace>> {
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
        let mut statement = self.connection.prepare(&format!(
            "SELECT {SHELL_COLUMNS} FROM shell_profiles ORDER BY created_at DESC"
        ))?;
        let profiles = statement
            .query_map([], map_shell)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(profiles
            .into_iter()
            .map(|profile| unseal_shell(self.secrets.as_ref(), profile))
            .collect())
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
        // 按 Shell 过滤：排查「某个目标上做过什么」是审计最常见的用法
        if let Some(shell_id) = &filter.shell_id {
            clauses.push("shell_id = ?".into());
            params.push(Box::new(shell_id.clone()));
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

        let total: u64 = self.connection.query_row(
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
        transaction.execute_batch(&format!("PRAGMA user_version = {}", index + 1))?;
        transaction.commit()?;
    }
    Ok(())
}

/// `shell_profiles` 的列清单（顺序必须与 [`map_shell`] 一致）。
const SHELL_COLUMNS: &str = "id, workspace_id, name, endpoint, runtime, protocol_id, password, \
     protocol_params, authorization_ack, status, last_connected_at, created_at, tags";

/// 转义 LIKE 模式里的通配符（标签/关键字是用户输入，`%` `_` 不该当通配符用）。
fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// 由输入构造 Shell 档案（创建与批量导入共用）。
fn shell_profile_from(input: CreateShell, protocol_id: &str) -> ShellProfile {
    ShellProfile {
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
    }
}

/// 插入一条 Shell + 一条创建审计（调用方负责事务边界）。
fn insert_shell_row(
    transaction: &rusqlite::Transaction<'_>,
    secrets: Option<&SecretStore>,
    profile: &ShellProfile,
) -> rusqlite::Result<()> {
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
            seal(secrets, "shell.password", &profile.password),
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
            raw.execute_batch(MIGRATIONS[0]).unwrap();
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
        assert_eq!(
            db.get_settings().unwrap().max_file_size_mb,
            32,
            "默认设置应可读"
        );
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
        assert_eq!(dashboard.audit_events.len(), 2);
        // Shell 列表改为分页查询；看板只带聚合
        assert_eq!(dashboard.shell_stats.total, 1);
        assert_eq!(dashboard.shell_stats.by_workspace.len(), 1);
        let (total, shells) = db.query_shells(&ShellQuery::default()).unwrap();
        assert_eq!(total, 1);
        assert_eq!(shells.len(), 1);
        assert_eq!(shells[0].password, "secret");
        assert!(shells[0].authorization_ack);
    }

    /// Shell 分页查询：总数与分页无关、翻页不重不漏、各过滤器按预期生效。
    #[test]
    fn query_shells_pages_filters_and_searches() {
        let mut db = Database::open(":memory:").unwrap();
        let lab = db.create_workspace(sample_workspace()).unwrap();
        let other = db
            .create_workspace(CreateWorkspace {
                name: "Prod".into(),
                authorization_scope: "example.com".into(),
                expires_at: None,
            })
            .unwrap();
        let rows = [
            (
                lab.id.clone(),
                "web-01",
                "http://10.0.0.1/a.php",
                ["prod", "web"],
            ),
            (
                lab.id.clone(),
                "web-02",
                "http://10.0.0.2/a.php",
                ["prod", "web"],
            ),
            (
                lab.id.clone(),
                "db-01",
                "http://10.0.0.3/a.php",
                ["db", "db"],
            ),
            (
                lab.id.clone(),
                "internal",
                "http://10.0.0.4/a.php",
                ["production", "production"],
            ),
            (
                other.id.clone(),
                "web-03",
                "http://10.0.0.5/a.php",
                ["prod", "prod"],
            ),
        ];
        let mut ids = Vec::new();
        for (workspace_id, name, endpoint, tags) in rows {
            let mut input = sample_shell(workspace_id);
            input.name = name.into();
            input.endpoint = endpoint.into();
            input.tags = Some(tags.iter().map(|tag| (*tag).to_string()).collect());
            ids.push(db.create_shell(input, "builtin.mock.v1").unwrap().id);
        }
        db.update_shell_status(&ids[0], "online").unwrap();

        let first = db
            .query_shells(&ShellQuery {
                limit: Some(2),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(first.0, 5, "total 与分页无关");
        assert_eq!(first.1.len(), 2);
        let second = db
            .query_shells(&ShellQuery {
                limit: Some(2),
                offset: Some(2),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(second.0, 5);
        let seen: std::collections::HashSet<_> = first
            .1
            .iter()
            .chain(second.1.iter())
            .map(|shell| shell.id.clone())
            .collect();
        assert_eq!(seen.len(), 4, "两页之间不得重复");
        // 稳定排序：同一 created_at（同批创建）下顺序必须可重复，否则翻页会漏行
        let again = db
            .query_shells(&ShellQuery {
                limit: Some(2),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            again.1.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
            first.1.iter().map(|s| s.id.clone()).collect::<Vec<_>>()
        );

        // workspace 过滤
        let (total, items) = db
            .query_shells(&ShellQuery {
                workspace_id: Some(lab.id.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!((total, items.len()), (4, 4));
        // status 过滤
        let (total, _) = db
            .query_shells(&ShellQuery {
                status: Some("online".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 1);
        // 标签精确匹配：prod 不得命中 production
        let (total, _) = db
            .query_shells(&ShellQuery {
                tag: Some("prod".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 3);
        let (total, _) = db
            .query_shells(&ShellQuery {
                tag: Some("production".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 1);
        // 关键字：name / endpoint / tags 都覆盖
        let (total, _) = db
            .query_shells(&ShellQuery {
                query: Some("web-0".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 3);
        let (total, _) = db
            .query_shells(&ShellQuery {
                query: Some("10.0.0.3".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 1);
        // 用户输入的通配符必须被转义（否则 `%` 会匹配整库）
        let (total, _) = db
            .query_shells(&ShellQuery {
                query: Some("%".into()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(total, 0, "`%` 应转义为字面量");
    }

    /// 看板聚合：总数 / 在线 / 标签去重 / 各 Workspace 计数。
    #[test]
    fn shell_stats_aggregates_library() {
        let mut db = Database::open(":memory:").unwrap();
        let lab = db.create_workspace(sample_workspace()).unwrap();
        let a = db
            .create_shell(sample_shell(lab.id.clone()), "builtin.mock.v1")
            .unwrap();
        let mut second = sample_shell(lab.id.clone());
        second.tags = Some(vec!["prod".into()]);
        db.create_shell(second, "builtin.mock.v1").unwrap();
        db.update_shell_status(&a.id, "online").unwrap();
        db.record_probe(&a, "online", "连接成功").unwrap();

        let stats = db.shell_stats().unwrap();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.online, 1);
        assert_eq!(stats.tags, vec!["prod".to_string(), "test".to_string()]);
        assert_eq!(stats.by_workspace.len(), 1);
        assert_eq!(stats.by_workspace[0].workspace_id, lab.id);
        assert_eq!(stats.by_workspace[0].count, 2);
        assert!(stats.last_connected_at.is_some());

        let dashboard = db.dashboard().unwrap();
        assert_eq!(dashboard.shell_stats.total, 2);
    }

    /// 批量导入是单事务：任一条失败整批回滚（不留半截导入，也不留半截审计）。
    #[test]
    fn create_shells_batch_rolls_back_on_failure() {
        let mut db = Database::open(":memory:").unwrap();
        let workspace = db.create_workspace(sample_workspace()).unwrap();
        let good = sample_shell(workspace.id.clone());
        // 指向不存在的 Workspace：外键约束会失败
        let bad = sample_shell("missing-workspace".into());
        let result = db.create_shells_batch(vec![
            (good, "builtin.mock.v1".into()),
            (bad, "builtin.mock.v1".into()),
        ]);
        assert!(result.is_err(), "坏行应让整批失败");
        let (total, _) = db.query_shells(&ShellQuery::default()).unwrap();
        assert_eq!(total, 0, "整批回滚：不得留下半截导入");
        let (audit_total, _) = db
            .query_audit(&AuditFilter {
                workspace_id: None,
                shell_id: None,
                action: Some("shell.create".into()),
                outcome: None,
                limit: None,
                offset: None,
            })
            .unwrap();
        assert_eq!(audit_total, 0, "回滚后不得留下 shell.create 审计");
    }

    /// 敏感字段落库必须是密文，读取时还原；`update_shell` 不改密码时不得二次加密。
    #[test]
    fn secrets_are_encrypted_at_rest() {
        let dir = std::env::temp_dir().join(format!("dosword-sec-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.sqlite");
        let mut db = Database::open(&path).unwrap();
        assert!(db.secrets.is_some(), "真实文件库应启用密钥保管");
        let workspace = db.create_workspace(sample_workspace()).unwrap();
        let profile = db
            .create_shell(sample_shell(workspace.id.clone()), "builtin.mock.v1")
            .unwrap();

        let raw: String = db
            .connection
            .query_row(
                "SELECT password FROM shell_profiles WHERE id = ?1",
                [&profile.id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(SecretStore::is_encrypted(&raw), "库里应是密文：{raw}");
        assert!(!raw.contains("secret"), "密文里不得出现明文密码：{raw}");
        // 读取路径还原为明文
        assert_eq!(db.shell(&profile.id).unwrap().unwrap().password, "secret");

        // 只改名字、不改密码：库里不得变成「密文的密文」
        db.update_shell(&UpdateShell {
            id: profile.id.clone(),
            name: "renamed".into(),
            endpoint: "mock://local".into(),
            password: None,
            tags: None,
            protocol_params: None,
        })
        .unwrap();
        let raw_after: String = db
            .connection
            .query_row(
                "SELECT password FROM shell_profiles WHERE id = ?1",
                [&profile.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            db.shell(&profile.id).unwrap().unwrap().password,
            "secret",
            "不改密码时不得二次加密：{raw_after}"
        );

        // MCP 令牌同样加密落盘
        let mut settings = db.get_settings().unwrap();
        settings.mcp_token = "tok-123456".into();
        db.update_settings(&settings).unwrap();
        let raw_settings: String = db
            .connection
            .query_row(
                "SELECT value FROM app_settings WHERE key = 'app'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        // settings 是整段 JSON：断言 token 字段被加密、明文不出现
        assert!(raw_settings.contains("enc:v1:"), "{raw_settings}");
        assert!(!raw_settings.contains("tok-123456"), "{raw_settings}");
        assert_eq!(db.get_settings().unwrap().mcp_token, "tok-123456");

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 旧版本留下的明文密码在下次打开时被就地迁移为密文（且仍可正常读取）。
    #[test]
    fn legacy_plaintext_password_is_migrated_on_open() {
        let dir = std::env::temp_dir().join(format!("dosword-sec-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("legacy.sqlite");
        {
            let mut db = Database::open(&path).unwrap();
            let workspace = db.create_workspace(sample_workspace()).unwrap();
            let mut input = sample_shell(workspace.id);
            input.password = Some("legacy-pw".into());
            db.create_shell(input, "builtin.mock.v1").unwrap();
            // 模拟旧版本：把密码写回明文
            db.connection
                .execute("UPDATE shell_profiles SET password = 'legacy-pw'", [])
                .unwrap();
        }
        // 重新打开 → 迁移
        let db = Database::open(&path).unwrap();
        let raw: String = db
            .connection
            .query_row("SELECT password FROM shell_profiles LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(SecretStore::is_encrypted(&raw), "旧明文应被迁移：{raw}");
        let shells = db.list_shells().unwrap();
        assert_eq!(shells[0].password, "legacy-pw");
        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
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
            chunk_size_mb: 4,
            allow_arbitrary_code: true,
            audit_retention_days: 30,
            gzip_enabled: true,
            tls_verify: false,
            allow_arbitrary_local_paths: false,
            ..AppSettings::default()
        };
        db.update_settings(&updated).unwrap();
        let loaded = db.get_settings().unwrap();
        assert!(loaded.http_enabled);
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
        db.record_audit(
            Some(&workspace.id),
            None,
            "shell.exec",
            "success",
            "执行命令: id",
        )
        .unwrap();
        let events = db.dashboard().unwrap().audit_events;
        assert!(events.iter().any(|event| event.action == "shell.exec"));
    }

    #[test]
    fn audit_without_workspace_is_allowed() {
        // v3 之后：系统级事件（无 Workspace 归属）也能落库
        let db = Database::open(":memory:").unwrap();
        db.record_audit(
            None,
            None,
            "settings.update",
            "success",
            "真实网络协议已关闭",
        )
        .unwrap();
        let events = db.dashboard().unwrap().audit_events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "settings.update");
    }

    #[test]
    fn purge_audit_removes_only_expired_rows() {
        let db = Database::open(":memory:").unwrap();
        // 写入一条「昨天」与一条「现在」的审计（created_at 由 record_audit 生成当前时间，
        // 这里直接改写为历史时间模拟过期数据）
        db.record_audit(None, None, "shell.exec", "success", "旧事件")
            .unwrap();
        db.record_audit(None, None, "shell.exec", "success", "新事件")
            .unwrap();
        let old = (Utc::now() - chrono::Duration::days(100)).to_rfc3339();
        db.connection
            .execute(
                "UPDATE audit_events SET created_at = ?1 WHERE detail = '旧事件'",
                [old],
            )
            .unwrap();
        let removed = db.purge_audit(30).unwrap();
        assert_eq!(removed, 1, "仅过期事件应被清理");
        let events = db.dashboard().unwrap().audit_events;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].detail, "新事件");
        // retention = 0 表示不清理
        assert_eq!(db.purge_audit(0).unwrap(), 0);
    }
}
