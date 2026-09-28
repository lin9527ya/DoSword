//! 内存会话管理：连接成功后保存协议会话状态，TTL 过期后惰性清理。
//!
//! 会话不落盘——应用重启即全部失效，需要重新连接。对安全测试工具而言
//! 这是简单且安全的策略。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dosword_sdk::SessionState;
use dosword_sdk::domain::{AppSettings, ProbeResult, ShellProfile};

/// 会话默认存活时长（秒）。
pub const SESSION_TTL_SECS: u64 = 4 * 60 * 60;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// 一个活跃会话：绑定到 Shell 配置，持有协议的连接状态。
pub struct ShellSession {
    pub id: String,
    pub profile_id: String,
    pub workspace_id: String,
    pub protocol_id: String,
    /// 协议连接状态（`Arc` 便于命令层短锁取出后在锁外执行网络调用）。
    pub state: Arc<dyn SessionState>,
    /// 连接时的环境信息（服务器 / 目录 / 分隔符等）。
    pub info: ProbeResult,
    pub last_used_at: u64,
    /// 上下文缓存：连接时写入，update_shell / update_settings 时失效（避免每命令重复查库）。
    pub profile: Option<ShellProfile>,
    pub settings: Option<AppSettings>,
    /// P5：Workspace 过期时间快照（复查免查库；update_workspace 时置 None）。
    pub workspace_expires_at: Option<String>,
}

/// 会话注册表（进程内单例，受 Mutex 保护）。
pub struct SessionManager {
    sessions: HashMap<String, ShellSession>,
    ttl_secs: u64,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            ttl_secs: SESSION_TTL_SECS,
        }
    }

    /// 惰性清理过期会话，然后返回指定会话的可变引用。
    /// 查询会话（P8：顺带清理过期，避免只读路径残留过期会话）。
    pub fn get(&mut self, session_id: &str) -> Option<&ShellSession> {
        self.purge_expired();
        self.sessions.get(session_id)
    }

    pub fn get_mut(&mut self, session_id: &str) -> Result<&mut ShellSession, String> {
        self.purge_expired();
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| "会话不存在或已过期，请重新连接".to_string())?;
        session.last_used_at = now_secs();
        Ok(session)
    }

    /// 注册一个新会话，返回会话 ID。
    pub fn insert(
        &mut self,
        profile_id: &str,
        workspace_id: &str,
        protocol_id: &str,
        state: Arc<dyn SessionState>,
        info: ProbeResult,
    ) -> String {
        self.purge_expired();
        // 同一 Shell 只保留一个会话：先移除旧会话
        self.sessions
            .retain(|_, session| session.profile_id != profile_id);
        let id = format!("s{}", SESSION_COUNTER.fetch_add(1, Ordering::Relaxed) + 1);
        let now = now_secs();
        self.sessions.insert(
            id.clone(),
            ShellSession {
                id: id.clone(),
                profile_id: profile_id.to_string(),
                workspace_id: workspace_id.to_string(),
                protocol_id: protocol_id.to_string(),
                state,
                info,
                last_used_at: now,
                profile: None,
                settings: None,
                workspace_expires_at: None,
            },
        );
        id
    }

    /// 按 Shell 失效会话上下文缓存（update_shell 后调用）。
    pub fn invalidate_context(&mut self, profile_id: &str) {
        for session in self.sessions.values_mut() {
            if session.profile_id == profile_id {
                session.profile = None;
                session.settings = None;
            }
        }
    }

    /// 失效全部会话上下文缓存（update_settings 后调用）。
    pub fn invalidate_context_all(&mut self) {
        for session in self.sessions.values_mut() {
            session.profile = None;
            session.settings = None;
        }
    }

    /// 失效指定 Workspace 会话的授权过期快照（update_workspace 后调用）。
    pub fn invalidate_workspace_expiry(&mut self, workspace_id: &str) {
        for session in self.sessions.values_mut() {
            if session.workspace_id == workspace_id {
                session.workspace_expires_at = None;
            }
        }
    }

    /// 断开指定会话并返回被移除的会话。幂等：不存在时返回 None。
    pub fn remove(&mut self, session_id: &str) -> Option<ShellSession> {
        self.sessions.remove(session_id)
    }

    /// 移除指定 Workspace 的全部会话（Workspace 被删除时调用），返回被移除的会话 id。
    pub fn remove_by_workspace(&mut self, workspace_id: &str) -> Vec<String> {
        let removed: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.workspace_id == workspace_id)
            .map(|(id, _)| id.clone())
            .collect();
        self.sessions
            .retain(|_, session| session.workspace_id != workspace_id);
        removed
    }

    /// 移除指定 Shell 配置的全部会话（Shell 被删除时调用），返回被移除的会话 id。
    pub fn remove_by_profile(&mut self, profile_id: &str) -> Vec<String> {
        let removed: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.profile_id == profile_id)
            .map(|(id, _)| id.clone())
            .collect();
        self.sessions
            .retain(|_, session| session.profile_id != profile_id);
        removed
    }

    /// 查询某 Shell 的活跃会话 id（connect 替换前清理旧 PTY 用）。
    pub fn session_id_for_profile(&self, profile_id: &str) -> Option<String> {
        self.sessions
            .iter()
            .find(|(_, session)| session.profile_id == profile_id)
            .map(|(id, _)| id.clone())
    }

    /// 列出全部活跃会话的元信息（不含协议状态）。
    pub fn list(&mut self) -> Vec<(String, String, String, u64)> {
        self.purge_expired();
        self.sessions
            .values()
            .map(|session| {
                (
                    session.id.clone(),
                    session.profile_id.clone(),
                    session.info.server.clone(),
                    session.last_used_at,
                )
            })
            .collect()
    }

    /// 存活会话数（诊断用；当前无调用点，保留为会话表的自然访问器）。
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    fn purge_expired(&mut self) {
        let now = now_secs();
        self.sessions
            .retain(|_, session| now.saturating_sub(session.last_used_at) < self.ttl_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyState;
    impl SessionState for DummyState {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn dummy_info() -> ProbeResult {
        ProbeResult {
            status: "online".into(),
            server: "dummy".into(),
            web_server: "dummy".into(),
            runtime: "php".into(),
            current_dir: "/".into(),
            separator: "/".into(),
            message: "dummy".into(),

            php_sapi: "".to_string(),
            arch: "".to_string(),
            extensions: vec![],
            disable_functions: "".to_string(),
            info: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn insert_and_retrieve() {
        let mut manager = SessionManager::new();
        let id = manager.insert(
            "p1",
            "w1",
            "builtin.mock.v1",
            Arc::new(DummyState),
            dummy_info(),
        );
        assert_eq!(manager.get_mut(&id).unwrap().profile_id, "p1");
    }

    #[test]
    fn same_profile_replaces_old_session() {
        let mut manager = SessionManager::new();
        let first = manager.insert(
            "p1",
            "w1",
            "builtin.mock.v1",
            Arc::new(DummyState),
            dummy_info(),
        );
        let second = manager.insert(
            "p1",
            "w1",
            "builtin.mock.v1",
            Arc::new(DummyState),
            dummy_info(),
        );
        assert_ne!(first, second);
        assert!(manager.get_mut(&first).is_err(), "旧会话应被替换");
        assert!(manager.get_mut(&second).is_ok());
    }

    #[test]
    fn expired_session_is_purged() {
        let mut manager = SessionManager::new();
        manager.ttl_secs = 1;
        let id = manager.insert(
            "p1",
            "w1",
            "builtin.mock.v1",
            Arc::new(DummyState),
            dummy_info(),
        );
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(manager.get_mut(&id).is_err(), "过期会话应被清理");
    }

    #[test]
    fn remove_is_idempotent() {
        let mut manager = SessionManager::new();
        let id = manager.insert(
            "p1",
            "w1",
            "builtin.mock.v1",
            Arc::new(DummyState),
            dummy_info(),
        );
        assert!(manager.remove(&id).is_some());
        assert!(manager.remove(&id).is_none(), "重复断开应幂等返回 None");
    }

    #[test]
    fn list_returns_metadata() {
        let mut manager = SessionManager::new();
        manager.insert(
            "p1",
            "w1",
            "builtin.mock.v1",
            Arc::new(DummyState),
            dummy_info(),
        );
        let sessions = manager.list();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].1, "p1");
    }
}
