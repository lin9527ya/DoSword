//! 内存会话管理：连接成功后保存协议会话状态，TTL 过期后惰性清理。
//!
//! 会话不落盘——应用重启即全部失效，需要重新连接。对安全测试工具而言
//! 这是简单且安全的策略。

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dosword_sdk::SessionState;
use dosword_sdk::domain::{AppSettings, ProbeResult, SessionInfo, ShellProfile};

/// 会话默认存活时长（秒）。
pub const SESSION_TTL_SECS: u64 = 4 * 60 * 60;

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// 令牌桶（W4 背压）：同一会话的 PTY 轮询与文件分块**共享**一个桶，
/// 避免 agent / 前端高频请求把目标打满。容量内突发不限制，持续速率受限。
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: std::time::Instant,
}

impl TokenBucket {
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec,
            last: std::time::Instant::now(),
        }
    }

    fn refill(&mut self, now: std::time::Instant) {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last = now;
        }
    }

    /// 取 `count` 个令牌；在 `timeout` 内取不到返回 `false`。
    pub fn acquire(&mut self, count: f64, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let now = std::time::Instant::now();
            self.refill(now);
            if self.tokens >= count {
                self.tokens -= count;
                return true;
            }
            if now >= deadline {
                return false;
            }
            let wait = ((count - self.tokens) / self.refill_per_sec).clamp(0.001, 0.05);
            std::thread::sleep(std::time::Duration::from_secs_f64(wait));
        }
    }
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
    /// 最近一次心跳成功时间（W4）。心跳**不**刷新 `last_used_at`：
    /// TTL 仍由用户交互决定，空闲会话照常过期。
    pub last_heartbeat_at: u64,
    /// 最近一次心跳是否失败（目标掉线 / 会话失效）。
    pub stale: bool,
    /// W4 背压：PTY 轮询与文件分块共享的令牌桶。
    pub limiter: Arc<std::sync::Mutex<TokenBucket>>,
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
                last_heartbeat_at: now,
                stale: false,
                limiter: Arc::new(std::sync::Mutex::new(TokenBucket::new(120.0, 40.0))),
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
    /// 会话列表快照（含心跳状态），按最近交互时间倒序。
    pub fn list(&mut self) -> Vec<SessionInfo> {
        self.purge_expired();
        let mut items: Vec<SessionInfo> = self
            .sessions
            .values()
            .map(|session| SessionInfo {
                session_id: session.id.clone(),
                profile_id: session.profile_id.clone(),
                server: session.info.server.clone(),
                last_used_at: session.last_used_at,
                last_heartbeat_at: session.last_heartbeat_at,
                stale: session.stale,
            })
            .collect();
        items.sort_by_key(|item| std::cmp::Reverse(item.last_used_at));
        items
    }

    /// 心跳目标：`(session_id, protocol_id, 连接状态)`。
    /// 锁内只做克隆，探活在锁外执行。
    pub fn heartbeat_targets(&mut self) -> Vec<(String, String, Arc<dyn SessionState>)> {
        self.purge_expired();
        self.sessions
            .values()
            .map(|session| {
                (
                    session.id.clone(),
                    session.protocol_id.clone(),
                    Arc::clone(&session.state),
                )
            })
            .collect()
    }

    /// 会话共享令牌桶（W4 背压：PTY 与文件流共用）。
    pub fn limiter(
        &mut self,
        session_id: &str,
    ) -> Result<Arc<std::sync::Mutex<TokenBucket>>, String> {
        self.purge_expired();
        self.sessions
            .get(session_id)
            .map(|session| Arc::clone(&session.limiter))
            .ok_or_else(|| "会话不存在或已过期，请重新连接".to_string())
    }

    /// 记录一次心跳结果：成功刷新时间并清除 stale；失败只标记 stale。
    pub fn mark_heartbeat(&mut self, session_id: &str, alive: bool) {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.stale = !alive;
            if alive {
                session.last_heartbeat_at = now_secs();
            }
        }
    }

    /// 全部活跃会话 id（设置变更时批量失效用）。
    pub fn list_ids(&mut self) -> Vec<String> {
        self.purge_expired();
        self.sessions.keys().cloned().collect()
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
            capabilities: None,
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

    /// W4：心跳失败标记 stale，成功清除；且**不**刷新用户交互时间（TTL 不变）。
    #[test]
    fn heartbeat_marks_stale_and_does_not_touch_last_used() {
        let mut manager = SessionManager::new();
        let id = manager.insert(
            "p1",
            "w1",
            "builtin.mock.v1",
            Arc::new(DummyState),
            dummy_info(),
        );
        let before = manager.list();
        assert!(!before[0].stale, "新会话不应是 stale");
        let used_at = before[0].last_used_at;

        manager.mark_heartbeat(&id, false);
        let after_fail = manager.list();
        assert!(after_fail[0].stale, "心跳失败应标记 stale");
        assert_eq!(
            after_fail[0].last_used_at, used_at,
            "心跳不得刷新 last_used_at"
        );

        manager.mark_heartbeat(&id, true);
        let after_ok = manager.list();
        assert!(!after_ok[0].stale, "心跳成功应清除 stale");
        assert_eq!(after_ok[0].last_used_at, used_at);
        // 目标列表也用于探活
        assert_eq!(manager.heartbeat_targets().len(), 1);
    }

    /// W4 背压：令牌桶按容量限制突发、按速率补充。
    #[test]
    fn token_bucket_throttles_and_refills() {
        let mut bucket = TokenBucket::new(2.0, 100.0);
        assert!(bucket.acquire(1.0, std::time::Duration::ZERO));
        assert!(bucket.acquire(1.0, std::time::Duration::ZERO));
        assert!(
            !bucket.acquire(1.0, std::time::Duration::ZERO),
            "桶空时应立即失败"
        );
        // 100/s → 约 10ms 补充一个令牌
        assert!(
            bucket.acquire(1.0, std::time::Duration::from_millis(200)),
            "等待后应能取到令牌"
        );
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
        assert_eq!(sessions[0].profile_id, "p1");
    }
}
