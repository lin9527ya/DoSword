//! 交互式 PTY 会话注册表：管理目标反弹回连的 TCP 流，
//! 供前端 xterm 双向读写（start_pty_session / pty_write / pty_read / pty_close）。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

pub struct PtyRegistry {
    sessions: parking_lot::Mutex<HashMap<String, Arc<parking_lot::Mutex<TcpStream>>>>,
    /// pty_id -> 所属 Shell 会话 id（断开 Shell 时级联清理 PTY）。
    owner: parking_lot::Mutex<HashMap<String, String>>,
    counter: std::sync::atomic::AtomicU64,
}

impl PtyRegistry {
    pub fn new() -> Self {
        Self {
            sessions: parking_lot::Mutex::new(HashMap::new()),
            owner: parking_lot::Mutex::new(HashMap::new()),
            counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// 注册回连的 TCP 流（绑定所属 Shell 会话），返回 PTY 会话 ID。
    pub fn insert(&self, session_id: &str, stream: TcpStream) -> String {
        let id = format!(
            "pty{}",
            self.counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(80)));
        self.sessions
            .lock()
            .insert(id.clone(), Arc::new(parking_lot::Mutex::new(stream)));
        self.owner.lock().insert(id.clone(), session_id.to_string());
        id
    }

    /// 写入数据到目标 shell。
    pub fn write(&self, id: &str, data: &[u8]) -> Result<(), String> {
        // P8：锁内仅克隆流句柄，IO 在锁外执行（慢流不阻塞其他 PTY 操作）
        let stream = self
            .sessions
            .lock()
            .get(id)
            .cloned()
            .ok_or_else(|| "PTY 会话不存在或已关闭".to_string())?;
        let mut guard = stream.lock();
        guard
            .write_all(data)
            .map_err(|error| format!("PTY 写入失败：{error}"))
    }

    /// 非阻塞读取可用输出（空串表示暂时无输出；错误表示连接关闭）。
    pub fn read(&self, id: &str) -> Result<Vec<u8>, String> {
        // P8：锁内仅克隆流句柄，IO 在锁外执行
        let stream = self
            .sessions
            .lock()
            .get(id)
            .cloned()
            .ok_or_else(|| "PTY 会话不存在或已关闭".to_string())?;
        let mut guard = stream.lock();
        let mut buf = vec![0u8; 8192];
        match guard.read(&mut buf) {
            Ok(0) => Err("PTY 连接已关闭".to_string()),
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(Vec::new()),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok(Vec::new()),
            Err(error) => Err(format!("PTY 读取失败：{error}")),
        }
    }

    /// 关闭并移除 PTY 会话。
    pub fn close(&self, id: &str) {
        self.sessions.lock().remove(id);
        self.owner.lock().remove(id);
    }

    /// 清理某 Shell 会话关联的全部 PTY（断开 Shell 时调用）。
    pub fn close_for_session(&self, session_id: &str) {
        let ids: Vec<String> = self
            .owner
            .lock()
            .iter()
            .filter(|(_, owner_session)| owner_session == &session_id)
            .map(|(id, _)| id.clone())
            .collect();
        {
            let mut sessions = self.sessions.lock();
            for id in &ids {
                sessions.remove(id);
            }
        }
        {
            let mut owner = self.owner.lock();
            for id in &ids {
                owner.remove(id);
            }
        }
    }

    /// 当前存活的 PTY 数量（测试与诊断用）。
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.sessions.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 建立一对已连接的 TCP 流（本地监听 + 连接）。
    fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn close_for_session_removes_owned_ptys() {
        let registry = PtyRegistry::new();
        let (a, a_peer) = connected_pair();
        let (b, b_peer) = connected_pair();
        let pty_a = registry.insert("s1", a);
        let pty_b = registry.insert("s2", b);
        // 保持对端存活（否则 client 立即读到 EOF）
        let _peers = (a_peer, b_peer);
        assert_eq!(registry.len(), 2);
        registry.close_for_session("s1");
        assert_eq!(registry.len(), 1, "仅 s1 的 PTY 应被清理");
        assert!(registry.read(&pty_a).is_err(), "已清理的 PTY 应不可读");
        assert!(registry.read(&pty_b).is_ok(), "保留的 PTY 应可读");
        // 幂等：重复清理无副作用
        registry.close_for_session("s1");
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn close_removes_single_pty_and_owner() {
        let registry = PtyRegistry::new();
        let (a, _peer) = connected_pair();
        let pty = registry.insert("s1", a);
        drop(_peer);
        registry.close(&pty);
        assert_eq!(registry.len(), 0);
        assert!(registry.write(&pty, b"x").is_err(), "关闭后写入应报错");
    }
}
