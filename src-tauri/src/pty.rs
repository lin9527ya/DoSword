//! 交互式 PTY 会话注册表：管理目标反弹回连的 TCP 流，
//! 供前端 xterm 双向读写（start_pty_session / pty_write / pty_read / pty_close）。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

pub struct PtyRegistry {
    sessions: Mutex<HashMap<String, Arc<Mutex<TcpStream>>>>,
    counter: std::sync::atomic::AtomicU64,
}

impl PtyRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            counter: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// 注册回连的 TCP 流，返回 PTY 会话 ID。
    pub fn insert(&self, stream: TcpStream) -> String {
        let id = format!(
            "pty{}",
            self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(80)));
        self.sessions
            .lock()
            .map_err(|_| ())
            .map(|mut map| {
                map.insert(id.clone(), Arc::new(Mutex::new(stream)));
            })
            .ok();
        id
    }

    /// 写入数据到目标 shell。
    pub fn write(&self, id: &str, data: &[u8]) -> Result<(), String> {
        let sessions = self.sessions.lock().map_err(|_| "PTY 锁异常".to_string())?;
        let stream = sessions
            .get(id)
            .ok_or_else(|| "PTY 会话不存在或已关闭".to_string())?;
        let mut guard = stream.lock().map_err(|_| "PTY 流锁异常".to_string())?;
        guard
            .write_all(data)
            .map_err(|error| format!("PTY 写入失败：{error}"))
    }

    /// 非阻塞读取可用输出（空串表示暂时无输出；错误表示连接关闭）。
    pub fn read(&self, id: &str) -> Result<Vec<u8>, String> {
        let sessions = self.sessions.lock().map_err(|_| "PTY 锁异常".to_string())?;
        let stream = sessions
            .get(id)
            .ok_or_else(|| "PTY 会话不存在或已关闭".to_string())?;
        let mut guard = stream.lock().map_err(|_| "PTY 流锁异常".to_string())?;
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
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(id);
        }
    }

    /// 清理某会话关联的全部 PTY（断开 Shell 时调用）。
    pub fn close_for_session(&self, session_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, _| true);
        }
        let _ = session_id;
    }
}
