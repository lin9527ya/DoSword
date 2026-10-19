//! 数据目录单实例锁。
//!
//! 桌面端与 `dosword-cli` 共用同一数据目录 / 同一 SQLite 文件。SQLite 侧靠
//! `busy_timeout` + WAL 保证并发安全（CLI 与 GUI 同时跑不会损坏库），
//! 但**两个桌面实例**同时打开会出现两个窗口、两套会话表与重复审计，属于用户侧事故。
//!
//! 因此：GUI 启动时对 `<app_data>/dosword.lock` 取**独占**锁并持有到进程退出；
//! CLI 不取锁（短命进程 + busy_timeout 已足够），避免"开着 GUI 就用不了 CLI"。
//!
//! 进程崩溃时操作系统会释放文件锁，不会留下永久脏锁。

use std::fs::{File, OpenOptions};
use std::path::Path;

/// 持有中的锁。Drop 时释放（关闭文件句柄即释放 OS 锁）。
pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// 获取独占锁。已有实例持有时返回 Err（含可展示给用户的原因）。
    pub fn acquire(dir: &Path) -> Result<Self, String> {
        let path = dir.join("dosword.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| format!("无法创建锁文件 {}：{error}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(error) => Err(format!(
                "另一个 DoSword 实例正在使用该数据目录（{}）：{error}",
                path.display()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("dosword-lock-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("创建临时目录");
        dir
    }

    #[test]
    fn second_acquire_is_rejected() {
        let dir = temp_dir("excl");
        let first = InstanceLock::acquire(&dir).expect("首次获取应成功");
        let second = InstanceLock::acquire(&dir);
        assert!(second.is_err(), "同一目录不应允许第二个实例");
        let message = second.err().unwrap();
        assert!(message.contains("另一个 DoSword 实例"), "{message}");
        drop(first);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lock_is_released_on_drop() {
        let dir = temp_dir("drop");
        {
            let _guard = InstanceLock::acquire(&dir).expect("首次获取应成功");
        }
        // 上一个 guard 已释放，可再次获取
        let again = InstanceLock::acquire(&dir);
        assert!(again.is_ok(), "释放后应可重新获取");
        let _ = std::fs::remove_dir_all(dir);
    }
}
