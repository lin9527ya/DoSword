//! 静态密钥保管：连接密码 / MCP 令牌在数据库里**加密存放**。
//!
//! # 密钥来源（按优先级）
//!
//! 1. 系统钥匙串（Linux Secret Service / Windows Credential Manager / macOS Keychain）
//! 2. 数据目录下的 `master.key`（Unix 上 0600）—— 无桌面会话的服务器、CI、容器里回落
//!
//! 两者都不可用时返回 `None`，调用方按「不加密」处理并打日志。实际几乎不会发生：
//! 数据目录不可写时数据库本身也无法使用。
//!
//! # 威慑边界（写清楚，避免误以为这是全盘防护）
//!
//! 防的是**数据库文件 / 备份外泄**后被直接读出明文密码；**不防**同机同用户下的提权
//! 读取 —— 能读数据目录就能读 `master.key`。换机器或丢了钥匙串后旧密文解不开，
//! 需要重新录入密码。
//!
//! # 存储格式
//!
//! `enc:v1:<base64(nonce[12] || ciphertext || tag[16])>`，AAD = 字段名：
//! 把密文挪到别的字段（或用另一把 key）会解密失败。空值不加密（「没设置密码」本身
//! 是有意义的状态）。旧版明文值原样可读，启动时由 `Database` 统一迁移。

use std::path::Path;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;

const PREFIX: &str = "enc:v1:";
const SERVICE: &str = "dosword";
const ACCOUNT: &str = "master-key";
const KEY_FILE: &str = "master.key";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// 主密钥及其来源。
pub struct SecretStore {
    key: [u8; KEY_LEN],
    source: &'static str,
}

impl SecretStore {
    /// 加载或创建主密钥。钥匙串优先，其次数据目录内的密钥文件。
    ///
    /// 返回 `None` 表示两者都不可用（调用方应降级为不加密并打日志）。
    pub fn load(data_dir: &Path) -> Option<Self> {
        if let Some(store) = Self::from_keyring() {
            // 一行启动日志：让运维知道密钥到底存在哪（钥匙串还是数据目录内的文件）
            eprintln!(
                "[secrets] 敏感字段加密已启用（主密钥来源：{}）",
                store.source()
            );
            return Some(store);
        }
        let store = Self::from_key_file(data_dir);
        if let Some(store) = &store {
            eprintln!(
                "[secrets] 敏感字段加密已启用（系统钥匙串不可用，主密钥来源：{}）",
                store.source()
            );
        }
        store
    }

    pub fn source(&self) -> &'static str {
        self.source
    }

    /// 是否为加密格式（旧版明文返回 false）。
    pub fn is_encrypted(stored: &str) -> bool {
        stored.starts_with(PREFIX)
    }

    /// 加密一个字段值。空值原样返回（「未设置」应保持为空）。
    pub fn encrypt(&self, field: &str, plaintext: &str) -> String {
        if plaintext.is_empty() {
            return String::new();
        }
        let Ok(cipher) = Aes256Gcm::new_from_slice(&self.key) else {
            return plaintext.to_string();
        };
        let mut nonce = [0u8; NONCE_LEN];
        // 系统随机源不可用时宁可明文也不丢数据（此时 `load` 通常也已失败）
        if getrandom::fill(&mut nonce).is_err() {
            return plaintext.to_string();
        }
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: field.as_bytes(),
        };
        match cipher.encrypt(Nonce::from_slice(&nonce), payload) {
            Ok(sealed) => {
                let mut frame = Vec::with_capacity(NONCE_LEN + sealed.len());
                frame.extend_from_slice(&nonce);
                frame.extend_from_slice(&sealed);
                format!(
                    "{PREFIX}{}",
                    base64::engine::general_purpose::STANDARD.encode(frame)
                )
            }
            Err(_) => plaintext.to_string(),
        }
    }

    /// 解密一个字段值。非加密格式（旧版明文）原样返回；解密失败返回 `None`
    /// （密钥丢失 / 密文损坏 / 字段不符 —— 调用方应告警并让用户重新录入）。
    pub fn decrypt(&self, field: &str, stored: &str) -> Option<String> {
        if !Self::is_encrypted(stored) {
            return Some(stored.to_string());
        }
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&stored[PREFIX.len()..])
            .ok()?;
        if raw.len() < NONCE_LEN {
            return None;
        }
        let (nonce, sealed) = raw.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(&self.key).ok()?;
        let payload = Payload {
            msg: sealed,
            aad: field.as_bytes(),
        };
        let plain = cipher.decrypt(Nonce::from_slice(nonce), payload).ok()?;
        String::from_utf8(plain).ok()
    }

    /// 钥匙串读取 / 首次创建。
    fn from_keyring() -> Option<Self> {
        let entry = keyring::Entry::new(SERVICE, ACCOUNT).ok()?;
        let key = match entry.get_password() {
            Ok(encoded) => decode_key(&encoded)?,
            // 首次使用：生成并写入钥匙串
            Err(keyring::Error::NoEntry) => {
                let key = random_key()?;
                entry
                    .set_password(&base64::engine::general_purpose::STANDARD.encode(key))
                    .ok()?;
                // 并发首次启动（桌面端与 CLI 同时）可能互相覆盖：以**最终读到的**为准，
                // 否则一方会拿自己的 key 去解另一方加密的数据
                entry
                    .get_password()
                    .ok()
                    .and_then(|encoded| decode_key(&encoded))
                    .or(Some(key))?
            }
            // 无 Secret Service / 无桌面会话等：交给文件回落
            Err(_) => return None,
        };
        Some(Self {
            key,
            source: "keyring",
        })
    }

    fn from_key_file(data_dir: &Path) -> Option<Self> {
        let path = data_dir.join(KEY_FILE);
        if let Some(store) = Self::read_key_file(&path) {
            return Some(store);
        }
        let key = random_key()?;
        match write_key_file(&path, &key) {
            Ok(()) => Some(Self {
                key,
                source: "file",
            }),
            // 并发首次启动（桌面端与 CLI 同时）：对方先创建了文件 → 读它的
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Self::read_key_file(&path)
            }
            Err(_) => None,
        }
    }

    fn read_key_file(path: &Path) -> Option<Self> {
        let encoded = std::fs::read_to_string(path).ok()?;
        let key = decode_key(encoded.trim())?;
        Some(Self {
            key,
            source: "file",
        })
    }
}

fn random_key() -> Option<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    getrandom::fill(&mut key).ok()?;
    Some(key)
}

fn decode_key(encoded: &str) -> Option<[u8; KEY_LEN]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    if raw.len() != KEY_LEN {
        return None;
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&raw);
    Some(key)
}

fn write_key_file(path: &Path, key: &[u8; KEY_LEN]) -> std::io::Result<()> {
    use std::io::Write as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 0600：仅本用户可读写（防的是同机其他用户与备份外泄）
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> SecretStore {
        SecretStore {
            key: [7u8; KEY_LEN],
            source: "test",
        }
    }

    #[test]
    fn round_trip_and_prefix() {
        let store = store();
        let sealed = store.encrypt("shell.password", "s3cret-密码");
        assert!(SecretStore::is_encrypted(&sealed), "{sealed}");
        assert!(!sealed.contains("s3cret"), "密文里不得出现明文");
        assert_eq!(
            store.decrypt("shell.password", &sealed).as_deref(),
            Some("s3cret-密码")
        );
    }

    #[test]
    fn empty_stays_empty() {
        let store = store();
        assert_eq!(store.encrypt("shell.password", ""), "");
        assert_eq!(store.decrypt("shell.password", "").as_deref(), Some(""));
    }

    #[test]
    fn legacy_plaintext_passes_through() {
        let store = store();
        assert_eq!(
            store.decrypt("shell.password", "old-plaintext").as_deref(),
            Some("old-plaintext")
        );
    }

    #[test]
    fn aad_binds_field_and_wrong_key_fails() {
        let store = store();
        let sealed = store.encrypt("shell.password", "abc");
        // 挪到另一个字段 → AAD 不符，必须失败
        assert!(store.decrypt("mcp.token", &sealed).is_none());
        // 换一把 key → 必须失败
        let other = SecretStore {
            key: [9u8; KEY_LEN],
            source: "test",
        };
        assert!(other.decrypt("shell.password", &sealed).is_none());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let store = store();
        let sealed = store.encrypt("shell.password", "abc");
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(&sealed[PREFIX.len()..])
            .unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = format!(
            "{PREFIX}{}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        );
        assert!(store.decrypt("shell.password", &tampered).is_none());
    }

    #[test]
    fn key_file_is_created_with_restrictive_permissions() {
        let dir = std::env::temp_dir().join(format!("dosword-key-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // 钥匙串在测试环境通常不可用；即便可用，这个用例也直接测文件回落
        let store = SecretStore::from_key_file(&dir).expect("应能创建密钥文件");
        assert_eq!(store.source(), "file");
        let path = dir.join(KEY_FILE);
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "密钥文件必须仅本用户可读写");
        }
        // 再次加载应读到同一把 key
        let again = SecretStore::from_key_file(&dir).expect("应能读回密钥");
        let sealed = store.encrypt("f", "x");
        assert_eq!(again.decrypt("f", &sealed).as_deref(), Some("x"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
