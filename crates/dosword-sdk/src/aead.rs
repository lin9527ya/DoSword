//! AEAD 传输层：HKDF-SHA256 + AES-256-GCM + 防重放。
//!
//! 帧格式：`base64( nonce[12] || seq[8 BE] || ciphertext || tag[16] )`
//! AAD：`"dsw2" || dir(1) || seq(8 BE)`，`dir` 为 0x01（请求）/ 0x02（响应）。
//! 密钥：`HKDF-SHA256(ikm = SHA256(password), salt = "dosword/aead/v2", info = "dsw2", 32)`。
//!
//! # nonce 的构成（请求方向）
//!
//! 请求 nonce = `sid[8] || seq 低 32 位[4 BE]`，而不是纯随机 12 字节：
//!
//! - `sid` 每次**连接**随机生成一次，连接内所有请求共用 → 服务端据此把重放窗口
//!   按连接隔离（stub 里一个连接一个状态文件）。重放窗口状态存在目标机上、会跨
//!   连接存活，若没有 `sid`，客户端重连后序号从 1 重新开始就会被 stub 判成重放而
//!   **永久拒绝**（死会话，实测如此）。`sid` 由 GCM 隐式认证（它是 IV），无法篡改。
//! - 低 32 位用递增序号而非随机数，保证连接内 nonce **必然不重复**。
//!
//! 响应方向仍用纯随机 nonce（服务端生成），客户端窗口只存在于内存、随会话消失。
//!
//! 已知边界：目标机状态文件被系统清理后，对应连接的重放窗口随之失效（旧帧可被重放
//! 一次）；这是「不在目标机长期留状态」与「跨连接防重放」之间的取舍。连接内与
//! 状态文件存活期间的重放都会被拒。
//!
//! 失败即失败：解密 / tag / seq 任一校验不过都返回错误，绝不回退明文。

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use sha2::{Digest, Sha256};

pub const PROTOCOL_TAG: &[u8] = b"dsw2";
pub const DIR_REQUEST: u8 = 0x01;
pub const DIR_RESPONSE: u8 = 0x02;
const HKDF_SALT: &[u8] = b"dosword/aead/v2";
const HKDF_INFO: &[u8] = b"dsw2";
const NONCE_LEN: usize = 12;
/// 请求 nonce 前 8 字节 = 连接标识（服务端据此隔离重放窗口）
pub const SID_LEN: usize = 8;
const SEQ_LEN: usize = 8;
const TAG_LEN: usize = 16;

/// HKDF-SHA256（独立函数，便于用 RFC 5869 向量验证）。
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, String> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; length];
    hk.expand(info, &mut out)
        .map_err(|error| format!("HKDF 派生失败：{error}"))?;
    Ok(out)
}

/// 由连接密码派生 32 字节会话密钥。
pub fn derive_key(password: &str) -> [u8; 32] {
    let ikm = Sha256::digest(password.as_bytes());
    let okm = hkdf_sha256(&ikm, HKDF_SALT, HKDF_INFO, 32).expect("32 字节固定合法");
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

/// 嵌入 stub 的 IKM（SHA256(password) 的十六进制），不是明文密码。
pub fn ikm_hex(password: &str) -> String {
    hex(&Sha256::digest(password.as_bytes()))
}

/// 头鉴权令牌：密钥前 8 字节的十六进制（16 字符）。
pub fn token_hex(key: &[u8; 32]) -> String {
    hex(&key[..8])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn aad(dir: u8, seq: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROTOCOL_TAG.len() + 1 + SEQ_LEN);
    out.extend(PROTOCOL_TAG);
    out.push(dir);
    out.extend(seq.to_be_bytes());
    out
}

fn cipher(key: &[u8; 32]) -> Result<Aes256Gcm, String> {
    Aes256Gcm::new_from_slice(key).map_err(|error| format!("AEAD 密钥初始化失败：{error}"))
}

fn random_nonce() -> [u8; NONCE_LEN] {
    // 复用 uuid 的 CSPRNG（v4 共 122 位随机），取前 12 字节作 nonce
    let uuid = uuid::Uuid::new_v4();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&uuid.as_bytes()[..NONCE_LEN]);
    nonce
}

/// 连接标识：每次连接随机一次，写入请求 nonce 前 8 字节。
///
/// uuid v4 的前 8 字节含 6 个固定位（版本 / 变体），实际熵约 58 位 —— 对
/// 「每连接一个 sid」而言足够（2^29 次连接才有约 50% 碰撞概率），且不引入新依赖。
pub fn random_sid() -> [u8; SID_LEN] {
    let uuid = uuid::Uuid::new_v4();
    let mut sid = [0u8; SID_LEN];
    sid.copy_from_slice(&uuid.as_bytes()[..SID_LEN]);
    sid
}

/// 请求 nonce = `sid[8] || seq 低 32 位[4 BE]`。同连接内 seq 单调 → nonce 不重复。
pub fn request_nonce(sid: &[u8; SID_LEN], seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..SID_LEN].copy_from_slice(sid);
    nonce[SID_LEN..].copy_from_slice(&(seq as u32).to_be_bytes());
    nonce
}

/// 封装一帧（随机 nonce）。`seq` 由调用方保证每方向单调递增。
pub fn seal(key: &[u8; 32], dir: u8, seq: u64, plaintext: &[u8]) -> Result<String, String> {
    seal_with_nonce(key, dir, seq, &random_nonce(), plaintext)
}

/// 封装一帧，nonce 由调用方给定（`AeadSession` 用 `sid || seq` 构造）。
pub fn seal_with_nonce(
    key: &[u8; 32],
    dir: u8,
    seq: u64,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<String, String> {
    let cipher = cipher(key)?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &aad(dir, seq),
            },
        )
        .map_err(|_| "AEAD 加密失败".to_string())?;
    let mut frame = Vec::with_capacity(NONCE_LEN + SEQ_LEN + encrypted.len());
    frame.extend(nonce);
    frame.extend(seq.to_be_bytes());
    frame.extend(encrypted);
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &frame,
    ))
}

/// 解封一帧，返回 `(seq, plaintext)`。tag 校验失败即报错。
pub fn open(key: &[u8; 32], dir: u8, payload: &str) -> Result<(u64, Vec<u8>), String> {
    let frame = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload.trim())
        .map_err(|_| "AEAD 帧 Base64 解码失败".to_string())?;
    if frame.len() < NONCE_LEN + SEQ_LEN + TAG_LEN {
        return Err("AEAD 帧长度不足".to_string());
    }
    let (nonce, rest) = frame.split_at(NONCE_LEN);
    let (seq_bytes, ciphertext) = rest.split_at(SEQ_LEN);
    let seq = u64::from_be_bytes(seq_bytes.try_into().expect("8 字节"));
    let cipher = cipher(key)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad(dir, seq),
            },
        )
        .map_err(|_| "AEAD 校验失败（密文被篡改或密钥不匹配）".to_string())?;
    Ok((seq, plaintext))
}

/// 64 位滑动窗口，拒绝重放与过旧的乱序包。
#[derive(Debug, Default)]
pub struct ReplayWindow {
    max_seq: u64,
    /// bit i 表示 `max_seq - i` 已经收到
    bitmap: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// 接受则返回 true；重放 / 超出窗口返回 false。
    pub fn accept(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.max_seq {
            let shift = seq - self.max_seq;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.max_seq = seq;
            true
        } else {
            let diff = self.max_seq - seq;
            if diff >= 64 {
                return false;
            }
            let bit = 1u64 << diff;
            if self.bitmap & bit != 0 {
                false
            } else {
                self.bitmap |= bit;
                true
            }
        }
    }
}

/// 会话级 AEAD 状态：连接标识 + 发送序号 + 接收滑动窗口。
pub struct AeadSession {
    key: [u8; 32],
    sid: [u8; SID_LEN],
    send_seq: u64,
    recv: ReplayWindow,
    token: String,
}

impl AeadSession {
    pub fn new(password: &str) -> Self {
        let key = derive_key(password);
        let token = token_hex(&key);
        Self {
            key,
            sid: random_sid(),
            send_seq: 0,
            recv: ReplayWindow::new(),
            token,
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// 本连接的标识（16 个十六进制字符），仅用于日志 / 排查。
    pub fn sid_hex(&self) -> String {
        hex(&self.sid)
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<String, String> {
        self.send_seq = self.send_seq.saturating_add(1);
        let nonce = request_nonce(&self.sid, self.send_seq);
        seal_with_nonce(&self.key, DIR_REQUEST, self.send_seq, &nonce, plaintext)
    }

    pub fn open(&mut self, payload: &str) -> Result<Vec<u8>, String> {
        let (seq, plaintext) = open(&self.key, DIR_RESPONSE, payload)?;
        if !self.recv.accept(seq) {
            return Err(format!("响应序号被拒绝（重放或超出窗口）：{seq}"));
        }
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 Test Case 1
    #[test]
    fn hkdf_matches_rfc5869_case1() {
        let ikm = vec![0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(
            okm,
            vec![
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
            ]
        );
    }

    /// 取出帧里的 nonce（base64 → 前 12 字节）
    fn frame_nonce(frame: &str) -> Vec<u8> {
        let raw =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, frame).unwrap();
        raw[..NONCE_LEN].to_vec()
    }

    /// 请求 nonce = `sid || seq 低 32 位`：连接内 sid 不变、计数器递增 → 必不重复。
    #[test]
    fn session_nonce_is_sid_then_counter() {
        let key = derive_key("secret");
        let mut session = AeadSession::new("secret");
        let first = session.seal(b"one").unwrap();
        let second = session.seal(b"two").unwrap();
        let (n1, n2) = (frame_nonce(&first), frame_nonce(&second));
        assert_eq!(n1[..SID_LEN], n2[..SID_LEN], "同一连接内 sid 必须保持不变");
        assert_eq!(u32::from_be_bytes(n1[SID_LEN..].try_into().unwrap()), 1);
        assert_eq!(u32::from_be_bytes(n2[SID_LEN..].try_into().unwrap()), 2);
        assert_ne!(n1, n2);
        assert_eq!(open(&key, DIR_REQUEST, &first).unwrap().1, b"one");
        assert_eq!(open(&key, DIR_REQUEST, &second).unwrap().1, b"two");
    }

    /// 不同连接（即使同一密码）必须得到不同 sid —— stub 的重放窗口靠它隔离，
    /// 否则重连后序号从 1 重来会被判成重放，会话永久不可用。
    #[test]
    fn sessions_use_distinct_sids() {
        let first = AeadSession::new("secret");
        let second = AeadSession::new("secret");
        assert_ne!(first.sid_hex(), second.sid_hex());
        assert_eq!(first.sid_hex().len(), SID_LEN * 2);
    }

    #[test]
    fn seal_open_round_trip_and_padding() {
        let key = derive_key("secret");
        let frame = seal(&key, DIR_REQUEST, 7, b"hello aead").unwrap();
        // base64 帧里不应出现明文
        assert!(!frame.contains("hello"));
        let (seq, plain) = open(&key, DIR_REQUEST, &frame).unwrap();
        assert_eq!(seq, 7);
        assert_eq!(plain, b"hello aead");
    }

    #[test]
    fn tampered_frame_is_rejected() {
        let key = derive_key("secret");
        let frame = seal(&key, DIR_REQUEST, 1, b"payload").unwrap();
        let mut raw =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &frame).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let tampered = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &raw);
        assert!(open(&key, DIR_REQUEST, &tampered).is_err());
    }

    #[test]
    fn direction_is_bound_into_aad() {
        let key = derive_key("secret");
        let frame = seal(&key, DIR_REQUEST, 1, b"x").unwrap();
        // 用响应方向解同一帧必须失败（AAD 方向域不同）
        assert!(open(&key, DIR_RESPONSE, &frame).is_err());
    }

    #[test]
    fn replay_window_accepts_out_of_order_once() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(1));
        assert!(window.accept(2));
        assert!(!window.accept(2), "重复序号必须拒绝");
        assert!(!window.accept(1), "已收到的序号必须拒绝");
        assert!(window.accept(4));
        assert!(window.accept(3), "窗口内的乱序包应被接受一次");
        assert!(!window.accept(3));
        // 把最大序号推高后再发一个过旧的序号
        assert!(window.accept(200));
        assert!(!window.accept(100), "超出 64 位窗口的旧序号必须拒绝");
    }

    #[test]
    fn session_rejects_replayed_response() {
        // 模拟服务端响应（方向 = 0x02），客户端 AeadSession::open 只接受响应方向
        let key = derive_key("secret");
        let frame = seal(&key, DIR_RESPONSE, 1, b"r1").unwrap();
        let mut receiver = AeadSession::new("secret");
        let _ = receiver.open(&frame).unwrap();
        assert!(receiver.open(&frame).is_err(), "重放响应必须拒绝");
    }
}
