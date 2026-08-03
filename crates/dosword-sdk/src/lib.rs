//! DoSword 协议 SDK。
//!
//! 纯接口库（零 tauri 依赖）：协议插件实现 [`plugin::ProtocolPlugin`]
//! 后即可接入宿主，授权检查 / 审计 / 会话管理由宿主自动完成。

pub mod domain;
pub mod encoder;
pub mod plugin;
pub mod protocol;

pub use encoder::{
    aes_cbc_decrypt, aes_cbc_encrypt, aes_ecb_decrypt, aes_ecb_encrypt, aes_iv, aes_key,
    char_decode, des_ecb_decrypt, des_ecb_encrypt, des_key, md5_hex, obfuscate_decode,
    Base64Encoder, CharEncoder, DesEcbEncoder, EncoderRegistry, PayloadEncoder,
    STUB_LANGUAGES, XorBase64Encoder,
};
pub use plugin::{PluginKind, PluginManifest, PluginRegistry, ProtocolPlugin};
pub use protocol::{Protocol, ProtocolError, SessionState};
