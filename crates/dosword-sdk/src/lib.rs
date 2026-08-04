//! DoSword 协议 SDK。
//!
//! 纯接口库（零 tauri 依赖）：协议插件实现 [`plugin::ProtocolPlugin`]
//! 后即可接入宿主，授权检查 / 审计 / 会话管理由宿主自动完成。

pub mod domain;
pub mod crypto;
pub mod encoder;
pub mod feature_plugins;
pub mod plugin;
pub mod protocol;

pub use encoder::{
    aes_cbc_decrypt, aes_cbc_encrypt, aes_ecb_decrypt, aes_ecb_encrypt, aes_iv, aes_key,
    char_decode, des_ecb_decrypt, des_ecb_encrypt, des_key, md5_hex, obfuscate_decode,
    php_stream_decode, session_handler_code, Base64Encoder, CharEncoder, DesEcbEncoder,
    EncoderRegistry, NativeEncoder, PayloadEncoder, PhpStreamEncoder, STUB_LANGUAGES,
    XorBase64Encoder, XorBodyEncoder, XorSessionEncoder,
};
pub use plugin::{
    FeatureManifest, FeaturePlugin, FeaturePluginRegistry, ParamSpec, PluginKind,
    PluginManifest, PluginRegistry, ProtocolPlugin,
};
pub use protocol::{Protocol, ProtocolError, SessionState};
