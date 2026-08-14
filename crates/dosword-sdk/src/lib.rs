//! DoSword 协议 SDK。
//!
//! 纯接口库（零 tauri 依赖）：协议插件实现 [`plugin::ProtocolPlugin`]
//! 后即可接入宿主，授权检查 / 审计 / 会话管理由宿主自动完成。

pub mod asp_stub;
pub mod bypass;
pub mod crypto;
pub mod domain;
pub mod encoder;
pub mod feature_plugins;
pub mod jsp_stub;
pub mod node_stub;
pub mod plugin;
pub mod protocol;
pub mod python_stub;

pub use encoder::{
    Base64Encoder, CharEncoder, DesEcbEncoder, EncoderRegistry, NativeEncoder, PayloadEncoder,
    PhpStreamEncoder, STUB_LANGUAGES, XorBase64Encoder, XorBodyEncoder, XorSessionEncoder,
    aes_cbc_decrypt, aes_cbc_encrypt, aes_ecb_decrypt, aes_ecb_encrypt, aes_iv, aes_key,
    char_decode, des_ecb_decrypt, des_ecb_encrypt, des_key, md5_hex, obfuscate_decode,
    php_stream_decode, session_handler_code,
};
pub use plugin::{
    FeatureManifest, FeaturePlugin, FeaturePluginRegistry, NativePlugin, NativePluginAbi,
    ParamSpec, PluginExecution, PluginKind, PluginManifest, PluginRegistry, ProtocolPlugin,
    ScriptFeaturePlugin, ScriptPluginDef,
};
pub use protocol::{Protocol, ProtocolError, SessionState};

pub use bypass::{
    BypassComPlugin, BypassDlPlugin, BypassEvalPlugin, BypassFfiPlugin, BypassLdPreloadPlugin,
    BypassPcntlPlugin, BypassReversePcntlPlugin, BypassScanPlugin, BypassSyscallPlugin,
};
