//! 二进制 .plugin 加载器：libloading（dlopen）加载 Rust cdylib，
//! 验证 ABI 魔数/版本后包装为 FeaturePlugin。

use std::ffi::{CStr, CString};
use std::sync::Arc;

use dosword_sdk::domain::AppSettings;
use dosword_sdk::protocol::{Protocol, SessionState};
use dosword_sdk::{FeatureManifest, FeaturePlugin, NativePluginAbi, ProtocolError};

const ABI_MAGIC: u32 = 0x4453_5744;
const ABI_VERSION: u32 = 1;

/// 已加载的二进制插件（Library 存活期内 ABI 函数指针有效）。
pub struct NativeFeaturePlugin {
    _lib: Arc<libloading::Library>,
    abi: NativePluginAbi,
}

impl NativeFeaturePlugin {
    /// 从动态库文件加载并校验 ABI。
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        // SAFETY: 插件为受信任的本地 .plugin（同脚本插件信任模型）
        let lib = unsafe { libloading::Library::new(path) }
            .map_err(|error| format!("加载插件失败：{error}"))?;
        // SAFETY: 符号由导出宏固定生成
        let entry: libloading::Symbol<unsafe extern "C" fn() -> *const NativePluginAbi> = unsafe {
            lib.get(b"dosword_plugin_abi")
        }
        .map_err(|_| "插件缺少 dosword_plugin_abi 导出符号（非本工具二进制插件）".to_string())?;
        // SAFETY: 调用插件导出函数获取 ABI 指针
        let abi_ptr = unsafe { entry() };
        if abi_ptr.is_null() {
            return Err("插件 ABI 指针为空".to_string());
        }
        // SAFETY: ABI 结构由导出宏按固定布局写入（按值复制函数指针）
        let abi = unsafe { std::ptr::read(abi_ptr) };
        if abi.magic != ABI_MAGIC {
            return Err(format!("插件魔数不匹配（0x{:08x}）", abi.magic));
        }
        if abi.version != ABI_VERSION {
            return Err(format!(
                "插件 ABI 版本不兼容（{}，当前 {ABI_VERSION}）",
                abi.version
            ));
        }
        Ok(Self {
            _lib: Arc::new(lib),
            abi,
        })
    }

    /// 插件清单（公开：安装/注册用；trait 方法为 feature 版，命名避开）。
    pub fn abi_manifest(&self) -> Result<FeatureManifest, String> {
        let ptr = (self.abi.manifest_json)();
        if ptr.is_null() {
            return Err("插件清单为空".to_string());
        }
        // SAFETY: 导出宏保证返回静态 NUL 结尾字符串
        let json = unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .map_err(|_| "插件清单非 UTF-8".to_string())?;
        serde_json::from_str(json).map_err(|error| format!("插件清单解析失败：{error}"))
    }

    fn execute_json(
        &self,
        runtime: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let runtime_c = CString::new(runtime).map_err(|_| "runtime 含 NUL".to_string())?;
        let params_c = CString::new(params.to_string()).map_err(|_| "参数含 NUL".to_string())?;
        // 插件 ABI 已校验；函数指针在 Library 存活期内有效（指针本身为安全 extern fn）
        let out = (self.abi.execute_json)(runtime_c.as_ptr(), params_c.as_ptr());
        if out.is_null() {
            return Err("插件执行返回空".to_string());
        }
        // SAFETY: 插件返回堆分配 NUL 结尾字符串，按约定释放
        let result = unsafe { CStr::from_ptr(out) }
            .to_str()
            .map(|s| s.to_string())
            .unwrap_or_default();
        (self.abi.free_json)(out);
        serde_json::from_str(&result).map_err(|error| format!("插件结果非 JSON：{error}"))
    }
}

impl FeaturePlugin for NativeFeaturePlugin {
    fn manifest(&self) -> FeatureManifest {
        self.abi_manifest().unwrap_or_else(|error| FeatureManifest {
            id: "native.load_error".into(),
            name: "加载失败的二进制插件".into(),
            version: "0".into(),
            description: error,
            category: "general".into(),
            languages: vec![],
            params: vec![],
            kind: "feature".into(),
        })
    }

    fn execute(
        &self,
        _protocol: &dyn Protocol,
        _session: &dyn SessionState,
        runtime: &str,
        params: &serde_json::Value,
        _settings: &AppSettings,
    ) -> Result<serde_json::Value, ProtocolError> {
        self.execute_json(runtime, params)
            .map_err(ProtocolError::ServerError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 依赖示例插件已构建（cargo test 前执行 cargo build -p dosword-plugin-bin）。
    fn plugin_so() -> std::path::PathBuf {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        root.join("target/debug/libdosword_plugin_bin.so")
    }

    #[test]
    fn load_validates_abi_and_manifest() {
        let path = plugin_so();
        if !path.exists() {
            eprintln!("跳过：示例插件未构建（先执行 cargo build -p dosword-plugin-bin）");
            return;
        }
        let plugin = NativeFeaturePlugin::load(&path).expect("应能加载示例插件");
        let manifest = plugin.abi_manifest().unwrap();
        assert_eq!(manifest.id, "bin.text_tools");
        assert_eq!(manifest.name, "文本工具（二进制）");
    }

    #[test]
    fn execute_native_pure_logic() {
        let path = plugin_so();
        if !path.exists() {
            eprintln!("跳过：示例插件未构建");
            return;
        }
        let plugin = NativeFeaturePlugin::load(&path).unwrap();
        let out = plugin
            .execute_json(
                "php",
                &serde_json::json!({"op": "b64_encode", "text": "hello"}),
            )
            .unwrap();
        assert_eq!(out["output"], "aGVsbG8=");
        let out = plugin
            .execute_json("php", &serde_json::json!({"op": "reverse", "text": "abc"}))
            .unwrap();
        assert_eq!(out["output"], "cba");
        // 未知操作 → 错误
        assert!(
            plugin
                .execute_json("php", &serde_json::json!({"op": "nope"}))
                .is_err()
        );
    }

    #[test]
    fn reject_invalid_library() {
        let result = NativeFeaturePlugin::load(std::path::Path::new("/etc/hostname"));
        assert!(result.is_err(), "非动态库应拒绝");
    }
}
