//! 插件体系：清单、协议插件 trait 与注册表。
//!
//! 宿主在启动时遍历内置插件与第三方插件（workspace crate）注册；
//! 动态加载（dlopen）作为 v2 演进，注册表接口已预留，插件代码无需改动。

use std::collections::HashMap;

use crate::protocol::Protocol;

/// 插件类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub enum PluginKind {
    /// 协议插件：实现 `Protocol`，注册后可创建/连接 Shell。
    Protocol,
    /// 功能插件（预留）：未来提供 UI 面板等能力扩展。
    Feature,
}

/// 插件清单（元数据，前端「插件」面板展示）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub kind: PluginKind,
    pub description: String,
    /// 声明的能力列表：["files"] ["terminal"] ["database"] 等。
    /// 空列表视为全支持（兼容旧协议）。
    pub capabilities: Vec<String>,
}

impl PluginManifest {
    /// 是否声明支持某能力（空列表 = 全部支持）。
    pub fn supports(&self, capability: &str) -> bool {
        self.capabilities.is_empty() || self.capabilities.iter().any(|item| item == capability)
    }
}

/// 协议插件：清单 + 协议实现。
pub trait ProtocolPlugin: Protocol {
    fn manifest(&self) -> PluginManifest;
}

/// 插件注册表。`id` 冲突时拒绝注册（防止覆盖内置协议）。
#[derive(Default)]
pub struct PluginRegistry {
    map: HashMap<String, Box<dyn ProtocolPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册插件。id 重复（含内置协议）返回错误。
    pub fn register(&mut self, plugin: Box<dyn ProtocolPlugin>) -> Result<(), String> {
        let id = plugin.id().to_string();
        if self.map.contains_key(&id) {
            return Err(format!("插件 id 冲突，已存在：{id}"));
        }
        self.map.insert(id, plugin);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&dyn ProtocolPlugin> {
        self.map.get(id).map(|boxed| boxed.as_ref())
    }

    /// 全部插件元信息（按 id 稳定排序）。
    pub fn list(&self) -> Vec<PluginManifest> {
        let mut manifests: Vec<PluginManifest> =
            self.map.values().map(|plugin| plugin.manifest()).collect();
        manifests.sort_by(|a, b| a.id.cmp(&b.id));
        manifests
    }

    /// 协议元信息列表（前端创建 Shell 下拉用，含 requires_network）。
    pub fn protocol_metas(&self) -> Vec<crate::domain::ProtocolMeta> {
        let mut metas: Vec<crate::domain::ProtocolMeta> = self
            .map
            .values()
            .map(|plugin| {
                let manifest = plugin.manifest();
                crate::domain::ProtocolMeta {
                    id: plugin.id().to_string(),
                    display_name: manifest.name,
                    requires_network: plugin.requires_network(),
                    version: manifest.version,
                    description: manifest.description,
                    capabilities: manifest.capabilities,
                }
            })
            .collect();
        metas.sort_by(|a, b| a.id.cmp(&b.id));
        metas
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SessionState;

    struct DummyPluginImpl;
    impl Protocol for DummyPluginImpl {
        fn id(&self) -> &'static str {
            "test.dummy.v1"
        }
        fn display_name(&self) -> &'static str {
            "Dummy"
        }
        fn requires_network(&self) -> bool {
            false
        }
        fn probe(
            &self,
            _profile: &crate::domain::ShellProfile,
            _settings: &crate::domain::AppSettings,
        ) -> Result<crate::domain::ProbeResult, crate::protocol::ProtocolError> {
            unreachable!()
        }
        fn connect(
            &self,
            _profile: &crate::domain::ShellProfile,
            _settings: &crate::domain::AppSettings,
        ) -> Result<
            (Box<dyn SessionState>, crate::domain::ProbeResult),
            crate::protocol::ProtocolError,
        > {
            unreachable!()
        }
        fn execute_command(
            &self,
            _session: &dyn SessionState,
            _command: &str,
            _settings: &crate::domain::AppSettings,
        ) -> Result<crate::domain::CommandOutput, crate::protocol::ProtocolError> {
            unreachable!()
        }
        fn list_dir(
            &self,
            _session: &dyn SessionState,
            _path: &str,
            _settings: &crate::domain::AppSettings,
        ) -> Result<crate::domain::DirListing, crate::protocol::ProtocolError> {
            unreachable!()
        }
        fn read_file(
            &self,
            _session: &dyn SessionState,
            _path: &str,
            _settings: &crate::domain::AppSettings,
        ) -> Result<Vec<u8>, crate::protocol::ProtocolError> {
            unreachable!()
        }
        fn write_file(
            &self,
            _session: &dyn SessionState,
            _path: &str,
            _content: &[u8],
            _settings: &crate::domain::AppSettings,
        ) -> Result<(), crate::protocol::ProtocolError> {
            unreachable!()
        }
        fn delete_path(
            &self,
            _session: &dyn SessionState,
            _path: &str,
            _settings: &crate::domain::AppSettings,
        ) -> Result<(), crate::protocol::ProtocolError> {
            unreachable!()
        }
        fn rename_path(
            &self,
            _session: &dyn SessionState,
            _from: &str,
            _to: &str,
            _settings: &crate::domain::AppSettings,
        ) -> Result<(), crate::protocol::ProtocolError> {
            unreachable!()
        }
    }

    impl ProtocolPlugin for DummyPluginImpl {
        fn manifest(&self) -> PluginManifest {
            PluginManifest {
                id: "test.dummy.v1".into(),
                name: "Dummy 插件".into(),
                version: "0.1.0".into(),
                kind: PluginKind::Protocol,
                description: "测试".into(),
                capabilities: vec!["terminal".into()],
            }
        }
    }

    #[test]
    fn register_and_list() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(DummyPluginImpl)).unwrap();
        let manifests = registry.list();
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].id, "test.dummy.v1");
        assert_eq!(manifests[0].kind, PluginKind::Protocol);
    }

    #[test]
    fn duplicate_id_rejected() {
        let mut registry = PluginRegistry::new();
        registry.register(Box::new(DummyPluginImpl)).unwrap();
        let result = registry.register(Box::new(DummyPluginImpl));
        assert!(result.is_err(), "重复 id 应被拒绝");
    }

    #[test]
    fn capabilities_semantics() {
        let manifest = PluginManifest {
            id: "x".into(),
            name: "x".into(),
            version: "1".into(),
            kind: PluginKind::Protocol,
            description: "".into(),
            capabilities: vec!["terminal".into()],
        };
        assert!(manifest.supports("terminal"));
        assert!(!manifest.supports("files"));
        // 空列表 = 全支持
        let all = PluginManifest {
            capabilities: vec![],
            ..manifest.clone()
        };
        assert!(all.supports("database"));
    }
}

// ---------------------------------------------------------------------------
// 功能插件（Feature）：跨语言能力扩展（ZIP / 进程 / 端口扫描 / bypass 等）。
// 通用插件（languages 为空）与语言专用插件（languages 限定 php/jsp/aspnet）。
// 插件在 execute 时拿到协议句柄，可自由组合协议能力（命令 / run_code / 文件）。
// ---------------------------------------------------------------------------

/// 插件参数定义（前端渲染表单用）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct ParamSpec {
    pub name: String,
    pub label: String,
    /// "string" | "int" | "bool" | "select"
    #[serde(rename = "type")]
    pub param_type: String,
    #[ts(type = "string | number | boolean | null")]
    pub default: Option<serde_json::Value>,
    /// select 选项。
    pub options: Option<Vec<String>>,
}

/// 功能插件清单。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, ts_rs::TS)]
#[serde(rename_all = "camelCase")]
pub struct FeatureManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    /// 类别：general（通用）/ php / jsp / aspnet（语言专用）。
    pub category: String,
    /// 支持的语言（协议 runtime）：["php","jsp","aspnet"]；空 = 通用。
    pub languages: Vec<String>,
    /// 参数 schema。
    pub params: Vec<ParamSpec>,
    /// 插件类型：feature（功能）/ crypto（加密器）/ loader（加载器），默认 feature。
    #[serde(default = "default_plugin_kind")]
    pub kind: String,
}

fn default_plugin_kind() -> String {
    "feature".to_string()
}

/// 功能插件：多语言能力扩展。
pub trait FeaturePlugin: Send + Sync {
    fn manifest(&self) -> FeatureManifest;

    /// 执行插件。`protocol` 为会话所属协议实例（可调用 execute_command /
    /// run_code / 文件等能力），`session` 为已连接会话状态，
    /// `runtime` 为目标运行时语言（php / jsp / aspnet）。
    fn execute(
        &self,
        protocol: &dyn crate::protocol::Protocol,
        session: &dyn crate::protocol::SessionState,
        runtime: &str,
        params: &serde_json::Value,
        settings: &crate::domain::AppSettings,
    ) -> Result<serde_json::Value, crate::protocol::ProtocolError>;
}

/// 插件执行方式：命令型（按语言执行系统命令）或代码型（按语言运行载荷）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum PluginExecution {
    /// 执行系统命令（通用，无需载荷）：commands[language] = 命令模板。
    Command {
        commands: std::collections::HashMap<String, String>,
    },
    /// 运行目标语言代码载荷：codes[language] = 代码模板（{{param}} 占位符）。
    Code {
        codes: std::collections::HashMap<String, String>,
    },
}

/// 外部 .plugin 文件：JSON 清单 + 执行定义（脚本型功能插件）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptPluginDef {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    /// general（通用）/ php / jsp / aspnet（语言专用）。
    pub category: String,
    /// 支持的语言。
    pub languages: Vec<String>,
    pub params: Vec<ParamSpec>,
    /// 插件类型：feature / crypto / loader（可选，默认 feature）。
    #[serde(default = "default_plugin_kind")]
    pub kind: String,
    pub execution: PluginExecution,
}

/// 基于 .plugin 清单的脚本型功能插件（命令型 / 代码型）。
pub struct ScriptFeaturePlugin {
    manifest: FeatureManifest,
    execution: PluginExecution,
}

impl ScriptFeaturePlugin {
    /// 从 .plugin JSON 内容构建。
    pub fn from_json(content: &str) -> Result<Self, String> {
        let def: ScriptPluginDef =
            serde_json::from_str(content).map_err(|error| format!("插件清单解析失败：{error}"))?;
        if def.id.trim().is_empty() {
            return Err("插件 id 不能为空".to_string());
        }
        Ok(Self {
            manifest: FeatureManifest {
                id: def.id,
                name: def.name,
                version: def.version,
                description: def.description,
                category: def.category,
                languages: def.languages,
                params: def.params,
                kind: def.kind,
            },
            execution: def.execution,
        })
    }
}

impl ScriptFeaturePlugin {
    /// 插件清单（公开访问，安装/列表用）。
    pub fn manifest(&self) -> FeatureManifest {
        self.manifest.clone()
    }
}

impl FeaturePlugin for ScriptFeaturePlugin {
    fn manifest(&self) -> FeatureManifest {
        self.manifest.clone()
    }

    fn execute(
        &self,
        protocol: &dyn crate::protocol::Protocol,
        session: &dyn crate::protocol::SessionState,
        runtime: &str,
        params: &serde_json::Value,
        settings: &crate::domain::AppSettings,
    ) -> Result<serde_json::Value, crate::protocol::ProtocolError> {
        match &self.execution {
            PluginExecution::Command { commands } => {
                let template = commands
                    .get(runtime)
                    .or_else(|| commands.get("default"))
                    .ok_or_else(|| {
                        crate::protocol::ProtocolError::NotSupported(format!(
                            "插件 {} 不支持运行时 {runtime}",
                            self.manifest.id
                        ))
                    })?;
                let command = render_template(template, params);
                let output = protocol.execute_command(session, &command, settings)?;
                Ok(serde_json::json!({
                    "ok": true,
                    "command": command,
                    "stdout": output.stdout,
                }))
            }
            PluginExecution::Code { codes } => {
                let template = codes.get(runtime).ok_or_else(|| {
                    crate::protocol::ProtocolError::NotSupported(format!(
                        "插件 {} 不支持运行时 {runtime}",
                        self.manifest.id
                    ))
                })?;
                let code = render_template(template, params);
                let output = protocol.run_code(session, runtime, &code, settings)?;
                // 载荷输出优先按 JSON 解析，否则按文本返回
                match serde_json::from_str::<serde_json::Value>(&output) {
                    Ok(value) => Ok(value),
                    Err(_) => Ok(serde_json::json!({ "ok": true, "output": output })),
                }
            }
        }
    }
}

/// 模板渲染：`{{param}}` 占位符替换为参数值（字符串 / 数字 / 布尔原样嵌入）。
pub fn render_template(template: &str, params: &serde_json::Value) -> String {
    let mut out = template.to_string();
    if let Some(obj) = params.as_object() {
        for (key, value) in obj {
            let placeholder = format!("{{{{{key}}}}}");
            let rendered = match value {
                serde_json::Value::String(text) => text.clone(),
                serde_json::Value::Number(number) => number.to_string(),
                serde_json::Value::Bool(flag) => flag.to_string(),
                _ => value.to_string(),
            };
            out = out.replace(&placeholder, &rendered);
        }
    }
    out
}

/// 功能插件注册表。
#[derive(Default)]
pub struct FeaturePluginRegistry {
    map: std::collections::HashMap<String, std::sync::Arc<dyn FeaturePlugin>>,
    /// 已安装外部插件 id（供列表展示来源）。
    pub installed: std::collections::HashSet<String>,
}

impl FeaturePluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册。id 重复返回错误。
    pub fn register(&mut self, plugin: Box<dyn FeaturePlugin>) -> Result<(), String> {
        let id = plugin.manifest().id.clone();
        if self.map.contains_key(&id) {
            return Err(format!("功能插件 id 冲突：{id}"));
        }
        self.map.insert(id, std::sync::Arc::from(plugin));
        Ok(())
    }

    /// P2：返回 Arc 引用（调用方可锁外执行插件，避免注册表锁跨网络持有）。
    pub fn get(&self, id: &str) -> Option<std::sync::Arc<dyn FeaturePlugin>> {
        self.map.get(id).map(std::sync::Arc::clone)
    }

    /// 移除插件（卸载外部插件用）。
    pub fn unregister(&mut self, id: &str) {
        self.map.remove(id);
        self.installed.remove(id);
    }

    pub fn list(&self) -> Vec<FeatureManifest> {
        let mut items: Vec<FeatureManifest> =
            self.map.values().map(|plugin| plugin.manifest()).collect();
        items.sort_by(|a, b| a.id.cmp(&b.id));
        items
    }

    /// 内置功能插件（架构示例 + 常用能力）。
    pub fn builtin() -> Self {
        let mut registry = Self::new();
        let _ = registry.register(Box::new(crate::feature_plugins::ProcessesPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::PortScanPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::PhpEnvPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::ZipPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::WebShellScanPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::SuperTerminalPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::EvalCodePlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::RealCmdPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::SocksProxyPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::HttpProxyPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::BypassOpenBasedirPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassScanPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassSyscallPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassFfiPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassPcntlPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassLdPreloadPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassComPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassEvalPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassDlPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassFastcgiPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassIconvPlugin));
        let _ = registry.register(Box::new(crate::bypass::BypassReversePcntlPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::FileSearchPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::NetInfoPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::UserListPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::CryptoToolPlugin));
        let _ = registry.register(Box::new(crate::feature_plugins::CodeLoaderPlugin));
        registry
    }
}

#[cfg(test)]
mod script_plugin_tests {
    use super::*;

    const COMMAND_PLUGIN: &str = r#"{
        "id": "demo.cmd.v1",
        "name": "命令示例",
        "version": "1.0.0",
        "description": "命令型插件示例",
        "category": "general",
        "languages": ["php", "jsp"],
        "params": [
            {"name": "limit", "label": "行数", "type": "int", "default": 10}
        ],
        "execution": {
            "type": "command",
            "commands": {
                "default": "ps -eo pid,cmd | head -{{limit}}"
            }
        }
    }"#;

    const CODE_PLUGIN: &str = r#"{
        "id": "demo.code.v1",
        "name": "代码示例",
        "version": "1.0.0",
        "description": "代码型插件示例",
        "category": "php",
        "languages": ["php"],
        "params": [
            {"name": "path", "label": "路径", "type": "string", "default": "/tmp"}
        ],
        "execution": {
            "type": "code",
            "codes": {
                "php": "<?php echo json_encode(array('path' => '{{path}}', 'ok' => true));"
            }
        }
    }"#;

    #[test]
    fn script_plugin_from_json_command() {
        let plugin = ScriptFeaturePlugin::from_json(COMMAND_PLUGIN).unwrap();
        assert_eq!(plugin.manifest().id, "demo.cmd.v1");
        assert_eq!(plugin.manifest().category, "general");
    }

    #[test]
    fn script_plugin_from_json_code() {
        let plugin = ScriptFeaturePlugin::from_json(CODE_PLUGIN).unwrap();
        assert_eq!(plugin.manifest().languages, vec!["php"]);
    }

    #[test]
    fn script_plugin_invalid_json_rejected() {
        assert!(ScriptFeaturePlugin::from_json("not json").is_err());
        assert!(ScriptFeaturePlugin::from_json(r#"{"id":""}"#).is_err());
    }

    #[test]
    fn render_template_replaces_params() {
        let params = serde_json::json!({"limit": 5, "path": "/var/www", "flag": true});
        assert_eq!(
            render_template("ps | head -{{limit}} {{path}} {{flag}}", &params),
            "ps | head -5 /var/www true"
        );
    }
}

#[cfg(test)]
mod feature_tests {
    use super::*;

    #[test]
    fn feature_registry_lists_builtin() {
        let registry = FeaturePluginRegistry::builtin();
        let ids: Vec<String> = registry.list().into_iter().map(|m| m.id).collect();
        assert!(ids.contains(&"processes".to_string()), "{ids:?}");
        assert!(ids.contains(&"port_scan".to_string()), "{ids:?}");
        assert!(ids.contains(&"php_env".to_string()), "{ids:?}");
        assert!(ids.contains(&"zip".to_string()), "{ids:?}");
        assert!(ids.contains(&"webshell_scan".to_string()), "{ids:?}");
        assert!(ids.contains(&"bypass_scan".to_string()), "{ids:?}");
        assert!(ids.contains(&"bypass_syscall".to_string()), "{ids:?}");
        assert!(ids.contains(&"bypass_ffi".to_string()), "{ids:?}");
        assert!(ids.contains(&"bypass_pcntl".to_string()), "{ids:?}");
        assert!(ids.contains(&"bypass_ld_preload".to_string()), "{ids:?}");
        assert!(ids.contains(&"bypass_fastcgi".to_string()), "{ids:?}");
        assert!(ids.contains(&"bypass_iconv".to_string()), "{ids:?}");
        assert!(ids.contains(&"socks_proxy".to_string()), "{ids:?}");
        assert!(ids.contains(&"http_proxy".to_string()), "{ids:?}");
        assert!(ids.contains(&"p_eval_code".to_string()), "{ids:?}");
        // 重复注册拒绝
        let mut r = FeaturePluginRegistry::new();
        assert!(
            r.register(Box::new(crate::feature_plugins::ProcessesPlugin))
                .is_ok()
        );
        assert!(
            r.register(Box::new(crate::feature_plugins::ProcessesPlugin))
                .is_err()
        );
    }
}

// ---------------------------------------------------------------------------
// 二进制插件（Native .plugin）：Rust cdylib，运行时 dlopen 加载。
// 导出宏生成 C ABI 符号（magic/version/manifest/execute），宿主用 libloading 加载。
// v1 约定：execute 为纯逻辑（无协议句柄）；需要命令/代码通道的插件用脚本型 .plugin。
// ---------------------------------------------------------------------------

/// 二进制插件：纯逻辑执行（runtime + 参数 → JSON）。
pub trait NativePlugin: Send + Sync {
    fn manifest(&self) -> FeatureManifest;
    fn execute_native(
        &self,
        runtime: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
}

/// 二进制插件 C ABI（#[repr(C)]，跨 crate 稳定布局）。
/// 内部仅为函数指针与整数，跨线程安全。
#[repr(C)]
pub struct NativePluginAbi {
    /// 内部字段见下（unsafe impl Sync 见文件尾）。
    /// 魔数 "DSWD"。
    pub magic: u32,
    /// ABI 版本（当前 1）。
    pub version: u32,
    /// 返回清单 JSON（静态字符串，无需释放）。
    pub manifest_json: extern "C" fn() -> *const std::ffi::c_char,
    /// 执行：runtime + 参数 JSON → 结果 JSON（宿主调用 free_json 释放）。
    pub execute_json:
        extern "C" fn(*const std::ffi::c_char, *const std::ffi::c_char) -> *mut std::ffi::c_char,
    /// 释放 execute_json 返回的字符串。
    pub free_json: extern "C" fn(*mut std::ffi::c_char),
}

/// 导出二进制插件：插件类型需为 unit struct（常量构造），实现 `NativePlugin`。
/// 用法：
/// ```ignore
/// use dosword_sdk::{export_dosword_plugin, NativePlugin, FeatureManifest, ParamSpec};
/// pub struct DemoPlugin;
/// impl NativePlugin for DemoPlugin { ... }
/// export_dosword_plugin!(DemoPlugin);
/// ```
#[macro_export]
macro_rules! export_dosword_plugin {
    ($plugin:ident) => {
        static DOSWORD_PLUGIN_INSTANCE: $plugin = $plugin;

        extern "C" fn __dosword_manifest_json() -> *const std::ffi::c_char {
            static CELL: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
            let ptr = *CELL.get_or_init(|| {
                let json = serde_json::to_string(&DOSWORD_PLUGIN_INSTANCE.manifest())
                    .unwrap_or_else(|_| "{}".to_string());
                // CString 含 NUL 结尾，宿主侧 CStr::from_ptr 安全；一次性静态泄漏可接受
                let cstring = std::ffi::CString::new(json).unwrap_or_default();
                cstring.into_raw() as usize
            });
            ptr as *const std::ffi::c_char
        }

        extern "C" fn __dosword_execute_json(
            runtime: *const std::ffi::c_char,
            params_json: *const std::ffi::c_char,
        ) -> *mut std::ffi::c_char {
            use std::ffi::CStr;
            let runtime = unsafe { CStr::from_ptr(runtime) }
                .to_str()
                .unwrap_or("")
                .to_string();
            let params: serde_json::Value = if params_json.is_null() {
                serde_json::Value::Null
            } else {
                unsafe { CStr::from_ptr(params_json) }
                    .to_str()
                    .map(|s| serde_json::from_str(s).unwrap_or(serde_json::Value::Null))
                    .unwrap_or(serde_json::Value::Null)
            };
            let result = DOSWORD_PLUGIN_INSTANCE.execute_native(&runtime, &params);
            let json = match result {
                Ok(value) => serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string()),
                Err(error) => serde_json::json!({ "ok": false, "error": error }).to_string(),
            };
            let cstring = std::ffi::CString::new(json).unwrap_or_default();
            cstring.into_raw()
        }

        extern "C" fn __dosword_free_json(ptr: *mut std::ffi::c_char) {
            if ptr.is_null() {
                return;
            }
            // S15：分配为 CString（into_raw），按 from_raw 还原（std 契约保证尺寸一致）
            unsafe {
                drop(std::ffi::CString::from_raw(ptr));
            }
        }

        /// ABI 入口符号。
        #[unsafe(no_mangle)]
        pub extern "C" fn dosword_plugin_abi() -> *const dosword_sdk::NativePluginAbi {
            static ABI: dosword_sdk::NativePluginAbi = dosword_sdk::NativePluginAbi {
                magic: 0x4453_5744,
                version: 1,
                manifest_json: __dosword_manifest_json,
                execute_json: __dosword_execute_json,
                free_json: __dosword_free_json,
            };
            &ABI
        }
    };
}

// NativePluginAbi 仅含函数指针与整数（可跨线程调用），显式声明 Send + Sync。
unsafe impl Send for NativePluginAbi {}
unsafe impl Sync for NativePluginAbi {}
