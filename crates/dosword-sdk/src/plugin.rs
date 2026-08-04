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
        let mut manifests: Vec<PluginManifest> = self
            .map
            .values()
            .map(|plugin| plugin.manifest())
            .collect();
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
        ) -> Result<(Box<dyn SessionState>, crate::domain::ProbeResult), crate::protocol::ProtocolError>
        {
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

/// 功能插件注册表。
#[derive(Default)]
pub struct FeaturePluginRegistry {
    map: std::collections::HashMap<String, Box<dyn FeaturePlugin>>,
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
        self.map.insert(id, plugin);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&dyn FeaturePlugin> {
        self.map.get(id).map(|plugin| plugin.as_ref())
    }

    pub fn list(&self) -> Vec<FeatureManifest> {
        let mut items: Vec<FeatureManifest> = self
            .map
            .values()
            .map(|plugin| plugin.manifest())
            .collect();
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
        registry
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
        // 重复注册拒绝
        let mut r = FeaturePluginRegistry::new();
        assert!(r.register(Box::new(crate::feature_plugins::ProcessesPlugin)).is_ok());
        assert!(r.register(Box::new(crate::feature_plugins::ProcessesPlugin)).is_err());
    }
}
