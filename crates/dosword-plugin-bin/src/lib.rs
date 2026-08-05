//! 二进制 .plugin 示例：文本处理（base64 编解码 / 反转 / 大小写），纯逻辑。
//! 编译为 cdylib 后，宿主动态加载（dlopen）并注册为功能插件。

use base64::Engine;
use dosword_sdk::{export_dosword_plugin, FeatureManifest, NativePlugin, ParamSpec};

pub struct TextToolsPlugin;

impl NativePlugin for TextToolsPlugin {
    fn manifest(&self) -> FeatureManifest {
        FeatureManifest {
            id: "bin.text_tools".into(),
            name: "文本工具（二进制）".into(),
            version: "1.0.0".into(),
            description: "二进制插件示例：base64 编解码 / 反转 / 大小写转换（纯逻辑，无协议通道）。".into(),
            category: "general".into(),
            languages: vec![],
            params: vec![
                ParamSpec {
                    name: "op".into(),
                    label: "操作".into(),
                    param_type: "select".into(),
                    default: Some(serde_json::json!("b64_encode")),
                    options: Some(vec![
                        "b64_encode".into(),
                        "b64_decode".into(),
                        "reverse".into(),
                        "upper".into(),
                        "lower".into(),
                    ]),
                },
                ParamSpec {
                    name: "text".into(),
                    label: "文本".into(),
                    param_type: "string".into(),
                    default: Some(serde_json::json!("hello")),
                    options: None,
                },
            ],
        }
    }

    fn execute_native(
        &self,
        _runtime: &str,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let op = params
            .get("op")
            .and_then(|v| v.as_str())
            .unwrap_or("b64_encode");
        let text = params.get("text").and_then(|v| v.as_str()).unwrap_or("");
        let output = match op {
            "b64_encode" => base64::engine::general_purpose::STANDARD.encode(text.as_bytes()),
            "b64_decode" => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .map_err(|e| format!("base64 解码失败：{e}"))?;
                String::from_utf8_lossy(&bytes).into_owned()
            }
            "reverse" => text.chars().rev().collect(),
            "upper" => text.to_uppercase(),
            "lower" => text.to_lowercase(),
            other => return Err(format!("未知操作：{other}")),
        };
        Ok(serde_json::json!({ "ok": true, "op": op, "output": output }))
    }
}

export_dosword_plugin!(TextToolsPlugin);
