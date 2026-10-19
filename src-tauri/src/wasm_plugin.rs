//! W6 WASM 沙箱插件：`wasmtime` 运行时 + **能力声明**（未声明即拒绝）。
//!
//! 与 `native_plugin.rs`（dlopen，进程内无隔离）不同，WASM 插件只能调用宿主
//! 显式链接的导入函数：
//!
//! | 能力（manifest `capabilities`） | 链接的宿主函数 |
//! |---|---|
//! | （总是可用） | `dsw_log(ptr,len)` |
//! | `fs.read` | `dsw_fs_read(path_ptr,path_len,out_ptr,out_cap) -> i32` |
//! | `http` | `dsw_http_get(url_ptr,url_len,out_ptr,out_cap) -> i32` |
//! | `exec` | `dsw_exec(cmd_ptr,cmd_len,out_ptr,out_cap) -> i32` |
//!
//! 未声明的能力**不会链接**，插件在实例化阶段即失败（link-time denial），
//! 而不是运行到一半才被拦。宿主按次新建 `Store`，并设置燃料（防死循环）与
//! 内存上限（64 MiB）；所有宿主调用都有 1 MiB 结果上限。
//!
//! 插件 ABI（导出）：`memory`、`dsw_alloc(len) -> ptr`、
//! `dsw_execute(req_ptr, req_len) -> i64`（高 32 位结果指针、低 32 位结果长度）。
//! 请求 JSON 为 `{"runtime":"php","params":{...}}`，返回值必须是 JSON 文本。
//!
//! 插件文件：`<name>.wasm` + 同名清单 `<name>.wasm.json`：
//! ```json
//! { "id": "wasm_echo", "name": "WASM Echo", "version": "0.1.0",
//!   "description": "...", "capabilities": ["fs.read"] }
//! ```

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;
use wasmtime::{
    Caller, Config, Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use dosword_sdk::domain::AppSettings;
use dosword_sdk::protocol::{Protocol, ProtocolError, SessionState};
use dosword_sdk::{FeatureManifest, FeaturePlugin, ParamSpec};

/// 单次执行燃料上限（约几千万条指令，足够纯逻辑插件）。
const FUEL_LIMIT: u64 = 50_000_000;
/// 插件线性内存上限。
const MEMORY_LIMIT: usize = 64 * 1024 * 1024;
/// 宿主调用（读文件 / HTTP / 命令）的结果上限。
const HOST_RESULT_LIMIT: usize = 1024 * 1024;
/// 宿主调用的超时（HTTP / 命令）。
const HOST_TIMEOUT: Duration = Duration::from_secs(10);

/// 插件清单（与 `.wasm` 同名 + `.json`）。
#[derive(Debug, Deserialize)]
struct WasmManifest {
    id: String,
    name: String,
    version: String,
    description: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    languages: Vec<String>,
    #[serde(default)]
    params: Vec<ParamSpec>,
    #[serde(default)]
    capabilities: Vec<String>,
}

/// 宿主状态：内存上限 + 插件目录（日志只保留在内存，便于排障）。
struct HostState {
    limits: StoreLimits,
    /// 插件的允许工作目录（`fs.read` 的根）。
    root: PathBuf,
    logs: Vec<String>,
}

/// 已加载的 WASM 插件。
pub struct WasmFeaturePlugin {
    engine: Engine,
    module: Module,
    manifest: FeatureManifest,
    capabilities: Vec<String>,
    root: PathBuf,
}

impl WasmFeaturePlugin {
    /// 从 `<name>.wasm`（同名 `.wasm.json` 清单）加载并校验。
    pub fn load(path: &Path) -> Result<Self, String> {
        let manifest_path = PathBuf::from(format!("{}.json", path.display()));
        let content = std::fs::read_to_string(&manifest_path)
            .map_err(|error| format!("缺少插件清单 {}：{error}", manifest_path.display()))?;
        let parsed: WasmManifest = serde_json::from_str(&content)
            .map_err(|error| format!("插件清单不是合法 JSON：{error}"))?;
        dosword_sdk::plugin::validate_plugin_id(&parsed.id)?;
        // 能力白名单：未知能力直接拒绝（fail closed）
        for capability in &parsed.capabilities {
            if !matches!(capability.as_str(), "fs.read" | "http" | "exec") {
                return Err(format!("未知能力声明：{capability}"));
            }
        }
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine =
            Engine::new(&config).map_err(|error| format!("初始化 wasmtime 失败：{error}"))?;
        let module = Module::from_file(&engine, path)
            .map_err(|error| format!("加载 WASM 模块失败：{error}"))?;
        let root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Ok(Self {
            engine,
            module,
            manifest: FeatureManifest {
                id: parsed.id,
                name: parsed.name,
                version: parsed.version,
                description: parsed.description,
                category: parsed.category.unwrap_or_else(|| "wasm".to_string()),
                languages: parsed.languages,
                params: parsed.params,
                kind: "feature".to_string(),
            },
            capabilities: parsed.capabilities,
            root,
        })
    }

    /// 执行一次插件调用（每次新建 Store：状态隔离 + 燃料/内存重新计算）。
    fn invoke(&self, runtime: &str, params: &Value) -> Result<Value, ProtocolError> {
        let request = serde_json::json!({ "runtime": runtime, "params": params }).to_string();
        let mut store = Store::new(
            &self.engine,
            HostState {
                limits: StoreLimitsBuilder::new().memory_size(MEMORY_LIMIT).build(),
                root: self.root.clone(),
                logs: Vec::new(),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(FUEL_LIMIT)
            .map_err(|error| ProtocolError::ServerError(format!("设置燃料失败：{error}")))?;

        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        // 日志始终可用（无副作用）
        linker
            .func_wrap(
                "dsw",
                "dsw_log",
                |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
                    if let Ok(text) = read_guest(&mut caller, ptr, len) {
                        caller
                            .data_mut()
                            .logs
                            .push(String::from_utf8_lossy(&text).chars().take(512).collect());
                    }
                },
            )
            .map_err(|error| ProtocolError::ServerError(format!("链接 dsw_log 失败：{error}")))?;
        // 能力门禁：只有声明过的能力才链接对应宿主函数
        if self.capabilities.iter().any(|c| c == "fs.read") {
            linker
                .func_wrap(
                    "dsw",
                    "dsw_fs_read",
                    |mut caller: Caller<'_, HostState>,
                     path_ptr: i32,
                     path_len: i32,
                     out_ptr: i32,
                     out_cap: i32|
                     -> i32 {
                        let path = match read_guest(&mut caller, path_ptr, path_len) {
                            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                            Err(_) => return -1,
                        };
                        let root = caller.data().root.clone();
                        let resolved = match resolve_within(&root, &path) {
                            Some(path) => path,
                            None => return -2,
                        };
                        let data = match std::fs::read(&resolved) {
                            Ok(data) => data,
                            Err(_) => return -2,
                        };
                        write_guest(&mut caller, out_ptr, out_cap, &data)
                    },
                )
                .map_err(|error| {
                    ProtocolError::ServerError(format!("链接 dsw_fs_read 失败：{error}"))
                })?;
        }
        if self.capabilities.iter().any(|c| c == "http") {
            linker
                .func_wrap(
                    "dsw",
                    "dsw_http_get",
                    |mut caller: Caller<'_, HostState>,
                     url_ptr: i32,
                     url_len: i32,
                     out_ptr: i32,
                     out_cap: i32|
                     -> i32 {
                        let url = match read_guest(&mut caller, url_ptr, url_len) {
                            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                            Err(_) => return -1,
                        };
                        let client = match reqwest::blocking::Client::builder()
                            .timeout(HOST_TIMEOUT)
                            .redirect(reqwest::redirect::Policy::limited(3))
                            .build()
                        {
                            Ok(client) => client,
                            Err(_) => return -2,
                        };
                        let response = match client.get(&url).send() {
                            Ok(response) => response,
                            Err(_) => return -2,
                        };
                        let mut body = Vec::new();
                        use std::io::Read;
                        let _ = response
                            .take(HOST_RESULT_LIMIT as u64)
                            .read_to_end(&mut body);
                        write_guest(&mut caller, out_ptr, out_cap, &body)
                    },
                )
                .map_err(|error| {
                    ProtocolError::ServerError(format!("链接 dsw_http_get 失败：{error}"))
                })?;
        }
        if self.capabilities.iter().any(|c| c == "exec") {
            linker
                .func_wrap(
                    "dsw",
                    "dsw_exec",
                    |mut caller: Caller<'_, HostState>,
                     cmd_ptr: i32,
                     cmd_len: i32,
                     out_ptr: i32,
                     out_cap: i32|
                     -> i32 {
                        let command = match read_guest(&mut caller, cmd_ptr, cmd_len) {
                            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                            Err(_) => return -1,
                        };
                        let output = run_command_with_timeout(&command);
                        match output {
                            Some(bytes) => write_guest(&mut caller, out_ptr, out_cap, &bytes),
                            None => -2,
                        }
                    },
                )
                .map_err(|error| {
                    ProtocolError::ServerError(format!("链接 dsw_exec 失败：{error}"))
                })?;
        }

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|error| {
                ProtocolError::NotSupported(format!(
                    "WASM 插件实例化失败（可能是导入了未声明的能力）：{error}"
                ))
            })?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| ProtocolError::ParseError("WASM 插件缺少 memory 导出".into()))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "dsw_alloc")
            .map_err(|_| ProtocolError::ParseError("WASM 插件缺少 dsw_alloc 导出".into()))?;
        let execute = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "dsw_execute")
            .map_err(|_| ProtocolError::ParseError("WASM 插件缺少 dsw_execute 导出".into()))?;

        let ptr = alloc
            .call(&mut store, request.len() as i32)
            .map_err(|error| ProtocolError::ServerError(format!("dsw_alloc 失败：{error}")))?;
        memory
            .write(&mut store, ptr as usize, request.as_bytes())
            .map_err(|error| ProtocolError::ServerError(format!("写插件内存失败：{error}")))?;
        let packed = execute
            .call(&mut store, (ptr, request.len() as i32))
            .map_err(|error| ProtocolError::ServerError(format!("插件执行失败：{error}")))?;
        let out_ptr = (packed >> 32) as u32 as usize;
        let out_len = (packed & 0xFFFF_FFFF) as u32 as usize;
        if out_len == 0 {
            return Err(ProtocolError::ParseError("插件返回空结果".into()));
        }
        if out_len > HOST_RESULT_LIMIT {
            return Err(ProtocolError::ParseError(format!(
                "插件返回结果过大（{out_len} 字节，上限 {HOST_RESULT_LIMIT}）"
            )));
        }
        if out_ptr + out_len > memory.data_size(&store) {
            return Err(ProtocolError::ParseError("插件返回指针越界".into()));
        }
        let mut buffer = vec![0u8; out_len];
        memory
            .read(&store, out_ptr, &mut buffer)
            .map_err(|error| ProtocolError::ParseError(format!("读插件内存失败：{error}")))?;
        serde_json::from_slice(&buffer)
            .map_err(|error| ProtocolError::ParseError(format!("插件返回值不是合法 JSON：{error}")))
    }
}

impl FeaturePlugin for WasmFeaturePlugin {
    fn manifest(&self) -> FeatureManifest {
        self.manifest.clone()
    }

    fn execute(
        &self,
        _protocol: &dyn Protocol,
        _session: &dyn SessionState,
        runtime: &str,
        params: &Value,
        _settings: &AppSettings,
    ) -> Result<Value, ProtocolError> {
        self.invoke(runtime, params)
    }
}

/// 读 guest 内存（带上限校验）。
fn read_guest(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Result<Vec<u8>, String> {
    if ptr < 0 || len < 0 || len as usize > HOST_RESULT_LIMIT {
        return Err("参数越界".to_string());
    }
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or_else(|| "插件缺少 memory".to_string())?;
    let start = ptr as usize;
    let end = start + len as usize;
    if end > memory.data_size(&*caller) {
        return Err("读取越界".to_string());
    }
    let mut buffer = vec![0u8; len as usize];
    memory
        .read(&*caller, start, &mut buffer)
        .map_err(|error| error.to_string())?;
    Ok(buffer)
}

/// 写 guest 内存：返回写入字节数；超出 `out_cap` 返回 `-(所需长度)`。
fn write_guest(caller: &mut Caller<'_, HostState>, out_ptr: i32, out_cap: i32, data: &[u8]) -> i32 {
    if out_ptr < 0 || out_cap < 0 {
        return -1;
    }
    if data.len() > out_cap as usize {
        return -(data.len().min(i32::MAX as usize) as i32);
    }
    let memory: Memory = match caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
    {
        Some(memory) => memory,
        None => return -1,
    };
    let start = out_ptr as usize;
    if start + data.len() > memory.data_size(&*caller) {
        return -1;
    }
    match memory.write(&mut *caller, start, data) {
        Ok(()) => data.len() as i32,
        Err(_) => -1,
    }
}

/// `fs.read` 的根约束：路径必须落在插件目录内（防 `../` 穿越）。
fn resolve_within(root: &Path, requested: &str) -> Option<PathBuf> {
    let candidate = Path::new(requested);
    let joined = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    let canonical_root = root.canonicalize().ok()?;
    let canonical = joined.canonicalize().ok()?;
    canonical.starts_with(&canonical_root).then_some(canonical)
}

/// 执行命令并施加超时（std 没有内建超时，轮询 `try_wait`）。
fn run_command_with_timeout(command: &str) -> Option<Vec<u8>> {
    #[cfg(windows)]
    let mut child = std::process::Command::new("cmd")
        .args(["/C", command])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    #[cfg(not(windows))]
    let mut child = std::process::Command::new("sh")
        .args(["-c", command])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + HOST_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().ok()?;
                let mut bytes = output.stdout;
                bytes.extend_from_slice(&output.stderr);
                bytes.truncate(HOST_RESULT_LIMIT);
                return Some(bytes);
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 最小插件：`dsw_execute` 固定返回 `{}`（2 字节）。
    const ECHO_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "dsw_alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $len)))
    (local.get $ptr))
  (func (export "dsw_execute") (param $ptr i32) (param $len i32) (result i64)
    (local $out i32)
    (local.set $out (i32.const 2048))
    (i32.store8 (local.get $out) (i32.const 123))
    (i32.store8 (i32.add (local.get $out) (i32.const 1)) (i32.const 125))
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
      (i64.extend_i32_u (i32.const 2))))
)
"#;

    /// 导入 `dsw_exec` 的插件：未声明能力时实例化必须失败。
    const EXEC_WAT: &str = r#"
(module
  (import "dsw" "dsw_exec"
    (func $exec (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "dsw_alloc") (param $len i32) (result i32) (i32.const 1024))
  (func (export "dsw_execute") (param $ptr i32) (param $len i32) (result i64)
    (drop (call $exec (i32.const 0) (i32.const 0) (i32.const 2048) (i32.const 64)))
    (i32.store8 (i32.const 2048) (i32.const 123))
    (i32.store8 (i32.const 2049) (i32.const 125))
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 2048)) (i64.const 32))
      (i64.extend_i32_u (i32.const 2))))
)
"#;

    fn write_plugin(dir: &Path, wat: &str, capabilities: &[&str]) -> PathBuf {
        let path = dir.join("t.wasm");
        std::fs::write(&path, wat::parse_str(wat).expect("WAT 编译")).unwrap();
        std::fs::write(
            dir.join("t.wasm.json"),
            serde_json::json!({
                "id": "wasm_test",
                "name": "WASM Test",
                "version": "0.1.0",
                "description": "测试插件",
                "capabilities": capabilities,
            })
            .to_string(),
        )
        .unwrap();
        path
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("dosword-wasm-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn runs_plugin_and_returns_json() {
        let dir = temp_dir("echo");
        let path = write_plugin(&dir, ECHO_WAT, &[]);
        let plugin = WasmFeaturePlugin::load(&path).expect("加载插件");
        assert_eq!(plugin.manifest().id, "wasm_test");
        let value = plugin
            .invoke("php", &serde_json::json!({}))
            .expect("执行插件");
        assert_eq!(value, serde_json::json!({}));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn undeclared_capability_is_denied_at_link_time() {
        let dir = temp_dir("deny");
        // 未声明 exec：导入无法解析 → 实例化失败
        let path = write_plugin(&dir, EXEC_WAT, &[]);
        let plugin = WasmFeaturePlugin::load(&path).expect("加载插件");
        let error = plugin.invoke("php", &serde_json::json!({})).unwrap_err();
        assert!(
            matches!(error, ProtocolError::NotSupported(_)),
            "应因未声明能力被拒绝：{error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn declared_capability_is_linked() {
        let dir = temp_dir("allow");
        let path = write_plugin(&dir, EXEC_WAT, &["exec"]);
        let plugin = WasmFeaturePlugin::load(&path).expect("加载插件");
        // 声明后可以实例化并执行（命令为空输出，返回 `{}`）
        let value = plugin
            .invoke("php", &serde_json::json!({}))
            .expect("声明 exec 后应可执行");
        assert_eq!(value, serde_json::json!({}));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_capability_rejected() {
        let dir = temp_dir("unknown");
        let path = write_plugin(&dir, ECHO_WAT, &["root"]);
        assert!(WasmFeaturePlugin::load(&path).is_err(), "未知能力必须拒绝");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `fs.read` 只能读插件目录内的文件（防目录穿越）。
    #[test]
    fn fs_read_is_confined_to_plugin_root() {
        let dir = temp_dir("fs");
        std::fs::write(dir.join("data.txt"), b"hello").unwrap();
        assert!(resolve_within(&dir, "data.txt").is_some());
        assert!(resolve_within(&dir, "../escape.txt").is_none());
        assert!(resolve_within(&dir, "/etc/passwd").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
