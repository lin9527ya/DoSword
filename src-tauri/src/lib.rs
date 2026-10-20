mod auth;
pub mod commands;
mod instance_lock;
#[cfg(feature = "mcp")]
mod mcp;
mod memshell;
mod native_plugin;
pub mod playbook;
mod protocol;
mod proxy_chain;
mod pty;
mod session;
pub mod storage;
#[cfg(feature = "wasm")]
pub mod wasm_plugin;

use std::sync::Mutex;

#[cfg(feature = "wasm")]
use dosword_sdk::FeaturePlugin as _;
use protocol::ProtocolRegistry;
use session::SessionManager;
use storage::Database;
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

/// 应用全局状态。
///
/// # 锁序约定（务必遵守）
///
/// `database` 与 `sessions` 是两把**全局**锁，任何时刻都不得同时持有 ——
/// 需要「先改库再刷会话缓存」的，把库操作放进自己的作用域、出了作用域再取会话锁；
/// 需要「先读会话再写审计」的，短锁取出参数、释放后再写库。
///
/// 为什么约定「干脆不嵌套」而不是「固定一个先后顺序」：
/// - `sessions` 是全局的，任何一次嵌套都会让一次库访问（含 fsync）挡住**所有**会话的操作；
/// - `database` 的调用点极多，靠「顺序」约束很容易被后续改动破坏。
///
/// 参考实现：`commands::session_ctx` / `commands::with_session`（短锁取 `Arc` 克隆，
/// 网络调用在锁外执行）。
///
/// 历史：`connect_shell_impl`（锁内读库取授权快照）、`disconnect_shell_impl` 与
/// `run_feature_plugin`（锁内写审计）三处曾违反该约定，已修。
pub struct AppState {
    database: Mutex<Database>,
    sessions: Mutex<SessionManager>,
    protocols: ProtocolRegistry,
    feature_plugins: std::sync::Mutex<dosword_sdk::FeaturePluginRegistry>,
    ptys: pty::PtyRegistry,
    dir_cache: Mutex<DirCache>,
    /// 多跳代理链（id → 本地监听器）
    proxy_chains: Mutex<std::collections::HashMap<String, proxy_chain::LocalChain>>,
    /// W4 断点续传：上传检查点（会话 + 远端路径）
    upload_checkpoints: Mutex<std::collections::HashMap<(String, String), UploadCheckpoint>>,
    /// W4 断点续传：下载检查点（会话 + 远端路径 + 本地路径）
    download_checkpoints:
        Mutex<std::collections::HashMap<(String, String, String), DownloadCheckpoint>>,
    /// 运行期设置覆盖（CLI 的 --proxy / --timeout / --tls-verify）。
    /// 只影响本次进程，不写回数据库。
    settings_override: Mutex<Option<dosword_sdk::domain::AppSettings>>,
}

/// W4 断点续传：上传检查点。
///
/// `size` / `last_modified` 用来识别「同一个源文件」——同名但内容不同的文件
/// 不会误续传（远端被改动时也会重置）。
#[derive(Debug, Clone)]
pub struct UploadCheckpoint {
    pub size: u64,
    pub last_modified: i64,
    /// 已成功写入远端的字节数（顺序追加语义）。
    pub written: u64,
}

/// W4 断点续传：下载检查点。
#[derive(Debug, Clone)]
pub struct DownloadCheckpoint {
    /// 开始下载时记录的远端大小；重试时不一致则不续传。
    pub remote_size: u64,
    /// 已写入本地 `.dswpart` 的字节数。
    pub written: u64,
}

/// 目录列表缓存：`lru::LruCache` + TTL 5s + Arc 共享（O(1) 淘汰，免深拷贝）。
/// 键 = (session_id, path)；写操作按会话批量失效。容量 256，命中时提升热度。
pub struct DirCache {
    inner: lru::LruCache<
        (String, String),
        (
            std::time::Instant,
            std::sync::Arc<dosword_sdk::domain::DirListing>,
        ),
    >,
    ttl: std::time::Duration,
}

impl Default for DirCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DirCache {
    pub fn new() -> Self {
        Self {
            inner: lru::LruCache::new(std::num::NonZeroUsize::new(256).unwrap()),
            ttl: std::time::Duration::from_secs(5),
        }
    }

    /// 命中且未过期时返回 Arc（引用计数，LruCache::get 会提升热度）。
    pub fn get(
        &mut self,
        key: &(String, String),
        ttl: std::time::Duration,
    ) -> Option<std::sync::Arc<dosword_sdk::domain::DirListing>> {
        let (hit_at, listing) = self.inner.get(key)?;
        if hit_at.elapsed() > ttl {
            return None;
        }
        Some(std::sync::Arc::clone(listing))
    }

    /// 使用默认 TTL 的快捷 get
    pub fn get_ttl(
        &mut self,
        key: &(String, String),
    ) -> Option<std::sync::Arc<dosword_sdk::domain::DirListing>> {
        self.get(key, self.ttl)
    }

    pub fn insert(
        &mut self,
        key: (String, String),
        value: (
            std::time::Instant,
            std::sync::Arc<dosword_sdk::domain::DirListing>,
        ),
    ) {
        self.inner.put(key, value);
    }

    /// 失效某会话的全部目录缓存（写操作后调用，保证一致性）。
    pub fn invalidate_session(&mut self, session_id: &str) {
        let keys: Vec<(String, String)> = self
            .inner
            .iter()
            .filter(|(k, _)| k.0 == session_id)
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            self.inner.pop(&k);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl AppState {
    /// 只读访问数据库（CLI 用来列出 Shell；桌面端命令走内部字段）。
    pub fn database(&self) -> &Mutex<Database> {
        &self.database
    }

    /// 设置运行期覆盖的全局设置（CLI 使用；不写回数据库）。
    pub fn set_settings_override(&self, settings: dosword_sdk::domain::AppSettings) {
        if let Ok(mut guard) = self.settings_override.lock() {
            *guard = Some(settings);
        }
    }

    /// 应用运行期覆盖（无覆盖时返回原值）。
    pub(crate) fn effective_settings(
        &self,
        base: dosword_sdk::domain::AppSettings,
    ) -> dosword_sdk::domain::AppSettings {
        self.settings_override
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
            .unwrap_or(base)
    }
}

/// 加载功能插件：内置 + 插件目录中的脚本（`.plugin`）/
/// 原生（`.native.*`）/ WASM（`.wasm` + 同名 `.wasm.json` 清单）。
///
/// 加载失败只跳过，不阻塞启动（与原有行为一致）。
pub fn load_feature_plugins(plugins_dir: &std::path::Path) -> dosword_sdk::FeaturePluginRegistry {
    let mut registry = dosword_sdk::FeaturePluginRegistry::builtin();
    let Ok(entries) = std::fs::read_dir(plugins_dir) else {
        return registry;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if file_name.ends_with(".plugin") {
            if let Ok(content) = std::fs::read_to_string(entry.path())
                && let Ok(plugin) = dosword_sdk::ScriptFeaturePlugin::from_json(&content)
            {
                let id = plugin.manifest().id.clone();
                if registry.register(Box::new(plugin)).is_ok() {
                    registry.installed.insert(id);
                }
            }
        } else if file_name.contains(".native.") {
            // 二进制插件：动态加载（失败跳过）
            if let Ok(plugin) = crate::native_plugin::NativeFeaturePlugin::load(&entry.path())
                && let Ok(manifest) = plugin.abi_manifest()
            {
                let id = manifest.id.clone();
                if registry.register(Box::new(plugin)).is_ok() {
                    registry.installed.insert(id);
                }
            }
        } else if file_name.ends_with(".wasm") {
            // WASM 沙箱插件（能力声明见 wasm_plugin 模块文档）
            #[cfg(feature = "wasm")]
            if let Ok(plugin) = crate::wasm_plugin::WasmFeaturePlugin::load(&entry.path()) {
                let id = plugin.manifest().id.clone();
                if registry.register(Box::new(plugin)).is_ok() {
                    registry.installed.insert(id);
                }
            }
        }
    }
    registry
}

/// 默认数据目录（与 Tauri `app_data_dir` 一致：`<XDG_DATA_HOME>/io.dosword.desktop`），
/// 供 CLI 与桌面端共享同一个 SQLite 与插件目录。
pub fn default_data_dir() -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(|home| std::path::PathBuf::from(home).join(".local/share"))
            })
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        base.join("io.dosword.desktop")
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        home.join("Library/Application Support/io.dosword.desktop")
    }
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("APPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        base.join("io.dosword.desktop")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        std::path::PathBuf::from(".")
    }
}

/// 测试用 AppState（内存库 + 内置插件），供跨模块测试复用。
#[cfg(test)]
pub(crate) fn test_app_state() -> AppState {
    build_app_state(
        Database::open(":memory:").expect("内存数据库"),
        dosword_sdk::FeaturePluginRegistry::builtin(),
    )
}

/// Q9：统一装配 AppState（两处启动路径复用）。
pub fn build_app_state(
    database: Database,
    feature_plugins: dosword_sdk::FeaturePluginRegistry,
) -> AppState {
    AppState {
        database: Mutex::new(database),
        sessions: Mutex::new(SessionManager::new()),
        protocols: ProtocolRegistry::builtin(),
        feature_plugins: Mutex::new(feature_plugins),
        ptys: pty::PtyRegistry::new(),
        dir_cache: Mutex::new(DirCache::new()),
        proxy_chains: Mutex::new(std::collections::HashMap::new()),
        upload_checkpoints: Mutex::new(std::collections::HashMap::new()),
        download_checkpoints: Mutex::new(std::collections::HashMap::new()),
        settings_override: Mutex::new(None),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_data = app.path().app_data_dir()?;
            std::fs::create_dir_all(&app_data)?;
            // 单实例锁：两个桌面实例会各有一套会话表与重复审计。
            // 锁由操作系统在进程退出/崩溃时自动释放，不会留下脏锁。
            // 已被占用时给出可读提示并退出（不静默开第二个窗口）。
            let instance_lock = match instance_lock::InstanceLock::acquire(&app_data) {
                Ok(lock) => lock,
                Err(message) => {
                    eprintln!("[startup] {message}");
                    app.dialog()
                        .message(message)
                        .title("DoSword 已在运行")
                        .kind(tauri_plugin_dialog::MessageDialogKind::Error)
                        .blocking_show();
                    std::process::exit(0);
                }
            };
            // 交给 Tauri 管理，保证锁持有到进程退出
            app.manage(instance_lock);
            let database = Database::open(app_data.join("dosword.sqlite3"))?;
            // P5：启动时按保留期清理过期审计（设置 0 表示不清理）
            if let Ok(settings) = database.get_settings()
                && settings.audit_retention_days > 0
            {
                let _ = database.purge_audit(settings.audit_retention_days);
            }
            let plugins_dir = app_data.join("plugins");
            let registry = load_feature_plugins(&plugins_dir);
            app.manage(build_app_state(database, registry));

            // MCP 服务端：装配状态；若设置里已启用则自动拉起（失败只记录，不阻塞启动）
            #[cfg(feature = "mcp")]
            mcp::bootstrap(app.handle().clone());

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::dashboard,
            // Shell 库：分页查询 + 单取 + 精简列表（看板不再返回全量 Shell）
            commands::query_shells,
            commands::get_shell,
            commands::list_shell_summaries,
            commands::create_workspace,
            commands::update_workspace,
            commands::delete_workspace,
            commands::create_shell,
            commands::update_shell,
            commands::delete_shell,
            commands::probe_shell,
            commands::test_connection,
            commands::list_protocols,
            commands::list_plugins,
            commands::list_feature_plugins,
            commands::run_feature_plugin,
            commands::refresh_shell_status,
            commands::http_send,
            commands::test_proxy_upstream,
            commands::encode_text,
            commands::backup_shells,
            commands::batch_update_shells,
            commands::read_local_file,
            commands::export_shells,
            commands::import_shells,
            commands::install_plugin,
            commands::install_native_plugin,
            commands::uninstall_plugin,
            #[cfg(feature = "wasm")]
            commands::install_wasm_plugin,
            commands::list_encoders,
            commands::register_custom_encoder,
            commands::generate_shell,
            commands::list_audit,
            commands::write_local_file,
            commands::get_settings,
            commands::update_settings,
            commands::connect_shell,
            commands::disconnect_shell,
            commands::get_session_probe,
            commands::start_pty_session,
            commands::pty_write,
            commands::pty_read,
            commands::pty_close,
            commands::list_sessions,
            commands::heartbeat_sessions,
            commands::run_playbook,
            commands::execute_command,
            commands::list_dir,
            commands::batch_list_dir,
            commands::memshell_capabilities,
            commands::memshell_install,
            commands::memshell_check,
            commands::memshell_uninstall,
            commands::memshell_list,
            commands::memshell_exec,
            commands::orchestrate_run,
            commands::proxy_chain_start,
            commands::proxy_chain_stop,
            commands::proxy_chain_list,
            commands::read_file,
            commands::write_file,
            commands::upload_file,
            commands::download_file,
            commands::delete_path,
            commands::rename_path,
            commands::create_dir,
            commands::touch_path,
            commands::write_chunk,
            commands::read_chunk,
            commands::upload_begin,
            commands::upload_finish,
            commands::db_probe,
            commands::db_query,
            commands::list_request_log,
            commands::clear_request_log,
            commands::mcp_status,
            commands::mcp_start,
            commands::mcp_stop,
            commands::mcp_rotate_token,
            commands::mcp_recent_calls,
            commands::mcp_clear_log,
            commands::mcp_pending_approvals,
            commands::mcp_resolve_approval,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start DoSword");
}
