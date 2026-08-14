mod auth;
mod commands;
mod native_plugin;
mod protocol;
mod pty;
mod session;
mod storage;

use std::sync::Mutex;

use protocol::ProtocolRegistry;
use session::SessionManager;
use storage::Database;
use tauri::Manager;

pub struct AppState {
    database: Mutex<Database>,
    sessions: Mutex<SessionManager>,
    protocols: ProtocolRegistry,
    feature_plugins: std::sync::Mutex<dosword_sdk::FeaturePluginRegistry>,
    ptys: pty::PtyRegistry,
    dir_cache: Mutex<DirCache>,
}

/// 目录列表缓存（LRU + TTL 5s）：容量 256，满则淘汰最久未使用条目（P7）。
/// 键 = (session_id, path)；写操作按会话失效。
pub struct DirCache {
    map: std::collections::HashMap<
        (String, String),
        (std::time::Instant, dosword_sdk::domain::DirListing),
    >,
    order: std::collections::VecDeque<(String, String)>,
    cap: usize,
}

impl DirCache {
    pub fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
            cap: 256,
        }
    }

    /// 命中时把键移到队尾（LRU 语义）。
    pub fn get(
        &mut self,
        key: &(String, String),
    ) -> Option<&(std::time::Instant, dosword_sdk::domain::DirListing)> {
        if let Some(position) = self.order.iter().position(|item| item == key) {
            let entry = self.order.remove(position)?;
            self.order.push_back(entry);
        }
        self.map.get(key)
    }

    pub fn insert(
        &mut self,
        key: (String, String),
        value: (std::time::Instant, dosword_sdk::domain::DirListing),
    ) {
        if let Some(position) = self.order.iter().position(|item| *item == key) {
            self.order.remove(position);
        }
        while self.map.len() >= self.cap {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.map.remove(&oldest);
                }
                None => break,
            }
        }
        self.order.push_back(key.clone());
        self.map.insert(key, value);
    }

    /// 失效某会话的全部目录缓存（写操作后调用，保证一致性）。
    pub fn invalidate_session(&mut self, session_id: &str) {
        self.order.retain(|key| key.0 != session_id);
        self.map.retain(|key, _| key.0 != session_id);
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
            let database = Database::open(app_data.join("dosword.sqlite3"))?;
            // P5：启动时按保留期清理过期审计（设置 0 表示不清理）
            if let Ok(settings) = database.get_settings() {
                if settings.audit_retention_days > 0 {
                    let _ = database.purge_audit(settings.audit_retention_days);
                }
            }
            let plugins_dir = app_data.join("plugins");
            if plugins_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&plugins_dir) {
                    let mut registry = dosword_sdk::FeaturePluginRegistry::builtin();
                    for entry in entries.flatten() {
                        let file_name = entry.file_name().to_string_lossy().into_owned();
                        if file_name.ends_with(".plugin") {
                            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                                if let Ok(plugin) =
                                    dosword_sdk::ScriptFeaturePlugin::from_json(&content)
                                {
                                    let id = plugin.manifest().id.clone();
                                    if registry.register(Box::new(plugin)).is_ok() {
                                        registry.installed.insert(id);
                                    }
                                }
                            }
                        } else if file_name.contains(".native.") {
                            // 二进制插件：动态加载（失败跳过，不阻塞启动）
                            if let Ok(plugin) =
                                crate::native_plugin::NativeFeaturePlugin::load(&entry.path())
                            {
                                if let Ok(manifest) = plugin.abi_manifest() {
                                    let id = manifest.id.clone();
                                    if registry.register(Box::new(plugin)).is_ok() {
                                        registry.installed.insert(id);
                                    }
                                }
                            }
                        }
                    }
                    app.manage(AppState {
                        database: Mutex::new(database),
                        sessions: Mutex::new(SessionManager::new()),
                        protocols: ProtocolRegistry::builtin(),
                        feature_plugins: std::sync::Mutex::new(registry),
                        ptys: pty::PtyRegistry::new(),
                        dir_cache: Mutex::new(DirCache::new()),
                    });
                    return Ok(());
                }
            }
            app.manage(AppState {
                database: Mutex::new(database),
                sessions: Mutex::new(SessionManager::new()),
                protocols: ProtocolRegistry::builtin(),
                feature_plugins: std::sync::Mutex::new(
                    dosword_sdk::FeaturePluginRegistry::builtin(),
                ),
                ptys: pty::PtyRegistry::new(),
                dir_cache: Mutex::new(DirCache::new()),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::dashboard,
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
            commands::encode_text,
            commands::backup_shells,
            commands::batch_update_shells,
            commands::read_local_file,
            commands::export_shells,
            commands::import_shells,
            commands::install_plugin,
            commands::install_native_plugin,
            commands::uninstall_plugin,
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
            commands::execute_command,
            commands::list_dir,
            commands::batch_list_dir,
            commands::read_file,
            commands::write_file,
            commands::upload_file,
            commands::download_file,
            commands::delete_path,
            commands::rename_path,
            commands::create_dir,
            commands::touch_path,
            commands::write_chunk,
            commands::db_probe,
            commands::db_query,
            commands::list_request_log,
            commands::clear_request_log,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start DoSword");
}
