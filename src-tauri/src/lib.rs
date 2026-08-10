mod auth;
mod commands;
mod protocol;
mod pty;
mod session;
mod native_plugin;
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
            let plugins_dir = app_data.join("plugins");
            if plugins_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&plugins_dir) {
                    let mut registry = dosword_sdk::FeaturePluginRegistry::builtin();
                    for entry in entries.flatten() {
                        let file_name = entry.file_name().to_string_lossy().into_owned();
                        if file_name.ends_with(".plugin") {
                            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                                if let Ok(plugin) = dosword_sdk::ScriptFeaturePlugin::from_json(&content) {
                                    let id = plugin.manifest().id.clone();
                                    if registry.register(Box::new(plugin)).is_ok() {
                                        registry.installed.insert(id);
                                    }
                                }
                            }
                        } else if file_name.contains(".native.") {
                            // 二进制插件：动态加载（失败跳过，不阻塞启动）
                            if let Ok(plugin) = crate::native_plugin::NativeFeaturePlugin::load(&entry.path()) {
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
                    });
                    return Ok(());
                }
            }
            app.manage(AppState {
                database: Mutex::new(database),
                sessions: Mutex::new(SessionManager::new()),
                protocols: ProtocolRegistry::builtin(),
                feature_plugins: std::sync::Mutex::new(dosword_sdk::FeaturePluginRegistry::builtin()),
                ptys: pty::PtyRegistry::new(),
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
