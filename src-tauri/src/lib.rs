mod auth;
mod commands;
mod domain;
mod protocol;
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
            app.manage(AppState {
                database: Mutex::new(database),
                sessions: Mutex::new(SessionManager::new()),
                protocols: ProtocolRegistry::builtin(),
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
            commands::list_audit,
            commands::write_local_file,
            commands::get_settings,
            commands::update_settings,
            commands::connect_shell,
            commands::disconnect_shell,
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
            commands::write_chunk,
            commands::db_probe,
            commands::db_query,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start DoSword");
}
