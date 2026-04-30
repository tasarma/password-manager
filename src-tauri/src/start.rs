// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]

use crate::commands::*;
use crate::model::EncryptionKey;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use tauri::Manager as _;
use tokio::sync::RwLock;

/// Shared state accessible across Tauri commands
pub struct AppState {
    pub pool: Arc<RwLock<Option<SqlitePool>>>,
    pub encryption_key: Arc<RwLock<Option<EncryptionKey>>>,
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            register,
            login,
            logout,
            add_password,
            get_passwords,
            get_password_by_id,
            delete_password,
            update_password,
            is_db_exist,
            delete_db_directory,
        ])
        .setup(|app| {
            tauri::async_runtime::block_on(async move {
                let state = AppState {
                    pool: Arc::new(RwLock::new(None)),
                    encryption_key: Arc::new(RwLock::new(None)),
                };
                app.manage(state);
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
