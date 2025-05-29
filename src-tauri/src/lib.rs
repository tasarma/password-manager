// #![allow(unused_imports)]
// #![allow(unused_variables)]
// #![allow(dead_code)]

pub mod argon2_key_derivation;
pub mod commands;
pub mod db;
pub mod model;

use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
// use tauri::{App, Emitter, Manager as _, State};
use tauri::Manager as _;
// use tauri_plugin_log::{Target, TargetKind};
use tokio::sync::RwLock;

use commands::*;

#[cfg(test)]
#[path = "tests/db_tests.rs"]
mod db_tests;

#[cfg(test)]
#[path = "tests/argon2_tests.rs"]
mod argon2_tests;

#[cfg(test)]
#[path = "tests/model_tests.rs"]
mod model_tests;


/// Shared state accessible across Tauri commands

pub struct AppState {
    pub pool: Arc<RwLock<Option<SqlitePool>>>,
    pub encryption_key: Arc<RwLock<Option<[u8; 32]>>>,
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::new().build())
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
