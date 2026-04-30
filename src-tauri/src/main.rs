// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use password_manager_lib::telemetry::{get_subscriber, init_subscriber};

fn main() {
    let subscriber = get_subscriber("password_manager".into(), "info".into(), std::io::stdout);
    init_subscriber(subscriber);

    password_manager_lib::start::run()
}
