-- Add migration script here
CREATE TABLE IF NOT EXISTS master_password_hash (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password_hash BLOB NOT NULL
);