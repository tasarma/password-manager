use anyhow::{Context, Result};

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
    Row,
};
use std::{fs, path::PathBuf, str::FromStr};
use tauri::{AppHandle, Manager as _};

use crate::argon2_key_derivation::KeyManager;
pub struct DBManager;

impl DBManager {
    const MAX_CONNECTIONS: u32 = 1;
    const DB_NAME: &'static str = "passwords.db";
}

impl DBManager {
    async fn verify_database_connection(pool: &SqlitePool) -> Result<()> {
        sqlx::query("SELECT count(*) FROM sqlite_master")
            .fetch_one(pool)
            .await
            .context("Failed to verify database connection")?;

        Ok(())
    }

    pub async fn delete_db_directory(app: &AppHandle) -> Result<(), anyhow::Error> {
        let db_dir = app
            .path()
            .app_data_dir()
            .context("Failed to retrieve application data directory")?;

        if db_dir.exists() {
            fs::remove_dir_all(&db_dir)
                .with_context(|| format!("Failed to delete database directory at {:?}", db_dir))?;
        }

        Ok(())
    }

    async fn create_db_file(app: &AppHandle) -> Result<PathBuf, anyhow::Error> {
        let db_dir = app
            .path()
            .app_data_dir()
            .context("Failed to retrieve application data directory to create database file")?;

        std::fs::create_dir_all(&db_dir).context("Failed to create directory for database")?;
        let db_path = db_dir.join(DBManager::DB_NAME);

        Ok(db_path)
    }

    pub async fn is_db_exist(app: &AppHandle) -> Result<bool> {
        let db_path = Self::get_db_path(app).await?;
        Ok(db_path.exists())
    }

    pub async fn get_db_path(app: &AppHandle) -> Result<PathBuf> {
        let db_dir = app
            .path()
            .app_data_dir()
            .context("Failed to retrieve application data directory")?;
        let db_path = db_dir.join(DBManager::DB_NAME);

        Ok(db_path)
    }

    async fn is_database_encrypted(db_path: &PathBuf) -> Result<bool> {
        let db_uri = db_path.to_str().context("Invalid database path")?;

        let options = SqliteConnectOptions::from_str(db_uri)
            .context("Failed to parse database path")?
            .create_if_missing(false);

        let pool_result = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await;

        match pool_result {
            Ok(pool) => {
                let query_result = Self::verify_database_connection(&pool).await;

                match query_result {
                    Ok(_) => Ok(false),
                    Err(_) => Ok(true),
                }
            }
            Err(_) => Ok(true),
        }
    }

    pub async fn connect_to_database_with_encryption(
        db_path: &PathBuf,
        master_password: &str,
    ) -> Result<SqlitePool> {
        let db_uri = db_path.to_str().context("Invalid database path")?;

        let options = SqliteConnectOptions::from_str(db_uri)
            .context("Failed to parse database path")?
            .pragma("key", format!("'{}'", master_password.replace("'", "''")))
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(DBManager::MAX_CONNECTIONS)
            .connect_with(options)
            .await
            .context("Failed to connect to database")?;

        Self::verify_database_connection(&pool)
            .await
            .context("Failed to verify password for encrypted database")?;

        Ok(pool)
    }

    async fn connect_to_database_without_encryption(db_path: &PathBuf) -> Result<SqlitePool> {
        let db_uri = db_path.to_str().context("Invalid database path")?;

        let options = SqliteConnectOptions::from_str(db_uri)
            .context("Failed to parse database path")?
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(DBManager::MAX_CONNECTIONS)
            .connect_with(options)
            .await
            .context("Failed to connect to unencrypted database")?;

        Ok(pool)
    }

    pub async fn store_master_password_hash(
        pool: &SqlitePool,
        derived_encryption_key: &[u8; KeyManager::LEN_ENCRYPTION_KEY],
    ) -> Result<()> {
        // Stores the derived encryption key from Argon2 (not the raw password hash)
        sqlx::query(
            "INSERT OR REPLACE INTO master_password_hash (id, password_hash) VALUES (1, ?)",
        )
        .bind(&derived_encryption_key[..])
        .execute(pool)
        .await
        .context("Could not insert the encryption key into database")?;

        Ok(())
    }

    async fn verify_master_password(
        app: &AppHandle,
        pool: &SqlitePool,
        master_password: &str,
    ) -> Result<bool> {
        let row = sqlx::query("SELECT password_hash FROM master_password_hash WHERE id = 1")
            .fetch_optional(pool)
            .await
            .context("Failed to query password hash")?;

        match row {
            Some(row) => {
                let stored_key_bytes: Vec<u8> = row
                    .try_get("password_hash")
                    .context("Failed to get 'password_hash' column from row")?;

                let stored_key: [u8; KeyManager::LEN_ENCRYPTION_KEY] = stored_key_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Stored key has invalid length"))?;

                let re_derived_key: [u8; KeyManager::LEN_ENCRYPTION_KEY] =
                    KeyManager::get_encryption_key(app, master_password)
                        .await
                        .context("Failed to re-derive key for verification")?;

                let is_match = re_derived_key == stored_key;

                Ok(is_match)
            }
            None => Ok(false),
        }
    }

    pub async fn setup_database(
        db_path: &PathBuf,
        master_password: &str,
        encrypt_db: bool,
    ) -> Result<SqlitePool> {
        let pool = if encrypt_db {
            Self::connect_to_database_with_encryption(db_path, master_password).await?
        } else {
            Self::connect_to_database_without_encryption(db_path).await?
        };

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("Failed to run database migrations")?;

        Ok(pool)
    }

    pub async fn register(
        app: &AppHandle,
        master_password: &str,
        encrypt_db: bool,
    ) -> Result<SqlitePool, anyhow::Error> {
        let db_path = Self::create_db_file(app).await?;
        let pool = Self::setup_database(&db_path, master_password, encrypt_db).await?;

        Ok(pool)
    }

    pub async fn login(
        app: &AppHandle,
        master_password: &str,
    ) -> Result<SqlitePool, anyhow::Error> {
        let db_path = Self::get_db_path(app).await?;
        let is_encrypted = Self::is_database_encrypted(&db_path).await?;

        let pool = if is_encrypted {
            Self::connect_to_database_with_encryption(&db_path, master_password).await?
        } else {
            let pool = Self::connect_to_database_without_encryption(&db_path).await?;

            let is_valid = Self::verify_master_password(app, &pool, master_password).await?;
            if !is_valid {
                return Err(anyhow::anyhow!("Invalid password"));
            }

            pool
        };

        Ok(pool)
    }
}
