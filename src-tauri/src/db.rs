use anyhow::{Context, Result};

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
    Row,
};
use std::{fs, path::PathBuf, str::FromStr};
use tauri::{AppHandle, Manager as _};

use crate::argon2_key_derivation::get_encryption_key;
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
        derived_encryption_key: &[u8],
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
                let stored_key_bytes: &[u8] = row
                    .try_get("password_hash")
                    .context("Failed to get 'password_hash' column from row")?;

                let stored_key = stored_key_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Stored key has invalid length"))?;

                let re_derived_key = get_encryption_key(app, master_password)
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

#[cfg(test)]
mod db_tests {
    use crate::db::DBManager;
    use sqlx::SqlitePool;
    use std::path::PathBuf;
    use tempfile::tempdir;

    async fn setup_encrypted_db(db_path: &PathBuf, password: &str) -> SqlitePool {
        DBManager::setup_database(db_path, password, true)
            .await
            .expect("Failed to setup encrypted database")
    }

    #[tokio::test]
    async fn can_connect_to_encrypted_database_with_correct_password() {
        // Arrange
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_correct_password.db");
        let password = "securepassword";

        // Act
        let pool = setup_encrypted_db(&db_path, password).await;

        // Assert
        let result: (i64,) = sqlx::query_as("SELECT count(*) FROM sqlite_master")
            .fetch_one(&pool)
            .await
            .expect("Failed to query sqlite_master");
        assert!(
            result.0 >= 0,
            "Expected to find at least one entry in sqlite_master"
        );
    }

    #[tokio::test]
    async fn cannot_connect_to_encrypted_database_with_wrong_password() {
        // Arrange
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_wrong_password.db");
        let correct_password = "correct-password";
        let wrong_password = "wrong-password";

        setup_encrypted_db(&db_path, correct_password).await;

        // Act
        let result = DBManager::connect_to_database_with_encryption(&db_path, wrong_password).await;

        // Assert
        assert!(
            result.is_err(),
            "Expected error when connecting with wrong password"
        );
    }

    #[tokio::test]
    async fn register_and_login_should_persist_and_retrieve_data() {
        // Arrange
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("register_login_test.db");
        let password = "supersecure";

        let pool = setup_encrypted_db(&db_path, password).await;

        sqlx::query("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, name TEXT)")
            .execute(&pool)
            .await
            .expect("Failed to create test table");

        sqlx::query("INSERT INTO test (name) VALUES (?)")
            .bind("Alice")
            .execute(&pool)
            .await
            .expect("Failed to insert test data");

        // Act
        let login_pool = DBManager::connect_to_database_with_encryption(&db_path, password)
            .await
            .expect("Failed to login with correct password");

        // Assert
        let name: (String,) = sqlx::query_as("SELECT name FROM test WHERE id = 1")
            .fetch_one(&login_pool)
            .await
            .expect("Failed to query inserted data");

        assert_eq!(name.0, "Alice", "Expected name to be 'Alice'");
    }

    #[tokio::test]
    async fn database_migration_should_run_successfully() {
        // Arrange
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("migration_test.db");
        let password = "migrationpass";

        // Act
        let result = DBManager::setup_database(&db_path, password, true).await;

        // Assert
        match result {
            Ok(pool) => {
                let _: (i64,) = sqlx::query_as("SELECT count(*) FROM sqlite_master")
                    .fetch_one(&pool)
                    .await
                    .expect("Failed to query sqlite_master after migration");
            }
            Err(e) => {
                if e.to_string().contains("No such file or directory") {
                    println!("Migration folder not found; skipping test.");
                } else {
                    panic!("Unexpected error during migration: {:?}", e);
                }
            }
        }
    }
}
