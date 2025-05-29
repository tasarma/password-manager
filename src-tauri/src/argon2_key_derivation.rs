use anyhow::{Context, Result};
use argon2::{
    self,
    Algorithm, Argon2, ParamsBuilder, Version,
};
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::{fs, path::PathBuf};
use tauri::{AppHandle, Manager};

pub struct KeyManager;

impl KeyManager {
    const MEMORY_COST: u32 = 19 * 1024; // ~19MB
    const ITERATIONS: u32 = 2; // Number of passes over memory
    const PARALLELISM: u32 = 1; // Number of parallel threads
    pub const LEN_SALT: usize = 16;
    pub const LEN_ENCRYPTION_KEY: usize = 32;
    const SALT_FILE_NAME: &'static str = "salt.bin";
}

impl KeyManager {
    pub async fn is_salt_file_exist(app: &AppHandle) -> Result<bool> {
        let salt_path = Self::get_salt_file_path(app).await?;
        Ok(salt_path.exists())
    }

    pub async fn get_salt_file_path(app: &AppHandle) -> Result<PathBuf> {
        let salt_dir = app
            .path()
            .app_data_dir()
            .context("Failed to retrieve application data directory to get salt file path")?;
        let salt_path = salt_dir.join(Self::SALT_FILE_NAME);

        Ok(salt_path)
    }

    pub async fn read_salt(app: &AppHandle) -> Result<Vec<u8>> {
        let salt_path = Self::get_salt_file_path(app).await?;
        match fs::read(&salt_path) {
            Ok(salt) => Ok(salt),
            Err(_) => {
                let salt= Self::create_salt(app).await?;
                Ok(salt)
            }
        }
    }

    async fn create_salt(app: &AppHandle) -> Result<Vec<u8>> {
        let mut salt = vec![0u8; Self::LEN_SALT];
        OsRng
            .try_fill_bytes(&mut salt)
            .context("Failed to generate salt")?;
        let salt_path = Self::get_salt_file_path(app).await?;
        fs::write(&salt_path, &salt).context("Failed to write salt to file")?;
        Ok(salt)
    }

    pub fn derive_encryption_key(
        master_password: &str,
        salt: &[u8],
    ) -> Result<[u8; Self::LEN_ENCRYPTION_KEY], anyhow::Error> {
        let params = ParamsBuilder::new()
            .m_cost(Self::MEMORY_COST)
            .t_cost(Self::ITERATIONS)
            .p_cost(Self::PARALLELISM)
            .build()
            .map_err(|e| anyhow::anyhow!("Invalid Argon2 params: {}", e))?;

        let argon = Argon2::new(Algorithm::Argon2id, Version::default(), params);

        let mut key = [0u8; Self::LEN_ENCRYPTION_KEY];
        argon
            .hash_password_into(master_password.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow::anyhow!("Failed to derive encryption key: {}", e))?;

        Ok(key)
    }

    pub async fn get_encryption_key(
        app: &AppHandle,
        master_password: &str,
    ) -> Result<[u8; Self::LEN_ENCRYPTION_KEY], anyhow::Error> {
        let salt = Self::read_salt(app).await?;
        let key: [u8; Self::LEN_ENCRYPTION_KEY] =
            Self::derive_encryption_key(master_password, &salt)?;
        Ok(key)
    }
}
