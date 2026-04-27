//! Argon2id key derivation for the master encryption key.
//!
//! This module derives a 32-byte AES-256 encryption key from the user's
//! master password using the Argon2id algorithm (RFC 9106). A random
//! 16-byte salt is generated on first use and persisted to disk so that
//! the same password always produces the same key on the same machine.

use anyhow::Result;
use argon2::{self, Algorithm, Argon2, ParamsBuilder, Version};
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use tauri::{AppHandle, Manager};

use crate::{
    error::{AppError, AppResult},
    model::{EncryptionKey, KEY_LENGTH},
};

pub struct KeyManager;

impl KeyManager {
    const MEMORY_COST: u32 = 19 * 1024; // ~19MB
    const ITERATIONS: u32 = 2; // Number of passes over memory
    const PARALLELISM: u32 = 1; // Number of parallel threads
    pub const LEN_SALT: usize = 16;
}

const SALT_FILE_NAME: &'static str = "salt.bin";

/// Returns the absolute path to the salt file inside the app data directory.
pub fn salt_file_path(app: &AppHandle) -> AppResult<PathBuf> {
    let salt_dir = app.path().app_data_dir().map_err(|_| {
        AppError::KeyDerivation(format!(
            "Failed to retrieve application data directory to get salt file path"
        ))
    })?;
    let salt_path = salt_dir.join(SALT_FILE_NAME);

    Ok(salt_path)
}

/// Generates a fresh random salt and writes it to `path`.
///
/// The parent directory is assumed to already exist (created during DB setup).
#[tracing::instrument(name="Create and Save the salt", skip(path), fields(path = ?path))]
fn create_and_persist_salt(path: &Path) -> AppResult<Vec<u8>> {
    let mut salt = vec![0u8; KeyManager::LEN_SALT];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| AppError::KeyDerivation(format!("Failed to generate salt")))?;

    fs::write(path, &salt)
        .map_err(|_| AppError::KeyDerivation(format!("Failed to write salt to {:?}", path)))?;

    tracing::info!("New salt created and persisted.");
    Ok(salt)
}

/// Returns `true` if the salt file already exists on disk.
#[tracing::instrument(name = "Check if the salt file exists", skip(app))]
pub async fn is_salt_file_exist(app: &AppHandle) -> Result<bool> {
    let salt_path = salt_file_path(app)?;
    Ok(salt_path.exists())
}

/// Reads the salt from disk, creating it only if the file does not yet exist.
#[tracing::instrument(name = "Read the salt from  disk", skip(app))]
pub async fn read_salt(app: &AppHandle) -> AppResult<Vec<u8>> {
    let salt_path = salt_file_path(app)?;

    match fs::read(&salt_path) {
        Ok(salt) => {
            tracing::debug!("Salt read from disk ({} bytes)", salt.len());
            Ok(salt)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            tracing::info!("Salt file not found; generating a new one");
            create_and_persist_salt(&salt_path)
        }

        Err(e) => {
            Err(e).map_err(|e| AppError::KeyDerivation(format!("Failed to read salt from {:?}", e)))
        }
    }
}

/// Derives a 32-byte [`EncryptionKey`] from `master_password` and `salt`
/// using Argon2id with hardened parameters.
///
/// This function is CPU- and memory-intensive by design: the parameters
/// (~19 MiB, 2 iterations) make offline brute-force attacks expensive.
///
/// # Errors
///
/// Returns an error if the Argon2 parameters are invalid or if the
/// underlying hash operation fails.
#[tracing::instrument(name = "Derive encryption key from master_password and salt", skip_all)]
pub fn derive_encryption_key(master_password: &str, salt: &[u8]) -> AppResult<EncryptionKey> {
    let params = ParamsBuilder::new()
        .m_cost(KeyManager::MEMORY_COST)
        .t_cost(KeyManager::ITERATIONS)
        .p_cost(KeyManager::PARALLELISM)
        .build()
        .map_err(|e| AppError::KeyDerivation(format!("Invalid Argon2 parameters: {}", e)))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::default(), params);

    let mut key = [0u8; KEY_LENGTH];
    argon
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .map_err(|e| AppError::KeyDerivation(format!("Argon2id key derivation failed: {}", e)))?;

    tracing::debug!("Encryption key derived successfully");
    Ok(EncryptionKey::new(key))
}

/// Reads the persisted salt and derives the [`EncryptionKey`] for the given
/// master password in one step.
///
/// This is the primary entry point used by the authentication commands.
#[tracing::instrument(name = "Reads the salt and derives the key", skip_all)]
pub async fn get_encryption_key(
    app: &AppHandle,
    master_password: &str,
) -> AppResult<EncryptionKey> {
    let salt = read_salt(app).await?;
    let key = derive_encryption_key(master_password, &salt)?;
    Ok(key)
}

#[cfg(test)]
mod argon2_tests {
    use super::*;

    #[test]
    fn test_derive_encryption_key() {
        // Arrange
        let master_password = "my-secret-password";
        let salt = b"static-test-salt12";

        // Act
        let key1 = derive_encryption_key(master_password, salt).expect("Key derivation failed");
        let key2 = derive_encryption_key(master_password, salt).expect("Key derivation failed");

        // Assert
        assert_eq!(key1.len(), KEY_LENGTH, "Derived key must be 32 bytes");
        assert_eq!(key1, key2, "Same password and salt must produce same key");
    }
}
