use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct PasswordEntry {
    pub id: String,
    pub title: String,
    #[sqlx(default)]
    #[serde(default)]
    pub username: Option<String>,
    pub password: String,
    #[sqlx(default)]
    #[serde(default)]
    pub url: Option<String>,
    #[sqlx(default)]
    #[serde(default)]
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    #[sqlx(default)]
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
    pub deleted: bool,
    #[sqlx(default)]
    #[serde(skip)]
    pub nonce: Option<String>,
}
impl PasswordEntry {
    pub const LEN_NONCE: usize = 12;
}

impl PasswordEntry {
    pub fn encrypt_password(password: &str, key: &[u8]) -> Result<(String, Option<String>)> {
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;

        let mut nonce_bytes = [0u8; Self::LEN_NONCE];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to generate nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, password.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt password: {}", e))?;

        Ok((
            general_purpose::STANDARD.encode(ciphertext),
            Some(general_purpose::STANDARD.encode(nonce_bytes)),
        ))
    }

    pub fn decrypt_password(ciphertext: &str, nonce: &str, key: &[u8]) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;

        let nonce_bytes = general_purpose::STANDARD.decode(nonce)?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = general_purpose::STANDARD.decode(ciphertext)?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to decrypt password: {}", e))?;

        Ok(String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("Failed to convert to string: {}", e))?)
    }
}
