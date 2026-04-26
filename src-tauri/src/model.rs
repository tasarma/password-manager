use crate::error::{AppError, AppResult};
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
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the AES-GCM nonce in bytes (96 bits, as recommended by NIST).
const NONCE_LENGTH: usize = 12;

/// Expected length of an AES-256 key in bytes.
const KEY_LENGTH: usize = 32;

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

pub struct CipherBundle {
    pub cipher_text: String,
    pub nonce_bytes: String,
}

/// ZeroizeOnDrop ensures the key is wiped from RAM when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey([u8; KEY_LENGTH]);

impl EncryptionKey {
    pub fn new() -> Self {
        Self([0u8; KEY_LENGTH])
    }
}

impl AsRef<[u8]> for EncryptionKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; KEY_LENGTH]> for EncryptionKey {
    fn from(value: [u8; KEY_LENGTH]) -> Self {
        EncryptionKey(value)
    }
}

impl PasswordEntry {
    #[tracing::instrument(name = "Encrypt a password before saving in the database", skip_all)]
    pub fn encrypt_password(
        password: &str,
        encryption_key: &EncryptionKey,
    ) -> AppResult<CipherBundle> {
        let cipher = Aes256Gcm::new_from_slice(encryption_key.as_ref())
            .map_err(|e| AppError::Encryption(format!("Invalid key length: {}", e)))?;

        let mut nonce_b64 = [0u8; NONCE_LENGTH];
        OsRng
            .try_fill_bytes(&mut nonce_b64)
            .map_err(|e| AppError::Encryption(format!("RNG failure: {}", e)))?;
        let nonce = Nonce::from_slice(&nonce_b64);

        let cipher_text_b64 = cipher
            .encrypt(nonce, password.as_bytes())
            .map_err(|e| AppError::Encryption(format!("Encryption failed: {}", e)))?;

        let cipher_text = general_purpose::STANDARD.encode(cipher_text_b64);
        let nonce_bytes = general_purpose::STANDARD.encode(nonce_b64);

        Ok(CipherBundle {
            cipher_text,
            nonce_bytes,
        })
    }

    pub fn decrypt_password(
        ciphertext: &str,
        nonce: &str,
        encryption_key: &EncryptionKey,
    ) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(encryption_key.as_ref())
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine};
    use rand::rngs::OsRng;
    use rand::TryRngCore;

    fn generate_key() -> EncryptionKey {
        let mut key = [0u8; KEY_LENGTH];
        OsRng.try_fill_bytes(&mut key).unwrap();
        EncryptionKey(key)
    }

    #[test]
    fn test_encrypt_and_decrypt_password_success() {
        // Arrange
        let key = generate_key();
        let original_password = "super_secret_password";

        // Act
        let cb = PasswordEntry::encrypt_password(original_password, &key).unwrap();

        let decoded_nonce = general_purpose::STANDARD.decode(&cb.nonce_bytes).unwrap();

        let decrypted_password =
            PasswordEntry::decrypt_password(&cb.cipher_text, &cb.nonce_bytes, &key).unwrap();

        // Assert
        assert!(cb.cipher_text.len() > 0);
        assert!(decoded_nonce.len() == NONCE_LENGTH);
        assert_eq!(original_password, decrypted_password);
    }

    #[test]
    fn test_decrypt_with_wrong_key_should_fail() {
        // Arrange
        let key1 = generate_key();
        let key2 = generate_key();
        let original_password = "password123";

        // Act
        let cb = PasswordEntry::encrypt_password(original_password, &key1).unwrap();

        let result = PasswordEntry::decrypt_password(&cb.cipher_text, &cb.nonce_bytes, &key2);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_modified_ciphertext_should_fail() {
        // Arrange
        let key = generate_key();
        let original_password = "correct-horse-battery-staple";

        // Act
        let mut cb = PasswordEntry::encrypt_password(original_password, &key).unwrap();

        // Tamper with the ciphertext (simulate corruption)
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&cb.cipher_text)
            .unwrap();
        bytes[0] ^= 0xFF; // flip a bit
        cb.cipher_text = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let result = PasswordEntry::decrypt_password(&cb.cipher_text, &cb.nonce_bytes, &key);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_returns_unique_nonce_each_time() {
        // Arrange
        let key = generate_key();
        let password = "unique-nonce-test";

        // Act
        let cb_1 = PasswordEntry::encrypt_password(password, &key).unwrap();
        let cb_2 = PasswordEntry::encrypt_password(password, &key).unwrap();

        // Assert
        assert_ne!(cb_1.nonce_bytes, cb_2.nonce_bytes);
    }
}
