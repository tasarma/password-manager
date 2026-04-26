use crate::error::{AppError, AppResult};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
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

/// The output of a successful encryption: base64-encoded ciphertext and nonce.
///
/// Both are stored as `String` because they are written to SQLite TEXT columns.
/// The nonce is always present after encryption, so it is not `Option`.
pub struct CipherBundle {
    cipher_text: String,
    nonce_bytes: String,
}

impl CipherBundle {
    pub fn get_cipher_text(&self) -> &str {
        &self.cipher_text
    }

    pub fn get_nonce(&self) -> &str {
        &self.nonce_bytes
    }
}

/// A 32-byte AES-256 encryption key derived from the master password via Argon2.
///
/// The newtype pattern serves two purposes:
///
/// 1. **Type safety** — the compiler prevents accidentally passing a random
///    `[u8; 32]` (e.g., a nonce buffer) where an encryption key is expected.
/// 2. **Guaranteed zeroization** — `ZeroizeOnDrop` ensures the key bytes is
///    wiped from RAM when dropped. Without this, old key material
///    lingers in heap memory until the allocator happens to reuse it.
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

/// A password entry as stored in the database and returned to the frontend.
///
/// Note: `nonce` is skipped during serialization (`serde(skip)`) so it is
/// never exposed to the TypeScript frontend. It is fetched from the DB solely
/// to perform decryption before the entry is returned.
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
    pub nonce: String,
}

impl PasswordEntry {
    /// Encrypt a plaintext password using AES-256-GCM.
    ///
    /// A cryptographically random 96-bit nonce is generated for every call,
    /// ensuring that encrypting the same password twice produces different
    /// ciphertext — a requirement for GCM semantic security.
    ///
    /// # Errors
    ///
    /// Returns an error if nonce generation or AES-GCM encryption fails.
    #[tracing::instrument(
        name = "Encrypt a password before saving in the database",
        skip_all,
        fields(cipher = "AES-256-GCM")
    )]
    pub fn encrypt(password: &str, encryption_key: &EncryptionKey) -> AppResult<CipherBundle> {
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

    /// Decrypt an AES-256-GCM ciphertext using the provided key and nonce.
    ///
    /// Both `ciphertext_b64` and `nonce_b64` must be valid standard base64.
    /// The GCM authentication tag is verified during decryption; any
    /// tampering with the ciphertext will cause this function to return `Err`.
    ///
    /// # Errors
    ///
    /// Returns an error if base64 decoding, AES-GCM decryption (including
    /// authentication tag verification), or UTF-8 decoding of the plaintext fails.
    #[tracing::instrument(name = "Decrypt a password", skip_all, fields(cipher = "AES-256-GCM"))]
    pub fn decrypt(
        cipher_text: &str,
        nonce: &str,
        encryption_key: &EncryptionKey,
    ) -> AppResult<String> {
        let cipher = Aes256Gcm::new_from_slice(encryption_key.as_ref())
            .map_err(|e| AppError::Encryption(format!("Failed to initialise Cipher: {}", e)))?;

        let nonce_bytes = general_purpose::STANDARD
            .decode(nonce)
            .map_err(|_| AppError::Validation("Invalid nonce encoding".into()))?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let cipher_text = general_purpose::STANDARD
            .decode(cipher_text)
            .map_err(|_| AppError::Validation("Invalid ciphertext encoding.".into()))?;

        let plaintext = cipher
            .decrypt(nonce, cipher_text.as_ref())
            .map_err(|_| AppError::Encryption("Decryption failed or data corrupted".into()))?;

        let password = String::from_utf8(plaintext)
            .map_err(|_| AppError::Validation("Decrypted data is not valid UTF-8".into()))?;

        Ok(password)
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
        let cb = PasswordEntry::encrypt(original_password, &key).unwrap();

        let decoded_nonce = general_purpose::STANDARD.decode(&cb.nonce_bytes).unwrap();

        let decrypted_password =
            PasswordEntry::decrypt(&cb.cipher_text, &cb.nonce_bytes, &key).unwrap();

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
        let cb = PasswordEntry::encrypt(original_password, &key1).unwrap();

        let result = PasswordEntry::decrypt(&cb.cipher_text, &cb.nonce_bytes, &key2);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_modified_ciphertext_should_fail() {
        // Arrange
        let key = generate_key();
        let original_password = "correct-horse-battery-staple";

        // Act
        let mut cb = PasswordEntry::encrypt(original_password, &key).unwrap();

        // Tamper with the ciphertext (simulate corruption)
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&cb.cipher_text)
            .unwrap();
        bytes[0] ^= 0xFF; // flip a bit
        cb.cipher_text = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let result = PasswordEntry::decrypt(&cb.cipher_text, &cb.nonce_bytes, &key);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_returns_unique_nonce_each_time() {
        // Arrange
        let key = generate_key();
        let password = "unique-nonce-test";

        // Act
        let cb_1 = PasswordEntry::encrypt(password, &key).unwrap();
        let cb_2 = PasswordEntry::encrypt(password, &key).unwrap();

        // Assert
        assert_ne!(cb_1.nonce_bytes, cb_2.nonce_bytes);
    }
}
