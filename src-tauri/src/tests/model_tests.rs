#[cfg(test)]
mod model_tests {
    use crate::model::PasswordEntry;
    use base64::{engine::general_purpose, Engine};
    use rand::rngs::OsRng;
    use rand::TryRngCore;

    fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.try_fill_bytes(&mut key).unwrap();
        key
    }

    #[test]
    fn test_encrypt_and_decrypt_password_success() {
        // Arrange
        let key = generate_key();
        let original_password = "super_secret_password";

        // Act
        let (cipthertext, nonce) =
            PasswordEntry::encrypt_password(original_password, &key).unwrap();

        let nonce = nonce.unwrap();
        let decoded_nonce = general_purpose::STANDARD.decode(&nonce).unwrap();

        let decrypted_password =
            PasswordEntry::decrypt_password(&cipthertext, &nonce, &key).unwrap();

        // Assert
        assert!(cipthertext.len() > 0);
        assert!(decoded_nonce.len() == PasswordEntry::LEN_NONCE);
        assert_eq!(original_password, decrypted_password);
    }

    #[test]
    fn test_decrypt_with_wrong_key_should_fail() {
        // Arrange
        let key1 = generate_key();
        let key2 = generate_key();
        let original_password = "password123";

        // Act
        let (cipthertext, nonce) =
            PasswordEntry::encrypt_password(original_password, &key1).unwrap();

        let result = PasswordEntry::decrypt_password(&cipthertext, &nonce.unwrap(), &key2);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_modified_ciphertext_should_fail() {
        // Arrange
        let key = generate_key();
        let original_password = "correct-horse-battery-staple";

        // Act
        let (mut cipthertext, nonce) =
            PasswordEntry::encrypt_password(original_password, &key).unwrap();

        // Tamper with the ciphertext (simulate corruption)
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&cipthertext)
            .unwrap();
        bytes[0] ^= 0xFF; // flip a bit
        cipthertext = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let result = PasswordEntry::decrypt_password(&cipthertext, &nonce.unwrap(), &key);

        // Assert
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_returns_unique_nonce_each_time() {
        // Arrange
        let key = generate_key();
        let password = "unique-nonce-test";

        // Act
        let (_, nonce1) = PasswordEntry::encrypt_password(password, &key).unwrap();
        let (_, nonce2) = PasswordEntry::encrypt_password(password, &key).unwrap();

        // Assert
        assert_ne!(nonce1, nonce2);
    }
}
