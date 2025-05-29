#[cfg(test)]
mod argon2_tests {
    use crate::argon2_key_derivation::KeyManager;

    #[test]
    fn test_derive_encryption_key() {
        // Arrange
        let master_password = "my-secret-password";
        let salt = b"static-test-salt12";

        // Act
        let key1 = KeyManager::derive_encryption_key(master_password, salt)
            .expect("Key derivation failed");
        let key2 = KeyManager::derive_encryption_key(master_password, salt)
            .expect("Key derivation failed");

        // Assert
        assert_eq!(key1.len(), 32, "Derived key must be 32 bytes");
        assert_eq!(key1, key2, "Same password and salt must produce same key");
    }
}
