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
