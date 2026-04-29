use crate::{
    argon2_key_derivation::get_encryption_key,
    db::DBManager,
    error::{AppError, AppResult},
    model::PasswordEntry,
    start::AppState,
};
use chrono::Utc;
use futures::TryStreamExt;
use tauri::{AppHandle, State};
use uuid::Uuid;

/// Registers a new user by creating a fresh database and deriving the
/// encryption key from the provided master password.
///
/// If a database already exists, it is deleted before creating the new one,
/// allowing re-registration.
#[tauri::command]
#[tracing::instrument(
    name = "Register a new user",
    skip(app, state, master_password),
    fields(encrypt_db)
)]
pub async fn register(
    app: AppHandle,
    state: State<'_, AppState>,
    master_password: String,
    encrypt_db: bool,
) -> AppResult<()> {
    if master_password.is_empty() {
        return Err(AppError::Validation(
            "Master password cannot be empty".into(),
        ));
    }

    // Delete any existing database so registration is idempotent.
    if DBManager::is_db_exist(&app).await.unwrap_or(false) {
        DBManager::delete_db_directory(&app).await?;
    }

    let pool = DBManager::register(&app, &master_password, encrypt_db)
        .await
        .map_err(|e| AppError::Database(format!("{}", e)))?;

    let key = get_encryption_key(&app, &master_password)
        .await
        .map_err(|_| AppError::KeyDerivation("Invalid password".into()))?;

    if !encrypt_db {
        DBManager::store_master_password_hash(&pool, &key)
            .await
            .map_err(|e| AppError::Database(format!("{}", e)))?;
    }

    {
        let mut guard = state.pool.write().await;
        *guard = Some(pool);
    }

    {
        let mut guard = state.encryption_key.write().await;
        *guard = Some(key.into());
    }

    tracing::info!("Login successful");
    Ok(())
}

/// Authenticates the user by opening the existing database and verifying the
/// master password.
///
/// On success, the connection pool and derived encryption key are stored in
/// `AppState`.
#[tauri::command]
#[tracing::instrument(name = "Login", skip_all)]
pub async fn login(
    app: AppHandle,
    state: State<'_, AppState>,
    master_password: String,
) -> AppResult<()> {
    if !DBManager::is_db_exist(&app).await.unwrap_or(false) {
        return Err(AppError::Validation("Please register first.".into()));
    }

    let pool = DBManager::login(&app, &master_password)
        .await
        .map_err(|_| AppError::Database("Invalid Password".into()))?;

    {
        let mut guard = state.pool.write().await;
        *guard = Some(pool);
    }

    let key = get_encryption_key(&app, &master_password)
        .await
        .map_err(|_| AppError::KeyDerivation("Failed to get encryption key".into()))?;

    {
        let mut guard = state.encryption_key.write().await;
        *guard = Some(key.into());
    }

    tracing::info!("Login successful");
    Ok(())
}

/// Logs out the current user by closing the database connection and zeroing
/// the encryption key.
///
/// The `EncryptionKey` type implements `ZeroizeOnDrop`, so replacing the
/// `Some(key)` with `None` drops the old key and overwrites its bytes with
/// zeros before the allocator can reuse the memory.
#[tauri::command]
#[tracing::instrument(name = "Logout", skip_all)]
pub async fn logout(state: State<'_, AppState>) -> AppResult<()> {
    let pool_to_close = state.pool.write().await.take();
    // Dropping the EncryptionKey here triggers ZeroizeOnDrop.
    let _ = state.encryption_key.write().await.take();

    if let Some(pool) = pool_to_close {
        pool.close().await;
        tracing::info!("Database pool closed");
    }

    tracing::info!("Logout complete; encryption key zeroized");
    Ok(())
}

/// Adds a new password entry to the vault.
///
/// The password is encrypted with AES-256-GCM before being written to the
/// database. Title and password are required; all other fields are optional.
#[tauri::command]
#[tracing::instrument(name = "Add a new password", skip_all)]
pub async fn add_password(
    state: State<'_, AppState>,
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
) -> AppResult<()> {
    validate_password_fields(&title, &password, &notes)?;

    let pool = state.pool.write().await;
    let pool = pool.as_ref().ok_or(AppError::NotAuthenticated)?;

    let guard = state.encryption_key.read().await;
    let encryption_key = guard.as_ref().ok_or(AppError::NotAuthenticated)?;

    let cipher_bundle = PasswordEntry::encrypt(&password, encryption_key)
        .map_err(|e| AppError::KeyDerivation(e.to_string()))?;

    let id = Uuid::new_v4().to_string();
    let created_at = Utc::now();

    sqlx::query(
        "INSERT INTO passwords (id, title, username, password, url, notes, created_at, updated_at, deleted, nonce) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
    )
    .bind(&id)
    .bind(&title)
    .bind(username)
    .bind(cipher_bundle.get_cipher_text())
    .bind(url)
    .bind(notes)
    .bind(created_at.timestamp())
    .bind(None::<i64>)
    .bind(false)
    .bind(cipher_bundle.get_nonce())
    .execute(pool)
    .await
    .map_err(|e| AppError::Database(format!("Failed to add password to database: {}", e)))?;

    tracing::info!(id = %id, title = %title, "Password entry added");
    Ok(())
}

/// Returns all non-deleted password entries, with passwords decrypted.
///
/// > **Future optimization:** For large vaults, consider returning metadata
/// > only and decrypting on demand via [`get_password_by_id`].
#[tauri::command]
#[tracing::instrument(name = "Retrieve all passwords", skip_all)]
pub async fn get_passwords(state: tauri::State<'_, AppState>) -> AppResult<Vec<PasswordEntry>> {
    let pool = state.pool.read().await;
    let pool = pool
        .as_ref()
        .ok_or(AppError::Database("Database pool not initialized".into()))?;

    let encryption_key = state.encryption_key.read().await;
    let encryption_key = encryption_key
        .as_ref()
        .ok_or(AppError::Database("Encryption key not initialized".into()))?;

    let mut entries: Vec<PasswordEntry> =
        sqlx::query_as::<_, PasswordEntry>("SELECT * FROM passwords WHERE deleted = false")
            .fetch(pool)
            .try_collect()
            .await
            .map_err(|_| AppError::Internal("Failed to get passwords".into()))?;

    // Future Optimization
    // If the list grows, consider lazy-decrypting per-entry.
    for entry in &mut entries {
        let decrypted = PasswordEntry::decrypt(&entry.password, &entry.nonce, encryption_key)
            .map_err(|_| AppError::Encryption("Can't decrypt password".into()))?;
        entry.password = decrypted;
    }

    tracing::debug!(count = entries.len(), "Passwords retrieved and decrypted");
    Ok(entries)
}

/// Returns a single password entry by ID, with the password decrypted.
#[tauri::command]
#[tracing::instrument(name = "Retrieve a password by ID", skip(state), fields(id))]
pub async fn get_password_by_id(
    state: tauri::State<'_, AppState>,
    id: String,
) -> AppResult<PasswordEntry> {
    let pool = state.pool.read().await;
    let pool = pool
        .as_ref()
        .ok_or(AppError::Database("Database pool not initialized".into()))?;

    let encryption_key = state.encryption_key.read().await;
    let encryption_key = encryption_key.as_ref().ok_or(AppError::Encryption(
        "Encryption key not initialized".into(),
    ))?;

    let mut entry: PasswordEntry = sqlx::query_as::<_, PasswordEntry>(
        "SELECT * FROM passwords WHERE deleted = false and id = ?1",
    )
    .bind(&id)
    .fetch_one(pool)
    .await
    .map_err(|_| AppError::Database("Failed to get password by id".into()))?;

    // Decrypt password before returning
    let decrypted = PasswordEntry::decrypt(&entry.password, &entry.nonce, encryption_key)
        .map_err(|_| AppError::Encryption("Failed to decrypt password".into()))?;
    entry.password = decrypted;

    tracing::debug!(id = %id, "Password entry retrieved");
    Ok(entry)
}

/// Updates an existing password entry.
///
/// The new password is encrypted before being written. All fields except
/// `id` are replaced.
#[tauri::command]
#[tracing::instrument(
    name = "Update a password",
    skip(state, title, username, password, url, notes),
    fields(id)
)]
pub async fn update_password(
    state: State<'_, AppState>,
    id: String,
    title: String,
    username: String,
    password: String,
    url: Option<String>,
    notes: Option<String>,
) -> AppResult<()> {
    validate_password_fields(&title, &password, &notes)?;

    let updated_at = Utc::now();

    let pool = state.pool.write().await;
    let pool = pool
        .as_ref()
        .ok_or(AppError::Database("Database pool not initialized".into()))?;

    let encryption_key = state.encryption_key.read().await;
    let encryption_key = encryption_key.as_ref().ok_or(AppError::Encryption(
        "Encryption key not initialized".into(),
    ))?;

    let cipher_bundle = PasswordEntry::encrypt(&password, encryption_key)?;

    sqlx::query(
       "UPDATE passwords SET title=?1, username=?2, password=?3, url=?4, notes=?5, updated_at=?6, nonce=?7 WHERE id = ?8",
   )
   .bind(title)
   .bind(username)
   .bind(cipher_bundle.get_cipher_text())
   .bind(url)
   .bind(notes)
   .bind(updated_at.timestamp())
   .bind(cipher_bundle.get_nonce())
   .bind(&id)
   .execute(pool)
   .await
   .map_err(|_| AppError::Database("Failed to update password in database".into()))?;

    tracing::info!(id = %id, "Password entry updated");
    Ok(())
}

/// Soft-deletes a password entry by setting `deleted = true`.
///
/// Entries are never physically removed from the database to allow for
/// future audit logging or recovery.
#[tauri::command]
#[tracing::instrument(name = "Delete a password", skip(state), fields(id))]
pub async fn delete_password(state: tauri::State<'_, AppState>, id: String) -> AppResult<()> {
    let pool = state.pool.write().await;
    let pool = pool
        .as_ref()
        .ok_or(AppError::Database("Database pool not initialized".into()))?;

    sqlx::query("UPDATE passwords SET deleted = true WHERE id = ?1")
        .bind(&id)
        .execute(pool)
        .await
        .map_err(|_| AppError::Database("Could not delete password".into()))?;

    tracing::info!(id = %id, "Password entry soft-deleted");
    Ok(())
}

/// Returns whether a database file exists on disk.
///
/// Safe to call when not authenticated.
#[tauri::command]
#[tracing::instrument(name = "Check if db exist", skip_all)]
pub async fn is_db_exist(app: AppHandle) -> AppResult<bool> {
    let db_exist = DBManager::is_db_exist(&app).await.unwrap_or(false);
    Ok(db_exist)
}

/// Deletes the database file and salt, resetting the application to its
/// initial state.
#[tauri::command]
#[tracing::instrument(name = "Delte the directory where the Database is located", skip_all)]
pub async fn delete_db_directory(app: AppHandle) -> AppResult<()> {
    DBManager::delete_db_directory(&app)
        .await
        .map_err(|_| AppError::Database("Could not delete database directory".into()))?;
    tracing::info!("Database and salt files deleted");
    Ok(())
}

/// Validates common fields shared by `add_password` and `update_password`.
fn validate_password_fields(title: &str, password: &str, notes: &Option<String>) -> AppResult<()> {
    if title.is_empty() {
        return Err(AppError::Validation("Title is required".into()));
    }
    if password.is_empty() {
        return Err(AppError::Validation("Password is required".into()));
    }
    if let Some(n) = notes {
        if n.len() > 500 {
            return Err(AppError::Validation(
                "Notes cannot exceed 500 characters".into(),
            ));
        }
    }
    Ok(())
}
