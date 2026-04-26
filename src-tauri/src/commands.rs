use crate::{
    argon2_key_derivation::KeyManager, db::DBManager, model::PasswordEntry, start::AppState,
};
use chrono::Utc;
use futures::TryStreamExt;
use tauri::{AppHandle, State};
use uuid::Uuid;

#[tauri::command]
pub async fn register(
    app: AppHandle,
    state: State<'_, AppState>,
    master_password: String,
    encrypt_db: bool,
) -> Result<(), String> {
    if master_password.is_empty() {
        return Err("Password cannot be empty".to_string());
    }

    if DBManager::is_db_exist(&app).await.unwrap_or(false) {
        DBManager::delete_db_directory(&app)
            .await
            .map_err(|e| format!("Could not register: {}", e))?;
    }

    let pool = DBManager::register(&app, &master_password, encrypt_db)
        .await
        .map_err(|e| e.to_string())?;

    let key = KeyManager::get_encryption_key(&app, &master_password)
        .await
        .map_err(|e| format!("Invalid password {}", e))?;

    if !encrypt_db {
        DBManager::store_master_password_hash(&pool, &key)
            .await
            .map_err(|e| format!("Can't store the hash {}", e))?;
    }

    {
        let mut guard = state.pool.write().await;
        *guard = Some(pool);
    }

    {
        let mut guard = state.encryption_key.write().await;
        *guard = Some(key.into());
    }

    Ok(())
}

#[tauri::command]
pub async fn login(
    app: AppHandle,
    state: State<'_, AppState>,
    master_password: String,
) -> Result<(), String> {
    if !DBManager::is_db_exist(&app).await.unwrap_or(false) {
        return Err("Please register first.".to_string());
    }

    let pool = DBManager::login(&app, &master_password)
        .await
        .map_err(|_e| "Invalid Password")?;

    {
        let mut guard = state.pool.write().await;
        *guard = Some(pool);
    }

    let key: [u8; KeyManager::LEN_ENCRYPTION_KEY] =
        KeyManager::get_encryption_key(&app, &master_password)
            .await
            .map_err(|e| format!("Failed to get encryption key: {}", e))?;

    {
        let mut guard = state.encryption_key.write().await;
        *guard = Some(key.into());
    }

    Ok(())
}

#[tauri::command]
pub async fn logout(state: State<'_, AppState>) -> Result<(), String> {
    let pool_to_close = {
        let mut pool_guard = state.pool.write().await;
        pool_guard.take()
    };
    if let Some(pool) = pool_to_close {
        pool.close().await;
    }
    Ok(())
}

#[tauri::command]
pub async fn add_password(
    state: State<'_, AppState>,
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
) -> Result<(), String> {
    if title.is_empty() || username.is_none() || password.is_empty() {
        return Err("Title, username, and password are required".to_string());
    }

    if let Some(ref n) = notes {
        if n.len() > 500 {
            return Err("Notes cannot exceed 500 characters".to_string());
        }
    }

    let guard = state.encryption_key.read().await;
    let encryption_key = guard.as_ref().ok_or("Encryption key not initialized")?;

    let cipher_bundle =
        PasswordEntry::encrypt(&password, encryption_key).map_err(|e| e.to_string())?;

    let pool = state.pool.write().await;
    let pool = pool.as_ref().ok_or("Database pool not initialized")?;

    let id = Uuid::new_v4().to_string();
    let created_at = Utc::now();

    sqlx::query(
        "INSERT INTO passwords (id, title, username, password, url, notes, created_at, updated_at, deleted, nonce) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
    )
    .bind(id)
    .bind(title)
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
    .map_err(|e| format!("Failed to add password to database: {}", e))?;

    Ok(())
}

#[tauri::command]
pub async fn get_passwords(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PasswordEntry>, String> {
    let pool = state.pool.read().await;
    let pool = pool.as_ref().ok_or("Database pool not initialized")?;

    let encryption_key = state.encryption_key.read().await;
    let encryption_key = encryption_key
        .as_ref()
        .ok_or("Encryption key not initialized")?;

    let mut entries: Vec<PasswordEntry> =
        sqlx::query_as::<_, PasswordEntry>("SELECT * FROM passwords WHERE deleted = false")
            .fetch(pool)
            .try_collect()
            .await
            .map_err(|e| format!("Failed to get passwords {}", e))?;

    // Future Optimization
    // If the list grows, consider lazy-decrypting per-entry.
    for entry in &mut entries {
        let decrypted = PasswordEntry::decrypt(&entry.password, &entry.nonce, encryption_key)
            .map_err(|e| format!("Can't decrypt password: {}", e))?;
        entry.password = decrypted;
    }

    Ok(entries)
}

#[tauri::command]
pub async fn get_password_by_id(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<PasswordEntry, String> {
    let pool = state.pool.read().await;
    let pool = pool.as_ref().ok_or("Database pool not initialized")?;

    let encryption_key = state.encryption_key.read().await;
    let encryption_key = encryption_key
        .as_ref()
        .ok_or("Encryption key not initialized")?;

    let mut entry: PasswordEntry = sqlx::query_as::<_, PasswordEntry>(
        "SELECT * FROM passwords WHERE deleted = false and id = ?1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| format!("Failed to get password by id {}", e))?;

    // Decrypt password before returning
    let decrypted = PasswordEntry::decrypt(&entry.password, &entry.nonce, encryption_key)
        .map_err(|e| format!("Failed to decrypt password: {}", e))?;
    entry.password = decrypted;

    Ok(entry)
}

#[tauri::command]
pub async fn update_password(
    state: State<'_, AppState>,
    id: String,
    title: String,
    username: String,
    password: String,
    url: Option<String>,
    notes: Option<String>,
) -> Result<(), String> {
    if title.is_empty() || username.is_empty() || password.is_empty() {
        return Err("Title, username, and password are required".to_string());
    }

    if let Some(ref n) = notes {
        if n.len() > 500 {
            return Err("Notes cannot exceed 500 characters".to_string());
        }
    }

    let updated_at = Utc::now();

    let pool = state.pool.write().await;
    let pool = pool.as_ref().ok_or("Database pool not initialized")?;

    let encryption_key = state.encryption_key.read().await;
    let encryption_key = encryption_key
        .as_ref()
        .ok_or("Encryption key not initialized")?;

    let cipher_bundle =
        PasswordEntry::encrypt(&password, encryption_key).map_err(|e| e.to_string())?;

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
   .bind(id)
   .execute(pool)
   .await
   .map_err(|e| format!("Failed to update password in database: {}", e))?;

    Ok(())
}

#[tauri::command]
pub async fn delete_password(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    let pool = state.pool.write().await;
    let pool = pool.as_ref().ok_or("Database pool not initialized")?;

    sqlx::query("UPDATE passwords SET deleted = true WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| format!("Could not delete password {}", e))?;

    Ok(())
}

#[tauri::command]
pub async fn is_db_exist(app: AppHandle) -> Result<bool, String> {
    let db_exist = DBManager::is_db_exist(&app).await.unwrap_or(false);
    Ok(db_exist)
}

#[tauri::command]
pub async fn delete_db_directory(app: AppHandle) -> Result<(), String> {
    DBManager::delete_db_directory(&app)
        .await
        .map_err(|e| format!("Could not delete database directory: {}", e))?;
    Ok(())
}
