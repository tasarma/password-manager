use serde::Serialize;
use thiserror::Error;

/// Centralized Application Error type
/// Structured error type for all Tauri command boundaries.
///
/// Using an enum rather than `String` allows the TypeScript frontend to
/// branch on error *kind* without parsing human-readable messages.
///
/// Tauri commands require the `Err` variant to implement `Serialize`.
/// `Result<T, E>` where `E: Serialize`.
#[derive(Debug, Error, Serialize)]
pub enum AppError {
    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Key derivation error: {0}")]
    KeyDerivation(String),
}

pub type AppResult<T> = Result<T, AppError>;
