//! Wire types and crypto parameters shared by the `senders` server and the
//! WASM frontend.
//!
//! Nothing in here ever touches key material: the server only sees ciphertext,
//! an opaque encrypted-metadata blob, and a *hash* of the download auth key.

use serde::{Deserialize, Serialize};

pub mod b64;

/// Plaintext bytes per AES-GCM record. Ciphertext records are 16 bytes longer.
pub const CHUNK_SIZE: usize = 64 * 1024;
/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;
/// Ciphertext bytes per record.
pub const CHUNK_CIPHERTEXT_SIZE: usize = CHUNK_SIZE + TAG_LEN;

/// Random per-file prefix of the STREAM nonce. The remaining 5 bytes are a
/// 4-byte big-endian record counter plus a 1-byte final-record flag.
pub const NONCE_PREFIX_LEN: usize = 7;
/// Full AES-GCM nonce length.
pub const NONCE_LEN: usize = 12;
/// Length of the master secret that lives in the URL fragment.
pub const SECRET_LEN: usize = 32;
/// Length of every derived symmetric key.
pub const KEY_LEN: usize = 32;
/// Salt length for password-derived auth keys.
pub const AUTH_SALT_LEN: usize = 16;
/// PBKDF2-HMAC-SHA256 iterations for password-protected files.
pub const PBKDF2_ITERATIONS: u32 = 250_000;

/// HKDF `info` strings. Distinct labels keep the derived keys independent.
pub const INFO_CONTENT: &[u8] = b"senders/v1/content";
pub const INFO_METADATA: &[u8] = b"senders/v1/metadata";
pub const INFO_AUTH: &[u8] = b"senders/v1/auth";

/// Expiry bounds, in seconds: one day to thirty days.
pub const MIN_EXPIRY_SECS: u64 = 24 * 60 * 60;
pub const MAX_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;
pub const DEFAULT_EXPIRY_SECS: u64 = MIN_EXPIRY_SECS;

/// Download-count bounds. `1` means "delete immediately after one download".
pub const MIN_DOWNLOADS: u32 = 1;
pub const MAX_DOWNLOADS: u32 = 1000;
pub const DEFAULT_MAX_DOWNLOADS: u32 = 1;

/// Headers carrying upload parameters alongside the streamed ciphertext body.
pub mod header {
    pub const METADATA: &str = "x-senders-metadata";
    pub const AUTH_HASH: &str = "x-senders-auth-hash";
    pub const AUTH_SALT: &str = "x-senders-auth-salt";
    pub const NONCE_PREFIX: &str = "x-senders-nonce-prefix";
    pub const EXPIRES_IN: &str = "x-senders-expires-in";
    pub const MAX_DOWNLOADS: &str = "x-senders-max-downloads";
}

/// Cleartext metadata about a file, encrypted client-side before upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub name: String,
    #[serde(default)]
    pub mime: String,
    pub size: u64,
}

/// Result of a successful upload. `owner_token` is shown once and never stored
/// in cleartext by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResponse {
    pub id: String,
    pub owner_token: String,
    pub expires_at: u64,
}

/// Unauthenticated pre-flight information a downloader needs before it can
/// derive the auth key (it must know whether a password is required, and with
/// which salt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileParams {
    pub id: String,
    pub has_password: bool,
    /// base64url PBKDF2 salt; present only when `has_password`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_salt: Option<String>,
    pub kdf_iterations: u32,
    pub expires_at: u64,
    pub downloads_remaining: u32,
}

/// Authenticated metadata response: everything needed to start decrypting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataResponse {
    pub id: String,
    /// base64url AES-GCM ciphertext of a JSON [`FileMetadata`], nonce-prefixed.
    pub metadata: String,
    /// base64url STREAM nonce prefix.
    pub nonce_prefix: String,
    /// Ciphertext length in bytes.
    pub size: u64,
    pub expires_at: u64,
    pub downloads_remaining: u32,
}

/// Owner-only view of a file's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerInfo {
    pub id: String,
    pub downloads: u32,
    pub max_downloads: u32,
    pub expires_at: u64,
    pub size: u64,
    pub has_password: bool,
}

/// Owner-initiated password (re)configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetPasswordRequest {
    /// base64url SHA-256 of the new auth key.
    pub auth_hash: String,
    /// base64url PBKDF2 salt, or `None` to remove the password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_salt: Option<String>,
}

/// Server limits and auth state, fetched by the frontend at boot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub max_file_size: u64,
    pub min_expiry_secs: u64,
    pub max_expiry_secs: u64,
    pub default_expiry_secs: u64,
    pub max_downloads: u32,
    pub default_max_downloads: u32,
    /// `off`, `upload`, or `all`.
    pub auth_mode: String,
    pub auth_required: bool,
    pub session: Option<SessionInfo>,
}

/// The signed-in user, when OIDC is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Uniform error body for every failing API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
}

/// Ciphertext length for a plaintext of `len` bytes under the record scheme.
pub fn ciphertext_len(len: u64) -> u64 {
    let chunk = CHUNK_SIZE as u64;
    // An empty file still produces one (empty, authenticated) final record.
    let records = if len == 0 { 1 } else { len.div_ceil(chunk) };
    len + records * TAG_LEN as u64
}

/// Plaintext length recovered from a ciphertext length, or `None` if the
/// length is not a valid encoding.
pub fn plaintext_len(cipher_len: u64) -> Option<u64> {
    let full = CHUNK_CIPHERTEXT_SIZE as u64;
    let tag = TAG_LEN as u64;
    let whole = cipher_len / full;
    let rest = cipher_len % full;
    if rest == 0 {
        // Last record is exactly full; there must be at least one record.
        if whole == 0 {
            None
        } else {
            Some(cipher_len - whole * tag)
        }
    } else if rest < tag {
        None
    } else {
        Some(cipher_len - (whole + 1) * tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_roundtrip() {
        for len in [
            0u64,
            1,
            100,
            CHUNK_SIZE as u64 - 1,
            CHUNK_SIZE as u64,
            CHUNK_SIZE as u64 + 1,
            5_000_000,
        ] {
            let c = ciphertext_len(len);
            assert_eq!(plaintext_len(c), Some(len), "len={len} cipher={c}");
        }
    }

    #[test]
    fn rejects_impossible_ciphertext_lengths() {
        assert_eq!(plaintext_len(0), None);
        assert_eq!(plaintext_len(TAG_LEN as u64 - 1), None);
    }
}
