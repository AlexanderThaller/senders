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

/// HKDF `info` label for the file-body key. Distinct labels are what keep the
/// three derived keys independent of one another.
pub const INFO_CONTENT: &[u8] = b"senders/v1/content";
/// HKDF `info` label for the key that seals the name/type metadata.
pub const INFO_METADATA: &[u8] = b"senders/v1/metadata";
/// HKDF `info` label for the download capability.
pub const INFO_AUTH: &[u8] = b"senders/v1/auth";

/// Shortest lifetime a share may be given, in seconds.
pub const MIN_EXPIRY_SECS: u64 = 24 * 60 * 60;
/// Longest lifetime a share may be given, in seconds. A server may lower this
/// but not raise it.
pub const MAX_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;
/// Lifetime used when the client does not ask for one.
pub const DEFAULT_EXPIRY_SECS: u64 = MIN_EXPIRY_SECS;

/// Smallest download budget: one download, then the file is destroyed.
pub const MIN_DOWNLOADS: u32 = 1;
/// Largest download budget a client may request.
pub const MAX_DOWNLOADS: u32 = 1000;
/// Budget used when the client does not ask for one. Burn after reading is the
/// safer default, so it is the default.
pub const DEFAULT_MAX_DOWNLOADS: u32 = 1;

/// Headers carrying upload parameters alongside the streamed ciphertext body.
pub mod header {
    /// base64url ciphertext of the JSON [`FileMetadata`](super::FileMetadata).
    pub const METADATA: &str = "x-senders-metadata";
    /// base64url SHA-256 of the download capability.
    pub const AUTH_HASH: &str = "x-senders-auth-hash";
    /// base64url PBKDF2 salt; present only for passphrase-protected files.
    pub const AUTH_SALT: &str = "x-senders-auth-salt";
    /// base64url STREAM nonce prefix.
    pub const NONCE_PREFIX: &str = "x-senders-nonce-prefix";
    /// Requested lifetime in seconds; clamped by the server.
    pub const EXPIRES_IN: &str = "x-senders-expires-in";
    /// Requested download budget; clamped by the server.
    pub const MAX_DOWNLOADS: &str = "x-senders-max-downloads";
}

/// Cleartext metadata about a file, encrypted client-side before upload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// The file name as the sender chose it.
    pub name: String,
    /// MIME type, so the download is saved as the right kind of file.
    #[serde(default)]
    pub mime: String,
    /// Plaintext length in bytes.
    #[serde(default)]
    pub size: u64,
}

/// Result of a successful upload. `owner_token` is shown once and never stored
/// in cleartext by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResponse {
    /// Share identifier; the part of the link before the `#`.
    pub id: String,
    /// Proof of ownership, shown once and never stored in the clear.
    pub owner_token: String,
    /// Absolute expiry, seconds since the Unix epoch.
    pub expires_at: u64,
}

/// Unauthenticated pre-flight information a downloader needs before it can
/// derive the auth key (it must know whether a password is required, and with
/// which salt).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileParams {
    /// Share identifier, echoed back.
    pub id: String,
    /// Whether a passphrase is needed before anything can be downloaded.
    pub has_password: bool,
    /// base64url PBKDF2 salt; present only when `has_password`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_salt: Option<String>,
    /// PBKDF2 iteration count to use with `auth_salt`.
    pub kdf_iterations: u32,
    /// Absolute expiry, seconds since the Unix epoch.
    pub expires_at: u64,
    /// Downloads still allowed before the file is destroyed.
    pub downloads_remaining: u32,
}

/// Authenticated metadata response: everything needed to start decrypting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataResponse {
    /// Share identifier, echoed back.
    pub id: String,
    /// base64url AES-GCM ciphertext of a JSON [`FileMetadata`], nonce-prefixed.
    pub metadata: String,
    /// base64url STREAM nonce prefix.
    pub nonce_prefix: String,
    /// Ciphertext length in bytes.
    pub size: u64,
    /// Absolute expiry, seconds since the Unix epoch.
    pub expires_at: u64,
    /// Downloads still allowed before the file is destroyed.
    pub downloads_remaining: u32,
}

/// Owner-only view of a file's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerInfo {
    /// Share identifier, echoed back.
    pub id: String,
    /// Downloads served so far.
    pub downloads: u32,
    /// Total download budget.
    pub max_downloads: u32,
    /// Absolute expiry, seconds since the Unix epoch.
    pub expires_at: u64,
    /// Ciphertext length in bytes.
    pub size: u64,
    /// Whether a passphrase is required to download.
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
    /// Largest ciphertext this server accepts, in bytes.
    pub max_file_size: u64,
    /// Shortest lifetime this server offers, in seconds.
    pub min_expiry_secs: u64,
    /// Longest lifetime this server offers, in seconds.
    pub max_expiry_secs: u64,
    /// Lifetime applied when the client does not choose one.
    pub default_expiry_secs: u64,
    /// Largest download budget this server allows.
    pub max_downloads: u32,
    /// Download budget applied when the client does not choose one.
    pub default_max_downloads: u32,
    /// `off`, `upload`, or `all`.
    pub auth_mode: String,
    /// Whether any route requires a signed-in user.
    pub auth_required: bool,
    /// The current user, when signed in.
    pub session: Option<SessionInfo>,
}

/// The signed-in user, when OIDC is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Stable identifier for the user, from the identity provider.
    pub subject: String,
    /// Email address, when the provider supplies one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Display name, when the provider supplies one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Uniform error body for every failing API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable machine-readable code, e.g. `not_found`.
    pub error: String,
    /// Human-readable explanation, safe to show to the user.
    pub message: String,
}

/// Ciphertext length for a plaintext of `len` bytes under the record scheme.
#[must_use]
pub fn ciphertext_len(len: u64) -> u64 {
    let chunk = CHUNK_SIZE as u64;
    // An empty file still produces one (empty, authenticated) final record.
    let records = if len == 0 { 1 } else { len.div_ceil(chunk) };
    len + records * TAG_LEN as u64
}

/// Plaintext length recovered from a ciphertext length, or `None` if the
/// length is not a valid encoding.
#[must_use]
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
