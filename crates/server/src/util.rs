//! Small primitives shared across the server: clock, RNG, and hashing.

use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `N` bytes from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// A URL-safe random identifier with 128 bits of entropy.
pub fn random_id() -> String {
    senders_proto::b64::encode(random_bytes::<16>())
}

/// A URL-safe random token with 256 bits of entropy.
pub fn random_token() -> String {
    senders_proto::b64::encode(random_bytes::<32>())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Constant-time comparison, so token checks do not leak a prefix by timing.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Reject identifiers that are not exactly what [`random_id`] produces, so a
/// malicious id can never escape a storage prefix or blow up a Redis key.
pub fn is_valid_id(id: &str) -> bool {
    id.len() == 22
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_accepted() {
        for _ in 0..64 {
            assert!(is_valid_id(&random_id()));
        }
    }

    #[test]
    fn traversal_and_junk_ids_are_rejected() {
        for bad in [
            "",
            "..",
            "../../etc/passwd",
            "short",
            &"a".repeat(23),
            "aaaaaaaaaaaaaaaaaaaaa/",
        ] {
            assert!(!is_valid_id(bad), "should reject {bad:?}");
        }
    }
}
