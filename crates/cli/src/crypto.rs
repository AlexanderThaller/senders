//! Native cryptography, mirroring `crates/web/src/crypto.rs`.
//!
//! The frontend does this work against the browser's `WebCrypto`; the CLI has
//! no browser to borrow one from, so this is the same scheme implemented
//! against `RustCrypto` crates instead. The two must agree byte for byte — same
//! HKDF labels, same STREAM nonce layout, same AES-GCM tag length — or a file
//! sealed by one side would not open on the other.
//!
//! # Scheme
//!
//! See `crates/web/src/crypto.rs` for the full write-up; in short, a 32-byte
//! `secret` yields three independent HKDF-SHA256 keys (content, metadata,
//! auth), and the file body is sealed in 64 KiB records under the STREAM
//! construction so truncation and reordering fail loudly instead of silently.

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit};
use hkdf::Hkdf;
use rand::RngCore as _;
use senders_proto::{
    INFO_AUTH, INFO_CONTENT, INFO_METADATA, KEY_LEN, NONCE_LEN, SECRET_LEN, TAG_LEN,
};
use sha2::{Digest, Sha256};

/// Result shorthand for the cryptographic operations in this module.
pub type Result<T> = std::result::Result<T, Error>;

/// A cryptographic operation failed.
///
/// Decryption failures are deliberately indistinguishable from one another: a
/// caller cannot tell a wrong key from a tampered record, which is the point.
#[derive(Debug, Clone)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// `n` bytes from a CSPRNG seeded from the OS.
#[must_use]
pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// Build a fixed-size `generic-array` from a byte slice.
///
/// `generic-array` 0.14 blanket-deprecates itself in favour of a 1.x release
/// that `aes-gcm` 0.10 has not adopted yet, so every constructor on it warns.
/// Centralised here rather than at each of the call sites below.
#[expect(
    deprecated,
    reason = "generic-array 0.14 deprecates its whole API pending a 1.x upgrade across the RustCrypto crates aes-gcm 0.10 depends on; there is no non-deprecated constructor yet"
)]
fn fixed_bytes<N: aes_gcm::aead::generic_array::ArrayLength<u8>>(
    slice: &[u8],
) -> aes_gcm::aead::generic_array::GenericArray<u8, N> {
    aes_gcm::aead::generic_array::GenericArray::clone_from_slice(slice)
}

/// Generate a passphrase meant to be carried over a *different* channel than
/// the share link. Formatting (grouping, alphabet) lives in `senders-proto`,
/// shared with `crates/web`; only the randomness source is native here.
#[must_use]
pub fn generate_passphrase() -> String {
    senders_proto::passphrase::format(&random_bytes(senders_proto::passphrase::BYTES))
}

/// SHA-256, used to turn the auth key into the digest the server stores.
#[must_use]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Derive `KEY_LEN` bytes from `secret` under an HKDF `info` label. An empty
/// salt is the RFC 5869 default; the secret is already uniformly random, so
/// the extract step has nothing to gain from one.
fn hkdf(secret: &[u8], info: &[u8]) -> [u8; KEY_LEN] {
    let mut okm = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(Some(&[]), secret)
        .expand(info, &mut okm)
        .expect("KEY_LEN is within HKDF-SHA256's 255-block output limit");
    okm
}

/// Derive an auth key from a password. Deliberately slow: this is the only
/// thing standing between a leaked link and the file.
#[must_use]
pub fn pbkdf2(password: &str, salt: &[u8], iterations: u32) -> [u8; KEY_LEN] {
    let mut okm = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut okm);
    okm
}

/// The three keys for one file, plus the auth key the server will check.
pub struct FileKeys {
    content: Aes256Gcm,
    metadata: Aes256Gcm,
    /// The download capability. Sent to the server only as a SHA-256 digest.
    pub auth: Vec<u8>,
}

impl std::fmt::Debug for FileKeys {
    /// Hand-written so no key material can reach a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileKeys").finish_non_exhaustive()
    }
}

impl FileKeys {
    /// Derive everything from the URL-fragment secret.
    pub fn derive(secret: &[u8]) -> Result<Self> {
        if secret.len() != SECRET_LEN {
            return Err(Error(format!("secret must be {SECRET_LEN} bytes")));
        }
        let content = Aes256Gcm::new(&fixed_bytes(&hkdf(secret, INFO_CONTENT)));
        let metadata = Aes256Gcm::new(&fixed_bytes(&hkdf(secret, INFO_METADATA)));
        let auth = hkdf(secret, INFO_AUTH).to_vec();
        Ok(Self {
            content,
            metadata,
            auth,
        })
    }

    /// Replace the URL-derived auth key with a password-derived one.
    #[must_use]
    pub fn with_auth(mut self, auth: Vec<u8>) -> Self {
        self.auth = auth;
        self
    }

    /// The value the server stores and compares against.
    #[must_use]
    pub fn auth_hash(&self) -> Vec<u8> {
        sha256(&self.auth)
    }

    /// Seal the metadata blob. Layout: `nonce(12) || ciphertext`.
    pub fn seal_metadata(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = random_bytes(NONCE_LEN);
        let sealed = self
            .metadata
            .encrypt(&fixed_bytes(&nonce_bytes), plaintext)
            .map_err(|err| Error(format!("failed to seal metadata: {err}")))?;
        let mut out = nonce_bytes;
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Open the metadata blob sealed by [`seal_metadata`](Self::seal_metadata).
    pub fn open_metadata(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(Error("metadata is truncated".into()));
        }
        let (nonce, body) = sealed.split_at(NONCE_LEN);
        self.metadata
            .decrypt(&fixed_bytes(nonce), body)
            .map_err(|_| Error("failed to open metadata".into()))
    }

    /// Seal one plaintext record of the body.
    pub fn seal_record(
        &self,
        prefix: &[u8],
        counter: u32,
        last: bool,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = senders_proto::stream::record_nonce(prefix, counter, last);
        self.content
            .encrypt(&fixed_bytes(&nonce), plaintext)
            .map_err(|err| Error(format!("failed to seal record {counter}: {err}")))
    }

    /// Open one ciphertext record. Fails if the record was reordered,
    /// truncated, tampered with, or came from a different file.
    pub fn open_record(
        &self,
        prefix: &[u8],
        counter: u32,
        last: bool,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = senders_proto::stream::record_nonce(prefix, counter, last);
        self.content
            .decrypt(&fixed_bytes(&nonce), ciphertext)
            .map_err(|_| Error(format!("failed to open record {counter}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use senders_proto::NONCE_PREFIX_LEN;

    // Nonce construction itself (uniqueness per record, the final-record
    // flag) is tested once, in `senders_proto::stream`; these tests cover
    // this crate's own layer: the AEAD seal/open built on top of it.

    #[test]
    fn metadata_round_trips() {
        let secret = random_bytes(SECRET_LEN);
        let keys = FileKeys::derive(&secret).expect("valid secret length");
        let sealed = keys.seal_metadata(b"hello world").expect("seal");
        assert_eq!(keys.open_metadata(&sealed).expect("open"), b"hello world");
    }

    #[test]
    fn tampered_metadata_fails_to_open() {
        let secret = random_bytes(SECRET_LEN);
        let keys = FileKeys::derive(&secret).expect("valid secret length");
        let mut sealed = keys.seal_metadata(b"hello world").expect("seal");
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(keys.open_metadata(&sealed).is_err());
    }

    #[test]
    fn records_round_trip_and_reject_the_wrong_position() {
        let secret = random_bytes(SECRET_LEN);
        let keys = FileKeys::derive(&secret).expect("valid secret length");
        let prefix = random_bytes(NONCE_PREFIX_LEN);

        let sealed = keys
            .seal_record(&prefix, 0, true, b"a single record")
            .expect("seal");
        assert_eq!(
            keys.open_record(&prefix, 0, true, &sealed).expect("open"),
            b"a single record"
        );
        // Wrong counter, wrong final flag, and a different key must all fail.
        assert!(keys.open_record(&prefix, 1, true, &sealed).is_err());
        assert!(keys.open_record(&prefix, 0, false, &sealed).is_err());
        let other = FileKeys::derive(&random_bytes(SECRET_LEN)).expect("valid secret length");
        assert!(other.open_record(&prefix, 0, true, &sealed).is_err());
    }

    #[test]
    fn password_derived_auth_replaces_the_link_derived_one() {
        let secret = random_bytes(SECRET_LEN);
        let link_derived = FileKeys::derive(&secret).expect("valid secret length").auth;
        let salt = random_bytes(16);
        let from_password = pbkdf2("correct horse battery staple", &salt, 1000).to_vec();
        let keys = FileKeys::derive(&secret)
            .expect("valid secret length")
            .with_auth(from_password.clone());
        assert_ne!(keys.auth, link_derived);
        assert_eq!(keys.auth, from_password);
    }

    #[test]
    fn rejects_a_short_secret() {
        assert!(FileKeys::derive(&[0u8; SECRET_LEN - 1]).is_err());
    }
}
