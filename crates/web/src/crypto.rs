//! Client-side cryptography.
//!
//! Everything runs against the browser's WebCrypto implementation, so the
//! actual AES and SHA work happens in audited native code with hardware
//! acceleration. This module only arranges the calls.
//!
//! # Scheme
//!
//! A 32-byte `secret` is generated per upload and placed in the URL fragment,
//! which browsers never send to a server. Three independent keys are derived
//! from it with HKDF-SHA256 under distinct `info` labels:
//!
//! * content key  — AES-256-GCM over the file body
//! * metadata key — AES-256-GCM over the JSON filename/type blob
//! * auth key     — the bearer capability proving you may download
//!
//! The body is encrypted with the STREAM construction: the plaintext is split
//! into 64 KiB records, each sealed under the same key with the nonce
//! `prefix(7) || counter_be32 || final_flag`. Distinct counters keep nonces
//! unique; the final flag means a truncated file fails to authenticate instead
//! of silently decrypting to a prefix.
//!
//! When a password is set, the auth key comes from PBKDF2 over the password
//! instead, so knowing the URL is not enough to download.

use js_sys::{Object, Reflect, Uint8Array};
use senders_proto::{
    CHUNK_SIZE, INFO_AUTH, INFO_CONTENT, INFO_METADATA, KEY_LEN, NONCE_LEN, NONCE_PREFIX_LEN,
    SECRET_LEN, TAG_LEN,
};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{CryptoKey, SubtleCrypto};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<JsValue> for Error {
    fn from(value: JsValue) -> Self {
        Error(
            value
                .as_string()
                .or_else(|| js_sys::Error::from(value.clone()).message().as_string())
                .unwrap_or_else(|| format!("{value:?}")),
        )
    }
}

/// Reach WebCrypto through the global object rather than through `window`,
/// so this works in a page, in a worker, and under the test runner alike.
///
/// A missing `crypto` global almost always means an insecure context:
/// browsers only expose WebCrypto over HTTPS or on localhost.
fn crypto() -> Result<web_sys::Crypto> {
    let found = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))?;
    if found.is_undefined() || found.is_null() {
        return Err(Error(
            "WebCrypto is unavailable. This page must be served over HTTPS (or from localhost)."
                .into(),
        ));
    }
    Ok(found.unchecked_into())
}

fn subtle() -> Result<SubtleCrypto> {
    Ok(crypto()?.subtle())
}

/// `n` bytes from the browser CSPRNG.
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    crypto()?.get_random_values_with_u8_array(&mut buf)?;
    Ok(buf)
}

/// Crockford base32: no `I`, `L`, `O` or `U`, so a passphrase read aloud or
/// copied by hand does not turn into a different passphrase.
const PASSPHRASE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Generate a passphrase meant to be carried over a *different* channel than
/// the share link.
///
/// Five groups of four symbols is 100 bits of entropy — far beyond anything a
/// person would invent, and still short enough to dictate over the phone.
pub fn generate_passphrase() -> Result<String> {
    const GROUPS: usize = 5;
    const PER_GROUP: usize = 4;

    let bytes = random_bytes(GROUPS * PER_GROUP)?;
    let mut out = String::with_capacity(GROUPS * (PER_GROUP + 1) - 1);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 && index % PER_GROUP == 0 {
            out.push('-');
        }
        // The alphabet is exactly 32 symbols, so masking the low 5 bits is a
        // uniform choice — no modulo bias.
        out.push(PASSPHRASE_ALPHABET[(byte & 0x1F) as usize] as char);
    }
    Ok(out)
}

fn bytes_object(bytes: &[u8]) -> Object {
    Uint8Array::from(bytes).unchecked_into()
}

fn set(target: &Object, key: &str, value: impl Into<JsValue>) -> Result<()> {
    Reflect::set(target, &JsValue::from_str(key), &value.into())?;
    Ok(())
}

async fn resolve(promise: js_sys::Promise) -> Result<JsValue> {
    JsFuture::from(promise).await.map_err(Error::from)
}

async fn resolve_bytes(promise: js_sys::Promise) -> Result<Vec<u8>> {
    let buffer = resolve(promise).await?;
    Ok(Uint8Array::new(&buffer).to_vec())
}

fn usages(list: &[&str]) -> JsValue {
    let array = js_sys::Array::new();
    for usage in list {
        array.push(&JsValue::from_str(usage));
    }
    array.into()
}

/// SHA-256, used to turn the auth key into the digest the server stores.
pub async fn sha256(data: &[u8]) -> Result<Vec<u8>> {
    resolve_bytes(subtle()?.digest_with_str_and_u8_array("SHA-256", data)?).await
}

/// Derive `KEY_LEN` bytes from `secret` under an HKDF `info` label.
async fn hkdf(secret: &[u8], info: &[u8]) -> Result<Vec<u8>> {
    let subtle = subtle()?;
    let base = resolve(subtle.import_key_with_str(
        "raw",
        &bytes_object(secret),
        "HKDF",
        false,
        &usages(&["deriveBits"]),
    )?)
    .await?
    .unchecked_into::<CryptoKey>();

    let params = Object::new();
    set(&params, "name", "HKDF")?;
    set(&params, "hash", "SHA-256")?;
    // An empty salt is the RFC 5869 default; the secret is already uniformly
    // random, so the extract step has nothing to gain from one.
    set(&params, "salt", bytes_object(&[]))?;
    set(&params, "info", bytes_object(info))?;

    resolve_bytes(subtle.derive_bits_with_object(&params, &base, (KEY_LEN * 8) as u32)?).await
}

/// Derive an auth key from a password. Deliberately slow: this is the only
/// thing standing between a leaked link and the file.
pub async fn pbkdf2(password: &str, salt: &[u8], iterations: u32) -> Result<Vec<u8>> {
    let subtle = subtle()?;
    let base = resolve(subtle.import_key_with_str(
        "raw",
        &bytes_object(password.as_bytes()),
        "PBKDF2",
        false,
        &usages(&["deriveBits"]),
    )?)
    .await?
    .unchecked_into::<CryptoKey>();

    let params = Object::new();
    set(&params, "name", "PBKDF2")?;
    set(&params, "hash", "SHA-256")?;
    set(&params, "salt", bytes_object(salt))?;
    set(&params, "iterations", iterations)?;

    resolve_bytes(subtle.derive_bits_with_object(&params, &base, (KEY_LEN * 8) as u32)?).await
}

async fn import_aes(key: &[u8]) -> Result<CryptoKey> {
    let params = Object::new();
    set(&params, "name", "AES-GCM")?;
    Ok(resolve(subtle()?.import_key_with_object(
        "raw",
        &bytes_object(key),
        &params,
        false,
        &usages(&["encrypt", "decrypt"]),
    )?)
    .await?
    .unchecked_into())
}

fn gcm_params(nonce: &[u8]) -> Result<Object> {
    let params = Object::new();
    set(&params, "name", "AES-GCM")?;
    set(&params, "iv", bytes_object(nonce))?;
    set(&params, "tagLength", (TAG_LEN * 8) as u32)?;
    Ok(params)
}

/// The STREAM nonce for record `counter`.
fn record_nonce(prefix: &[u8], counter: u32, final_record: bool) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4].copy_from_slice(&counter.to_be_bytes());
    nonce[NONCE_LEN - 1] = u8::from(final_record);
    nonce
}

/// The three keys for one file, plus the auth key the server will check.
pub struct FileKeys {
    content: CryptoKey,
    metadata: CryptoKey,
    pub auth: Vec<u8>,
}

impl FileKeys {
    /// Derive everything from the URL-fragment secret.
    pub async fn derive(secret: &[u8]) -> Result<Self> {
        if secret.len() != SECRET_LEN {
            return Err(Error(format!("secret must be {SECRET_LEN} bytes")));
        }
        Ok(Self {
            content: import_aes(&hkdf(secret, INFO_CONTENT).await?).await?,
            metadata: import_aes(&hkdf(secret, INFO_METADATA).await?).await?,
            auth: hkdf(secret, INFO_AUTH).await?,
        })
    }

    /// Replace the URL-derived auth key with a password-derived one.
    pub fn with_auth(mut self, auth: Vec<u8>) -> Self {
        self.auth = auth;
        self
    }

    /// The value the server stores and compares against.
    pub async fn auth_hash(&self) -> Result<Vec<u8>> {
        sha256(&self.auth).await
    }

    /// Seal the metadata blob. Layout: `nonce(12) || ciphertext`.
    pub async fn seal_metadata(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = random_bytes(NONCE_LEN)?;
        let sealed = resolve_bytes(subtle()?.encrypt_with_object_and_u8_array(
            &gcm_params(&nonce)?,
            &self.metadata,
            plaintext,
        )?)
        .await?;
        let mut out = nonce;
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    pub async fn open_metadata(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return Err(Error("metadata is truncated".into()));
        }
        let (nonce, body) = sealed.split_at(NONCE_LEN);
        resolve_bytes(subtle()?.decrypt_with_object_and_u8_array(
            &gcm_params(nonce)?,
            &self.metadata,
            body,
        )?)
        .await
    }

    /// Seal one plaintext record of the body.
    pub async fn seal_record(
        &self,
        prefix: &[u8],
        counter: u32,
        last: bool,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        debug_assert!(plaintext.len() <= CHUNK_SIZE);
        resolve_bytes(subtle()?.encrypt_with_object_and_u8_array(
            &gcm_params(&record_nonce(prefix, counter, last))?,
            &self.content,
            plaintext,
        )?)
        .await
    }

    /// Open one ciphertext record. Fails if the record was reordered,
    /// truncated, tampered with, or came from a different file.
    pub async fn open_record(
        &self,
        prefix: &[u8],
        counter: u32,
        last: bool,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        resolve_bytes(subtle()?.decrypt_with_object_and_u8_array(
            &gcm_params(&record_nonce(prefix, counter, last))?,
            &self.content,
            ciphertext,
        )?)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_unique_per_record_and_mark_the_end() {
        let prefix = [1u8; NONCE_PREFIX_LEN];
        let first = record_nonce(&prefix, 0, false);
        let second = record_nonce(&prefix, 1, false);
        let last = record_nonce(&prefix, 1, true);

        assert_ne!(first, second, "counter must vary the nonce");
        assert_ne!(second, last, "the final flag must vary the nonce");
        assert_eq!(&first[..NONCE_PREFIX_LEN], &prefix);
        assert_eq!(
            &second[NONCE_PREFIX_LEN..NONCE_LEN - 1],
            &1u32.to_be_bytes()
        );
        assert_eq!(last[NONCE_LEN - 1], 1);
    }
}
