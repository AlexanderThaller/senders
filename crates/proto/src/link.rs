//! The share-link format: `<origin>/d/<id>#<secret>`. The secret travels in
//! the URL fragment, which browsers never send to a server.
//!
//! This only encodes and decodes the secret as an opaque, already-random byte
//! string — the same thing [`b64`](crate::b64) already does for every other
//! binary value on the wire. Nothing here derives or inspects key material.

use crate::{SECRET_LEN, b64};

/// Build a share link.
#[must_use]
pub fn share_url(origin: &str, id: &str, secret: &[u8]) -> String {
    format!(
        "{}/d/{id}#{}",
        origin.trim_end_matches('/'),
        b64::encode(secret)
    )
}

/// Decode a fragment into a secret, or `None` if it is malformed or the
/// wrong length.
#[must_use]
pub fn decode_secret(fragment: &str) -> Option<Vec<u8>> {
    let secret = b64::decode(fragment)?;
    (secret.len() == SECRET_LEN).then_some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_urls_put_the_secret_in_the_fragment() {
        let url = share_url("https://send.example/", "abc", &[0u8; SECRET_LEN]);
        let (base, fragment) = url.split_once('#').expect("share URLs carry a fragment");
        assert_eq!(base, "https://send.example/d/abc");
        assert_eq!(decode_secret(fragment), Some(vec![0u8; SECRET_LEN]));
    }

    #[test]
    fn rejects_a_malformed_or_short_secret() {
        assert_eq!(decode_secret("not-base64!!"), None);
        assert_eq!(decode_secret(&b64::encode([0u8; SECRET_LEN - 1])), None);
    }
}
