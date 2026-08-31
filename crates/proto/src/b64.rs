//! base64url (unpadded) helpers — the encoding used for every binary value
//! that travels in a URL, header, or JSON field.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.as_bytes()).ok()
}

/// Decode exactly `N` bytes, rejecting anything longer or shorter.
pub fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = decode(s)?;
    v.try_into().ok()
}
