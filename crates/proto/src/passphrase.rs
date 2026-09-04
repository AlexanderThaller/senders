//! Formatting for generated passphrases. Callers supply the randomness (the
//! CSPRNG differs by platform — `WebCrypto` in the browser, the OS RNG on the
//! CLI); this only lays the bytes out for a human to read or dictate.

/// Crockford base32: no `I`, `L`, `O` or `U`, so a passphrase read aloud or
/// copied by hand does not turn into a different passphrase.
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Symbols per group, e.g. `NT80` in `NT80-CFH7-ECZF-XCVJ-4E1X`.
const PER_GROUP: usize = 4;

/// Random bytes a passphrase is generated from — 5 groups of 4 symbols is 100
/// bits of entropy, far beyond anything a person would invent, and still
/// short enough to dictate over the phone.
pub const BYTES: usize = 20;

/// Format `bytes` as a passphrase, grouped for reading aloud.
///
/// # Panics
///
/// Panics if `bytes.len() != `[`BYTES`].
#[must_use]
pub fn format(bytes: &[u8]) -> String {
    assert_eq!(bytes.len(), BYTES, "a passphrase needs exactly BYTES bytes");
    let mut out = String::with_capacity(BYTES + BYTES / PER_GROUP - 1);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 && index % PER_GROUP == 0 {
            out.push('-');
        }
        // The alphabet is exactly 32 symbols, so masking the low 5 bits is a
        // uniform choice — no modulo bias.
        out.push(ALPHABET[(byte & 0x1F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_five_groups_of_four() {
        let passphrase = format(&[0u8; BYTES]);
        let groups: Vec<&str> = passphrase.split('-').collect();
        assert_eq!(groups.len(), 5);
        assert!(groups.iter().all(|group| group.len() == PER_GROUP));
        assert!(
            passphrase
                .chars()
                .all(|c| c == '-' || ALPHABET.contains(&(c as u8)))
        );
    }

    #[test]
    #[should_panic(expected = "a passphrase needs exactly BYTES bytes")]
    fn rejects_the_wrong_input_length() {
        let _ = format(&[0u8; BYTES - 1]);
    }
}
