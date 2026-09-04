//! Framing for the STREAM construction described in the crate root docs:
//! nonce layout and record counting. Pure byte/number arithmetic — no key
//! material passes through here, only public lengths and counters, which is
//! why it is safe for this to be the one implementation every client
//! (`crates/web`, `crates/cli`) derives its record loop from.

use crate::{CHUNK_CIPHERTEXT_SIZE, CHUNK_SIZE, NONCE_LEN, NONCE_PREFIX_LEN};

/// The STREAM nonce for record `counter`:
/// `random_prefix(7) || counter_be32(4) || final_flag(1)`.
#[must_use]
pub fn record_nonce(prefix: &[u8], counter: u32, final_record: bool) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..NONCE_PREFIX_LEN + 4].copy_from_slice(&counter.to_be_bytes());
    nonce[NONCE_LEN - 1] = u8::from(final_record);
    nonce
}

/// The STREAM counter for record `index`.
///
/// The counter is 32 bits, which at 64 KiB records caps a file at 256 TiB —
/// far beyond any size a server will accept — so this cannot be reached in
/// practice.
#[must_use]
pub fn record_index(index: u64) -> u32 {
    u32::try_from(index).expect("record counts are bounded by the maximum file size")
}

/// `len` divided into `chunk`-sized records, rounding up. An empty body still
/// gets one (empty) record, so "zero bytes" is a fact a peer can verify
/// rather than assume.
fn record_count(len: u64, chunk: u64) -> u64 {
    if len == 0 { 1 } else { len.div_ceil(chunk) }
}

/// How many plaintext records a body of `size` bytes seals into.
#[must_use]
pub fn plain_record_count(size: u64) -> u32 {
    u32::try_from(record_count(size, CHUNK_SIZE as u64))
        .expect("record counts are bounded by the maximum file size")
}

/// How many ciphertext records make up a body of `cipher_len` bytes.
#[must_use]
pub fn cipher_record_count(cipher_len: u64) -> u64 {
    record_count(cipher_len, CHUNK_CIPHERTEXT_SIZE as u64)
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

    #[test]
    fn record_counts_cover_the_boundaries() {
        assert_eq!(plain_record_count(0), 1);
        assert_eq!(plain_record_count(1), 1);
        assert_eq!(plain_record_count(CHUNK_SIZE as u64), 1);
        assert_eq!(plain_record_count(CHUNK_SIZE as u64 + 1), 2);

        assert_eq!(cipher_record_count(0), 1);
        assert_eq!(cipher_record_count(1), 1);
        assert_eq!(cipher_record_count(CHUNK_CIPHERTEXT_SIZE as u64), 1);
        assert_eq!(cipher_record_count(CHUNK_CIPHERTEXT_SIZE as u64 + 1), 2);
        assert_eq!(cipher_record_count(2 * CHUNK_CIPHERTEXT_SIZE as u64), 2);
    }
}
