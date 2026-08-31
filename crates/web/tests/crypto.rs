//! Tests for the real `WebCrypto` code path, run against the compiled wasm.
//!
//! These are the tests that matter most: if record framing or key separation
//! is wrong, the server-side tests would still pass while every file shipped
//! would be unrecoverable or forgeable.

#![expect(
    clippy::unwrap_used,
    reason = "these are tests; #[wasm_bindgen_test] does not expand to #[test], so allow-unwrap-in-tests cannot see that"
)]
#![expect(
    clippy::cast_possible_truncation,
    reason = "test fixtures build byte patterns from indices"
)]

use senders_proto::{CHUNK_SIZE, NONCE_PREFIX_LEN, SECRET_LEN};
use senders_web::crypto::{self, FileKeys};
use wasm_bindgen_test::wasm_bindgen_test;

fn secret(byte: u8) -> Vec<u8> {
    vec![byte; SECRET_LEN]
}

fn prefix() -> Vec<u8> {
    vec![0xA5; NONCE_PREFIX_LEN]
}

#[wasm_bindgen_test]
async fn the_csprng_produces_distinct_values_of_the_right_length() {
    let a = crypto::random_bytes(SECRET_LEN).unwrap();
    let b = crypto::random_bytes(SECRET_LEN).unwrap();
    assert_eq!(a.len(), SECRET_LEN);
    assert_ne!(a, b, "two draws must not collide");
    assert!(
        a.iter().any(|byte| *byte != 0),
        "the buffer must actually be filled"
    );
}

#[wasm_bindgen_test]
async fn key_derivation_is_deterministic_and_separates_labels() {
    let first = FileKeys::derive(&secret(1)).await.unwrap();
    let again = FileKeys::derive(&secret(1)).await.unwrap();
    let other = FileKeys::derive(&secret(2)).await.unwrap();

    assert_eq!(
        first.auth, again.auth,
        "the same secret must give the same auth key"
    );
    assert_ne!(
        first.auth, other.auth,
        "a different secret must give a different auth key"
    );

    // The auth key is handed to the server as a capability, so it must not be
    // usable to decrypt anything: it has to differ from the content key.
    let sealed = first
        .seal_record(&prefix(), 0, true, b"payload")
        .await
        .unwrap();
    let forged = FileKeys::derive(&first.auth).await.unwrap();
    assert!(
        forged
            .open_record(&prefix(), 0, true, &sealed)
            .await
            .is_err(),
        "the auth key must not double as the content key"
    );
}

#[wasm_bindgen_test]
async fn a_record_round_trips_byte_for_byte() {
    let keys = FileKeys::derive(&secret(3)).await.unwrap();
    let plaintext: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i % 251) as u8).collect();

    let sealed = keys
        .seal_record(&prefix(), 0, false, &plaintext)
        .await
        .unwrap();
    assert_eq!(
        sealed.len(),
        plaintext.len() + 16,
        "each record carries a 16-byte tag"
    );

    let opened = keys
        .open_record(&prefix(), 0, false, &sealed)
        .await
        .unwrap();
    assert_eq!(opened, plaintext);
}

#[wasm_bindgen_test]
async fn an_empty_file_still_produces_an_authenticated_record() {
    let keys = FileKeys::derive(&secret(4)).await.unwrap();
    let sealed = keys.seal_record(&prefix(), 0, true, b"").await.unwrap();
    assert_eq!(sealed.len(), 16, "an empty record is just its tag");
    assert_eq!(
        keys.open_record(&prefix(), 0, true, &sealed).await.unwrap(),
        Vec::<u8>::new()
    );
}

#[wasm_bindgen_test]
async fn tampering_with_ciphertext_is_detected() {
    let keys = FileKeys::derive(&secret(5)).await.unwrap();
    let mut sealed = keys
        .seal_record(&prefix(), 0, true, b"transfer 100 EUR")
        .await
        .unwrap();

    sealed[3] ^= 0x01;
    assert!(
        keys.open_record(&prefix(), 0, true, &sealed).await.is_err(),
        "a flipped ciphertext bit must fail authentication"
    );

    sealed[3] ^= 0x01;
    let last = sealed.len() - 1;
    sealed[last] ^= 0x80;
    assert!(
        keys.open_record(&prefix(), 0, true, &sealed).await.is_err(),
        "a flipped tag bit must fail authentication"
    );
}

#[wasm_bindgen_test]
async fn records_cannot_be_reordered_or_replayed() {
    let keys = FileKeys::derive(&secret(6)).await.unwrap();
    let first = keys
        .seal_record(&prefix(), 0, false, b"alpha")
        .await
        .unwrap();

    assert!(
        keys.open_record(&prefix(), 1, false, &first).await.is_err(),
        "a record must not decrypt at another position"
    );
    assert!(
        keys.open_record(&[0x11; NONCE_PREFIX_LEN], 0, false, &first)
            .await
            .is_err(),
        "a record from another file must not decrypt here"
    );
}

#[wasm_bindgen_test]
async fn truncating_a_file_is_detected_by_the_final_flag() {
    let keys = FileKeys::derive(&secret(7)).await.unwrap();
    // Two records; the attacker drops the second and presents the first as the
    // whole file. Without the final-flag in the nonce this would succeed.
    let head = keys
        .seal_record(&prefix(), 0, false, b"first half")
        .await
        .unwrap();
    assert!(
        keys.open_record(&prefix(), 0, true, &head).await.is_err(),
        "a non-final record must not open as a final one"
    );

    let tail = keys
        .seal_record(&prefix(), 1, true, b"second half")
        .await
        .unwrap();
    assert!(
        keys.open_record(&prefix(), 1, false, &tail).await.is_err(),
        "a final record must not open as a non-final one"
    );
}

#[wasm_bindgen_test]
async fn a_wrong_secret_cannot_open_anything() {
    let mine = FileKeys::derive(&secret(8)).await.unwrap();
    let theirs = FileKeys::derive(&secret(9)).await.unwrap();
    let sealed = mine
        .seal_record(&prefix(), 0, true, b"private")
        .await
        .unwrap();
    assert!(
        theirs
            .open_record(&prefix(), 0, true, &sealed)
            .await
            .is_err()
    );
}

#[wasm_bindgen_test]
async fn metadata_round_trips_and_is_nonce_prefixed() {
    let keys = FileKeys::derive(&secret(10)).await.unwrap();
    let plaintext = br#"{"name":"contract.pdf","mime":"application/pdf","size":42}"#;

    let sealed = keys.seal_metadata(plaintext).await.unwrap();
    assert_eq!(
        sealed.len(),
        12 + plaintext.len() + 16,
        "nonce + ciphertext + tag"
    );

    // Sealing twice must not repeat a nonce, or the two blobs would leak their xor.
    let again = keys.seal_metadata(plaintext).await.unwrap();
    assert_ne!(
        sealed[..12],
        again[..12],
        "each seal must draw a fresh nonce"
    );

    assert_eq!(
        keys.open_metadata(&sealed).await.unwrap(),
        plaintext.to_vec()
    );
    assert!(
        keys.open_metadata(&sealed[..20]).await.is_err(),
        "truncated metadata must be rejected"
    );
}

#[wasm_bindgen_test]
async fn the_auth_hash_is_a_sha256_digest_of_the_auth_key() {
    let keys = FileKeys::derive(&secret(11)).await.unwrap();
    let hash = keys.auth_hash().await.unwrap();
    assert_eq!(hash.len(), 32);
    assert_eq!(hash, crypto::sha256(&keys.auth).await.unwrap());
    assert_ne!(
        hash, keys.auth,
        "the server must never receive the key itself"
    );
}

#[wasm_bindgen_test]
async fn password_derivation_depends_on_both_password_and_salt() {
    let salt_a = vec![1u8; 16];
    let salt_b = vec![2u8; 16];

    let base = crypto::pbkdf2("hunter2", &salt_a, 1_000).await.unwrap();
    assert_eq!(base.len(), 32);
    assert_eq!(
        base,
        crypto::pbkdf2("hunter2", &salt_a, 1_000).await.unwrap()
    );
    assert_ne!(
        base,
        crypto::pbkdf2("hunter3", &salt_a, 1_000).await.unwrap()
    );
    assert_ne!(
        base,
        crypto::pbkdf2("hunter2", &salt_b, 1_000).await.unwrap()
    );
    assert_ne!(
        base,
        crypto::pbkdf2("hunter2", &salt_a, 2_000).await.unwrap()
    );
}

#[wasm_bindgen_test]
async fn a_multi_record_file_reassembles_in_order() {
    let keys = FileKeys::derive(&secret(12)).await.unwrap();
    let records: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 1024]).collect();

    let mut sealed = Vec::new();
    for (index, plaintext) in records.iter().enumerate() {
        let last = index == records.len() - 1;
        sealed.push(
            keys.seal_record(&prefix(), index as u32, last, plaintext)
                .await
                .unwrap(),
        );
    }

    let mut recovered = Vec::new();
    for (index, ciphertext) in sealed.iter().enumerate() {
        let last = index == sealed.len() - 1;
        recovered.push(
            keys.open_record(&prefix(), index as u32, last, ciphertext)
                .await
                .unwrap(),
        );
    }
    assert_eq!(recovered, records);
}

#[wasm_bindgen_test]
async fn generated_passphrases_are_strong_and_unambiguous() {
    let first = crypto::generate_passphrase().unwrap();
    let second = crypto::generate_passphrase().unwrap();

    assert_ne!(first, second, "each passphrase must be freshly drawn");
    assert_eq!(
        first.len(),
        5 * 4 + 4,
        "five groups of four, hyphen separated"
    );
    assert_eq!(first.matches('-').count(), 4);

    // Ambiguous glyphs must not appear: these get mistranscribed over a phone.
    for confusable in ['I', 'L', 'O', 'U'] {
        assert!(!first.contains(confusable), "{first} contains {confusable}");
    }
    for symbol in first.chars().filter(|c| *c != '-') {
        assert!(
            symbol.is_ascii_digit() || symbol.is_ascii_uppercase(),
            "unexpected symbol {symbol} in {first}"
        );
    }

    // A crude but real check that the generator is not stuck: 200 draws of 20
    // symbols should touch most of a 32-symbol alphabet.
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..200 {
        seen.extend(
            crypto::generate_passphrase()
                .unwrap()
                .chars()
                .filter(|c| *c != '-'),
        );
    }
    assert!(seen.len() > 28, "alphabet coverage was only {}", seen.len());
}
