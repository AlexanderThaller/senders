//! Full client-side pipeline: a real `File` in, ciphertext out, and back again
//! through the same re-framing the network path uses.

use js_sys::{Array, Uint8Array};
use senders_proto::{CHUNK_SIZE, FileMetadata, b64};
use senders_web::crypto::FileKeys;
use senders_web::transfer;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;
use web_sys::{Blob, File};

fn make_file(bytes: &[u8], name: &str, mime: &str) -> File {
    let parts = Array::new();
    parts.push(&Uint8Array::from(bytes));
    let options = web_sys::FilePropertyBag::new();
    options.set_type(mime);
    File::new_with_u8_array_sequence_and_options(&parts, name, &options).expect("File")
}

async fn blob_bytes(blob: &Blob) -> Vec<u8> {
    let buffer = JsFuture::from(blob.array_buffer())
        .await
        .expect("array buffer");
    Uint8Array::new(&buffer).to_vec()
}

/// Feed ciphertext back in fixed-size pieces, imitating network chunking that
/// does not line up with record boundaries.
fn chunked(
    bytes: Vec<u8>,
    chunk: usize,
) -> impl futures_util::Stream<Item = Result<Vec<u8>, senders_web::api::ApiError>> {
    let pieces: Vec<Vec<u8>> = bytes.chunks(chunk.max(1)).map(<[u8]>::to_vec).collect();
    futures_util::stream::iter(pieces.into_iter().map(Ok))
}

async fn round_trip(payload: &[u8], network_chunk: usize) {
    let file = make_file(payload, "report.bin", "application/octet-stream");
    let sealed = transfer::seal_file(&file, |_| {}).await.expect("seal");

    let ciphertext = blob_bytes(&sealed.blob).await;
    assert_eq!(
        ciphertext.len() as u64,
        senders_proto::ciphertext_len(payload.len() as u64),
        "ciphertext length must match what the server-side helper predicts"
    );
    assert_ne!(
        ciphertext, payload,
        "the blob handed to the server must not be the plaintext"
    );

    // Re-derive from the fragment secret, exactly as the download page does.
    let keys = FileKeys::derive(&sealed.secret).await.expect("derive");

    let recovered = transfer::open_stream(
        &keys,
        &sealed.nonce_prefix,
        ciphertext.len() as u64,
        "application/octet-stream",
        chunked(ciphertext, network_chunk),
        |_| {},
    )
    .await
    .expect("open");

    assert_eq!(
        blob_bytes(&recovered).await,
        payload,
        "round trip must be byte-exact"
    );
}

#[wasm_bindgen_test]
async fn a_small_file_round_trips() {
    round_trip(b"the quick brown fox", 8192).await;
}

#[wasm_bindgen_test]
async fn an_empty_file_round_trips() {
    round_trip(b"", 8192).await;
}

#[wasm_bindgen_test]
async fn a_file_spanning_several_records_round_trips() {
    let payload: Vec<u8> = (0..CHUNK_SIZE * 3 + 1234)
        .map(|i| (i % 253) as u8)
        .collect();
    round_trip(&payload, 64 * 1024).await;
}

#[wasm_bindgen_test]
async fn a_file_that_is_an_exact_multiple_of_the_record_size_round_trips() {
    // The boundary case: the final record is full, so a naive framing would
    // decrypt it with the wrong final-flag.
    let payload: Vec<u8> = (0..CHUNK_SIZE * 2).map(|i| (i % 251) as u8).collect();
    round_trip(&payload, 32 * 1024).await;
}

#[wasm_bindgen_test]
async fn network_chunking_never_affects_the_result() {
    let payload: Vec<u8> = (0..CHUNK_SIZE + 777).map(|i| (i % 249) as u8).collect();
    // Awkward sizes: smaller than a record, prime-ish, and larger than a record.
    for chunk in [1, 7, 1023, CHUNK_SIZE - 1, CHUNK_SIZE + 17, 1_000_000] {
        round_trip(&payload, chunk).await;
    }
}

#[wasm_bindgen_test]
async fn a_truncated_download_is_rejected_rather_than_returned_partial() {
    let payload: Vec<u8> = (0..CHUNK_SIZE * 2 + 500).map(|i| (i % 247) as u8).collect();
    let file = make_file(&payload, "big.bin", "application/octet-stream");
    let sealed = transfer::seal_file(&file, |_| {}).await.expect("seal");
    let keys = FileKeys::derive(&sealed.secret).await.expect("derive");

    let mut ciphertext = blob_bytes(&sealed.blob).await;
    let full_len = ciphertext.len() as u64;
    ciphertext.truncate(ciphertext.len() - 4_000);

    let result = transfer::open_stream(
        &keys,
        &sealed.nonce_prefix,
        full_len,
        "application/octet-stream",
        chunked(ciphertext, 8192),
        |_| {},
    )
    .await;
    assert!(
        result.is_err(),
        "a short download must fail loudly, not yield a partial file"
    );
}

#[wasm_bindgen_test]
async fn the_metadata_blob_hides_the_filename_and_recovers_it() {
    let file = make_file(b"payload", "salary-review-2026.pdf", "application/pdf");
    let sealed = transfer::seal_file(&file, |_| {}).await.expect("seal");

    assert!(
        !sealed.metadata.contains("salary"),
        "the filename must not be readable in the blob sent to the server"
    );

    let keys = FileKeys::derive(&sealed.secret).await.expect("derive");
    let raw = b64::decode(&sealed.metadata).expect("base64url");
    let opened = keys.open_metadata(&raw).await.expect("open metadata");
    let decoded: FileMetadata = serde_json::from_slice(&opened).expect("json");

    assert_eq!(decoded.name, "salary-review-2026.pdf");
    assert_eq!(decoded.mime, "application/pdf");
    assert_eq!(decoded.size, 7);
}

#[wasm_bindgen_test]
async fn every_upload_uses_a_fresh_secret_and_nonce_prefix() {
    let file = make_file(b"same bytes every time", "a.bin", "text/plain");
    let first = transfer::seal_file(&file, |_| {}).await.expect("seal");
    let second = transfer::seal_file(&file, |_| {}).await.expect("seal");

    assert_ne!(first.secret, second.secret);
    assert_ne!(first.nonce_prefix, second.nonce_prefix);
    // Identical plaintext must not produce identical ciphertext.
    assert_ne!(
        blob_bytes(&first.blob).await,
        blob_bytes(&second.blob).await
    );
}

#[wasm_bindgen_test]
async fn share_links_keep_the_key_in_the_fragment() {
    let file = make_file(b"x", "a.bin", "text/plain");
    let sealed = transfer::seal_file(&file, |_| {}).await.expect("seal");
    let url = transfer::share_url(
        "https://send.example",
        "abcdefghijklmnopqrstuv",
        &sealed.secret,
    );

    let (path, fragment) = url.split_once('#').expect("a fragment");
    assert!(
        !path.contains(&b64::encode(&sealed.secret)),
        "the key must not be in the path or query"
    );
    assert_eq!(b64::decode(fragment).unwrap(), sealed.secret);
}
