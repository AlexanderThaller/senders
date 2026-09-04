//! Library crate behind the `senders-cli` binary.
//!
//! Split from `main.rs` so the pieces underneath a command — crypto, the API
//! client, and the encrypt/decrypt pipelines — carry unit tests that do not
//! need a running server. See `crates/web/src/{crypto,api,transfer}.rs`: this
//! is the same scheme against a filesystem and `reqwest` instead of a browser.

pub mod api;
pub mod cli;
pub mod commands;
pub mod crypto;
pub mod transfer;
