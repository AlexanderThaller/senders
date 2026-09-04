//! Subcommand implementations. Each mirrors one thing the web frontend does,
//! against a filesystem and `reqwest` instead of the browser.

pub mod download;
pub mod info;
pub mod upload;
