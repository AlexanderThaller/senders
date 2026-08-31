//! Runtime configuration. Every knob is available as both a CLI flag and an
//! environment variable, so the same binary is convenient locally and in a pod.

use clap::{Parser, ValueEnum};
use senders_proto::{
    DEFAULT_EXPIRY_SECS, DEFAULT_MAX_DOWNLOADS, MAX_DOWNLOADS, MAX_EXPIRY_SECS, MIN_EXPIRY_SECS,
};
use std::net::SocketAddr;
use std::path::PathBuf;

/// How much of the service sits behind OIDC login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum AuthMode {
    /// Anyone may upload and download.
    Off,
    /// Uploading requires a login; share links stay publicly downloadable.
    Upload,
    /// Every API route requires a login — the service is fully hidden.
    All,
}

impl AuthMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Upload => "upload",
            Self::All => "all",
        }
    }

    pub fn enabled(self) -> bool {
        self != Self::Off
    }
}

#[derive(Debug, Clone, Parser)]
#[command(name = "senders", about = "End-to-end encrypted file sharing", version)]
pub struct Config {
    /// Address to listen on.
    #[arg(long, env = "SENDERS_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,

    /// Blob storage URI: `fs:<path>` or `s3://<bucket>[/<prefix>]`.
    #[arg(long, env = "SENDERS_STORAGE", default_value = "fs:./data/blobs")]
    pub storage: String,

    /// Metadata store URI: `redis://…` or `memory:`.
    #[arg(long, env = "SENDERS_METADATA", default_value = "memory:")]
    pub metadata: String,

    /// Directory holding the built frontend (trunk's `dist`).
    #[arg(long, env = "SENDERS_STATIC_DIR", default_value = "./dist")]
    pub static_dir: PathBuf,

    /// Largest accepted ciphertext, in bytes.
    #[arg(long, env = "SENDERS_MAX_FILE_SIZE", default_value_t = 2 * 1024 * 1024 * 1024)]
    pub max_file_size: u64,

    /// Expiry offered when the client does not ask for one, in seconds.
    #[arg(long, env = "SENDERS_DEFAULT_EXPIRY", default_value_t = DEFAULT_EXPIRY_SECS)]
    pub default_expiry: u64,

    /// Longest expiry a client may request, in seconds (capped at 30 days).
    #[arg(long, env = "SENDERS_MAX_EXPIRY", default_value_t = MAX_EXPIRY_SECS)]
    pub max_expiry: u64,

    /// Largest download budget a client may request.
    #[arg(long, env = "SENDERS_MAX_DOWNLOADS", default_value_t = MAX_DOWNLOADS)]
    pub max_downloads: u32,

    /// Seconds between sweeps for expired files.
    #[arg(long, env = "SENDERS_REAP_INTERVAL", default_value_t = 60)]
    pub reap_interval: u64,

    /// Public origin of this service; used to build OIDC redirect URIs.
    #[arg(
        long,
        env = "SENDERS_PUBLIC_URL",
        default_value = "http://localhost:8080"
    )]
    pub public_url: String,

    /// Which routes require an authenticated session.
    #[arg(long, env = "SENDERS_AUTH_MODE", default_value = "off")]
    pub auth_mode: AuthMode,

    /// OIDC issuer URL; discovery is done against `<issuer>/.well-known/openid-configuration`.
    #[arg(long, env = "SENDERS_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,

    #[arg(long, env = "SENDERS_OIDC_CLIENT_ID")]
    pub oidc_client_id: Option<String>,

    #[arg(long, env = "SENDERS_OIDC_CLIENT_SECRET", hide_env_values = true)]
    pub oidc_client_secret: Option<String>,

    /// Extra scopes to request, comma-separated. `openid` is always included.
    #[arg(long, env = "SENDERS_OIDC_SCOPES", default_value = "email,profile")]
    pub oidc_scopes: String,

    /// If set, only these comma-separated email domains may sign in.
    #[arg(long, env = "SENDERS_OIDC_ALLOWED_DOMAINS")]
    pub oidc_allowed_domains: Option<String>,

    /// Key used to sign session cookies. Generated at startup if unset, which
    /// invalidates sessions on restart and breaks multi-replica deployments.
    #[arg(long, env = "SENDERS_SESSION_SECRET", hide_env_values = true)]
    pub session_secret: Option<String>,

    /// Session lifetime, in seconds.
    #[arg(long, env = "SENDERS_SESSION_TTL", default_value_t = 12 * 60 * 60)]
    pub session_ttl: u64,

    /// Drop the `Secure` attribute on cookies, for plain-HTTP local testing.
    #[arg(long, env = "SENDERS_COOKIE_INSECURE", default_value_t = false)]
    pub cookie_insecure: bool,
}

impl Config {
    /// Build a config from an explicit argument list, as `main` would from the
    /// real command line. Useful for tests and for embedding the server.
    pub fn parse_from_args<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        Self::parse_from(args)
    }

    /// Clamp a requested expiry into the configured window.
    pub fn clamp_expiry(&self, requested: Option<u64>) -> u64 {
        let max = self.max_expiry.clamp(MIN_EXPIRY_SECS, MAX_EXPIRY_SECS);
        requested
            .unwrap_or(self.default_expiry)
            .clamp(MIN_EXPIRY_SECS, max)
    }

    /// Clamp a requested download budget into the configured window.
    pub fn clamp_downloads(&self, requested: Option<u32>) -> u32 {
        let max = self.max_downloads.clamp(1, MAX_DOWNLOADS);
        requested.unwrap_or(DEFAULT_MAX_DOWNLOADS).clamp(1, max)
    }

    pub fn effective_max_expiry(&self) -> u64 {
        self.max_expiry.clamp(MIN_EXPIRY_SECS, MAX_EXPIRY_SECS)
    }

    pub fn effective_max_downloads(&self) -> u32 {
        self.max_downloads.clamp(1, MAX_DOWNLOADS)
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}/auth/callback", self.public_url.trim_end_matches('/'))
    }

    pub fn allowed_domains(&self) -> Vec<String> {
        self.oidc_allowed_domains
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect()
    }

    /// Reject configurations that would silently do the wrong thing.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.auth_mode.enabled() {
            if !cfg!(feature = "oidc") {
                anyhow::bail!(
                    "--auth-mode {} needs a binary built with the `oidc` feature",
                    self.auth_mode.as_str()
                );
            }
            for (name, value) in [
                ("--oidc-issuer", &self.oidc_issuer),
                ("--oidc-client-id", &self.oidc_client_id),
            ] {
                if value.is_none() {
                    anyhow::bail!("--auth-mode {} requires {name}", self.auth_mode.as_str());
                }
            }
            if self.public_url.starts_with("http://localhost") && !self.cookie_insecure {
                tracing::warn!(
                    "public URL is plain HTTP but cookies are marked Secure; pass --cookie-insecure for local testing"
                );
            }
        }
        if self.default_expiry < MIN_EXPIRY_SECS
            || self.default_expiry > self.effective_max_expiry()
        {
            anyhow::bail!(
                "--default-expiry must be between {MIN_EXPIRY_SECS} and {} seconds",
                self.effective_max_expiry()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config::parse_from(["senders"])
    }

    #[test]
    fn expiry_is_clamped_to_one_to_thirty_days() {
        let cfg = config();
        assert_eq!(cfg.clamp_expiry(Some(0)), MIN_EXPIRY_SECS);
        assert_eq!(cfg.clamp_expiry(Some(u64::MAX)), MAX_EXPIRY_SECS);
        assert_eq!(cfg.clamp_expiry(None), DEFAULT_EXPIRY_SECS);
        assert_eq!(cfg.clamp_expiry(Some(7 * 24 * 3600)), 7 * 24 * 3600);
    }

    #[test]
    fn download_budget_is_clamped_and_defaults_to_burn_after_reading() {
        let cfg = config();
        assert_eq!(cfg.clamp_downloads(None), 1);
        assert_eq!(cfg.clamp_downloads(Some(0)), 1);
        assert_eq!(cfg.clamp_downloads(Some(u32::MAX)), MAX_DOWNLOADS);
    }

    #[test]
    fn auth_mode_requires_oidc_settings() {
        let mut cfg = config();
        cfg.auth_mode = AuthMode::Upload;
        assert!(cfg.validate().is_err());
        cfg.oidc_issuer = Some("https://idp.example".into());
        cfg.oidc_client_id = Some("senders".into());
        assert!(cfg.validate().is_ok());
    }
}
