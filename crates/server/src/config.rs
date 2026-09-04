//! Runtime configuration. Every knob is available as both a CLI flag and an
//! environment variable, so the same binary is convenient locally and in a pod.

use anyhow::Context as _;
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
    /// The mode's name, as it appears in configuration and `/api/info`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Upload => "upload",
            Self::All => "all",
        }
    }

    /// Whether any route requires a signed-in user.
    #[must_use]
    pub fn enabled(self) -> bool {
        self != Self::Off
    }
}

#[derive(Debug, Clone, Parser)]
#[command(name = "senders", about = "End-to-end encrypted file sharing", version)]
/// Everything the server reads at startup.
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
    /// OIDC client identifier.
    pub oidc_client_id: Option<String>,

    #[arg(long, env = "SENDERS_OIDC_CLIENT_SECRET", hide_env_values = true)]
    /// OIDC client secret, for confidential clients.
    pub oidc_client_secret: Option<String>,

    /// File holding the OIDC client secret, read at startup.
    ///
    /// Preferred over the inline form wherever a secrets manager delivers
    /// material as a mounted file: the value never appears in the pod spec,
    /// the process environment, or `/proc/<pid>/environ`.
    #[arg(
        long,
        env = "SENDERS_OIDC_CLIENT_SECRET_FILE",
        conflicts_with = "oidc_client_secret"
    )]
    pub oidc_client_secret_file: Option<PathBuf>,

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

    /// File holding the session signing key, read at startup.
    ///
    /// Same reasoning as `--oidc-client-secret-file`.
    #[arg(
        long,
        env = "SENDERS_SESSION_SECRET_FILE",
        conflicts_with = "session_secret"
    )]
    pub session_secret_file: Option<PathBuf>,

    /// Session lifetime, in seconds.
    #[arg(long, env = "SENDERS_SESSION_TTL", default_value_t = 12 * 60 * 60)]
    pub session_ttl: u64,

    /// Drop the `Secure` attribute on cookies, for plain-HTTP local testing.
    #[arg(long, env = "SENDERS_COOKIE_INSECURE", default_value_t = false)]
    pub cookie_insecure: bool,

    /// Probe a already-running instance's `/healthz` and exit 0 or 1 instead of
    /// serving.
    ///
    /// This exists so the container image can declare a HEALTHCHECK: it runs on
    /// distroless, which has no shell, no curl and no wget, so the binary has
    /// to be able to check itself.
    #[arg(long, default_value_t = false)]
    pub healthcheck: bool,
}

/// The address a health probe should connect to, given a listen address.
///
/// A server bound to the wildcard address is not reachable *at* it on every
/// platform, so probes go to loopback on the same port.
#[must_use]
pub fn probe_address(bind: SocketAddr) -> SocketAddr {
    if bind.ip().is_unspecified() {
        match bind {
            SocketAddr::V4(_) => SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, bind.port())),
            SocketAddr::V6(_) => SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, bind.port())),
        }
    } else {
        bind
    }
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
    #[must_use]
    pub fn clamp_expiry(&self, requested: Option<u64>) -> u64 {
        let max = self.max_expiry.clamp(MIN_EXPIRY_SECS, MAX_EXPIRY_SECS);
        requested
            .unwrap_or(self.default_expiry)
            .clamp(MIN_EXPIRY_SECS, max)
    }

    /// Clamp a requested download budget into the configured window.
    #[must_use]
    pub fn clamp_downloads(&self, requested: Option<u32>) -> u32 {
        let max = self.max_downloads.clamp(1, MAX_DOWNLOADS);
        requested.unwrap_or(DEFAULT_MAX_DOWNLOADS).clamp(1, max)
    }

    /// The longest lifetime this server will actually grant.
    #[must_use]
    pub fn effective_max_expiry(&self) -> u64 {
        self.max_expiry.clamp(MIN_EXPIRY_SECS, MAX_EXPIRY_SECS)
    }

    /// The largest download budget this server will actually grant.
    #[must_use]
    pub fn effective_max_downloads(&self) -> u32 {
        self.max_downloads.clamp(1, MAX_DOWNLOADS)
    }

    /// The OIDC redirect URI, derived from the public URL.
    #[must_use]
    pub fn redirect_uri(&self) -> String {
        format!("{}/auth/callback", self.public_url.trim_end_matches('/'))
    }

    /// The email-domain allow-list, lowercased and split.
    #[must_use]
    pub fn allowed_domains(&self) -> Vec<String> {
        self.oidc_allowed_domains
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect()
    }

    /// Read every `--*-secret-file` into its inline counterpart.
    ///
    /// Called once at startup, before anything looks at the secrets. Reading
    /// them here rather than at each use keeps the rest of the server unaware
    /// that a file was involved, and turns an unreadable mount into a clean
    /// failure to start instead of a request-time error.
    ///
    /// A trailing newline is stripped: `echo`, `openssl rand -base64` and most
    /// secret managers add one, and a signing key that differs by a newline
    /// fails in a way that looks like a wrong key rather than a formatting
    /// mistake. An otherwise empty file is an error for the same reason — it
    /// is a mount that has not been populated, not a deliberate empty secret.
    pub fn load_secret_files(&mut self) -> anyhow::Result<()> {
        for (target, path) in [
            (&mut self.oidc_client_secret, &self.oidc_client_secret_file),
            (&mut self.session_secret, &self.session_secret_file),
        ] {
            let Some(path) = path else { continue };
            let value = std::fs::read_to_string(path)
                .with_context(|| format!("reading the secret file {}", path.display()))?;
            let value = value.trim_end_matches(['\n', '\r']);
            anyhow::ensure!(
                !value.is_empty(),
                "the secret file {} is empty",
                path.display()
            );
            *target = Some(value.to_owned());
        }
        Ok(())
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
    fn health_probes_target_loopback_when_bound_to_the_wildcard() {
        let parse = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert_eq!(
            probe_address(parse("0.0.0.0:8080")),
            parse("127.0.0.1:8080")
        );
        assert_eq!(probe_address(parse("[::]:8080")), parse("[::1]:8080"));
        // An explicit address is already reachable and must be left alone.
        assert_eq!(
            probe_address(parse("10.1.2.3:9000")),
            parse("10.1.2.3:9000")
        );
        assert_eq!(
            probe_address(parse("127.0.0.1:1234")),
            parse("127.0.0.1:1234")
        );
    }

    #[test]
    fn secret_files_are_read_and_their_trailing_newline_stripped() {
        let dir = std::env::temp_dir().join("senders-secret-file-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session-secret");
        // The trailing newline is what `openssl rand -base64 32 > file` and
        // most secret managers write.
        std::fs::write(&path, "s3cret\n").unwrap();

        let mut cfg = Config::parse_from([
            "senders",
            "--session-secret-file",
            &path.display().to_string(),
        ]);
        assert_eq!(cfg.session_secret, None, "not read until load_secret_files");
        cfg.load_secret_files().unwrap();
        assert_eq!(cfg.session_secret.as_deref(), Some("s3cret"));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn an_empty_secret_file_is_an_unpopulated_mount_not_an_empty_secret() {
        let dir = std::env::temp_dir().join("senders-secret-file-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty-secret");
        std::fs::write(&path, "\n").unwrap();

        let mut cfg = Config::parse_from([
            "senders",
            "--session-secret-file",
            &path.display().to_string(),
        ]);
        assert!(cfg.load_secret_files().is_err());

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_missing_secret_file_fails_to_start_rather_than_serving_without_it() {
        let mut cfg = Config::parse_from([
            "senders",
            "--oidc-client-secret-file",
            "/nonexistent/senders/client-secret",
        ]);
        assert!(cfg.load_secret_files().is_err());
    }

    #[test]
    fn the_inline_and_file_forms_of_a_secret_are_mutually_exclusive() {
        assert!(
            Config::try_parse_from([
                "senders",
                "--session-secret",
                "inline",
                "--session-secret-file",
                "/tmp/whatever",
            ])
            .is_err()
        );
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
