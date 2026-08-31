//! The `senders` binary: parses configuration, wires up storage and sessions,
//! and serves until told to stop.

use anyhow::Context as _;
use clap::Parser as _;
use senders_server::{build_state, config::Config, reaper, router};
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("SENDERS_LOG")
                .unwrap_or_else(|_| EnvFilter::new("info,tower_http=warn")),
        )
        .init();

    let config = Config::parse();
    if config.healthcheck {
        return healthcheck(senders_server::config::probe_address(config.bind)).await;
    }

    let bind = config.bind;
    let reap_interval = Duration::from_secs(config.reap_interval.max(5));
    tracing::info!(
        storage = %config.storage,
        metadata = %config.metadata,
        auth_mode = %config.auth_mode.as_str(),
        "starting senders"
    );

    let state = build_state(config).await?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let reaper_handle = tokio::spawn(reaper::run(state.clone(), reap_interval, shutdown_rx));

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    tracing::info!(address = %listener.local_addr()?, "listening");

    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serving")?;

    // Let the reaper finish its current sweep before the process exits.
    let _ = shutdown_tx.send(true);
    let _ = reaper_handle.await;
    Ok(())
}

/// Ask a running instance whether it is healthy, speaking just enough HTTP/1.0
/// to avoid pulling an HTTP client into the binary for this.
async fn healthcheck(address: std::net::SocketAddr) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let probe = async {
        let mut stream = tokio::net::TcpStream::connect(address).await?;
        stream
            .write_all(format!("GET /healthz HTTP/1.0\r\nHost: {address}\r\n\r\n").as_bytes())
            .await?;
        // The response is a status line plus "ok"; a small cap is plenty and
        // keeps a misbehaving server from stalling the probe on a huge body.
        let mut response = Vec::new();
        stream.take(4096).read_to_end(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };

    let response = tokio::time::timeout(Duration::from_secs(5), probe)
        .await
        .context("health probe timed out")?
        .with_context(|| format!("could not reach {address}"))?;

    let status = String::from_utf8_lossy(&response);
    let healthy = status
        .lines()
        .next()
        .is_some_and(|line| line.contains(" 200 "));
    anyhow::ensure!(
        healthy,
        "unhealthy: {}",
        status.lines().next().unwrap_or("no response")
    );
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("installing the Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing the SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown signal received");
}
