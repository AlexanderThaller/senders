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

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("installing the Ctrl-C handler")
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
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    tracing::info!("shutdown signal received");
}
