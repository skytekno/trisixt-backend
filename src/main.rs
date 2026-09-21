use std::{sync::Arc, time::Duration};
use tracing_subscriber::EnvFilter;
use trisixt::{config::Config, routes, state::AppState, worker};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let command = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "serve".to_owned());
    if command == "--version" {
        println!("trisixt {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if !matches!(command.as_str(), "serve" | "worker" | "migrate") {
        return Err("usage: trisixt [serve|worker|migrate|--version]".into());
    }
    let config = Arc::new(Config::from_env()?);
    let pg = sqlx::postgres::PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&config.database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pg).await?;
    if command == "migrate" {
        tracing::info!("migrations complete");
        return Ok(());
    }
    let state = AppState {
        config: config.clone(),
        pg,
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    if command == "worker" {
        // Fail startup so the service supervisor can report/restart a broken
        // worker rather than leave a running process that delivers no events.
        trisixt::providers::Analytics::from_env(&config)?;
    }
    let signal = async move {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("install terminate signal handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        let _ = shutdown_tx.send(true);
    };
    if command == "worker" {
        tokio::select! {
            _ = signal => {},
            _ = worker::run(state.clone(), shutdown_rx) => {
                return Err("analytics worker stopped unexpectedly".into());
            }
        }
    } else {
        let addr = format!("{}:{}", config.host, config.port);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!("trisixt listening on {addr}");
        axum::serve(
            listener,
            routes::router(state.clone())
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(signal)
        .await?;
    }
    state.pg.close().await;
    Ok(())
}
