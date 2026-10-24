use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

use action_runner_controller::app::create_router;
use action_runner_controller::cluster::ClusterRegistry;
use action_runner_controller::config::Config;
use action_runner_controller::job::JobStore;
use action_runner_controller::scheduler::DAGScheduler;
use action_runner_controller::webhook::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "action_runner_controller=info,tower_http=info".into()),
        )
        .init();

    let config = Config::load();
    let bind_addr: SocketAddr = config.bind_addr.parse()?;

    info!("Starting ActionRunner-controller on {}", bind_addr);
    info!("Allowed repositories: {:?}", config.allowed_repositories);
    info!("Workspace directory:  {}", config.workspace_dir.display());

    if config.webhook_secret.is_some() {
        info!("GitHub Webhook HMAC signature verification: ACTIVE");
    } else if config.allow_insecure_no_secret {
        warn!("GitHub Webhook HMAC signature verification: INSECURE DEV MODE (unverified payloads accepted)");
    } else {
        warn!("GitHub Webhook HMAC signature verification: STRICT (incoming webhooks will be rejected until GITHUB_WEBHOOK_SECRET is set)");
    }

    let job_store = JobStore::new(100, Some(&config.workspace_dir));
    let cluster = ClusterRegistry::new();
    let (tx, _rx) = mpsc::channel(32);

    let scheduler = Arc::new(DAGScheduler::new(
        config.clone(),
        job_store.clone(),
        cluster.clone(),
    ));
    tokio::spawn(scheduler.run_loop());

    let (log_broadcaster, _) = tokio::sync::broadcast::channel(4096);

    let state = Arc::new(AppState {
        config,
        job_store,
        cluster,
        tx,
        log_broadcaster,
    });

    let app = create_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
