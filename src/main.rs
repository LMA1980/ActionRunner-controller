use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};

use mu_ci_controller::app::create_router;
use mu_ci_controller::cluster::ClusterRegistry;
use mu_ci_controller::config::Config;
use mu_ci_controller::console::{spawn_reconciler, ConsoleConfig, ConsoleState};
use mu_ci_controller::job::JobStore;
use mu_ci_controller::scheduler::DAGScheduler;
use mu_ci_controller::webhook::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mu_ci_controller=info,tower_http=info".into()),
        )
        .init();

    let config = Config::load();
    let bind_addr: SocketAddr = config.bind_addr.parse()?;

    info!("Starting mu-ci-controller on {}", bind_addr);
    info!("Allowed repositories: {:?}", config.allowed_repositories);
    info!("Workspace directory:  {}", config.workspace_dir.display());

    if config.webhook_secret.is_some() {
        info!("GitHub Webhook HMAC signature verification: ACTIVE");
    } else if config.allow_insecure_no_secret {
        warn!("GitHub Webhook HMAC signature verification: INSECURE DEV MODE (unverified payloads accepted)");
    } else {
        warn!("GitHub Webhook HMAC signature verification: STRICT (incoming webhooks will be rejected until GITHUB_WEBHOOK_SECRET is set)");
    }

    let job_store = JobStore::from_config(100, &config);
    info!(
        node_id = %config.node_id,
        ha_policy = %config.ha_role.as_str(),
        initial_role = %job_store.ha_role().as_str(),
        "Initialized JobStore HA role"
    );
    let cluster = ClusterRegistry::new();
    let (tx, _rx) = mpsc::channel(32);

    let scheduler = Arc::new(DAGScheduler::new(
        config.clone(),
        job_store.clone(),
        cluster.clone(),
    ));
    tokio::spawn(scheduler.run_loop());

    let (log_broadcaster, _) = tokio::sync::broadcast::channel(4096);

    let console = ConsoleState::new(ConsoleConfig::from_config(&config));
    spawn_reconciler(console.clone(), job_store.clone(), cluster.clone());

    let state = Arc::new(AppState {
        config,
        job_store,
        cluster,
        tx,
        log_broadcaster,
        console,
    });
    mu_ci_controller::webhook::spawn_ha_coordinator(state.clone());

    let app = create_router(state.clone());

    if let (Some(quic_bind), Some(cert_path), Some(key_path), Some(ca_path)) = (
        &state.config.quic_bind_addr,
        &state.config.tls_cert_path,
        &state.config.tls_key_path,
        &state.config.tls_ca_path,
    ) {
        match mu_ci_controller::tls::build_server_config_from_files(cert_path, key_path, ca_path) {
            Ok(server_tls_cfg) => {
                match mu_ci_controller::quic::make_quic_server_config(server_tls_cfg) {
                    Ok(quic_cfg) => match quic_bind.parse::<SocketAddr>() {
                        Ok(quic_addr) => {
                            match mu_ci_controller::quic::bind_quic_endpoint(quic_addr, quic_cfg) {
                                Ok(endpoint) => {
                                    info!(
                                        "Bound dual-stack UDP QUIC endpoint (ALPN h3) on {}",
                                        quic_addr
                                    );
                                    tokio::spawn(mu_ci_controller::quic::run_quic_server(
                                        endpoint,
                                        app.clone(),
                                    ));
                                }
                                Err(e) => {
                                    warn!("Failed to bind QUIC endpoint: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Invalid ACTION_RUNNER_QUIC_BIND address '{quic_bind}': {e}");
                        }
                    },
                    Err(e) => {
                        warn!("Failed to configure QUIC transport crypto: {e}");
                    }
                }
            }
            Err(e) => {
                warn!("Failed to load mTLS certificates for QUIC: {e}");
            }
        }
    }

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
