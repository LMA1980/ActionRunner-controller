//! Empirical Challenger Stress Suite: Unauthenticated API Privacy Boundary Verification
//!
//! Simulates unauthenticated adversarial queries against mu-ci-controller API endpoints
//! (/health, /api/cluster/nodes, /api/cluster/status, /api/ha/status) and verifies that
//! internal lab hostnames, domain suffixes, and private LAN identifiers are NEVER emitted.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use mu_ci_controller::app::create_router;
use mu_ci_controller::cluster::ClusterRegistry;
use mu_ci_controller::config::Config;
use mu_ci_controller::console::{ConsoleConfig, ConsoleState};
use mu_ci_controller::job::JobStore;
use mu_ci_controller::webhook::AppState;
use mu_ci_ipc::WorkerRegistration;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc;
use tower::ServiceExt;

const TEST_API_KEY: &str = "challenge-secret-api-key-42";

fn make_test_state(controller_node_id: &str, healthy_ws: bool) -> Arc<AppState> {
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);

    let ws_path = if healthy_ws {
        std::env::temp_dir()
    } else {
        std::path::PathBuf::from("/nonexistent-challenge-dir-io-fail")
    };

    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: ws_path,
        allowed_repositories: vec!["LMA1980/*".to_string()],
        allowed_actors: vec![],
        allow_fork_prs: false,
        allowed_pr_authors: vec!["OWNER".to_string()],
        log_api_key: Some(TEST_API_KEY.to_string()),
        webhook_secret: None,
        cluster_token: "cluster-token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 2,
        github_token: None,
        node_id: controller_node_id.to_string(),
        ..Config::default()
    };

    let console = ConsoleState::new(ConsoleConfig::default());

    Arc::new(AppState {
        config,
        job_store: JobStore::new(100, None),
        cluster: ClusterRegistry::new(),
        tx,
        log_broadcaster,
        console,
    })
}

#[tokio::test]
async fn test_unauthenticated_health_redacts_internal_hostnames() {
    let forbidden_names = [
        "entrance",
        "rubicon",
        "pey-wail-deu",
        "pey_wail_deu",
        "lab.local",
    ];

    for &host in &[
        "entrance.lab.local",
        "rubicon.lab.local",
        "pey-wail-deu.lab.local",
    ] {
        // Test healthy (200 OK)
        let state = make_test_state(host, true);
        let app = create_router(state);

        let req = Request::builder()
            .uri("/health")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        for &forbidden in &forbidden_names {
            assert!(
                !body_str.to_lowercase().contains(forbidden),
                "Privacy Leak in /health unauthenticated response: found '{forbidden}' in body: {body_str}"
            );
        }

        let json_val: Value = serde_json::from_str(&body_str).unwrap();
        let cid = json_val["controller_id"].as_str().unwrap();
        assert!(
            cid == "node-a" || cid == "node-b" || cid == "worker-riscv64",
            "Expected sanitized controller_id alias, got: {cid}"
        );

        // Test unhealthy (503 Service Unavailable) error branch
        let unhealthy_state = make_test_state(host, false);
        let unh_app = create_router(unhealthy_state);
        let unh_req = Request::builder()
            .uri("/health")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let unh_response = unh_app.oneshot(unh_req).await.unwrap();
        assert_eq!(unh_response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let unh_bytes = to_bytes(unh_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let unh_str = String::from_utf8(unh_bytes.to_vec()).unwrap();
        for &forbidden in &forbidden_names {
            assert!(
                !unh_str.to_lowercase().contains(forbidden),
                "Privacy Leak in /health 503 response: found '{forbidden}' in body: {unh_str}"
            );
        }
        let unh_json: Value = serde_json::from_str(&unh_str).unwrap();
        let unh_cid = unh_json["controller_id"].as_str().unwrap();
        assert!(
            unh_cid == "node-a" || unh_cid == "node-b" || unh_cid == "worker-riscv64",
            "Expected sanitized controller_id alias on 503, got: {unh_cid}"
        );

        // Authenticated request with valid API key should reveal operator node_id
        let auth_req = Request::builder()
            .uri("/health")
            .method("GET")
            .header("X-API-Key", TEST_API_KEY)
            .body(Body::empty())
            .unwrap();

        let auth_res = app.oneshot(auth_req).await.unwrap();
        let auth_body_bytes = to_bytes(auth_res.into_body(), usize::MAX).await.unwrap();
        let auth_json: Value = serde_json::from_slice(&auth_body_bytes).unwrap();
        assert_eq!(auth_json["controller_id"].as_str().unwrap(), host);
    }
}

#[tokio::test]
async fn test_unauthenticated_cluster_nodes_redacts_all_registered_workers() {
    let state = make_test_state("entrance.lab.local", true);

    // Register 4 nodes with internal lab names
    let nodes = [
        ("entrance.lab.local", "x86_64"),
        ("rubicon.lab.local", "x86_64"),
        ("pey-wail-deu.lab.local", "riscv64"),
        ("extra-node.lab.local", "aarch64"),
    ];

    for (node_id, arch) in nodes {
        let (cmd_tx, _) = mpsc::channel(4);
        let reg = WorkerRegistration {
            node_id: node_id.to_string(),
            arch: arch.to_string(),
            max_slots: 1,
            tags: vec![],
            toolchains: vec![],
            ram_total_mb: 32768,
            btrfs_enabled: true,
        };
        state.cluster.register(reg, cmd_tx).await;
    }

    let app = create_router(state.clone());

    // 1. Unauthenticated request to /api/cluster/nodes
    let req = Request::builder()
        .uri("/api/cluster/nodes")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    for forbidden in &["entrance", "rubicon", "pey-wail-deu", "lab.local"] {
        assert!(
            !body_str.to_lowercase().contains(forbidden),
            "Privacy leak in /api/cluster/nodes: found '{forbidden}' in: {body_str}"
        );
    }

    let views: Vec<Value> = serde_json::from_str(&body_str).unwrap();
    let returned_ids: Vec<&str> = views
        .iter()
        .map(|v| v["node_id"].as_str().unwrap())
        .collect();

    assert!(returned_ids.contains(&"node-a"), "Missing node-a alias");
    assert!(returned_ids.contains(&"node-b"), "Missing node-b alias");
    assert!(
        returned_ids.contains(&"worker-riscv64"),
        "Missing worker-riscv64 alias"
    );
    assert!(
        returned_ids.contains(&"extra-node.example.invalid"),
        "Missing .example.invalid domain replacement"
    );

    // 2. Unauthenticated request to /api/cluster/status
    let status_req = Request::builder()
        .uri("/api/cluster/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let status_res = app.clone().oneshot(status_req).await.unwrap();
    let status_bytes = to_bytes(status_res.into_body(), usize::MAX).await.unwrap();
    let status_str = String::from_utf8(status_bytes.to_vec()).unwrap();

    for forbidden in &["entrance", "rubicon", "pey-wail-deu", "lab.local"] {
        assert!(
            !status_str.to_lowercase().contains(forbidden),
            "Privacy leak in /api/cluster/status: found '{forbidden}' in: {status_str}"
        );
    }

    // 3. Unauthenticated request to /api/ha/status
    let ha_req = Request::builder()
        .uri("/api/ha/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let ha_res = app.clone().oneshot(ha_req).await.unwrap();
    let ha_bytes = to_bytes(ha_res.into_body(), usize::MAX).await.unwrap();
    let ha_str = String::from_utf8(ha_bytes.to_vec()).unwrap();

    for forbidden in &["entrance", "rubicon", "pey-wail-deu", "lab.local"] {
        assert!(
            !ha_str.to_lowercase().contains(forbidden),
            "Privacy leak in /api/ha/status: found '{forbidden}' in: {ha_str}"
        );
    }

    // 4. Spoofed header attack: attacker sends spoofed user or wrong key
    let spoof_req = Request::builder()
        .uri("/api/cluster/nodes")
        .method("GET")
        .header("X-Forwarded-User", "admin") // spoofed without valid proxy secret
        .header("X-API-Key", "wrong-attacker-key")
        .body(Body::empty())
        .unwrap();

    let spoof_res = app.oneshot(spoof_req).await.unwrap();
    let spoof_bytes = to_bytes(spoof_res.into_body(), usize::MAX).await.unwrap();
    let spoof_str = String::from_utf8(spoof_bytes.to_vec()).unwrap();

    for forbidden in &["entrance", "rubicon", "pey-wail-deu", "lab.local"] {
        assert!(
            !spoof_str.to_lowercase().contains(forbidden),
            "Spoofed auth header leaked private hostnames: found '{forbidden}' in: {spoof_str}"
        );
    }
}
