//! Empirical Challenger Stress Suite: Unauthenticated API Privacy Boundary Verification
//!
//! Simulates unauthenticated adversarial queries against mu-ci-controller API endpoints
//! (/health, /api/cluster/nodes, /api/cluster/status, /api/ha/status) and verifies that
//! internal lab hostnames, domain suffixes, and private LAN identifiers are NEVER emitted.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Utc;
use futures_util::StreamExt;
use mu_ci_controller::app::create_router;
use mu_ci_controller::cluster::ClusterRegistry;
use mu_ci_controller::config::Config;
use mu_ci_controller::console::{ConsoleConfig, ConsoleState};
use mu_ci_controller::job::{Job, JobStore, StageRecord, StageStatus};
use mu_ci_controller::webhook::AppState;
use mu_ci_ipc::WorkerRegistration;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc;
use tower::ServiceExt;

const TEST_API_KEY: &str = "challenge-secret-api-key-42";

// Synthetic test fixtures for privacy boundary verification
const TEST_NODE_A: &str = "test-node-alpha";
const TEST_NODE_B: &str = "test-node-beta";
const TEST_WORKER_RV: &str = "test-worker-riscv";
const TEST_WORKER_RV_U: &str = "test_worker_riscv";
const TEST_WORKER_ARM: &str = "test-worker-arm";
const TEST_WORKER_ARM_U: &str = "test_worker_arm";
const TEST_DOMAIN: &str = "corp.internal";
const TEST_DOMAIN_SUFFIX: &str = ".corp.internal";

static INIT_ENV: std::sync::Once = std::sync::Once::new();
fn ensure_test_env() {
    INIT_ENV.call_once(|| {
        std::env::set_var(
            "MUCI_NODE_MAP",
            "test-node-alpha=node-a,test-node-beta=node-b,test-worker-riscv=worker-riscv64,test_worker_riscv=worker-riscv64,test-worker-arm=worker-aarch64,test_worker_arm=worker-aarch64",
        );
    });
}

fn assert_no_leak(payload: &str, context: &str) {
    let lower = payload.to_lowercase();
    let forbidden_names = [
        TEST_NODE_A,
        TEST_NODE_B,
        TEST_WORKER_RV,
        TEST_WORKER_RV_U,
        TEST_WORKER_ARM,
        TEST_WORKER_ARM_U,
        TEST_DOMAIN,
    ];
    for token in forbidden_names {
        assert!(
            !lower.contains(token),
            "Privacy leak detected in {context}: found forbidden token '{token}' in response:\n{payload}"
        );
    }
}

fn make_test_state_with_key(
    controller_node_id: &str,
    api_key: Option<&str>,
    healthy_ws: bool,
) -> Arc<AppState> {
    ensure_test_env();
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
        log_api_key: api_key.map(|k| k.to_string()),
        webhook_secret: None,
        cluster_token: "cluster-token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 4,
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

fn make_test_state(controller_node_id: &str, healthy_ws: bool) -> Arc<AppState> {
    make_test_state_with_key(controller_node_id, Some(TEST_API_KEY), healthy_ws)
}

#[tokio::test]
async fn test_unauthenticated_health_redacts_internal_hostnames() {
    let forbidden_names = [
        TEST_NODE_A,
        TEST_NODE_B,
        TEST_WORKER_RV,
        TEST_WORKER_RV_U,
        TEST_DOMAIN,
    ];

    let host_a = format!("{TEST_NODE_A}{TEST_DOMAIN_SUFFIX}");
    let host_b = format!("{TEST_NODE_B}{TEST_DOMAIN_SUFFIX}");
    let host_c = format!("{TEST_WORKER_RV}{TEST_DOMAIN_SUFFIX}");

    let test_hosts = [host_a.as_str(), host_b.as_str(), host_c.as_str()];

    for &host in &test_hosts {
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
    let node_a = format!("{TEST_NODE_A}{TEST_DOMAIN_SUFFIX}");
    let node_b = format!("{TEST_NODE_B}{TEST_DOMAIN_SUFFIX}");
    let node_c = format!("{TEST_WORKER_RV}{TEST_DOMAIN_SUFFIX}");
    let node_d = format!("extra-node{TEST_DOMAIN_SUFFIX}");
    let node_tb = TEST_WORKER_ARM;
    let node_tbu = TEST_WORKER_ARM_U;

    let state = make_test_state(&node_a, true);

    // Register 6 nodes with internal lab names
    let nodes = [
        (node_a.as_str(), "x86_64", vec![node_a.clone()]),
        (node_b.as_str(), "x86_64", vec!["x86_64".to_string()]),
        (node_c.as_str(), "riscv64", vec!["riscv64".to_string()]),
        (node_d.as_str(), "aarch64", vec!["aarch64".to_string()]),
        (
            node_tb,
            "aarch64",
            vec![node_tb.to_string(), "k3".to_string()],
        ),
        (node_tbu, "aarch64", vec![node_tbu.to_string()]),
    ];

    for (node_id, arch, tags) in nodes {
        let (cmd_tx, _) = mpsc::channel(4);
        let reg = WorkerRegistration {
            node_id: node_id.to_string(),
            arch: arch.to_string(),
            max_slots: 1,
            tags,
            toolchains: vec![],
            ram_total_mb: 32768,
            btrfs_enabled: true,
        };
        state.cluster.register(reg, cmd_tx).await;
    }

    let app = create_router(state.clone());

    let forbidden_names = [
        TEST_NODE_A,
        TEST_NODE_B,
        TEST_WORKER_RV,
        TEST_WORKER_RV_U,
        TEST_WORKER_ARM,
        TEST_WORKER_ARM_U,
        TEST_DOMAIN,
    ];

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

    for &forbidden in &forbidden_names {
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
        returned_ids.contains(&"worker-aarch64"),
        "Missing worker-aarch64 alias"
    );
    assert!(
        returned_ids.contains(&"extra-node.example.invalid"),
        "Missing .example.invalid domain replacement"
    );

    for v in &views {
        if let Some(tags) = v["tags"].as_array() {
            for tag in tags {
                let tag_str = tag.as_str().unwrap();
                for &forbidden in &forbidden_names {
                    assert!(
                        !tag_str.to_lowercase().contains(forbidden),
                        "Privacy leak in node tags: found '{forbidden}' in tag '{tag_str}'"
                    );
                }
            }
        }
    }

    // 2. Unauthenticated request to /api/cluster/status
    let status_req = Request::builder()
        .uri("/api/cluster/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let status_res = app.clone().oneshot(status_req).await.unwrap();
    let status_bytes = to_bytes(status_res.into_body(), usize::MAX).await.unwrap();
    let status_str = String::from_utf8(status_bytes.to_vec()).unwrap();

    for &forbidden in &forbidden_names {
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

    for &forbidden in &forbidden_names {
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

    let spoof_res = app.clone().oneshot(spoof_req).await.unwrap();
    let spoof_bytes = to_bytes(spoof_res.into_body(), usize::MAX).await.unwrap();
    let spoof_str = String::from_utf8(spoof_bytes.to_vec()).unwrap();

    for &forbidden in &forbidden_names {
        assert!(
            !spoof_str.to_lowercase().contains(forbidden),
            "Spoofed auth header leaked private hostnames: found '{forbidden}' in: {spoof_str}"
        );
    }
}

#[tokio::test]
async fn test_unauthenticated_queue_and_jobs_redacts_node_and_stage_metadata() {
    let node_a = format!("{TEST_NODE_A}{TEST_DOMAIN_SUFFIX}");
    let node_tb = TEST_WORKER_ARM;

    let state = make_test_state(&node_a, true);

    let job_id = "test-job-privacy-1";
    let job = Job {
        id: job_id.to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/test-repo".to_string(),
        clone_url: String::new(),
        commit_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };
    state
        .job_store
        .enqueue_job(job, std::path::PathBuf::from("logs/test.log"))
        .await;

    let stage = StageRecord {
        id: "stage-1".to_string(),
        name: "build".to_string(),
        tags: vec![node_tb.to_string(), "k3".to_string()],
        threads: 4,
        toolchain: None,
        depends_on: vec![],
        status: StageStatus::Running {
            node_id: node_a.clone(),
            started_at: Utc::now(),
            pid: Some(1234),
        },
        assigned_node: Some(node_a.clone()),
        exclusive: false,
    };
    state.job_store.set_stages(job_id, vec![stage]).await;

    let app = create_router(state.clone());

    let forbidden_names = [
        TEST_NODE_A,
        TEST_NODE_B,
        TEST_WORKER_RV,
        TEST_WORKER_RV_U,
        TEST_WORKER_ARM,
        TEST_WORKER_ARM_U,
        TEST_DOMAIN,
    ];

    // 1. Unauthenticated GET /api/queue
    let queue_req = Request::builder()
        .uri("/api/queue")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let queue_res = app.clone().oneshot(queue_req).await.unwrap();
    assert_eq!(queue_res.status(), StatusCode::OK);
    let queue_bytes = to_bytes(queue_res.into_body(), usize::MAX).await.unwrap();
    let queue_str = String::from_utf8(queue_bytes.to_vec()).unwrap();
    for &forbidden in &forbidden_names {
        assert!(
            !queue_str.to_lowercase().contains(forbidden),
            "Privacy leak in /api/queue: found '{forbidden}' in: {queue_str}"
        );
    }
    let queue_val: Value = serde_json::from_str(&queue_str).unwrap();
    let stage_node = queue_val["queued_jobs"][0]["record"]["stages"][0]["assigned_node"]
        .as_str()
        .unwrap();
    assert_eq!(stage_node, "node-a");
    let stage_tag = queue_val["queued_jobs"][0]["record"]["stages"][0]["tags"][0]
        .as_str()
        .unwrap();
    assert_eq!(stage_tag, "worker-aarch64");
    let stage_status_node = queue_val["queued_jobs"][0]["record"]["stages"][0]["status"]["details"]
        ["node_id"]
        .as_str()
        .unwrap();
    assert_eq!(stage_status_node, "node-a");

    // 2. Unauthenticated GET /api/jobs
    let jobs_req = Request::builder()
        .uri("/api/jobs")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let jobs_res = app.clone().oneshot(jobs_req).await.unwrap();
    assert_eq!(jobs_res.status(), StatusCode::OK);
    let jobs_bytes = to_bytes(jobs_res.into_body(), usize::MAX).await.unwrap();
    let jobs_str = String::from_utf8(jobs_bytes.to_vec()).unwrap();
    for &forbidden in &forbidden_names {
        assert!(
            !jobs_str.to_lowercase().contains(forbidden),
            "Privacy leak in /api/jobs: found '{forbidden}' in: {jobs_str}"
        );
    }

    // 3. Unauthenticated GET /api/jobs/{id}
    let job_req = Request::builder()
        .uri(format!("/api/jobs/{job_id}"))
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let job_res = app.clone().oneshot(job_req).await.unwrap();
    assert_eq!(job_res.status(), StatusCode::OK);
    let job_bytes = to_bytes(job_res.into_body(), usize::MAX).await.unwrap();
    let job_str = String::from_utf8(job_bytes.to_vec()).unwrap();
    for &forbidden in &forbidden_names {
        assert!(
            !job_str.to_lowercase().contains(forbidden),
            "Privacy leak in /api/jobs/{job_id}: found '{forbidden}' in: {job_str}"
        );
    }
    let job_val: Value = serde_json::from_str(&job_str).unwrap();
    assert_eq!(
        job_val["stages"][0]["assigned_node"].as_str().unwrap(),
        "node-a"
    );

    // 4. Authenticated GET /api/jobs/{id} reveals raw operator values
    let auth_job_req = Request::builder()
        .uri(format!("/api/jobs/{job_id}"))
        .method("GET")
        .header("X-API-Key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();

    let auth_job_res = app.oneshot(auth_job_req).await.unwrap();
    assert_eq!(auth_job_res.status(), StatusCode::OK);
    let auth_bytes = to_bytes(auth_job_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let auth_val: Value = serde_json::from_slice(&auth_bytes).unwrap();
    assert_eq!(
        auth_val["stages"][0]["assigned_node"].as_str().unwrap(),
        node_a
    );
    assert_eq!(auth_val["stages"][0]["tags"][0].as_str().unwrap(), node_tb);
}

#[tokio::test]
async fn test_adversarial_mixed_case_and_fqdn_sanitization() {
    let s_e = TEST_NODE_A;
    let s_r = TEST_NODE_B;
    let s_p = TEST_WORKER_RV;
    let s_pu = TEST_WORKER_RV_U;
    let s_tb = TEST_WORKER_ARM;
    let _s_tbu = TEST_WORKER_ARM_U;
    let s_d = TEST_DOMAIN_SUFFIX;

    let s_tb_upper = s_tb.to_ascii_uppercase();
    let s_tbu_mixed = "Test_Worker_Arm".to_string();
    let s_pu_mixed = "Test_Worker_Riscv".to_string();
    let s_p_upper = s_p.to_ascii_uppercase();
    let s_e_cap = "Test-Node-Alpha".to_string();
    let s_e_upper = s_e.to_ascii_uppercase();
    let s_e_mixed = "tEsT-nOdE-aLpHa".to_string();
    let s_r_upper = s_r.to_ascii_uppercase();
    let s_r_mixed = "tEsT-nOdE-bEtA".to_string();

    let adversarial_nodes = vec![
        // Uppercase and mixed case
        (s_tb_upper.clone(), "worker-aarch64"),
        (s_tbu_mixed, "worker-aarch64"),
        (s_pu_mixed.clone(), "worker-riscv64"),
        (s_p_upper, "worker-riscv64"),
        (s_e_cap, "node-a"),
        (s_e_upper, "node-a"),
        (s_e_mixed, "node-a"),
        (s_r_upper, "node-b"),
        (s_r_mixed, "node-b"),
        // FQDN variations
        (format!("{s_tb}{s_d}"), "worker-aarch64"),
        (format!("sub.{s_e}{s_d}"), "node-a"),
        (format!("deep.sub.{s_r}{s_d}"), "node-b"),
        (format!("node.{s_p}{s_d}"), "worker-riscv64"),
        (format!("node.{s_pu}{s_d}"), "worker-riscv64"),
        (format!("other-worker{s_d}"), "other-worker.example.invalid"),
        (format!("OTHER-WORKER{s_d}"), "other-worker.example.invalid"),
        (format!("myhost{s_d}:8080"), "myhost.example.invalid:8080"),
        // Unknown nodes
        ("worker-generic-1".to_string(), "worker-generic-1"),
        ("x86-worker-99".to_string(), "x86-worker-99"),
        // Empty string
        ("".to_string(), ""),
        // Injection payloads
        (
            "<script>alert(1)</script>".to_string(),
            "<script>alert(1)</script>",
        ),
        (
            "'; DROP TABLE nodes; --".to_string(),
            "'; DROP TABLE nodes; --",
        ),
        (
            "../../../../etc/passwd".to_string(),
            "../../../../etc/passwd",
        ),
    ];

    let host_ctrl = format!("{s_e}{s_d}");
    let state = make_test_state(&host_ctrl, true);

    // Register all adversarial nodes in cluster
    for (node_id, _) in &adversarial_nodes {
        if !node_id.is_empty() {
            let (cmd_tx, _) = mpsc::channel(4);
            let reg = WorkerRegistration {
                node_id: node_id.clone(),
                arch: "x86_64".to_string(),
                max_slots: 1,
                tags: vec![node_id.clone(), "adversarial-tag".to_string()],
                toolchains: vec![],
                ram_total_mb: 16384,
                btrfs_enabled: false,
            };
            state.cluster.register(reg, cmd_tx).await;
        }
    }

    let app = create_router(state.clone());

    // 1. Unauthenticated GET /api/cluster/nodes
    let req = Request::builder()
        .uri("/api/cluster/nodes")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8(bytes.to_vec()).unwrap();

    assert_no_leak(&body_str, "/api/cluster/nodes (unauthenticated)");

    let nodes_val: Vec<Value> = serde_json::from_str(&body_str).unwrap();
    for (raw_id, expected_sanitized) in &adversarial_nodes {
        if raw_id.is_empty() {
            continue;
        }
        let found = nodes_val.iter().any(|n| {
            let nid = n["node_id"].as_str().unwrap_or_default();
            nid == *expected_sanitized
        });
        assert!(
            found,
            "Expected sanitized node '{expected_sanitized}' for raw '{raw_id}', but was not found in response"
        );
    }

    // 2. Authenticated GET /api/cluster/nodes receives raw unredacted values
    let auth_req = Request::builder()
        .uri("/api/cluster/nodes")
        .method("GET")
        .header("X-API-Key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();

    let auth_res = app.clone().oneshot(auth_req).await.unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK);
    let auth_bytes = to_bytes(auth_res.into_body(), usize::MAX).await.unwrap();
    let auth_str = String::from_utf8(auth_bytes.to_vec()).unwrap();
    let auth_nodes: Vec<Value> = serde_json::from_str(&auth_str).unwrap();

    let has_raw_tb = auth_nodes
        .iter()
        .any(|n| n["node_id"].as_str() == Some(&s_tb_upper));
    assert!(
        has_raw_tb,
        "Authenticated request must retain raw uppercase worker node ID"
    );
    let has_raw_p = auth_nodes
        .iter()
        .any(|n| n["node_id"].as_str() == Some(&s_pu_mixed));
    assert!(
        has_raw_p,
        "Authenticated request must retain raw mixed-case worker node ID"
    );
}

#[tokio::test]
async fn test_adversarial_endpoints_privacy_across_all_routes() {
    let s_e = TEST_NODE_A;
    let s_r = TEST_NODE_B;
    let s_tb = TEST_WORKER_ARM;
    let s_d = TEST_DOMAIN_SUFFIX;

    let host_ctrl = format!("{s_r}{s_d}");
    let state = make_test_state(&host_ctrl, true);

    // Register workers with forbidden identifiers in node_id and tags
    let raw_node_e = format!("{s_e}{s_d}");
    let raw_node_tb = format!("{s_tb}{s_d}");

    let (cmd_tx1, _) = mpsc::channel(4);
    state
        .cluster
        .register(
            WorkerRegistration {
                node_id: raw_node_e.clone(),
                arch: "x86_64".to_string(),
                max_slots: 1,
                tags: vec![raw_node_e.clone(), "primary".to_string()],
                toolchains: vec![],
                ram_total_mb: 32768,
                btrfs_enabled: true,
            },
            cmd_tx1,
        )
        .await;

    let (cmd_tx2, _) = mpsc::channel(4);
    state
        .cluster
        .register(
            WorkerRegistration {
                node_id: raw_node_tb.clone(),
                arch: "aarch64".to_string(),
                max_slots: 1,
                tags: vec![raw_node_tb.clone(), "arm".to_string()],
                toolchains: vec![],
                ram_total_mb: 8192,
                btrfs_enabled: false,
            },
            cmd_tx2,
        )
        .await;

    // Enqueue jobs with assigned nodes, tags, and stage status containing forbidden strings
    let job_id = "adv-job-privacy-42";
    let job = Job {
        id: job_id.to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/test-repo".to_string(),
        clone_url: String::new(),
        commit_sha: "11223344556677889900aabbccddeeff11223344".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };
    state
        .job_store
        .enqueue_job(job, std::path::PathBuf::from("logs/adv.log"))
        .await;

    let stages = vec![
        StageRecord {
            id: "stage-e".to_string(),
            name: "compile".to_string(),
            tags: vec![raw_node_e.clone(), "x86".to_string()],
            threads: 4,
            toolchain: None,
            depends_on: vec![],
            status: StageStatus::Assigned {
                node_id: raw_node_e.clone(),
                started_at: Utc::now(),
            },
            assigned_node: Some(raw_node_e.clone()),
            exclusive: false,
        },
        StageRecord {
            id: "stage-tb".to_string(),
            name: "test-arm".to_string(),
            tags: vec![raw_node_tb.clone(), "k3".to_string()],
            threads: 2,
            toolchain: None,
            depends_on: vec!["stage-e".to_string()],
            status: StageStatus::Running {
                node_id: raw_node_tb.clone(),
                started_at: Utc::now(),
                pid: Some(9999),
            },
            assigned_node: Some(raw_node_tb.clone()),
            exclusive: false,
        },
    ];
    state.job_store.set_stages(job_id, stages).await;

    let app = create_router(state.clone());

    // 1. Unauthenticated GET /health
    let req = Request::builder()
        .uri("/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8(bytes.to_vec()).unwrap();
    assert_no_leak(&s, "/health");
    let val: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(val["controller_id"], "node-b");

    // 2. Unauthenticated GET /api/queue
    let req = Request::builder()
        .uri("/api/queue")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8(bytes.to_vec()).unwrap();
    assert_no_leak(&s, "/api/queue");
    let q_val: Value = serde_json::from_str(&s).unwrap();
    let stage0 = &q_val["queued_jobs"][0]["record"]["stages"][0];
    assert_eq!(stage0["assigned_node"], "node-a");
    assert_eq!(stage0["tags"][0], "node-a");
    assert_eq!(stage0["status"]["details"]["node_id"], "node-a");
    let stage1 = &q_val["queued_jobs"][0]["record"]["stages"][1];
    assert_eq!(stage1["assigned_node"], "worker-aarch64");
    assert_eq!(stage1["tags"][0], "worker-aarch64");
    assert_eq!(stage1["status"]["details"]["node_id"], "worker-aarch64");

    // 3. Unauthenticated GET /api/jobs
    let req = Request::builder()
        .uri("/api/jobs")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8(bytes.to_vec()).unwrap();
    assert_no_leak(&s, "/api/jobs");

    // 4. Unauthenticated GET /api/jobs/{id}
    let req = Request::builder()
        .uri(format!("/api/jobs/{job_id}"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8(bytes.to_vec()).unwrap();
    assert_no_leak(&s, "/api/jobs/{id}");
    let j_val: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(j_val["stages"][0]["assigned_node"], "node-a");
    assert_eq!(j_val["stages"][1]["assigned_node"], "worker-aarch64");

    // 5. Unauthenticated GET /api/cluster/status
    let req = Request::builder()
        .uri("/api/cluster/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8(bytes.to_vec()).unwrap();
    assert_no_leak(&s, "/api/cluster/status");
    let cs_val: Value = serde_json::from_str(&s).unwrap();
    assert_eq!(cs_val["controller_id"], "node-b");

    // 6. Unauthenticated GET /api/ha/status
    let req = Request::builder()
        .uri("/api/ha/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8(bytes.to_vec()).unwrap();
    assert_no_leak(&s, "/api/ha/status");

    // 7. Unauthenticated GET /api/events returns 401 when API key configured, preventing leak
    let req = Request::builder()
        .uri("/api/events")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8(bytes.to_vec()).unwrap();
    assert_no_leak(&s, "/api/events (unauth 401)");

    // 8. Authenticated GET /api/queue receives raw unredacted values
    let auth_req = Request::builder()
        .uri("/api/queue")
        .method("GET")
        .header("X-API-Key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let auth_res = app.clone().oneshot(auth_req).await.unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK);
    let auth_bytes = to_bytes(auth_res.into_body(), usize::MAX).await.unwrap();
    let auth_q: Value = serde_json::from_slice(&auth_bytes).unwrap();
    assert_eq!(
        auth_q["queued_jobs"][0]["record"]["stages"][0]["assigned_node"],
        raw_node_e
    );
    assert_eq!(
        auth_q["queued_jobs"][0]["record"]["stages"][1]["assigned_node"],
        raw_node_tb
    );

    // 9. Authenticated GET /api/jobs/{id} receives raw unredacted values
    let auth_req = Request::builder()
        .uri(format!("/api/jobs/{job_id}"))
        .method("GET")
        .header("X-API-Key", TEST_API_KEY)
        .body(Body::empty())
        .unwrap();
    let auth_res = app.clone().oneshot(auth_req).await.unwrap();
    assert_eq!(auth_res.status(), StatusCode::OK);
    let auth_bytes = to_bytes(auth_res.into_body(), usize::MAX).await.unwrap();
    let auth_j: Value = serde_json::from_slice(&auth_bytes).unwrap();
    assert_eq!(auth_j["stages"][0]["assigned_node"], raw_node_e);
    assert_eq!(auth_j["stages"][1]["assigned_node"], raw_node_tb);
}

#[tokio::test]
async fn test_unauthenticated_events_stream_sanitization_in_open_mode() {
    let s_e = TEST_NODE_A;
    let s_tb = TEST_WORKER_ARM;
    let s_d = TEST_DOMAIN_SUFFIX;

    let host_ctrl = format!("{s_e}{s_d}");
    // No API key configured -> open public mode where /api/events streams unauthenticated
    let state = make_test_state_with_key(&host_ctrl, None, true);

    let raw_node_tb = format!("{s_tb}{s_d}");
    let (cmd_tx, _) = mpsc::channel(4);
    state
        .cluster
        .register(
            WorkerRegistration {
                node_id: raw_node_tb.clone(),
                arch: "aarch64".to_string(),
                max_slots: 1,
                tags: vec![raw_node_tb.clone()],
                toolchains: vec![],
                ram_total_mb: 8192,
                btrfs_enabled: false,
            },
            cmd_tx,
        )
        .await;

    let job_id = "adv-sse-job-1";
    let job = Job {
        id: job_id.to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/test-repo".to_string(),
        clone_url: String::new(),
        commit_sha: "99887766554433221100aabbccddeeff99887766".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };
    state
        .job_store
        .enqueue_job(job, std::path::PathBuf::from("logs/sse.log"))
        .await;
    state
        .job_store
        .set_stages(
            job_id,
            vec![StageRecord {
                id: "stage-1".to_string(),
                name: "test".to_string(),
                tags: vec![raw_node_tb.clone()],
                threads: 2,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Assigned {
                    node_id: raw_node_tb.clone(),
                    started_at: Utc::now(),
                },
                assigned_node: Some(raw_node_tb.clone()),
                exclusive: false,
            }],
        )
        .await;

    let app = create_router(state.clone());

    // Connect unauthenticated to /api/events
    let req = Request::builder()
        .uri("/api/events")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers().get("content-type").unwrap(),
        "text/event-stream"
    );

    // Read the initial event stream payload (which pushes queue, jobs, cluster snapshots)
    let body = res.into_body();
    let mut stream = body.into_data_stream();
    let mut accumulated = Vec::new();

    // Collect first chunks of the SSE stream
    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.unwrap();
        accumulated.extend_from_slice(&chunk);
        if accumulated.len() > 200 {
            break;
        }
    }

    let stream_text = String::from_utf8_lossy(&accumulated);
    assert_no_leak(&stream_text, "/api/events SSE stream (unauthenticated)");
}

#[tokio::test]
async fn test_adversarial_bare_domain_check() {
    let s_l = TEST_DOMAIN;
    let state = make_test_state("node-a", true);

    let (cmd_tx, _) = mpsc::channel(4);
    state
        .cluster
        .register(
            WorkerRegistration {
                node_id: s_l.to_string(),
                arch: "x86_64".to_string(),
                max_slots: 1,
                tags: vec![s_l.to_string()],
                toolchains: vec![],
                ram_total_mb: 16384,
                btrfs_enabled: false,
            },
            cmd_tx,
        )
        .await;

    let app = create_router(state);

    let req = Request::builder()
        .uri("/api/cluster/nodes")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let s = String::from_utf8(bytes.to_vec()).unwrap();

    // Check if the bare domain leaked
    let leaked = s.to_lowercase().contains(s_l);
    assert!(!leaked, "Bare internal domain leaked: {}", s);
}
