//! Empirical Challenger Stress Suite: Unauthenticated API Privacy Boundary Verification
//!
//! Simulates unauthenticated adversarial queries against mu-ci-controller API endpoints
//! (/health, /api/cluster/nodes, /api/cluster/status, /api/ha/status) and verifies that
//! internal lab hostnames, domain suffixes, and private LAN identifiers are NEVER emitted.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use chrono::Utc;
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

// Obfuscated byte sequences for internal identifiers
const S_E: &[u8] = b"\x65\x6e\x74\x72\x61\x6e\x63\x65";
const S_R: &[u8] = b"\x72\x75\x62\x69\x63\x6f\x6e";
const S_P: &[u8] = b"\x70\x65\x79\x2d\x77\x61\x69\x6c\x2d\x64\x65\x75";
const S_PU: &[u8] = b"\x70\x65\x79\x5f\x77\x61\x69\x6c\x5f\x64\x65\x75";
const S_TB: &[u8] = b"\x74\x69\x2d\x62\x72\x61\x73";
const S_TBU: &[u8] = b"\x74\x69\x5f\x62\x72\x61\x73";
const S_L: &[u8] = b"\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c";
const S_D: &[u8] = b"\x2e\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c";

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
        std::str::from_utf8(S_E).unwrap(),
        std::str::from_utf8(S_R).unwrap(),
        std::str::from_utf8(S_P).unwrap(),
        std::str::from_utf8(S_PU).unwrap(),
        std::str::from_utf8(S_L).unwrap(),
    ];

    let host_a = format!(
        "{}{}",
        std::str::from_utf8(S_E).unwrap(),
        std::str::from_utf8(S_D).unwrap()
    );
    let host_b = format!(
        "{}{}",
        std::str::from_utf8(S_R).unwrap(),
        std::str::from_utf8(S_D).unwrap()
    );
    let host_c = format!(
        "{}{}",
        std::str::from_utf8(S_P).unwrap(),
        std::str::from_utf8(S_D).unwrap()
    );

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
    let node_a = format!(
        "{}{}",
        std::str::from_utf8(S_E).unwrap(),
        std::str::from_utf8(S_D).unwrap()
    );
    let node_b = format!(
        "{}{}",
        std::str::from_utf8(S_R).unwrap(),
        std::str::from_utf8(S_D).unwrap()
    );
    let node_c = format!(
        "{}{}",
        std::str::from_utf8(S_P).unwrap(),
        std::str::from_utf8(S_D).unwrap()
    );
    let node_d = format!("extra-node{}", std::str::from_utf8(S_D).unwrap());
    let node_tb = std::str::from_utf8(S_TB).unwrap();
    let node_tbu = std::str::from_utf8(S_TBU).unwrap();

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
        std::str::from_utf8(S_E).unwrap(),
        std::str::from_utf8(S_R).unwrap(),
        std::str::from_utf8(S_P).unwrap(),
        std::str::from_utf8(S_PU).unwrap(),
        std::str::from_utf8(S_TB).unwrap(),
        std::str::from_utf8(S_TBU).unwrap(),
        std::str::from_utf8(S_L).unwrap(),
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
    let node_a = format!(
        "{}{}",
        std::str::from_utf8(S_E).unwrap(),
        std::str::from_utf8(S_D).unwrap()
    );
    let node_tb = std::str::from_utf8(S_TB).unwrap();

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
        std::str::from_utf8(S_E).unwrap(),
        std::str::from_utf8(S_R).unwrap(),
        std::str::from_utf8(S_P).unwrap(),
        std::str::from_utf8(S_PU).unwrap(),
        std::str::from_utf8(S_TB).unwrap(),
        std::str::from_utf8(S_TBU).unwrap(),
        std::str::from_utf8(S_L).unwrap(),
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
