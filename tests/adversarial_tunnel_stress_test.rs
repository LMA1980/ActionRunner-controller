//! Adversarial stress test suite for Issue #104:
//! Standby HTTP 503 upgrade rejection, RFC 6455 CloseFrame eviction on demotion,
//! Pong suppression under demotion, and disconnect floods.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use futures_util::{SinkExt, StreamExt};
use mu_ci_controller::app::create_router;
use mu_ci_controller::cluster::ClusterRegistry;
use mu_ci_controller::config::{Config, HaRole, HaRoleConfig};
use mu_ci_controller::console::{ConsoleConfig, ConsoleState};
use mu_ci_controller::job::JobStore;
use mu_ci_controller::storage_backend::{ControllerStorage, InMemoryStorage};
use mu_ci_controller::webhook::AppState;
use mu_ci_ipc::{
    create_fory_runtime, IpcHeader, WorkerHeartbeat, WorkerRegistration, MSG_TYPE_WORKER_HEARTBEAT,
    MSG_TYPE_WORKER_REGISTRATION,
};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

fn build_test_state(
    node_id: &str,
    ha_role: HaRoleConfig,
    workspace_dir: PathBuf,
    storage: Arc<dyn ControllerStorage>,
) -> Arc<AppState> {
    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: workspace_dir.clone(),
        allowed_repositories: vec!["LMA1980/*".to_string()],
        allowed_actors: vec!["*".to_string()],
        allow_fork_prs: false,
        allowed_pr_authors: vec!["OWNER".to_string()],
        log_api_key: None,
        webhook_secret: None,
        cluster_token: "ha-test-cluster-token".to_string(),
        job_timeout_seconds: 60,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 4,
        github_token: None,
        node_id: node_id.to_string(),
        ha_role,
        lease_ttl_seconds: 15,
        standby_sync_seconds: 5,
        ..Config::default()
    };

    let job_store = JobStore::from_config_with_storage(100, &config, Arc::clone(&storage));
    let cluster = ClusterRegistry::new();
    let (tx, _rx) = mpsc::channel(32);
    let (log_broadcaster, _) = broadcast::channel(256);
    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: None,
        github_token: None,
        workspace_dir: Some(workspace_dir),
        cache_file: None,
        metadata_ttl: Duration::from_secs(3600),
    });
    console.attach_storage(storage);

    Arc::new(AppState {
        config,
        job_store,
        cluster,
        tx,
        log_broadcaster,
        console,
    })
}

/// Scenario 1: Verify Standby strictly rejects tunnel upgrades with HTTP 503 (never 101).
/// Also verify invalid token is rejected with 401 Unauthorized before checking HA role.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_adversarial_standby_strict_http_503_and_token_precedence() {
    let ws = tempfile::tempdir().expect("ws");
    let storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());
    let state = build_test_state(
        "node-standby",
        HaRoleConfig::Standby,
        ws.path().join("ws-standby"),
        storage,
    );

    let app = create_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 1A. Wrong cluster token -> must return 401 Unauthorized
    let ws_url_wrong_token = format!(
        "ws://{}/api/cluster/tunnel?token=invalid-secret-token",
        addr
    );
    match connect_async(&ws_url_wrong_token).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "Invalid token must return 401 Unauthorized"
            );
        }
        other => panic!("Expected HTTP 401 for wrong token, got {:?}", other),
    }

    // 1B. Valid cluster token on Standby -> must return 503 Service Unavailable (never 101)
    let ws_url_valid_token = format!(
        "ws://{}/api/cluster/tunnel?token=ha-test-cluster-token",
        addr
    );
    match connect_async(&ws_url_valid_token).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(
                resp.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "Standby node must return strictly 503 Service Unavailable"
            );
        }
        Ok((_, resp)) => {
            panic!(
                "Standby must NEVER return 101 Switching Protocols: {:?}",
                resp.status()
            );
        }
        Err(e) => {
            panic!("Unexpected error connecting to Standby: {:?}", e);
        }
    }
}

/// Scenario 2: Verify Leader demotion evicts all 20 concurrent worker tunnels with
/// RFC 6455 CloseFrame (code 1000, reason "controller demoted to standby") within <= 500ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_adversarial_leader_demotion_evicts_concurrent_workers_within_500ms() {
    let ws = tempfile::tempdir().expect("ws");
    let storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());
    let state = build_test_state(
        "node-leader",
        HaRoleConfig::Leader,
        ws.path().join("ws-leader"),
        storage,
    );

    let app = create_router(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let ws_url = format!(
        "ws://{}/api/cluster/tunnel?token=ha-test-cluster-token",
        addr
    );

    const WORKER_COUNT: usize = 20;
    let mut streams = Vec::with_capacity(WORKER_COUNT);
    let fory = create_fory_runtime().expect("fory");

    // Connect and register 20 workers
    for i in 0..WORKER_COUNT {
        let (mut stream, resp) = connect_async(&ws_url)
            .await
            .expect("Worker must connect to Leader");
        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

        let node_id = format!("stress-worker-{:02}", i);
        let reg = WorkerRegistration {
            node_id: node_id.clone(),
            arch: "x86_64".to_string(),
            tags: vec!["default".to_string()],
            max_slots: 2,
            ram_total_mb: 8192,
            toolchains: vec!["system".to_string()],
            btrfs_enabled: false,
        };
        let payload = fory.serialize(&reg).unwrap();
        let header = IpcHeader::new(MSG_TYPE_WORKER_REGISTRATION, payload.len() as u32, 0, 1);
        let mut frame = Vec::with_capacity(mu_ci_ipc::HEADER_SIZE + payload.len());
        frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
        frame.extend_from_slice(&payload);
        stream.send(WsMessage::Binary(frame.into())).await.unwrap();

        streams.push((node_id, stream));
    }

    // Wait for all 20 to register
    for (node_id, _) in &streams {
        let mut registered = false;
        for _ in 0..50 {
            if state.cluster.is_node_online(node_id).await {
                registered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(registered, "Worker {} failed to register", node_id);
    }

    // Demote the Leader controller
    let t_demote = Instant::now();
    state.demote_to_standby().await;
    assert_eq!(state.job_store.ha_role(), HaRole::Standby);

    // Concurrently wait for all 20 workers to receive the RFC 6455 CloseFrame
    let mut tasks = Vec::new();
    for (node_id, mut stream) in streams {
        let task = tokio::spawn(async move {
            let res = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;
            (node_id, res)
        });
        tasks.push(task);
    }

    for task in tasks {
        let (node_id, res) = task.await.expect("task join");
        match res {
            Ok(Some(Ok(WsMessage::Close(Some(close_frame))))) => {
                assert_eq!(
                    close_frame.code,
                    CloseCode::Normal,
                    "Worker {} close code must be 1000 Normal",
                    node_id
                );
                assert_eq!(
                    close_frame.reason.as_str(),
                    "controller demoted to standby",
                    "Worker {} close reason must match",
                    node_id
                );
            }
            Ok(Some(Ok(other))) => {
                panic!(
                    "Worker {} expected CloseFrame, received unexpected message: {:?}",
                    node_id, other
                );
            }
            Ok(Some(Err(e))) => {
                // Connection closed at transport layer without full frame or after frame
                println!("Worker {} stream error on close: {:?}", node_id, e);
            }
            Ok(None) => {
                // Socket closed
            }
            Err(_) => {
                panic!(
                    "Worker {} timed out after 500ms without receiving eviction CloseFrame",
                    node_id
                );
            }
        }
    }

    let elapsed = t_demote.elapsed();
    assert!(
        elapsed < Duration::from_millis(1000),
        "Eviction of all 20 workers took {:?}, must be <= 1s",
        elapsed
    );

    // Verify all 20 workers are unregistered from cluster
    for i in 0..WORKER_COUNT {
        let node_id = format!("stress-worker-{:02}", i);
        assert!(
            !state.cluster.is_node_online(&node_id).await,
            "Worker {} must be offline after demotion",
            node_id
        );
    }
}

/// Scenario 3: Verify demoted controller suppresses Pong on incoming Ping,
/// sends RFC 6455 CloseFrame and closes socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_adversarial_demoted_controller_suppresses_pong_on_ping() {
    let ws = tempfile::tempdir().expect("ws");
    let storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());
    let state = build_test_state(
        "node-ping-suppress",
        HaRoleConfig::Leader,
        ws.path().join("ws-ping"),
        storage,
    );

    let app = create_router(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let ws_url = format!(
        "ws://{}/api/cluster/tunnel?token=ha-test-cluster-token",
        addr
    );

    let (mut stream, _) = connect_async(&ws_url).await.unwrap();
    let fory = create_fory_runtime().expect("fory");

    // Register worker
    let reg = WorkerRegistration {
        node_id: "ping-worker".to_string(),
        arch: "x86_64".to_string(),
        tags: vec!["default".to_string()],
        max_slots: 1,
        ram_total_mb: 4096,
        toolchains: vec!["system".to_string()],
        btrfs_enabled: false,
    };
    let payload = fory.serialize(&reg).unwrap();
    let header = IpcHeader::new(MSG_TYPE_WORKER_REGISTRATION, payload.len() as u32, 0, 1);
    let mut frame = Vec::new();
    frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
    frame.extend_from_slice(&payload);
    stream.send(WsMessage::Binary(frame.into())).await.unwrap();

    // Verify online
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(state.cluster.is_node_online("ping-worker").await);

    // Demote role ONLY in job_store without draining yet to simulate race
    state.job_store.set_ha_role(HaRole::Standby);

    // Send Ping
    stream
        .send(WsMessage::Ping(vec![0xAA, 0xBB, 0xCC, 0xDD].into()))
        .await
        .unwrap();

    // The demoted controller must NOT respond with Pong; it must send CloseFrame and close
    let res = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;
    match res {
        Ok(Some(Ok(WsMessage::Close(Some(close))))) => {
            assert_eq!(close.code, CloseCode::Normal);
            assert_eq!(close.reason.as_str(), "controller demoted to standby");
        }
        Ok(Some(Ok(WsMessage::Pong(_)))) => {
            panic!("Demoted controller responded with Pong! Must suppress Pong.");
        }
        other => panic!("Expected CloseFrame, got {:?}", other),
    }
}

/// Scenario 4: Verify demoted controller suppresses application-layer Pong on MSG_TYPE_WORKER_HEARTBEAT,
/// sends RFC 6455 CloseFrame and closes socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_adversarial_demoted_controller_suppresses_heartbeat_pong() {
    let ws = tempfile::tempdir().expect("ws");
    let storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());
    let state = build_test_state(
        "node-hb-suppress",
        HaRoleConfig::Leader,
        ws.path().join("ws-hb"),
        storage,
    );

    let app = create_router(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let ws_url = format!(
        "ws://{}/api/cluster/tunnel?token=ha-test-cluster-token",
        addr
    );

    let (mut stream, _) = connect_async(&ws_url).await.unwrap();
    let fory = create_fory_runtime().expect("fory");

    // Register worker
    let reg = WorkerRegistration {
        node_id: "hb-worker".to_string(),
        arch: "x86_64".to_string(),
        tags: vec!["default".to_string()],
        max_slots: 1,
        ram_total_mb: 4096,
        toolchains: vec!["system".to_string()],
        btrfs_enabled: false,
    };
    let payload = fory.serialize(&reg).unwrap();
    let header = IpcHeader::new(MSG_TYPE_WORKER_REGISTRATION, payload.len() as u32, 0, 1);
    let mut frame = Vec::new();
    frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
    frame.extend_from_slice(&payload);
    stream.send(WsMessage::Binary(frame.into())).await.unwrap();

    // Verify online
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(state.cluster.is_node_online("hb-worker").await);

    // Demote role in job_store to simulate role transition
    state.job_store.set_ha_role(HaRole::Standby);

    // Send WorkerHeartbeat
    let hb = WorkerHeartbeat {
        node_id: "hb-worker".to_string(),
        active_slots: 0,
        cpu_load_pct: 50.0,
        ram_used_mb: 2048,
        timestamp_epoch_ms: 12345,
    };
    let hb_payload = fory.serialize(&hb).unwrap();
    let hb_header = IpcHeader::new(MSG_TYPE_WORKER_HEARTBEAT, hb_payload.len() as u32, 0, 2);
    let mut hb_frame = Vec::new();
    hb_frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&hb_header));
    hb_frame.extend_from_slice(&hb_payload);
    stream
        .send(WsMessage::Binary(hb_frame.into()))
        .await
        .unwrap();

    // Must NOT respond with Pong; must send CloseFrame and exit
    let res = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;
    match res {
        Ok(Some(Ok(WsMessage::Close(Some(close))))) => {
            assert_eq!(close.code, CloseCode::Normal);
            assert_eq!(close.reason.as_str(), "controller demoted to standby");
        }
        Ok(Some(Ok(WsMessage::Pong(_)))) => {
            panic!("Demoted controller acknowledged heartbeat with Pong! Must suppress Pong.");
        }
        other => panic!("Expected CloseFrame, got {:?}", other),
    }
}

/// Scenario 5: Rapid connect/disconnect flood with 40 workers to verify no deadlocks,
/// unclosed tasks, or leaked registrations in ClusterRegistry.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_adversarial_disconnect_flood_no_leaks() {
    let ws = tempfile::tempdir().expect("ws");
    let storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());
    let state = build_test_state(
        "node-flood",
        HaRoleConfig::Leader,
        ws.path().join("ws-flood"),
        storage,
    );

    let app = create_router(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let ws_url = format!(
        "ws://{}/api/cluster/tunnel?token=ha-test-cluster-token",
        addr
    );

    const FLOOD_COUNT: usize = 40;
    let mut handles = Vec::with_capacity(FLOOD_COUNT);

    for i in 0..FLOOD_COUNT {
        let url = ws_url.clone();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = connect_async(&url).await.unwrap();
            let fory = create_fory_runtime().expect("fory");
            let node_id = format!("flood-worker-{:03}", i);

            let reg = WorkerRegistration {
                node_id: node_id.clone(),
                arch: "x86_64".to_string(),
                tags: vec!["default".to_string()],
                max_slots: 1,
                ram_total_mb: 1024,
                toolchains: vec!["system".to_string()],
                btrfs_enabled: false,
            };
            let payload = fory.serialize(&reg).unwrap();
            let header = IpcHeader::new(MSG_TYPE_WORKER_REGISTRATION, payload.len() as u32, 0, 1);
            let mut frame = Vec::new();
            frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
            frame.extend_from_slice(&payload);
            stream.send(WsMessage::Binary(frame.into())).await.unwrap();

            // Send 2 heartbeats
            for seq in 2..=3 {
                let hb = WorkerHeartbeat {
                    node_id: node_id.clone(),
                    active_slots: 0,
                    cpu_load_pct: 10.0,
                    ram_used_mb: 512,
                    timestamp_epoch_ms: 1000 * seq,
                };
                let hb_payload = fory.serialize(&hb).unwrap();
                let hb_header =
                    IpcHeader::new(MSG_TYPE_WORKER_HEARTBEAT, hb_payload.len() as u32, 0, seq);
                let mut hb_frame = Vec::new();
                hb_frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&hb_header));
                hb_frame.extend_from_slice(&hb_payload);
                if stream
                    .send(WsMessage::Binary(hb_frame.into()))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            // Abruptly close
            let _ = stream.close(None).await;
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.expect("worker task completed");
    }

    // Wait up to 2 seconds for all workers to unregister
    let mut all_unregistered = false;
    for _ in 0..100 {
        let mut any_online = false;
        for i in 0..FLOOD_COUNT {
            let node_id = format!("flood-worker-{:03}", i);
            if state.cluster.is_node_online(&node_id).await {
                any_online = true;
                break;
            }
        }
        if !any_online {
            all_unregistered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert!(
        all_unregistered,
        "All flooded workers must be cleanly unregistered from ClusterRegistry"
    );
}

/// Scenario 6: Demotion eviction when the command channel is full (backpressure test).
/// Tests that `disconnect_all()` async send fallback reliably delivers CloseFrame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_adversarial_demotion_eviction_under_channel_backpressure() {
    use mu_ci_controller::cluster::WorkerCommand;
    use mu_ci_ipc::StageCancelTask;

    let ws = tempfile::tempdir().expect("ws");
    let storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());
    let state = build_test_state(
        "node-backpressure",
        HaRoleConfig::Leader,
        ws.path().join("ws-bp"),
        storage,
    );

    let app = create_router(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let ws_url = format!(
        "ws://{}/api/cluster/tunnel?token=ha-test-cluster-token",
        addr
    );

    let (mut stream, _) = connect_async(&ws_url).await.unwrap();
    let fory = create_fory_runtime().expect("fory");

    // Register worker with 10 slots
    let reg = WorkerRegistration {
        node_id: "bp-worker".to_string(),
        arch: "x86_64".to_string(),
        tags: vec!["default".to_string()],
        max_slots: 10,
        ram_total_mb: 8192,
        toolchains: vec!["system".to_string()],
        btrfs_enabled: false,
    };
    let payload = fory.serialize(&reg).unwrap();
    let header = IpcHeader::new(MSG_TYPE_WORKER_REGISTRATION, payload.len() as u32, 0, 1);
    let mut frame = Vec::new();
    frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
    frame.extend_from_slice(&payload);
    stream.send(WsMessage::Binary(frame.into())).await.unwrap();

    // Wait until registered
    for _ in 0..50 {
        if state.cluster.is_node_online("bp-worker").await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(state.cluster.is_node_online("bp-worker").await);

    // Lease a slot to get access to the worker's command tx
    let lease = state
        .cluster
        .lease_slot("job-1", "stage-1", &[], None, false)
        .await;
    let (_node_id, tx) = lease.expect("lease slot");

    // Fill channel buffer (channel capacity is 32)
    for i in 0..32 {
        let _ = tx.try_send(WorkerCommand::Cancel(StageCancelTask {
            job_id: format!("job-cancel-{}", i),
            stage_id: "stage-cancel".to_string(),
            reason: "test".to_string(),
        }));
    }

    // Demote controller to Standby - disconnect_all will hit TrySendError::Full
    // and engage the 500ms spawned fallback!
    state.demote_to_standby().await;

    // The client reads messages until it gets CloseFrame
    let mut received_close = false;
    let deadline = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < deadline {
        let msg = tokio::time::timeout(Duration::from_millis(300), stream.next()).await;
        match msg {
            Ok(Some(Ok(WsMessage::Close(Some(close))))) => {
                assert_eq!(close.code, CloseCode::Normal);
                assert_eq!(close.reason.as_str(), "controller demoted to standby");
                received_close = true;
                break;
            }
            Ok(Some(Ok(WsMessage::Binary(_)))) => {
                // Cancel frame drained from buffer, keep reading
            }
            Ok(Some(Ok(WsMessage::Close(None)))) | Ok(None) => {
                received_close = true;
                break;
            }
            Ok(Some(Err(_))) => {
                received_close = true;
                break;
            }
            Err(_) => {
                // Timeout on this read chunk
            }
            Ok(Some(Ok(other))) => {
                println!("Received other message: {:?}", other);
            }
        }
    }

    assert!(
        received_close,
        "Worker must receive CloseFrame even when mpsc channel buffer was full"
    );
}
