//! End-to-end Active-Standby High-Availability (HA) failover, single-leader lease,
//! `JobStore` + `ConsoleState` re-hydration, and shared job log fallback tests (`#72`–`#85`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use action_runner_controller::app::create_router;
use action_runner_controller::cluster::ClusterRegistry;
use action_runner_controller::config::{Config, HaRole, HaRoleConfig};
use action_runner_controller::console::{ConsoleConfig, ConsoleState};
use action_runner_controller::job::{Job, JobStatus, JobStore, StageRecord, StageStatus};
use action_runner_controller::storage_backend::{
    ControllerStorage, InMemoryStorage, MuObserveRemoteConfig, MuObserveRemoteStorage,
};
use action_runner_controller::webhook::AppState;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use muobserve_ipc::{
    decode_control_envelope, encode_control_envelope, read_frame, write_frame,
    CentralSubmoduleSnapshot, ControlRpcEnvelope, IpcHeader, QuerySubmoduleSnapshotsResponse,
    UpsertJobRecordResponse, MSG_TYPE_FORY_CONTROL,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tower::ServiceExt;

fn build_controller_state(
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
        metadata_ttl: std::time::Duration::from_secs(3600),
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

#[tokio::test]
async fn test_active_standby_lease_acquisition_and_standby_gate() {
    let shared_storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());
    let ws_a = tempfile::tempdir().expect("ws_a");
    let ws_b = tempfile::tempdir().expect("ws_b");

    // 1. node-a starts in Auto mode and acquires the initial leader lease (epoch 1)
    let state_a = build_controller_state(
        "node-a",
        HaRoleConfig::Auto,
        ws_a.path().to_path_buf(),
        Arc::clone(&shared_storage),
    );
    assert_eq!(state_a.job_store.ha_role(), HaRole::Leader);
    let lease = shared_storage.get_leader_lease().expect("lease present");
    assert_eq!(lease.holder_id, "node-a");
    assert_eq!(lease.epoch, 1);

    // 2. node-a enqueues and claims a running job, plus a second queued job
    let job1 = Job {
        id: "job-ha-running-1".to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/ActionRunner-controller".to_string(),
        clone_url: "https://github.com/LMA1980/ActionRunner-controller.git".to_string(),
        commit_sha: "1111111122222222333333334444444455555555".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };
    state_a
        .job_store
        .enqueue_job(
            job1.clone(),
            PathBuf::from("logs/LMA1980/ActionRunner-controller/job-ha-running-1.log"),
        )
        .await;
    let claimed = state_a
        .job_store
        .claim_next_queued_job(4)
        .await
        .expect("node-a leader should claim job1");
    assert_eq!(claimed.id, "job-ha-running-1");

    let job2 = Job {
        id: "job-ha-queued-2".to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/MuObserve".to_string(),
        clone_url: "https://github.com/LMA1980/MuObserve.git".to_string(),
        commit_sha: "6666666677777777888888889999999900000000".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };
    state_a
        .job_store
        .enqueue_job(
            job2.clone(),
            PathBuf::from("logs/LMA1980/MuObserve/job-ha-queued-2.log"),
        )
        .await;

    // 3. node-b starts in Auto mode while node-a's lease is active -> starts as Standby
    let state_b = build_controller_state(
        "node-b",
        HaRoleConfig::Auto,
        ws_b.path().to_path_buf(),
        Arc::clone(&shared_storage),
    );
    assert_eq!(state_b.job_store.ha_role(), HaRole::Standby);

    // 4. Verify node-b did NOT clobber node-a's Running job in storage or memory
    let stored_job1 = shared_storage
        .get_job("job-ha-running-1")
        .expect("job1 in storage");
    assert!(
        matches!(stored_job1.status, JobStatus::Running { .. }),
        "Standby startup must not reset primary's Running job to Queued"
    );
    let b_job1 = state_b
        .job_store
        .get_job("job-ha-running-1")
        .await
        .expect("job1 visible on standby");
    assert!(matches!(b_job1.status, JobStatus::Running { .. }));

    // 5. Verify Standby gate: node-b refuses to claim queued job2 while in Standby
    assert!(
        state_b.job_store.claim_next_queued_job(4).await.is_none(),
        "Standby controller must never claim queued jobs"
    );

    // 6. Verify /health and /api/cluster/status expose ha_role and controller_id on both nodes
    let app_a = create_router(state_a.clone());
    let resp_a = app_a
        .oneshot(
            Request::builder()
                .uri("/api/cluster/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_a.status(), StatusCode::OK);
    let body_a: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp_a.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body_a["controller_id"], "node-a");
    assert_eq!(body_a["ha_role"], "leader");

    let app_b = create_router(state_b.clone());
    let resp_b = app_b
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_b.status(), StatusCode::OK);
    let body_b: Value = serde_json::from_slice(
        &axum::body::to_bytes(resp_b.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body_b["controller_id"], "node-b");
    assert_eq!(body_b["ha_role"], "standby");
}

#[tokio::test]
async fn test_standby_promotion_rehydrates_job_store_and_console_state() {
    let shared_storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());
    let ws_a = tempfile::tempdir().expect("ws_a");
    let ws_b = tempfile::tempdir().expect("ws_b");

    let state_a = build_controller_state(
        "node-a",
        HaRoleConfig::Auto,
        ws_a.path().to_path_buf(),
        Arc::clone(&shared_storage),
    );
    let state_b = build_controller_state(
        "node-b",
        HaRoleConfig::Auto,
        ws_b.path().to_path_buf(),
        Arc::clone(&shared_storage),
    );
    assert_eq!(state_a.job_store.ha_role(), HaRole::Leader);
    assert_eq!(state_b.job_store.ha_role(), HaRole::Standby);

    // 1. Simulate GitHub push webhook on node-a for a feature branch on a public repository
    let push_payload = json!({
        "ref": "refs/heads/feat/ha-failover-drill",
        "before": "0000000000000000000000000000000000000000",
        "after": "abcdef1234567890abcdef1234567890abcdef12",
        "created": true,
        "deleted": false,
        "repository": {
            "full_name": "LMA1980/ActionRunner-controller",
            "private": false,
            "visibility": "public",
            "default_branch": "main"
        }
    });
    state_a
        .console
        .observe_webhook("push", &push_payload, &state_a.job_store)
        .await;

    // 2. Enqueue and start a multi-stage job on node-a with one Completed stage and one Running stage
    let job = Job {
        id: "job-inflight-failover-1".to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/ActionRunner-controller".to_string(),
        clone_url: "https://github.com/LMA1980/ActionRunner-controller.git".to_string(),
        commit_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
        ref_name: "refs/heads/feat/ha-failover-drill".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };
    state_a
        .job_store
        .enqueue_job(
            job.clone(),
            PathBuf::from("logs/LMA1980/ActionRunner-controller/job-inflight-failover-1.log"),
        )
        .await;
    let _ = state_a.job_store.claim_next_queued_job(4).await.unwrap();
    state_a
        .job_store
        .set_stages(
            &job.id,
            vec![
                StageRecord {
                    id: "fmt-check".to_string(),
                    name: "Format".to_string(),
                    tags: vec!["fmt".to_string()],
                    threads: 2,
                    toolchain: None,
                    depends_on: Vec::new(),
                    status: StageStatus::Completed {
                        duration_secs: 4,
                        exit_code: 0,
                    },
                    assigned_node: Some("node-a".to_string()),
                },
                StageRecord {
                    id: "native-k3".to_string(),
                    name: "Native Verification".to_string(),
                    tags: vec!["k3".to_string()],
                    threads: 6,
                    toolchain: None,
                    depends_on: vec!["fmt-check".to_string()],
                    status: StageStatus::Running {
                        node_id: "worker-riscv64".to_string(),
                        started_at: Utc::now(),
                        pid: Some(4242),
                    },
                    assigned_node: Some("worker-riscv64".to_string()),
                },
            ],
        )
        .await;

    // 3. Standby periodic tick on node-b warms JobStore & ConsoleState without clobbering Running state
    state_b.tick_ha_coordinator().await;
    assert_eq!(state_b.job_store.ha_role(), HaRole::Standby);

    let app_b = create_router(state_b.clone());
    let repos_resp = app_b
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/repos")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(repos_resp.status(), StatusCode::OK);
    let repos_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(repos_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(repos_json["repos"].as_array().unwrap().len(), 1);
    assert_eq!(repos_json["repos"][0]["repo"], "ActionRunner-controller");

    let topo_resp = app_b
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/repos/LMA1980/ActionRunner-controller/topology")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(topo_resp.status(), StatusCode::OK);
    let topo_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(topo_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        topo_json["branches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["ref"] == "feat/ha-failover-drill"),
        "Standby topology must include feat/ha-failover-drill siding synced from storage"
    );

    // 4. Promote node-b via POST /api/ha/promote (simulating primary outage / operator promotion)
    let promote_resp = app_b
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/ha/promote")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(promote_resp.status(), StatusCode::OK);
    let promote_json: Value = serde_json::from_slice(
        &axum::body::to_bytes(promote_resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(promote_json["controller_id"], "node-b");
    assert_eq!(promote_json["ha_role"], "leader");
    assert_eq!(promote_json["leader_lease"]["holder_id"], "node-b");
    assert_eq!(promote_json["leader_lease"]["epoch"], 2);

    // 5. Verify interrupted Running job was recovered to Queued with Completed stage preserved
    let recovered = state_b
        .job_store
        .get_job(&job.id)
        .await
        .expect("recovered job present on node-b");
    assert_eq!(recovered.status, JobStatus::Queued);
    assert_eq!(
        recovered.stages[0].status,
        StageStatus::Completed {
            duration_secs: 4,
            exit_code: 0
        }
    );
    assert_eq!(recovered.stages[1].status, StageStatus::Pending);
    assert_eq!(recovered.stages[1].assigned_node, None);

    // 6. Verify node-a steps down to Standby on its next coordinator tick after seeing epoch 2
    state_a.tick_ha_coordinator().await;
    assert_eq!(state_a.job_store.ha_role(), HaRole::Standby);

    // 7. Verify node-b (now Leader) can claim and resume the recovered job
    let claimed_by_b = state_b
        .job_store
        .claim_next_queued_job(4)
        .await
        .expect("promoted leader node-b must claim recovered job");
    assert_eq!(claimed_by_b.id, job.id);
}

#[tokio::test]
async fn test_shared_job_log_persistence_and_fallback_after_failover() {
    let shared_storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());
    let ws_a = tempfile::tempdir().expect("ws_a");
    let ws_b = tempfile::tempdir().expect("ws_b");

    let state_a = build_controller_state(
        "node-a",
        HaRoleConfig::Leader,
        ws_a.path().to_path_buf(),
        Arc::clone(&shared_storage),
    );
    let state_b = build_controller_state(
        "node-b",
        HaRoleConfig::Standby,
        ws_b.path().to_path_buf(),
        Arc::clone(&shared_storage),
    );

    let job_id = "job-shared-log-999".to_string();
    let job = Job {
        id: job_id.clone(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/ActionRunner-controller".to_string(),
        clone_url: "https://github.com/LMA1980/ActionRunner-controller.git".to_string(),
        commit_sha: "deadbeef12345678deadbeef12345678deadbeef".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };
    state_a
        .job_store
        .enqueue_job(
            job,
            PathBuf::from("logs/LMA1980/ActionRunner-controller/job-shared-log-999.log"),
        )
        .await;

    // Stream two log chunks on node-a (note: ws_b has NO local log file on disk)
    state_a.broadcast_log(
        &job_id,
        "2026-11-01T18:00:00Z [node-a] [fmt-check] [stdout] Formatting check passed\n",
    );
    state_a.broadcast_log(
        &job_id,
        "2026-11-01T18:00:05Z [worker-riscv64] [native-k3] [stdout] test result: ok. 42 passed; 0 failed\n",
    );
    state_a
        .job_store
        .update_status(
            &job_id,
            JobStatus::Completed {
                duration_secs: 5,
                exit_code: 0,
            },
        )
        .await;

    // Promote node-b (whose local workspace_dir ws_b has no log file on disk)
    let _ = state_b.promote_to_leader().await;
    let app_b = create_router(state_b);

    for path in [
        format!("/api/jobs/{job_id}/log"),
        format!("/api/jobs/{job_id}/logs"),
    ] {
        let resp = app_b
            .clone()
            .oneshot(Request::builder().uri(&path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let text = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("Formatting check passed"));
        assert!(text.contains("test result: ok. 42 passed; 0 failed"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_muobserve_remote_storage_ha_lease_and_log_roundtrip() {
    type SubSnapshotMap = BTreeMap<(String, String, String), CentralSubmoduleSnapshot>;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
    let addr = listener.local_addr().expect("local_addr");
    let sub_store: Arc<Mutex<SubSnapshotMap>> = Arc::new(Mutex::new(BTreeMap::new()));

    let store_clone = Arc::clone(&sub_store);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let store_conn = Arc::clone(&store_clone);
            tokio::spawn(async move {
                while let Ok((hdr, payload)) = read_frame(&mut stream).await {
                    let Ok(req) = decode_control_envelope(&payload) else {
                        break;
                    };
                    let resp = match req {
                        ControlRpcEnvelope::UpsertJobBatchReq(batch) => {
                            let mut g = store_conn.lock().unwrap();
                            for snap in batch.submodule_snapshots {
                                g.insert(
                                    (
                                        snap.parent_repo_key.clone(),
                                        snap.branch_key.clone(),
                                        snap.submodule_key.clone(),
                                    ),
                                    snap,
                                );
                            }
                            ControlRpcEnvelope::UpsertJobRecordResp(UpsertJobRecordResponse {
                                request_id: batch.request_id,
                                accepted: true,
                                upserted_count: 1,
                                error_message: None,
                            })
                        }
                        ControlRpcEnvelope::QuerySubmoduleSnapshotsReq(q) => {
                            let g = store_conn.lock().unwrap();
                            let snapshots: Vec<CentralSubmoduleSnapshot> = g
                                .values()
                                .filter(|s| {
                                    q.parent_repo_key
                                        .as_ref()
                                        .map(|p| &s.parent_repo_key == p)
                                        .unwrap_or(true)
                                        && q.branch_key
                                            .as_ref()
                                            .map(|b| &s.branch_key == b)
                                            .unwrap_or(true)
                                        && q.submodule_key
                                            .as_ref()
                                            .map(|k| &s.submodule_key == k)
                                            .unwrap_or(true)
                                })
                                .cloned()
                                .collect();
                            ControlRpcEnvelope::QuerySubmoduleSnapshotsResp(
                                QuerySubmoduleSnapshotsResponse {
                                    request_id: q.request_id,
                                    snapshots,
                                },
                            )
                        }
                        _ => break,
                    };
                    let out_bytes = encode_control_envelope(&resp).unwrap();
                    let out_hdr = IpcHeader::new(
                        MSG_TYPE_FORY_CONTROL,
                        out_bytes.len() as u32,
                        0,
                        hdr.sequence,
                    );
                    if write_frame(&mut stream, &out_hdr, &out_bytes)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });

    let remote_a =
        MuObserveRemoteStorage::new(MuObserveRemoteConfig::plain_tcp(addr.to_string())).unwrap();
    let remote_b =
        MuObserveRemoteStorage::new(MuObserveRemoteConfig::plain_tcp(addr.to_string())).unwrap();

    // 1. Lease acquisition & contention over MuObserve RPC
    assert!(remote_a.try_acquire_or_renew_lease("node-a", 15, false));
    assert!(!remote_b.try_acquire_or_renew_lease("node-b", 15, false));
    assert!(remote_b.try_acquire_or_renew_lease("node-b", 15, true));
    let lease = remote_a.get_leader_lease().expect("remote lease");
    assert_eq!(lease.holder_id, "node-b");
    assert_eq!(lease.epoch, 2);

    // 2. Shared job log append & retrieval across instances
    remote_a.append_job_log("job-rpc-1", "Stage 1 output\n");
    remote_a.append_job_log("job-rpc-1", "Stage 2 output\n");
    assert_eq!(
        remote_b.get_job_log("job-rpc-1").as_deref(),
        Some("Stage 1 output\nStage 2 output\n")
    );

    // 3. Normal submodule snapshot queries filter out internal __ar_* records
    assert!(remote_b
        .load_submodule_snapshots(None, None, None)
        .is_empty());
}

#[tokio::test]
async fn test_ha_failback_prevents_standby_queue_stall() {
    let shared_storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());
    let ws_a = tempfile::tempdir().expect("ws_a");
    let ws_b = tempfile::tempdir().expect("ws_b");

    // 1. Standby node-b (Auto) starts first while primary node-a is offline -> node-b holds epoch 1
    let state_b = build_controller_state(
        "node-b",
        HaRoleConfig::Auto,
        ws_b.path().to_path_buf(),
        Arc::clone(&shared_storage),
    );
    assert_eq!(state_b.job_store.ha_role(), HaRole::Leader);
    assert_eq!(
        shared_storage.get_leader_lease().unwrap().holder_id,
        "node-b"
    );

    // 2. Primary node-a starts in Auto mode before node-b's lease expires -> initially Standby,
    //    but HAProxy routes worker heartbeats to node-a (`is_online = true`).
    let state_a = build_controller_state(
        "node-a",
        HaRoleConfig::Auto,
        ws_a.path().to_path_buf(),
        Arc::clone(&shared_storage),
    );
    assert_eq!(state_a.job_store.ha_role(), HaRole::Standby);

    let (cmd_tx, _cmd_rx) = mpsc::channel(8);
    state_a
        .cluster
        .register(
            action_runner_ipc::WorkerRegistration {
                node_id: "worker-riscv64".to_string(),
                arch: "riscv64".to_string(),
                tags: vec!["riscv64".to_string(), "k3".to_string()],
                toolchains: vec!["system".to_string()],
                max_slots: 1,
                ram_total_mb: 32768,
                btrfs_enabled: false,
            },
            cmd_tx,
        )
        .await;

    // 3. Coordinator tick on node-a detects active worker heartbeats on Standby and reclaims leadership;
    //    subsequent tick on node-b steps down to Standby and disconnects any attached worker tunnels (#104).
    let (cmd_tx_b, mut cmd_rx_b) = mpsc::channel(8);
    state_b
        .cluster
        .register(
            action_runner_ipc::WorkerRegistration {
                node_id: "worker-stale-standby".to_string(),
                arch: "x86_64".to_string(),
                tags: vec!["default".to_string()],
                toolchains: vec!["system".to_string()],
                max_slots: 1,
                ram_total_mb: 32768,
                btrfs_enabled: true,
            },
            cmd_tx_b,
        )
        .await;

    state_a.tick_ha_coordinator().await;
    assert_eq!(state_a.job_store.ha_role(), HaRole::Leader);
    let lease = shared_storage.get_leader_lease().unwrap();
    assert_eq!(lease.holder_id, "node-a");
    assert_eq!(lease.epoch, 2);

    state_b.tick_ha_coordinator().await;
    assert_eq!(state_b.job_store.ha_role(), HaRole::Standby);
    assert!(
        state_b.cluster.list_nodes_view().await.is_empty(),
        "Standby step-down must disconnect attached worker tunnels"
    );
    assert!(matches!(
        cmd_rx_b.try_recv(),
        Ok(action_runner_controller::cluster::WorkerCommand::Disconnect)
    ));

    // A subsequent tick on node-b must stay Standby (no ping-pong) now that stale workers were disconnected
    state_b.tick_ha_coordinator().await;
    assert_eq!(state_b.job_store.ha_role(), HaRole::Standby);
    assert_eq!(
        shared_storage.get_leader_lease().unwrap().holder_id,
        "node-a"
    );

    // 4. Verify designated Leader policy (`HaRoleConfig::Leader`) also reclaims lease if demoted
    state_a.demote_to_standby().await;
    assert_eq!(state_a.job_store.ha_role(), HaRole::Standby);
    let ws_c = tempfile::tempdir().expect("ws_c");
    let state_c = build_controller_state(
        "node-c",
        HaRoleConfig::Leader,
        ws_c.path().to_path_buf(),
        Arc::clone(&shared_storage),
    );
    let _ = state_b.promote_to_leader().await;
    state_c.tick_ha_coordinator().await;
    assert_eq!(state_c.job_store.ha_role(), HaRole::Leader);
    assert_eq!(
        shared_storage.get_leader_lease().unwrap().holder_id,
        "node-c"
    );
}
