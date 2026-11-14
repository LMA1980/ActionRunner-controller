//! Integration tests for Issue #104:
//! "Prevent Gray-Failure HA Deadlocks: Decouple JobStore Write Lock from Remote Storage RPCs & Enforce Bidirectional Tunnel Liveness"
//!
//! - Test 1: `test_gray_failure_jobstore_reads_never_blocked_by_slow_storage_rpc`
//! - Test 2: `test_standby_tunnel_rejection_and_demotion_eviction`

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use mu_ci_controller::app::create_router;
use mu_ci_controller::cluster::ClusterRegistry;
use mu_ci_controller::config::{Config, HaRole, HaRoleConfig};
use mu_ci_controller::console::{ConsoleConfig, ConsoleState};
use mu_ci_controller::job::{Job, JobRecord, JobStore};
use mu_ci_controller::storage_backend::{ControllerStorage, InMemoryStorage, LeaderLease};
use mu_ci_controller::webhook::AppState;
use mu_ci_ipc::{
    create_fory_runtime, IpcHeader, WorkerHeartbeat, WorkerRegistration, MSG_TYPE_WORKER_HEARTBEAT,
    MSG_TYPE_WORKER_REGISTRATION,
};
use mu_observable_ipc::{
    CentralBranchSnapshot, CentralSubmoduleSnapshot, RegressionGateReport, RegressionGateRequest,
};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Mock StorageBackend with Injected Latency / Gray-Failure Simulation
// ---------------------------------------------------------------------------

pub struct SlowStorageBackend {
    inner: Arc<dyn ControllerStorage>,
    delay: Duration,
    pub upsert_active: Arc<AtomicBool>,
    pub upsert_count: Arc<AtomicUsize>,
}

impl SlowStorageBackend {
    pub fn new(delay: Duration) -> Self {
        Self {
            inner: Arc::new(InMemoryStorage::open()),
            delay,
            upsert_active: Arc::new(AtomicBool::new(false)),
            upsert_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl ControllerStorage for SlowStorageBackend {
    fn upsert_record(&self, record: &JobRecord) {
        self.upsert_count.fetch_add(1, Ordering::SeqCst);
        self.upsert_active.store(true, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.inner.upsert_record(record);
        self.upsert_active.store(false, Ordering::SeqCst);
    }

    fn upsert_records_batch(&self, records: &[JobRecord]) {
        self.upsert_count.fetch_add(1, Ordering::SeqCst);
        self.upsert_active.store(true, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        self.inner.upsert_records_batch(records);
        self.upsert_active.store(false, Ordering::SeqCst);
    }

    fn load_recent_jobs(&self, limit: usize) -> Vec<JobRecord> {
        self.inner.load_recent_jobs(limit)
    }

    fn load_branch_snapshots(
        &self,
        repo_key: Option<&str>,
        branch_key: Option<&str>,
    ) -> Vec<CentralBranchSnapshot> {
        self.inner.load_branch_snapshots(repo_key, branch_key)
    }

    fn load_submodule_snapshots(
        &self,
        parent_repo_key: Option<&str>,
        submodule_key: Option<&str>,
        branch_key: Option<&str>,
    ) -> Vec<CentralSubmoduleSnapshot> {
        self.inner
            .load_submodule_snapshots(parent_repo_key, submodule_key, branch_key)
    }

    fn get_job(&self, job_id: &str) -> Option<JobRecord> {
        self.upsert_count.fetch_add(1, Ordering::SeqCst);
        self.upsert_active.store(true, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        let res = self.inner.get_job(job_id);
        self.upsert_active.store(false, Ordering::SeqCst);
        res
    }

    fn find_card_context(
        &self,
        repo: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        self.inner.find_card_context(repo, branch)
    }

    fn find_submodule_card_context(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        self.inner
            .find_submodule_card_context(parent_repo, submodule, branch)
    }

    fn evaluate_regression_gate(
        &self,
        req: &RegressionGateRequest,
    ) -> Option<RegressionGateReport> {
        self.inner.evaluate_regression_gate(req)
    }

    fn append_job_log(&self, job_id: &str, chunk: &str) {
        self.inner.append_job_log(job_id, chunk);
    }

    fn get_job_log(&self, job_id: &str) -> Option<String> {
        self.inner.get_job_log(job_id)
    }

    fn try_acquire_or_renew_lease(&self, holder_id: &str, ttl_secs: u64, force: bool) -> bool {
        self.inner
            .try_acquire_or_renew_lease(holder_id, ttl_secs, force)
    }

    fn release_lease(&self, holder_id: &str) {
        self.inner.release_lease(holder_id);
    }

    fn get_leader_lease(&self) -> Option<LeaderLease> {
        self.inner.get_leader_lease()
    }

    fn save_console_registry(&self, registry_json: &str) {
        self.inner.save_console_registry(registry_json);
    }

    fn load_console_registry(&self) -> Option<String> {
        self.inner.load_console_registry()
    }

    fn configure_auth_state_path(&self, path: &std::path::Path) {
        self.inner.configure_auth_state_path(path);
    }

    fn auth_catalog(&self) -> Option<&mu_ci_controller::db::CatalogStore> {
        self.inner.auth_catalog()
    }

    fn sync_platform_auth_json(&self, json: &str) {
        self.inner.sync_platform_auth_json(json);
    }

    fn seed_bootstrap_admins(&self, admins: &[String]) {
        self.inner.seed_bootstrap_admins(admins);
    }
}

// ---------------------------------------------------------------------------
// Helper: Build AppState with Custom Configuration & Storage
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Test 1: JobStore Concurrency & Storage Latency Isolation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_gray_failure_jobstore_reads_never_blocked_by_slow_storage_rpc() {
    let ws = tempfile::tempdir().expect("ws");
    let storage_delay = Duration::from_millis(500);
    let slow_storage = Arc::new(SlowStorageBackend::new(storage_delay));
    let upsert_active = Arc::clone(&slow_storage.upsert_active);

    let state = build_test_state(
        "node-a",
        HaRoleConfig::Leader,
        ws.path().to_path_buf(),
        slow_storage,
    );
    assert_eq!(state.job_store.ha_role(), HaRole::Leader);

    // Seed one completed job into the store so queue and job queries have data
    let seed_job = Job {
        id: "job-seed-001".to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/ActionRunner-controller".to_string(),
        clone_url: "https://github.com/LMA1980/ActionRunner-controller.git".to_string(),
        commit_sha: "0000111122223333444455556666777788889999".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
        pr_number: None,
    };
    state
        .job_store
        .enqueue_job(seed_job, PathBuf::from("logs/seed.log"))
        .await;

    let app = create_router(state.clone());

    // 1. Launch a background mutation: enqueueing a new job which triggers a 500ms storage RPC
    let mutating_job = Job {
        id: "job-slow-storage-002".to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/ActionRunner-controller".to_string(),
        clone_url: "https://github.com/LMA1980/ActionRunner-controller.git".to_string(),
        commit_sha: "aaaabbbbccccddddeeeeffff0000111122223333".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
        pr_number: None,
    };

    let store_clone = state.job_store.clone();
    let mutation_handle = tokio::spawn(async move {
        store_clone
            .enqueue_job(mutating_job, PathBuf::from("logs/slow.log"))
            .await;
    });

    // Wait until the storage backend is actively sleeping inside `upsert_record`
    for _ in 0..100 {
        if upsert_active.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        upsert_active.load(Ordering::SeqCst),
        "Storage backend must be actively processing the slow upsert RPC"
    );

    // 2. Perform concurrent read operations while storage is blocked:
    // Operation A: Direct in-memory queue snapshot
    let t0 = std::time::Instant::now();
    let snap = state.job_store.queue_snapshot().await;
    let snap_duration = t0.elapsed();
    assert!(
        snap_duration < Duration::from_millis(50),
        "queue_snapshot must complete in sub-millisecond/sub-50ms time, took {:?}",
        snap_duration
    );
    assert!(snap.stats.total_jobs >= 1);

    // Operation B: Direct in-memory job list query
    let t1 = std::time::Instant::now();
    let jobs = state.job_store.list_jobs().await;
    let list_duration = t1.elapsed();
    assert!(
        list_duration < Duration::from_millis(50),
        "list_jobs must complete in sub-millisecond/sub-50ms time, took {:?}",
        list_duration
    );
    assert!(!jobs.is_empty());

    // Operation C: HTTP GET /health check
    let t2 = std::time::Instant::now();
    let resp_health = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let health_duration = t2.elapsed();
    assert_eq!(resp_health.status(), StatusCode::OK);
    assert!(
        health_duration < Duration::from_millis(100),
        "GET /health must not block on remote storage RPC, took {:?}",
        health_duration
    );

    // Operation D: HTTP GET /queue inspection
    let t3 = std::time::Instant::now();
    let resp_queue = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/queue")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let queue_duration = t3.elapsed();
    assert_eq!(resp_queue.status(), StatusCode::OK);
    assert!(
        queue_duration < Duration::from_millis(100),
        "GET /queue must not block on remote storage RPC, took {:?}",
        queue_duration
    );

    // Operation E: HTTP GET /api/cluster/status inspection
    let t4 = std::time::Instant::now();
    let resp_status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/cluster/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status_duration = t4.elapsed();
    assert_eq!(resp_status.status(), StatusCode::OK);
    assert!(
        status_duration < Duration::from_millis(100),
        "GET /api/cluster/status must not block on remote storage RPC, took {:?}",
        status_duration
    );

    // Wait for the mutation to finish
    let _ = mutation_handle.await;

    // Verify final state consistency
    let final_jobs = state.job_store.list_jobs().await;
    assert_eq!(final_jobs.len(), 2);
    assert!(final_jobs
        .iter()
        .any(|j| j.job.id == "job-slow-storage-002"));

    // 3. Verify resume_job with remote get_job RPC does not hold read lock across RPC
    let store_clone2 = state.job_store.clone();
    let resume_handle = tokio::spawn(async move {
        let _ = store_clone2.resume_job("job-missing-999").await;
    });

    for _ in 0..100 {
        if upsert_active.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        upsert_active.load(Ordering::SeqCst),
        "Storage backend must be actively processing the slow get_job RPC"
    );

    // Measure write operation latency while storage get_job is active
    let t_write = std::time::Instant::now();
    state
        .job_store
        .requeue_preserving_priority("job-slow-storage-002")
        .await;
    let write_duration = t_write.elapsed();
    assert!(
        write_duration < Duration::from_millis(100),
        "JobStore write operations must not be blocked while resume_job calls get_job, took {:?}",
        write_duration
    );

    let _ = resume_handle.await;
}

// ---------------------------------------------------------------------------
// Test 2: Standby Tunnel Rejection & Demotion Eviction
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_standby_tunnel_rejection_and_demotion_eviction() {
    let ws = tempfile::tempdir().expect("ws");
    let shared_storage: Arc<dyn ControllerStorage> = Arc::new(InMemoryStorage::open());

    // -----------------------------------------------------------------------
    // Part 2A: Standby Tunnel Connection Rejection
    // -----------------------------------------------------------------------
    let state_standby = build_test_state(
        "node-b",
        HaRoleConfig::Standby,
        ws.path().join("ws-b"),
        Arc::clone(&shared_storage),
    );
    assert_eq!(state_standby.job_store.ha_role(), HaRole::Standby);

    let app_standby = create_router(state_standby.clone());
    let listener_standby = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_standby = listener_standby.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener_standby, app_standby).await.unwrap();
    });

    let ws_url_standby = format!(
        "ws://{}/api/cluster/tunnel?token=ha-test-cluster-token",
        addr_standby
    );

    // Connecting to a Standby controller must fail during upgrade (503 Service Unavailable) or close immediately
    let connect_res = connect_async(&ws_url_standby).await;
    match connect_res {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(
                resp.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "Standby node must reject tunnel handshake with HTTP 503"
            );
        }
        Ok((mut stream, _resp)) => {
            // Alternatively, if upgraded, it must close the stream immediately
            let next_msg = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;
            match next_msg {
                Ok(Some(Ok(WsMessage::Close(_)))) | Ok(None) => {}
                other => panic!(
                    "Standby node accepted tunnel without immediate closure: {:?}",
                    other
                ),
            }
        }
        Err(e) => {
            // Connection refused or terminated
            assert!(
                e.to_string().contains("503") || e.to_string().contains("refused"),
                "Expected 503 rejection: {:?}",
                e
            );
        }
    }

    // -----------------------------------------------------------------------
    // Part 2B: Leader Connection & Bidirectional Heartbeat Exchange
    // -----------------------------------------------------------------------
    let state_leader = build_test_state(
        "node-a",
        HaRoleConfig::Leader,
        ws.path().join("ws-a"),
        Arc::clone(&shared_storage),
    );
    assert_eq!(state_leader.job_store.ha_role(), HaRole::Leader);

    let app_leader = create_router(state_leader.clone());
    let listener_leader = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_leader = listener_leader.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener_leader, app_leader).await.unwrap();
    });

    let ws_url_leader = format!(
        "ws://{}/api/cluster/tunnel?token=ha-test-cluster-token",
        addr_leader
    );

    let (mut ws_stream, resp) = connect_async(&ws_url_leader)
        .await
        .expect("Worker must successfully connect to Leader");
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);

    let fory = create_fory_runtime().expect("fory");

    // Send WorkerRegistration
    let reg = WorkerRegistration {
        node_id: "mock-worker-1".to_string(),
        arch: "x86_64".to_string(),
        tags: vec!["fmt".to_string(), "clippy".to_string()],
        max_slots: 2,
        ram_total_mb: 32768,
        toolchains: vec!["system".to_string()],
        btrfs_enabled: false,
        rust_semver: None,
    };
    let payload = fory.serialize(&reg).expect("serialize reg");
    let header = IpcHeader::new(MSG_TYPE_WORKER_REGISTRATION, payload.len() as u32, 0, 1);
    let mut reg_frame = Vec::with_capacity(mu_ci_ipc::HEADER_SIZE + payload.len());
    reg_frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
    reg_frame.extend_from_slice(&payload);
    ws_stream
        .send(WsMessage::Binary(reg_frame.into()))
        .await
        .expect("send reg");

    // Verify worker registration in ClusterRegistry
    let mut is_online = false;
    for _ in 0..50 {
        if state_leader.cluster.is_node_online("mock-worker-1").await {
            is_online = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(is_online, "Worker must be registered and online on Leader");

    // Send WorkerHeartbeat
    let hb = WorkerHeartbeat {
        node_id: "mock-worker-1".to_string(),
        active_slots: 0,
        cpu_load_pct: 12.0,
        ram_used_mb: 1024,
        timestamp_epoch_ms: 1000,
    };
    let hb_payload = fory.serialize(&hb).expect("serialize hb");
    let hb_header = IpcHeader::new(MSG_TYPE_WORKER_HEARTBEAT, hb_payload.len() as u32, 0, 2);
    let mut hb_frame = Vec::with_capacity(mu_ci_ipc::HEADER_SIZE + hb_payload.len());
    hb_frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&hb_header));
    hb_frame.extend_from_slice(&hb_payload);
    ws_stream
        .send(WsMessage::Binary(hb_frame.into()))
        .await
        .expect("send heartbeat");

    // Receive Leader's Pong heartbeat acknowledgment
    let ack = tokio::time::timeout(Duration::from_secs(2), ws_stream.next()).await;
    match ack {
        Ok(Some(Ok(WsMessage::Pong(_)))) => {
            // Success: Bidirectional heartbeat exchange verified!
        }
        other => panic!("Expected WebSocket Pong heartbeat ACK, got {:?}", other),
    }

    // -----------------------------------------------------------------------
    // Part 2C: Demotion Eviction (Leader -> Standby Closes Active Tunnel)
    // -----------------------------------------------------------------------
    state_leader.demote_to_standby().await;
    assert_eq!(state_leader.job_store.ha_role(), HaRole::Standby);

    // The active WebSocket tunnel must be actively closed by the demoted controller
    let close_event = tokio::time::timeout(Duration::from_secs(2), ws_stream.next()).await;
    match close_event {
        Ok(Some(Ok(WsMessage::Close(_)))) | Ok(None) => {
            // Tunnel successfully closed upon controller demotion!
        }
        other => panic!(
            "Expected WebSocket Close frame upon controller demotion, got {:?}",
            other
        ),
    }

    // Verify worker is no longer online in ClusterRegistry
    assert!(
        !state_leader.cluster.is_node_online("mock-worker-1").await,
        "Worker must be unregistered from cluster after demotion"
    );

    // Subsequent connection attempts to the demoted controller must now be rejected
    let reconnect_res = connect_async(&ws_url_leader).await;
    match reconnect_res {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        Ok((mut stream, _)) => {
            let next_msg = tokio::time::timeout(Duration::from_millis(500), stream.next()).await;
            match next_msg {
                Ok(Some(Ok(WsMessage::Close(_)))) | Ok(None) => {}
                other => panic!("Demoted controller allowed reconnect: {:?}", other),
            }
        }
        Err(_) => {}
    }
}

// ---------------------------------------------------------------------------
// Test 3: High Concurrency Stress Test: Multiple Writers & Readers Under Slow RPCs
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn test_stress_concurrent_writers_and_readers_under_slow_storage_rpcs() {
    let ws = tempfile::tempdir().expect("ws");
    let storage_delay = Duration::from_millis(500);
    let slow_storage = Arc::new(SlowStorageBackend::new(storage_delay));
    let upsert_active = Arc::clone(&slow_storage.upsert_active);

    let state = build_test_state(
        "node-stress",
        HaRoleConfig::Leader,
        ws.path().to_path_buf(),
        slow_storage,
    );

    // Seed a job
    let job = Job {
        id: "job-stress-seed-000".to_string(),
        event_type: "push".to_string(),
        repo_name: "LMA1980/ActionRunner-controller".to_string(),
        clone_url: "https://github.com/LMA1980/ActionRunner-controller.git".to_string(),
        commit_sha: "1111222233334444555566667777888899990000".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
        pr_number: None,
    };
    state
        .job_store
        .enqueue_job(job, PathBuf::from("logs/seed.log"))
        .await;

    // Case A: resume_job for seed job (which exists in store)
    println!("--- Testing Case A: resume_job existing ---");
    let store_clone = state.job_store.clone();
    let writer_handle = tokio::spawn(async move {
        let _ = store_clone.resume_job("job-stress-seed-000").await;
    });

    for _ in 0..100 {
        if upsert_active.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(upsert_active.load(Ordering::SeqCst));

    let t0 = std::time::Instant::now();
    let _snap = state.job_store.queue_snapshot().await;
    let d0 = t0.elapsed();
    println!("Case A direct queue_snapshot took: {:?}", d0);
    assert!(
        d0 < Duration::from_millis(50),
        "Case A queue_snapshot exceeded 50ms ceiling: {:?}",
        d0
    );
    writer_handle.await.unwrap();

    // Case B: resume_job for missing job (which does get_job)
    println!("--- Testing Case B: resume_job missing ---");
    let store_clone = state.job_store.clone();
    let writer_b = tokio::spawn(async move {
        let _ = store_clone.resume_job("job-missing-999").await;
    });

    for _ in 0..100 {
        if upsert_active.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(upsert_active.load(Ordering::SeqCst));

    let t1 = std::time::Instant::now();
    let _snap = state.job_store.queue_snapshot().await;
    let d1 = t1.elapsed();
    println!("Case B direct queue_snapshot took: {:?}", d1);
    assert!(
        d1 < Duration::from_millis(50),
        "Case B queue_snapshot exceeded 50ms ceiling: {:?}",
        d1
    );
    writer_b.await.unwrap();

    // Case C: 4 concurrent writers (2 resume + 2 restart)
    println!("--- Testing Case C: 4 concurrent writers ---");
    let store_c1 = state.job_store.clone();
    let store_c2 = state.job_store.clone();
    let store_c3 = state.job_store.clone();
    let store_c4 = state.job_store.clone();
    let w1 = tokio::spawn(async move {
        let _ = store_c1.resume_job("job-missing-101").await;
    });
    let w2 = tokio::spawn(async move {
        let _ = store_c2.restart_job("job-stress-seed-000").await;
    });
    let w3 = tokio::spawn(async move {
        let _ = store_c3.resume_job("job-missing-102").await;
    });
    let w4 = tokio::spawn(async move {
        let _ = store_c4.restart_job("job-stress-seed-000").await;
    });

    for _ in 0..100 {
        if upsert_active.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(upsert_active.load(Ordering::SeqCst));

    let t2 = std::time::Instant::now();
    let _snap = state.job_store.queue_snapshot().await;
    let d2 = t2.elapsed();
    println!("Case C direct queue_snapshot took: {:?}", d2);
    assert!(
        d2 < Duration::from_millis(50),
        "Case C direct queue_snapshot exceeded 50ms ceiling: {:?}",
        d2
    );

    let mut readers = Vec::new();
    for _ in 0..20 {
        let st = state.job_store.clone();
        readers.push(tokio::spawn(async move {
            let start = std::time::Instant::now();
            let _snap = st.queue_snapshot().await;
            start.elapsed()
        }));
    }

    let mut max_d = Duration::ZERO;
    for r in readers {
        let d = r.await.unwrap();
        if d > max_d {
            max_d = d;
        }
    }
    println!("Case C 20 concurrent readers max duration: {:?}", max_d);
    assert!(
        max_d < Duration::from_millis(50),
        "Case C concurrent readers exceeded 50ms ceiling: {:?}",
        max_d
    );

    w1.await.unwrap();
    w2.await.unwrap();
    w3.await.unwrap();
    w4.await.unwrap();
}
