use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, patch},
    Json, Router,
};
use chrono::Utc;
use mu_ci_controller::cluster::{ClusterRegistry, WorkerCommand};
use mu_ci_controller::config::Config;
use mu_ci_controller::job::{Job, JobStatus, JobStore, StageStatus};
use mu_ci_controller::scheduler::DAGScheduler;
use mu_ci_ipc::WorkerRegistration;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path as StdPath;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MockPrComment {
    id: u64,
    pr_number: u64,
    body: String,
}

#[derive(Clone, Debug)]
struct MockStatusReport {
    sha: String,
    state: String,
    description: String,
    context: String,
}

#[derive(Default)]
struct MockGitHubState {
    next_comment_id: AtomicUsize,
    post_count: AtomicUsize,
    patch_count: AtomicUsize,
    comments: Mutex<Vec<MockPrComment>>,
    statuses: Mutex<Vec<MockStatusReport>>,
}

#[derive(Deserialize)]
struct CommentBodyPayload {
    body: String,
}

#[derive(Deserialize)]
struct StatusPayload {
    state: String,
    description: Option<String>,
    context: Option<String>,
}

async fn mock_list_pr_comments(
    State(state): State<Arc<MockGitHubState>>,
    Path((_owner, _repo, pr_number)): Path<(String, String, u64)>,
) -> Json<Vec<serde_json::Value>> {
    let comments = state.comments.lock().await;
    let list = comments
        .iter()
        .filter(|c| c.pr_number == pr_number)
        .map(|c| serde_json::json!({ "id": c.id, "body": c.body }))
        .collect();
    Json(list)
}

async fn mock_create_pr_comment(
    State(state): State<Arc<MockGitHubState>>,
    Path((_owner, _repo, pr_number)): Path<(String, String, u64)>,
    Json(payload): Json<CommentBodyPayload>,
) -> (StatusCode, Json<serde_json::Value>) {
    let id = state.next_comment_id.fetch_add(1, Ordering::SeqCst) as u64 + 100;
    state.post_count.fetch_add(1, Ordering::SeqCst);
    state.comments.lock().await.push(MockPrComment {
        id,
        pr_number,
        body: payload.body.clone(),
    });
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "body": payload.body })),
    )
}

async fn mock_patch_pr_comment(
    State(state): State<Arc<MockGitHubState>>,
    Path((_owner, _repo, comment_id)): Path<(String, String, u64)>,
    Json(payload): Json<CommentBodyPayload>,
) -> StatusCode {
    state.patch_count.fetch_add(1, Ordering::SeqCst);
    let mut comments = state.comments.lock().await;
    if let Some(existing) = comments.iter_mut().find(|c| c.id == comment_id) {
        existing.body = payload.body;
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn mock_create_status(
    State(state): State<Arc<MockGitHubState>>,
    Path((_owner, _repo, sha)): Path<(String, String, String)>,
    Json(payload): Json<StatusPayload>,
) -> StatusCode {
    state.statuses.lock().await.push(MockStatusReport {
        sha,
        state: payload.state,
        description: payload.description.unwrap_or_default(),
        context: payload.context.unwrap_or_default(),
    });
    StatusCode::CREATED
}

async fn start_mock_github_server() -> (String, Arc<MockGitHubState>) {
    let state = Arc::new(MockGitHubState::default());
    let app = Router::new()
        .route(
            "/repos/{owner}/{repo}/issues/{pr_number}/comments",
            get(mock_list_pr_comments).post(mock_create_pr_comment),
        )
        .route(
            "/repos/{owner}/{repo}/issues/comments/{comment_id}",
            patch(mock_patch_pr_comment),
        )
        .route(
            "/repos/{owner}/{repo}/statuses/{sha}",
            axum::routing::post(mock_create_status),
        )
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock github");
    let addr = listener.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), state)
}

fn make_worker_reg(node_id: &str, arch: &str, tags: &[&str]) -> WorkerRegistration {
    WorkerRegistration {
        node_id: node_id.to_string(),
        arch: arch.to_string(),
        tags: tags.iter().map(|t| (*t).to_string()).collect(),
        max_slots: 1,
        ram_total_mb: 32768,
        btrfs_enabled: false,
        toolchains: vec!["stable".to_string()],
        rust_semver: Some("1.86.0".to_string()),
    }
}

fn spawn_simulated_worker(
    node_id: String,
    mut rx: mpsc::Receiver<WorkerCommand>,
    cluster: ClusterRegistry,
    job_store: JobStore,
    executed: Arc<Mutex<Vec<(String, String)>>>,
) {
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            if let WorkerCommand::Dispatch(task) = cmd {
                job_store
                    .update_stage_running(&task.job_id, &task.stage_id, &node_id, 4242)
                    .await;
                sleep(Duration::from_millis(15)).await;
                executed
                    .lock()
                    .await
                    .push((node_id.clone(), task.stage_id.clone()));
                cluster
                    .release_stage_slot(&node_id, &task.job_id, &task.stage_id)
                    .await;
                job_store
                    .update_stage_status(
                        &task.job_id,
                        &task.stage_id,
                        StageStatus::Completed {
                            duration_secs: 1,
                            exit_code: 0,
                        },
                    )
                    .await;
                job_store.notify_event();
            }
        }
    });
}

async fn write_workflow_manifest(ws_path: &StdPath, repo_name: &str, yaml: &str) {
    let muci_dir = ws_path.join("repos").join(repo_name).join(".muci");
    tokio::fs::create_dir_all(&muci_dir)
        .await
        .expect("create .muci dir");
    tokio::fs::write(muci_dir.join("mu-ci.yml"), yaml)
        .await
        .expect("write mu-ci.yml");
}

async fn wait_for_job_terminal(
    job_store: &JobStore,
    job_id: &str,
) -> mu_ci_controller::job::JobRecord {
    for _ in 0..100 {
        if let Some(rec) = job_store.get_job(job_id).await {
            if matches!(
                rec.status,
                JobStatus::Completed { .. } | JobStatus::Failed { .. } | JobStatus::Skipped { .. }
            ) {
                return rec;
            }
        }
        sleep(Duration::from_millis(30)).await;
    }
    let latest = job_store.get_job(job_id).await;
    panic!(
        "timed out waiting for job '{job_id}' to reach terminal status; latest={:?}",
        latest
    );
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn test_kva23_stage_skips_immediately_with_dedup_pr_comment_and_dag_completion() {
    let (mock_base_url, github_state) = start_mock_github_server().await;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("controller_ws");
    tokio::fs::create_dir_all(&ws_path)
        .await
        .expect("create ws");

    let repo_name = "LMA1980/kva23-test-repo";
    let workflow_yaml = r#"
version: "4"
name: "v4 KVA23 Skip Pipeline"
toolchain:
  min_version: "1.80.0"
  channel: "stable"
tasks:
  rust-check:
    tool: "cargo-clippy"
    args: ["--workspace"]
  kva23-bench:
    tool: "cargo-bench"
    args: ["--workspace"]
  rust-summary:
    tool: "cargo-test"
    args: ["--workspace"]
stages:
  - id: check
    name: "Workspace Check"
    tasks: ["rust-check"]
    tags: ["rust"]
    toolchain: "stable"
  - id: bench_kva23
    name: "Optional KVA23 Benchmark"
    tasks: ["kva23-bench"]
    depends_on: ["check"]
    tags: ["kva23"]
    if_unavailable:
      policy: skip
      pr_comment: true
      capability_label: "KVA23"
  - id: summary
    name: "Downstream Summary"
    tasks: ["rust-summary"]
    depends_on: ["check", "bench_kva23"]
    tags: ["rust"]
    toolchain: "stable"
on_action:
  pull_request: ["check", "bench_kva23", "summary"]
"#;
    write_workflow_manifest(&ws_path, repo_name, workflow_yaml).await;

    let cfg = Config {
        workspace_dir: ws_path.clone(),
        max_concurrent_jobs: 4,
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        github_token: Some(format!("ghs_mock_token@{mock_base_url}")),
        ..Config::default()
    };

    let mem_storage = Arc::new(mu_ci_controller::storage_backend::InMemoryStorage::open());
    let job_store = JobStore::with_storage(100, Some(&ws_path), mem_storage.clone());
    let cluster = ClusterRegistry::new();
    let executed = Arc::new(Mutex::new(Vec::new()));

    // Register only a general x86_64/rust worker; ZERO live KVA23 nodes exist.
    let (tx_a, rx_a) = mpsc::channel(32);
    cluster
        .register(make_worker_reg("node-a", "x86_64", &["rust"]), tx_a)
        .await;
    spawn_simulated_worker(
        "node-a".to_string(),
        rx_a,
        cluster.clone(),
        job_store.clone(),
        executed.clone(),
    );

    let scheduler = Arc::new(DAGScheduler::new(cfg, job_store.clone(), cluster.clone()));
    let sched_task = scheduler.clone();
    let handle = tokio::spawn(async move {
        sched_task.run_loop().await;
    });

    // PR commit #1 -> creates sticky PR comment via POST and completes DAG cleanly.
    let job_1 = Job {
        id: "job-kva23-skip-1".to_string(),
        event_type: "pull_request".to_string(),
        repo_name: repo_name.to_string(),
        clone_url: "invalid://local-disk-workflow".to_string(),
        commit_sha: "abcdef1234567890abcdef1234567890abcdef12".to_string(),
        ref_name: "refs/heads/feat/kva23-bench".to_string(),
        sender: "LMA1980".to_string(),
        pr_number: Some(77),
        queued_at: Utc::now(),
    };
    job_store
        .enqueue_job(job_1.clone(), ws_path.join("logs/j1.log"))
        .await;

    let rec_1 = wait_for_job_terminal(&job_store, &job_1.id).await;
    assert_eq!(rec_1.job.pr_number, Some(77));
    assert!(
        matches!(rec_1.status, JobStatus::Completed { exit_code: 0, .. }),
        "expected DAG completion exit_code 0, got {:?}",
        rec_1.status
    );

    let stage_map: HashMap<_, _> = rec_1.stages.iter().map(|s| (s.id.as_str(), s)).collect();
    assert!(matches!(
        stage_map["check"].status,
        StageStatus::Completed { exit_code: 0, .. }
    ));
    match &stage_map["bench_kva23"].status {
        StageStatus::Skipped { reason } => {
            assert!(
                reason.contains("No KVA23 node accessible"),
                "unexpected skip reason: {reason}"
            );
        }
        other => panic!("expected bench_kva23 Skipped, got {:?}", other),
    }
    assert_eq!(
        stage_map["bench_kva23"].skip_reason_code.as_deref(),
        Some("no_capable_node")
    );
    assert_eq!(
        stage_map["bench_kva23"].skip_capability.as_deref(),
        Some("KVA23")
    );
    assert!(
        matches!(
            stage_map["summary"].status,
            StageStatus::Completed { exit_code: 0, .. }
        ),
        "downstream stage depending on skipped stage must execute and pass"
    );

    assert_eq!(github_state.post_count.load(Ordering::SeqCst), 1);
    assert_eq!(github_state.patch_count.load(Ordering::SeqCst), 0);
    {
        let comments = github_state.comments.lock().await;
        assert_eq!(comments.len(), 1);
        assert!(comments[0].body.contains("<!-- mu-ci-skip:bench_kva23 -->"));
        assert!(comments[0]
            .body
            .contains("Stage 'bench_kva23' skipped for abcdef1: No KVA23 node accessible."));
    }
    {
        let statuses = github_state.statuses.lock().await;
        assert!(
            statuses.iter().any(|s| {
                s.sha == job_1.commit_sha
                    && s.state == "success"
                    && !s.description.is_empty()
                    && !s.context.is_empty()
            }),
            "k3-ci / CI commit status must conclude success when all non-skipped stages pass"
        );
    }

    // Verify structured telemetry span emitted for skipped stage.
    let spans = mem_storage.get_emitted_spans();
    assert!(
        spans.iter().any(|sp| {
            sp.span_name == "ci.stage.skipped:bench_kva23"
                && sp.attributes_json.contains("no_capable_node")
                && sp.attributes_json.contains("KVA23")
        }),
        "expected structured skip telemetry span, got {:?}",
        spans
    );

    // PR commit #2 on the SAME PR #77 -> updates existing marker comment via PATCH (no duplicate comment).
    let job_2 = Job {
        id: "job-kva23-skip-2".to_string(),
        event_type: "pull_request".to_string(),
        repo_name: repo_name.to_string(),
        clone_url: "invalid://local-disk-workflow".to_string(),
        commit_sha: "fedcba9876543210fedcba9876543210fedcba98".to_string(),
        ref_name: "refs/heads/feat/kva23-bench".to_string(),
        sender: "LMA1980".to_string(),
        pr_number: Some(77),
        queued_at: Utc::now(),
    };
    job_store
        .enqueue_job(job_2.clone(), ws_path.join("logs/j2.log"))
        .await;

    let rec_2 = wait_for_job_terminal(&job_store, &job_2.id).await;
    assert!(matches!(
        rec_2.status,
        JobStatus::Completed { exit_code: 0, .. }
    ));

    assert_eq!(github_state.post_count.load(Ordering::SeqCst), 1);
    assert_eq!(github_state.patch_count.load(Ordering::SeqCst), 1);
    {
        let comments = github_state.comments.lock().await;
        assert_eq!(comments.len(), 1, "must deduplicate sticky PR skip comment");
        assert!(comments[0].body.contains("<!-- mu-ci-skip:bench_kva23 -->"));
        assert!(comments[0]
            .body
            .contains("Stage 'bench_kva23' skipped for fedcba9: No KVA23 node accessible."));
    }

    handle.abort();
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn test_v4_workflow_min_version_fails_fast_when_cluster_version_too_old() {
    let (mock_base_url, github_state) = start_mock_github_server().await;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("controller_ws");
    tokio::fs::create_dir_all(&ws_path)
        .await
        .expect("create ws");

    let repo_name = "LMA1980/toolchain-failfast-repo";
    let workflow_yaml = r#"
version: "4"
name: "v4 Unsupported Min Toolchain"
toolchain:
  min_version: "1.90.0"
  channel: "stable"
tasks:
  rust-check:
    tool: "cargo-clippy"
    args: ["--workspace"]
stages:
  - id: check
    name: "Workspace Check"
    tasks: ["rust-check"]
    tags: ["rust"]
    toolchain: "stable"
on_action:
  pull_request: ["check"]
"#;
    write_workflow_manifest(&ws_path, repo_name, workflow_yaml).await;

    let cfg = Config {
        workspace_dir: ws_path.clone(),
        max_concurrent_jobs: 4,
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        github_token: Some(format!("ghs_mock_token@{mock_base_url}")),
        ..Config::default()
    };

    let job_store = JobStore::new(100, Some(&ws_path));
    let cluster = ClusterRegistry::new();
    let executed = Arc::new(Mutex::new(Vec::new()));

    let (tx_a, rx_a) = mpsc::channel(32);
    let mut reg = make_worker_reg("node-a", "x86_64", &["rust"]);
    reg.rust_semver = Some("1.82.0".to_string());
    cluster.register(reg, tx_a).await;
    spawn_simulated_worker(
        "node-a".to_string(),
        rx_a,
        cluster.clone(),
        job_store.clone(),
        executed.clone(),
    );

    let scheduler = Arc::new(DAGScheduler::new(cfg, job_store.clone(), cluster.clone()));
    let sched_task = scheduler.clone();
    let handle = tokio::spawn(async move {
        sched_task.run_loop().await;
    });

    let job = Job {
        id: "job-minver-fail-1".to_string(),
        event_type: "pull_request".to_string(),
        repo_name: repo_name.to_string(),
        clone_url: "invalid://local-disk-workflow".to_string(),
        commit_sha: "9988776655443322110099887766554433221100".to_string(),
        ref_name: "refs/heads/feat/too-new-rust".to_string(),
        sender: "LMA1980".to_string(),
        pr_number: Some(99),
        queued_at: Utc::now(),
    };
    job_store
        .enqueue_job(job.clone(), ws_path.join("logs/j_fail.log"))
        .await;

    let rec = wait_for_job_terminal(&job_store, &job.id).await;
    match &rec.status {
        JobStatus::Failed { error } => {
            assert!(
                error.contains("1.90.0") && error.contains("1.82.0"),
                "expected min_version and cluster_version in error: {error}"
            );
        }
        other => panic!("expected fast failure JobStatus::Failed, got {:?}", other),
    }

    assert!(
        executed.lock().await.is_empty(),
        "no stage must dispatch when toolchain.min_version fails fast"
    );

    let statuses = github_state.statuses.lock().await;
    assert!(statuses
        .iter()
        .any(|s| s.sha == job.commit_sha && s.state == "failure"));

    handle.abort();
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn test_busy_live_kva23_node_keeps_stage_queued_without_skip_or_pr_comment() {
    let (mock_base_url, github_state) = start_mock_github_server().await;
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("controller_ws");
    tokio::fs::create_dir_all(&ws_path)
        .await
        .expect("create ws");

    let repo_name = "LMA1980/kva23-busy-repo";
    let workflow_yaml = r#"
version: "4"
name: "v4 KVA23 Busy Node Queueing"
tasks:
  kva23-bench:
    tool: "cargo-bench"
    args: ["--workspace"]
stages:
  - id: bench_kva23
    name: "Optional KVA23 Benchmark"
    tasks: ["kva23-bench"]
    tags: ["kva23"]
    if_unavailable:
      policy: skip
      pr_comment: true
      capability_label: "KVA23"
on_action:
  pull_request: ["bench_kva23"]
"#;
    write_workflow_manifest(&ws_path, repo_name, workflow_yaml).await;

    let cfg = Config {
        workspace_dir: ws_path.clone(),
        max_concurrent_jobs: 4,
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        github_token: Some(format!("ghs_mock_token@{mock_base_url}")),
        ..Config::default()
    };

    let job_store = JobStore::new(100, Some(&ws_path));
    let cluster = ClusterRegistry::new();
    let executed = Arc::new(Mutex::new(Vec::new()));

    // Register 1 live generic node (so stages.is_empty() claim succeeds on fresh queue) and
    // 1 live KVA23 node whose sole slot is currently busy on an unrelated job.
    let (tx_a, rx_a) = mpsc::channel(32);
    cluster
        .register(make_worker_reg("node-a", "x86_64", &["rust"]), tx_a)
        .await;
    spawn_simulated_worker(
        "node-a".to_string(),
        rx_a,
        cluster.clone(),
        job_store.clone(),
        executed.clone(),
    );

    let (tx_kva, rx_kva) = mpsc::channel(32);
    cluster
        .register(
            make_worker_reg("worker-riscv64-kva23", "riscv64", &["kva23"]),
            tx_kva,
        )
        .await;
    spawn_simulated_worker(
        "worker-riscv64-kva23".to_string(),
        rx_kva,
        cluster.clone(),
        job_store.clone(),
        executed.clone(),
    );

    // Occupy worker-riscv64-kva23's single slot with another job's lease.
    let leased = cluster
        .lease_slot(
            "blocking-job",
            "blocking-stage",
            &["kva23".to_string()],
            None,
            false,
        )
        .await;
    assert!(leased.is_some(), "should lease busy slot on KVA23 worker");

    let scheduler = Arc::new(DAGScheduler::new(cfg, job_store.clone(), cluster.clone()));
    let sched_task = scheduler.clone();
    let handle = tokio::spawn(async move {
        sched_task.run_loop().await;
    });

    let job = Job {
        id: "job-kva23-busy-1".to_string(),
        event_type: "pull_request".to_string(),
        repo_name: repo_name.to_string(),
        clone_url: "invalid://local-disk-workflow".to_string(),
        commit_sha: "1122334455667788112233445566778811223344".to_string(),
        ref_name: "refs/heads/feat/kva23-busy".to_string(),
        sender: "LMA1980".to_string(),
        pr_number: Some(88),
        queued_at: Utc::now(),
    };
    job_store
        .enqueue_job(job.clone(), ws_path.join("logs/j_busy.log"))
        .await;

    // Wait long enough for execute_job + yield-and-requeue to run while KVA23 node is busy.
    sleep(Duration::from_millis(180)).await;
    let mid_rec = job_store.get_job(&job.id).await.expect("job exists");
    assert_eq!(mid_rec.stages.len(), 1);
    assert_eq!(
        mid_rec.stages[0].status,
        StageStatus::Pending,
        "busy live KVA23 node must keep stage Pending/queued rather than skipping"
    );
    assert_eq!(github_state.post_count.load(Ordering::SeqCst), 0);
    assert_eq!(github_state.patch_count.load(Ordering::SeqCst), 0);

    // Now free the KVA23 worker slot and refresh heartbeat; the queued stage should execute and pass.
    cluster
        .release_stage_slot("worker-riscv64-kva23", "blocking-job", "blocking-stage")
        .await;
    job_store.notify_event();

    let final_rec = wait_for_job_terminal(&job_store, &job.id).await;
    assert!(matches!(
        final_rec.status,
        JobStatus::Completed { exit_code: 0, .. }
    ));
    assert!(matches!(
        final_rec.stages[0].status,
        StageStatus::Completed { exit_code: 0, .. }
    ));
    assert_eq!(github_state.post_count.load(Ordering::SeqCst), 0);
    assert_eq!(github_state.patch_count.load(Ordering::SeqCst), 0);

    let log_items = executed.lock().await;
    assert!(
        log_items
            .iter()
            .any(|(nid, sid)| nid == "worker-riscv64-kva23" && sid == "bench_kva23"),
        "expected bench_kva23 to run on worker-riscv64-kva23 once slot freed, got {:?}",
        *log_items
    );

    handle.abort();
}
