use action_runner::config::{IsolationMode, WorkerConfig};
use action_runner::worker::WorkerAgent;
use action_runner_controller::app::create_router;
use action_runner_controller::cluster::ClusterRegistry;
use action_runner_controller::config::Config;
use action_runner_controller::job::{Job, JobStatus, JobStore, StageStatus};
use action_runner_controller::scheduler::DAGScheduler;
use action_runner_controller::webhook::AppState;
use chrono::Utc;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::sleep;

#[tokio::test]
async fn test_end_to_end_distributed_dag_execution() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            "action_runner=debug,action_runner_controller=debug,action_runner_ipc=debug",
        )
        .try_init();

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("controller_ws");
    tokio::fs::create_dir_all(&ws_path)
        .await
        .expect("create controller ws");

    let repo_name = "LMA1980/test-e2e-cluster";
    let repo_path = ws_path.join("repos").join(repo_name);
    let actionrunner_dir = repo_path.join(".actionrunner");
    tokio::fs::create_dir_all(&actionrunner_dir)
        .await
        .expect("create actionrunner dir");

    // Define a 2-stage DAG: fmt -> clippy
    let workflow_yaml = r#"
version: "2"
name: "E2E Distributed CI"
stages:
  - id: stage-fmt
    name: "Check Formatting"
    tags: ["fmt"]
    threads: 2
    run: "echo '[E2E-STEP-1] formatting passed cleanly'"
  - id: stage-clippy
    name: "Check Clippy"
    tags: ["clippy"]
    threads: 2
    depends_on: ["stage-fmt"]
    run: "echo '[E2E-STEP-2] clippy linter passed cleanly'"
"#;

    tokio::fs::write(actionrunner_dir.join("on-push.yml"), workflow_yaml)
        .await
        .expect("write workflow");

    // 1. Controller setup
    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: ws_path.clone(),
        allowed_repositories: vec!["*".to_string()],
        allowed_actors: vec![],
        allow_fork_prs: true,
        allowed_pr_authors: vec![],
        log_api_key: None,
        webhook_secret: None,
        cluster_token: "test-e2e-secret-token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 2,
        github_token: None,
    };

    let job_store = JobStore::new(100, Some(&ws_path));
    let cluster = ClusterRegistry::new();
    let (tx, _rx) = mpsc::channel(32);

    let scheduler = Arc::new(DAGScheduler::new(
        config.clone(),
        job_store.clone(),
        cluster.clone(),
    ));
    tokio::spawn(scheduler.run_loop());

    let state = Arc::new(AppState {
        config: config.clone(),
        job_store: job_store.clone(),
        cluster: cluster.clone(),
        tx,
    });

    let app = create_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let local_addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 2. Worker setup
    let worker_ws = temp_dir.path().join("worker_ws");
    tokio::fs::create_dir_all(&worker_ws)
        .await
        .expect("create worker ws");

    let worker_config = WorkerConfig {
        controller_url: format!("ws://{}/api/cluster/tunnel", local_addr),
        cluster_token: "test-e2e-secret-token".to_string(),
        node_id: "worker-n100-test".to_string(),
        arch: "x86_64".to_string(),
        tags: vec![
            "x86_64".to_string(),
            "n100".to_string(),
            "fmt".to_string(),
            "clippy".to_string(),
        ],
        max_slots: 2,
        workspace_dir: worker_ws,
        toolchains: vec!["system".to_string()],
        use_btrfs: false,
        isolation_mode: IsolationMode::None,
    };

    let worker = WorkerAgent::new(worker_config);
    tokio::spawn(async move {
        let _ = worker.connect_and_process().await;
    });

    // Wait for worker registration
    let mut registered = false;
    for _ in 0..50 {
        let nodes = cluster.list_nodes_view().await;
        if let Some(node) = nodes.iter().find(|n| n.node_id == "worker-n100-test") {
            if node.is_online {
                registered = true;
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert!(registered, "Worker did not register with cluster registry");

    // 3. Enqueue Job
    let job = Job {
        id: "job-e2e-001".to_string(),
        event_type: "push".to_string(),
        repo_name: repo_name.to_string(),
        clone_url: repo_path.to_str().unwrap().to_string(),
        commit_sha: "c0ffee1234".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };

    let log_file = PathBuf::from(format!("logs/{}/{}.log", repo_name, job.id));
    job_store.enqueue_job(job, log_file).await;

    // 4. Wait for Job Completion
    let mut finished = false;

    for i in 0..100 {
        if let Some(record) = job_store.get_job("job-e2e-001").await {
            eprintln!(
                "[tick {}] job status: {:?}, stages: {:?}",
                i,
                record.status,
                record
                    .stages
                    .iter()
                    .map(|s| (&s.id, &s.status))
                    .collect::<Vec<_>>()
            );
            match &record.status {
                JobStatus::Completed { exit_code, .. } => {
                    assert_eq!(*exit_code, 0, "Job completed with non-zero exit code");
                    finished = true;
                    break;
                }
                JobStatus::Failed { error } => {
                    panic!("Job failed unexpectedly: {}", error);
                }
                _ => {}
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    assert!(finished, "Job did not complete within timeout");

    // 5. Verify Stages and Log Aggregation
    let job_record = job_store
        .get_job("job-e2e-001")
        .await
        .expect("job record exists");
    assert_eq!(job_record.stages.len(), 2);

    for stage in &job_record.stages {
        match &stage.status {
            StageStatus::Completed { exit_code, .. } => {
                assert_eq!(*exit_code, 0, "Stage {} did not succeed", stage.id);
            }
            other => panic!("Stage {} in unexpected state: {:?}", stage.id, other),
        }
    }

    // Verify Arrow streaming aggregated logs
    let log_path = ws_path.join(&job_record.log_file);
    let log_content = tokio::fs::read_to_string(&log_path)
        .await
        .expect("read aggregated log file");

    assert!(
        log_content.contains("[E2E-STEP-1] formatting passed cleanly"),
        "Missing fmt step output in aggregated log: {}",
        log_content
    );
    assert!(
        log_content.contains("[E2E-STEP-2] clippy linter passed cleanly"),
        "Missing clippy step output in aggregated log: {}",
        log_content
    );
}
