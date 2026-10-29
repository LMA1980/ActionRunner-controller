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

    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);

    let state = Arc::new(AppState {
        config: config.clone(),
        job_store: job_store.clone(),
        cluster: cluster.clone(),
        tx,
        log_broadcaster,
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

    let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let worker = WorkerAgent::new(worker_config);
    tokio::spawn(async move {
        let _ = worker.connect_and_process(&mut shutdown_rx).await;
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

#[tokio::test]
async fn test_multi_repo_single_action_per_node_scheduling() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("controller_ws_multi");
    tokio::fs::create_dir_all(&ws_path)
        .await
        .expect("create controller ws");

    let repos = [
        "LMA1980/repo-alpha",
        "LMA1980/repo-beta",
        "LMA1980/repo-gamma",
        "LMA1980/repo-delta",
    ];

    let workflow_yaml = r#"
version: "2"
name: "Multi-Repo Pipeline"
stages:
  - id: fmt-check
    name: "Check Formatting"
    tags: ["fmt"]
    threads: 2
    run: "sleep 0.2; echo '[FMT-OK]'"
  - id: clippy-check
    name: "Check Clippy"
    tags: ["clippy"]
    threads: 6
    run: "sleep 0.2; echo '[CLIPPY-OK]'"
  - id: audit-check
    name: "Check Audit"
    tags: ["audit"]
    threads: 2
    depends_on: ["fmt-check"]
    run: "sleep 0.2; echo '[AUDIT-OK]'"
"#;

    for repo_name in &repos {
        let actionrunner_dir = ws_path.join("repos").join(repo_name).join(".actionrunner");
        tokio::fs::create_dir_all(&actionrunner_dir)
            .await
            .expect("create actionrunner dir");
        tokio::fs::write(actionrunner_dir.join("on-push.yml"), workflow_yaml)
            .await
            .expect("write workflow");
    }

    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: ws_path.clone(),
        allowed_repositories: vec!["*".to_string()],
        allowed_actors: vec![],
        allow_fork_prs: true,
        allowed_pr_authors: vec![],
        log_api_key: None,
        webhook_secret: None,
        cluster_token: "test-multi-secret-token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 6,
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

    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);
    let state = Arc::new(AppState {
        config: config.clone(),
        job_store: job_store.clone(),
        cluster: cluster.clone(),
        tx,
        log_broadcaster,
    });

    let app = create_router(state);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let local_addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Spawn 2 workers (entrance for fmt/audit, rubicon for clippy)
    for (node_id, tags) in [
        ("entrance", vec!["fmt".to_string(), "audit".to_string()]),
        ("rubicon", vec!["clippy".to_string()]),
    ] {
        let worker_ws = temp_dir.path().join(format!("worker_{}", node_id));
        tokio::fs::create_dir_all(&worker_ws).await.unwrap();
        let worker_config = WorkerConfig {
            controller_url: format!("ws://{}/api/cluster/tunnel", local_addr),
            cluster_token: "test-multi-secret-token".to_string(),
            node_id: node_id.to_string(),
            arch: "x86_64".to_string(),
            tags,
            max_slots: 1,
            workspace_dir: worker_ws,
            toolchains: vec!["system".to_string()],
            use_btrfs: false,
            isolation_mode: IsolationMode::None,
        };
        let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let worker = WorkerAgent::new(worker_config);
        tokio::spawn(async move {
            let _ = worker.connect_and_process(&mut shutdown_rx).await;
        });
    }

    for _ in 0..50 {
        let nodes = cluster.list_nodes_view().await;
        if nodes.len() == 2 && nodes.iter().all(|n| n.is_online) {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }

    // Submit 4 repository events simultaneously
    for (idx, repo_name) in repos.iter().enumerate() {
        let repo_path = ws_path.join("repos").join(repo_name);
        let job = Job {
            id: format!("job-multi-{}", idx + 1),
            event_type: "push".to_string(),
            repo_name: repo_name.to_string(),
            clone_url: repo_path.to_str().unwrap().to_string(),
            commit_sha: format!("deadbeef0{}", idx + 1),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let log_file = PathBuf::from(format!("logs/{}/{}.log", repo_name, job.id));
        job_store.enqueue_job(job, log_file).await;
    }

    let mut max_concurrent_running_jobs = 0usize;
    for _ in 0..200 {
        let nodes = cluster.list_nodes_view().await;
        for n in &nodes {
            assert_eq!(n.max_slots, 1, "Node {} max_slots must be 1", n.node_id);
            assert!(
                n.active_slots <= 1,
                "Node {} exceeded 1 active stage slot: {}",
                n.node_id,
                n.active_slots
            );
        }

        let snap = job_store.queue_snapshot().await;
        max_concurrent_running_jobs = max_concurrent_running_jobs.max(snap.stats.running_jobs);

        if snap.stats.completed_jobs == 4 {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }

    let final_snap = job_store.queue_snapshot().await;
    assert_eq!(final_snap.stats.completed_jobs, 4);
    assert!(
        max_concurrent_running_jobs >= 2,
        "Multiple repositories should be in Running state concurrently across the cluster"
    );
}

#[tokio::test]
async fn test_e2e_exclusive_stage_isolation_and_drain() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("controller_ws_exclusive");
    tokio::fs::create_dir_all(&ws_path)
        .await
        .expect("create controller ws");

    let repo_name = "LMA1980/repo-bench";
    let actionrunner_dir = ws_path.join("repos").join(repo_name).join(".actionrunner");
    tokio::fs::create_dir_all(&actionrunner_dir)
        .await
        .expect("create actionrunner dir");

    // Pipeline with:
    // 1. fmt-check (shared)
    // 2. bench-exclusive (exclusive: true, depends on fmt-check)
    // 3. audit-check (shared, depends on bench-exclusive)
    let workflow_yaml = r#"
version: "2"
name: "Exclusive Bench Pipeline"
stages:
  - id: fmt-check
    name: "Check Formatting"
    tags: ["bench-node"]
    threads: 2
    run: "sleep 0.2; echo '[FMT-DONE]'"
  - id: bench-exclusive
    name: "Hardware Benchmark"
    tags: ["bench-node"]
    threads: 6
    exclusive: true
    depends_on: ["fmt-check"]
    run: "sleep 0.3; echo '[BENCH-EXCLUSIVE-DONE]'"
  - id: audit-check
    name: "Audit Check"
    tags: ["bench-node"]
    threads: 2
    depends_on: ["bench-exclusive"]
    run: "sleep 0.2; echo '[AUDIT-DONE]'"
"#;
    tokio::fs::write(actionrunner_dir.join("on-push.yml"), workflow_yaml)
        .await
        .expect("write workflow");

    let repo2_name = "LMA1980/repo-concurrent";
    let actionrunner2_dir = ws_path.join("repos").join(repo2_name).join(".actionrunner");
    tokio::fs::create_dir_all(&actionrunner2_dir)
        .await
        .expect("create actionrunner dir 2");
    let workflow2_yaml = r#"
version: "2"
name: "Concurrent Normal Pipeline"
stages:
  - id: concurrent-stage
    name: "Concurrent Stage"
    tags: ["bench-node"]
    threads: 2
    run: "sleep 0.2; echo '[CONCURRENT-DONE]'"
"#;
    tokio::fs::write(actionrunner2_dir.join("on-push.yml"), workflow2_yaml)
        .await
        .expect("write workflow 2");

    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: ws_path.clone(),
        allowed_repositories: vec!["*".to_string()],
        allowed_actors: vec![],
        allow_fork_prs: true,
        allowed_pr_authors: vec![],
        log_api_key: None,
        webhook_secret: None,
        cluster_token: "test-exclusive-token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 4,
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

    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);
    let state = Arc::new(AppState {
        config: config.clone(),
        job_store: job_store.clone(),
        cluster: cluster.clone(),
        tx,
        log_broadcaster,
    });

    let app = create_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind port");
    let local_addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Start 1 worker with max_slots = 2
    let worker_ws = temp_dir.path().join("worker_ws_bench");
    tokio::fs::create_dir_all(&worker_ws).await.unwrap();
    let worker_config = WorkerConfig {
        controller_url: format!("ws://{}/api/cluster/tunnel", local_addr),
        cluster_token: "test-exclusive-token".to_string(),
        node_id: "bench-node-worker".to_string(),
        arch: "x86_64".to_string(),
        tags: vec!["bench-node".to_string()],
        max_slots: 2,
        workspace_dir: worker_ws,
        toolchains: vec!["system".to_string()],
        use_btrfs: false,
        isolation_mode: IsolationMode::None,
    };
    let (_shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let worker = WorkerAgent::new(worker_config);
    tokio::spawn(async move {
        let _ = worker.connect_and_process(&mut shutdown_rx).await;
    });

    for _ in 0..50 {
        let nodes = cluster.list_nodes_view().await;
        if nodes.len() == 1 && nodes[0].is_online {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }

    // Submit Job 1 (contains exclusive stage)
    let repo_path = ws_path.join("repos").join(repo_name);
    let job1 = Job {
        id: "job-exclusive-1".to_string(),
        event_type: "push".to_string(),
        repo_name: repo_name.to_string(),
        clone_url: repo_path.to_str().unwrap().to_string(),
        commit_sha: "beef0001".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };
    job_store
        .enqueue_job(job1, PathBuf::from("logs/job1.log"))
        .await;

    // Concurrently submit Job 2 (non-exclusive pipeline)
    let repo2_path = ws_path.join("repos").join(repo2_name);
    let job2 = Job {
        id: "job-exclusive-2".to_string(),
        event_type: "push".to_string(),
        repo_name: repo2_name.to_string(),
        clone_url: repo2_path.to_str().unwrap().to_string(),
        commit_sha: "beef0002".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };
    job_store
        .enqueue_job(job2, PathBuf::from("logs/job2.log"))
        .await;

    // Monitor execution and assert that while bench-exclusive is running on bench-node-worker,
    // active_slots on bench-node-worker is strictly 1 (no concurrent stages on node).
    let mut verified_exclusive_concurrency = false;
    for _ in 0..200 {
        if let Some(record) = job_store.get_job("job-exclusive-1").await {
            let bench_stage = record.stages.iter().find(|s| s.id == "bench-exclusive");
            if let Some(s) = bench_stage {
                if matches!(
                    s.status,
                    StageStatus::Running { .. } | StageStatus::Assigned { .. }
                ) {
                    let nodes = cluster.list_nodes_view().await;
                    if let Some(w) = nodes.iter().find(|n| n.node_id == "bench-node-worker") {
                        assert_eq!(
                            w.active_slots, 1,
                            "While exclusive bench is running, active_slots on node must be exactly 1"
                        );
                        verified_exclusive_concurrency = true;
                    }
                }
            }
        }

        let snap = job_store.queue_snapshot().await;
        if snap.stats.completed_jobs == 2 {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }

    assert!(
        verified_exclusive_concurrency,
        "Must have observed exclusive stage execution window"
    );
    let final_snap = job_store.queue_snapshot().await;
    assert_eq!(final_snap.stats.completed_jobs, 2);
}
