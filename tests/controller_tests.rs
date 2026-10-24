use action_runner_controller::workflow::WorkflowConfig;
use std::path::Path;

#[test]
fn test_workflow_dag_validation_valid() {
    let yaml = r#"
version: "2"
name: "Test Pipeline"
stages:
  - id: fmt
    name: "Format"
    tags: ["fmt"]
    threads: 2
    run: "cargo fmt --check"
  - id: clippy
    name: "Clippy"
    tags: ["clippy"]
    threads: 4
    run: "cargo clippy"
  - id: test-native
    name: "Native Test"
    tags: ["k3"]
    depends_on: ["fmt", "clippy"]
    run: "cargo test"
"#;
    let wf = WorkflowConfig::load_from_str(yaml, Path::new("."), 600).expect("valid workflow");
    assert_eq!(wf.stages.len(), 3);
    assert_eq!(wf.stages[2].depends_on, vec!["fmt", "clippy"]);
}

#[test]
fn test_workflow_dag_cycle_detection() {
    let yaml = r#"
version: "2"
name: "Cyclic Pipeline"
stages:
  - id: stage-a
    name: "A"
    tags: ["test"]
    depends_on: ["stage-b"]
    run: "echo a"
  - id: stage-b
    name: "B"
    tags: ["test"]
    depends_on: ["stage-a"]
    run: "echo b"
"#;
    let err = WorkflowConfig::load_from_str(yaml, Path::new("."), 600).unwrap_err();
    assert!(err.contains("Cyclic dependency detected"));
}

#[test]
fn test_workflow_v1_backwards_compatibility() {
    let yaml = r#"
name: "V1 Pipeline"
steps:
  - name: "Step 1"
    run: "cargo fmt"
  - name: "Step 2"
    run: "cargo test"
"#;
    let wf = WorkflowConfig::load_from_str(yaml, Path::new("."), 600).expect("valid v1");
    assert_eq!(wf.stages.len(), 2);
    assert_eq!(wf.stages[0].id, "step-1");
    assert_eq!(wf.stages[1].id, "step-2");
    assert_eq!(wf.stages[1].depends_on, vec!["step-1"]);
}

#[tokio::test]
async fn test_job_card_svg_route_and_headers() {
    use action_runner_controller::app::create_router;
    use action_runner_controller::cluster::ClusterRegistry;
    use action_runner_controller::config::Config;
    use action_runner_controller::job::{Job, JobStatus, JobStore};
    use action_runner_controller::scheduler::DAGScheduler;
    use action_runner_controller::webhook::AppState;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("ws");
    let config = Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: ws_path.clone(),
        allowed_repositories: vec!["*".to_string()],
        allowed_actors: vec![],
        allow_fork_prs: true,
        allowed_pr_authors: vec![],
        log_api_key: None,
        webhook_secret: None,
        cluster_token: "token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 2,
        github_token: None,
    };

    let job_store = JobStore::new(100, None);
    let cluster = ClusterRegistry::new();
    let (tx, _rx) = mpsc::channel(32);
    let _scheduler = Arc::new(DAGScheduler::new(
        config.clone(),
        job_store.clone(),
        cluster.clone(),
    ));

    let state = Arc::new(AppState {
        config,
        job_store: job_store.clone(),
        cluster,
        tx,
    });

    let job = Job {
        id: "job-test-123".to_string(),
        event_type: "pull_request".to_string(),
        repo_name: "LMA1980/ActionRunner-web".to_string(),
        clone_url: String::new(),
        commit_sha: "9ca1c51a8e62c3950dde184046fa4613298b539c".to_string(),
        ref_name: "feat/first-view-host-attribution".to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now(),
    };
    job_store
        .enqueue_job(job, PathBuf::from("logs/test.log"))
        .await;
    job_store
        .update_status(
            "job-test-123",
            JobStatus::Completed {
                duration_secs: 143,
                exit_code: 0,
            },
        )
        .await;

    let app = create_router(state);

    let req = Request::builder()
        .uri("/api/jobs/job-test-123/card.svg")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cache_control = resp
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(cache_control.contains("no-cache"));
    assert!(cache_control.contains("no-store"));

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let svg_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(svg_str.contains("LMA1980/ActionRunner-web"));
    assert!(svg_str.contains("9ca1c51a"));
    assert!(svg_str.contains("✓ PASSING"));
}
