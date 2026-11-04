//! Integration tests for the read-only console API (`/api/repos`, `/summary`,
//! `/topology`) and the additive SSE kinds on `/api/events` (#50).

use action_runner_controller::app::create_router;
use action_runner_controller::cluster::ClusterRegistry;
use action_runner_controller::config::Config;
use action_runner_controller::console::{ConsoleConfig, ConsoleState};
use action_runner_controller::job::{
    Job, JobMetrics, JobStatus, JobStore, StageRecord, StageStatus,
};
use action_runner_controller::webhook::AppState;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use chrono::{Duration as ChronoDuration, Utc};
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const API_KEY: &str = "console-test-key";
const SHA_CORE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_SECRET: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_CHILD: &str = "cccccccccccccccccccccccccccccccccccccccc";

fn test_config(log_api_key: Option<&str>) -> Config {
    Config {
        bind_addr: "127.0.0.1:0".to_string(),
        workspace_dir: PathBuf::from("/nonexistent-console-ws"),
        allowed_repositories: vec!["LMA1980/*".to_string()],
        allowed_actors: vec![],
        allow_fork_prs: false,
        allowed_pr_authors: vec!["OWNER".to_string()],
        log_api_key: log_api_key.map(str::to_string),
        webhook_secret: None,
        cluster_token: "token".to_string(),
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        max_concurrent_jobs: 2,
        github_token: None,
        ..Config::default()
    }
}

fn make_state(log_api_key: Option<&str>, console: ConsoleState) -> Arc<AppState> {
    let (tx, _rx) = tokio::sync::mpsc::channel(64);
    let (log_broadcaster, _) = tokio::sync::broadcast::channel(128);
    Arc::new(AppState {
        config: test_config(log_api_key),
        job_store: JobStore::new(100, None),
        cluster: ClusterRegistry::new(),
        tx,
        log_broadcaster,
        console,
    })
}

/// Minimal GitHub REST mock: `/repos/{o}/{r}` and `/repos/{o}/{r}/contents/{path}`.
async fn spawn_github_mock() -> String {
    let mut repos: BTreeMap<&'static str, Value> = BTreeMap::new();
    repos.insert(
        "LMA1980/parent",
        json!({"private": false, "visibility": "public", "default_branch": "main"}),
    );
    repos.insert(
        "LMA1980/child",
        json!({"private": false, "visibility": "public", "default_branch": "main"}),
    );
    repos.insert(
        "LMA1980/secret-lib",
        json!({"private": true, "visibility": "private", "default_branch": "main"}),
    );
    repos.insert(
        "LMA1980/private-parent",
        json!({"private": true, "visibility": "private", "default_branch": "trunk"}),
    );
    let repos = Arc::new(repos);

    let mut files: BTreeMap<String, String> = BTreeMap::new();
    files.insert(
        "LMA1980/parent/.gitmodules".into(),
        "[submodule \"code/core\"]\n\tpath = code/core\n\turl = https://github.com/LMA1980/child.git\n[submodule \"code/secret\"]\n\tpath = code/secret\n\turl = ../secret-lib.git\n".into(),
    );
    files.insert(
        "LMA1980/parent/code/core".into(),
        json!({"type": "submodule", "sha": SHA_CORE}).to_string(),
    );
    files.insert(
        "LMA1980/parent/code/secret".into(),
        json!({"type": "submodule", "sha": SHA_SECRET}).to_string(),
    );
    files.insert(
        "LMA1980/parent/.actionrunner/ActionRunner.yml".into(),
        r#"
version: "3"
name: "Parent Pipeline"
tasks:
  fmt:
    tool: "cargo-fmt"
  clippy:
    tool: "cargo-clippy"
  test:
    tool: "cargo-test"
stages:
  - id: fmt
    name: "FMT"
    tasks: ["fmt"]
  - id: clippy
    name: "CLIPPY"
    tasks: ["clippy"]
    depends_on: ["fmt"]
  - id: test
    name: "TEST"
    tasks: ["test"]
    depends_on: ["clippy"]
on_action:
  push: ["fmt", "clippy", "test"]
"#
        .into(),
    );
    files.insert(
        "LMA1980/private-parent/.gitmodules".into(),
        "[submodule \"code/child\"]\n\tpath = code/child\n\turl = git@github.com:LMA1980/child.git\n"
            .into(),
    );
    files.insert(
        "LMA1980/private-parent/code/child".into(),
        json!({"type": "submodule", "sha": SHA_CHILD}).to_string(),
    );
    let files = Arc::new(files);

    let app = Router::new()
        .route(
            "/repos/{owner}/{repo}",
            get({
                let repos = repos.clone();
                move |axum::extract::Path((o, r)): axum::extract::Path<(String, String)>| {
                    let repos = repos.clone();
                    async move {
                        match repos.get(format!("{o}/{r}").as_str()) {
                            Some(v) => (StatusCode::OK, v.to_string()),
                            None => (StatusCode::NOT_FOUND, "{}".to_string()),
                        }
                    }
                }
            }),
        )
        .route(
            "/repos/{owner}/{repo}/contents/{*path}",
            get({
                let files = files.clone();
                move |axum::extract::Path((o, r, p)): axum::extract::Path<(
                    String,
                    String,
                    String,
                )>| {
                    let files = files.clone();
                    async move {
                        match files.get(&format!("{o}/{r}/{p}")) {
                            Some(v) => (StatusCode::OK, v.clone()),
                            None => (StatusCode::NOT_FOUND, "{}".to_string()),
                        }
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

async fn get_json(app: &Router, uri: &str, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().uri(uri);
    if let Some(b) = bearer {
        req = req.header("Authorization", format!("Bearer {b}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

async fn post_webhook(app: &Router, event: &str, payload: Value) -> StatusCode {
    let req = Request::builder()
        .method("POST")
        .uri("/webhook")
        .header("x-github-event", event)
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();
    app.clone().oneshot(req).await.unwrap().status()
}

fn repo_obj(full: &str, private: bool) -> Value {
    json!({
        "full_name": full,
        "private": private,
        "default_branch": "main",
        "clone_url": format!("https://github.com/{full}.git"),
    })
}

/// Enqueues and completes a job with metrics on `ref_name`.
async fn completed_job(
    store: &JobStore,
    id: &str,
    repo: &str,
    ref_name: &str,
    sha: &str,
    age_mins: i64,
    metrics: Option<JobMetrics>,
) {
    let job = Job {
        id: id.to_string(),
        event_type: "push".to_string(),
        repo_name: repo.to_string(),
        clone_url: String::new(),
        commit_sha: sha.to_string(),
        ref_name: ref_name.to_string(),
        sender: "LMA1980".to_string(),
        queued_at: Utc::now() - ChronoDuration::minutes(age_mins),
    };
    store
        .enqueue_job(job, PathBuf::from(format!("logs/{id}.log")))
        .await;
    if let Some(m) = metrics {
        store.update_metrics(id, m).await;
    }
    store
        .update_status(
            id,
            JobStatus::Completed {
                duration_secs: 10,
                exit_code: 0,
            },
        )
        .await;
}

fn metrics(score: u32, coverage: f64, bench: &str) -> JobMetrics {
    JobMetrics {
        quality_score: score,
        letter_grade: "A".to_string(),
        coverage_pct: Some(coverage),
        benchmark_summary: Some(bench.to_string()),
        tests_passed: 10,
        tests_total: 10,
        advisories_count: 0,
        clippy_warnings: 0,
        submodules: BTreeMap::new(),
    }
}

fn find_repo<'a>(list: &'a Value, name: &str) -> Option<&'a Value> {
    list["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["repo"] == name)
}

async fn seeded_state() -> Arc<AppState> {
    let api = spawn_github_mock().await;
    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api),
        ..ConsoleConfig::default()
    });
    for r in ["parent", "child", "secret-lib", "private-parent"] {
        console.refresh_repo("LMA1980", r, None).await;
    }
    make_state(Some(API_KEY), console)
}

#[tokio::test]
async fn repos_filter_private_and_expose_submodule_graph() {
    let state = seeded_state().await;
    // A repository known only from job history with unknown visibility.
    completed_job(
        &state.job_store,
        "job-hist-1",
        "LMA1980/history-only",
        "refs/heads/main",
        "1111111111111111111111111111111111111111",
        5,
        None,
    )
    .await;
    let app = create_router(state.clone());

    // Anonymous: only public repositories.
    let (status, anon) = get_json(&app, "/api/repos", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(anon["authenticated"], false);
    let names: Vec<&str> = anon["repos"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["repo"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"parent") && names.contains(&"child"));
    assert!(!names.contains(&"secret-lib"), "private repo leaked");
    assert!(!names.contains(&"private-parent"), "private repo leaked");
    assert!(
        !names.contains(&"history-only"),
        "unknown visibility must fail closed"
    );

    let parent = find_repo(&anon, "parent").unwrap();
    assert_eq!(parent["visibility"], "public");
    assert_eq!(parent["default_branch"], "main");
    assert_eq!(
        parent["submodules"],
        json!([
            {"path": "code/core", "owner": "LMA1980", "repo": "child", "pinned_sha": SHA_CORE},
            {"path": "code/secret", "owner": "LMA1980", "repo": "secret-lib", "pinned_sha": SHA_SECRET},
        ])
    );
    let child = find_repo(&anon, "child").unwrap();
    assert_eq!(
        child["parents"],
        json!([{"owner": "LMA1980", "repo": "parent", "path": "code/core"}]),
        "private parent must be hidden from anonymous sessions"
    );

    // Wrong key behaves as anonymous.
    let (_, wrong) = get_json(&app, "/api/repos", Some("nope")).await;
    assert_eq!(wrong["authenticated"], false);
    assert!(find_repo(&wrong, "secret-lib").is_none());

    // Authenticated: everything, including parents from private superprojects.
    let (_, authed) = get_json(&app, "/api/repos", Some(API_KEY)).await;
    assert_eq!(authed["authenticated"], true);
    assert_eq!(
        find_repo(&authed, "secret-lib").unwrap()["visibility"],
        "private"
    );
    let pp = find_repo(&authed, "private-parent").unwrap();
    assert_eq!(pp["default_branch"], "trunk");
    let hist = find_repo(&authed, "history-only").unwrap();
    assert_eq!(hist["visibility"], Value::Null);
    assert_eq!(hist["latest_job_id"], "job-hist-1");
    assert_eq!(hist["status"], "passing");
    let child = find_repo(&authed, "child").unwrap();
    assert_eq!(child["parents"].as_array().unwrap().len(), 2);
    assert!(authed["fabric_rev"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn submodules_refresh_on_default_branch_push_touching_gitmodules() {
    let api = spawn_github_mock().await;
    let console = ConsoleState::new(ConsoleConfig {
        github_api_url: Some(api),
        ..ConsoleConfig::default()
    });
    let state = make_state(Some(API_KEY), console);
    let app = create_router(state.clone());

    let status = post_webhook(
        &app,
        "push",
        json!({
            "ref": "refs/heads/main",
            "after": "2222222222222222222222222222222222222222",
            "repository": repo_obj("LMA1980/parent", false),
            "sender": {"login": "LMA1980"},
            "commits": [{"added": [], "modified": [".gitmodules"], "removed": []}],
        }),
    )
    .await;
    assert!(status.is_success());

    let mut subs = Value::Null;
    for _ in 0..50 {
        let (_, list) = get_json(&app, "/api/repos", None).await;
        if let Some(p) = find_repo(&list, "parent") {
            if p["submodules"].as_array().map(|a| a.len()) == Some(2) {
                subs = p["submodules"].clone();
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(subs[0]["repo"], "child");
    assert_eq!(subs[0]["pinned_sha"], SHA_CORE);
}

#[tokio::test]
async fn summary_scorecard_and_visibility() {
    let state = seeded_state().await;
    let store = &state.job_store;
    completed_job(
        store,
        "job-p-1",
        "LMA1980/parent",
        "refs/heads/main",
        "3333333333333333333333333333333333333333",
        20,
        Some(metrics(88, 80.0, "1 benches (10.0 µs/iter)")),
    )
    .await;
    completed_job(
        store,
        "job-p-2",
        "LMA1980/parent",
        "refs/heads/main",
        "4444444444444444444444444444444444444444",
        10,
        Some(metrics(92, 87.5, "1 benches (11.0 µs/iter)")),
    )
    .await;
    completed_job(
        store,
        "job-s-1",
        "LMA1980/secret-lib",
        "refs/heads/main",
        "5555555555555555555555555555555555555555",
        5,
        Some(metrics(70, 50.0, "")),
    )
    .await;
    let app = create_router(state.clone());

    let (status, s) = get_json(&app, "/api/repos/LMA1980/parent/summary", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(s["status"], "passing");
    assert_eq!(s["branch"], "main");
    assert_eq!(s["latest_completed_job_id"], "job-p-2");
    assert_eq!(s["score"], 92);
    assert_eq!(s["coverage"], 87.5);
    assert_eq!(s["coverage_bp"], 8750);
    assert_eq!(s["bench_delta"], 10.0);
    let hist: Vec<&str> = s["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["job_id"].as_str().unwrap())
        .collect();
    assert_eq!(hist, vec!["job-p-1", "job-p-2"], "history is oldest-first");
    assert_eq!(s["submodules"].as_array().unwrap().len(), 2);

    // The list carries the same CI numbers.
    let (_, list) = get_json(&app, "/api/repos", None).await;
    let p = find_repo(&list, "parent").unwrap();
    assert_eq!(p["latest_job_id"], "job-p-2");
    assert_eq!(p["score"], 92);
    assert_eq!(p["bench_delta"], 10.0);

    // Unknown -> 404; private + anonymous -> 404 (not 403); private + key -> 200.
    let (status, _) = get_json(&app, "/api/repos/LMA1980/does-not-exist/summary", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get_json(&app, "/api/repos/LMA1980/secret-lib/summary", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, s) = get_json(&app, "/api/repos/LMA1980/secret-lib/summary", Some(API_KEY)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(s["score"], 70);
    let (status, _) = get_json(&app, "/api/repos/LMA1980/secret-lib/topology", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn topology_tracks_simulated_webhooks() {
    let state = make_state(None, ConsoleState::default());
    let app = create_router(state.clone());
    let full = "LMA1980/railway";

    // Branch created (feat/**) and an unrelated non-feat branch.
    assert!(post_webhook(
        &app,
        "create",
        json!({"ref": "feat/rail", "ref_type": "branch", "master_branch": "main",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await
    .is_success());
    assert!(post_webhook(
        &app,
        "create",
        json!({"ref": "experiment", "ref_type": "branch",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await
    .is_success());

    let (status, t0) = get_json(&app, "/api/repos/LMA1980/railway/topology", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(t0["stations_source"], "default");
    let ids: Vec<&str> = t0["stations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec!["fmt-check", "clippy-check", "native-k3"]);
    let refs: Vec<&str> = t0["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["ref"].as_str().unwrap())
        .collect();
    assert_eq!(
        refs,
        vec!["feat/rail"],
        "non-feat branch without PR is hidden"
    );
    let rev0 = t0["fabric_rev"].as_u64().unwrap();

    // Push to the branch (queues a train) and open PRs on feat/rail and fix/bug.
    assert!(post_webhook(
        &app,
        "push",
        json!({"ref": "refs/heads/feat/rail", "after": "6666666666666666666666666666666666666666",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await
    .is_success());
    for (number, head, draft) in [(7, "feat/rail", false), (8, "fix/bug", true)] {
        assert!(post_webhook(
            &app,
            "pull_request",
            json!({"action": "opened", "number": number,
                   "repository": repo_obj(full, false), "sender": {"login": "LMA1980"},
                   "pull_request": {"number": number, "draft": draft, "author_association": "OWNER",
                       "head": {"ref": head, "sha": "7777777777777777777777777777777777777777",
                                "repo": {"full_name": full}},
                       "base": {"ref": "main", "repo": {"full_name": full}}}}),
        )
        .await
        .is_success());
    }

    // Give the queued train stages, one running on a node.
    let jobs = state.job_store.list_jobs().await;
    let train_job = jobs
        .iter()
        .filter(|j| j.job.repo_name == full && j.job.ref_name.ends_with("feat/rail"))
        .max_by_key(|j| j.job.queued_at)
        .expect("push / PR queued a job");
    let job_id = train_job.job.id.clone();
    let stage = |id: &str| StageRecord {
        id: id.to_string(),
        name: id.to_uppercase(),
        tags: vec![],
        threads: 2,
        toolchain: None,
        depends_on: vec![],
        status: StageStatus::Pending,
        assigned_node: None,
        exclusive: false,
    };
    state
        .job_store
        .set_stages(&job_id, vec![stage("fmt"), stage("clippy"), stage("test")])
        .await;
    state
        .job_store
        .update_stage_status(
            &job_id,
            "fmt",
            StageStatus::Completed {
                duration_secs: 1,
                exit_code: 0,
            },
        )
        .await;
    state
        .job_store
        .update_stage_status(
            &job_id,
            "clippy",
            StageStatus::Running {
                node_id: "node-a".to_string(),
                started_at: Utc::now(),
                pid: None,
            },
        )
        .await;

    let (_, t1) = get_json(&app, "/api/repos/LMA1980/railway/topology", None).await;
    assert!(t1["fabric_rev"].as_u64().unwrap() > rev0);
    assert_eq!(t1["stations_source"], "job");
    let branches = t1["branches"].as_array().unwrap();
    let rail = branches.iter().find(|b| b["ref"] == "feat/rail").unwrap();
    assert_eq!(rail["pr_state"], "open");
    assert_eq!(rail["pr_number"], 7);
    assert_eq!(rail["base_ref"], "main");
    assert_eq!(rail["last_job"]["job_id"], job_id.as_str());
    assert_eq!(rail["last_job"]["stage"], "clippy");
    let bug = branches.iter().find(|b| b["ref"] == "fix/bug").unwrap();
    assert_eq!(bug["pr_state"], "draft", "open-PR branch listed");

    let train = t1["trains"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["job_id"] == job_id.as_str())
        .unwrap();
    assert_eq!(train["ref"], "feat/rail");
    assert_eq!(train["stage"], "clippy");
    assert_eq!(train["node_id"], "node-a");
    assert_eq!(
        train["stage_states"],
        json!([
            {"station": "fmt", "state": "passed", "node_id": null},
            {"station": "clippy", "state": "running", "node_id": "node-a"},
            {"station": "test", "state": "pending", "node_id": null},
        ])
    );

    // PR merged, then branch deleted: siding leaves the topology.
    assert!(post_webhook(
        &app,
        "pull_request",
        json!({"action": "closed", "number": 7,
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"},
               "pull_request": {"number": 7, "merged": true, "author_association": "OWNER",
                   "merge_commit_sha": "8888888888888888888888888888888888888888",
                   "head": {"ref": "feat/rail", "sha": "7777777777777777777777777777777777777777",
                            "repo": {"full_name": full}},
                   "base": {"ref": "main", "repo": {"full_name": full}}}}),
    )
    .await
    .is_success());
    let (_, t2) = get_json(&app, "/api/repos/LMA1980/railway/topology", None).await;
    let rail = t2["branches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["ref"] == "feat/rail")
        .unwrap();
    assert_eq!(rail["pr_state"], "merged");

    assert!(post_webhook(
        &app,
        "delete",
        json!({"ref": "feat/rail", "ref_type": "branch",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await
    .is_success());
    let (_, t3) = get_json(&app, "/api/repos/LMA1980/railway/topology", None).await;
    assert!(t3["branches"]
        .as_array()
        .unwrap()
        .iter()
        .all(|b| b["ref"] != "feat/rail"));
    assert!(t3["fabric_rev"].as_u64().unwrap() > t2["fabric_rev"].as_u64().unwrap());
}

/// Reads SSE frames until one with `event: <kind>` arrives; returns the accumulated text.
async fn read_until<S>(stream: &mut S, kind: &str) -> String
where
    S: futures_util::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin,
{
    let mut acc = String::new();
    let needle = format!("event: {kind}\n");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !acc.contains(&needle) {
        let chunk = tokio::time::timeout_at(deadline, stream.next())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {kind}; got:\n{acc}"))
            .expect("stream ended")
            .expect("stream error");
        acc.push_str(&String::from_utf8_lossy(&chunk));
    }
    acc
}

fn frame_data(acc: &str, kind: &str) -> Value {
    let needle = format!("event: {kind}\n");
    let start = acc.rfind(&needle).unwrap() + needle.len();
    let line = acc[start..]
        .lines()
        .find(|l| l.starts_with("data: "))
        .unwrap();
    serde_json::from_str(&line["data: ".len()..]).unwrap()
}

#[tokio::test]
async fn sse_emits_additive_console_kinds_and_filters_private() {
    // No API key configured: the stream is open and anonymous.
    let state = make_state(None, ConsoleState::default());
    let app = create_router(state.clone());
    state
        .console
        .reconcile(&state.job_store, &state.cluster)
        .await; // baseline

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = resp.into_body().into_data_stream();
    let initial = read_until(&mut stream, "cluster").await;
    assert!(initial.contains("event: queue\n") && initial.contains("event: jobs\n"));

    // Private repository events never reach anonymous subscribers.
    post_webhook(
        &app,
        "create",
        json!({"ref": "feat/hidden", "ref_type": "branch",
               "repository": repo_obj("LMA1980/top-secret", true), "sender": {"login": "LMA1980"}}),
    )
    .await;
    let full = "LMA1980/sse-public";
    post_webhook(
        &app,
        "create",
        json!({"ref": "feat/sse", "ref_type": "branch",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await;
    let acc = read_until(&mut stream, "branch_created").await;
    assert!(!acc.contains("top-secret"), "private event leaked: {acc}");
    let created = frame_data(&acc, "branch_created");
    assert_eq!(created["repo"], "sse-public");
    assert_eq!(created["ref"], "feat/sse");
    let rev1 = created["fabric_rev"].as_u64().unwrap();

    post_webhook(
        &app,
        "pull_request",
        json!({"action": "opened", "number": 11,
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"},
               "pull_request": {"number": 11, "author_association": "OWNER",
                   "head": {"ref": "feat/sse", "sha": "9999999999999999999999999999999999999999",
                            "repo": {"full_name": full}},
                   "base": {"ref": "main", "repo": {"full_name": full}}}}),
    )
    .await;
    let acc = read_until(&mut stream, "pr_state_changed").await;
    let pr = frame_data(&acc, "pr_state_changed");
    assert_eq!(pr["pr_state"], "open");
    assert_eq!(pr["previous_state"], "none");
    assert_eq!(pr["pr_number"], 11);
    assert!(pr["fabric_rev"].as_u64().unwrap() > rev1);

    post_webhook(
        &app,
        "delete",
        json!({"ref": "feat/sse", "ref_type": "branch",
               "repository": repo_obj(full, false), "sender": {"login": "LMA1980"}}),
    )
    .await;
    let acc = read_until(&mut stream, "branch_deleted").await;
    assert_eq!(frame_data(&acc, "branch_deleted")["ref"], "feat/sse");

    // job_stage_changed from the reconciler.
    completed_job(
        &state.job_store,
        "job-sse-stage",
        full,
        "refs/heads/main",
        "abababababababababababababababababababab",
        1,
        None,
    )
    .await;
    state
        .job_store
        .set_stages(
            "job-sse-stage",
            vec![StageRecord {
                id: "fmt".to_string(),
                name: "FMT".to_string(),
                tags: vec![],
                threads: 2,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Pending,
                assigned_node: None,
                exclusive: false,
            }],
        )
        .await;
    state
        .console
        .reconcile(&state.job_store, &state.cluster)
        .await;
    state
        .job_store
        .update_stage_status(
            "job-sse-stage",
            "fmt",
            StageStatus::Running {
                node_id: "node-a".to_string(),
                started_at: Utc::now(),
                pid: None,
            },
        )
        .await;
    state
        .console
        .reconcile(&state.job_store, &state.cluster)
        .await;
    let acc = read_until(&mut stream, "job_stage_changed").await;
    let st = frame_data(&acc, "job_stage_changed");
    assert_eq!(st["job_id"], "job-sse-stage");
    assert_eq!(st["stage"], "fmt");
    assert_eq!(st["state"], "running");
    assert_eq!(st["previous_state"], "pending");
    assert_eq!(st["node_id"], "node-a");

    // node_membership_changed on worker join.
    let (cmd_tx, _cmd_rx) = tokio::sync::mpsc::channel(4);
    state
        .cluster
        .register(
            action_runner_ipc::WorkerRegistration {
                node_id: "worker-riscv64".to_string(),
                arch: "riscv64".to_string(),
                tags: vec!["k3".to_string()],
                max_slots: 1,
                ram_total_mb: 1024,
                btrfs_enabled: false,
                toolchains: vec!["system".to_string()],
            },
            cmd_tx,
        )
        .await;
    state
        .console
        .reconcile(&state.job_store, &state.cluster)
        .await;
    let acc = read_until(&mut stream, "node_membership_changed").await;
    let nm = frame_data(&acc, "node_membership_changed");
    assert_eq!(nm["node_id"], "worker-riscv64");
    assert_eq!(nm["change"], "joined");
    assert_eq!(nm["online_nodes"], json!(["worker-riscv64"]));
}

#[tokio::test]
async fn sse_private_events_reach_authenticated_streams() {
    let state = make_state(Some(API_KEY), ConsoleState::default());
    let app = create_router(state.clone());
    // Existing behaviour unchanged: a configured key is required for the stream.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/events?token={API_KEY}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut stream = resp.into_body().into_data_stream();
    read_until(&mut stream, "cluster").await;
    post_webhook(
        &app,
        "create",
        json!({"ref": "feat/hidden", "ref_type": "branch",
               "repository": repo_obj("LMA1980/top-secret", true), "sender": {"login": "LMA1980"}}),
    )
    .await;
    let acc = read_until(&mut stream, "branch_created").await;
    assert_eq!(frame_data(&acc, "branch_created")["repo"], "top-secret");
}

#[tokio::test]
async fn registry_cache_survives_restart_and_keeps_fabric_rev_monotonic() {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("console_registry.json");
    let cfg = || ConsoleConfig {
        cache_file: Some(cache.clone()),
        ..ConsoleConfig::default()
    };
    let store = JobStore::new(10, None);
    let console = ConsoleState::new(cfg());
    console
        .observe_webhook(
            "create",
            &json!({"ref": "feat/persist", "ref_type": "branch",
                    "repository": repo_obj("LMA1980/cached", false)}),
            &store,
        )
        .await;
    let rev = console.fabric_rev().await;
    assert!(rev >= 1);

    let restarted = ConsoleState::new(cfg());
    assert_eq!(restarted.fabric_rev().await, rev);
    let entry = restarted.entry("LMA1980", "cached").await.unwrap();
    assert!(entry.branches.contains_key("feat/persist"));
}
