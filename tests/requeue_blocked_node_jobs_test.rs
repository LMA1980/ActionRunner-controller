use chrono::{Duration as ChronoDuration, Utc};
use mu_ci_controller::cluster::{ClusterRegistry, WorkerCommand};
use mu_ci_controller::config::Config;
use mu_ci_controller::job::{Job, JobStatus, JobStore, StageRecord, StageStatus};
use mu_ci_controller::scheduler::DAGScheduler;
use mu_ci_ipc::WorkerRegistration;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;

fn make_worker_reg(node_id: &str, arch: &str, tags: &[&str], max_slots: u32) -> WorkerRegistration {
    WorkerRegistration {
        node_id: node_id.to_string(),
        arch: arch.to_string(),
        tags: tags.iter().map(|t| (*t).to_string()).collect(),
        max_slots,
        ram_total_mb: 32768,
        btrfs_enabled: false,
        toolchains: vec!["system".to_string()],
    }
}

async fn init_test_git_repo(ws_path: &Path, repo_name: &str, workflow_yaml: &str) -> String {
    let repo_path = ws_path.join("repos").join(repo_name);
    let actionrunner_dir = repo_path.join(".actionrunner");
    tokio::fs::create_dir_all(&actionrunner_dir)
        .await
        .expect("create .actionrunner dir");
    tokio::fs::write(actionrunner_dir.join("ActionRunner.yml"), workflow_yaml)
        .await
        .expect("write ActionRunner.yml");

    for args in [
        &["init", "-b", "main"][..],
        &["config", "user.name", "CI Test"][..],
        &["config", "user.email", "ci@example.com"][..],
        &["config", "commit.gpgsign", "false"][..],
        &["add", "."][..],
        &["commit", "-m", "initial workflow"][..],
    ] {
        let out = tokio::process::Command::new("git")
            .args(args)
            .current_dir(&repo_path)
            .output()
            .await
            .expect("git command");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let rev = tokio::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&repo_path)
        .output()
        .await
        .expect("git rev-parse HEAD");
    String::from_utf8(rev.stdout)
        .expect("utf8 sha")
        .trim()
        .to_string()
}

fn spawn_simulated_worker(
    node_id: String,
    mut rx: mpsc::Receiver<WorkerCommand>,
    cluster: ClusterRegistry,
    job_store: JobStore,
    completion_log: Arc<Mutex<Vec<(String, String, String)>>>,
) {
    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            if let WorkerCommand::Dispatch(task) = cmd {
                job_store
                    .update_stage_running(&task.job_id, &task.stage_id, &node_id, 4242)
                    .await;
                sleep(Duration::from_millis(15)).await;
                completion_log.lock().await.push((
                    node_id.clone(),
                    task.job_id.clone(),
                    task.stage_id.clone(),
                ));
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

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn test_blocked_node_specific_jobs_yield_to_queue_without_starving_pipeline() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("controller_ws");
    tokio::fs::create_dir_all(&ws_path)
        .await
        .expect("create controller ws");

    let hybrid_workflow = r#"
version: "3"
name: "Hybrid Pipeline"
tasks:
  fmt-task:
    tool: "cargo-fmt"
    args: ["--check"]
  k3-task:
    tool: "cargo-test"
    args: ["--workspace"]
stages:
  - id: stage-fmt
    name: "Format"
    tasks: ["fmt-task"]
    tags: ["fmt"]
    threads: 2
  - id: stage-k3-test
    name: "Hardware Test"
    tasks: ["k3-task"]
    tags: ["k3"]
    threads: 6
    exclusive: true
    depends_on: ["stage-fmt"]
on_action:
  push: ["stage-fmt", "stage-k3-test"]
"#;

    let general_workflow = r#"
version: "3"
name: "General Pipeline"
tasks:
  fmt-task:
    tool: "cargo-fmt"
    args: ["--check"]
  clippy-task:
    tool: "cargo-clippy"
    args: ["--workspace"]
stages:
  - id: stage-fmt
    name: "Format"
    tasks: ["fmt-task"]
    tags: ["fmt"]
    threads: 2
  - id: stage-clippy
    name: "Clippy"
    tasks: ["clippy-task"]
    tags: ["clippy"]
    threads: 2
    depends_on: ["stage-fmt"]
on_action:
  push: ["stage-fmt", "stage-clippy"]
"#;

    let config = Config {
        workspace_dir: ws_path.clone(),
        max_concurrent_jobs: 3,
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        ..Config::default()
    };

    let job_store = JobStore::new(100, Some(&ws_path));
    let cluster = ClusterRegistry::new();
    let completion_log: Arc<Mutex<Vec<(String, String, String)>>> =
        Arc::new(Mutex::new(Vec::new()));

    // Register two general compilation workers (`node-a`, `node-b`); `worker-riscv64` (`k3`) is offline.
    for node_id in ["node-a", "node-b"] {
        let (tx, rx) = mpsc::channel(32);
        cluster
            .register(
                make_worker_reg(node_id, "x86_64", &["x86_64", "fmt", "clippy"], 1),
                tx,
            )
            .await;
        spawn_simulated_worker(
            node_id.to_string(),
            rx,
            cluster.clone(),
            job_store.clone(),
            completion_log.clone(),
        );
    }

    let t0 = Utc::now() - ChronoDuration::seconds(600);

    // Enqueue 6 hybrid jobs (> max_concurrent_jobs = 3) FIRST so they sit at the head of the FIFO queue.
    for idx in 1..=6 {
        let repo_name = format!("org/repo-hybrid-{idx}");
        let sha = init_test_git_repo(&ws_path, &repo_name, hybrid_workflow).await;
        let clone_url = ws_path
            .join("repos")
            .join(&repo_name)
            .to_string_lossy()
            .to_string();
        let job_id = format!("job-hybrid-{idx}");
        let job = Job {
            id: job_id.clone(),
            event_type: "push".to_string(),
            repo_name: repo_name.clone(),
            clone_url,
            commit_sha: sha,
            ref_name: "refs/heads/main".to_string(),
            sender: "ci-bot".to_string(),
            queued_at: t0 + ChronoDuration::seconds((idx as i64) * 10),
        };
        job_store
            .enqueue_job(job, PathBuf::from(format!("logs/{repo_name}/{job_id}.log")))
            .await;
    }

    // Enqueue 3 general x86_64 jobs AFTER all 6 hybrid jobs.
    for idx in 1..=3 {
        let repo_name = format!("org/repo-general-{idx}");
        let sha = init_test_git_repo(&ws_path, &repo_name, general_workflow).await;
        let clone_url = ws_path
            .join("repos")
            .join(&repo_name)
            .to_string_lossy()
            .to_string();
        let job_id = format!("job-general-{idx}");
        let job = Job {
            id: job_id.clone(),
            event_type: "push".to_string(),
            repo_name: repo_name.clone(),
            clone_url,
            commit_sha: sha,
            ref_name: "refs/heads/main".to_string(),
            sender: "ci-bot".to_string(),
            queued_at: t0 + ChronoDuration::seconds(100 + (idx as i64) * 10),
        };
        job_store
            .enqueue_job(job, PathBuf::from(format!("logs/{repo_name}/{job_id}.log")))
            .await;
    }

    let scheduler = Arc::new(DAGScheduler::new(
        config,
        job_store.clone(),
        cluster.clone(),
    ));
    let sched_handle = tokio::spawn(scheduler.run_loop());

    // Wait until all 3 general jobs reach Completed and all 6 hybrid jobs have yielded back to Queued
    // with `stage-fmt` pre-computed and `stage-k3-test` Pending.
    let mut unblocked_ok = false;
    for _ in 0..200 {
        let mut all_general_done = true;
        for idx in 1..=3 {
            let rec = job_store
                .get_job(&format!("job-general-{idx}"))
                .await
                .expect("general job exists");
            if !matches!(rec.status, JobStatus::Completed { exit_code: 0, .. }) {
                all_general_done = false;
                break;
            }
        }

        let mut all_hybrid_requeued = true;
        for idx in 1..=6 {
            let rec = job_store
                .get_job(&format!("job-hybrid-{idx}"))
                .await
                .expect("hybrid job exists");
            let fmt_done = rec.stages.iter().any(|s| {
                s.id == "stage-fmt"
                    && matches!(s.status, StageStatus::Completed { exit_code: 0, .. })
            });
            let k3_pending = rec
                .stages
                .iter()
                .any(|s| s.id == "stage-k3-test" && matches!(s.status, StageStatus::Pending));
            if !matches!(rec.status, JobStatus::Queued) || !fmt_done || !k3_pending {
                all_hybrid_requeued = false;
                break;
            }
        }

        if all_general_done && all_hybrid_requeued {
            unblocked_ok = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }

    assert!(
        unblocked_ok,
        "Blocked node-specific jobs must yield back to Queued and allow subsequent general pipelines to complete"
    );

    let snap = job_store.queue_snapshot().await;
    assert_eq!(
        snap.stats.running_jobs, 0,
        "Zero jobs should remain stuck in Running when target node is offline"
    );
    assert_eq!(snap.stats.queued_jobs, 6);
    assert_eq!(snap.stats.completed_jobs, 3);

    // Verify original FIFO queue positions 1..=6 are preserved across all 6 re-queued hybrid jobs.
    for idx in 1..=6 {
        assert_eq!(
            job_store
                .job_queue_position(&format!("job-hybrid-{idx}"))
                .await,
            Some(idx)
        );
    }

    // Now bring `worker-riscv64` online and verify all 6 hybrid jobs resume in FIFO order
    // without re-executing `stage-fmt`.
    let (k3_tx, k3_rx) = mpsc::channel(32);
    cluster
        .register(
            make_worker_reg("worker-riscv64", "riscv64", &["riscv64", "k3"], 1),
            k3_tx,
        )
        .await;
    spawn_simulated_worker(
        "worker-riscv64".to_string(),
        k3_rx,
        cluster.clone(),
        job_store.clone(),
        completion_log.clone(),
    );
    job_store.notify_event();

    let mut all_hybrid_completed = false;
    for _ in 0..200 {
        let mut done = true;
        for idx in 1..=6 {
            let rec = job_store
                .get_job(&format!("job-hybrid-{idx}"))
                .await
                .expect("hybrid job");
            if !matches!(rec.status, JobStatus::Completed { exit_code: 0, .. }) {
                done = false;
                break;
            }
        }
        if done {
            all_hybrid_completed = true;
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }

    assert!(
        all_hybrid_completed,
        "All 6 re-queued hybrid jobs must resume and complete once worker-riscv64 connects"
    );

    let log_entries = completion_log.lock().await.clone();
    let k3_order: Vec<String> = log_entries
        .iter()
        .filter(|(node, _, stage)| node == "worker-riscv64" && stage == "stage-k3-test")
        .map(|(_, jid, _)| jid.clone())
        .collect();
    assert_eq!(
        k3_order,
        vec![
            "job-hybrid-1",
            "job-hybrid-2",
            "job-hybrid-3",
            "job-hybrid-4",
            "job-hybrid-5",
            "job-hybrid-6",
        ],
        "Re-queued hybrid jobs must resume on worker-riscv64 in strict original FIFO order"
    );

    for idx in 1..=6 {
        let target_jid = format!("job-hybrid-{idx}");
        let fmt_runs = log_entries
            .iter()
            .filter(|(_, jid, stage)| *jid == target_jid && stage == "stage-fmt")
            .count();
        assert_eq!(
            fmt_runs, 1,
            "{target_jid} must not re-run already completed stage-fmt on resume"
        );
    }

    sched_handle.abort();
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn test_orphan_running_jobs_self_heal_to_queued_and_unblock_capacity() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("controller_ws");
    tokio::fs::create_dir_all(&ws_path).await.expect("ws_path");

    let store = JobStore::new(50, Some(&ws_path));
    let cluster = ClusterRegistry::new();

    let (tx, _rx) = mpsc::channel(16);
    cluster
        .register(make_worker_reg("node-a", "x86_64", &["fmt"], 1), tx)
        .await;

    let t0 = Utc::now() - ChronoDuration::seconds(120);

    // Artificially leave 3 jobs in `JobStatus::Running` with `!is_job_in_flight`, zero active stages,
    // and zero cluster leases, saturating `max_concurrent = 3` while waiting on offline `k3`.
    for idx in 1..=3 {
        let jid = format!("job-orphan-{idx}");
        let job = Job {
            id: jid.clone(),
            event_type: "push".to_string(),
            repo_name: format!("org/orphan-{idx}"),
            clone_url: String::new(),
            commit_sha: format!("sha-orphan-{idx}"),
            ref_name: "refs/heads/main".to_string(),
            sender: "ci-bot".to_string(),
            queued_at: t0 + ChronoDuration::seconds((idx as i64) * 5),
        };
        store
            .enqueue_job(job, PathBuf::from(format!("logs/orphan-{idx}.log")))
            .await;
        store
            .set_stages(
                &jid,
                vec![
                    StageRecord {
                        id: "stage-fmt".to_string(),
                        name: "Format".to_string(),
                        tags: vec!["fmt".to_string()],
                        threads: 2,
                        toolchain: None,
                        depends_on: vec![],
                        status: StageStatus::Completed {
                            duration_secs: 1,
                            exit_code: 0,
                        },
                        assigned_node: Some("node-a".to_string()),
                        exclusive: false,
                    },
                    StageRecord {
                        id: "stage-k3".to_string(),
                        name: "K3 Test".to_string(),
                        tags: vec!["k3".to_string()],
                        threads: 4,
                        toolchain: None,
                        depends_on: vec!["stage-fmt".to_string()],
                        status: StageStatus::Pending,
                        assigned_node: None,
                        exclusive: true,
                    },
                ],
            )
            .await;
        store
            .update_status(
                &jid,
                JobStatus::Running {
                    started_at: Utc::now(),
                },
            )
            .await;
        assert!(!store.is_job_in_flight(&jid));
    }

    // Enqueue a runnable job for `node-a` (`tags: ["fmt"]`)
    let runnable = Job {
        id: "job-runnable-4".to_string(),
        event_type: "push".to_string(),
        repo_name: "org/runnable-4".to_string(),
        clone_url: String::new(),
        commit_sha: "sha-runnable-4".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "ci-bot".to_string(),
        queued_at: t0 + ChronoDuration::seconds(50),
    };
    store
        .enqueue_job(runnable, PathBuf::from("logs/runnable-4.log"))
        .await;
    store
        .set_stages(
            "job-runnable-4",
            vec![StageRecord {
                id: "stage-fmt".to_string(),
                name: "Format".to_string(),
                tags: vec!["fmt".to_string()],
                threads: 2,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Pending,
                assigned_node: None,
                exclusive: false,
            }],
        )
        .await;

    // Single claim sweep must heal all 3 orphan Running jobs -> Queued AND claim job-runnable-4!
    let claimed = store
        .claim_next_queued_job_for_cluster(3, Some(&cluster))
        .await
        .expect("must heal orphan Running jobs and claim runnable job");
    assert_eq!(claimed.id, "job-runnable-4");

    for idx in 1..=3 {
        let rec = store
            .get_job(&format!("job-orphan-{idx}"))
            .await
            .expect("orphan record");
        assert!(
            matches!(rec.status, JobStatus::Queued),
            "Orphan unleased Running job-{idx} must be swept back to Queued"
        );
    }
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn test_claim_and_lease_eligibility_parity_for_stage_concurrency_limit() {
    let store = JobStore::new(20, None);
    let cluster = ClusterRegistry::new();

    let (tx, _rx) = mpsc::channel(16);
    cluster
        .register(make_worker_reg("node-a", "x86_64", &["ci"], 4), tx)
        .await;

    // Lease 1 shared stage on `node-a` (1 of 4 slots occupied).
    let initial = cluster
        .lease_slot(
            "job-active-1",
            "stage-shared",
            &["ci".to_string()],
            None,
            false,
        )
        .await;
    assert!(initial.is_some());

    // Enqueue a second job whose ready stage enforces `max_concurrent_per_node = 1`.
    let job2 = Job {
        id: "job-limited-2".to_string(),
        event_type: "push".to_string(),
        repo_name: "org/limited-repo".to_string(),
        clone_url: String::new(),
        commit_sha: "sha-limited".to_string(),
        ref_name: "refs/heads/main".to_string(),
        sender: "ci-bot".to_string(),
        queued_at: Utc::now(),
    };
    store
        .enqueue_job(job2, PathBuf::from("logs/limited-2.log"))
        .await;
    store
        .set_stages(
            "job-limited-2",
            vec![StageRecord {
                id: "stage-limited".to_string(),
                name: "Limited Stage".to_string(),
                tags: vec!["ci".to_string()],
                threads: 2,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Pending,
                assigned_node: None,
                exclusive: false,
            }],
        )
        .await;
    cluster.set_stage_concurrency_limits("job-limited-2", [("stage-limited".to_string(), 1)]);

    assert!(
        !cluster
            .has_available_slot_for_stage_with_limit(&["ci".to_string()], None, false, Some(1))
            .await
    );
    assert!(cluster
        .lease_slot_with_limit(
            "job-limited-2",
            "stage-limited",
            &["ci".to_string()],
            None,
            false,
            Some(1),
        )
        .await
        .is_none());

    // Claim must ALSO return None (matching `lease_slot_with_limit`) rather than falsely claiming
    // because `node-a` has `max_slots = 4`.
    let claim_blocked = store
        .claim_next_queued_job_for_cluster(3, Some(&cluster))
        .await;
    assert!(
        claim_blocked.is_none(),
        "Claim must respect per-stage max_concurrent_per_node limit to avoid Queued <-> Running spin"
    );

    // Release the occupied slot on `node-a` -> now `job-limited-2` can be claimed and leased!
    cluster
        .release_stage_slot("node-a", "job-active-1", "stage-shared")
        .await;
    let claim_ok = store
        .claim_next_queued_job_for_cluster(3, Some(&cluster))
        .await;
    assert_eq!(
        claim_ok.expect("claimed after slot release").id,
        "job-limited-2"
    );
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn test_closed_worker_channel_releases_slot_and_requeues_job() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let ws_path = temp_dir.path().join("controller_ws");
    tokio::fs::create_dir_all(&ws_path).await.expect("ws_path");

    let wf = r#"
version: "3"
name: "Single K3 Stage"
tasks:
  k3-task:
    tool: "cargo-test"
    args: ["--workspace"]
stages:
  - id: stage-k3
    name: "K3 Stage"
    tasks: ["k3-task"]
    tags: ["k3"]
    threads: 4
on_action:
  push: ["stage-k3"]
"#;

    let repo_name = "org/repo-closed-chan";
    let sha = init_test_git_repo(&ws_path, repo_name, wf).await;
    let clone_url = ws_path
        .join("repos")
        .join(repo_name)
        .to_string_lossy()
        .to_string();

    let config = Config {
        workspace_dir: ws_path.clone(),
        max_concurrent_jobs: 2,
        job_timeout_seconds: 30,
        allow_insecure_no_secret: true,
        ..Config::default()
    };
    let job_store = JobStore::new(20, Some(&ws_path));
    let cluster = ClusterRegistry::new();

    // Register `worker-riscv64`, then immediately drop `rx` so `cmd_tx.send` fails on dispatch.
    let (tx, rx) = mpsc::channel(4);
    cluster
        .register(make_worker_reg("worker-riscv64", "riscv64", &["k3"], 1), tx)
        .await;
    drop(rx);

    let job = Job {
        id: "job-closed-chan-1".to_string(),
        event_type: "push".to_string(),
        repo_name: repo_name.to_string(),
        clone_url,
        commit_sha: sha,
        ref_name: "refs/heads/main".to_string(),
        sender: "ci-bot".to_string(),
        queued_at: Utc::now(),
    };
    job_store
        .enqueue_job(job, PathBuf::from("logs/closed-chan-1.log"))
        .await;

    let unreg_cluster = cluster.clone();
    let unreg_store = job_store.clone();
    let released_before_unreg = Arc::new(AtomicUsize::new(0));
    let released_flag = released_before_unreg.clone();
    tokio::spawn(async move {
        for _ in 0..50 {
            let rec = unreg_store.get_job("job-closed-chan-1").await;
            let stages_ready = rec.as_ref().is_some_and(|r| !r.stages.is_empty());
            if stages_ready
                && !unreg_cluster
                    .has_active_leases_for_job("job-closed-chan-1")
                    .await
            {
                released_flag.store(1, Ordering::SeqCst);
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        unreg_cluster.unregister("worker-riscv64").await;
        unreg_store.notify_event();
    });

    let scheduler = Arc::new(DAGScheduler::new(
        config,
        job_store.clone(),
        cluster.clone(),
    ));
    let sched_handle = tokio::spawn(scheduler.run_loop());

    let mut requeued = false;
    for _ in 0..100 {
        if let Some(rec) = job_store.get_job("job-closed-chan-1").await {
            if !rec.stages.is_empty()
                && matches!(rec.status, JobStatus::Queued)
                && matches!(rec.stages[0].status, StageStatus::Pending)
            {
                requeued = true;
                break;
            }
        }
        sleep(Duration::from_millis(30)).await;
    }

    assert_eq!(
        released_before_unreg.load(Ordering::SeqCst),
        1,
        "Closed worker command channel must immediately release the leased stage slot"
    );
    assert!(
        requeued,
        "Job must return to JobStatus::Queued with stage-k3 reset to Pending after closed channel dispatch"
    );

    sched_handle.abort();
}
