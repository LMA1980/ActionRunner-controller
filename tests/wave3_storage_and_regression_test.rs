//! Milestone 3 Wave 3 & Phase 3 (`#41`–`#47`, `M3.054`–`M3.065`) integration and parity tests for:
//! - `ControllerStorage` (`InMemoryStorage`, `MuObserveRemoteStorage`)
//! - Root W3C `traceparent` generation and propagation in `StageDispatchTask`
//! - `RegressionGateReport` evaluation (`Pass`, `Warn`, `Fail` / `RegressionDetected`)
//! - Phase 3 local DuckDB decommissioning (`Cargo.toml` zero `duckdb` linkage)

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::{TimeZone, Utc};
use muobserve_ipc::{
    decode_control_envelope, encode_control_envelope, read_frame, write_frame,
    BenchmarkRegressionItem, CentralBranchSnapshot, CentralJobRecord, CentralSubmoduleSnapshot,
    ControlRpcEnvelope, IpcHeader, QueryBranchSnapshotsResponse, QueryJobsHistoryResponse,
    QuerySubmoduleSnapshotsResponse, RegressionGateReport, RegressionGateRequest,
    RegressionVerdict, TestRegressionItem, TraceContext, UpsertJobRecordResponse,
    MSG_TYPE_FORY_CONTROL,
};
use tokio::net::TcpListener;

use action_runner_controller::job::{Job, JobMetrics, JobRecord, JobStatus, SubmoduleMetrics};
use action_runner_controller::scheduler::build_v3_stage_dispatch_task;
use action_runner_controller::storage_backend::{
    apply_regression_gate_to_job, compute_letter_grade, job_root_trace_context,
    job_root_traceparent, ControllerStorage, InMemoryStorage, MuObserveRemoteConfig,
    MuObserveRemoteStorage,
};
use action_runner_controller::workflow::{ActionRunnerWorkflow, StageConfig, TaskConfig};

#[derive(Default)]
struct MockMuObserveState {
    jobs: BTreeMap<String, CentralJobRecord>,
    branch_snapshots: BTreeMap<(String, String), CentralBranchSnapshot>,
    submodule_snapshots: BTreeMap<(String, String, String), CentralSubmoduleSnapshot>,
    next_regression_report: Option<RegressionGateReport>,
}

async fn spawn_mock_muobserve_server() -> (String, Arc<Mutex<MockMuObserveState>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock muobserve");
    let addr = listener.local_addr().expect("local addr").to_string();
    let state = Arc::new(Mutex::new(MockMuObserveState::default()));
    let state_clone = Arc::clone(&state);

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let st = Arc::clone(&state_clone);
            tokio::spawn(async move {
                while let Ok((hdr, payload)) = read_frame(&mut stream).await {
                    if hdr.msg_type != MSG_TYPE_FORY_CONTROL {
                        break;
                    }
                    let Ok(req_env) = decode_control_envelope(&payload) else {
                        break;
                    };
                    let resp_env = {
                        let mut guard = st.lock().expect("lock mock state");
                        match req_env {
                            ControlRpcEnvelope::UpsertJobRecordReq(req) => {
                                guard.jobs.insert(req.record.job_id.clone(), req.record);
                                let mut count = 1u32;
                                if let Some(b) = req.branch_snapshot {
                                    guard
                                        .branch_snapshots
                                        .insert((b.repo_key.clone(), b.branch_key.clone()), b);
                                    count += 1;
                                }
                                for s in req.submodule_snapshots {
                                    guard.submodule_snapshots.insert(
                                        (
                                            s.parent_repo_key.clone(),
                                            s.branch_key.clone(),
                                            s.submodule_key.clone(),
                                        ),
                                        s,
                                    );
                                    count += 1;
                                }
                                ControlRpcEnvelope::UpsertJobRecordResp(UpsertJobRecordResponse {
                                    request_id: req.request_id,
                                    accepted: true,
                                    upserted_count: count,
                                    error_message: None,
                                })
                            }
                            ControlRpcEnvelope::UpsertJobBatchReq(req) => {
                                let mut count = 0u32;
                                for r in req.records {
                                    guard.jobs.insert(r.job_id.clone(), r);
                                    count += 1;
                                }
                                for b in req.branch_snapshots {
                                    guard
                                        .branch_snapshots
                                        .insert((b.repo_key.clone(), b.branch_key.clone()), b);
                                    count += 1;
                                }
                                for s in req.submodule_snapshots {
                                    guard.submodule_snapshots.insert(
                                        (
                                            s.parent_repo_key.clone(),
                                            s.branch_key.clone(),
                                            s.submodule_key.clone(),
                                        ),
                                        s,
                                    );
                                    count += 1;
                                }
                                ControlRpcEnvelope::UpsertJobRecordResp(UpsertJobRecordResponse {
                                    request_id: req.request_id,
                                    accepted: true,
                                    upserted_count: count,
                                    error_message: None,
                                })
                            }
                            ControlRpcEnvelope::QueryJobsHistoryReq(req) => {
                                let mut records: Vec<CentralJobRecord> = guard
                                    .jobs
                                    .values()
                                    .filter(|r| {
                                        req.repo_key
                                            .as_ref()
                                            .map(|rk| &r.repo_key == rk)
                                            .unwrap_or(true)
                                            && req
                                                .branch_key
                                                .as_ref()
                                                .map(|bk| &r.branch_key == bk)
                                                .unwrap_or(true)
                                            && req
                                                .job_id
                                                .as_ref()
                                                .map(|jid| &r.job_id == jid)
                                                .unwrap_or(true)
                                    })
                                    .cloned()
                                    .collect();
                                records.sort_by(|a, b| {
                                    b.queued_at_us
                                        .cmp(&a.queued_at_us)
                                        .then_with(|| b.updated_at_us.cmp(&a.updated_at_us))
                                });
                                let limit = if req.limit == 0 {
                                    100
                                } else {
                                    req.limit as usize
                                };
                                records.truncate(limit);
                                ControlRpcEnvelope::QueryJobsHistoryResp(QueryJobsHistoryResponse {
                                    request_id: req.request_id,
                                    records,
                                })
                            }
                            ControlRpcEnvelope::QueryBranchSnapshotsReq(req) => {
                                let mut snapshots: Vec<CentralBranchSnapshot> = guard
                                    .branch_snapshots
                                    .values()
                                    .filter(|s| {
                                        req.repo_key
                                            .as_ref()
                                            .map(|rk| &s.repo_key == rk)
                                            .unwrap_or(true)
                                            && req
                                                .branch_key
                                                .as_ref()
                                                .map(|bk| &s.branch_key == bk)
                                                .unwrap_or(true)
                                    })
                                    .cloned()
                                    .collect();
                                snapshots.sort_by(|a, b| {
                                    a.repo_key
                                        .cmp(&b.repo_key)
                                        .then_with(|| a.branch_key.cmp(&b.branch_key))
                                });
                                ControlRpcEnvelope::QueryBranchSnapshotsResp(
                                    QueryBranchSnapshotsResponse {
                                        request_id: req.request_id,
                                        snapshots,
                                    },
                                )
                            }
                            ControlRpcEnvelope::QuerySubmoduleSnapshotsReq(req) => {
                                let mut snapshots: Vec<CentralSubmoduleSnapshot> = guard
                                    .submodule_snapshots
                                    .values()
                                    .filter(|s| {
                                        req.parent_repo_key
                                            .as_ref()
                                            .map(|pk| &s.parent_repo_key == pk)
                                            .unwrap_or(true)
                                            && req
                                                .submodule_key
                                                .as_ref()
                                                .map(|sk| &s.submodule_key == sk)
                                                .unwrap_or(true)
                                            && req
                                                .branch_key
                                                .as_ref()
                                                .map(|bk| &s.branch_key == bk)
                                                .unwrap_or(true)
                                    })
                                    .cloned()
                                    .collect();
                                snapshots.sort_by(|a, b| {
                                    a.parent_repo_key
                                        .cmp(&b.parent_repo_key)
                                        .then_with(|| a.branch_key.cmp(&b.branch_key))
                                        .then_with(|| a.submodule_key.cmp(&b.submodule_key))
                                });
                                ControlRpcEnvelope::QuerySubmoduleSnapshotsResp(
                                    QuerySubmoduleSnapshotsResponse {
                                        request_id: req.request_id,
                                        snapshots,
                                    },
                                )
                            }
                            ControlRpcEnvelope::RegressionGateReq(req) => {
                                let report = guard.next_regression_report.clone().unwrap_or(
                                    RegressionGateReport {
                                        request_id: req.request_id,
                                        repo_key: req.repo_key,
                                        candidate_commit: req.candidate_commit,
                                        baseline_branch: req.baseline_branch,
                                        verdict: RegressionVerdict::Pass,
                                        regressed_benchmarks: Vec::new(),
                                        flaky_or_failed_tests: Vec::new(),
                                        summary: "All benchmarks and tests within bounds".into(),
                                    },
                                );
                                ControlRpcEnvelope::RegressionGateResp(report)
                            }
                            _ => ControlRpcEnvelope::Noop,
                        }
                    };
                    let Ok(resp_bytes) = encode_control_envelope(&resp_env) else {
                        break;
                    };
                    let resp_hdr = IpcHeader::new(
                        MSG_TYPE_FORY_CONTROL,
                        resp_bytes.len() as u32,
                        0,
                        hdr.sequence,
                    );
                    if write_frame(&mut stream, &resp_hdr, &resp_bytes)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });

    (addr, state)
}

fn sample_job_record(
    id: &str,
    repo_name: &str,
    ref_name: &str,
    commit_sha: &str,
    queued_secs: i64,
    status: JobStatus,
    with_submodule: bool,
) -> JobRecord {
    let ts = Utc.timestamp_opt(queued_secs, 0).unwrap();
    let mut submodules = BTreeMap::new();
    if with_submodule {
        submodules.insert(
            "k3-core".to_string(),
            SubmoduleMetrics {
                name: "k3-core".to_string(),
                path: "code/core".to_string(),
                quality_score: 98,
                letter_grade: "A+".to_string(),
                coverage_pct: Some(92.5),
                benchmark_summary: Some("125 ns/iter".to_string()),
                tests_passed: 42,
                tests_total: 42,
                clippy_warnings: 0,
            },
        );
    }

    let metrics = if matches!(
        status,
        JobStatus::Completed { .. } | JobStatus::Failed { .. }
    ) {
        Some(JobMetrics {
            quality_score: 96,
            letter_grade: "A+".to_string(),
            coverage_pct: Some(91.0),
            benchmark_summary: Some("240 ns/iter".to_string()),
            tests_passed: 120,
            tests_total: 120,
            advisories_count: 0,
            clippy_warnings: 0,
            submodules,
        })
    } else {
        None
    };

    JobRecord {
        job: Job {
            id: id.to_string(),
            event_type: "push".to_string(),
            repo_name: repo_name.to_string(),
            clone_url: format!("https://github.com/{repo_name}.git"),
            commit_sha: commit_sha.to_string(),
            ref_name: ref_name.to_string(),
            sender: "LMA1980".to_string(),
            queued_at: ts,
        },
        status,
        log_file: PathBuf::from(format!("logs/{repo_name}/{id}.log")),
        updated_at: ts,
        metrics,
        stages: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_controller_storage_parity_in_memory_and_remote_subtask_43_and_46() {
    let (addr_remote, _state_remote) = spawn_mock_muobserve_server().await;

    let in_memory = InMemoryStorage::open();
    let remote_only =
        MuObserveRemoteStorage::new(MuObserveRemoteConfig::plain_tcp(addr_remote)).expect("remote");

    let rec1 = sample_job_record(
        "job-1001",
        "LMA1980/ActionRunner-controller",
        "refs/heads/main",
        "1111111122222222",
        1_700_000_100,
        JobStatus::Completed {
            duration_secs: 45,
            exit_code: 0,
        },
        true,
    );
    let rec2 = sample_job_record(
        "job-1002",
        "LMA1980/ActionRunner-controller",
        "refs/heads/main",
        "3333333344444444",
        1_700_000_200,
        JobStatus::Running {
            started_at: Utc.timestamp_opt(1_700_000_205, 0).unwrap(),
        },
        false,
    );
    let rec3 = sample_job_record(
        "job-1003",
        "LMA1980/ActionRunner-rs",
        "refs/heads/feat/telemetry",
        "5555555566666666",
        1_700_000_300,
        JobStatus::Completed {
            duration_secs: 30,
            exit_code: 0,
        },
        false,
    );

    // 1. Test upsert_record on both storage backends
    in_memory.upsert_record(&rec1);
    remote_only.upsert_record(&rec1);

    // 2. Test upsert_records_batch on both storage backends
    let batch = vec![rec2.clone(), rec3.clone()];
    in_memory.upsert_records_batch(&batch);
    remote_only.upsert_records_batch(&batch);

    // 3. Verify load_recent_jobs parity across InMemoryStorage and MuObserveRemoteStorage
    let jobs_local = in_memory.load_recent_jobs(10);
    let jobs_remote = remote_only.load_recent_jobs(10);

    assert_eq!(jobs_local.len(), 3);
    assert_eq!(jobs_local, jobs_remote);

    // 4. Verify load_branch_snapshots parity across both storage backends
    let branches_local = in_memory.load_branch_snapshots(None, None);
    let branches_remote = remote_only.load_branch_snapshots(None, None);

    assert_eq!(branches_local.len(), 2);
    assert_eq!(branches_local, branches_remote);

    // Check active vs completed snapshot tracking on main
    let main_snap = branches_remote
        .iter()
        .find(|s| s.repo_key == "lma1980/actionrunner-controller" && s.branch_key == "main")
        .expect("main branch snapshot");
    assert_eq!(main_snap.latest_active_job_id.as_deref(), Some("job-1002"));
    assert_eq!(
        main_snap.latest_completed_job_id.as_deref(),
        Some("job-1001")
    );

    // 5. Verify load_submodule_snapshots parity across both storage backends
    let subs_local = in_memory.load_submodule_snapshots(None, None, None);
    let subs_remote = remote_only.load_submodule_snapshots(None, None, None);

    assert_eq!(subs_local.len(), 1);
    assert_eq!(subs_local, subs_remote);

    // 6. Verify card context and submodule lookups match
    assert_eq!(
        in_memory.find_card_context("LMA1980/ActionRunner-controller", Some("main")),
        remote_only.find_card_context("LMA1980/ActionRunner-controller", Some("main"))
    );
    assert_eq!(
        in_memory.find_submodule_card_context(
            "LMA1980/ActionRunner-controller",
            "k3-core",
            Some("main")
        ),
        remote_only.find_submodule_card_context(
            "LMA1980/ActionRunner-controller",
            "k3-core",
            Some("main")
        )
    );
}

#[test]
fn test_w3c_root_traceparent_and_stage_dispatch_propagation_subtask_44() {
    let ctx = job_root_trace_context("job-1793535000-deadbeef", "deadbeefcafebabe");
    let tp = job_root_traceparent("job-1793535000-deadbeef", "deadbeefcafebabe");

    let parsed = TraceContext::parse_traceparent(&tp).expect("valid W3C traceparent");
    assert_eq!(parsed, ctx);
    assert_eq!(parsed.trace_flags, 0x01);

    let mut tasks_map = std::collections::HashMap::new();
    tasks_map.insert(
        "clippy".to_string(),
        TaskConfig {
            tool: "cargo-clippy".to_string(),
            args: vec!["--workspace".to_string()],
            working_dir: None,
            env: std::collections::HashMap::new(),
            timeout_seconds: Some(300),
            sandbox_profile: None,
            sccache: None,
        },
    );
    let stage = StageConfig {
        id: "lint".to_string(),
        name: "Fmt & Clippy".to_string(),
        tags: vec!["x86_64".to_string()],
        threads: 2,
        toolchain: Some("stable".to_string()),
        depends_on: Vec::new(),
        exclusive: false,
        max_concurrent_per_node: 1,
        tasks: vec!["clippy".to_string()],
        sccache: None,
    };
    let workflow = ActionRunnerWorkflow {
        version: "3".to_string(),
        name: "CI".to_string(),
        env: std::collections::HashMap::new(),
        sccache: None,
        tasks: tasks_map,
        stages: vec![stage.clone()],
        on_action: std::collections::HashMap::new(),
    };

    let task = build_v3_stage_dispatch_task(
        "job-1793535000-deadbeef",
        "LMA1980/ActionRunner-controller",
        "https://github.com/LMA1980/ActionRunner-controller.git",
        "deadbeefcafebabe",
        &stage,
        &workflow,
        1800,
    )
    .expect("build dispatch task");

    assert_eq!(task.traceparent.as_deref(), Some(tp.as_str()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_regression_gate_evaluation_and_scorecard_penalties_subtask_44() {
    let (addr, mock_state) = spawn_mock_muobserve_server().await;
    let remote =
        MuObserveRemoteStorage::new(MuObserveRemoteConfig::plain_tcp(addr)).expect("remote");

    let mut base_metrics = JobMetrics {
        quality_score: 98,
        letter_grade: "A+".to_string(),
        coverage_pct: Some(90.0),
        benchmark_summary: Some("110 ns/iter".to_string()),
        tests_passed: 50,
        tests_total: 50,
        advisories_count: 0,
        clippy_warnings: 0,
        submodules: BTreeMap::new(),
    };
    let mut status = JobStatus::Completed {
        duration_secs: 42,
        exit_code: 0,
    };

    // 1. Verdict::Pass preserves score and Completed status
    let pass_report = remote
        .evaluate_regression_gate(&RegressionGateRequest {
            request_id: "req-pass".into(),
            repo_key: "lma1980/k3-kernels-rvv".into(),
            candidate_commit: "aaaa1111".into(),
            baseline_branch: "main".into(),
            max_slowdown_pct: 10.0,
            max_flakiness_pct: 5.0,
        })
        .expect("pass report");
    assert_eq!(pass_report.verdict, RegressionVerdict::Pass);
    apply_regression_gate_to_job(&mut base_metrics, &mut status, &pass_report);
    assert_eq!(base_metrics.quality_score, 98);
    assert_eq!(base_metrics.letter_grade, "A+");
    assert!(matches!(status, JobStatus::Completed { exit_code: 0, .. }));

    // 2. Verdict::Warn deducts flaky-test penalty and updates letter grade without failing job
    let warn_report = RegressionGateReport {
        request_id: "req-warn".into(),
        repo_key: "lma1980/k3-kernels-rvv".into(),
        candidate_commit: "bbbb2222".into(),
        baseline_branch: "main".into(),
        verdict: RegressionVerdict::Warn,
        regressed_benchmarks: Vec::new(),
        flaky_or_failed_tests: vec![
            TestRegressionItem {
                crate_name: "k3-kernels-rvv".into(),
                test_binary: "rvv_test".into(),
                test_name: "test_q4_k_gemv_edge".into(),
                status: "flaky".into(),
                flakiness_pct: 6.5,
                flip_flop_count: 3,
                failure_summary: None,
            },
            TestRegressionItem {
                crate_name: "k3-kernels-rvv".into(),
                test_binary: "rvv_test".into(),
                test_name: "test_q8_0_dot".into(),
                status: "flaky".into(),
                flakiness_pct: 5.2,
                flip_flop_count: 2,
                failure_summary: None,
            },
        ],
        summary: "2 flaky tests detected over 30d window".into(),
    };
    apply_regression_gate_to_job(&mut base_metrics, &mut status, &warn_report);
    assert_eq!(base_metrics.quality_score, 88);
    assert_eq!(base_metrics.letter_grade, "B");
    assert!(matches!(status, JobStatus::Completed { exit_code: 0, .. }));

    // 3. Verdict::Fail (RegressionDetected) caps score <= 65 (D/F) and fails the job
    {
        let mut guard = mock_state.lock().unwrap();
        guard.next_regression_report = Some(RegressionGateReport {
            request_id: "req-fail".into(),
            repo_key: "lma1980/k3-kernels-rvv".into(),
            candidate_commit: "cccc3333".into(),
            baseline_branch: "main".into(),
            verdict: RegressionVerdict::Fail,
            regressed_benchmarks: vec![BenchmarkRegressionItem {
                crate_name: "k3-kernels-rvv".into(),
                bench_name: "bench_vmadot_a100_1024".into(),
                arch: "riscv64".into(),
                cpu_cluster: "A100".into(),
                vlen_bits: 1024,
                baseline_median_ns: 120.0,
                candidate_ns: 156.0,
                delta_pct: 30.0,
                mad_z_score: 6.4,
                regressed: true,
            }],
            flaky_or_failed_tests: vec![TestRegressionItem {
                crate_name: "k3-kernels-rvv".into(),
                test_binary: "rvv_test".into(),
                test_name: "test_vmadot_tile_bounds".into(),
                status: "failed".into(),
                flakiness_pct: 0.0,
                flip_flop_count: 1,
                failure_summary: Some("assertion failed".into()),
            }],
            summary: "bench_vmadot_a100_1024 regressed by +30.0% on (riscv64, A100, vlen=1024)"
                .into(),
        });
    }

    let fail_report = remote
        .evaluate_regression_gate(&RegressionGateRequest {
            request_id: "req-fail".into(),
            repo_key: "lma1980/k3-kernels-rvv".into(),
            candidate_commit: "cccc3333".into(),
            baseline_branch: "main".into(),
            max_slowdown_pct: 10.0,
            max_flakiness_pct: 5.0,
        })
        .expect("fail report");
    assert_eq!(fail_report.verdict, RegressionVerdict::Fail);

    apply_regression_gate_to_job(&mut base_metrics, &mut status, &fail_report);
    assert!(base_metrics.quality_score <= 65);
    assert_eq!(
        base_metrics.letter_grade,
        compute_letter_grade(base_metrics.quality_score)
    );
    match status {
        JobStatus::Failed { error } => {
            assert!(error.starts_with("RegressionDetected:"));
            assert!(error.contains("bench_vmadot_a100_1024"));
        }
        other => panic!("Expected JobStatus::Failed, got {other:?}"),
    }
}
