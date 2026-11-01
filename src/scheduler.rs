use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::cluster::{ClusterRegistry, WorkerCommand};
use crate::config::Config;
use crate::job::{Job, JobStatus, JobStore, StageRecord, StageStatus};
use crate::workflow::{ActionRunnerWorkflow, StageConfig};
use action_runner_ipc::{
    NetworkEgressMode, SandboxBackendKind, SandboxConstraintSpec, StageDispatchTask,
    TypedTaskInvocation,
};
use action_runner_tools::{SandboxProfileRequirement, ToolInvocation, ToolRegistry};

// ============================================================================
// Sub-tasks #37 & #38: ToolAdapter Dispatch & Security Validation
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("Unapproved or prohibited tool: {0}")]
    UnapprovedTool(String),
    #[error("Task '{0}' not found in workflow tasks")]
    TaskNotFound(String),
    #[error("Stage '{0}' not found in workflow")]
    StageNotFound(String),
}

pub fn sandbox_req_to_ipc_spec(
    profile_name: &str,
    req: &SandboxProfileRequirement,
) -> SandboxConstraintSpec {
    let network_mode = if req.allow_network {
        if req.allowed_egress_hosts.is_empty() {
            NetworkEgressMode::RestrictedCidrs(vec!["0.0.0.0/0".to_string()])
        } else {
            NetworkEgressMode::RestrictedCidrs(req.allowed_egress_hosts.clone())
        }
    } else {
        NetworkEgressMode::Offline
    };

    let read_paths = req
        .readable_dirs
        .iter()
        .filter(|p| p.starts_with('/'))
        .cloned()
        .collect();
    let write_paths = req
        .writable_dirs
        .iter()
        .filter(|p| p.starts_with('/'))
        .cloned()
        .collect();
    let exec_paths = req
        .exec_binaries
        .iter()
        .filter(|p| p.starts_with('/'))
        .cloned()
        .collect();

    SandboxConstraintSpec {
        profile_name: profile_name.to_string(),
        backend: SandboxBackendKind::Kernel,
        read_paths,
        write_paths,
        exec_paths,
        network_mode,
        memlock_limit_kb: req.required_memlock_kb,
        max_pids: 256,
        require_set_ai_thread: false,
    }
}

pub fn build_v3_stage_dispatch_task(
    job_id: &str,
    repo_name: &str,
    clone_url: &str,
    commit_sha: &str,
    stage: &StageConfig,
    workflow: &ActionRunnerWorkflow,
    default_timeout: u64,
) -> Result<StageDispatchTask, DispatchError> {
    let registry = ToolRegistry::with_builtin_adapters();
    let mut typed_tasks = Vec::new();
    let mut stage_timeout = default_timeout;

    for task_id in &stage.tasks {
        let task_cfg = workflow
            .tasks
            .get(task_id)
            .ok_or_else(|| DispatchError::TaskNotFound(task_id.clone()))?;

        // Immediately reject prohibited shell wrappers
        if action_runner_tools::sanitize::is_prohibited_shell_wrapper(&task_cfg.tool) {
            return Err(DispatchError::UnapprovedTool(format!(
                "Tool '{}' in task '{}' is a prohibited shell wrapper",
                task_cfg.tool, task_id
            )));
        }

        let adapter = registry.get(&task_cfg.tool).map_err(|e| {
            DispatchError::UnapprovedTool(format!(
                "Tool '{}' in task '{}' is not registered: {}",
                task_cfg.tool, task_id, e
            ))
        })?;

        let mut inv = ToolInvocation::new(&task_cfg.tool, task_cfg.args.clone());
        if let Some(ref wd) = task_cfg.working_dir {
            inv = inv.with_working_dir(wd);
        }
        for (k, v) in &task_cfg.env {
            inv = inv.with_env(k, v);
        }

        // Validate invocation arguments via adapter
        adapter.validate(&inv).map_err(|e| {
            DispatchError::UnapprovedTool(format!(
                "Task '{}' validation failed for tool '{}': {}",
                task_id, task_cfg.tool, e
            ))
        })?;

        let sandbox_req = adapter.sandbox_profile(&inv);
        let profile_name = task_cfg.sandbox_profile.as_deref().unwrap_or("default");
        let sandbox_spec = sandbox_req_to_ipc_spec(profile_name, &sandbox_req);

        let env_pairs: Vec<(String, String)> = task_cfg
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        if let Some(to) = task_cfg.timeout_seconds {
            stage_timeout = stage_timeout.min(to);
        }

        typed_tasks.push(TypedTaskInvocation {
            task_id: task_id.clone(),
            tool_name: task_cfg.tool.clone(),
            args: task_cfg.args.clone(),
            working_dir: task_cfg.working_dir.clone(),
            env_vars: env_pairs,
            sandbox: sandbox_spec,
        });
    }

    let command_summary = if typed_tasks.is_empty() {
        stage.name.clone()
    } else {
        typed_tasks
            .iter()
            .map(|t| format!("{} {}", t.tool_name, t.args.join(" ")))
            .collect::<Vec<_>>()
            .join(" && ")
    };

    let sandbox_constraints = typed_tasks
        .first()
        .map(|t| t.sandbox.clone())
        .unwrap_or_default();

    let stage_env_pairs: Vec<(String, String)> = workflow
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Ok(StageDispatchTask {
        job_id: job_id.to_string(),
        stage_id: stage.id.clone(),
        stage_name: stage.name.clone(),
        repo_name: repo_name.to_string(),
        clone_url: clone_url.to_string(),
        commit_sha: commit_sha.to_string(),
        command: command_summary,
        working_dir: None,
        env_vars: stage_env_pairs,
        timeout_seconds: stage_timeout,
        threads: stage.threads,
        toolchain: stage.toolchain.clone(),
        exclusive: stage.exclusive,
        max_concurrent_per_node: stage.max_concurrent_per_node,
        tasks: typed_tasks,
        sandbox_constraints,
        traceparent: Some(crate::storage_backend::job_root_traceparent(
            job_id, commit_sha,
        )),
    })
}

// ============================================================================
// Sub-task #27: Declarative ActionRunner.yml Resolver
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedWorkflow {
    V3(ActionRunnerWorkflow),
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowResolveError {
    #[error("Legacy workflows are disabled via ACTIONRUNNER_DISABLE_LEGACY=1")]
    LegacyDisabled,
    #[error("No workflow found for event '{event}' in '{path}'")]
    NotFound { path: String, event: String },
    #[error("Failed to parse or validate workflow: {0}")]
    Validation(String),
    #[error("I/O error: {0}")]
    Io(String),
}

pub fn resolve_workflow_for_event(
    repo_path: &Path,
    event: &str,
    _max_timeout: u64,
) -> Result<ResolvedWorkflow, WorkflowResolveError> {
    let actionrunner_dir = repo_path.join(".actionrunner");

    // 1. Check for ActionRunner.yml / ActionRunner.yaml first
    for name in ["ActionRunner.yml", "ActionRunner.yaml"] {
        let v3_path = actionrunner_dir.join(name);
        if v3_path.exists() {
            let content = std::fs::read_to_string(&v3_path)
                .map_err(|e| WorkflowResolveError::Io(e.to_string()))?;
            let wf = ActionRunnerWorkflow::from_yaml(&content)
                .map_err(WorkflowResolveError::Validation)?;
            let subgraph = wf
                .subgraph_for_event(event)
                .map_err(|e| WorkflowResolveError::Validation(e.to_string()))?;
            return Ok(ResolvedWorkflow::V3(subgraph));
        }
    }

    // 2. If ActionRunner.yml is absent, check if legacy workflows are disabled
    if std::env::var("ACTIONRUNNER_DISABLE_LEGACY").as_deref() == Ok("1") {
        return Err(WorkflowResolveError::LegacyDisabled);
    }

    Err(WorkflowResolveError::NotFound {
        path: repo_path.display().to_string(),
        event: event.to_string(),
    })
}

/// Default distributed pipeline used when a repository has no `.actionrunner/ActionRunner.yml`
/// (fmt and clippy on x86 workers, native verification on the RISC-V board).
pub const DEFAULT_WORKFLOW_YAML: &str = r#"
version: "3"
name: "Default Distributed Pipeline"
tasks:
  cargo-fmt:
    tool: "cargo-fmt"
    args: ["--check"]
  cargo-clippy:
    tool: "cargo-clippy"
    args: ["--all-targets", "--", "-D", "warnings"]
  cargo-test:
    tool: "cargo-test"
    args: ["--workspace"]
stages:
  - id: fmt-check
    name: "Verify Formatting"
    tasks: ["cargo-fmt"]
    tags: ["fmt"]
    threads: 2
  - id: clippy-check
    name: "Verify Linter Hygiene"
    tasks: ["cargo-clippy"]
    tags: ["clippy"]
    threads: 4
  - id: native-k3
    name: "Native Verification"
    tasks: ["cargo-test"]
    tags: ["k3"]
    depends_on: ["fmt-check", "clippy-check"]
    threads: 6
on_action:
  push: ["fmt-check", "clippy-check", "native-k3"]
  pull_request: ["fmt-check", "clippy-check", "native-k3"]
  pullrequest: ["fmt-check", "clippy-check", "native-k3"]
  merge: ["fmt-check", "clippy-check", "native-k3"]
  tag: ["fmt-check", "clippy-check", "native-k3"]
  release: ["fmt-check", "clippy-check", "native-k3"]
"#;

pub struct DAGScheduler {
    config: Config,
    job_store: JobStore,
    cluster: ClusterRegistry,
}

impl DAGScheduler {
    pub fn new(config: Config, job_store: JobStore, cluster: ClusterRegistry) -> Self {
        Self {
            config,
            job_store,
            cluster,
        }
    }

    pub async fn run_loop(self: Arc<Self>) {
        info!("ActionRunner DAG Scheduler loop active");

        loop {
            while let Some(job) = self
                .job_store
                .claim_next_queued_job(self.config.max_concurrent_jobs)
                .await
            {
                let this = self.clone();
                tokio::spawn(async move {
                    this.execute_job(job).await;
                });
            }

            self.job_store.wait_for_event().await;
        }
    }

    async fn execute_job(&self, job: Job) {
        let start_time = Utc::now();
        info!(
            job_id = %job.id,
            repo = %job.repo_name,
            commit = %job.commit_sha,
            event = %job.event_type,
            "Starting DAG pipeline execution"
        );

        self.job_store
            .update_status(
                &job.id,
                JobStatus::Running {
                    started_at: start_time,
                },
            )
            .await;

        let target_url = format!("https://hook.lma1980.duckdns.org/web/#/jobs/{}", job.id);
        self.report_github_status(
            &job.repo_name,
            &job.commit_sha,
            "pending",
            "ActionRunner distributed pipeline running...",
            Some(&target_url),
        )
        .await;

        let repo_workspace = self.config.workspace_dir.join("repos").join(&job.repo_name);
        let log_file_path = self
            .config
            .workspace_dir
            .join("logs")
            .join(&job.repo_name)
            .join(format!("{}.log", job.id));

        if let Some(parent) = log_file_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        // 1. Sync or inspect repo to resolve .actionrunner/ActionRunner.yml
        let workflow = match self.resolve_and_load_workflow(&job, &repo_workspace).await {
            Ok(wf) => wf,
            Err(err) => {
                warn!(job_id = %job.id, error = %err, "Failed to load workflow; failing job");
                self.job_store
                    .update_status(&job.id, JobStatus::Failed { error: err.clone() })
                    .await;
                self.report_github_status(
                    &job.repo_name,
                    &job.commit_sha,
                    "failure",
                    &format!("Failed to load workflow: {}", err),
                    Some(&target_url),
                )
                .await;
                return;
            }
        };

        // 2. Initialize or preserve existing stage records in job store
        let existing_stages = self.job_store.get_stages(&job.id).await;
        let stage_records: Vec<StageRecord> = if !existing_stages.is_empty() {
            info!(
                job_id = %job.id,
                "Resuming existing DAG stage progression; preserving completed stages"
            );
            let existing_by_id: HashMap<String, StageRecord> = existing_stages
                .into_iter()
                .map(|s| (s.id.clone(), s))
                .collect();

            workflow
                .stages
                .iter()
                .map(|s| {
                    if let Some(mut existing) = existing_by_id.get(&s.id).cloned() {
                        if matches!(
                            existing.status,
                            StageStatus::Assigned { .. } | StageStatus::Running { .. }
                        ) {
                            existing.status = StageStatus::Pending;
                            existing.assigned_node = None;
                        }
                        existing
                    } else {
                        StageRecord {
                            id: s.id.clone(),
                            name: s.name.clone(),
                            tags: s.tags.clone(),
                            threads: s.threads,
                            toolchain: s.toolchain.clone(),
                            depends_on: s.depends_on.clone(),
                            status: StageStatus::Pending,
                            assigned_node: None,
                        }
                    }
                })
                .collect()
        } else {
            workflow
                .stages
                .iter()
                .map(|s| StageRecord {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    tags: s.tags.clone(),
                    threads: s.threads,
                    toolchain: s.toolchain.clone(),
                    depends_on: s.depends_on.clone(),
                    status: StageStatus::Pending,
                    assigned_node: None,
                })
                .collect()
        };

        self.job_store.set_stages(&job.id, stage_records).await;

        // 3. Orchestration loop: evaluate DAG progression
        let stages_by_id: HashMap<String, StageConfig> = workflow
            .stages
            .iter()
            .map(|s| (s.id.clone(), s.clone()))
            .collect();

        let mut leased_slots: HashMap<String, String> = HashMap::new(); // stage_id -> node_id

        loop {
            let job_record = match self.job_store.get_job(&job.id).await {
                Some(r) => r,
                None => break,
            };

            // Check if job was cancelled or finished
            match &job_record.status {
                JobStatus::Completed { .. }
                | JobStatus::Failed { .. }
                | JobStatus::Skipped { .. } => {
                    self.cluster
                        .cancel_and_release_job_slots(
                            &job.id,
                            "Job finished, cancelled, or superseded",
                        )
                        .await;
                    self.job_store.notify_event();
                    break;
                }
                _ => {}
            }

            // Watchdog: verify if assigned worker nodes are still online in cluster
            for stage in &job_record.stages {
                if let StageStatus::Assigned { node_id, .. }
                | StageStatus::Running { node_id, .. } = &stage.status
                {
                    let is_online = self.cluster.is_node_online(node_id).await;
                    if !is_online {
                        warn!(
                            job_id = %job.id,
                            stage = %stage.id,
                            node = %node_id,
                            "Watchdog detected assigned worker node is offline; returning stage to Pending"
                        );
                        self.cluster
                            .release_stage_slot(node_id, &job.id, &stage.id)
                            .await;
                        self.job_store
                            .update_stage_status(&job.id, &stage.id, StageStatus::Pending)
                            .await;
                        leased_slots.remove(&stage.id);
                    }
                }
            }

            let mut all_completed = true;
            let mut any_failed = false;
            let mut failure_error = String::new();

            for stage in &job_record.stages {
                match &stage.status {
                    StageStatus::Completed { exit_code, .. } => {
                        leased_slots.remove(&stage.id);
                        if *exit_code != 0 {
                            any_failed = true;
                            failure_error =
                                format!("Stage '{}' failed with code {}", stage.id, exit_code);
                        }
                    }
                    StageStatus::Failed { error } => {
                        leased_slots.remove(&stage.id);
                        any_failed = true;
                        failure_error = error.clone();
                    }
                    StageStatus::Pending => {
                        all_completed = false;
                        // Check if dependencies are satisfied
                        let deps_satisfied = stage.depends_on.iter().all(|dep_id| {
                            job_record.stages.iter().any(|s| {
                                s.id == *dep_id
                                    && matches!(
                                        s.status,
                                        StageStatus::Completed { exit_code: 0, .. }
                                    )
                            })
                        });

                        if deps_satisfied {
                            let stage_cfg = stages_by_id.get(&stage.id).unwrap();
                            // Attempt to lease a slot (respecting node capacity and exclusive stage locks)
                            if let Some((node_id, cmd_tx)) = self
                                .cluster
                                .lease_slot(
                                    &job.id,
                                    &stage.id,
                                    &stage_cfg.tags,
                                    stage_cfg.toolchain.as_deref(),
                                    stage_cfg.exclusive,
                                )
                                .await
                            {
                                info!(
                                    job_id = %job.id,
                                    stage = %stage.id,
                                    node = %node_id,
                                    "Dispatched stage to cluster worker"
                                );

                                leased_slots.insert(stage.id.clone(), node_id.clone());

                                self.job_store
                                    .update_stage_status(
                                        &job.id,
                                        &stage.id,
                                        StageStatus::Assigned {
                                            node_id: node_id.clone(),
                                            started_at: Utc::now(),
                                        },
                                    )
                                    .await;

                                let task = match build_v3_stage_dispatch_task(
                                    &job.id,
                                    &job.repo_name,
                                    &job.clone_url,
                                    &job.commit_sha,
                                    stage_cfg,
                                    &workflow,
                                    self.config.job_timeout_seconds,
                                ) {
                                    Ok(t) => t,
                                    Err(e) => {
                                        warn!(
                                            job_id = %job.id,
                                            stage = %stage.id,
                                            error = %e,
                                            "Failed to build stage dispatch task"
                                        );
                                        self.cluster
                                            .release_stage_slot(&node_id, &job.id, &stage.id)
                                            .await;
                                        self.job_store
                                            .update_stage_status(
                                                &job.id,
                                                &stage.id,
                                                StageStatus::Failed {
                                                    error: e.to_string(),
                                                },
                                            )
                                            .await;
                                        continue;
                                    }
                                };

                                let _ = cmd_tx.send(WorkerCommand::Dispatch(task)).await;
                            }
                        }
                    }
                    StageStatus::Assigned { .. } | StageStatus::Running { .. } => {
                        all_completed = false;
                    }
                    StageStatus::Skipped { .. } => {
                        leased_slots.remove(&stage.id);
                    }
                }
            }

            if any_failed {
                // Cancel and release only stages belonging to THIS job that are still leased
                self.cluster
                    .cancel_and_release_job_slots(&job.id, &failure_error)
                    .await;
                leased_slots.clear();
                self.job_store.notify_event();
                warn!(job_id = %job.id, error = %failure_error, "Pipeline stage failed");
                if job_record.metrics.is_none() {
                    if let Some(m) = crate::db::CatalogStore::extract_metrics_from_log_and_workspace(
                        &self.config.workspace_dir,
                        &job.repo_name,
                        &log_file_path,
                        false,
                    ) {
                        self.job_store.update_metrics(&job.id, m).await;
                    }
                }
                self.job_store
                    .update_status(
                        &job.id,
                        JobStatus::Failed {
                            error: failure_error.clone(),
                        },
                    )
                    .await;
                self.report_github_status(
                    &job.repo_name,
                    &job.commit_sha,
                    "failure",
                    &failure_error,
                    Some(&target_url),
                )
                .await;
                break;
            }

            if all_completed {
                let duration = (Utc::now() - start_time).num_seconds().max(0) as u64;
                info!(job_id = %job.id, duration_secs = duration, "All DAG stages completed successfully");

                // Release any lingering slots belonging strictly to THIS job
                self.cluster
                    .cancel_and_release_job_slots(&job.id, "All stages completed")
                    .await;
                leased_slots.clear();
                self.job_store.notify_event();

                if job_record.metrics.is_none()
                    || job_record
                        .metrics
                        .as_ref()
                        .map(|m| m.submodules.is_empty())
                        .unwrap_or(true)
                {
                    if let Some(m) = crate::db::CatalogStore::extract_metrics_from_log_and_workspace(
                        &self.config.workspace_dir,
                        &job.repo_name,
                        &log_file_path,
                        true,
                    ) {
                        self.job_store.update_metrics(&job.id, m).await;
                    }
                }

                let mut final_status = JobStatus::Completed {
                    duration_secs: duration,
                    exit_code: 0,
                };

                let gate_req = muobserve_ipc::RegressionGateRequest {
                    request_id: format!("reg-{}", job.id),
                    repo_key: job.repo_name.to_ascii_lowercase(),
                    candidate_commit: job.commit_sha.clone(),
                    baseline_branch: "main".to_string(),
                    max_slowdown_pct: 10.0,
                    max_flakiness_pct: 5.0,
                };
                if let Some(gate_report) = self.job_store.evaluate_regression_gate(&gate_req) {
                    let mut metrics = self
                        .job_store
                        .get_job(&job.id)
                        .await
                        .and_then(|r| r.metrics)
                        .unwrap_or_else(|| crate::job::JobMetrics {
                            quality_score: 100,
                            letter_grade: "A+".to_string(),
                            coverage_pct: None,
                            benchmark_summary: None,
                            tests_passed: 0,
                            tests_total: 0,
                            advisories_count: 0,
                            clippy_warnings: 0,
                            submodules: std::collections::BTreeMap::new(),
                        });
                    crate::storage_backend::apply_regression_gate_to_job(
                        &mut metrics,
                        &mut final_status,
                        &gate_report,
                    );
                    self.job_store.update_metrics(&job.id, metrics).await;
                }

                self.job_store
                    .update_status(&job.id, final_status.clone())
                    .await;
                match final_status {
                    JobStatus::Failed { ref error } => {
                        self.report_github_status(
                            &job.repo_name,
                            &job.commit_sha,
                            "failure",
                            error,
                            Some(&target_url),
                        )
                        .await;
                    }
                    _ => {
                        self.report_github_status(
                            &job.repo_name,
                            &job.commit_sha,
                            "success",
                            &format!("All stages completed successfully in {}s", duration),
                            Some(&target_url),
                        )
                        .await;
                    }
                }
                break;
            }

            // Sleep briefly or wait for notification
            tokio::select! {
                _ = self.job_store.wait_for_event() => {}
                _ = sleep(Duration::from_millis(500)) => {}
            }
        }
    }

    async fn resolve_and_load_workflow(
        &self,
        job: &Job,
        repo_workspace: &Path,
    ) -> Result<ActionRunnerWorkflow, String> {
        // 1. Sync or initialize repo_workspace and fetch commit_sha if commit_sha is provided
        if !job.commit_sha.is_empty() {
            if !repo_workspace.exists() {
                if let Some(parent) = repo_workspace.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                let clone_target = if !job.clone_url.is_empty() {
                    job.clone_url.clone()
                } else {
                    format!("https://github.com/{}.git", job.repo_name)
                };

                let clone_res = tokio::process::Command::new("git")
                    .arg("clone")
                    .arg("--no-checkout")
                    .arg(&clone_target)
                    .arg(repo_workspace)
                    .output()
                    .await;

                if let Err(e) = clone_res {
                    warn!(
                        repo = %job.repo_name,
                        error = %e,
                        "Failed to execute git clone for workflow resolution"
                    );
                }
            }

            if repo_workspace.exists() {
                let _ = tokio::process::Command::new("git")
                    .arg("-C")
                    .arg(repo_workspace)
                    .arg("fetch")
                    .arg("origin")
                    .arg(&job.commit_sha)
                    .output()
                    .await;

                // Check ActionRunner.yml / ActionRunner.yaml in git tree
                let v3_candidates = ["ActionRunner.yml", "ActionRunner.yaml"];
                for cand in &v3_candidates {
                    let git_spec = format!("{}:.actionrunner/{}", job.commit_sha, cand);
                    let show_res = tokio::process::Command::new("git")
                        .arg("-C")
                        .arg(repo_workspace)
                        .arg("show")
                        .arg(&git_spec)
                        .output()
                        .await;

                    if let Ok(out) = show_res {
                        if out.status.success() {
                            if let Ok(content) = String::from_utf8(out.stdout) {
                                if let Ok(wf) = ActionRunnerWorkflow::from_yaml(&content) {
                                    if let Ok(sub) = wf.subgraph_for_event(&job.event_type) {
                                        info!(
                                            job_id = %job.id,
                                            commit = %job.commit_sha,
                                            candidate = %cand,
                                            "Resolved declarative ActionRunner.yml workflow from commit tree via git show"
                                        );
                                        return Ok(sub);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // 2. Resolve from local disk workspace (.actionrunner/ActionRunner.yml)
        match resolve_workflow_for_event(
            repo_workspace,
            &job.event_type,
            self.config.job_timeout_seconds,
        ) {
            Ok(ResolvedWorkflow::V3(wf)) => return Ok(wf),
            Err(_) => {}
        }

        // If not found locally, create a default 3-stage distributed workflow (fmt on x86, clippy on x86, verify on k3)
        let default_yaml = DEFAULT_WORKFLOW_YAML;
        let wf = ActionRunnerWorkflow::from_yaml(default_yaml)?;
        if let Ok(sub) = wf.subgraph_for_event(&job.event_type) {
            if !sub.stages.is_empty() {
                return Ok(sub);
            }
        }
        Ok(wf)
    }

    async fn report_github_status(
        &self,
        repo: &str,
        sha: &str,
        state: &str,
        description: &str,
        target_url: Option<&str>,
    ) {
        let token = match &self.config.github_token {
            Some(t) if !t.trim().is_empty() => t.trim(),
            _ => return,
        };

        let mut desc = description.to_string();
        if desc.len() > 140 {
            desc.truncate(137);
            desc.push_str("...");
        }

        let url = format!("https://api.github.com/repos/{}/statuses/{}", repo, sha);
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "Failed to create HTTP client for GitHub status reporting");
                return;
            }
        };

        let payload = serde_json::json!({
            "state": state,
            "target_url": target_url,
            "description": desc,
            "context": "k3-ci",
        });

        match client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "ActionRunner-Controller/0.1.0")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    info!(repo = %repo, sha = %sha, state = %state, "Reported commit status to GitHub");
                } else {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    warn!(
                        repo = %repo,
                        sha = %sha,
                        status = %status,
                        body = %body,
                        "GitHub commit status API responded with error"
                    );
                }
            }
            Err(err) => {
                warn!(repo = %repo, sha = %sha, error = %err, "Failed to send commit status to GitHub");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{ActionRunnerWorkflow, StageConfig, TaskConfig};
    use action_runner_ipc::SandboxBackendKind;
    use std::collections::HashMap;
    use tempfile::tempdir;

    // --- Sub-task #37: ToolAdapter Dispatch Builder Tests ---

    #[test]
    fn test_build_v3_stage_dispatch_task_cargo_build_and_test() {
        let mut tasks = HashMap::new();
        tasks.insert(
            "task-build".to_string(),
            TaskConfig {
                tool: "cargo-build".to_string(),
                args: vec!["--workspace".to_string(), "--release".to_string()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(600),
                sandbox_profile: None,
            },
        );
        tasks.insert(
            "task-test".to_string(),
            TaskConfig {
                tool: "cargo-test".to_string(),
                args: vec!["--workspace".to_string()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: Some(900),
                sandbox_profile: None,
            },
        );

        let stage = StageConfig {
            id: "stage-ci".to_string(),
            name: "Build and Test".to_string(),
            tasks: vec!["task-build".to_string(), "task-test".to_string()],
            depends_on: vec![],
            tags: vec!["compute".to_string()],
            threads: 4,
            toolchain: Some("stable".to_string()),
            exclusive: true,
            max_concurrent_per_node: 1,
        };

        let wf = ActionRunnerWorkflow {
            version: "3".to_string(),
            name: "Test Pipeline".to_string(),
            env: HashMap::from([("CI".to_string(), "true".to_string())]),
            tasks,
            stages: vec![stage.clone()],
            on_action: HashMap::from([("push".to_string(), vec!["stage-ci".to_string()])]),
        };

        let dispatch = build_v3_stage_dispatch_task(
            "job-42",
            "test-repo",
            "https://github.com/example/test-repo.git",
            "abcd1234ef",
            &stage,
            &wf,
            1200,
        )
        .expect("Dispatch task should build successfully");

        assert_eq!(dispatch.job_id, "job-42");
        assert_eq!(dispatch.stage_id, "stage-ci");
        assert!(dispatch.exclusive);
        assert_eq!(dispatch.max_concurrent_per_node, 1);
        assert_eq!(dispatch.tasks.len(), 2);
        assert_eq!(dispatch.tasks[0].tool_name, "cargo-build");
        assert_eq!(dispatch.tasks[0].args, vec!["--workspace", "--release"]);
        assert_eq!(dispatch.tasks[1].tool_name, "cargo-test");
        assert_eq!(dispatch.tasks[1].args, vec!["--workspace"]);
        assert_eq!(
            dispatch.sandbox_constraints.backend,
            SandboxBackendKind::Kernel
        );
    }

    // --- Sub-task #38: Reject Unregistered Tool Commands or Shell Scripts ---

    #[test]
    fn test_reject_unapproved_tool_and_shell_injection() {
        // Prohibited shell wrapper: bash
        let mut tasks_bash = HashMap::new();
        tasks_bash.insert(
            "task-bash".to_string(),
            TaskConfig {
                tool: "bash".to_string(),
                args: vec!["-c".to_string(), "echo pwned".to_string()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: None,
                sandbox_profile: None,
            },
        );

        let stage_bash = StageConfig {
            id: "stage-bash".to_string(),
            name: "Bash Stage".to_string(),
            tasks: vec!["task-bash".to_string()],
            depends_on: vec![],
            tags: vec![],
            threads: 2,
            toolchain: None,
            exclusive: false,
            max_concurrent_per_node: 1,
        };

        let wf_bash = ActionRunnerWorkflow {
            version: "3".to_string(),
            name: "Malicious Pipeline".to_string(),
            env: HashMap::new(),
            tasks: tasks_bash,
            stages: vec![stage_bash.clone()],
            on_action: HashMap::new(),
        };

        let err_bash = build_v3_stage_dispatch_task(
            "job-bad",
            "malicious-repo",
            "https://example.com",
            "deadbeef",
            &stage_bash,
            &wf_bash,
            600,
        )
        .unwrap_err();

        match err_bash {
            DispatchError::UnapprovedTool(msg) => {
                assert!(msg.contains("prohibited shell wrapper") || msg.contains("bash"));
            }
            other => panic!("Expected UnapprovedTool error, got {:?}", other),
        }

        // Prohibited shell wrapper: sh
        let mut tasks_sh = HashMap::new();
        tasks_sh.insert(
            "task-sh".to_string(),
            TaskConfig {
                tool: "sh".to_string(),
                args: vec!["-c".to_string(), "ls".to_string()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: None,
                sandbox_profile: None,
            },
        );
        let stage_sh = StageConfig {
            id: "stage-sh".to_string(),
            name: "Sh Stage".to_string(),
            tasks: vec!["task-sh".to_string()],
            depends_on: vec![],
            tags: vec![],
            threads: 2,
            toolchain: None,
            exclusive: false,
            max_concurrent_per_node: 1,
        };
        let wf_sh = ActionRunnerWorkflow {
            version: "3".to_string(),
            name: "Sh Pipeline".to_string(),
            env: HashMap::new(),
            tasks: tasks_sh,
            stages: vec![stage_sh.clone()],
            on_action: HashMap::new(),
        };
        assert!(matches!(
            build_v3_stage_dispatch_task("job-sh", "r", "c", "s", &stage_sh, &wf_sh, 600),
            Err(DispatchError::UnapprovedTool(_))
        ));

        // Shell metacharacter injection: semicolon
        let mut tasks_semi = HashMap::new();
        tasks_semi.insert(
            "task-semi".to_string(),
            TaskConfig {
                tool: "cargo-test".to_string(),
                args: vec![
                    "--".to_string(),
                    ";".to_string(),
                    "rm".to_string(),
                    "-rf".to_string(),
                ],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: None,
                sandbox_profile: None,
            },
        );
        let stage_semi = StageConfig {
            id: "stage-semi".to_string(),
            name: "Semi Stage".to_string(),
            tasks: vec!["task-semi".to_string()],
            depends_on: vec![],
            tags: vec![],
            threads: 2,
            toolchain: None,
            exclusive: false,
            max_concurrent_per_node: 1,
        };
        let wf_semi = ActionRunnerWorkflow {
            version: "3".to_string(),
            name: "Semi Pipeline".to_string(),
            env: HashMap::new(),
            tasks: tasks_semi,
            stages: vec![stage_semi.clone()],
            on_action: HashMap::new(),
        };
        assert!(matches!(
            build_v3_stage_dispatch_task("job-semi", "r", "c", "s", &stage_semi, &wf_semi, 600),
            Err(DispatchError::UnapprovedTool(_))
        ));

        // Shell metacharacter injection: subshell $(whoami)
        let mut tasks_sub = HashMap::new();
        tasks_sub.insert(
            "task-sub".to_string(),
            TaskConfig {
                tool: "cargo-test".to_string(),
                args: vec!["$(whoami)".to_string()],
                working_dir: None,
                env: HashMap::new(),
                timeout_seconds: None,
                sandbox_profile: None,
            },
        );
        let stage_sub = StageConfig {
            id: "stage-sub".to_string(),
            name: "Subshell Stage".to_string(),
            tasks: vec!["task-sub".to_string()],
            depends_on: vec![],
            tags: vec![],
            threads: 2,
            toolchain: None,
            exclusive: false,
            max_concurrent_per_node: 1,
        };
        let wf_sub = ActionRunnerWorkflow {
            version: "3".to_string(),
            name: "Subshell Pipeline".to_string(),
            env: HashMap::new(),
            tasks: tasks_sub,
            stages: vec![stage_sub.clone()],
            on_action: HashMap::new(),
        };
        assert!(matches!(
            build_v3_stage_dispatch_task("job-sub", "r", "c", "s", &stage_sub, &wf_sub, 600),
            Err(DispatchError::UnapprovedTool(_))
        ));
    }

    // --- Sub-task #27: Declarative ActionRunner.yml Resolution Tests ---

    #[test]
    fn test_resolve_workflow_precedence_and_fallback() {
        let dir = tempdir().unwrap();
        let ar_dir = dir.path().join(".actionrunner");
        std::fs::create_dir_all(&ar_dir).unwrap();

        let v3_content = r#"
version: "3"
name: "Modern Declarative Pipeline"
tasks:
  build-task:
    tool: "cargo-build"
stages:
  - id: build-stage
    name: "Build"
    tasks: ["build-task"]
on_action:
  push: ["build-stage"]
"#;

        let v3_path = ar_dir.join("ActionRunner.yml");

        // 1. Successfully resolve v3 workflow
        std::fs::write(&v3_path, v3_content).unwrap();

        let res = resolve_workflow_for_event(dir.path(), "push", 600)
            .expect("should resolve successfully");
        match res {
            ResolvedWorkflow::V3(wf) => {
                assert_eq!(wf.name, "Modern Declarative Pipeline");
                assert_eq!(wf.stages.len(), 1);
                assert_eq!(wf.stages[0].id, "build-stage");
            }
        }

        // 2. Reject when ActionRunner.yml is absent
        std::fs::remove_file(&v3_path).unwrap();

        let res_missing = resolve_workflow_for_event(dir.path(), "push", 600);
        match res_missing {
            Err(WorkflowResolveError::NotFound { .. }) => {}
            other => panic!(
                "Expected NotFound error when ActionRunner.yml is absent, got {:?}",
                other
            ),
        }

        // 3. Fallback when legacy is disabled
        std::env::set_var("ACTIONRUNNER_DISABLE_LEGACY", "1");
        let res_disabled = resolve_workflow_for_event(dir.path(), "push", 600);
        std::env::remove_var("ACTIONRUNNER_DISABLE_LEGACY");

        match res_disabled {
            Err(WorkflowResolveError::LegacyDisabled) => {}
            other => panic!("Expected LegacyDisabled error, got {:?}", other),
        }
    }
}
