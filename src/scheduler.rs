use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::cluster::{ClusterRegistry, WorkerCommand};
use crate::config::Config;
use crate::job::{Job, JobStatus, JobStore, StageRecord, StageStatus};
use crate::workflow::{ActionRunnerWorkflow, LegacyStageConfig, StageConfig, WorkflowConfig};
use action_runner_ipc::{
    NetworkEgressMode, SandboxBackendKind, SandboxConstraintSpec, StageDispatchTask,
    TypedTaskInvocation,
};
use action_runner_tools::{SandboxProfileRequirement, ToolInvocation, ToolRegistry};

// ============================================================================
// Sub-task #28: Migration Warning Logs and Deprecation Telemetry Hook
// ============================================================================

pub static LEGACY_WORKFLOW_LOADS_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn emit_legacy_workflow_warning(repo_name: &str, legacy_file: &str) {
    LEGACY_WORKFLOW_LOADS_TOTAL.fetch_add(1, Ordering::Relaxed);
    warn!(
        event = "legacy_workflow_loaded",
        repo = %repo_name,
        file = %legacy_file,
        "Loaded deprecated .actionrunner/on-*.yml; migrate to .actionrunner/ActionRunner.yml v3"
    );
}

pub fn legacy_workflow_loads_total() -> u64 {
    LEGACY_WORKFLOW_LOADS_TOTAL.load(Ordering::Relaxed)
}

pub fn legacy_workflow_loads_prometheus_metric() -> String {
    format!(
        "# TYPE actionrunner_legacy_workflow_loads_total counter\nactionrunner_legacy_workflow_loads_total {}\n",
        legacy_workflow_loads_total()
    )
}

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

    SandboxConstraintSpec {
        profile_name: profile_name.to_string(),
        backend: SandboxBackendKind::Kernel,
        read_paths: req.readable_dirs.clone(),
        write_paths: req.writable_dirs.clone(),
        exec_paths: req.exec_binaries.clone(),
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
        let profile_name = task_cfg
            .sandbox_profile
            .as_deref()
            .unwrap_or_else(|| adapter.name());
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
    })
}

// ============================================================================
// Sub-task #27: Fallback Discovery & Precedence Resolver
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedWorkflow {
    V3(ActionRunnerWorkflow),
    Legacy(WorkflowConfig),
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
    max_timeout: u64,
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

    // 3. Fallback to on-<event>.yml (with on-pullrequest.yml for pull_request)
    let event_lower = event.to_ascii_lowercase();
    let mut candidates = vec![
        format!("on-{}.yml", event_lower),
        format!("on-{}.yaml", event_lower),
    ];
    if event_lower == "pull_request" || event_lower == "pullrequest" {
        candidates.push("on-pullrequest.yml".to_string());
        candidates.push("on-pullrequest.yaml".to_string());
    }

    let repo_name = repo_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");

    for cand in &candidates {
        let path = actionrunner_dir.join(cand);
        if path.exists() {
            emit_legacy_workflow_warning(repo_name, cand);
            let content = std::fs::read_to_string(&path)
                .map_err(|e| WorkflowResolveError::Io(e.to_string()))?;
            let legacy_wf = WorkflowConfig::load_from_str(&content, repo_path, max_timeout)
                .map_err(WorkflowResolveError::Validation)?;
            return Ok(ResolvedWorkflow::Legacy(legacy_wf));
        }
    }

    Err(WorkflowResolveError::NotFound {
        path: repo_path.display().to_string(),
        event: event.to_string(),
    })
}

pub fn v3_to_legacy_workflow(v3: &ActionRunnerWorkflow) -> WorkflowConfig {
    let mut stages = Vec::new();
    for s in &v3.stages {
        let run_cmd = if s.tasks.is_empty() {
            s.name.clone()
        } else {
            s.tasks
                .iter()
                .filter_map(|t_id| v3.tasks.get(t_id))
                .map(|t| format!("{} {}", t.tool, t.args.join(" ")))
                .collect::<Vec<_>>()
                .join(" && ")
        };
        stages.push(LegacyStageConfig {
            id: s.id.clone(),
            name: s.name.clone(),
            tags: s.tags.clone(),
            threads: s.threads,
            toolchain: s.toolchain.clone(),
            depends_on: s.depends_on.clone(),
            run: run_cmd,
            working_dir: None,
            env: Some(v3.env.clone()),
            timeout_seconds: None,
            continue_on_error: false,
            exclusive: s.exclusive,
        });
    }
    WorkflowConfig {
        version: Some(v3.version.clone()),
        name: v3.name.clone(),
        env: Some(v3.env.clone()),
        stages,
        steps: Vec::new(),
    }
}

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

        // 1. Sync or inspect repo to resolve .actionrunner/on-<event>.yml
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
        let stages_by_id: HashMap<String, LegacyStageConfig> = workflow
            .stages
            .into_iter()
            .map(|s| (s.id.clone(), s))
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

                                let task = StageDispatchTask {
                                    job_id: job.id.clone(),
                                    stage_id: stage.id.clone(),
                                    stage_name: stage.name.clone(),
                                    repo_name: job.repo_name.clone(),
                                    clone_url: job.clone_url.clone(),
                                    commit_sha: job.commit_sha.clone(),
                                    command: stage_cfg.run.clone(),
                                    working_dir: stage_cfg.working_dir.clone(),
                                    env_vars: stage_cfg
                                        .env
                                        .as_ref()
                                        .map(|m| {
                                            m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
                                        })
                                        .unwrap_or_default(),
                                    timeout_seconds: stage_cfg
                                        .timeout_seconds
                                        .unwrap_or(self.config.job_timeout_seconds),
                                    threads: stage_cfg.threads,
                                    toolchain: stage_cfg.toolchain.clone(),
                                    exclusive: stage_cfg.exclusive,
                                    max_concurrent_per_node: 1,
                                    tasks: Vec::new(),
                                    sandbox_constraints: SandboxConstraintSpec::default(),
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
                    if let Some(m) = crate::db::DuckDbStore::extract_metrics_from_log_and_workspace(
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
                    if let Some(m) = crate::db::DuckDbStore::extract_metrics_from_log_and_workspace(
                        &self.config.workspace_dir,
                        &job.repo_name,
                        &log_file_path,
                        true,
                    ) {
                        self.job_store.update_metrics(&job.id, m).await;
                    }
                }

                self.job_store
                    .update_status(
                        &job.id,
                        JobStatus::Completed {
                            duration_secs: duration,
                            exit_code: 0,
                        },
                    )
                    .await;
                self.report_github_status(
                    &job.repo_name,
                    &job.commit_sha,
                    "success",
                    &format!("All stages completed successfully in {}s", duration),
                    Some(&target_url),
                )
                .await;
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
    ) -> Result<WorkflowConfig, String> {
        let event_lower = job.event_type.to_ascii_lowercase();

        let mut candidates = vec![
            format!("on-{}.yml", event_lower),
            format!("on-{}.yaml", event_lower),
        ];

        if event_lower == "pull_request" || event_lower == "pullrequest" {
            candidates.push("on-pullrequest.yml".to_string());
            candidates.push("on-pullrequest.yaml".to_string());
        }

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

                // Check ActionRunner.yml / ActionRunner.yaml in git tree first
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
                                        return Ok(v3_to_legacy_workflow(&sub));
                                    }
                                }
                            }
                        }
                    }
                }

                for cand in &candidates {
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
                                info!(
                                    job_id = %job.id,
                                    commit = %job.commit_sha,
                                    candidate = %cand,
                                    "Resolved workflow configuration from commit tree via git show"
                                );
                                return WorkflowConfig::load_from_str(
                                    &content,
                                    repo_workspace,
                                    self.config.job_timeout_seconds,
                                );
                            }
                        }
                    }
                }
            }
        }

        // 2. Resolve from local disk workspace (.actionrunner/ActionRunner.yml or on-*.yml)
        match resolve_workflow_for_event(
            repo_workspace,
            &job.event_type,
            self.config.job_timeout_seconds,
        ) {
            Ok(ResolvedWorkflow::V3(wf)) => return Ok(v3_to_legacy_workflow(&wf)),
            Ok(ResolvedWorkflow::Legacy(wf)) => return Ok(wf),
            Err(_) => {}
        }

        // If not found locally, create a default 3-stage distributed workflow (fmt on x86, clippy on x86, verify on k3)
        let default_yaml = r#"
version: "2"
name: "Default Distributed Pipeline"
stages:
  - id: fmt-check
    name: "Verify Formatting"
    tags: ["fmt"]
    threads: 2
    run: "cargo fmt --check"
  - id: clippy-check
    name: "Verify Linter Hygiene"
    tags: ["clippy"]
    threads: 4
    run: "cargo clippy --all-targets -- -D warnings"
  - id: native-k3
    name: "Native Verification"
    tags: ["k3"]
    depends_on: ["fmt-check", "clippy-check"]
    threads: 6
    run: "cargo test"
"#;
        WorkflowConfig::load_from_str(
            default_yaml,
            repo_workspace,
            self.config.job_timeout_seconds,
        )
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

    // --- Sub-task #27: Fallback Discovery & Precedence Tests ---

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

        let legacy_content = r#"
version: "2"
name: "Legacy Pipeline"
stages:
  - id: legacy-stage
    name: "Legacy Stage"
    run: "cargo test"
"#;

        let v3_path = ar_dir.join("ActionRunner.yml");
        let legacy_path = ar_dir.join("on-push.yml");

        // 1. Precedence: Write both v3 and legacy
        std::fs::write(&v3_path, v3_content).unwrap();
        std::fs::write(&legacy_path, legacy_content).unwrap();

        let res = resolve_workflow_for_event(dir.path(), "push", 600)
            .expect("should resolve successfully");
        match res {
            ResolvedWorkflow::V3(wf) => {
                assert_eq!(wf.name, "Modern Declarative Pipeline");
                assert_eq!(wf.stages.len(), 1);
                assert_eq!(wf.stages[0].id, "build-stage");
            }
            ResolvedWorkflow::Legacy(_) => panic!("Expected V3 to take precedence over legacy"),
        }

        // 2. Fallback: Remove ActionRunner.yml, leaving only on-push.yml
        std::fs::remove_file(&v3_path).unwrap();
        let count_before = LEGACY_WORKFLOW_LOADS_TOTAL.load(Ordering::Relaxed);

        let res_legacy = resolve_workflow_for_event(dir.path(), "push", 600)
            .expect("should fallback to legacy on-push.yml");
        match res_legacy {
            ResolvedWorkflow::Legacy(wf) => {
                assert_eq!(wf.name, "Legacy Pipeline");
                assert_eq!(wf.stages.len(), 1);
                assert_eq!(wf.stages[0].id, "legacy-stage");
            }
            ResolvedWorkflow::V3(_) => panic!("Expected Legacy workflow"),
        }

        let count_after = LEGACY_WORKFLOW_LOADS_TOTAL.load(Ordering::Relaxed);
        assert_eq!(
            count_after,
            count_before + 1,
            "Legacy load counter must be incremented"
        );

        // 3. Fallback when legacy is disabled
        std::env::set_var("ACTIONRUNNER_DISABLE_LEGACY", "1");
        let res_disabled = resolve_workflow_for_event(dir.path(), "push", 600);
        std::env::remove_var("ACTIONRUNNER_DISABLE_LEGACY");

        match res_disabled {
            Err(WorkflowResolveError::LegacyDisabled) => {}
            other => panic!("Expected LegacyDisabled error, got {:?}", other),
        }
    }

    #[test]
    fn test_legacy_workflow_loaded_tracing_and_telemetry_counter() {
        use std::io;
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct SharedLogBuffer(Arc<Mutex<Vec<u8>>>);

        impl io::Write for SharedLogBuffer {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let log_buffer = Arc::new(Mutex::new(Vec::new()));
        let writer_buf = log_buffer.clone();

        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || SharedLogBuffer(writer_buf.clone()))
            .with_ansi(false)
            .finish();

        let dir = tempdir().unwrap();
        let repo_dir = dir.path().join("telemetry-test-repo");
        let ar_dir = repo_dir.join(".actionrunner");
        std::fs::create_dir_all(&ar_dir).unwrap();

        let legacy_content = r#"
version: "2"
name: "Legacy Pipeline"
stages:
  - id: legacy-stage
    name: "Legacy Stage"
    run: "cargo test"
"#;
        let legacy_path = ar_dir.join("on-push.yml");
        std::fs::write(&legacy_path, legacy_content).unwrap();

        let count_before = legacy_workflow_loads_total();

        let res = tracing::subscriber::with_default(subscriber, || {
            resolve_workflow_for_event(&repo_dir, "push", 600)
        });

        assert!(res.is_ok(), "resolve_workflow_for_event should succeed");
        assert!(matches!(res.unwrap(), ResolvedWorkflow::Legacy(_)));

        let count_after = legacy_workflow_loads_total();
        assert_eq!(
            count_after,
            count_before + 1,
            "legacy_workflow_loads_total must be incremented"
        );

        let prometheus_metric = legacy_workflow_loads_prometheus_metric();
        let expected_metric = format!(
            "# TYPE actionrunner_legacy_workflow_loads_total counter\nactionrunner_legacy_workflow_loads_total {}\n",
            count_after
        );
        assert_eq!(prometheus_metric, expected_metric);

        let captured_logs = String::from_utf8(log_buffer.lock().unwrap().clone()).unwrap();
        assert!(
            captured_logs.contains("legacy_workflow_loaded"),
            "Logs must contain 'legacy_workflow_loaded', got: {}",
            captured_logs
        );
        assert!(
            captured_logs.contains("telemetry-test-repo"),
            "Logs must contain repo name 'telemetry-test-repo', got: {}",
            captured_logs
        );
        assert!(
            captured_logs.contains("on-push.yml"),
            "Logs must contain legacy file 'on-push.yml', got: {}",
            captured_logs
        );
    }
}
