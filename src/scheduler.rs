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
use crate::workflow::{StageConfig, WorkflowConfig};
use action_runner_ipc::StageDispatchTask;

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
            while let Some(job) = self.job_store.claim_next_queued_job().await {
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
                    .update_status(&job.id, JobStatus::Failed { error: err })
                    .await;
                return;
            }
        };

        // 2. Initialize stage records in job store
        let stage_records: Vec<StageRecord> = workflow
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
            })
            .collect();

        self.job_store.set_stages(&job.id, stage_records).await;

        // 3. Orchestration loop: evaluate DAG progression
        let stages_by_id: HashMap<String, StageConfig> = workflow
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
                JobStatus::Completed { .. } | JobStatus::Failed { .. } | JobStatus::Skipped { .. } => {
                    break;
                }
                _ => {}
            }

            let mut all_completed = true;
            let mut any_failed = false;
            let mut failure_error = String::new();

            for stage in &job_record.stages {
                match &stage.status {
                    StageStatus::Completed { exit_code, .. } => {
                        if *exit_code != 0 {
                            any_failed = true;
                            failure_error = format!("Stage '{}' failed with code {}", stage.id, exit_code);
                        }
                    }
                    StageStatus::Failed { error } => {
                        any_failed = true;
                        failure_error = error.clone();
                    }
                    StageStatus::Pending => {
                        all_completed = false;
                        // Check if dependencies are satisfied
                        let deps_satisfied = stage.depends_on.iter().all(|dep_id| {
                            job_record.stages.iter().any(|s| {
                                s.id == *dep_id
                                    && matches!(s.status, StageStatus::Completed { exit_code: 0, .. })
                            })
                        });

                        if deps_satisfied {
                            let stage_cfg = stages_by_id.get(&stage.id).unwrap();
                            // Attempt to lease a slot
                            if let Some((node_id, cmd_tx)) = self
                                .cluster
                                .lease_slot(&stage_cfg.tags, stage_cfg.toolchain.as_deref())
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
                                        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                                        .unwrap_or_default(),
                                    timeout_seconds: stage_cfg
                                        .timeout_seconds
                                        .unwrap_or(self.config.job_timeout_seconds),
                                    threads: stage_cfg.threads,
                                    toolchain: stage_cfg.toolchain.clone(),
                                };

                                let _ = cmd_tx.send(WorkerCommand::Dispatch(task)).await;
                            }
                        }
                    }
                    StageStatus::Assigned { .. } | StageStatus::Running { .. } => {
                        all_completed = false;
                    }
                    StageStatus::Skipped { .. } => {}
                }
            }

            if any_failed {
                // Cancel running stages
                for (_s_id, node_id) in &leased_slots {
                    self.cluster.release_slot(node_id).await;
                }
                warn!(job_id = %job.id, error = %failure_error, "Pipeline stage failed");
                self.job_store
                    .update_status(&job.id, JobStatus::Failed { error: failure_error })
                    .await;
                break;
            }

            if all_completed {
                let duration = (Utc::now() - start_time).num_seconds().max(0) as u64;
                info!(job_id = %job.id, duration_secs = duration, "All DAG stages completed successfully");

                // Release any lingering slots
                for (_s_id, node_id) in leased_slots.drain() {
                    self.cluster.release_slot(&node_id).await;
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
        let actionrunner_dir = repo_workspace.join(".actionrunner");
        let event_lower = job.event_type.to_ascii_lowercase();

        let mut candidates = vec![
            format!("on-{}.yml", event_lower),
            format!("on-{}.yaml", event_lower),
        ];

        if event_lower == "pull_request" || event_lower == "pullrequest" {
            candidates.push("on-pullrequest.yml".to_string());
            candidates.push("on-pullrequest.yaml".to_string());
        }

        // Check if workspace already has repo cloned locally
        for cand in &candidates {
            let path = actionrunner_dir.join(cand);
            if path.exists() {
                let content = tokio::fs::read_to_string(&path)
                    .await
                    .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
                return WorkflowConfig::load_from_str(&content, repo_workspace, self.config.job_timeout_seconds);
            }
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
    run: "cargo test"
"#;
        WorkflowConfig::load_from_str(default_yaml, repo_workspace, self.config.job_timeout_seconds)
    }
}
