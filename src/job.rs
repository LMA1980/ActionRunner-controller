use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Job {
    pub id: String,
    pub event_type: String,
    pub repo_name: String,
    pub clone_url: String,
    pub commit_sha: String,
    pub ref_name: String,
    pub sender: String,
    pub queued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", content = "details")]
pub enum JobStatus {
    Queued,
    Running { started_at: DateTime<Utc> },
    Completed { duration_secs: u64, exit_code: i32 },
    Failed { error: String },
    Skipped { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubmoduleMetrics {
    pub name: String,
    #[serde(default)]
    pub path: String,
    pub quality_score: u32,
    pub letter_grade: String,
    #[serde(default)]
    pub tests_passed: u32,
    #[serde(default)]
    pub tests_total: u32,
    #[serde(default)]
    pub coverage_pct: Option<f64>,
    #[serde(default)]
    pub benchmark_summary: Option<String>,
    #[serde(default)]
    pub clippy_warnings: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobMetrics {
    pub quality_score: u32,
    pub letter_grade: String,
    #[serde(default)]
    pub coverage_pct: Option<f64>,
    #[serde(default)]
    pub benchmark_summary: Option<String>,
    #[serde(default)]
    pub tests_passed: u32,
    #[serde(default)]
    pub tests_total: u32,
    #[serde(default)]
    pub advisories_count: u32,
    #[serde(default)]
    pub clippy_warnings: u32,
    #[serde(default)]
    pub submodules: BTreeMap<String, SubmoduleMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", content = "details")]
pub enum StageStatus {
    Pending,
    Assigned {
        node_id: String,
        started_at: DateTime<Utc>,
    },
    Running {
        node_id: String,
        started_at: DateTime<Utc>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
    },
    Completed {
        duration_secs: u64,
        exit_code: i32,
    },
    Failed {
        error: String,
    },
    Skipped {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StageRecord {
    pub id: String,
    pub name: String,
    pub tags: Vec<String>,
    pub threads: u32,
    pub toolchain: Option<String>,
    pub depends_on: Vec<String>,
    pub status: StageStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_node: Option<String>,
    #[serde(default)]
    pub exclusive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobRecord {
    pub job: Job,
    pub status: JobStatus,
    pub log_file: PathBuf,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub metrics: Option<JobMetrics>,
    #[serde(default)]
    pub stages: Vec<StageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnqueueResult {
    pub job_id: String,
    pub queue_position: usize,
    pub superseded_jobs: Vec<String>,
    #[serde(default)]
    pub ignored: bool,
    #[serde(default)]
    pub ignore_reason: Option<String>,
    #[serde(default)]
    pub winning_job_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueItemView {
    pub position: usize,
    pub wait_secs: u64,
    pub elapsed_secs: Option<u64>,
    pub record: JobRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QueueStats {
    pub total_jobs: usize,
    pub running_jobs: usize,
    pub queued_jobs: usize,
    pub completed_jobs: usize,
    pub failed_jobs: usize,
    pub skipped_jobs: usize,
    pub superseded_jobs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueSnapshot {
    pub status: String,
    pub concurrency: usize,
    pub queue_depth: usize,
    pub active_job: Option<QueueItemView>,
    #[serde(default)]
    pub active_jobs: Vec<QueueItemView>,
    pub queued_jobs: Vec<QueueItemView>,
    pub stats: QueueStats,
    pub recent_jobs: Vec<JobRecord>,
}

pub struct InFlightJobGuard {
    job_store: Option<JobStore>,
    job_id: String,
}

impl std::fmt::Debug for InFlightJobGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InFlightJobGuard")
            .field("job_id", &self.job_id)
            .finish()
    }
}

impl InFlightJobGuard {
    pub fn new(job_store: JobStore, job_id: String) -> Self {
        job_store.mark_job_in_flight(&job_id);
        Self {
            job_store: Some(job_store),
            job_id,
        }
    }

    pub fn disarm(&mut self) {
        self.job_store = None;
    }
}

impl Drop for InFlightJobGuard {
    fn drop(&mut self) {
        if let Some(store) = self.job_store.take() {
            store.release_in_flight_job(&self.job_id);
        }
    }
}

#[derive(Clone)]
pub struct JobStore {
    inner: Arc<RwLock<VecDeque<JobRecord>>>,
    db: Arc<dyn crate::storage_backend::ControllerStorage>,
    notify: Arc<Notify>,
    max_history: usize,
    index_file: Option<PathBuf>,
    ha_role: Arc<std::sync::RwLock<crate::config::HaRole>>,
    node_id: String,
    in_flight_jobs: Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
}

impl JobStore {
    fn default_storage(
        workspace_dir: Option<&Path>,
    ) -> Arc<dyn crate::storage_backend::ControllerStorage> {
        let local_catalog = Arc::new(crate::db::CatalogStore::new());
        if let Some(ws) = workspace_dir {
            local_catalog.backfill_from_logs_dir(ws);
        }

        let in_memory_storage = Arc::new(crate::storage_backend::InMemoryStorage::new(Arc::clone(
            &local_catalog,
        )));
        let mode = crate::storage_backend::StorageBackendMode::from_env();
        match mode {
            crate::storage_backend::StorageBackendMode::InMemory => in_memory_storage,
            crate::storage_backend::StorageBackendMode::MuObserveRemote => {
                if let Some(cfg) = crate::storage_backend::MuObserveRemoteConfig::from_env() {
                    match crate::storage_backend::MuObserveRemoteStorage::new(cfg) {
                        Ok(remote) => Arc::new(remote),
                        Err(e) => {
                            warn!(
                                "Failed to initialize MuObserveRemoteStorage ({}), falling back to InMemoryStorage",
                                e
                            );
                            in_memory_storage
                        }
                    }
                } else {
                    in_memory_storage
                }
            }
        }
    }

    pub fn new(max_history: usize, workspace_dir: Option<&Path>) -> Self {
        let storage = Self::default_storage(workspace_dir);
        Self::with_storage(max_history, workspace_dir, storage)
    }

    pub fn from_config(max_history: usize, config: &crate::config::Config) -> Self {
        let storage = Self::default_storage(Some(&config.workspace_dir));
        Self::from_config_with_storage(max_history, config, storage)
    }

    pub fn from_config_with_storage(
        max_history: usize,
        config: &crate::config::Config,
        db: Arc<dyn crate::storage_backend::ControllerStorage>,
    ) -> Self {
        if !config.bootstrap_admins.is_empty() {
            db.seed_bootstrap_admins(&config.bootstrap_admins);
        }
        let initial_role = match config.ha_role {
            crate::config::HaRoleConfig::Leader => {
                let _ =
                    db.try_acquire_or_renew_lease(&config.node_id, config.lease_ttl_seconds, true);
                crate::config::HaRole::Leader
            }
            crate::config::HaRoleConfig::Standby => crate::config::HaRole::Standby,
            crate::config::HaRoleConfig::Auto => {
                if db.try_acquire_or_renew_lease(&config.node_id, config.lease_ttl_seconds, false) {
                    crate::config::HaRole::Leader
                } else {
                    crate::config::HaRole::Standby
                }
            }
        };
        Self::with_storage_and_role(
            max_history,
            Some(&config.workspace_dir),
            db,
            initial_role,
            config.node_id.clone(),
        )
    }

    pub fn with_storage(
        max_history: usize,
        workspace_dir: Option<&Path>,
        db: Arc<dyn crate::storage_backend::ControllerStorage>,
    ) -> Self {
        Self::with_storage_and_role(
            max_history,
            workspace_dir,
            db,
            crate::config::HaRole::Leader,
            "node-a".to_string(),
        )
    }

    pub fn with_storage_and_role(
        max_history: usize,
        workspace_dir: Option<&Path>,
        db: Arc<dyn crate::storage_backend::ControllerStorage>,
        initial_role: crate::config::HaRole,
        node_id: String,
    ) -> Self {
        let index_file = workspace_dir.map(|w| w.join("logs").join("jobs_index.json"));
        let notify = Arc::new(Notify::new());
        let recover_running = initial_role.is_leader();

        // 1. When starting as Leader with a workspace_dir, import jobs_index.json into storage
        if recover_running {
            if let Some(ref path) = index_file {
                if path.exists() {
                    if let Ok(content) = std::fs::read_to_string(path) {
                        if let Ok(mut jobs) = serde_json::from_str::<VecDeque<JobRecord>>(&content)
                        {
                            for rec in jobs.iter_mut() {
                                let has_active_stages = rec.stages.iter().any(|s| {
                                    matches!(
                                        s.status,
                                        StageStatus::Assigned { .. } | StageStatus::Running { .. }
                                    )
                                });
                                if matches!(rec.status, JobStatus::Running { .. })
                                    || (matches!(rec.status, JobStatus::Queued)
                                        && has_active_stages)
                                {
                                    rec.status = JobStatus::Queued;
                                    rec.updated_at = Utc::now();
                                    for stage in rec.stages.iter_mut() {
                                        if matches!(
                                            stage.status,
                                            StageStatus::Assigned { .. }
                                                | StageStatus::Running { .. }
                                        ) {
                                            stage.status = StageStatus::Pending;
                                            stage.assigned_node = None;
                                        }
                                    }
                                } else {
                                    let _ = sanitize_terminal_job_stages(rec);
                                }
                            }
                            // Upsert oldest-first into storage
                            let chronological: Vec<JobRecord> =
                                jobs.iter().rev().cloned().collect();
                            db.upsert_records_batch(&chronological);
                            info!(
                                "Synchronized {} job records from {} into ControllerStorage",
                                jobs.len(),
                                path.display()
                            );
                        }
                    }
                }
            }
        }

        // 2. Load recent jobs from storage into the active in-memory queue.
        // In Standby mode, preserve Running statuses without mutating ControllerStorage.
        let mut initial_jobs: VecDeque<JobRecord> =
            db.load_recent_jobs(max_history).into_iter().collect();
        if recover_running {
            let mut has_queued = false;
            let mut recovered_running = Vec::new();
            for rec in initial_jobs.iter_mut() {
                let has_active_stages = rec.stages.iter().any(|s| {
                    matches!(
                        s.status,
                        StageStatus::Assigned { .. } | StageStatus::Running { .. }
                    )
                });
                if matches!(rec.status, JobStatus::Running { .. })
                    || (matches!(rec.status, JobStatus::Queued) && has_active_stages)
                {
                    rec.status = JobStatus::Queued;
                    rec.updated_at = Utc::now();
                    for stage in rec.stages.iter_mut() {
                        if matches!(
                            stage.status,
                            StageStatus::Assigned { .. } | StageStatus::Running { .. }
                        ) {
                            stage.status = StageStatus::Pending;
                            stage.assigned_node = None;
                        }
                    }
                    recovered_running.push(rec.clone());
                } else if sanitize_terminal_job_stages(rec) {
                    rec.updated_at = Utc::now();
                    recovered_running.push(rec.clone());
                }
                if matches!(rec.status, JobStatus::Queued) {
                    has_queued = true;
                }
            }
            if !recovered_running.is_empty() {
                db.upsert_records_batch(&recovered_running);
                if let Some(ref path) = index_file {
                    if let Ok(json_str) = serde_json::to_string_pretty(&initial_jobs) {
                        let _ = std::fs::write(path, json_str);
                    }
                }
            }
            if has_queued {
                notify.notify_waiters();
            }
        }

        Self {
            inner: Arc::new(RwLock::new(initial_jobs)),
            db,
            notify,
            max_history,
            index_file,
            ha_role: Arc::new(std::sync::RwLock::new(initial_role)),
            node_id,
            in_flight_jobs: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
        }
    }

    #[must_use]
    pub fn ha_role(&self) -> crate::config::HaRole {
        self.ha_role
            .read()
            .map(|g| *g)
            .unwrap_or(crate::config::HaRole::Leader)
    }

    #[must_use]
    pub fn is_leader(&self) -> bool {
        self.ha_role().is_leader()
    }

    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn is_job_in_flight(&self, job_id: &str) -> bool {
        let set = self
            .in_flight_jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set.contains(job_id)
    }

    pub fn mark_job_in_flight(&self, job_id: &str) -> bool {
        let mut set = self
            .in_flight_jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set.insert(job_id.to_string())
    }

    pub fn release_in_flight_job(&self, job_id: &str) {
        let mut set = self
            .in_flight_jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set.remove(job_id);
    }

    pub fn set_ha_role(&self, role: crate::config::HaRole) {
        if let Ok(mut guard) = self.ha_role.write() {
            *guard = role;
        }
        if role.is_leader() {
            self.notify.notify_waiters();
        }
    }

    pub fn append_job_log(&self, job_id: &str, chunk: &str) {
        self.db.append_job_log(job_id, chunk);
    }

    pub fn append_job_log_buffered(&self, job_id: &str, chunk: &str) {
        self.db.append_job_log_buffered(job_id, chunk);
    }

    pub fn flush_job_log(&self, job_id: Option<&str>) {
        self.db.flush_job_log(job_id);
    }

    #[must_use]
    pub fn get_job_log(&self, job_id: &str) -> Option<String> {
        self.db.get_job_log(job_id)
    }

    pub fn seed_bootstrap_admins(&self, admins: &[String]) {
        self.db.seed_bootstrap_admins(admins);
    }

    pub fn create_auth_invite(&self, invite: &crate::db::AuthInviteRecord) {
        self.db.create_auth_invite(invite);
    }

    #[must_use]
    pub fn get_auth_invite(&self, invite_id: &str) -> Option<crate::db::AuthInviteRecord> {
        self.db.get_auth_invite(invite_id)
    }

    #[must_use]
    pub fn list_auth_invites(&self) -> Vec<crate::db::AuthInviteRecord> {
        self.db.list_auth_invites()
    }

    pub fn redeem_auth_invite(
        &self,
        invite_id: &str,
        presented_hmac: &str,
        github_login: &str,
        now: DateTime<Utc>,
    ) -> Result<crate::db::AuthUserRecord, crate::db::RedeemInviteError> {
        self.db
            .redeem_auth_invite(invite_id, presented_hmac, github_login, now)
    }

    #[must_use]
    pub fn get_auth_user(&self, github_login: &str) -> Option<crate::db::AuthUserRecord> {
        self.db.get_auth_user(github_login)
    }

    #[must_use]
    pub fn list_auth_users(&self) -> Vec<crate::db::AuthUserRecord> {
        self.db.list_auth_users()
    }

    pub fn revoke_auth_user(&self, github_login: &str) -> bool {
        self.db.revoke_auth_user(github_login)
    }

    fn run_storage_op<T>(
        &self,
        f: impl FnOnce(&dyn crate::storage_backend::ControllerStorage) -> T,
    ) -> T {
        let db = self.db.as_ref();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(|| f(db))
            }
            _ => f(db),
        }
    }

    /// Re-hydrates the in-memory job queue from [`ControllerStorage`] (`#81`).
    ///
    /// - When `recover_running` is `false` (periodic standby sync), refreshes `self.inner`
    ///   without altering `JobStatus::Running` jobs in storage.
    /// - When `recover_running` is `true` (standby promotion to leader), resets any interrupted
    ///   `JobStatus::Running` jobs (and `Assigned`/`Running` stages) back to `JobStatus::Queued`
    ///   (`StageStatus::Pending`), persists the recovered records to storage, and wakes the scheduler.
    pub async fn rehydrate_from_storage(&self, recover_running: bool) -> usize {
        let remote_jobs = self.run_storage_op(|db| db.load_recent_jobs(self.max_history));
        let mut recovered_for_db = Vec::new();
        let mut has_queued = false;
        let count;
        let is_leader = self.is_leader();

        {
            let mut store = self.inner.write().await;
            let mut by_id: BTreeMap<String, JobRecord> = BTreeMap::new();
            for rec in store.iter() {
                by_id.insert(rec.job.id.clone(), rec.clone());
            }
            for mut rec in remote_jobs {
                if self.is_job_in_flight(&rec.job.id) && by_id.contains_key(&rec.job.id) {
                    continue;
                }
                match by_id.get(&rec.job.id) {
                    Some(local)
                        if should_preserve_local_record(
                            !recover_running && is_leader,
                            local,
                            &rec,
                        ) =>
                    {
                        // Preserve fresher local in-flight state.
                    }
                    Some(local) => {
                        merge_completed_stages(local, &mut rec);
                        by_id.insert(rec.job.id.clone(), rec);
                    }
                    None => {
                        by_id.insert(rec.job.id.clone(), rec);
                    }
                }
            }

            let mut merged: Vec<JobRecord> = by_id.into_values().collect();
            merged.sort_by(|a, b| {
                b.job
                    .queued_at
                    .cmp(&a.job.queued_at)
                    .then_with(|| b.updated_at.cmp(&a.updated_at))
            });
            merged.truncate(self.max_history);

            if recover_running {
                let now = Utc::now();
                for rec in &mut merged {
                    if self.is_job_in_flight(&rec.job.id) {
                        continue;
                    }
                    let has_active_stages = rec.stages.iter().any(|s| {
                        matches!(
                            s.status,
                            StageStatus::Assigned { .. } | StageStatus::Running { .. }
                        )
                    });
                    if matches!(rec.status, JobStatus::Running { .. })
                        || (matches!(rec.status, JobStatus::Queued) && has_active_stages)
                    {
                        rec.status = JobStatus::Queued;
                        rec.updated_at = now;
                        for stage in &mut rec.stages {
                            if matches!(
                                stage.status,
                                StageStatus::Assigned { .. } | StageStatus::Running { .. }
                            ) {
                                stage.status = StageStatus::Pending;
                                stage.assigned_node = None;
                            }
                        }
                        recovered_for_db.push(rec.clone());
                    } else if sanitize_terminal_job_stages(rec) {
                        rec.updated_at = now;
                        recovered_for_db.push(rec.clone());
                    }
                    if matches!(rec.status, JobStatus::Queued) {
                        has_queued = true;
                    }
                }
            } else {
                for rec in &mut merged {
                    if matches!(rec.status, JobStatus::Queued) {
                        if let Some(started_at) = rec.stages.iter().find_map(|s| match s.status {
                            StageStatus::Assigned { started_at, .. }
                            | StageStatus::Running { started_at, .. } => Some(started_at),
                            _ => None,
                        }) {
                            rec.status = JobStatus::Running { started_at };
                        }
                    } else {
                        let _ = sanitize_terminal_job_stages(rec);
                    }
                }
                has_queued = merged
                    .iter()
                    .any(|rec| matches!(rec.status, JobStatus::Queued));
            }

            count = merged.len();
            *store = merged.into_iter().collect();
        }

        if !recovered_for_db.is_empty() {
            self.run_storage_op(|db| db.upsert_records_batch(&recovered_for_db));
        }
        if recover_running {
            self.persist().await;
        }
        if (recover_running || self.is_leader()) && (has_queued || !recovered_for_db.is_empty()) {
            self.notify.notify_waiters();
        }

        count
    }

    pub fn storage(&self) -> &Arc<dyn crate::storage_backend::ControllerStorage> {
        &self.db
    }

    pub fn evaluate_regression_gate(
        &self,
        req: &muobserve_ipc::RegressionGateRequest,
    ) -> Option<muobserve_ipc::RegressionGateReport> {
        self.db.evaluate_regression_gate(req)
    }

    async fn persist(&self) {
        if let Some(ref path) = self.index_file {
            let json_str = {
                let store = self.inner.read().await;
                serde_json::to_string_pretty(&*store).ok()
            };
            if let Some(json_str) = json_str {
                if let Some(parent) = path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                if let Err(e) = tokio::fs::write(path, json_str).await {
                    warn!("Failed to persist jobs_index.json: {}", e);
                }
            }
        }
    }

    /// Enqueues a job into the coalescing FIFO queue.
    ///
    /// Rules:
    /// - Same commit ID conflict resolution & deduplication:
    ///   - `merge` vs `push` on the same commit ID: the first event received wins.
    ///   - `pull_request` vs `push` on the same commit ID: `pull_request` always wins.
    ///   - Duplicate events of the same type on the same commit ID: first event received wins.
    /// - If any older job for the same `(repo_name, ref_name, event_type)` is currently `Queued`
    ///   waiting for execution, it is marked as `Skipped` (superseded by this newer commit) so
    ///   limited host resources only build the latest commit on that ref.
    pub async fn enqueue_job(&self, mut job: Job, mut log_file: PathBuf) -> EnqueueResult {
        let now = Utc::now();
        let mut superseded_jobs = Vec::new();
        let mut records_to_upsert = Vec::new();
        let queue_position;

        {
            let mut store = self.inner.write().await;

            let sha_short = &job.commit_sha[..8.min(job.commit_sha.len())];
            let norm_incoming_ref = normalize_ref(&job.ref_name);

            // Same-commit ID conflict resolution & deduplication:
            // 1. merge vs push on the same commit ID: the first event received wins.
            // 2. pull_request vs push on the same commit ID: pull_request always wins.
            // 3. duplicate events of the same type on the same commit ID: first event wins.
            if !job.commit_sha.is_empty() {
                let incoming_event = job.event_type.to_ascii_lowercase();

                // Find any existing active or finished jobs for this repo, normalized ref, and commit SHA (ignore Skipped jobs)
                let existing_commit_job = store.iter().find(|r| {
                    !matches!(r.status, JobStatus::Skipped { .. })
                        && r.job.repo_name.eq_ignore_ascii_case(&job.repo_name)
                        && !r.job.commit_sha.is_empty()
                        && r.job.commit_sha.eq_ignore_ascii_case(&job.commit_sha)
                        && normalize_ref(&r.job.ref_name) == norm_incoming_ref
                });

                if let Some(existing) = existing_commit_job {
                    let existing_event = existing.job.event_type.to_ascii_lowercase();

                    if incoming_event == "push" && existing_event == "merge" {
                        // Merge was received first; merge wins. Push is ignored.
                        return EnqueueResult {
                            job_id: job.id,
                            queue_position: 0,
                            superseded_jobs: Vec::new(),
                            ignored: true,
                            ignore_reason: Some(format!(
                                "Merge event ({}) already received for commit {}",
                                existing.job.id, sha_short
                            )),
                            winning_job_id: Some(existing.job.id.clone()),
                        };
                    } else if incoming_event == "merge" && existing_event == "push" {
                        // Push was received first; push wins. Merge is ignored.
                        return EnqueueResult {
                            job_id: job.id,
                            queue_position: 0,
                            superseded_jobs: Vec::new(),
                            ignored: true,
                            ignore_reason: Some(format!(
                                "Push event ({}) already received for commit {}",
                                existing.job.id, sha_short
                            )),
                            winning_job_id: Some(existing.job.id.clone()),
                        };
                    } else if incoming_event == "push" && existing_event == "pull_request" {
                        // pull_request always wins over push for the same commit ID. Push is ignored.
                        return EnqueueResult {
                            job_id: job.id,
                            queue_position: 0,
                            superseded_jobs: Vec::new(),
                            ignored: true,
                            ignore_reason: Some(format!(
                                "Pull request event ({}) wins over push for commit {}",
                                existing.job.id, sha_short
                            )),
                            winning_job_id: Some(existing.job.id.clone()),
                        };
                    } else if incoming_event == existing_event
                        && matches!(
                            existing.status,
                            JobStatus::Queued
                                | JobStatus::Running { .. }
                                | JobStatus::Completed { exit_code: 0, .. }
                        )
                    {
                        // Duplicate event of the same type for this commit ID: first received wins.
                        return EnqueueResult {
                            job_id: job.id,
                            queue_position: 0,
                            superseded_jobs: Vec::new(),
                            ignored: true,
                            ignore_reason: Some(format!(
                                "Duplicate {} event ({}) already received for commit {}",
                                incoming_event, existing.job.id, sha_short
                            )),
                            winning_job_id: Some(existing.job.id.clone()),
                        };
                    }
                }

                // If incoming is pull_request and existing is push:
                // pull_request ALWAYS wins over push for the same commit ID!
                // Supersede any Queued or Running push jobs for this commit ID.
                if incoming_event == "pull_request" {
                    for record in store.iter_mut() {
                        let rec_event = record.job.event_type.to_ascii_lowercase();
                        if rec_event == "push"
                            && record.job.repo_name.eq_ignore_ascii_case(&job.repo_name)
                            && !record.job.commit_sha.is_empty()
                            && record.job.commit_sha.eq_ignore_ascii_case(&job.commit_sha)
                            && normalize_ref(&record.job.ref_name) == norm_incoming_ref
                            && matches!(
                                record.status,
                                JobStatus::Queued | JobStatus::Running { .. }
                            )
                        {
                            let skip_reason = format!(
                                "Superseded by pull_request event for commit {} ({})",
                                sha_short, job.id
                            );
                            superseded_jobs.push(record.job.id.clone());
                            for stage in record.stages.iter_mut() {
                                if matches!(
                                    stage.status,
                                    StageStatus::Pending
                                        | StageStatus::Assigned { .. }
                                        | StageStatus::Running { .. }
                                ) {
                                    stage.status = StageStatus::Skipped {
                                        reason: skip_reason.clone(),
                                    };
                                }
                            }
                            record.status = JobStatus::Skipped {
                                reason: skip_reason,
                            };
                            record.updated_at = now;
                            records_to_upsert.push(record.clone());
                        }
                    }
                }
            }

            // Ensure unique job.id even when multiple webhooks arrive within the same second
            let base_id = job.id.clone();
            let mut suffix = 2u32;
            while store.iter().any(|r| r.job.id == job.id) {
                job.id = format!("{}-{}", base_id, suffix);
                log_file = Path::new("logs")
                    .join(&job.repo_name)
                    .join(format!("{}.log", job.id));
                suffix += 1;
            }

            // Coalesce any older still-Queued jobs for the same repo + ref + event_type
            for record in store.iter_mut() {
                if matches!(record.status, JobStatus::Queued)
                    && record.job.repo_name.eq_ignore_ascii_case(&job.repo_name)
                    && normalize_ref(&record.job.ref_name) == norm_incoming_ref
                    && record.job.event_type == job.event_type
                {
                    superseded_jobs.push(record.job.id.clone());
                    record.status = JobStatus::Skipped {
                        reason: format!(
                            "Superseded in queue by newer commit {} ({})",
                            sha_short, job.id
                        ),
                    };
                    let _ = sanitize_terminal_job_stages(record);
                    record.updated_at = now;
                    records_to_upsert.push(record.clone());
                }
            }

            // Evict oldest terminal record from hot in-memory deque if at max_history capacity
            // (never evict Queued/Running, and DuckDB retains full history permanently)
            if store.len() >= self.max_history {
                if let Some(pos) = store.iter().rposition(|r| {
                    !matches!(r.status, JobStatus::Queued | JobStatus::Running { .. })
                }) {
                    store.remove(pos);
                }
            }

            let new_record = JobRecord {
                job: job.clone(),
                status: JobStatus::Queued,
                log_file,
                updated_at: now,
                metrics: None,
                stages: Vec::new(),
            };
            records_to_upsert.push(new_record.clone());
            store.push_front(new_record);

            // Compute 1-based FIFO queue position among all currently Queued jobs
            queue_position = store
                .iter()
                .filter(|r| matches!(r.status, JobStatus::Queued))
                .count();
        }

        if !records_to_upsert.is_empty() {
            self.run_storage_op(|db| db.upsert_records_batch(&records_to_upsert));
        }
        self.persist().await;
        self.notify.notify_waiters();

        EnqueueResult {
            job_id: job.id,
            queue_position,
            superseded_jobs,
            ignored: false,
            ignore_reason: None,
            winning_job_id: None,
        }
    }

    #[cfg(test)]
    pub async fn add_job(&self, job: Job, log_file: PathBuf) {
        let _ = self.enqueue_job(job, log_file).await;
    }

    /// Atomically claims the oldest `Queued` job in FIFO order that respects global concurrency bounds
    /// and ensures strict single-pipeline serialization per repository.
    /// Returns `None` immediately when the controller is in `Standby` mode (`#80`).
    pub async fn claim_next_queued_job(&self, max_concurrent: usize) -> Option<Job> {
        self.claim_next_queued_job_for_cluster(max_concurrent, None)
            .await
    }

    /// Atomically claims the oldest `Queued` job in FIFO order whose ready stages can be satisfied
    /// by an available online worker slot in `cluster` (or whose stages have not yet been resolved
    /// while at least one worker slot is available).
    pub async fn claim_next_queued_job_for_cluster(
        &self,
        max_concurrent: usize,
        cluster: Option<&crate::cluster::ClusterRegistry>,
    ) -> Option<Job> {
        if !self.is_leader() {
            return None;
        }
        let (claimed, healed) = {
            let mut store = self.inner.write().await;
            let now = Utc::now();

            let mut healed = Vec::new();
            for r in store.iter_mut() {
                if matches!(r.status, JobStatus::Queued)
                    && r.stages.iter().any(|s| {
                        matches!(
                            s.status,
                            StageStatus::Assigned { .. } | StageStatus::Running { .. }
                        )
                    })
                {
                    r.status = JobStatus::Running { started_at: now };
                    r.updated_at = now;
                    healed.push(r.clone());
                } else if sanitize_terminal_job_stages(r) {
                    r.updated_at = now;
                    healed.push(r.clone());
                }
            }

            let mut running_count = 0;
            let mut running_repos = std::collections::HashSet::new();

            for r in store.iter() {
                if matches!(r.status, JobStatus::Running { .. }) {
                    running_count += 1;
                    running_repos.insert(r.job.repo_name.clone());
                }
            }

            if running_count >= max_concurrent {
                (None, healed)
            } else {
                let active_unleased_job_ids: std::collections::HashSet<String> = store
                    .iter()
                    .filter(|r| {
                        matches!(r.status, JobStatus::Running { .. })
                            && !r.stages.iter().any(|s| {
                                matches!(
                                    s.status,
                                    StageStatus::Assigned { .. } | StageStatus::Running { .. }
                                )
                            })
                    })
                    .map(|r| r.job.id.clone())
                    .collect();

                let mut found = None;
                for record in store.iter_mut().rev() {
                    if !matches!(record.status, JobStatus::Queued)
                        || running_repos.contains(&record.job.repo_name)
                        || self.is_job_in_flight(&record.job.id)
                    {
                        continue;
                    }

                    let all_stages_terminal = !record.stages.is_empty()
                        && !record.stages.iter().any(|s| {
                            matches!(
                                s.status,
                                StageStatus::Pending
                                    | StageStatus::Assigned { .. }
                                    | StageStatus::Running { .. }
                            )
                        });

                    if let Some(cluster_reg) = cluster {
                        if !all_stages_terminal {
                            let can_run = cluster_reg
                                .sync_and_try_reserve_for_claim(
                                    &active_unleased_job_ids,
                                    &record.job.id,
                                    &record.stages,
                                )
                                .await;
                            if !can_run {
                                continue;
                            }
                        }
                    }

                    record.status = JobStatus::Running { started_at: now };
                    record.updated_at = now;
                    self.mark_job_in_flight(&record.job.id);
                    found = Some((record.job.clone(), record.clone()));
                    break;
                }
                (found, healed)
            }
        };

        if !healed.is_empty() {
            self.run_storage_op(|db| db.upsert_records_batch(&healed));
        }

        if let Some((job, record)) = claimed {
            self.run_storage_op(|db| db.upsert_record(&record));
            self.persist().await;
            Some(job)
        } else {
            None
        }
    }

    /// Re-queues a `Running` job in-place when all of its currently ready stages are blocked
    /// waiting for busy worker nodes and it holds zero active stage leases.
    ///
    /// Preserves the job's original `queued_at` timestamp, queue position, and all completed
    /// "food sample" stages so it retains its original FIFO priority when a matching worker
    /// slot becomes free.
    pub async fn requeue_preserving_priority(&self, job_id: &str) -> bool {
        let requeued_record = {
            let mut store = self.inner.write().await;
            let now = Utc::now();
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                let has_active_stages = record.stages.iter().any(|s| {
                    matches!(
                        s.status,
                        StageStatus::Assigned { .. } | StageStatus::Running { .. }
                    )
                });
                let all_stages_terminal = !record.stages.is_empty()
                    && !record.stages.iter().any(|s| {
                        matches!(
                            s.status,
                            StageStatus::Pending
                                | StageStatus::Assigned { .. }
                                | StageStatus::Running { .. }
                        )
                    });
                if has_active_stages || all_stages_terminal {
                    return false;
                }
                if matches!(record.status, JobStatus::Running { .. }) {
                    record.status = JobStatus::Queued;
                    record.updated_at = now;
                    Some(record.clone())
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(record) = requeued_record {
            self.release_in_flight_job(job_id);
            self.run_storage_op(|db| db.upsert_record(&record));
            self.persist().await;
            self.notify.notify_waiters();
            true
        } else {
            false
        }
    }

    pub async fn wait_for_job(&self) {
        self.notify.notified().await;
    }

    pub async fn queue_snapshot(&self) -> QueueSnapshot {
        let store = self.inner.read().await;
        let now = Utc::now();

        let mut stats = QueueStats {
            total_jobs: store.len(),
            ..Default::default()
        };

        let mut active_job: Option<QueueItemView> = None;
        let mut active_jobs: Vec<QueueItemView> = Vec::new();
        let mut queued_records: Vec<JobRecord> = Vec::new();

        for record in store.iter().rev() {
            match &record.status {
                JobStatus::Running { started_at } => {
                    stats.running_jobs += 1;
                    let elapsed = (now - *started_at).num_seconds().max(0) as u64;
                    let wait = (*started_at - record.job.queued_at).num_seconds().max(0) as u64;
                    let view = QueueItemView {
                        position: 0,
                        wait_secs: wait,
                        elapsed_secs: Some(elapsed),
                        record: record.clone(),
                    };
                    if active_job.is_none() {
                        active_job = Some(view.clone());
                    }
                    active_jobs.push(view);
                }
                JobStatus::Queued => {
                    stats.queued_jobs += 1;
                    queued_records.push(record.clone());
                }
                JobStatus::Completed { exit_code: 0, .. } => {
                    stats.completed_jobs += 1;
                }
                JobStatus::Completed { .. } | JobStatus::Failed { .. } => {
                    stats.failed_jobs += 1;
                }
                JobStatus::Skipped { reason } => {
                    stats.skipped_jobs += 1;
                    if reason.contains("Superseded in queue") {
                        stats.superseded_jobs += 1;
                    }
                }
            }
        }

        // `queued_records` was collected in `.rev()` (oldest first = position 1)
        let queued_jobs: Vec<QueueItemView> = queued_records
            .into_iter()
            .enumerate()
            .map(|(idx, rec)| {
                let wait = (now - rec.job.queued_at).num_seconds().max(0) as u64;
                QueueItemView {
                    position: idx + 1,
                    wait_secs: wait,
                    elapsed_secs: None,
                    record: rec,
                }
            })
            .collect();

        let status = if !active_jobs.is_empty() || !queued_jobs.is_empty() {
            "busy".to_string()
        } else {
            "idle".to_string()
        };

        let recent_jobs = store.iter().take(50).cloned().collect();

        QueueSnapshot {
            status,
            concurrency: active_jobs.len().max(1),
            queue_depth: queued_jobs.len(),
            active_job,
            active_jobs,
            queued_jobs,
            stats,
            recent_jobs,
        }
    }

    pub async fn job_queue_position(&self, job_id: &str) -> Option<usize> {
        let store = self.inner.read().await;
        let mut pos = 0usize;
        for record in store.iter().rev() {
            if matches!(record.status, JobStatus::Queued) {
                pos += 1;
                if record.job.id == job_id {
                    return Some(pos);
                }
            }
        }
        None
    }

    pub async fn update_metrics(&self, job_id: &str, metrics: JobMetrics) {
        let updated_in_store = {
            let mut store = self.inner.write().await;
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                record.metrics = Some(metrics.clone());
                record.updated_at = Utc::now();
                Some(record.clone())
            } else {
                None
            }
        };
        if let Some(record) = updated_in_store {
            self.run_storage_op(|db| db.upsert_record(&record));
        } else if let Some(mut record) = self.run_storage_op(|db| db.get_job(job_id)) {
            record.metrics = Some(metrics);
            record.updated_at = Utc::now();
            self.run_storage_op(|db| db.upsert_record(&record));
        }
        self.persist().await;
    }

    pub async fn update_status(&self, job_id: &str, status: JobStatus) {
        if matches!(
            status,
            JobStatus::Queued
                | JobStatus::Completed { .. }
                | JobStatus::Failed { .. }
                | JobStatus::Skipped { .. }
        ) {
            self.release_in_flight_job(job_id);
        }
        let updated_in_store = {
            let mut store = self.inner.write().await;
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                record.status = status.clone();
                let _ = sanitize_terminal_job_stages(record);
                record.updated_at = Utc::now();
                Some(record.clone())
            } else {
                None
            }
        };
        if let Some(record) = updated_in_store {
            self.run_storage_op(|db| db.upsert_record(&record));
        } else if let Some(mut record) = self.run_storage_op(|db| db.get_job(job_id)) {
            record.status = status;
            let _ = sanitize_terminal_job_stages(&mut record);
            record.updated_at = Utc::now();
            self.run_storage_op(|db| db.upsert_record(&record));
        }
        self.persist().await;
        self.notify.notify_waiters();
    }

    pub async fn set_stages(&self, job_id: &str, stages: Vec<StageRecord>) {
        let updated = {
            let mut store = self.inner.write().await;
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                record.stages = stages;
                record.updated_at = Utc::now();
                Some(record.clone())
            } else {
                None
            }
        };
        if let Some(record) = updated {
            self.run_storage_op(|db| db.upsert_record(&record));
        }
        self.persist().await;
        self.notify.notify_waiters();
    }

    pub async fn update_stage_status(&self, job_id: &str, stage_id: &str, status: StageStatus) {
        let updated = {
            let mut store = self.inner.write().await;
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                if let Some(stage) = record.stages.iter_mut().find(|s| s.id == stage_id) {
                    if let StageStatus::Assigned { ref node_id, .. }
                    | StageStatus::Running { ref node_id, .. } = status
                    {
                        stage.assigned_node = Some(node_id.clone());
                    }
                    stage.status = status;
                    if matches!(
                        stage.status,
                        StageStatus::Assigned { .. } | StageStatus::Running { .. }
                    ) && matches!(record.status, JobStatus::Queued)
                    {
                        record.status = JobStatus::Running {
                            started_at: Utc::now(),
                        };
                    }
                    record.updated_at = Utc::now();
                }
                Some(record.clone())
            } else {
                None
            }
        };
        if let Some(record) = updated {
            self.run_storage_op(|db| db.upsert_record(&record));
        }
        self.persist().await;
        self.notify.notify_waiters();
    }

    pub async fn get_stages(&self, job_id: &str) -> Vec<StageRecord> {
        {
            let store = self.inner.read().await;
            if let Some(rec) = store.iter().find(|r| r.job.id == job_id) {
                return rec.stages.clone();
            }
        }
        self.run_storage_op(|db| db.get_job(job_id))
            .map(|r| r.stages)
            .unwrap_or_default()
    }

    /// Recovers stages assigned or running on a given worker node by resetting them to Pending.
    /// Returns the list of `(job_id, stage_id)` tuples recovered.
    pub async fn recover_stages_for_node(
        &self,
        node_id: &str,
        stage_filter: Option<&[String]>,
    ) -> Vec<(String, String)> {
        let mut recovered = Vec::new();
        let mut records_to_upsert = Vec::new();
        {
            let mut store = self.inner.write().await;
            let now = Utc::now();
            for record in store.iter_mut() {
                if matches!(record.status, JobStatus::Running { .. } | JobStatus::Queued) {
                    let mut modified = false;
                    for stage in record.stages.iter_mut() {
                        let is_node_match = stage.assigned_node.as_deref() == Some(node_id)
                            || match &stage.status {
                                StageStatus::Assigned { node_id: n, .. }
                                | StageStatus::Running { node_id: n, .. } => n == node_id,
                                _ => false,
                            };
                        let is_stage_match = match stage_filter {
                            Some(filter) => filter.iter().any(|f| f == &stage.id),
                            None => true,
                        };

                        if is_node_match
                            && is_stage_match
                            && matches!(
                                stage.status,
                                StageStatus::Assigned { .. } | StageStatus::Running { .. }
                            )
                        {
                            stage.status = StageStatus::Pending;
                            stage.assigned_node = None;
                            record.updated_at = now;
                            modified = true;
                            recovered.push((record.job.id.clone(), stage.id.clone()));
                        }
                    }
                    if modified {
                        records_to_upsert.push(record.clone());
                    }
                }
            }
        }

        if !records_to_upsert.is_empty() {
            self.run_storage_op(|db| db.upsert_records_batch(&records_to_upsert));
        }
        if !recovered.is_empty() {
            self.persist().await;
            self.notify.notify_waiters();
        }

        recovered
    }

    /// Resumes a job by leaving completed stages intact and returning failed/in-flight stages to Pending.
    /// To ensure strict FIFO fairness without line-cutting, the resumed job is moved to the tail
    /// of the queue (push_front in the storage deque) with an updated queued_at timestamp.
    /// Fails with an error if the job is currently actively Running.
    pub async fn resume_job(&self, job_id: &str) -> Result<JobRecord, String> {
        let exists_in_store = {
            let store = self.inner.read().await;
            store.iter().any(|r| r.job.id == job_id)
        };
        let db_fallback = if exists_in_store {
            None
        } else {
            self.run_storage_op(|db| db.get_job(job_id))
        };
        if !exists_in_store && db_fallback.is_none() {
            return Err(format!("Job '{}' not found", job_id));
        }
        let res = {
            let mut store = self.inner.write().await;
            let now = Utc::now();
            let pos = store.iter().position(|r| r.job.id == job_id);
            let mut record = if let Some(idx) = pos {
                if matches!(store[idx].status, JobStatus::Running { .. }) {
                    return Err(format!(
                        "Job '{}' is currently running; cannot resume an active job",
                        job_id
                    ));
                }
                store.remove(idx).unwrap()
            } else if let Some(rec) = db_fallback {
                rec
            } else {
                return Err(format!("Job '{}' not found", job_id));
            };

            for stage in record.stages.iter_mut() {
                if matches!(
                    stage.status,
                    StageStatus::Failed { .. }
                        | StageStatus::Assigned { .. }
                        | StageStatus::Running { .. }
                ) {
                    stage.status = StageStatus::Pending;
                    stage.assigned_node = None;
                }
            }
            record.status = JobStatus::Queued;
            record.job.queued_at = now;
            record.updated_at = now;
            store.push_front(record.clone());
            Ok(record)
        };

        if let Ok(ref record) = res {
            self.release_in_flight_job(job_id);
            self.run_storage_op(|db| db.upsert_record(record));
            self.persist().await;
            self.notify.notify_waiters();
        }

        res
    }

    /// Fully restarts a job by resetting all stages back to Pending.
    /// Resets metrics, moves to the tail of the queue, and rejects if currently running.
    pub async fn restart_job(&self, job_id: &str) -> Result<JobRecord, String> {
        let exists_in_store = {
            let store = self.inner.read().await;
            store.iter().any(|r| r.job.id == job_id)
        };
        let db_fallback = if exists_in_store {
            None
        } else {
            self.run_storage_op(|db| db.get_job(job_id))
        };
        if !exists_in_store && db_fallback.is_none() {
            return Err(format!("Job '{}' not found", job_id));
        }
        let res = {
            let mut store = self.inner.write().await;
            let now = Utc::now();
            let pos = store.iter().position(|r| r.job.id == job_id);
            let mut record = if let Some(idx) = pos {
                if matches!(store[idx].status, JobStatus::Running { .. }) {
                    return Err(format!(
                        "Job '{}' is currently running; cannot restart an active job",
                        job_id
                    ));
                }
                store.remove(idx).unwrap()
            } else if let Some(rec) = db_fallback {
                rec
            } else {
                return Err(format!("Job '{}' not found", job_id));
            };

            for stage in record.stages.iter_mut() {
                stage.status = StageStatus::Pending;
                stage.assigned_node = None;
            }
            record.status = JobStatus::Queued;
            record.metrics = None;
            record.job.queued_at = now;
            record.updated_at = now;
            store.push_front(record.clone());
            Ok(record)
        };

        if let Ok(ref record) = res {
            self.release_in_flight_job(job_id);
            self.run_storage_op(|db| db.upsert_record(record));
            self.persist().await;
            self.notify.notify_waiters();
        }

        res
    }

    pub async fn update_stage_running(
        &self,
        job_id: &str,
        stage_id: &str,
        node_id: &str,
        pid: u32,
    ) {
        let updated = {
            let mut store = self.inner.write().await;
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                let now = Utc::now();
                let mut stage_updated = false;
                for stage in record.stages.iter_mut() {
                    if stage.id == stage_id {
                        if matches!(
                            stage.status,
                            StageStatus::Pending
                                | StageStatus::Assigned { .. }
                                | StageStatus::Running { .. }
                        ) {
                            stage.status = StageStatus::Running {
                                node_id: node_id.to_string(),
                                started_at: now,
                                pid: Some(pid),
                            };
                            stage.assigned_node = Some(node_id.to_string());
                            stage_updated = true;
                        }
                        break;
                    }
                }
                if stage_updated {
                    record.updated_at = now;
                    if matches!(record.status, JobStatus::Queued) {
                        record.status = JobStatus::Running { started_at: now };
                    }
                    Some(record.clone())
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(record) = updated {
            self.run_storage_op(|db| db.upsert_record(&record));
            self.persist().await;
            self.notify.notify_waiters();
        }
    }

    pub async fn recover_stage_if_active(&self, job_id: &str, stage_id: &str) -> bool {
        let updated = {
            let mut store = self.inner.write().await;
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                if let Some(stage) = record.stages.iter_mut().find(|s| s.id == stage_id) {
                    if matches!(
                        stage.status,
                        StageStatus::Assigned { .. } | StageStatus::Running { .. }
                    ) {
                        stage.status = StageStatus::Pending;
                        stage.assigned_node = None;
                        record.updated_at = Utc::now();
                        Some(record.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(record) = updated {
            self.run_storage_op(|db| db.upsert_record(&record));
            self.persist().await;
            self.notify.notify_waiters();
            true
        } else {
            false
        }
    }

    pub async fn wait_for_event(&self) {
        self.notify.notified().await;
    }

    pub fn notify_event(&self) {
        self.notify.notify_waiters();
    }

    pub async fn get_job(&self, job_id: &str) -> Option<JobRecord> {
        {
            let store = self.inner.read().await;
            if let Some(rec) = store.iter().find(|r| r.job.id == job_id) {
                return Some(rec.clone());
            }
        }
        self.run_storage_op(|db| db.get_job(job_id))
    }

    pub async fn list_jobs(&self) -> Vec<JobRecord> {
        let store = self.inner.read().await;
        store.iter().cloned().collect()
    }

    /// Finds the latest completed (`Completed` or `Failed`) build for a repository/branch (or submodule),
    /// ignoring `Skipped`, `Queued`, and `Running` jobs so standalone status/score/coverage/benchmark
    /// badge pills only display `passing` or `failing` from completed executions.
    pub async fn find_latest_job(&self, repo: &str, branch: Option<&str>) -> Option<JobRecord> {
        self.run_storage_op(|db| db.find_latest_completed(repo, branch))
    }

    /// Finds `(latest_active_or_completed, latest_completed)` for a repository/branch Score Card,
    /// ignoring `Skipped` jobs and retaining the previous completed execution's metrics when a job
    /// is `Queued` or `Running`.
    pub async fn find_card_context(
        &self,
        repo: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        self.run_storage_op(|db| db.find_card_context(repo, branch))
    }

    pub async fn find_submodule_job(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> Option<JobRecord> {
        self.run_storage_op(|db| db.find_submodule_completed(parent_repo, submodule, branch))
    }

    pub async fn find_submodule_card_context(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        self.run_storage_op(|db| db.find_submodule_card_context(parent_repo, submodule, branch))
    }
}

pub fn extract_submodule_job(parent_record: &JobRecord, submodule: &str) -> Option<JobRecord> {
    let metrics = parent_record.metrics.as_ref()?;
    let clean_target = submodule
        .rsplit_once('/')
        .map(|(_, r)| r)
        .unwrap_or(submodule);

    for (sub_name, sub) in &metrics.submodules {
        let sub_short = sub_name
            .rsplit_once('/')
            .map(|(_, r)| r)
            .unwrap_or(sub_name);
        let path_short = sub
            .path
            .rsplit_once('/')
            .map(|(_, r)| r)
            .unwrap_or(&sub.path);

        let is_match = sub_name.eq_ignore_ascii_case(submodule)
            || sub_short.eq_ignore_ascii_case(clean_target)
            || path_short.eq_ignore_ascii_case(clean_target)
            || sub_name
                .replace('-', "_")
                .eq_ignore_ascii_case(&clean_target.replace('-', "_"));

        if is_match {
            let owner = parent_record
                .job
                .repo_name
                .split_once('/')
                .map(|(o, _)| o)
                .unwrap_or("LMA1980");
            let sub_job = Job {
                id: format!("{}-{}", parent_record.job.id, sub_short),
                event_type: parent_record.job.event_type.clone(),
                repo_name: format!("{}/{}", owner, sub_short),
                clone_url: String::new(),
                commit_sha: parent_record.job.commit_sha.clone(),
                ref_name: parent_record.job.ref_name.clone(),
                sender: parent_record.job.sender.clone(),
                queued_at: parent_record.job.queued_at,
            };
            return Some(JobRecord {
                job: sub_job,
                status: parent_record.status.clone(),
                log_file: parent_record.log_file.clone(),
                updated_at: parent_record.updated_at,
                metrics: Some(JobMetrics {
                    quality_score: sub.quality_score,
                    letter_grade: sub.letter_grade.clone(),
                    coverage_pct: sub.coverage_pct,
                    benchmark_summary: sub.benchmark_summary.clone(),
                    tests_passed: sub.tests_passed,
                    tests_total: sub.tests_total,
                    advisories_count: 0,
                    clippy_warnings: sub.clippy_warnings,
                    submodules: BTreeMap::new(),
                }),
                stages: Vec::new(),
            });
        }
    }

    None
}

/// Normalizes a git reference by stripping any leading `/` and `refs/heads/` prefix,
/// returning the bare branch or tag name.
pub fn normalize_ref(r: &str) -> &str {
    let trimmed = r.trim().trim_start_matches('/');
    trimmed.strip_prefix("refs/heads/").unwrap_or(trimmed)
}

/// Preserves any stages that already reached `StageStatus::Completed { exit_code: 0, .. }`
/// in `local` when merging a remote snapshot `remote` for the same job execution.
pub(crate) fn merge_completed_stages(local: &JobRecord, remote: &mut JobRecord) {
    if local.job.queued_at != remote.job.queued_at {
        return;
    }
    for r_stage in &mut remote.stages {
        if !matches!(r_stage.status, StageStatus::Completed { exit_code: 0, .. }) {
            if let Some(l_stage) = local.stages.iter().find(|s| s.id == r_stage.id) {
                if matches!(l_stage.status, StageStatus::Completed { exit_code: 0, .. }) {
                    r_stage.status = l_stage.status.clone();
                    if r_stage.assigned_node.is_none() {
                        r_stage.assigned_node = l_stage.assigned_node.clone();
                    }
                }
            }
        }
    }
}

/// Ensures terminal jobs (`Completed`, `Failed`, `Skipped`) never retain orphaned
/// `StageStatus::Assigned` or `StageStatus::Running` stages.
pub(crate) fn sanitize_terminal_job_stages(rec: &mut JobRecord) -> bool {
    let mut changed = false;
    match &rec.status {
        JobStatus::Completed { exit_code, .. } => {
            let code = *exit_code;
            for stage in &mut rec.stages {
                if matches!(
                    stage.status,
                    StageStatus::Assigned { .. } | StageStatus::Running { .. }
                ) {
                    stage.status = StageStatus::Completed {
                        exit_code: code,
                        duration_secs: 0,
                    };
                    changed = true;
                }
            }
        }
        JobStatus::Failed { error } => {
            let err_clone = error.clone();
            for stage in &mut rec.stages {
                if matches!(
                    stage.status,
                    StageStatus::Assigned { .. } | StageStatus::Running { .. }
                ) {
                    stage.status = StageStatus::Failed {
                        error: err_clone.clone(),
                    };
                    changed = true;
                }
            }
        }
        JobStatus::Skipped { reason } => {
            let reason_clone = reason.clone();
            for stage in &mut rec.stages {
                if matches!(
                    stage.status,
                    StageStatus::Pending
                        | StageStatus::Assigned { .. }
                        | StageStatus::Running { .. }
                ) {
                    stage.status = StageStatus::Skipped {
                        reason: reason_clone.clone(),
                    };
                    changed = true;
                }
            }
        }
        JobStatus::Queued | JobStatus::Running { .. } => {}
    }
    changed
}

/// Determines whether an in-memory `local` [`JobRecord`] should be preserved over
/// a snapshot record `rec` loaded from [`ControllerStorage`] during standby or leader rehydration (`#107`).
#[must_use]
pub(crate) fn should_preserve_local_record(
    is_leader: bool,
    local: &JobRecord,
    rec: &JobRecord,
) -> bool {
    if is_leader {
        // On the active leader, any record already in self.inner is authoritative
        // for its own status and stage progression, so never overwrite an existing
        // local record in by_id unless rec.updated_at > local.updated_at
        // AND matches!(local.status, JobStatus::Queued) AND local.stages.is_empty().
        let allow_remote_overwrite = rec.updated_at > local.updated_at
            && matches!(local.status, JobStatus::Queued)
            && local.stages.is_empty();
        if !allow_remote_overwrite {
            return true;
        }
    }

    let rec_is_terminal = matches!(
        rec.status,
        JobStatus::Completed { .. } | JobStatus::Failed { .. } | JobStatus::Skipped { .. }
    );
    let local_is_terminal = matches!(
        local.status,
        JobStatus::Completed { .. } | JobStatus::Failed { .. } | JobStatus::Skipped { .. }
    );
    if !is_leader && rec_is_terminal && !local_is_terminal {
        return false;
    }

    let local_completed = local
        .stages
        .iter()
        .filter(|s| matches!(s.status, StageStatus::Completed { .. }))
        .count();
    let rec_completed = rec
        .stages
        .iter()
        .filter(|s| matches!(s.status, StageStatus::Completed { .. }))
        .count();
    if !is_leader && rec_completed > local_completed {
        return false;
    }

    if local.updated_at >= rec.updated_at {
        return true;
    }

    if matches!(local.status, JobStatus::Running { .. }) && matches!(rec.status, JobStatus::Queued)
    {
        return true;
    }

    let local_has_active_stage = local.stages.iter().any(|s| {
        matches!(
            s.status,
            StageStatus::Assigned { .. } | StageStatus::Running { .. }
        )
    });
    let rec_has_active_stage = rec.stages.iter().any(|s| {
        matches!(
            s.status,
            StageStatus::Assigned { .. } | StageStatus::Running { .. }
        )
    });
    if local_has_active_stage && !rec_has_active_stage {
        return true;
    }

    if local_completed > rec_completed {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_submodule_job_lookup() {
        let store = JobStore::new(10, None);
        let job = Job {
            id: "job-model-runner-1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/model-runner".to_string(),
            clone_url: "https://github.com/LMA1980/model-runner.git".to_string(),
            commit_sha: "abcd1234efgh".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };

        let mut submodules = BTreeMap::new();
        submodules.insert(
            "k3-core".to_string(),
            SubmoduleMetrics {
                name: "k3-core".to_string(),
                path: "code/core".to_string(),
                quality_score: 95,
                letter_grade: "A+".to_string(),
                tests_passed: 4,
                tests_total: 4,
                coverage_pct: Some(92.5),
                benchmark_summary: Some("1 benches (49.0 ns/iter)".to_string()),
                clippy_warnings: 0,
            },
        );

        store
            .add_job(job.clone(), PathBuf::from("logs/test.log"))
            .await;
        store
            .update_metrics(
                &job.id,
                JobMetrics {
                    quality_score: 98,
                    letter_grade: "A+".to_string(),
                    coverage_pct: Some(90.0),
                    benchmark_summary: None,
                    tests_passed: 10,
                    tests_total: 10,
                    advisories_count: 0,
                    clippy_warnings: 0,
                    submodules,
                },
            )
            .await;
        store
            .update_status(
                &job.id,
                JobStatus::Completed {
                    duration_secs: 5,
                    exit_code: 0,
                },
            )
            .await;

        // Test direct parent lookup
        let parent = store.find_latest_job("LMA1980/model-runner", None).await;
        assert!(parent.is_some());
        assert_eq!(parent.unwrap().metrics.unwrap().quality_score, 98);

        // Test fallback lookup using repo name "k3-core"
        let sub_fallback = store.find_latest_job("LMA1980/k3-core", None).await;
        assert!(sub_fallback.is_some());
        let sub_rec = sub_fallback.unwrap();
        assert_eq!(sub_rec.job.repo_name, "LMA1980/k3-core");
        let sub_m = sub_rec.metrics.unwrap();
        assert_eq!(sub_m.quality_score, 95);
        assert_eq!(sub_m.letter_grade, "A+");
        assert_eq!(sub_m.tests_passed, 4);
        assert_eq!(sub_m.coverage_pct, Some(92.5));

        // Test fallback lookup using short name "k3-core"
        let sub_short = store.find_latest_job("k3-core", None).await;
        assert!(sub_short.is_some());

        // Test find_submodule_job explicitly
        let explicit_sub = store
            .find_submodule_job("LMA1980/model-runner", "k3-core", None)
            .await;
        assert!(explicit_sub.is_some());
        assert_eq!(explicit_sub.unwrap().metrics.unwrap().quality_score, 95);

        // Test path match fallback e.g. "core"
        let path_sub = store
            .find_submodule_job("LMA1980/model-runner", "core", None)
            .await;
        assert!(path_sub.is_some());
        assert_eq!(path_sub.unwrap().metrics.unwrap().quality_score, 95);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_coalescing_fifo_queue_and_snapshot() {
        let store = JobStore::new(20, None);

        // 1. Enqueue job 1 for ActionRunner-rs and claim it so it is Running
        let job1 = Job {
            id: "job-100-aaaa1111".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/ActionRunner-rs".to_string(),
            clone_url: "https://github.com/LMA1980/ActionRunner-rs.git".to_string(),
            commit_sha: "aaaa111100000000".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res1 = store
            .enqueue_job(job1.clone(), PathBuf::from("logs/job1.log"))
            .await;
        assert_eq!(res1.queue_position, 1);
        assert!(res1.superseded_jobs.is_empty());

        let claimed1 = store.claim_next_queued_job(10).await;
        assert!(claimed1.is_some());
        assert_eq!(claimed1.unwrap().id, "job-100-aaaa1111");

        // 2. While job 1 is running, enqueue two pushes for model-runner main and one for k3-core
        let job2_old = Job {
            id: "job-101-bbbb2222".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/model-runner".to_string(),
            clone_url: "https://github.com/LMA1980/model-runner.git".to_string(),
            commit_sha: "bbbb222200000000".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res2 = store
            .enqueue_job(job2_old.clone(), PathBuf::from("logs/job2.log"))
            .await;
        assert_eq!(res2.queue_position, 1);
        assert!(res2.superseded_jobs.is_empty());

        let job3_other = Job {
            id: "job-102-cccc3333".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/k3-core".to_string(),
            clone_url: "https://github.com/LMA1980/k3-core.git".to_string(),
            commit_sha: "cccc333300000000".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res3 = store
            .enqueue_job(job3_other.clone(), PathBuf::from("logs/job3.log"))
            .await;
        assert_eq!(res3.queue_position, 2);

        // Newer push for model-runner main arrives while job2_old is still Queued -> coalesces job2_old!
        let job4_new = Job {
            id: "job-103-dddd4444".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/model-runner".to_string(),
            clone_url: "https://github.com/LMA1980/model-runner.git".to_string(),
            commit_sha: "dddd444400000000".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res4 = store
            .enqueue_job(job4_new.clone(), PathBuf::from("logs/job4.log"))
            .await;
        assert_eq!(res4.superseded_jobs, vec!["job-101-bbbb2222".to_string()]);
        assert_eq!(res4.queue_position, 2);

        // Verify queue snapshot reflects 1 active job, 2 queued jobs, and 1 superseded job
        let snap = store.queue_snapshot().await;
        assert_eq!(snap.status, "busy");
        assert_eq!(snap.queue_depth, 2);
        assert_eq!(snap.stats.running_jobs, 1);
        assert_eq!(snap.stats.queued_jobs, 2);
        assert_eq!(snap.stats.superseded_jobs, 1);
        assert_eq!(snap.queued_jobs[0].record.job.id, "job-102-cccc3333");
        assert_eq!(snap.queued_jobs[0].position, 1);
        assert_eq!(snap.queued_jobs[1].record.job.id, "job-103-dddd4444");
        assert_eq!(snap.queued_jobs[1].position, 2);

        // Claim remaining jobs in FIFO order
        let next1 = store.claim_next_queued_job(10).await.unwrap();
        assert_eq!(next1.id, "job-102-cccc3333");
        let next2 = store.claim_next_queued_job(10).await.unwrap();
        assert_eq!(next2.id, "job-103-dddd4444");
        assert!(store.claim_next_queued_job(10).await.is_none());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_claim_next_queued_job_concurrency_and_per_repo_serialization() {
        let store = JobStore::new(10, None);

        let job_repo_a1 = Job {
            id: "job-a1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/repo-a".to_string(),
            clone_url: "https://github.com/LMA1980/repo-a.git".to_string(),
            commit_sha: "1111".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let job_repo_a2 = Job {
            id: "job-a2".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/repo-a".to_string(),
            clone_url: "https://github.com/LMA1980/repo-a.git".to_string(),
            commit_sha: "2222".to_string(),
            ref_name: "refs/heads/feat/branch-2".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let job_repo_b1 = Job {
            id: "job-b1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/repo-b".to_string(),
            clone_url: "https://github.com/LMA1980/repo-b.git".to_string(),
            commit_sha: "3333".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };

        store
            .enqueue_job(job_repo_a1, PathBuf::from("logs/a1.log"))
            .await;
        store
            .enqueue_job(job_repo_a2, PathBuf::from("logs/a2.log"))
            .await;
        store
            .enqueue_job(job_repo_b1, PathBuf::from("logs/b1.log"))
            .await;

        // 1. With max_concurrent = 2:
        // First claim: repo-a1 is claimed (running_count = 1, running_repos = {repo-a})
        let c1 = store.claim_next_queued_job(2).await;
        assert_eq!(c1.unwrap().id, "job-a1");

        // Second claim: repo-a2 cannot run because repo-a is already running! So repo-b1 is claimed.
        let c2 = store.claim_next_queued_job(2).await;
        assert_eq!(c2.unwrap().id, "job-b1");

        // Third claim: running_count = 2 >= max_concurrent (2), returns None.
        let c3 = store.claim_next_queued_job(2).await;
        assert!(c3.is_none());

        // Now repo-b1 finishes:
        store
            .update_status(
                "job-b1",
                JobStatus::Completed {
                    duration_secs: 5,
                    exit_code: 0,
                },
            )
            .await;
        // running_count is now 1 (repo-a1 is running), but repo-a is still running, so repo-a2 cannot run!
        let c4 = store.claim_next_queued_job(2).await;
        assert!(c4.is_none());

        // Now repo-a1 finishes:
        store
            .update_status(
                "job-a1",
                JobStatus::Completed {
                    duration_secs: 10,
                    exit_code: 0,
                },
            )
            .await;
        // Now repo-a is free: repo-a2 can finally be claimed!
        let c5 = store.claim_next_queued_job(2).await;
        assert_eq!(c5.unwrap().id, "job-a2");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_merge_vs_push_first_received_wins() {
        let store = JobStore::new(10, None);

        // Case 1: Merge arrives first -> merge enqueued, subsequent push on same commit ID is ignored
        let merge_job = Job {
            id: "job-merge-1".to_string(),
            event_type: "merge".to_string(),
            repo_name: "LMA1980/model-runner".to_string(),
            clone_url: String::new(),
            commit_sha: "abcd111122223333".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res_merge = store
            .enqueue_job(merge_job, PathBuf::from("logs/merge.log"))
            .await;
        assert!(!res_merge.ignored);
        assert_eq!(res_merge.job_id, "job-merge-1");
        assert_eq!(res_merge.queue_position, 1);

        let push_job = Job {
            id: "job-push-1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/model-runner".to_string(),
            clone_url: String::new(),
            commit_sha: "abcd111122223333".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res_push = store
            .enqueue_job(push_job, PathBuf::from("logs/push.log"))
            .await;
        assert!(res_push.ignored);
        assert_eq!(res_push.winning_job_id, Some("job-merge-1".to_string()));
        assert!(res_push
            .ignore_reason
            .as_ref()
            .unwrap()
            .contains("Merge event (job-merge-1) already received"));

        // Case 2: Push arrives first -> push enqueued, subsequent merge on same commit ID is ignored
        let push_first = Job {
            id: "job-push-first".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/ActionRunner-rs".to_string(),
            clone_url: String::new(),
            commit_sha: "beef444455556666".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res_push_first = store
            .enqueue_job(push_first, PathBuf::from("logs/push2.log"))
            .await;
        assert!(!res_push_first.ignored);
        assert_eq!(res_push_first.job_id, "job-push-first");

        let merge_second = Job {
            id: "job-merge-second".to_string(),
            event_type: "merge".to_string(),
            repo_name: "LMA1980/ActionRunner-rs".to_string(),
            clone_url: String::new(),
            commit_sha: "beef444455556666".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res_merge_second = store
            .enqueue_job(merge_second, PathBuf::from("logs/merge2.log"))
            .await;
        assert!(res_merge_second.ignored);
        assert_eq!(
            res_merge_second.winning_job_id,
            Some("job-push-first".to_string())
        );
        assert!(res_merge_second
            .ignore_reason
            .as_ref()
            .unwrap()
            .contains("Push event (job-push-first) already received"));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_pull_request_vs_push_pull_request_always_wins() {
        let store = JobStore::new(10, None);

        // Subcase A: pull_request arrives FIRST, push arrives SECOND for same commit ID
        let pr_first = Job {
            id: "job-pr-1".to_string(),
            event_type: "pull_request".to_string(),
            repo_name: "LMA1980/ActionRunner-controller".to_string(),
            clone_url: String::new(),
            commit_sha: "face1234567890ab".to_string(),
            ref_name: "feat/my-feature".to_string(), // PR format
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res_pr = store
            .enqueue_job(pr_first, PathBuf::from("logs/pr1.log"))
            .await;
        assert!(!res_pr.ignored);
        assert_eq!(res_pr.job_id, "job-pr-1");

        let push_second = Job {
            id: "job-push-second".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/ActionRunner-controller".to_string(),
            clone_url: String::new(),
            commit_sha: "face1234567890ab".to_string(),
            ref_name: "refs/heads/feat/my-feature".to_string(), // push format
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res_push = store
            .enqueue_job(push_second, PathBuf::from("logs/push_sec.log"))
            .await;
        assert!(res_push.ignored);
        assert_eq!(res_push.winning_job_id, Some("job-pr-1".to_string()));
        assert!(res_push
            .ignore_reason
            .as_ref()
            .unwrap()
            .contains("Pull request event (job-pr-1) wins over push"));

        // Subcase B: push arrives FIRST (queued), pull_request arrives SECOND -> pull_request wins and supersedes push!
        let push_queued = Job {
            id: "job-push-queued".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/ActionRunner-controller".to_string(),
            clone_url: String::new(),
            commit_sha: "deadbeef99998888".to_string(),
            ref_name: "refs/heads/feat/another".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res_push_q = store
            .enqueue_job(push_queued, PathBuf::from("logs/push_q.log"))
            .await;
        assert!(!res_push_q.ignored);
        assert_eq!(res_push_q.job_id, "job-push-queued");

        let pr_second = Job {
            id: "job-pr-wins".to_string(),
            event_type: "pull_request".to_string(),
            repo_name: "LMA1980/ActionRunner-controller".to_string(),
            clone_url: String::new(),
            commit_sha: "deadbeef99998888".to_string(),
            ref_name: "feat/another".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res_pr_wins = store
            .enqueue_job(pr_second, PathBuf::from("logs/pr_wins.log"))
            .await;
        assert!(!res_pr_wins.ignored);
        assert_eq!(res_pr_wins.job_id, "job-pr-wins");
        assert_eq!(
            res_pr_wins.superseded_jobs,
            vec!["job-push-queued".to_string()]
        );

        // Verify the push job was marked as Skipped
        let push_rec = store.get_job("job-push-queued").await.unwrap();
        assert!(matches!(
            push_rec.status,
            JobStatus::Skipped { reason } if reason.contains("Superseded by pull_request event")
        ));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_pull_request_supersedes_running_push() {
        let store = JobStore::new(10, None);

        let push_running = Job {
            id: "job-push-active".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/ActionRunner-rs".to_string(),
            clone_url: String::new(),
            commit_sha: "c0ffee1122334455".to_string(),
            ref_name: "refs/heads/feat/hotfix".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        store
            .enqueue_job(push_running, PathBuf::from("logs/push_act.log"))
            .await;
        let claimed = store.claim_next_queued_job(10).await.unwrap();
        assert_eq!(claimed.id, "job-push-active");

        // Now pull_request arrives for the same commit ID while push is Running
        let pr_incoming = Job {
            id: "job-pr-override".to_string(),
            event_type: "pull_request".to_string(),
            repo_name: "LMA1980/ActionRunner-rs".to_string(),
            clone_url: String::new(),
            commit_sha: "c0ffee1122334455".to_string(),
            ref_name: "feat/hotfix".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res = store
            .enqueue_job(pr_incoming, PathBuf::from("logs/pr_ovr.log"))
            .await;
        assert!(!res.ignored);
        assert_eq!(res.job_id, "job-pr-override");
        assert_eq!(res.superseded_jobs, vec!["job-push-active".to_string()]);

        // Running push must now be marked Skipped so scheduler stops it
        let push_rec = store.get_job("job-push-active").await.unwrap();
        assert!(matches!(
            push_rec.status,
            JobStatus::Skipped { reason } if reason.contains("Superseded by pull_request event")
        ));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_duplicate_same_event_ignored() {
        let store = JobStore::new(10, None);

        let job1 = Job {
            id: "job-orig-push".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/model-runner".to_string(),
            clone_url: String::new(),
            commit_sha: "9988776655443322".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res1 = store.enqueue_job(job1, PathBuf::from("logs/j1.log")).await;
        assert!(!res1.ignored);

        let job2 = Job {
            id: "job-dupe-push".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/model-runner".to_string(),
            clone_url: String::new(),
            commit_sha: "9988776655443322".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res2 = store.enqueue_job(job2, PathBuf::from("logs/j2.log")).await;
        assert!(res2.ignored);
        assert_eq!(res2.winning_job_id, Some("job-orig-push".to_string()));
        assert!(res2
            .ignore_reason
            .as_ref()
            .unwrap()
            .contains("Duplicate push event (job-orig-push) already received"));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_pr_on_branch_does_not_block_main_merge() {
        let store = JobStore::new(10, None);

        // 1. PR event on feature branch runs and completes
        let pr_job = Job {
            id: "job-pr-feature".to_string(),
            event_type: "pull_request".to_string(),
            repo_name: "LMA1980/test-repo".to_string(),
            clone_url: String::new(),
            commit_sha: "1234abcd1234abcd".to_string(),
            ref_name: "feat/cool-thing".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        store
            .enqueue_job(pr_job, PathBuf::from("logs/pr.log"))
            .await;
        store
            .update_status(
                "job-pr-feature",
                JobStatus::Completed {
                    duration_secs: 15,
                    exit_code: 0,
                },
            )
            .await;

        // 2. PR is fast-forward merged to main with the same commit SHA:
        // Merge event arrives for refs/heads/main -> must NOT be blocked by PR on feat/cool-thing!
        let merge_main = Job {
            id: "job-merge-main".to_string(),
            event_type: "merge".to_string(),
            repo_name: "LMA1980/test-repo".to_string(),
            clone_url: String::new(),
            commit_sha: "1234abcd1234abcd".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res_merge = store
            .enqueue_job(merge_main, PathBuf::from("logs/merge.log"))
            .await;
        assert!(
            !res_merge.ignored,
            "Merge to main should not be blocked by PR on feature branch"
        );
        assert_eq!(res_merge.job_id, "job-merge-main");

        // 3. GitHub also fires push event for refs/heads/main with the same commit SHA:
        // Because merge was received first for main, push to main is ignored!
        let push_main = Job {
            id: "job-push-main".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/test-repo".to_string(),
            clone_url: String::new(),
            commit_sha: "1234abcd1234abcd".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        let res_push = store
            .enqueue_job(push_main, PathBuf::from("logs/push.log"))
            .await;
        assert!(
            res_push.ignored,
            "Push to main should be ignored since merge already won on main"
        );
        assert_eq!(res_push.winning_job_id, Some("job-merge-main".to_string()));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_job_resume_and_restart() {
        let store = JobStore::new(10, None);
        let job = Job {
            id: "job-resume-test".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/test-repo".to_string(),
            clone_url: String::new(),
            commit_sha: "beef1234beef".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };

        store
            .add_job(job.clone(), PathBuf::from("logs/test.log"))
            .await;
        let stages = vec![
            StageRecord {
                id: "fmt".to_string(),
                name: "Format".to_string(),
                tags: vec![],
                threads: 2,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Completed {
                    duration_secs: 1,
                    exit_code: 0,
                },
                assigned_node: Some("node-1".to_string()),
                exclusive: false,
            },
            StageRecord {
                id: "test".to_string(),
                name: "Test".to_string(),
                tags: vec![],
                threads: 2,
                toolchain: None,
                depends_on: vec!["fmt".to_string()],
                status: StageStatus::Failed {
                    error: "test failed".to_string(),
                },
                assigned_node: Some("node-2".to_string()),
                exclusive: false,
            },
            StageRecord {
                id: "bench".to_string(),
                name: "Bench".to_string(),
                tags: vec![],
                threads: 2,
                toolchain: None,
                depends_on: vec!["test".to_string()],
                status: StageStatus::Pending,
                assigned_node: None,
                exclusive: false,
            },
        ];
        store.set_stages(&job.id, stages).await;
        store
            .update_status(
                &job.id,
                JobStatus::Failed {
                    error: "Stage failed".to_string(),
                },
            )
            .await;

        // 1. Resume should preserve Completed "fmt", and reset Failed "test" to Pending
        let resumed = store.resume_job(&job.id).await.expect("resume succeeds");
        assert!(matches!(resumed.status, JobStatus::Queued));
        assert!(matches!(
            resumed.stages[0].status,
            StageStatus::Completed { .. }
        ));
        assert_eq!(resumed.stages[1].status, StageStatus::Pending);
        assert_eq!(resumed.stages[1].assigned_node, None);
        assert_eq!(resumed.stages[2].status, StageStatus::Pending);

        // 2. Restart should reset ALL stages to Pending
        let restarted = store.restart_job(&job.id).await.expect("restart succeeds");
        assert!(matches!(restarted.status, JobStatus::Queued));
        assert_eq!(restarted.stages[0].status, StageStatus::Pending);
        assert_eq!(restarted.stages[0].assigned_node, None);
        assert_eq!(restarted.stages[1].status, StageStatus::Pending);
        assert_eq!(restarted.stages[2].status, StageStatus::Pending);

        // 3. Resuming or restarting a currently running job must fail to avoid phantom jobs
        store
            .update_status(
                &job.id,
                JobStatus::Running {
                    started_at: Utc::now(),
                },
            )
            .await;
        assert!(store.resume_job(&job.id).await.is_err());
        assert!(store.restart_job(&job.id).await.is_err());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_resumed_job_does_not_cut_queue_line() {
        let store = JobStore::new(10, None);
        let job1 = Job {
            id: "job-1-early".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/repo-a".to_string(),
            clone_url: String::new(),
            commit_sha: "sha1".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now() - chrono::Duration::seconds(100),
        };
        let job2 = Job {
            id: "job-2-queued".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/repo-b".to_string(),
            clone_url: String::new(),
            commit_sha: "sha2".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now() - chrono::Duration::seconds(50),
        };

        store
            .add_job(job1.clone(), PathBuf::from("logs/j1.log"))
            .await;
        store
            .update_status(
                &job1.id,
                JobStatus::Failed {
                    error: "failed".to_string(),
                },
            )
            .await;

        store
            .add_job(job2.clone(), PathBuf::from("logs/j2.log"))
            .await;
        // job2 is currently Queued

        // Now resume failed job1
        store.resume_job(&job1.id).await.expect("resumes ok");

        // When claiming next queued job, job2 must be claimed FIRST because it was queued before job1 was resumed!
        let claimed_first = store.claim_next_queued_job(10).await.expect("claim 1");
        assert_eq!(claimed_first.id, "job-2-queued");

        let claimed_second = store.claim_next_queued_job(10).await.expect("claim 2");
        assert_eq!(claimed_second.id, "job-1-early");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_recover_stages_for_node() {
        let store = JobStore::new(10, None);
        let job = Job {
            id: "job-recover-node".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/test-repo".to_string(),
            clone_url: String::new(),
            commit_sha: "c0ffee1234".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };

        store
            .add_job(job.clone(), PathBuf::from("logs/test.log"))
            .await;
        store
            .update_status(
                &job.id,
                JobStatus::Running {
                    started_at: Utc::now(),
                },
            )
            .await;

        let stages = vec![
            StageRecord {
                id: "stage-1".to_string(),
                name: "Stage 1".to_string(),
                tags: vec![],
                threads: 2,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Assigned {
                    node_id: "worker-riscv64".to_string(),
                    started_at: Utc::now(),
                },
                assigned_node: Some("worker-riscv64".to_string()),
                exclusive: false,
            },
            StageRecord {
                id: "stage-2".to_string(),
                name: "Stage 2".to_string(),
                tags: vec![],
                threads: 2,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Assigned {
                    node_id: "storage-node".to_string(),
                    started_at: Utc::now(),
                },
                assigned_node: Some("storage-node".to_string()),
                exclusive: false,
            },
        ];
        store.set_stages(&job.id, stages).await;

        // Node worker-riscv64 restarts or disconnects:
        let recovered = store.recover_stages_for_node("worker-riscv64", None).await;
        assert_eq!(
            recovered,
            vec![("job-recover-node".to_string(), "stage-1".to_string())]
        );

        let updated_job = store.get_job(&job.id).await.unwrap();
        assert_eq!(updated_job.stages[0].status, StageStatus::Pending);
        assert_eq!(updated_job.stages[0].assigned_node, None);
        // stage-2 on storage-node should remain untouched
        assert!(matches!(
            updated_job.stages[1].status,
            StageStatus::Assigned { .. }
        ));
        assert_eq!(
            updated_job.stages[1].assigned_node.as_deref(),
            Some("storage-node")
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_duckdb_persistent_history_survives_ring_buffer_eviction_and_ignores_skipped() {
        // Tiny max_history = 2 to force immediate eviction from in-memory deque
        let store = JobStore::new(2, None);

        // 1. Quiet repository completes a passing job with metrics
        let quiet_job = Job {
            id: "job-quiet-ipc-1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/ActionRunner-ipc".to_string(),
            clone_url: "https://github.com/LMA1980/ActionRunner-ipc.git".to_string(),
            commit_sha: "1111222233334444".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now() - chrono::Duration::seconds(500),
        };
        store
            .enqueue_job(quiet_job.clone(), PathBuf::from("logs/ipc.log"))
            .await;
        store
            .update_metrics(
                &quiet_job.id,
                JobMetrics {
                    quality_score: 99,
                    letter_grade: "A+".to_string(),
                    coverage_pct: Some(94.2),
                    benchmark_summary: Some("12.3 ns/iter".to_string()),
                    tests_passed: 18,
                    tests_total: 18,
                    advisories_count: 0,
                    clippy_warnings: 0,
                    submodules: BTreeMap::new(),
                },
            )
            .await;
        store
            .update_status(
                &quiet_job.id,
                JobStatus::Completed {
                    duration_secs: 12,
                    exit_code: 0,
                },
            )
            .await;

        // 2. Noisy repository runs 5 jobs, completely evicting quiet_job from the 2-slot in-memory VecDeque
        for i in 0..5 {
            let noisy_job = Job {
                id: format!("job-noisy-{}", i),
                event_type: "push".to_string(),
                repo_name: "LMA1980/model-runner".to_string(),
                clone_url: String::new(),
                commit_sha: format!("aaaa00000000000{}", i),
                ref_name: "refs/heads/main".to_string(),
                sender: "LMA1980".to_string(),
                queued_at: Utc::now() - chrono::Duration::seconds(400 - i * 10),
            };
            store
                .enqueue_job(noisy_job.clone(), PathBuf::from("logs/noisy.log"))
                .await;
            store
                .update_status(
                    &noisy_job.id,
                    JobStatus::Completed {
                        duration_secs: 5,
                        exit_code: 0,
                    },
                )
                .await;
        }

        // Verify in-memory list_jobs only has 2 items, yet DuckDB retains quiet_job for badges & cards!
        assert_eq!(store.list_jobs().await.len(), 2);

        let recovered_pill = store
            .find_latest_job("LMA1980/ActionRunner-ipc", None)
            .await
            .expect("DuckDB retains evicted repo for badge pills");
        assert_eq!(recovered_pill.job.id, "job-quiet-ipc-1");
        assert_eq!(recovered_pill.metrics.unwrap().quality_score, 99);

        let (card_act, card_comp) = store
            .find_card_context("LMA1980/ActionRunner-ipc", Some("main"))
            .await;
        assert_eq!(card_act.unwrap().job.id, "job-quiet-ipc-1");
        assert_eq!(card_comp.unwrap().job.id, "job-quiet-ipc-1");

        // 3. Now enqueue a new job on ActionRunner-ipc that gets superseded (Skipped) by another Queued job
        let queued_1 = Job {
            id: "job-ipc-queued-1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/ActionRunner-ipc".to_string(),
            clone_url: String::new(),
            commit_sha: "bbbb111122223333".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now() - chrono::Duration::seconds(20),
        };
        store
            .enqueue_job(queued_1.clone(), PathBuf::from("logs/q1.log"))
            .await;

        let queued_2 = Job {
            id: "job-ipc-queued-2".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/ActionRunner-ipc".to_string(),
            clone_url: String::new(),
            commit_sha: "cccc111122223333".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now() - chrono::Duration::seconds(10),
        };
        let enq_res = store
            .enqueue_job(queued_2.clone(), PathBuf::from("logs/q2.log"))
            .await;
        assert_eq!(
            enq_res.superseded_jobs,
            vec!["job-ipc-queued-1".to_string()]
        );

        // Pill lookup (find_latest_job) must STILL return job-quiet-ipc-1 (Completed, 99% A+), ignoring Skipped and Queued!
        let pill_during_queue = store
            .find_latest_job("LMA1980/ActionRunner-ipc", Some("main"))
            .await
            .unwrap();
        assert_eq!(pill_during_queue.job.id, "job-quiet-ipc-1");

        // Card context lookup (find_card_context) must return (job-ipc-queued-2 [Queued], job-quiet-ipc-1 [Completed]), ignoring Skipped job-ipc-queued-1!
        let (active_rec, prev_comp_rec) = store
            .find_card_context("LMA1980/ActionRunner-ipc", Some("main"))
            .await;
        assert_eq!(active_rec.unwrap().job.id, "job-ipc-queued-2");
        assert_eq!(prev_comp_rec.unwrap().job.id, "job-quiet-ipc-1");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_duckdb_backfill_from_historical_logs_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo_logs = tmp
            .path()
            .join("logs")
            .join("LMA1980")
            .join("ActionRunner-ipc");
        std::fs::create_dir_all(&repo_logs).expect("create repo logs dir");

        let log_file = repo_logs.join("job-1729500000-deadbeef.log");
        std::fs::write(
            &log_file,
            "2026-10-21T10:00:00Z [worker-riscv64] [test] [stdout] running 7 tests\n2026-10-21T10:00:02Z [worker-riscv64] [test] [stdout] test result: ok. 7 passed; 0 failed; 0 ignored\n",
        )
        .expect("write historical log");

        let store = JobStore::new(10, Some(tmp.path()));

        let rec = store
            .find_latest_job("LMA1980/ActionRunner-ipc", None)
            .await
            .expect("reconstructed from log file");
        assert_eq!(rec.job.id, "job-1729500000-deadbeef");
        assert_eq!(rec.job.commit_sha, "deadbeef");
        let m = rec.metrics.expect("metrics reconstructed");
        assert_eq!(m.quality_score, 100);
        assert_eq!(m.tests_passed, 7);
        assert_eq!(m.tests_total, 7);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_food_sample_requeue_preserves_priority_and_claims_ready_stages() {
        use crate::cluster::ClusterRegistry;
        use action_runner_ipc::WorkerRegistration;
        use tokio::sync::mpsc;

        let store = JobStore::new(10, None);
        let cluster = ClusterRegistry::new();

        // Register 2 workers: node-x86 (fmt) and worker-riscv64 (k3)
        let (tx_x86, _rx_x86) = mpsc::channel(8);
        cluster
            .register(
                WorkerRegistration {
                    node_id: "node-a".to_string(),
                    arch: "x86_64".to_string(),
                    tags: vec!["fmt".to_string()],
                    max_slots: 1,
                    ram_total_mb: 32768,
                    btrfs_enabled: true,
                    toolchains: vec!["system".to_string()],
                },
                tx_x86,
            )
            .await;

        let (tx_rv, _rx_rv) = mpsc::channel(8);
        cluster
            .register(
                WorkerRegistration {
                    node_id: "worker-riscv64".to_string(),
                    arch: "riscv64".to_string(),
                    tags: vec!["k3".to_string()],
                    max_slots: 1,
                    ram_total_mb: 32768,
                    btrfs_enabled: false,
                    toolchains: vec!["system".to_string()],
                },
                tx_rv,
            )
            .await;

        // Enqueue 3 jobs in order: job-1 (oldest), job-2, job-3 (newest)
        let t0 = Utc::now() - chrono::Duration::seconds(300);
        for (idx, repo) in ["LMA1980/repo-1", "LMA1980/repo-2", "LMA1980/repo-3"]
            .iter()
            .enumerate()
        {
            let job = Job {
                id: format!("job-{}", idx + 1),
                event_type: "push".to_string(),
                repo_name: (*repo).to_string(),
                clone_url: String::new(),
                commit_sha: format!("sha{}", idx + 1),
                ref_name: "refs/heads/main".to_string(),
                sender: "LMA1980".to_string(),
                queued_at: t0 + chrono::Duration::seconds((idx as i64) * 10),
            };
            store
                .enqueue_job(job, PathBuf::from(format!("logs/{}.log", idx + 1)))
                .await;
        }

        // 1. job-1 is claimed first and completes its `fmt-check` stage on `node-a`,
        //    and now has `test-check` (tag: k3) running on `worker-riscv64`.
        let c1 = store
            .claim_next_queued_job_for_cluster(3, Some(&cluster))
            .await
            .unwrap();
        assert_eq!(c1.id, "job-1");
        let _ = cluster
            .lease_slot("job-1", "test-check", &["k3".to_string()], None, true)
            .await
            .expect("lease k3 slot for job-1");
        store
            .set_stages(
                "job-1",
                vec![
                    StageRecord {
                        id: "fmt-check".to_string(),
                        name: "Fmt".to_string(),
                        tags: vec!["fmt".to_string()],
                        threads: 2,
                        toolchain: None,
                        depends_on: vec![],
                        status: StageStatus::Completed {
                            duration_secs: 2,
                            exit_code: 0,
                        },
                        assigned_node: Some("node-a".to_string()),
                        exclusive: false,
                    },
                    StageRecord {
                        id: "test-check".to_string(),
                        name: "Test".to_string(),
                        tags: vec!["k3".to_string()],
                        threads: 6,
                        toolchain: None,
                        depends_on: vec!["fmt-check".to_string()],
                        status: StageStatus::Running {
                            node_id: "worker-riscv64".to_string(),
                            started_at: Utc::now(),
                            pid: Some(1234),
                        },
                        assigned_node: Some("worker-riscv64".to_string()),
                        exclusive: true,
                    },
                ],
            )
            .await;

        // 2. job-2 is claimed next, completes its "food sample" `fmt-check` on `node-a`,
        //    and its next ready stage `test-check` requires `k3` (which is busy with job-1!).
        let c2 = store
            .claim_next_queued_job_for_cluster(3, Some(&cluster))
            .await
            .unwrap();
        assert_eq!(c2.id, "job-2");
        store
            .set_stages(
                "job-2",
                vec![
                    StageRecord {
                        id: "fmt-check".to_string(),
                        name: "Fmt".to_string(),
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
                        id: "test-check".to_string(),
                        name: "Test".to_string(),
                        tags: vec!["k3".to_string()],
                        threads: 6,
                        toolchain: None,
                        depends_on: vec!["fmt-check".to_string()],
                        status: StageStatus::Pending,
                        assigned_node: None,
                        exclusive: true,
                    },
                ],
            )
            .await;

        // Because job-2 has zero active stages and `worker-riscv64` is busy, it re-queues preserving priority!
        assert!(store.requeue_preserving_priority("job-2").await);

        // Verify job-2 is back at position #1 in the queue (ahead of job-3 at position #2)
        // and still retains its completed `fmt-check` stage!
        assert_eq!(store.job_queue_position("job-2").await, Some(1));
        assert_eq!(store.job_queue_position("job-3").await, Some(2));
        let j2_rec = store.get_job("job-2").await.unwrap();
        assert_eq!(j2_rec.job.queued_at, t0 + chrono::Duration::seconds(10));
        assert!(matches!(
            j2_rec.stages[0].status,
            StageStatus::Completed { exit_code: 0, .. }
        ));

        // 3. Now when the scheduler claims the next job for the cluster while `worker-riscv64` is still busy:
        //    job-2 (#1) only needs `k3` (busy), so the scheduler skips job-2 (leaving it at #1!)
        //    and claims job-3 (#2) so job-3 can get its "food sample" on `node-a`!
        let c3 = store
            .claim_next_queued_job_for_cluster(3, Some(&cluster))
            .await
            .unwrap();
        assert_eq!(c3.id, "job-3");
        assert_eq!(store.job_queue_position("job-2").await, Some(1));

        // 4. Once `worker-riscv64` finishes job-1's stage and releases its slot,
        //    job-2 (at position #1) is immediately claimed to run its remaining `k3` stage!
        cluster
            .release_stage_slot("worker-riscv64", "job-1", "test-check")
            .await;
        let c2_resumed = store
            .claim_next_queued_job_for_cluster(3, Some(&cluster))
            .await
            .unwrap();
        assert_eq!(c2_resumed.id, "job-2");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_no_overclaiming_when_multiple_queued_jobs_await_single_worker_slot() {
        use action_runner_ipc::WorkerRegistration;
        use tokio::sync::mpsc;

        let store = JobStore::new(10, None);
        let cluster = crate::cluster::ClusterRegistry::new();

        let (tx, _rx) = mpsc::channel(8);
        cluster
            .register(
                WorkerRegistration {
                    node_id: "worker-riscv64".to_string(),
                    arch: "riscv64".to_string(),
                    tags: vec!["k3".to_string()],
                    max_slots: 1,
                    ram_total_mb: 32768,
                    btrfs_enabled: false,
                    toolchains: vec!["system".to_string()],
                },
                tx,
            )
            .await;

        let t0 = Utc::now() - chrono::Duration::seconds(300);
        for idx in 1..=3 {
            let job = Job {
                id: format!("job-{}", idx),
                event_type: "push".to_string(),
                repo_name: format!("LMA1980/repo-{}", idx),
                clone_url: String::new(),
                commit_sha: format!("sha{}", idx),
                ref_name: "refs/heads/main".to_string(),
                sender: "LMA1980".to_string(),
                queued_at: t0 + chrono::Duration::seconds((idx as i64) * 10),
            };
            store
                .enqueue_job(job, PathBuf::from(format!("logs/{}.log", idx)))
                .await;

            store
                .set_stages(
                    &format!("job-{}", idx),
                    vec![
                        StageRecord {
                            id: "fmt-check".to_string(),
                            name: "Format".to_string(),
                            tags: vec!["fmt".to_string()],
                            threads: 2,
                            toolchain: None,
                            depends_on: vec![],
                            status: StageStatus::Completed {
                                duration_secs: 1,
                                exit_code: 0,
                            },
                            assigned_node: Some("node-x".to_string()),
                            exclusive: false,
                        },
                        StageRecord {
                            id: "test-check".to_string(),
                            name: "Test".to_string(),
                            tags: vec!["k3".to_string()],
                            threads: 4,
                            toolchain: None,
                            depends_on: vec!["fmt-check".to_string()],
                            status: StageStatus::Pending,
                            assigned_node: None,
                            exclusive: true,
                        },
                    ],
                )
                .await;
        }

        // Before execute_job calls lease_slot, calling claim_next_queued_job_for_cluster in a loop:
        let c1 = store
            .claim_next_queued_job_for_cluster(3, Some(&cluster))
            .await;
        assert!(c1.is_some());
        assert_eq!(c1.unwrap().id, "job-1");

        // Second call must return None because worker-riscv64 has a pending exclusive claim for job-1
        let c2 = store
            .claim_next_queued_job_for_cluster(3, Some(&cluster))
            .await;
        assert!(
            c2.is_none(),
            "Must not over-claim slot for job-2 while job-1 has pending claim"
        );

        // Third call must also return None
        let c3 = store
            .claim_next_queued_job_for_cluster(3, Some(&cluster))
            .await;
        assert!(c3.is_none());

        // Verify job-2 and job-3 remain Queued
        assert_eq!(store.job_queue_position("job-2").await, Some(1));
        assert_eq!(store.job_queue_position("job-3").await, Some(2));
        let j2 = store.get_job("job-2").await.unwrap();
        assert!(matches!(j2.status, JobStatus::Queued));
        let j3 = store.get_job("job-3").await.unwrap();
        assert!(matches!(j3.status, JobStatus::Queued));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_exclusive_stage_blocks_claim_until_worker_drains() {
        use action_runner_ipc::WorkerRegistration;
        use tokio::sync::mpsc;

        let store = JobStore::new(10, None);
        let cluster = crate::cluster::ClusterRegistry::new();

        let (tx, _rx) = mpsc::channel(8);
        cluster
            .register(
                WorkerRegistration {
                    node_id: "worker-dual".to_string(),
                    arch: "x86_64".to_string(),
                    tags: vec!["ci".to_string()],
                    max_slots: 2,
                    ram_total_mb: 32768,
                    btrfs_enabled: false,
                    toolchains: vec!["system".to_string()],
                },
                tx,
            )
            .await;

        // Lease 1 shared stage on worker-dual (leased_stages.len() == 1)
        let lease = cluster
            .lease_slot(
                "job-shared",
                "shared-stage",
                &["ci".to_string()],
                None,
                false,
            )
            .await;
        assert!(lease.is_some());
        assert_eq!(lease.unwrap().0, "worker-dual");

        // Enqueue a job whose only ready stage has exclusive: true
        let job = Job {
            id: "job-exclusive".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/exclusive-repo".to_string(),
            clone_url: String::new(),
            commit_sha: "abcd".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now(),
        };
        store
            .enqueue_job(job, PathBuf::from("logs/exclusive.log"))
            .await;

        store
            .set_stages(
                "job-exclusive",
                vec![StageRecord {
                    id: "exclusive-stage".to_string(),
                    name: "Exclusive Stage".to_string(),
                    tags: vec!["ci".to_string()],
                    threads: 2,
                    toolchain: None,
                    depends_on: vec![],
                    status: StageStatus::Pending,
                    assigned_node: None,
                    exclusive: true,
                }],
            )
            .await;

        // Calling claim_next_queued_job_for_cluster must return None because worker has 1 active leased stage
        let claim_attempt = store
            .claim_next_queued_job_for_cluster(3, Some(&cluster))
            .await;
        assert!(
            claim_attempt.is_none(),
            "Exclusive stage must not be claimed until worker drains all active leases"
        );

        // Worker drains: release the active shared stage slot
        cluster
            .release_stage_slot("worker-dual", "job-shared", "shared-stage")
            .await;

        // Now job-exclusive can be claimed!
        let claim_success = store
            .claim_next_queued_job_for_cluster(3, Some(&cluster))
            .await;
        assert!(claim_success.is_some());
        assert_eq!(claim_success.unwrap().id, "job-exclusive");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_update_stage_running_bumps_updated_at_and_promotes_queued() {
        let store = JobStore::new(10, None);
        let job = Job {
            id: "job-stage-run-1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/ActionRunner-controller".to_string(),
            clone_url: "https://github.com/LMA1980/ActionRunner-controller.git".to_string(),
            commit_sha: "11112222333344445555".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now() - chrono::Duration::seconds(30),
        };
        store
            .enqueue_job(job.clone(), PathBuf::from("logs/test.log"))
            .await;

        let stage = StageRecord {
            id: "stage-build".to_string(),
            name: "Build".to_string(),
            tags: vec!["k3".to_string()],
            threads: 4,
            toolchain: None,
            depends_on: vec![],
            status: StageStatus::Pending,
            assigned_node: None,
            exclusive: false,
        };
        store.set_stages(&job.id, vec![stage]).await;

        let initial_rec = store.get_job(&job.id).await.expect("job exists");
        assert_eq!(initial_rec.status, JobStatus::Queued);
        let initial_updated_at = initial_rec.updated_at;

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        store
            .update_stage_running(&job.id, "stage-build", "node-worker-1", 4321)
            .await;

        let updated_rec = store.get_job(&job.id).await.expect("job exists");
        assert!(
            updated_rec.updated_at > initial_updated_at,
            "record.updated_at must be bumped when stage transitions to running"
        );
        assert!(
            matches!(updated_rec.status, JobStatus::Running { .. }),
            "Queued job must be promoted to Running when stage transitions to running"
        );
        match &updated_rec.stages[0].status {
            StageStatus::Running {
                node_id,
                pid,
                started_at,
            } => {
                assert_eq!(node_id, "node-worker-1");
                assert_eq!(*pid, Some(4321));
                assert!(*started_at >= initial_updated_at);
            }
            other => panic!("expected StageStatus::Running, got {:?}", other),
        }
        assert_eq!(
            updated_rec.stages[0].assigned_node.as_deref(),
            Some("node-worker-1")
        );

        let db_rec = store.storage().get_job(&job.id).expect("in storage");
        assert!(matches!(db_rec.status, JobStatus::Running { .. }));
        assert_eq!(db_rec.updated_at, updated_rec.updated_at);
        match &db_rec.stages[0].status {
            StageStatus::Running { pid, node_id, .. } => {
                assert_eq!(node_id, "node-worker-1");
                assert_eq!(*pid, Some(4321));
            }
            other => panic!("expected StageStatus::Running in db, got {:?}", other),
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_leader_rehydrate_from_storage_never_clobbers_inflight_or_requeued_state() {
        let store = JobStore::new(10, None);
        assert!(store.is_leader());

        // 1. Enqueue job-1 and transition its stage to running with PID
        let job1 = Job {
            id: "job-leader-inflight-1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/ActionRunner-controller".to_string(),
            clone_url: "https://github.com/LMA1980/ActionRunner-controller.git".to_string(),
            commit_sha: "aaaa1111bbbb2222cccc".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now() - chrono::Duration::seconds(60),
        };
        store
            .enqueue_job(job1.clone(), PathBuf::from("logs/job1.log"))
            .await;
        store
            .set_stages(
                "job-leader-inflight-1",
                vec![StageRecord {
                    id: "stage-compile".to_string(),
                    name: "Compile".to_string(),
                    tags: vec!["k3".to_string()],
                    threads: 4,
                    toolchain: None,
                    depends_on: vec![],
                    status: StageStatus::Pending,
                    assigned_node: None,
                    exclusive: false,
                }],
            )
            .await;
        store
            .update_stage_running("job-leader-inflight-1", "stage-compile", "worker-a", 9999)
            .await;

        let j1_local = store.get_job("job-leader-inflight-1").await.unwrap();
        assert!(matches!(j1_local.status, JobStatus::Running { .. }));
        assert_eq!(
            j1_local.stages[0].status,
            StageStatus::Running {
                node_id: "worker-a".to_string(),
                started_at: match j1_local.stages[0].status {
                    StageStatus::Running { started_at, .. } => started_at,
                    _ => unreachable!(),
                },
                pid: Some(9999),
            }
        );

        // 2. Enqueue job-2 and requeue it preserving priority after stage completion
        let job2 = Job {
            id: "job-leader-requeued-2".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/MuObserve".to_string(),
            clone_url: "https://github.com/LMA1980/MuObserve.git".to_string(),
            commit_sha: "dddd3333eeee4444ffff".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: Utc::now() - chrono::Duration::seconds(45),
        };
        store
            .enqueue_job(job2.clone(), PathBuf::from("logs/job2.log"))
            .await;
        let claimed2 = store.claim_next_queued_job(4).await.expect("claim job2");
        assert_eq!(claimed2.id, "job-leader-requeued-2");
        store
            .set_stages(
                "job-leader-requeued-2",
                vec![
                    StageRecord {
                        id: "stage-lint".to_string(),
                        name: "Lint".to_string(),
                        tags: vec!["k3".to_string()],
                        threads: 2,
                        toolchain: None,
                        depends_on: vec![],
                        status: StageStatus::Completed {
                            duration_secs: 5,
                            exit_code: 0,
                        },
                        assigned_node: Some("worker-b".to_string()),
                        exclusive: false,
                    },
                    StageRecord {
                        id: "stage-bench".to_string(),
                        name: "Bench".to_string(),
                        tags: vec!["k3".to_string()],
                        threads: 6,
                        toolchain: None,
                        depends_on: vec!["stage-lint".to_string()],
                        status: StageStatus::Pending,
                        assigned_node: None,
                        exclusive: false,
                    },
                ],
            )
            .await;
        assert!(
            store
                .requeue_preserving_priority("job-leader-requeued-2")
                .await
        );

        // 3. Simulate stale/concurrent snapshot in ControllerStorage:
        //    - job-1 in storage has EQUAL updated_at but older StageStatus::Pending (no PID) and JobStatus::Queued
        //    - job-2 in storage has fewer completed stages and older status
        let stale_j1 = JobRecord {
            job: j1_local.job.clone(),
            log_file: j1_local.log_file.clone(),
            status: JobStatus::Queued,
            updated_at: j1_local.updated_at, // EQUAL timestamp (Issue #107 core reproduction)
            metrics: None,
            stages: vec![StageRecord {
                id: "stage-compile".to_string(),
                name: "Compile".to_string(),
                tags: vec!["k3".to_string()],
                threads: 4,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Pending, // stale: not running, no PID
                assigned_node: None,
                exclusive: false,
            }],
        };
        store.storage().upsert_record(&stale_j1);

        let stale_j2 = JobRecord {
            job: job2.clone(),
            log_file: PathBuf::from("logs/job2.log"),
            status: JobStatus::Running {
                started_at: Utc::now() - chrono::Duration::seconds(40),
            },
            updated_at: Utc::now() - chrono::Duration::seconds(30),
            metrics: None,
            stages: vec![StageRecord {
                id: "stage-lint".to_string(),
                name: "Lint".to_string(),
                tags: vec!["k3".to_string()],
                threads: 2,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Pending, // stale: not completed
                assigned_node: None,
                exclusive: false,
            }],
        };
        store.storage().upsert_record(&stale_j2);

        // 4. Rehydrate with recover_running = false (leader background or periodic sync)
        let count = store.rehydrate_from_storage(false).await;
        assert!(count >= 2);

        // 5. Verify the leader's in-flight and requeued states were NOT clobbered!
        let j1_after = store.get_job("job-leader-inflight-1").await.unwrap();
        assert!(
            matches!(j1_after.status, JobStatus::Running { .. }),
            "Leader in-flight running job must not be clobbered by stale storage record"
        );
        match &j1_after.stages[0].status {
            StageStatus::Running { node_id, pid, .. } => {
                assert_eq!(node_id, "worker-a");
                assert_eq!(
                    *pid,
                    Some(9999),
                    "Leader stage PID must be preserved against equal-timestamp stale storage"
                );
            }
            other => panic!("expected stage to remain Running, got {:?}", other),
        }

        let j2_after = store.get_job("job-leader-requeued-2").await.unwrap();
        assert_eq!(
            j2_after.status,
            JobStatus::Queued,
            "Leader requeued job must not be clobbered by stale storage status"
        );
        assert_eq!(
            j2_after.stages.len(),
            2,
            "Leader job stages must be preserved"
        );
        assert!(
            matches!(
                j2_after.stages[0].status,
                StageStatus::Completed { exit_code: 0, .. }
            ),
            "Completed stages must be preserved on leader"
        );
    }

    #[test]
    fn test_should_preserve_local_record_rules() {
        let t0 = Utc::now();
        let t1 = t0 + chrono::Duration::seconds(10);

        let make_rec =
            |id: &str, status: JobStatus, updated_at, stages: Vec<StageRecord>| JobRecord {
                job: Job {
                    id: id.to_string(),
                    event_type: "push".to_string(),
                    repo_name: "LMA1980/test".to_string(),
                    clone_url: "https://github.com/LMA1980/test.git".to_string(),
                    commit_sha: "1234".to_string(),
                    ref_name: "refs/heads/main".to_string(),
                    sender: "LMA1980".to_string(),
                    queued_at: t0,
                },
                log_file: PathBuf::from("logs/test.log"),
                status,
                updated_at,
                metrics: None,
                stages,
            };

        // 1. Leader preserves Running job even if remote is newer
        let local_running = make_rec("j1", JobStatus::Running { started_at: t0 }, t0, vec![]);
        let remote_queued_newer = make_rec("j1", JobStatus::Queued, t1, vec![]);
        assert!(should_preserve_local_record(
            true,
            &local_running,
            &remote_queued_newer
        ));

        // 2. Leader preserves Queued job with stages even if remote is newer
        let stage_pending = StageRecord {
            id: "s1".to_string(),
            name: "S1".to_string(),
            tags: vec![],
            threads: 1,
            toolchain: None,
            depends_on: vec![],
            status: StageStatus::Pending,
            assigned_node: None,
            exclusive: false,
        };
        let local_queued_with_stages =
            make_rec("j2", JobStatus::Queued, t0, vec![stage_pending.clone()]);
        let remote_queued_newer_2 = make_rec("j2", JobStatus::Queued, t1, vec![]);
        assert!(should_preserve_local_record(
            true,
            &local_queued_with_stages,
            &remote_queued_newer_2
        ));

        // 3. Leader allows remote overwrite ONLY if remote is newer AND local is Queued AND local has NO stages
        let local_queued_empty = make_rec("j3", JobStatus::Queued, t0, vec![]);
        let remote_newer_empty = make_rec("j3", JobStatus::Queued, t1, vec![]);
        assert!(!should_preserve_local_record(
            true,
            &local_queued_empty,
            &remote_newer_empty
        ));

        // 4. Standby preserves local when updated_at is equal (Issue #107)
        let local_standby = make_rec("j4", JobStatus::Queued, t0, vec![]);
        let remote_same_time = make_rec("j4", JobStatus::Queued, t0, vec![]);
        assert!(should_preserve_local_record(
            false,
            &local_standby,
            &remote_same_time
        ));

        // 5. Standby preserves local when local is Running and remote is Queued
        let local_standby_running =
            make_rec("j5", JobStatus::Running { started_at: t0 }, t0, vec![]);
        let remote_queued = make_rec("j5", JobStatus::Queued, t0, vec![]);
        assert!(should_preserve_local_record(
            false,
            &local_standby_running,
            &remote_queued
        ));

        // 6. Standby preserves local when local has active stage and remote does not
        let stage_running = StageRecord {
            id: "s1".to_string(),
            name: "S1".to_string(),
            tags: vec![],
            threads: 1,
            toolchain: None,
            depends_on: vec![],
            status: StageStatus::Running {
                node_id: "worker-1".to_string(),
                started_at: t0,
                pid: Some(123),
            },
            assigned_node: Some("worker-1".to_string()),
            exclusive: false,
        };
        let local_active_stage = make_rec(
            "j6",
            JobStatus::Running { started_at: t0 },
            t0,
            vec![stage_running],
        );
        let remote_pending_stage = make_rec(
            "j6",
            JobStatus::Running { started_at: t0 },
            t1,
            vec![stage_pending],
        );
        assert!(should_preserve_local_record(
            false,
            &local_active_stage,
            &remote_pending_stage
        ));

        // 7. Standby preserves local when local has more completed stages
        let stage_completed = StageRecord {
            id: "s0".to_string(),
            name: "S0".to_string(),
            tags: vec![],
            threads: 1,
            toolchain: None,
            depends_on: vec![],
            status: StageStatus::Completed {
                duration_secs: 2,
                exit_code: 0,
            },
            assigned_node: Some("worker-1".to_string()),
            exclusive: false,
        };
        let local_completed_more = make_rec(
            "j7",
            JobStatus::Running { started_at: t0 },
            t0,
            vec![stage_completed],
        );
        let remote_completed_fewer =
            make_rec("j7", JobStatus::Running { started_at: t0 }, t1, vec![]);
        assert!(should_preserve_local_record(
            false,
            &local_completed_more,
            &remote_completed_fewer
        ));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_job_with_active_stages_cannot_be_requeued_and_counted_as_running() {
        let store = JobStore::new(10, None);
        let now = Utc::now();

        // 1. Enqueue job-1 and claim it
        let job1 = Job {
            id: "job-active-1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/test-repo".to_string(),
            clone_url: "https://github.com/LMA1980/test-repo.git".to_string(),
            commit_sha: "sha1".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: now,
        };
        store.enqueue_job(job1, PathBuf::from("/tmp/j1.log")).await;

        let claimed1 = store.claim_next_queued_job(2).await;
        assert_eq!(claimed1.map(|j| j.id), Some("job-active-1".to_string()));

        // Assign a stage
        store
            .set_stages(
                "job-active-1",
                vec![StageRecord {
                    id: "stage-1".to_string(),
                    name: "Build".to_string(),
                    tags: vec!["ci".to_string()],
                    threads: 2,
                    toolchain: None,
                    depends_on: vec![],
                    status: StageStatus::Assigned {
                        node_id: "node-1".to_string(),
                        started_at: Utc::now(),
                    },
                    assigned_node: Some("node-1".to_string()),
                    exclusive: false,
                }],
            )
            .await;

        // Verify requeue_preserving_priority returns false because stage is Assigned
        assert!(
            !store.requeue_preserving_priority("job-active-1").await,
            "Requeue must be refused while stage is Assigned"
        );
        let rec1 = store.get_job("job-active-1").await.unwrap();
        assert!(matches!(rec1.status, JobStatus::Running { .. }));

        // Now change stage to Running
        store
            .update_stage_running("job-active-1", "stage-1", "node-1", 42)
            .await;
        assert!(
            !store.requeue_preserving_priority("job-active-1").await,
            "Requeue must be refused while stage is Running"
        );

        // 2. Test self-healing and running_repos counting:
        // Even if job status was somehow Queued while stage is Running,
        // claim_next_queued_job_for_cluster heals it in-place and counts it in running_repos/running_count.
        // Artificially reset job status to Queued while keeping stage Running:
        {
            let mut inner = store.inner.write().await;
            for r in inner.iter_mut() {
                if r.job.id == "job-active-1" {
                    r.status = JobStatus::Queued;
                }
            }
        }

        // Add a second job for the same repository
        let job2 = Job {
            id: "job-active-2".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/test-repo".to_string(),
            clone_url: "https://github.com/LMA1980/test-repo.git".to_string(),
            commit_sha: "sha2".to_string(),
            ref_name: "refs/heads/feat".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: now + chrono::Duration::seconds(5),
        };
        store.enqueue_job(job2, PathBuf::from("/tmp/j2.log")).await;

        // Try to claim with max_concurrent = 2:
        // job-active-1 will be healed to Running, and its repo counted in running_repos.
        // Therefore, job-active-2 (same repo) must NOT be claimed!
        let claimed2 = store.claim_next_queued_job(2).await;
        assert!(
            claimed2.is_none(),
            "Same repo candidate must be blocked because active-stages job counts toward running_repos"
        );

        // Verify job-active-1 was healed in-place to Running
        let healed_rec1 = store.get_job("job-active-1").await.unwrap();
        assert!(matches!(healed_rec1.status, JobStatus::Running { .. }));

        // Also test max_concurrent constraint when an active-stages job is present:
        let job3 = Job {
            id: "job-diff-repo".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/other-repo".to_string(),
            clone_url: "https://github.com/LMA1980/other-repo.git".to_string(),
            commit_sha: "sha3".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: now + chrono::Duration::seconds(10),
        };
        store.enqueue_job(job3, PathBuf::from("/tmp/j3.log")).await;

        // With max_concurrent = 1, running_count is 1 (job-active-1), so job-diff-repo cannot be claimed
        assert!(store.claim_next_queued_job(1).await.is_none());
        // With max_concurrent = 2, job-diff-repo can be claimed
        let claimed3 = store.claim_next_queued_job(2).await;
        assert_eq!(claimed3.map(|j| j.id), Some("job-diff-repo".to_string()));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_update_stage_promotes_queued_job_to_running() {
        let store = JobStore::new(10, None);
        let now = Utc::now();

        // 1. Test update_stage_status with Assigned
        let job1 = Job {
            id: "job-promote-1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/test-promote-1".to_string(),
            clone_url: "https://github.com/LMA1980/test-promote-1.git".to_string(),
            commit_sha: "sha1".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: now,
        };
        store.enqueue_job(job1, PathBuf::from("/tmp/p1.log")).await;
        store
            .set_stages(
                "job-promote-1",
                vec![StageRecord {
                    id: "stage-1".to_string(),
                    name: "Build".to_string(),
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

        // Verify status is currently Queued
        let rec1 = store.get_job("job-promote-1").await.unwrap();
        assert!(matches!(rec1.status, JobStatus::Queued));

        // Update stage status to Assigned
        store
            .update_stage_status(
                "job-promote-1",
                "stage-1",
                StageStatus::Assigned {
                    node_id: "worker-1".to_string(),
                    started_at: Utc::now(),
                },
            )
            .await;

        // Verify job status is automatically promoted to Running
        let promoted1 = store.get_job("job-promote-1").await.unwrap();
        assert!(matches!(promoted1.status, JobStatus::Running { .. }));

        // 2. Test update_stage_running
        let job2 = Job {
            id: "job-promote-2".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/test-promote-2".to_string(),
            clone_url: "https://github.com/LMA1980/test-promote-2.git".to_string(),
            commit_sha: "sha2".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: now,
        };
        store.enqueue_job(job2, PathBuf::from("/tmp/p2.log")).await;
        store
            .set_stages(
                "job-promote-2",
                vec![StageRecord {
                    id: "stage-2".to_string(),
                    name: "Test".to_string(),
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

        let rec2 = store.get_job("job-promote-2").await.unwrap();
        assert!(matches!(rec2.status, JobStatus::Queued));

        // Update stage to Running via update_stage_running
        store
            .update_stage_running("job-promote-2", "stage-2", "worker-1", 1234)
            .await;

        // Verify job status is automatically promoted to Running
        let promoted2 = store.get_job("job-promote-2").await.unwrap();
        assert!(matches!(promoted2.status, JobStatus::Running { .. }));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_in_flight_jobs_prevents_duplicate_concurrent_claims() {
        let store = JobStore::new(10, None);
        let now = Utc::now();

        let job = Job {
            id: "job-flight-1".to_string(),
            event_type: "push".to_string(),
            repo_name: "LMA1980/in-flight-repo".to_string(),
            clone_url: "https://github.com/LMA1980/in-flight-repo.git".to_string(),
            commit_sha: "sha1".to_string(),
            ref_name: "refs/heads/main".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: now,
        };
        store.enqueue_job(job, PathBuf::from("/tmp/f1.log")).await;

        // Initially not in flight
        assert!(!store.is_job_in_flight("job-flight-1"));

        // Claim the job
        let claimed = store.claim_next_queued_job(1).await;
        assert_eq!(claimed.map(|j| j.id), Some("job-flight-1".to_string()));

        // Claimed job is now tracked as in-flight
        assert!(store.is_job_in_flight("job-flight-1"));

        // Even if status is reset to Queued while still marked in-flight:
        {
            let mut inner = store.inner.write().await;
            for r in inner.iter_mut() {
                if r.job.id == "job-flight-1" {
                    r.status = JobStatus::Queued;
                }
            }
        }

        // Attempting to claim again while in-flight skips the job
        let duplicate_claim = store.claim_next_queued_job(5).await;
        assert!(
            duplicate_claim.is_none(),
            "Job in-flight must never be claimed concurrently"
        );

        // When requeued via requeue_preserving_priority, in_flight status is cleared
        // (First restore to Running so requeue succeeds)
        store
            .update_status(
                "job-flight-1",
                JobStatus::Running {
                    started_at: Utc::now(),
                },
            )
            .await;
        // Re-mark in flight
        store.mark_job_in_flight("job-flight-1");
        assert!(store.is_job_in_flight("job-flight-1"));

        assert!(store.requeue_preserving_priority("job-flight-1").await);
        assert!(
            !store.is_job_in_flight("job-flight-1"),
            "In-flight tracking must be released on requeue"
        );

        // Now it can be claimed again
        let reclaimed = store.claim_next_queued_job(1).await;
        assert_eq!(reclaimed.map(|j| j.id), Some("job-flight-1".to_string()));
        assert!(store.is_job_in_flight("job-flight-1"));

        // Completing the job releases in-flight tracking
        store
            .update_status(
                "job-flight-1",
                JobStatus::Completed {
                    exit_code: 0,
                    duration_secs: 10,
                },
            )
            .await;
        assert!(
            !store.is_job_in_flight("job-flight-1"),
            "In-flight tracking must be released on completion"
        );

        // InFlightJobGuard RAII drop test
        {
            let _guard = InFlightJobGuard::new(store.clone(), "job-guard-test".to_string());
            assert!(store.is_job_in_flight("job-guard-test"));
        }
        assert!(
            !store.is_job_in_flight("job-guard-test"),
            "InFlightJobGuard Drop must release in-flight job"
        );
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_fully_completed_stages_cannot_requeue_and_can_be_claimed_for_finalization() {
        let store = JobStore::new(10, None);
        let cluster = crate::cluster::ClusterRegistry::new();
        let now = Utc::now();

        let job = Job {
            id: "job-precomputed-7of7".to_string(),
            event_type: "pull_request".to_string(),
            repo_name: "LMA1980/k3-kernels-rvv".to_string(),
            clone_url: "https://github.com/LMA1980/k3-kernels-rvv.git".to_string(),
            commit_sha: "05a27afc4868d17657a4e16e94178dc1047edb8d".to_string(),
            ref_name: "feat/issue-40-matvec-q5k".to_string(),
            sender: "LMA1980".to_string(),
            queued_at: now,
        };
        store.enqueue_job(job, PathBuf::from("/tmp/7of7.log")).await;

        let claimed = store.claim_next_queued_job(1).await;
        assert_eq!(
            claimed.map(|j| j.id),
            Some("job-precomputed-7of7".to_string())
        );

        store
            .set_stages(
                "job-precomputed-7of7",
                vec![StageRecord {
                    id: "miri-check".to_string(),
                    name: "Verify Safe Execution".to_string(),
                    tags: vec!["k3".to_string()],
                    threads: 6,
                    toolchain: None,
                    depends_on: vec![],
                    status: StageStatus::Completed {
                        exit_code: 0,
                        duration_secs: 168,
                    },
                    assigned_node: Some("worker-riscv64".to_string()),
                    exclusive: false,
                }],
            )
            .await;

        // 1. Requeue must be refused when all stages are already Completed
        assert!(
            !store
                .requeue_preserving_priority("job-precomputed-7of7")
                .await,
            "Job with 100% completed stages must never be re-queued"
        );

        // 2. If a job with 100% completed stages was rehydrated in Queued state,
        // claim_next_queued_job_for_cluster must claim it immediately even with 0 cluster workers
        // so execute_job can finalize it.
        store.release_in_flight_job("job-precomputed-7of7");
        {
            let mut inner = store.inner.write().await;
            for r in inner.iter_mut() {
                if r.job.id == "job-precomputed-7of7" {
                    r.status = JobStatus::Queued;
                }
            }
        }
        let reclaimed = store
            .claim_next_queued_job_for_cluster(1, Some(&cluster))
            .await;
        assert_eq!(
            reclaimed.map(|j| j.id),
            Some("job-precomputed-7of7".to_string()),
            "Pre-computed Queued job with all stages Completed must be claimable without worker slot reservation"
        );

        // 3. Standby rehydration must accept terminal remote record even when local had a running stage
        let local_running_stage = JobRecord {
            job: Job {
                id: "job-standby-1".to_string(),
                event_type: "push".to_string(),
                repo_name: "LMA1980/k3-core".to_string(),
                clone_url: "https://github.com/LMA1980/k3-core.git".to_string(),
                commit_sha: "abcdef".to_string(),
                ref_name: "main".to_string(),
                sender: "LMA1980".to_string(),
                queued_at: now,
            },
            status: JobStatus::Running { started_at: now },
            log_file: PathBuf::from("logs/s1.log"),
            updated_at: now,
            metrics: None,
            stages: vec![StageRecord {
                id: "test".to_string(),
                name: "Test".to_string(),
                tags: vec![],
                threads: 1,
                toolchain: None,
                depends_on: vec![],
                status: StageStatus::Running {
                    node_id: "node-a".to_string(),
                    started_at: now,
                    pid: Some(42),
                },
                assigned_node: Some("node-a".to_string()),
                exclusive: false,
            }],
        };
        let mut remote_completed = local_running_stage.clone();
        remote_completed.status = JobStatus::Completed {
            exit_code: 0,
            duration_secs: 10,
        };
        remote_completed.stages[0].status = StageStatus::Completed {
            exit_code: 0,
            duration_secs: 10,
        };
        assert!(
            !should_preserve_local_record(false, &local_running_stage, &remote_completed),
            "Standby controller must never preserve stale local Running record over terminal remote Completed record"
        );
    }
}
