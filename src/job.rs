use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", content = "details")]
pub enum JobStatus {
    Queued,
    Running { started_at: DateTime<Utc> },
    Completed { duration_secs: u64, exit_code: i32 },
    Failed { error: String },
    Skipped { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub queued_jobs: Vec<QueueItemView>,
    pub stats: QueueStats,
    pub recent_jobs: Vec<JobRecord>,
}

#[derive(Clone)]
pub struct JobStore {
    inner: Arc<RwLock<VecDeque<JobRecord>>>,
    notify: Arc<Notify>,
    max_history: usize,
    index_file: Option<PathBuf>,
}

impl JobStore {
    pub fn new(max_history: usize, workspace_dir: Option<&Path>) -> Self {
        let index_file = workspace_dir.map(|w| w.join("logs").join("jobs_index.json"));
        let mut initial_jobs = VecDeque::with_capacity(max_history);
        let notify = Arc::new(Notify::new());

        if let Some(ref path) = index_file {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Ok(mut jobs) = serde_json::from_str::<VecDeque<JobRecord>>(&content) {
                        let mut has_queued = false;
                        for rec in jobs.iter_mut() {
                            if matches!(rec.status, JobStatus::Running { .. }) {
                                rec.status = JobStatus::Queued;
                                rec.updated_at = Utc::now();
                            }
                            if matches!(rec.status, JobStatus::Queued) {
                                has_queued = true;
                            }
                        }
                        if has_queued {
                            notify.notify_one();
                        }
                        info!(
                            "Restored {} job records from {}",
                            jobs.len(),
                            path.display()
                        );
                        initial_jobs = jobs;
                        while initial_jobs.len() > max_history {
                            initial_jobs.pop_back();
                        }
                    }
                }
            }
        }

        Self {
            inner: Arc::new(RwLock::new(initial_jobs)),
            notify,
            max_history,
            index_file,
        }
    }

    async fn persist(&self) {
        if let Some(ref path) = self.index_file {
            let store = self.inner.read().await;
            if let Some(parent) = path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            if let Ok(json_str) = serde_json::to_string_pretty(&*store) {
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
                            superseded_jobs.push(record.job.id.clone());
                            record.status = JobStatus::Skipped {
                                reason: format!(
                                    "Superseded by pull_request event for commit {} ({})",
                                    sha_short, job.id
                                ),
                            };
                            record.updated_at = now;
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
                    record.updated_at = now;
                }
            }

            // Evict oldest terminal record if at max_history capacity (never evict Queued/Running)
            if store.len() >= self.max_history {
                if let Some(pos) = store.iter().rposition(|r| {
                    !matches!(r.status, JobStatus::Queued | JobStatus::Running { .. })
                }) {
                    store.remove(pos);
                }
            }

            store.push_front(JobRecord {
                job: job.clone(),
                status: JobStatus::Queued,
                log_file,
                updated_at: now,
                metrics: None,
                stages: Vec::new(),
            });

            // Compute 1-based FIFO queue position among all currently Queued jobs
            queue_position = store
                .iter()
                .filter(|r| matches!(r.status, JobStatus::Queued))
                .count();
        }

        self.persist().await;
        self.notify.notify_one();

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
    pub async fn claim_next_queued_job(&self, max_concurrent: usize) -> Option<Job> {
        let claimed = {
            let mut store = self.inner.write().await;
            let now = Utc::now();

            let mut running_count = 0;
            let mut running_repos = std::collections::HashSet::new();

            for r in store.iter() {
                if matches!(r.status, JobStatus::Running { .. }) {
                    running_count += 1;
                    running_repos.insert(r.job.repo_name.clone());
                }
            }

            if running_count >= max_concurrent {
                return None;
            }

            let mut found = None;
            for record in store.iter_mut().rev() {
                if matches!(record.status, JobStatus::Queued)
                    && !running_repos.contains(&record.job.repo_name)
                {
                    record.status = JobStatus::Running { started_at: now };
                    record.updated_at = now;
                    found = Some(record.job.clone());
                    break;
                }
            }
            found
        };

        if claimed.is_some() {
            self.persist().await;
        }
        claimed
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
        let mut queued_records: Vec<JobRecord> = Vec::new();

        for record in store.iter() {
            match &record.status {
                JobStatus::Running { started_at } => {
                    stats.running_jobs += 1;
                    let elapsed = (now - *started_at).num_seconds().max(0) as u64;
                    let wait = (*started_at - record.job.queued_at).num_seconds().max(0) as u64;
                    if active_job.is_none() {
                        active_job = Some(QueueItemView {
                            position: 0,
                            wait_secs: wait,
                            elapsed_secs: Some(elapsed),
                            record: record.clone(),
                        });
                    }
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

        // Order queued jobs in FIFO execution order (oldest first = position 1)
        queued_records.reverse();
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

        let status = if active_job.is_some() || !queued_jobs.is_empty() {
            "busy".to_string()
        } else {
            "idle".to_string()
        };

        let recent_jobs = store.iter().take(50).cloned().collect();

        QueueSnapshot {
            status,
            concurrency: 1,
            queue_depth: queued_jobs.len(),
            active_job,
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
        {
            let mut store = self.inner.write().await;
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                record.metrics = Some(metrics);
                record.updated_at = Utc::now();
            }
        }
        self.persist().await;
    }

    pub async fn update_status(&self, job_id: &str, status: JobStatus) {
        {
            let mut store = self.inner.write().await;
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                record.status = status;
                record.updated_at = Utc::now();
            }
        }
        self.persist().await;
        self.notify.notify_waiters();
    }

    pub async fn set_stages(&self, job_id: &str, stages: Vec<StageRecord>) {
        {
            let mut store = self.inner.write().await;
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                record.stages = stages;
                record.updated_at = Utc::now();
            }
        }
        self.persist().await;
        self.notify.notify_waiters();
    }

    pub async fn update_stage_status(&self, job_id: &str, stage_id: &str, status: StageStatus) {
        {
            let mut store = self.inner.write().await;
            if let Some(record) = store.iter_mut().find(|r| r.job.id == job_id) {
                if let Some(stage) = record.stages.iter_mut().find(|s| s.id == stage_id) {
                    if let StageStatus::Assigned { ref node_id, .. }
                    | StageStatus::Running { ref node_id, .. } = status
                    {
                        stage.assigned_node = Some(node_id.clone());
                    }
                    stage.status = status;
                    record.updated_at = Utc::now();
                }
            }
        }
        self.persist().await;
        self.notify.notify_waiters();
    }

    pub async fn wait_for_event(&self) {
        self.notify.notified().await;
    }

    pub fn notify_event(&self) {
        self.notify.notify_waiters();
    }

    pub async fn get_job(&self, job_id: &str) -> Option<JobRecord> {
        let store = self.inner.read().await;
        store.iter().find(|r| r.job.id == job_id).cloned()
    }

    pub async fn list_jobs(&self) -> Vec<JobRecord> {
        let store = self.inner.read().await;
        store.iter().cloned().collect()
    }

    pub async fn find_latest_job(&self, repo: &str, branch: Option<&str>) -> Option<JobRecord> {
        let store = self.inner.read().await;

        // 1. Direct match on parent repository name
        for record in store.iter() {
            let matches_repo = record.job.repo_name.eq_ignore_ascii_case(repo)
                || record.job.repo_name.ends_with(&format!("/{}", repo));

            if !matches_repo {
                continue;
            }

            if let Some(b) = branch {
                let matches_branch = record.job.ref_name.eq_ignore_ascii_case(b)
                    || record.job.ref_name == format!("refs/heads/{}", b)
                    || record.job.ref_name.ends_with(&format!("/{}", b))
                    || record.job.ref_name == format!("refs/tags/{}", b);

                if matches_branch {
                    return Some(record.clone());
                }
            } else {
                return Some(record.clone());
            }
        }

        // 2. Submodule fallback: if repo targets a submodule (e.g. "LMA1980/k3-core" or "k3-core")
        let clean_target = repo.rsplit_once('/').map(|(_, r)| r).unwrap_or(repo);
        for record in store.iter() {
            if let Some(ref metrics) = record.metrics {
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

                    let is_match = sub_name.eq_ignore_ascii_case(repo)
                        || sub_short.eq_ignore_ascii_case(clean_target)
                        || path_short.eq_ignore_ascii_case(clean_target)
                        || sub_name
                            .replace('-', "_")
                            .eq_ignore_ascii_case(&clean_target.replace('-', "_"));

                    if is_match {
                        let owner = repo.split_once('/').map(|(o, _)| o).unwrap_or("LMA1980");
                        let sub_job = Job {
                            id: format!("{}-{}", record.job.id, sub_short),
                            event_type: record.job.event_type.clone(),
                            repo_name: format!("{}/{}", owner, sub_short),
                            clone_url: String::new(),
                            commit_sha: record.job.commit_sha.clone(),
                            ref_name: record.job.ref_name.clone(),
                            sender: record.job.sender.clone(),
                            queued_at: record.job.queued_at,
                        };
                        return Some(JobRecord {
                            job: sub_job,
                            status: record.status.clone(),
                            log_file: record.log_file.clone(),
                            updated_at: record.updated_at,
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
            }
        }

        None
    }

    pub async fn find_submodule_job(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> Option<JobRecord> {
        let parent_record = self.find_latest_job(parent_repo, branch).await?;
        extract_submodule_job(&parent_record, submodule)
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[tokio::test]
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
}
