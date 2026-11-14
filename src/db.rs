use chrono::{DateTime, Utc};
use mu_observable_ipc::{CentralBranchSnapshot, CentralJobRecord, CentralSubmoduleSnapshot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{info, warn};

use crate::job::{normalize_ref, Job, JobMetrics, JobRecord, JobStatus};
use crate::storage_backend::{
    compute_next_branch_snapshot, compute_next_submodule_snapshots,
    resolve_direct_repo_from_snapshots, resolve_submodule_from_snapshots, LeaderLease,
};

/// One-time operator invite record persisted in `auth_invites` (`#93`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthInviteRecord {
    pub invite_id: String,
    pub token_hmac: String,
    pub created_by: String,
    pub note: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub used_by_github_login: Option<String>,
    pub used_at: Option<String>,
}

/// Sanitized view of [`AuthInviteRecord`] returned by `GET /api/auth/invites`
/// without raw tokens or HMAC digests (`#96`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthInviteView {
    pub invite_id: String,
    pub created_by: String,
    pub note: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub used_by_github_login: Option<String>,
    pub used_at: Option<String>,
}

impl From<&AuthInviteRecord> for AuthInviteView {
    fn from(r: &AuthInviteRecord) -> Self {
        Self {
            invite_id: r.invite_id.clone(),
            created_by: r.created_by.clone(),
            note: r.note.clone(),
            created_at: r.created_at.clone(),
            expires_at: r.expires_at.clone(),
            used_by_github_login: r.used_by_github_login.clone(),
            used_at: r.used_at.clone(),
        }
    }
}

/// Bound GitHub operator record persisted in `auth_users` (`#93`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthUserRecord {
    pub github_login: String,
    pub role: String,
    pub invited_by: String,
    pub invite_id: Option<String>,
    pub bound_at: String,
    pub revoked: u8,
}

/// Atomic single-use invite redemption error (`#93`, `#95`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedeemInviteError {
    InviteNotFound,
    InvalidSignature,
    InviteAlreadyUsed,
    InviteExpired,
}

fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

type AuthSyncHook = std::sync::Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Default)]
struct InMemoryCatalog {
    jobs: BTreeMap<String, CentralJobRecord>,
    branch_snapshots: BTreeMap<(String, String), CentralBranchSnapshot>,
    submodule_snapshots: BTreeMap<(String, String, String), CentralSubmoduleSnapshot>,
    job_logs: BTreeMap<String, String>,
    leader_lease: Option<LeaderLease>,
    console_registry_json: Option<String>,
    auth_invites: BTreeMap<String, AuthInviteRecord>,
    auth_users: BTreeMap<String, AuthUserRecord>,
    platform_auth: crate::auth::PlatformAuthState,
    auth_state_path: Option<PathBuf>,
    auth_state_hash: Option<[u8; 32]>,
    auth_sync_hook: Option<AuthSyncHook>,
}

/// Pure-Rust in-memory state catalog for test harnesses and log metric extraction
/// following Phase 3 local DuckDB decommissioning (`#45`–`#47`).
#[derive(Default)]
pub struct CatalogStore {
    inner: Mutex<InMemoryCatalog>,
}

/// Backward-compatible type alias for [`CatalogStore`].
pub type Db = CatalogStore;

impl CatalogStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(InMemoryCatalog::default()),
        }
    }

    pub fn upsert_record(&self, record: &JobRecord) {
        let Ok(mut guard) = self.inner.lock() else {
            warn!("CatalogStore mutex poisoned during upsert_record");
            return;
        };
        Self::upsert_record_inner(&mut guard, record);
    }

    pub fn upsert_records_batch(&self, records: &[JobRecord]) {
        let Ok(mut guard) = self.inner.lock() else {
            warn!("CatalogStore mutex poisoned during upsert_records_batch");
            return;
        };
        for rec in records {
            Self::upsert_record_inner(&mut guard, rec);
        }
    }

    fn upsert_record_inner(catalog: &mut InMemoryCatalog, record: &JobRecord) {
        let Some(central) = Self::to_central_job_record(record) else {
            return;
        };
        let repo_key = central.repo_key.clone();
        let branch_key = central.branch_key.clone();

        let existing_branch = catalog
            .branch_snapshots
            .get(&(repo_key.clone(), branch_key.clone()))
            .cloned();

        let next_branch =
            compute_next_branch_snapshot(existing_branch.as_ref(), record, |rk, bk| {
                catalog
                    .jobs
                    .values()
                    .filter(|j| {
                        j.repo_key == rk
                            && j.branch_key == bk
                            && j.status_state != "Skipped"
                            && j.job_id != record.job.id
                    })
                    .max_by_key(|j| (j.queued_at_us, j.updated_at_us))
                    .map(|j| (j.job_id.clone(), j.record_json.clone(), j.queued_at_us))
            });

        if let Some(nb) = next_branch {
            catalog
                .branch_snapshots
                .insert((repo_key.clone(), branch_key.clone()), nb);
        }

        let existing_subs: Vec<CentralSubmoduleSnapshot> = catalog
            .submodule_snapshots
            .iter()
            .filter(|((prk, bk, _), _)| prk == &repo_key && bk == &branch_key)
            .map(|(_, v)| v.clone())
            .collect();

        for next_sub in compute_next_submodule_snapshots(&existing_subs, record) {
            catalog.submodule_snapshots.insert(
                (
                    next_sub.parent_repo_key.clone(),
                    next_sub.branch_key.clone(),
                    next_sub.submodule_key.clone(),
                ),
                next_sub,
            );
        }

        catalog.jobs.insert(central.job_id.clone(), central);
    }

    /// Loads recent jobs ordered newest-first.
    pub fn load_recent_jobs(&self, limit: usize) -> Vec<JobRecord> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };

        let mut records: Vec<&CentralJobRecord> = guard.jobs.values().collect();
        records.sort_by(|a, b| {
            b.queued_at_us
                .cmp(&a.queued_at_us)
                .then_with(|| b.updated_at_us.cmp(&a.updated_at_us))
        });

        records
            .into_iter()
            .take(limit)
            .filter_map(|r| serde_json::from_str::<JobRecord>(&r.record_json).ok())
            .collect()
    }

    /// Loads `branch_snapshots` rows filtered by optional `repo_key` and `branch_key`.
    pub fn load_branch_snapshots(
        &self,
        repo_key: Option<&str>,
        branch_key: Option<&str>,
    ) -> Vec<CentralBranchSnapshot> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };

        let repo_norm = repo_key.map(|r| r.to_ascii_lowercase());
        let branch_norm = branch_key.map(|b| normalize_ref(b).to_ascii_lowercase());

        guard
            .branch_snapshots
            .values()
            .filter(|s| {
                repo_norm.as_ref().map(|r| &s.repo_key == r).unwrap_or(true)
                    && branch_norm
                        .as_ref()
                        .map(|b| &s.branch_key == b)
                        .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    /// Loads `submodule_snapshots` rows filtered by optional `parent_repo_key`, `submodule_key`, and `branch_key`.
    pub fn load_submodule_snapshots(
        &self,
        parent_repo_key: Option<&str>,
        submodule_key: Option<&str>,
        branch_key: Option<&str>,
    ) -> Vec<CentralSubmoduleSnapshot> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };

        let parent_norm = parent_repo_key.map(|p| p.to_ascii_lowercase());
        let sub_norm = submodule_key.map(|s| {
            s.rsplit_once('/')
                .map(|(_, r)| r)
                .unwrap_or(s)
                .to_ascii_lowercase()
        });
        let branch_norm = branch_key.map(|b| normalize_ref(b).to_ascii_lowercase());

        guard
            .submodule_snapshots
            .values()
            .filter(|s| {
                parent_norm
                    .as_ref()
                    .map(|p| &s.parent_repo_key == p)
                    .unwrap_or(true)
                    && sub_norm
                        .as_ref()
                        .map(|sk| &s.submodule_key == sk)
                        .unwrap_or(true)
                    && branch_norm
                        .as_ref()
                        .map(|b| &s.branch_key == b)
                        .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    /// Converts a [`JobRecord`] into a [`CentralJobRecord`].
    pub fn to_central_job_record(record: &JobRecord) -> Option<CentralJobRecord> {
        let record_json = serde_json::to_string(record).ok()?;
        let repo_key = record.job.repo_name.to_ascii_lowercase();
        let branch_key = normalize_ref(&record.job.ref_name).to_ascii_lowercase();
        let queued_at_us = record.job.queued_at.timestamp_micros();
        let updated_at_us = record.updated_at.timestamp_micros();

        let (status_state, exit_code, duration_secs) = match &record.status {
            JobStatus::Queued => ("Queued".to_string(), None, None),
            JobStatus::Running { .. } => ("Running".to_string(), None, None),
            JobStatus::Completed {
                duration_secs,
                exit_code,
            } => (
                "Completed".to_string(),
                Some(*exit_code),
                Some(*duration_secs as i64),
            ),
            JobStatus::Failed { .. } => ("Failed".to_string(), None, None),
            JobStatus::Skipped { .. } => ("Skipped".to_string(), None, None),
        };

        let (
            quality_score,
            letter_grade,
            coverage_pct,
            benchmark_summary,
            tests_passed,
            tests_total,
            advisories_count,
            clippy_warnings,
        ) = match &record.metrics {
            Some(m) => (
                Some(m.quality_score as i32),
                Some(m.letter_grade.clone()),
                m.coverage_pct,
                m.benchmark_summary.clone(),
                Some(m.tests_passed as i32),
                Some(m.tests_total as i32),
                Some(m.advisories_count as i32),
                Some(m.clippy_warnings as i32),
            ),
            None => (None, None, None, None, None, None, None, None),
        };

        Some(CentralJobRecord {
            job_id: record.job.id.clone(),
            event_type: record.job.event_type.clone(),
            repo_name: record.job.repo_name.clone(),
            repo_key,
            clone_url: record.job.clone_url.clone(),
            commit_sha: record.job.commit_sha.clone(),
            ref_name: record.job.ref_name.clone(),
            branch_key,
            sender: record.job.sender.clone(),
            queued_at_us,
            updated_at_us,
            status_state,
            exit_code,
            duration_secs,
            quality_score,
            letter_grade,
            coverage_pct,
            benchmark_summary,
            tests_passed,
            tests_total,
            advisories_count,
            clippy_warnings,
            record_json,
        })
    }

    /// Looks up a single job by ID.
    pub fn get_job(&self, job_id: &str) -> Option<JobRecord> {
        let guard = self.inner.lock().ok()?;
        let rec = guard.jobs.get(job_id)?;
        serde_json::from_str(&rec.record_json).ok()
    }

    /// Finds the latest completed (`Completed` or `Failed`) job for a repository/branch.
    pub fn find_latest_completed(&self, repo: &str, branch: Option<&str>) -> Option<JobRecord> {
        let (_active, completed) = self.find_card_context(repo, branch);
        completed
    }

    /// Finds `(latest_active_or_completed, latest_completed)` for a repository/branch.
    pub fn find_card_context(
        &self,
        repo: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        let branch_snapshots = self.load_branch_snapshots(None, None);
        let sub_snapshots = self.load_submodule_snapshots(None, None, None);

        let (mut direct_active, mut direct_completed) =
            resolve_direct_repo_from_snapshots(&branch_snapshots, repo, branch);
        let (sub_active, sub_completed) =
            resolve_submodule_from_snapshots(&sub_snapshots, &branch_snapshots, None, repo, branch);

        if let (Some(ref mut d_comp), Some(ref s_comp)) = (&mut direct_completed, &sub_completed) {
            if d_comp.metrics.is_none() && s_comp.metrics.is_some() {
                d_comp.metrics = s_comp.metrics.clone();
            }
        }
        if let (Some(ref mut d_act), Some(ref s_act)) = (&mut direct_active, &sub_active) {
            if matches!(
                d_act.status,
                JobStatus::Completed { .. } | JobStatus::Failed { .. }
            ) && d_act.metrics.is_none()
                && s_act.metrics.is_some()
            {
                d_act.metrics = s_act.metrics.clone();
            }
        }

        if direct_active.is_some() || direct_completed.is_some() {
            return (direct_active, direct_completed);
        }
        (sub_active, sub_completed)
    }

    /// Finds the latest completed (`Completed` or `Failed`) job for a specific submodule.
    pub fn find_submodule_completed(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> Option<JobRecord> {
        let (_active, completed) = self.find_submodule_card_context(parent_repo, submodule, branch);
        completed
    }

    /// Finds `(latest_active_or_completed, latest_completed)` for a specific submodule.
    pub fn find_submodule_card_context(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        let branch_snapshots = self.load_branch_snapshots(None, None);
        let sub_snapshots = self.load_submodule_snapshots(None, None, None);
        resolve_submodule_from_snapshots(
            &sub_snapshots,
            &branch_snapshots,
            Some(parent_repo),
            submodule,
            branch,
        )
    }

    /// Appends a log chunk for `job_id` in the in-memory catalog (`#83`).
    pub fn append_job_log(&self, job_id: &str, chunk: &str) {
        if chunk.is_empty() {
            return;
        }
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        guard
            .job_logs
            .entry(job_id.to_string())
            .or_default()
            .push_str(chunk);
    }

    /// Retrieves the full persisted execution log for `job_id` (`#83`, `#84`).
    pub fn get_job_log(&self, job_id: &str) -> Option<String> {
        let guard = self.inner.lock().ok()?;
        guard
            .job_logs
            .get(job_id)
            .cloned()
            .filter(|s| !s.is_empty())
    }

    /// Attempts to acquire or renew the single-leader lease for `holder_id` with `ttl_secs` (`#79`).
    pub fn try_acquire_or_renew_lease(&self, holder_id: &str, ttl_secs: u64, force: bool) -> bool {
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        let now_us = Utc::now().timestamp_micros();
        let ttl_us = (ttl_secs.max(1) as i64).saturating_mul(1_000_000);
        let epoch = match guard.leader_lease {
            None => 1,
            Some(ref lease) if lease.holder_id == holder_id => lease.epoch,
            Some(ref lease) if force || lease.is_expired(now_us) => lease.epoch.saturating_add(1),
            Some(_) => return false,
        };
        guard.leader_lease = Some(LeaderLease {
            holder_id: holder_id.to_string(),
            acquired_at_us: now_us,
            expires_at_us: now_us.saturating_add(ttl_us),
            epoch,
        });
        true
    }

    /// Releases the single-leader lease if held by `holder_id` (`#79`).
    pub fn release_lease(&self, holder_id: &str) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        if let Some(ref mut lease) = guard.leader_lease {
            if lease.holder_id == holder_id {
                lease.expires_at_us = 0;
            }
        }
    }

    /// Returns the current [`LeaderLease`] state, if any (`#79`).
    pub fn get_leader_lease(&self) -> Option<LeaderLease> {
        let guard = self.inner.lock().ok()?;
        guard.leader_lease.clone()
    }

    /// Saves the serialized `ConsoleState` registry JSON (`#82`).
    pub fn save_console_registry(&self, registry_json: &str) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.console_registry_json = Some(registry_json.to_string());
        }
    }

    /// Loads the serialized `ConsoleState` registry JSON (`#82`).
    pub fn load_console_registry(&self) -> Option<String> {
        let guard = self.inner.lock().ok()?;
        guard.console_registry_json.clone()
    }

    fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    fn sync_legacy_mirrors(guard: &mut InMemoryCatalog) {
        guard.auth_users.clear();
        for (k, u) in &guard.platform_auth.users {
            let role = if guard.platform_auth.user_has_platform_admin_binding(k) {
                "admin"
            } else {
                crate::auth::BASELINE_ROLE_ID
            };
            guard.auth_users.insert(
                k.clone(),
                AuthUserRecord {
                    github_login: u.github_login.clone(),
                    role: role.to_string(),
                    invited_by: u.invited_by.clone(),
                    invite_id: u.invite_id.clone(),
                    bound_at: u.bound_at.clone(),
                    revoked: u8::from(u.revoked),
                },
            );
        }
        guard.auth_invites.clear();
        for (k, inv) in &guard.platform_auth.invites {
            guard.auth_invites.insert(
                k.clone(),
                AuthInviteRecord {
                    invite_id: inv.invite_id.clone(),
                    token_hmac: inv.token_hmac.clone(),
                    created_by: inv.created_by.clone(),
                    note: inv.note.clone(),
                    created_at: inv.created_at.clone(),
                    expires_at: inv.expires_at.clone(),
                    used_by_github_login: inv.used_by_github_login.clone(),
                    used_at: inv.used_at.clone(),
                },
            );
        }
    }

    fn sync_auth_from_disk_if_changed(guard: &mut InMemoryCatalog) {
        let Some(ref path) = guard.auth_state_path else {
            return;
        };
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        let hash = Self::sha256_bytes(&bytes);
        if guard.auth_state_hash == Some(hash) {
            return;
        }
        if let Ok(Some(loaded)) = crate::auth::load_auth_state_file(path) {
            guard.platform_auth = loaded;
            guard.auth_state_hash = Some(hash);
            Self::sync_legacy_mirrors(guard);
        }
    }

    fn persist_auth_if_configured(guard: &mut InMemoryCatalog) {
        Self::sync_legacy_mirrors(guard);
        if let Some(ref path) = guard.auth_state_path {
            if let Err(err) = crate::auth::save_auth_state_atomic(path, &guard.platform_auth) {
                warn!(
                    "Failed to persist platform_auth state to {}: {}",
                    path.display(),
                    err
                );
            } else if let Ok(bytes) = std::fs::read(path) {
                guard.auth_state_hash = Some(Self::sha256_bytes(&bytes));
            }
        }
        if let Some(ref hook) = guard.auth_sync_hook {
            if let Ok(json) = serde_json::to_string(&guard.platform_auth) {
                hook(&json);
            }
        }
    }

    /// Configures persistent JSON storage for [`crate::auth::PlatformAuthState`],
    /// loading existing state from disk (or migrating legacy rows) idempotently (`#175`).
    pub fn configure_auth_state_path(&self, path: PathBuf) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        guard.auth_state_path = Some(path.clone());
        match crate::auth::load_auth_state_file(&path) {
            Ok(Some(loaded)) => {
                guard.platform_auth = loaded;
                if let Ok(bytes) = std::fs::read(&path) {
                    guard.auth_state_hash = Some(Self::sha256_bytes(&bytes));
                }
                Self::sync_legacy_mirrors(&mut guard);
            }
            Ok(None) => {
                // Migrate any legacy in-memory users/invites if populated prior to config.
                Self::persist_auth_if_configured(&mut guard);
            }
            Err(err) => {
                warn!(
                    "Failed to load platform auth state from {}: {}",
                    path.display(),
                    err
                );
            }
        }
    }

    /// Registers a replication hook invoked with serialized JSON after each auth mutation.
    pub fn set_auth_sync_hook(&self, hook: std::sync::Arc<dyn Fn(&str) + Send + Sync>) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.auth_sync_hook = Some(hook);
        }
    }

    /// Replaces in-memory `PlatformAuthState` from a remote snapshot JSON if its revision is newer.
    pub fn import_platform_auth_json_if_newer(&self, json: &str) {
        let Ok(mut remote) = serde_json::from_str::<crate::auth::PlatformAuthState>(json) else {
            return;
        };
        remote.reconcile_after_load();
        if let Ok(mut guard) = self.inner.lock() {
            if remote.snapshot_revision > guard.platform_auth.snapshot_revision {
                guard.platform_auth = remote;
                Self::sync_legacy_mirrors(&mut guard);
            }
        }
    }

    /// Exports current `PlatformAuthState` as JSON for HA snapshot sync.
    pub fn export_platform_auth_json(&self) -> Option<String> {
        let mut guard = self.inner.lock().ok()?;
        Self::sync_auth_from_disk_if_changed(&mut guard);
        serde_json::to_string(&guard.platform_auth).ok()
    }

    /// Executes a read-only closure against the synchronized [`crate::auth::PlatformAuthState`].
    pub fn read_platform_auth<R>(
        &self,
        f: impl FnOnce(&crate::auth::PlatformAuthState) -> R,
    ) -> Option<R> {
        let mut guard = self.inner.lock().ok()?;
        Self::sync_auth_from_disk_if_changed(&mut guard);
        Some(f(&guard.platform_auth))
    }

    /// Executes a mutating closure against [`crate::auth::PlatformAuthState`] and persists changes.
    pub fn mutate_platform_auth<R>(
        &self,
        f: impl FnOnce(&mut crate::auth::PlatformAuthState) -> R,
    ) -> Option<R> {
        let mut guard = self.inner.lock().ok()?;
        Self::sync_auth_from_disk_if_changed(&mut guard);
        let out = f(&mut guard.platform_auth);
        Self::persist_auth_if_configured(&mut guard);
        Some(out)
    }

    /// Seeds `config.bootstrap_admins` as `operator` + dormant `platform-admin` idempotently (`#175`).
    pub fn seed_bootstrap_admins(&self, admins: &[String]) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        Self::sync_auth_from_disk_if_changed(&mut guard);
        if guard
            .platform_auth
            .seed_bootstrap_admins(admins, Utc::now())
        {
            Self::persist_auth_if_configured(&mut guard);
        } else {
            Self::sync_legacy_mirrors(&mut guard);
        }
    }

    /// Inserts a newly generated one-time invite into `auth_invites` (`#93`).
    pub fn create_auth_invite(&self, invite: &AuthInviteRecord) {
        if let Ok(mut guard) = self.inner.lock() {
            guard
                .auth_invites
                .insert(invite.invite_id.clone(), invite.clone());
        }
    }

    /// Looks up a single invite by `invite_id` (`#93`).
    pub fn get_auth_invite(&self, invite_id: &str) -> Option<AuthInviteRecord> {
        let guard = self.inner.lock().ok()?;
        guard.auth_invites.get(invite_id).cloned()
    }

    /// Lists all invites in `auth_invites` (`#93`, `#96`).
    pub fn list_auth_invites(&self) -> Vec<AuthInviteRecord> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };
        guard.auth_invites.values().cloned().collect()
    }

    /// Atomically verifies and redeems a single-use invite token, marking `used_by_github_login`
    /// and `used_at`, and upserting the user into `auth_users` with `revoked = 0` (`#93`, `#95`).
    pub fn redeem_auth_invite(
        &self,
        invite_id: &str,
        presented_hmac: &str,
        github_login: &str,
        now: DateTime<Utc>,
    ) -> Result<AuthUserRecord, RedeemInviteError> {
        let Ok(mut guard) = self.inner.lock() else {
            return Err(RedeemInviteError::InviteNotFound);
        };
        let invite = guard
            .auth_invites
            .get_mut(invite_id)
            .ok_or(RedeemInviteError::InviteNotFound)?;

        if !constant_time_eq_bytes(invite.token_hmac.as_bytes(), presented_hmac.as_bytes()) {
            return Err(RedeemInviteError::InvalidSignature);
        }

        if invite.used_at.is_some() || invite.used_by_github_login.is_some() {
            return Err(RedeemInviteError::InviteAlreadyUsed);
        }

        let expires_at = DateTime::parse_from_rfc3339(&invite.expires_at)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|_| RedeemInviteError::InviteExpired)?;
        if expires_at <= now {
            return Err(RedeemInviteError::InviteExpired);
        }

        let login_clean = github_login.trim().to_string();
        let login_key = login_clean.to_ascii_lowercase();
        let now_str = now.to_rfc3339();

        invite.used_by_github_login = Some(login_clean.clone());
        invite.used_at = Some(now_str.clone());

        let invited_by = invite.created_by.clone();
        let inv_id = invite.invite_id.clone();

        let user = AuthUserRecord {
            github_login: login_clean,
            role: "operator".to_string(),
            invited_by,
            invite_id: Some(inv_id),
            bound_at: now_str,
            revoked: 0,
        };
        guard.auth_users.insert(login_key, user.clone());
        Ok(user)
    }

    /// Looks up a user in `auth_users` case-insensitively (`#93`).
    pub fn get_auth_user(&self, github_login: &str) -> Option<AuthUserRecord> {
        let guard = self.inner.lock().ok()?;
        let key = github_login.trim().to_ascii_lowercase();
        guard.auth_users.get(&key).cloned()
    }

    /// Lists all bound/revoked users in `auth_users` (`#93`, `#96`).
    pub fn list_auth_users(&self) -> Vec<AuthUserRecord> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };
        guard.auth_users.values().cloned().collect()
    }

    /// Revokes a user (`revoked = 1`) in `auth_users` (`#93`, `#96`).
    pub fn revoke_auth_user(&self, github_login: &str) -> bool {
        let Ok(mut guard) = self.inner.lock() else {
            return false;
        };
        let key = github_login.trim().to_ascii_lowercase();
        if let Some(user) = guard.auth_users.get_mut(&key) {
            user.revoked = 1;
            true
        } else {
            false
        }
    }

    /// Scans `workspace_dir/logs/<owner>/<repo>/job-*.log` and imports any historical log files
    /// that were previously evicted from `jobs_index.json`, as well as enriching
    /// existing completed/failed records whose `metrics` or `metrics.submodules` were missing.
    pub fn backfill_from_logs_dir(&self, workspace_dir: &Path) -> usize {
        let logs_root = workspace_dir.join("logs");
        if !logs_root.is_dir() {
            return 0;
        }

        let Ok(owners) = std::fs::read_dir(&logs_root) else {
            return 0;
        };

        let mut recovered_records = Vec::new();

        for owner_entry in owners.flatten() {
            let owner_path = owner_entry.path();
            if !owner_path.is_dir() {
                continue;
            }
            let Some(owner_name) = owner_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };

            let Ok(repos) = std::fs::read_dir(&owner_path) else {
                continue;
            };

            for repo_entry in repos.flatten() {
                let repo_path = repo_entry.path();
                if !repo_path.is_dir() {
                    continue;
                }
                let Some(repo_short) = repo_path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let repo_full = format!("{}/{}", owner_name, repo_short);
                let has_gitmodules = workspace_dir
                    .join("repos")
                    .join(&repo_full)
                    .join(".gitmodules")
                    .is_file();

                let Ok(log_files) = std::fs::read_dir(&repo_path) else {
                    continue;
                };

                for log_entry in log_files.flatten() {
                    let log_path = log_entry.path();
                    if log_path.extension().and_then(|e| e.to_str()) != Some("log") {
                        continue;
                    }
                    let Some(job_id) = log_path.file_stem().and_then(|s| s.to_str()) else {
                        continue;
                    };
                    if !job_id.starts_with("job-") {
                        continue;
                    }

                    if let Some(mut existing) = self.get_job(job_id) {
                        let is_terminal = matches!(
                            existing.status,
                            JobStatus::Completed { .. } | JobStatus::Failed { .. }
                        );
                        let needs_metrics = existing.metrics.is_none()
                            || (has_gitmodules
                                && existing
                                    .metrics
                                    .as_ref()
                                    .map(|m| m.submodules.is_empty())
                                    .unwrap_or(true));
                        if is_terminal && needs_metrics {
                            let is_success = matches!(
                                existing.status,
                                JobStatus::Completed { exit_code: 0, .. }
                            );
                            if let Some(extracted) = Self::extract_metrics_from_log_and_workspace(
                                workspace_dir,
                                &repo_full,
                                &log_path,
                                is_success,
                            ) {
                                existing.metrics = Some(extracted);
                                recovered_records.push(existing);
                            }
                        }
                        continue;
                    }

                    if let Some(rec) = Self::reconstruct_record_from_log(
                        &repo_full,
                        job_id,
                        &log_path,
                        workspace_dir,
                    ) {
                        recovered_records.push(rec);
                    }
                }
            }
        }

        if recovered_records.is_empty() {
            return 0;
        }

        recovered_records.sort_by_key(|r| r.job.queued_at);
        let count = recovered_records.len();
        self.upsert_records_batch(&recovered_records);
        info!(
            recovered_count = count,
            "Backfilled and enriched historical job records from workspace log files"
        );
        count
    }

    pub fn extract_metrics_from_log_and_workspace(
        workspace_dir: &Path,
        repo_full: &str,
        log_path: &Path,
        is_success: bool,
    ) -> Option<JobMetrics> {
        let content = std::fs::read_to_string(log_path).ok()?;
        if content.trim().is_empty() {
            return None;
        }
        Some(Self::extract_metrics_from_content_and_workspace(
            workspace_dir,
            repo_full,
            &content,
            is_success,
        ))
    }

    pub fn extract_metrics_from_content_and_workspace(
        workspace_dir: &Path,
        repo_full: &str,
        content: &str,
        is_success: bool,
    ) -> JobMetrics {
        let mut tests_passed = 0u32;
        let mut tests_total = 0u32;
        let mut overall_coverage: Option<f64> = None;
        let mut best_bench_ns: Option<f64> = None;
        let mut per_dir_lines: BTreeMap<String, (u64, u64)> = BTreeMap::new();

        for line in content.lines() {
            let body = if let Some((_, after_stream)) = line.split_once("[stdout] ") {
                after_stream
            } else if let Some((_, after_stream)) = line.split_once("[stderr] ") {
                after_stream
            } else {
                line
            };

            if let Some(idx) = body.find("test result:") {
                let after = &body[idx..];
                let tokens: Vec<&str> = after.split_whitespace().collect();
                for window in tokens.windows(2) {
                    if window[1].starts_with("passed") {
                        if let Ok(n) = window[0].parse::<u32>() {
                            tests_passed += n;
                            tests_total += n;
                        }
                    } else if window[1].starts_with("failed") {
                        if let Ok(n) = window[0].parse::<u32>() {
                            tests_total += n;
                        }
                    }
                }
            }

            let trimmed = body.trim();
            if trimmed.starts_with("TOTAL ") {
                let pcts: Vec<f64> = trimmed
                    .split_whitespace()
                    .filter_map(|tok| tok.strip_suffix('%'))
                    .filter_map(|num| num.parse::<f64>().ok())
                    .collect();
                if let Some(&cov) = pcts.get(2).or_else(|| pcts.first()) {
                    overall_coverage = Some(cov);
                }
            } else if trimmed.contains(".rs ") && trimmed.contains('%') {
                let cols: Vec<&str> = trimmed.split_whitespace().collect();
                if cols.len() >= 10 {
                    if let Some((dir_prefix, _)) = cols[0].split_once('/') {
                        if let (Ok(total_l), Ok(missed_l)) =
                            (cols[7].parse::<u64>(), cols[8].parse::<u64>())
                        {
                            let entry = per_dir_lines
                                .entry(dir_prefix.to_ascii_lowercase())
                                .or_insert((0, 0));
                            entry.0 += total_l;
                            entry.1 += missed_l;
                        }
                    }
                }
            }

            if let Some(b_idx) = body.find("bench:") {
                let after_b = body[b_idx + "bench:".len()..].trim();
                if let Some(first_tok) = after_b.split_whitespace().next() {
                    let clean_num = first_tok.replace(',', "");
                    if let Ok(ns) = clean_num.parse::<f64>() {
                        if ns > 0.0 {
                            best_bench_ns = Some(match best_bench_ns {
                                Some(curr) => curr.min(ns),
                                None => ns,
                            });
                        }
                    }
                }
            }
        }

        let benchmark_summary = best_bench_ns.map(|ns| format!("{:.1} ns/iter", ns));

        let mut submodules = BTreeMap::new();
        let gitmodules_path = workspace_dir
            .join("repos")
            .join(repo_full)
            .join(".gitmodules");
        if let Ok(gm_content) = std::fs::read_to_string(&gitmodules_path) {
            for (sub_name, sub_path) in Self::parse_gitmodules(&gm_content) {
                let path_short = sub_path
                    .rsplit_once('/')
                    .map(|(_, s)| s)
                    .unwrap_or(&sub_path)
                    .to_ascii_lowercase();
                let name_short = sub_name
                    .strip_prefix("k3-")
                    .unwrap_or(&sub_name)
                    .to_ascii_lowercase();

                let sub_cov = per_dir_lines
                    .get(&path_short)
                    .or_else(|| per_dir_lines.get(&name_short))
                    .and_then(|&(tot, missed)| {
                        if tot > 0 {
                            Some(
                                ((tot.saturating_sub(missed) as f64 / tot as f64) * 1000.0).round()
                                    / 10.0,
                            )
                        } else {
                            None
                        }
                    })
                    .or(overall_coverage);

                let sub_score = if is_success { 100 } else { 40 };
                let sub_grade = if is_success {
                    "A+".to_string()
                } else {
                    "F".to_string()
                };

                submodules.insert(
                    sub_name.clone(),
                    crate::job::SubmoduleMetrics {
                        name: sub_name,
                        path: sub_path,
                        quality_score: sub_score,
                        letter_grade: sub_grade,
                        tests_passed: 0,
                        tests_total: 0,
                        coverage_pct: sub_cov,
                        benchmark_summary: benchmark_summary.clone(),
                        clippy_warnings: 0,
                    },
                );
            }
        }

        let quality_score = if is_success { 100 } else { 40 };
        let letter_grade = if is_success {
            "A+".to_string()
        } else {
            "F".to_string()
        };

        JobMetrics {
            quality_score,
            letter_grade,
            coverage_pct: overall_coverage,
            benchmark_summary,
            tests_passed,
            tests_total,
            advisories_count: 0,
            clippy_warnings: 0,
            submodules,
        }
    }

    fn parse_gitmodules(gm_content: &str) -> Vec<(String, String)> {
        let mut result = Vec::new();
        let mut curr_path: Option<String> = None;
        let mut curr_url: Option<String> = None;

        let flush = |p: Option<String>, u: Option<String>, out: &mut Vec<(String, String)>| {
            if let Some(path_val) = p {
                let name = u
                    .and_then(|url_str| {
                        let trimmed = url_str.trim().trim_end_matches(".git");
                        trimmed
                            .rsplit_once('/')
                            .or_else(|| trimmed.rsplit_once(':'))
                            .map(|(_, repo)| repo.to_string())
                    })
                    .unwrap_or_else(|| {
                        path_val
                            .rsplit_once('/')
                            .map(|(_, s)| s.to_string())
                            .unwrap_or_else(|| path_val.clone())
                    });
                out.push((name, path_val));
            }
        };

        for line in gm_content.lines() {
            let t = line.trim();
            if t.starts_with("[submodule ") {
                flush(curr_path.take(), curr_url.take(), &mut result);
            } else if let Some((k, v)) = t.split_once('=') {
                let key = k.trim();
                let val = v.trim().to_string();
                if key == "path" {
                    curr_path = Some(val);
                } else if key == "url" {
                    curr_url = Some(val);
                }
            }
        }
        flush(curr_path.take(), curr_url.take(), &mut result);
        result
    }

    fn reconstruct_record_from_log(
        repo_full: &str,
        job_id: &str,
        log_path: &Path,
        workspace_dir: &Path,
    ) -> Option<JobRecord> {
        let rest = job_id.strip_prefix("job-")?;
        let mut parts = rest.split('-');
        let ts_secs: i64 = parts.next()?.parse().ok()?;
        let sha_short = parts.next().unwrap_or("unknown").to_string();

        let queued_at = DateTime::<Utc>::from_timestamp(ts_secs, 0).unwrap_or_else(Utc::now);
        let mtime_dt = std::fs::metadata(log_path)
            .and_then(|m| m.modified())
            .ok()
            .map(DateTime::<Utc>::from)
            .unwrap_or(queued_at);

        let content = std::fs::read_to_string(log_path).unwrap_or_default();
        if content.trim().is_empty() {
            return None;
        }

        let has_failure = content.contains("Process exited with code")
            || content.contains("Stage failed")
            || content.contains("=== Pipeline Status: FAILED")
            || content.contains("test result: FAILED.")
            || content.contains("error: test failed")
            || content.contains("error: could not compile");

        let mut first_log_ts: Option<DateTime<Utc>> = None;
        let mut last_log_ts: Option<DateTime<Utc>> = None;
        let mut stage_order: Vec<String> = Vec::new();
        let mut stage_info: BTreeMap<String, (String, DateTime<Utc>, DateTime<Utc>)> =
            BTreeMap::new();

        for line in content.lines() {
            if let Some((ts_tok, rest_line)) = line.split_once(" [") {
                if let Ok(parsed_dt) = DateTime::parse_from_rfc3339(ts_tok.trim()) {
                    let dt_utc = parsed_dt.with_timezone(&Utc);
                    if first_log_ts.is_none() {
                        first_log_ts = Some(dt_utc);
                    }
                    last_log_ts = Some(dt_utc);

                    if let Some((node_id, after_node)) = rest_line.split_once("] [") {
                        if let Some((stage_id, _after_stage)) = after_node.split_once(']') {
                            if stage_id != "controller" && !stage_id.is_empty() {
                                if !stage_info.contains_key(stage_id) {
                                    stage_order.push(stage_id.to_string());
                                    stage_info.insert(
                                        stage_id.to_string(),
                                        (node_id.to_string(), dt_utc, dt_utc),
                                    );
                                } else if let Some(entry) = stage_info.get_mut(stage_id) {
                                    entry.2 = dt_utc;
                                }
                            }
                        }
                    }
                }
            }
        }

        let duration_secs = match (first_log_ts, last_log_ts) {
            (Some(f), Some(l)) => (l - f).num_seconds().max(1) as u64,
            _ => (mtime_dt - queued_at).num_seconds().max(1) as u64,
        };

        let stages: Vec<crate::job::StageRecord> = stage_order
            .into_iter()
            .filter_map(|sid| {
                let (node_id, s_first, s_last) = stage_info.remove(&sid)?;
                let st_dur = (s_last - s_first).num_seconds().max(1) as u64;
                Some(crate::job::StageRecord {
                    id: sid.clone(),
                    name: sid,
                    tags: Vec::new(),
                    threads: 1,
                    toolchain: None,
                    depends_on: Vec::new(),
                    status: crate::job::StageStatus::Completed {
                        duration_secs: st_dur,
                        exit_code: 0,
                    },
                    assigned_node: Some(node_id),
                    exclusive: false,
                    skip_if_unavailable: false,
                    skip_reason_code: None,
                    skip_capability: None,
                })
            })
            .collect();

        let (resolved_sha, resolved_ref) =
            Self::resolve_git_commit_and_ref(workspace_dir, repo_full, &sha_short);

        let status = if has_failure {
            JobStatus::Failed {
                error: "Stage failed during execution".to_string(),
            }
        } else {
            JobStatus::Completed {
                duration_secs,
                exit_code: 0,
            }
        };

        let metrics = Some(Self::extract_metrics_from_content_and_workspace(
            workspace_dir,
            repo_full,
            &content,
            !has_failure,
        ));

        let rel_log_file = PathBuf::from("logs")
            .join(repo_full)
            .join(format!("{}.log", job_id));

        Some(JobRecord {
            job: Job {
                id: job_id.to_string(),
                event_type: "push".to_string(),
                repo_name: repo_full.to_string(),
                clone_url: format!("https://github.com/{}.git", repo_full),
                commit_sha: resolved_sha,
                ref_name: resolved_ref,
                sender: "LMA1980".to_string(),
                pr_number: None,
                queued_at,
            },
            status,
            log_file: rel_log_file,
            updated_at: last_log_ts.unwrap_or(mtime_dt),
            metrics,
            stages,
        })
    }

    fn resolve_git_commit_and_ref(
        workspace_dir: &Path,
        repo_full: &str,
        sha_short: &str,
    ) -> (String, String) {
        let repo_dir = workspace_dir.join("repos").join(repo_full);
        if !repo_dir.is_dir() || sha_short == "unknown" {
            return (sha_short.to_string(), "refs/heads/main".to_string());
        }

        let full_sha = std::process::Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args([
                "rev-parse",
                "--verify",
                &format!("{}^{{commit}}", sha_short),
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| sha_short.to_string());

        let branches_out = std::process::Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args(["branch", "-a", "--contains", &full_sha])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();

        let mut candidate_branch: Option<String> = None;
        for line in branches_out.lines() {
            let trimmed = line.trim().trim_start_matches('*').trim();
            if trimmed.is_empty() || trimmed.contains("->") || trimmed.starts_with('(') {
                continue;
            }
            let b = trimmed.strip_prefix("remotes/origin/").unwrap_or(trimmed);
            if b == "main" || b == "master" {
                return (full_sha, format!("refs/heads/{}", b));
            }
            if !b.starts_with("pr/") && candidate_branch.is_none() {
                candidate_branch = Some(format!("refs/heads/{}", b));
            }
        }

        (
            full_sha,
            candidate_branch.unwrap_or_else(|| "refs/heads/main".to_string()),
        )
    }
}
