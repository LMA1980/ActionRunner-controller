//! HTTP handlers for the read-only console API:
//!
//! - `GET /api/repos`
//! - `GET /api/repos/{owner}/{repo}/summary`
//! - `GET /api/repos/{owner}/{repo}/topology`
//!
//! Private (and not-yet-classified) repositories are only returned to requests that
//! present the controller API key (`ACTION_RUNNER_LOG_API_KEY`) as
//! `Authorization: Bearer <key>` or `X-Api-Key: <key>`. Anonymous requests for a
//! private repository get the same `404` as an unknown repository.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::{
    current_stage, job_state, parse_bench_ns, repo_key, stage_state, JobState, ParentRef, PrState,
    RepoEntry, RepoStatus, StageState, Station, SubmoduleRef, Visibility,
};
use crate::config::{is_safe_repo_name, Config};
use crate::job::{extract_submodule_job, normalize_ref, JobRecord, JobStatus, JobStore};
use crate::webhook::AppState;

type HmacSha256 = Hmac<Sha256>;
static INVITE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Maximum number of points in the summary sparkline.
const HISTORY_LIMIT: usize = 20;

// ============================================================================
// Authentication & HMAC Invite Tokens (#95, #96)
// ============================================================================

/// Resolved operator authentication tier (`#95`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResolution {
    /// Request presents a valid `Authorization: Bearer <log_api_key>` or `X-Api-Key: <log_api_key>`.
    AdminApiKey,
    /// Request presents a valid `X-Proxy-Secret` + `X-Forwarded-User` whose login is active and `revoked == 0`.
    BoundUser { github_login: String, role: String },
    /// Request presents a valid `X-Proxy-Secret` + `X-Forwarded-User`, but the login is not bound or is revoked.
    UninvitedUser { github_login: String },
    /// Request has no valid API key and no valid `X-Proxy-Secret` + `X-Forwarded-User`.
    Anonymous,
}

impl AuthResolution {
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        matches!(self, Self::AdminApiKey | Self::BoundUser { .. })
    }

    #[must_use]
    pub fn is_admin(&self) -> bool {
        match self {
            Self::AdminApiKey => true,
            Self::BoundUser { role, .. } => role == "admin" || role == "platform-admin",
            Self::UninvitedUser { .. } | Self::Anonymous => false,
        }
    }
}

/// `true` when the request presents the configured controller API key. With no key
/// configured nobody is authenticated (fail closed).
#[must_use]
pub fn is_authenticated(config: &Config, headers: &HeaderMap) -> bool {
    let Some(required) = config.log_api_key.as_deref() else {
        return false;
    };
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let api_key = headers.get("x-api-key").and_then(|h| h.to_str().ok());
    [bearer, api_key]
        .into_iter()
        .flatten()
        .any(|presented| constant_time_eq(presented.trim().as_bytes(), required.as_bytes()))
}

/// Resolves operator identity across `AdminApiKey`, `BoundUser`, `UninvitedUser`, and `Anonymous` (`#95`).
#[must_use]
pub fn resolve_auth(config: &Config, job_store: &JobStore, headers: &HeaderMap) -> AuthResolution {
    resolve_auth_with_query_key(config, job_store, headers, None)
}

/// Resolves operator identity, optionally accepting a query-string API key for SSE streams (`#95`, `#176`).
#[must_use]
pub fn resolve_auth_with_query_key(
    config: &Config,
    job_store: &JobStore,
    headers: &HeaderMap,
    query_key: Option<&str>,
) -> AuthResolution {
    let eval =
        super::platform_auth::EvaluatedRequestAuth::evaluate(config, job_store, headers, query_key);
    if eval.is_admin_api_key {
        return AuthResolution::AdminApiKey;
    }
    if eval.is_uninvited {
        return AuthResolution::UninvitedUser {
            github_login: eval.login.unwrap_or_default(),
        };
    }
    if eval.invite_bound && !eval.passkey_enrollment_required {
        return AuthResolution::BoundUser {
            github_login: eval.login.unwrap_or_default(),
            role: eval
                .session_dto
                .role
                .unwrap_or_else(|| crate::auth::BASELINE_ROLE_ID.to_string()),
        };
    }
    AuthResolution::Anonymous
}

/// Computes the lowercase hex HMAC-SHA256 over `inv_<invite_id>` using `signing_key` (`#95`).
#[must_use]
pub fn compute_invite_hmac(signing_key: &str, invite_id: &str) -> Option<String> {
    let payload = format!("inv_{invite_id}");
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes()).ok()?;
    mac.update(payload.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Generates a new `(invite_id, token_hmac, invite_token)` tuple signed with `signing_key` (`#95`).
#[must_use]
pub fn generate_invite_token(signing_key: &str) -> Option<(String, String, String)> {
    let seq = INVITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now_nanos = Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(b"muconsole-invite:");
    hasher.update(now_nanos.to_le_bytes());
    hasher.update(seq.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    let digest = hasher.finalize();
    let invite_id = hex::encode(&digest[..12]);
    let token_hmac = compute_invite_hmac(signing_key, &invite_id)?;
    let invite_token = format!("inv_{invite_id}.{token_hmac}");
    Some((invite_id, token_hmac, invite_token))
}

/// Parses `inv_<invite_id>.<hmac_sha256_hex>` into `(invite_id, hmac_sha256_hex)` (`#95`).
#[must_use]
pub fn parse_invite_token(raw_token: &str) -> Option<(&str, &str)> {
    let trimmed = raw_token.trim();
    let (prefix, hmac_hex) = trimmed.split_once('.')?;
    let invite_id = prefix.strip_prefix("inv_")?;
    if invite_id.is_empty() || hmac_hex.is_empty() {
        return None;
    }
    Some((invite_id, hmac_hex))
}

/// Verifies an `inv_<invite_id>.<hmac_sha256_hex>` token against `signing_key` in constant time (`#95`).
#[must_use]
pub fn verify_invite_token<'a>(
    signing_key: &str,
    raw_token: &'a str,
) -> Option<(&'a str, &'a str)> {
    let (invite_id, presented_hmac) = parse_invite_token(raw_token)?;
    let expected_hmac = compute_invite_hmac(signing_key, invite_id)?;
    if constant_time_eq(presented_hmac.as_bytes(), expected_hmac.as_bytes()) {
        Some((invite_id, presented_hmac))
    } else {
        None
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ============================================================================
// JSON model
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RepoListItem {
    pub owner: String,
    pub repo: String,
    /// `null` while visibility is not yet known (only visible to authenticated sessions).
    pub visibility: Option<Visibility>,
    pub default_branch: String,
    pub latest_job_id: Option<String>,
    /// Quality score (`0..=100`) of the latest completed default-branch job.
    pub score: Option<u32>,
    /// Line coverage in percent.
    pub coverage: Option<f64>,
    /// Benchmark change vs. the previous completed default-branch job, in percent
    /// (positive = slower).
    pub bench_delta: Option<f64>,
    pub status: RepoStatus,
    pub submodules: Vec<SubmoduleRef>,
    pub parents: Vec<ParentRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RepoListResponse {
    pub fabric_rev: u64,
    pub authenticated: bool,
    pub repos: Vec<RepoListItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryPoint {
    pub job_id: String,
    pub commit_sha: String,
    pub status: JobState,
    pub score: Option<u32>,
    pub coverage: Option<f64>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubmoduleScore {
    pub path: String,
    pub owner: String,
    pub repo: String,
    pub pinned_sha: Option<String>,
    pub score: Option<u32>,
    pub letter_grade: Option<String>,
    pub coverage: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RepoSummary {
    pub owner: String,
    pub repo: String,
    pub visibility: Option<Visibility>,
    pub default_branch: String,
    pub branch: String,
    pub status: RepoStatus,
    pub latest_job_id: Option<String>,
    pub latest_completed_job_id: Option<String>,
    pub commit_sha: Option<String>,
    pub score: Option<u32>,
    pub letter_grade: Option<String>,
    pub coverage: Option<f64>,
    /// Coverage in basis points (`0..=10_000`).
    pub coverage_bp: Option<u32>,
    pub bench_summary: Option<String>,
    pub bench_delta: Option<f64>,
    pub tests_passed: Option<u32>,
    pub tests_total: Option<u32>,
    pub clippy_warnings: Option<u32>,
    pub advisories_count: Option<u32>,
    pub updated_at: Option<DateTime<Utc>>,
    /// Oldest-first sparkline of completed jobs on `branch`.
    pub history: Vec<HistoryPoint>,
    pub submodules: Vec<SubmoduleScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JobBrief {
    pub job_id: String,
    pub status: JobState,
    pub commit_sha: String,
    pub stage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TopologyBranch {
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub base_ref: String,
    pub fork_stage: Option<String>,
    pub pr_state: PrState,
    pub pr_number: Option<u32>,
    pub head_sha: Option<String>,
    pub last_job: Option<JobBrief>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StageSignal {
    pub station: String,
    pub state: StageState,
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Train {
    pub job_id: String,
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub status: JobState,
    pub commit_sha: String,
    pub stage: Option<String>,
    pub stage_states: Vec<StageSignal>,
    pub node_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StationsSource {
    /// `.actionrunner/ActionRunner.yml` on the default branch.
    Workflow,
    /// Stage list of the repository's most recent job.
    Job,
    /// Controller default pipeline.
    Default,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RepoTopology {
    pub owner: String,
    pub repo: String,
    pub default_branch: String,
    pub fabric_rev: u64,
    pub stations_source: StationsSource,
    pub stations: Vec<Station>,
    pub branches: Vec<TopologyBranch>,
    pub trains: Vec<Train>,
}

#[derive(Debug, Default, Deserialize)]
pub struct SummaryQuery {
    pub branch: Option<String>,
}

// ============================================================================
// Helpers
// ============================================================================

fn json_status<T: Serialize>(status: StatusCode, val: &T) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (
                header::VARY,
                "Authorization, X-Api-Key, X-Proxy-Secret, X-Forwarded-User",
            ),
        ],
        Json(val),
    )
        .into_response()
}

fn json_ok<T: Serialize>(val: &T) -> Response {
    json_status(StatusCode::OK, val)
}

fn not_found(owner: &str, repo: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        Json(serde_json::json!({
            "error": "Repository not found",
            "repository": format!("{owner}/{repo}"),
        })),
    )
        .into_response()
}

/// Every repository the controller knows about: the console registry plus job
/// history (branch snapshots and in-memory jobs). Keyed by lower-case `owner/repo`.
pub async fn known_repo_names(
    job_store: &JobStore,
    entries: &BTreeMap<String, RepoEntry>,
) -> BTreeMap<String, (String, String)> {
    let mut out: BTreeMap<String, (String, String)> = BTreeMap::new();
    for e in entries.values() {
        out.insert(
            repo_key(&e.owner, &e.repo),
            (e.owner.clone(), e.repo.clone()),
        );
    }
    let mut names: BTreeSet<String> = job_store
        .storage()
        .load_branch_snapshots(None, None)
        .into_iter()
        .map(|s| s.repo_name)
        .collect();
    names.extend(
        job_store
            .list_jobs()
            .await
            .into_iter()
            .map(|r| r.job.repo_name),
    );
    for name in names {
        if !is_safe_repo_name(&name) {
            continue;
        }
        if let Some((o, r)) = name.split_once('/') {
            out.entry(repo_key(o, r))
                .or_insert_with(|| (o.to_string(), r.to_string()));
        }
    }
    out
}

fn repo_status(latest: Option<&JobRecord>) -> RepoStatus {
    match latest.map(|r| job_state(&r.status)) {
        Some(JobState::Queued | JobState::Running) => RepoStatus::Running,
        Some(JobState::Passed) => RepoStatus::Passing,
        Some(JobState::Failed) => RepoStatus::Failing,
        Some(JobState::Skipped) | None => RepoStatus::Unknown,
    }
}

fn is_finished(r: &JobRecord) -> bool {
    matches!(
        r.status,
        JobStatus::Completed { .. } | JobStatus::Failed { .. }
    )
}

fn jobs_on<'a>(jobs: &'a [JobRecord], repo_full: &'a str, branch: &'a str) -> Vec<&'a JobRecord> {
    let mut v: Vec<&JobRecord> = jobs
        .iter()
        .filter(|r| {
            r.job.repo_name.eq_ignore_ascii_case(repo_full)
                && normalize_ref(&r.job.ref_name) == branch
        })
        .collect();
    v.sort_by_key(|a| std::cmp::Reverse(a.job.queued_at));
    v
}

fn bench_delta(jobs: &[JobRecord], repo_full: &str, branch: &str) -> Option<f64> {
    let pts: Vec<f64> = jobs_on(jobs, repo_full, branch)
        .into_iter()
        .filter(|r| is_finished(r))
        .filter_map(|r| {
            r.metrics
                .as_ref()
                .and_then(|m| m.benchmark_summary.as_deref())
                .and_then(parse_bench_ns)
        })
        .take(2)
        .collect();
    match pts.as_slice() {
        [cur, prev] if *prev > 0.0 => Some(((cur - prev) / prev * 10_000.0).round() / 100.0),
        _ => None,
    }
}

fn coverage_bp(pct: f64) -> u32 {
    (pct * 100.0).round().clamp(0.0, 10_000.0) as u32
}

fn can_view(entry: Option<&RepoEntry>, authed: bool) -> bool {
    authed || entry.map(RepoEntry::is_public).unwrap_or(false)
}

/// Inverted submodule graph: child key -> parents (only parents the caller may see).
fn parents_index(
    entries: &BTreeMap<String, RepoEntry>,
    authed: bool,
) -> BTreeMap<String, Vec<ParentRef>> {
    let mut idx: BTreeMap<String, Vec<ParentRef>> = BTreeMap::new();
    for parent in entries.values() {
        if !can_view(Some(parent), authed) {
            continue;
        }
        for s in &parent.submodules {
            idx.entry(repo_key(&s.owner, &s.repo))
                .or_default()
                .push(ParentRef {
                    owner: parent.owner.clone(),
                    repo: parent.repo.clone(),
                    path: s.path.clone(),
                });
        }
    }
    idx
}

struct Resolved {
    owner: String,
    repo: String,
    entry: RepoEntry,
}

async fn resolve_visible(
    state: &AppState,
    owner: &str,
    repo: &str,
    authed: bool,
) -> Option<Resolved> {
    let entries = state.console.entries().await;
    let known = known_repo_names(&state.job_store, &entries).await;
    let key = repo_key(owner, repo);
    let (o, r) = known.get(&key).cloned()?;
    let entry = entries
        .get(&key)
        .cloned()
        .unwrap_or_else(|| RepoEntry::new(&o, &r));
    if entry.is_stale(state.console.metadata_ttl()) {
        state.console.schedule_refresh(&o, &r, None);
    }
    if !can_view(Some(&entry), authed) {
        return None;
    }
    Some(Resolved {
        owner: o,
        repo: r,
        entry,
    })
}

// ============================================================================
// Handlers
// ============================================================================

/// `GET /api/repos`
pub async fn list_repos(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let eval = super::platform_auth::EvaluatedRequestAuth::evaluate(
        &state.config,
        &state.job_store,
        &headers,
        None,
    );
    if let Some(denied) = eval.gate_public_read("ci:repos.public.read") {
        return denied;
    }
    let authed = eval.has_policy("ci:repos.private.read");
    let entries = state.console.entries().await;
    let known = known_repo_names(&state.job_store, &entries).await;
    let jobs = state.job_store.list_jobs().await;
    let parents = parents_index(&entries, authed);
    let ttl = state.console.metadata_ttl();

    let mut repos = Vec::new();
    for (key, (owner, repo)) in &known {
        let entry = entries.get(key);
        if entry.map(|e| e.is_stale(ttl)).unwrap_or(true) {
            state.console.schedule_refresh(owner, repo, None);
        }
        if !can_view(entry, authed) {
            continue;
        }
        let default_branch = entry
            .map(|e| e.default_branch().to_string())
            .unwrap_or_else(|| "main".to_string());
        let full = format!("{owner}/{repo}");
        let (active, completed) = state
            .job_store
            .find_card_context(&full, Some(&default_branch))
            .await;
        let metrics = completed.as_ref().and_then(|c| c.metrics.as_ref());
        repos.push(RepoListItem {
            owner: owner.clone(),
            repo: repo.clone(),
            visibility: entry.and_then(|e| e.visibility),
            default_branch: default_branch.clone(),
            latest_job_id: active
                .as_ref()
                .or(completed.as_ref())
                .map(|r| r.job.id.clone()),
            score: metrics.map(|m| m.quality_score),
            coverage: metrics.and_then(|m| m.coverage_pct),
            bench_delta: bench_delta(&jobs, &full, &default_branch),
            status: repo_status(active.as_ref().or(completed.as_ref())),
            submodules: entry.map(|e| e.submodules.clone()).unwrap_or_default(),
            parents: parents.get(key).cloned().unwrap_or_default(),
        });
    }

    json_ok(&RepoListResponse {
        fabric_rev: state.console.fabric_rev().await,
        authenticated: authed,
        repos,
    })
}

/// `GET /api/repos/{owner}/{repo}/summary[?branch=]`
pub async fn repo_summary(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<SummaryQuery>,
) -> Response {
    let eval = super::platform_auth::EvaluatedRequestAuth::evaluate(
        &state.config,
        &state.job_store,
        &headers,
        None,
    );
    if let Some(denied) = eval.gate_public_read("ci:repos.public.read") {
        return denied;
    }
    let authed = eval.has_policy("ci:repos.private.read");
    let Some(res) = resolve_visible(&state, &owner, &repo, authed).await else {
        return not_found(&owner, &repo);
    };
    let full = format!("{}/{}", res.owner, res.repo);
    let default_branch = res.entry.default_branch().to_string();
    let branch = query
        .branch
        .as_deref()
        .map(normalize_ref)
        .filter(|b| !b.is_empty())
        .unwrap_or(&default_branch)
        .to_string();

    let (active, completed) = state
        .job_store
        .find_card_context(&full, Some(&branch))
        .await;
    let jobs = state.job_store.list_jobs().await;
    let metrics = completed.as_ref().and_then(|c| c.metrics.as_ref());

    let mut history: Vec<HistoryPoint> = jobs_on(&jobs, &full, &branch)
        .into_iter()
        .filter(|r| is_finished(r))
        .take(HISTORY_LIMIT)
        .map(|r| HistoryPoint {
            job_id: r.job.id.clone(),
            commit_sha: r.job.commit_sha.clone(),
            status: job_state(&r.status),
            score: r.metrics.as_ref().map(|m| m.quality_score),
            coverage: r.metrics.as_ref().and_then(|m| m.coverage_pct),
            updated_at: r.updated_at,
        })
        .collect();
    history.reverse();

    let submodules = res
        .entry
        .submodules
        .iter()
        .map(|s| {
            let sub = completed
                .as_ref()
                .and_then(|c| extract_submodule_job(c, &s.path));
            let m = sub.as_ref().and_then(|j| j.metrics.as_ref());
            SubmoduleScore {
                path: s.path.clone(),
                owner: s.owner.clone(),
                repo: s.repo.clone(),
                pinned_sha: s.pinned_sha.clone(),
                score: m.map(|m| m.quality_score),
                letter_grade: m.map(|m| m.letter_grade.clone()),
                coverage: m.and_then(|m| m.coverage_pct),
            }
        })
        .collect();

    json_ok(&RepoSummary {
        owner: res.owner.clone(),
        repo: res.repo.clone(),
        visibility: res.entry.visibility,
        default_branch: default_branch.clone(),
        branch: branch.clone(),
        status: repo_status(active.as_ref().or(completed.as_ref())),
        latest_job_id: active
            .as_ref()
            .or(completed.as_ref())
            .map(|r| r.job.id.clone()),
        latest_completed_job_id: completed.as_ref().map(|r| r.job.id.clone()),
        commit_sha: completed.as_ref().map(|r| r.job.commit_sha.clone()),
        score: metrics.map(|m| m.quality_score),
        letter_grade: metrics.map(|m| m.letter_grade.clone()),
        coverage: metrics.and_then(|m| m.coverage_pct),
        coverage_bp: metrics.and_then(|m| m.coverage_pct).map(coverage_bp),
        bench_summary: metrics.and_then(|m| m.benchmark_summary.clone()),
        bench_delta: bench_delta(&jobs, &full, &branch),
        tests_passed: metrics.map(|m| m.tests_passed),
        tests_total: metrics.map(|m| m.tests_total),
        clippy_warnings: metrics.map(|m| m.clippy_warnings),
        advisories_count: metrics.map(|m| m.advisories_count),
        updated_at: completed.as_ref().map(|r| r.updated_at),
        history,
        submodules,
    })
}

fn default_stations() -> Vec<Station> {
    crate::workflow::ActionRunnerWorkflow::from_yaml(crate::scheduler::DEFAULT_WORKFLOW_YAML)
        .map(|wf| {
            wf.stages
                .iter()
                .map(|s| Station {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    depends_on: s.depends_on.clone(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn brief(r: &JobRecord) -> JobBrief {
    JobBrief {
        job_id: r.job.id.clone(),
        status: job_state(&r.status),
        commit_sha: r.job.commit_sha.clone(),
        stage: current_stage(r).map(|s| s.id.clone()),
    }
}

fn train(r: &JobRecord) -> Train {
    let cur = current_stage(r);
    Train {
        job_id: r.job.id.clone(),
        ref_name: normalize_ref(&r.job.ref_name).to_string(),
        status: job_state(&r.status),
        commit_sha: r.job.commit_sha.clone(),
        stage: cur.map(|s| s.id.clone()),
        stage_states: r
            .stages
            .iter()
            .map(|s| StageSignal {
                station: s.id.clone(),
                state: stage_state(&s.status),
                node_id: s.assigned_node.clone().or_else(|| match &s.status {
                    crate::job::StageStatus::Assigned { node_id, .. }
                    | crate::job::StageStatus::Running { node_id, .. } => Some(node_id.clone()),
                    _ => None,
                }),
            })
            .collect(),
        node_id: cur.and_then(|s| match &s.status {
            crate::job::StageStatus::Assigned { node_id, .. }
            | crate::job::StageStatus::Running { node_id, .. } => Some(node_id.clone()),
            _ => s.assigned_node.clone(),
        }),
    }
}

/// `GET /api/repos/{owner}/{repo}/topology`
pub async fn repo_topology(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let eval = super::platform_auth::EvaluatedRequestAuth::evaluate(
        &state.config,
        &state.job_store,
        &headers,
        None,
    );
    if let Some(denied) = eval.gate_public_read("ci:repos.public.read") {
        return denied;
    }
    let authed = eval.has_policy("ci:repos.private.read");
    let Some(res) = resolve_visible(&state, &owner, &repo, authed).await else {
        return not_found(&owner, &repo);
    };
    let full = format!("{}/{}", res.owner, res.repo);
    let default_branch = res.entry.default_branch().to_string();
    let all_jobs = state.job_store.list_jobs().await;
    let mut repo_jobs: Vec<&JobRecord> = all_jobs
        .iter()
        .filter(|r| {
            r.job.repo_name.eq_ignore_ascii_case(&full)
                && !matches!(r.status, JobStatus::Skipped { .. })
        })
        .collect();
    repo_jobs.sort_by_key(|a| std::cmp::Reverse(a.job.queued_at));

    // Stations: workflow definition -> latest job's stage list -> controller default.
    let (stations_source, stations) = match res.entry.stations.clone() {
        Some(st) if !st.is_empty() => (StationsSource::Workflow, st),
        _ => match repo_jobs.iter().find(|r| !r.stages.is_empty()) {
            Some(r) => (
                StationsSource::Job,
                r.stages
                    .iter()
                    .map(|s| Station {
                        id: s.id.clone(),
                        name: s.name.clone(),
                        depends_on: s.depends_on.clone(),
                    })
                    .collect(),
            ),
            None => (StationsSource::Default, default_stations()),
        },
    };

    let latest_on = |branch: &str| {
        repo_jobs
            .iter()
            .find(|r| normalize_ref(&r.job.ref_name) == branch)
            .copied()
    };
    let is_live = |r: &JobRecord| matches!(r.status, JobStatus::Queued | JobStatus::Running { .. });

    // Branches: tracked feat/** and open-PR branches, plus feat/** refs with a live job.
    let mut branches: Vec<TopologyBranch> = res
        .entry
        .branches
        .values()
        .filter(|b| b.is_listed())
        .map(|b| TopologyBranch {
            ref_name: b.ref_name.clone(),
            base_ref: b.base_ref.clone(),
            fork_stage: b.fork_stage.clone(),
            pr_state: b.pr_state,
            pr_number: b.pr_number,
            head_sha: b.head_sha.clone(),
            last_job: latest_on(&b.ref_name).map(brief),
        })
        .collect();
    let mut listed: BTreeSet<String> = branches.iter().map(|b| b.ref_name.clone()).collect();
    for r in &repo_jobs {
        let b = normalize_ref(&r.job.ref_name);
        if b.starts_with("feat/")
            && is_live(r)
            && !listed.contains(b)
            && !res.entry.deleted_branches.contains_key(b)
        {
            listed.insert(b.to_string());
            branches.push(TopologyBranch {
                ref_name: b.to_string(),
                base_ref: default_branch.clone(),
                fork_stage: None,
                pr_state: PrState::None,
                pr_number: None,
                head_sha: Some(r.job.commit_sha.clone()),
                last_job: latest_on(b).map(brief),
            });
        }
    }
    branches.sort_by(|a, b| a.ref_name.cmp(&b.ref_name));

    // Trains: every live job, plus the latest job on the main line and each siding.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut trains = Vec::new();
    for r in repo_jobs.iter().filter(|r| is_live(r)) {
        seen.insert(r.job.id.clone());
        trains.push(train(r));
    }
    for b in std::iter::once(default_branch.as_str()).chain(listed.iter().map(String::as_str)) {
        if let Some(r) = latest_on(b) {
            if seen.insert(r.job.id.clone()) {
                trains.push(train(r));
            }
        }
    }

    json_ok(&RepoTopology {
        owner: res.owner,
        repo: res.repo,
        default_branch,
        fabric_rev: state.console.fabric_rev().await,
        stations_source,
        stations,
        branches,
        trains,
    })
}

// ============================================================================
// Operator Auth & Invite Registry Endpoints (#95, #96, #176)
// ============================================================================

pub use super::platform_auth::{
    auth_session, create_invite, list_invites, redeem_invite, revoke_user, RedeemInviteRequest,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_compare() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn coverage_basis_points() {
        assert_eq!(coverage_bp(87.456), 8746);
        assert_eq!(coverage_bp(150.0), 10_000);
        assert_eq!(coverage_bp(-1.0), 0);
    }

    #[test]
    fn invite_token_generation_and_hmac_verification() {
        let key = "test-signing-key-95";
        let (id, hmac_hex, token) = generate_invite_token(key).expect("generate token");
        assert!(token.starts_with("inv_"));
        assert_eq!(
            verify_invite_token(key, &token),
            Some((id.as_str(), hmac_hex.as_str()))
        );
        assert_eq!(verify_invite_token("wrong-key", &token), None);
        let tampered =
            format!("inv_{id}.0000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(verify_invite_token(key, &tampered), None);
    }

    #[test]
    fn redeem_invite_request_payload_shapes() {
        let req_a: RedeemInviteRequest = serde_json::from_str(r#"{"token": "tok_a"}"#).unwrap();
        assert_eq!(req_a.effective_token(), Some("tok_a"));

        let req_b: RedeemInviteRequest =
            serde_json::from_str(r#"{"invite_token": "tok_b"}"#).unwrap();
        assert_eq!(req_b.effective_token(), Some("tok_b"));

        let req_c: RedeemInviteRequest =
            serde_json::from_str(r#"{"token": "tok_c", "invite_token": "tok_c"}"#).unwrap();
        assert_eq!(req_c.effective_token(), Some("tok_c"));

        let req_d: RedeemInviteRequest = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(req_d.effective_token(), None);
    }
}
