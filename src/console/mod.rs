//! Read-only console model for MuConsole: repository registry, submodule graph,
//! branch / pull-request topology, `fabric_rev` and the additive SSE event kinds.
//!
//! All state here is derived from data the controller already receives (GitHub
//! webhooks, job records, cluster membership) plus cached read-only GitHub API
//! lookups of `.gitmodules` and `.actionrunner/ActionRunner.yml` on the default
//! branch. Nothing in this module mutates jobs, stages or cluster leases.

pub mod api;
pub mod github;
pub mod gitmodules;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{debug, info, warn};

use crate::cluster::ClusterRegistry;
use crate::config::{is_safe_repo_name, Config};
use crate::job::{normalize_ref, JobRecord, JobStatus, JobStore, StageRecord, StageStatus};
use crate::workflow::ActionRunnerWorkflow;

use github::{GitHubClient, GitHubError};

const ZERO_SHA: &str = "0000000000000000000000000000000000000000";
/// GitHub truncates `push` payload commit lists at 20 entries.
const PUSH_COMMIT_LIST_CAP: usize = 20;

// ============================================================================
// Public JSON model
// ============================================================================

/// Repository visibility as reported by GitHub. Unknown visibility is treated as
/// private (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
    Internal,
}

impl Visibility {
    /// Reads `repository.visibility` / `repository.private` from a webhook or REST payload.
    #[must_use]
    pub fn from_repository(repo: &Value) -> Option<Self> {
        if let Some(v) = repo.get("visibility").and_then(Value::as_str) {
            return match v {
                "public" => Some(Self::Public),
                "private" => Some(Self::Private),
                "internal" => Some(Self::Internal),
                _ => None,
            };
        }
        repo.get("private").and_then(Value::as_bool).map(|p| {
            if p {
                Self::Private
            } else {
                Self::Public
            }
        })
    }

    fn from_metadata(meta: &github::RepoMetadata) -> Self {
        match meta.visibility.as_deref() {
            Some("public") => Self::Public,
            Some("internal") => Self::Internal,
            Some("private") => Self::Private,
            _ if meta.private => Self::Private,
            _ => Self::Public,
        }
    }
}

/// Overall CI status of a repository's default branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoStatus {
    Unknown,
    Passing,
    Running,
    Failing,
}

/// Pull-request state of a tracked branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PrState {
    #[default]
    None,
    Open,
    Draft,
    Merged,
    Closed,
}

/// Block-signal state of one station for one train.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StageState {
    Pending,
    Running,
    Passed,
    Failed,
    Skipped,
}

/// Job state as seen by the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    Queued,
    Running,
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmoduleRef {
    pub path: String,
    pub owner: String,
    pub repo: String,
    pub pinned_sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentRef {
    pub owner: String,
    pub repo: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Station {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub depends_on: Vec<String>,
}

/// A tracked non-default branch (siding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchEntry {
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub base_ref: String,
    pub fork_stage: Option<String>,
    #[serde(default)]
    pub pr_state: PrState,
    #[serde(default)]
    pub pr_number: Option<u32>,
    #[serde(default)]
    pub head_sha: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl BranchEntry {
    /// Sidings are drawn for `feat/**` branches and for any branch with a pull request.
    fn emits_events(&self) -> bool {
        self.ref_name.starts_with("feat/") || self.pr_number.is_some()
    }

    /// Branches listed in the topology: `feat/**` plus open (or draft) pull requests.
    pub(crate) fn is_listed(&self) -> bool {
        self.ref_name.starts_with("feat/")
            || matches!(self.pr_state, PrState::Open | PrState::Draft)
    }
}

/// Cached per-repository console state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepoEntry {
    pub owner: String,
    pub repo: String,
    #[serde(default)]
    pub visibility: Option<Visibility>,
    #[serde(default)]
    pub default_branch: Option<String>,
    #[serde(default)]
    pub submodules: Vec<SubmoduleRef>,
    /// Ref or SHA the submodule list was resolved at (`None` = never resolved).
    #[serde(default)]
    pub submodules_ref: Option<String>,
    /// Stations from `.actionrunner/ActionRunner.yml` on the default branch.
    #[serde(default)]
    pub stations: Option<Vec<Station>>,
    #[serde(default)]
    pub metadata_refreshed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub branches: BTreeMap<String, BranchEntry>,
    /// Recently deleted refs (kept for a day) so a still-queued job does not
    /// resurrect a deleted siding.
    #[serde(default)]
    pub deleted_branches: BTreeMap<String, DateTime<Utc>>,
}

impl RepoEntry {
    pub(crate) fn new(owner: &str, repo: &str) -> Self {
        Self {
            owner: owner.to_string(),
            repo: repo.to_string(),
            visibility: None,
            default_branch: None,
            submodules: Vec::new(),
            submodules_ref: None,
            stations: None,
            metadata_refreshed_at: None,
            branches: BTreeMap::new(),
            deleted_branches: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn default_branch(&self) -> &str {
        self.default_branch.as_deref().unwrap_or("main")
    }

    #[must_use]
    pub fn is_public(&self) -> bool {
        self.visibility == Some(Visibility::Public)
    }

    pub(crate) fn is_stale(&self, ttl: Duration) -> bool {
        match self.metadata_refreshed_at {
            None => true,
            Some(at) => (Utc::now() - at).to_std().map(|d| d > ttl).unwrap_or(false),
        }
    }
}

/// Lower-cased `owner/repo` map key.
#[must_use]
pub fn repo_key(owner: &str, repo: &str) -> String {
    format!("{owner}/{repo}").to_ascii_lowercase()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Registry {
    #[serde(default)]
    fabric_rev: u64,
    #[serde(default)]
    repos: BTreeMap<String, RepoEntry>,
}

impl Registry {
    fn bump(&mut self) -> u64 {
        self.fabric_rev = self.fabric_rev.saturating_add(1);
        self.fabric_rev
    }
}

// ============================================================================
// SSE events
// ============================================================================

/// Additive SSE kinds published on `/api/events`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleEventKind {
    BranchCreated,
    BranchDeleted,
    PrStateChanged,
    JobStageChanged,
    NodeMembershipChanged,
}

impl ConsoleEventKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BranchCreated => "branch_created",
            Self::BranchDeleted => "branch_deleted",
            Self::PrStateChanged => "pr_state_changed",
            Self::JobStageChanged => "job_stage_changed",
            Self::NodeMembershipChanged => "node_membership_changed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConsoleEvent {
    pub kind: ConsoleEventKind,
    /// `true` when the event may be delivered to anonymous subscribers.
    pub public: bool,
    pub data: Value,
}

// ============================================================================
// Configuration
// ============================================================================

#[derive(Debug, Clone)]
pub struct ConsoleConfig {
    /// GitHub REST base URL; `None` disables API lookups (local clone fallback only).
    pub github_api_url: Option<String>,
    pub github_token: Option<String>,
    /// Controller workspace (`<workspace>/repos/<owner>/<repo>` holds the CI clones).
    pub workspace_dir: Option<PathBuf>,
    /// JSON cache of the registry (survives restarts, keeps `fabric_rev` monotonic).
    pub cache_file: Option<PathBuf>,
    /// How long resolved metadata / submodules stay fresh without a triggering push.
    pub metadata_ttl: Duration,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            github_api_url: None,
            github_token: None,
            workspace_dir: None,
            cache_file: None,
            metadata_ttl: Duration::from_secs(6 * 3600),
        }
    }
}

impl ConsoleConfig {
    /// Builds the production configuration.
    ///
    /// - `ACTION_RUNNER_GITHUB_API_URL` (default `https://api.github.com`, `off` disables)
    /// - `ACTION_RUNNER_CONSOLE_METADATA_TTL_SECS` (default `21600`)
    /// - reuses `GITHUB_TOKEN` from [`Config`].
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        let api = std::env::var("ACTION_RUNNER_GITHUB_API_URL")
            .unwrap_or_else(|_| "https://api.github.com".to_string());
        let github_api_url = if api.trim().eq_ignore_ascii_case("off") || api.trim().is_empty() {
            None
        } else {
            Some(api.trim().to_string())
        };
        let metadata_ttl = std::env::var("ACTION_RUNNER_CONSOLE_METADATA_TTL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(6 * 3600));
        Self {
            github_api_url,
            github_token: config.github_token.clone(),
            workspace_dir: Some(config.workspace_dir.clone()),
            cache_file: Some(default_cache_file(&config.workspace_dir)),
            metadata_ttl,
        }
    }
}

// ============================================================================
// Console state
// ============================================================================

#[derive(Default)]
struct ReconcileState {
    initialized: bool,
    /// `(job_id, stage_id)` -> `(state, node_id)`
    stages: HashMap<(String, String), (StageState, Option<String>)>,
    /// `node_id` -> online
    nodes: HashMap<String, bool>,
}

struct Inner {
    cfg: ConsoleConfig,
    github: Option<GitHubClient>,
    registry: RwLock<Registry>,
    events: broadcast::Sender<ConsoleEvent>,
    refreshing: std::sync::Mutex<HashSet<String>>,
    reconcile: Mutex<ReconcileState>,
    persist_lock: Mutex<()>,
}

/// Shared, cheaply clonable console state.
#[derive(Clone)]
pub struct ConsoleState(Arc<Inner>);

impl Default for ConsoleState {
    fn default() -> Self {
        Self::new(ConsoleConfig::default())
    }
}

impl ConsoleState {
    #[must_use]
    pub fn new(cfg: ConsoleConfig) -> Self {
        let github = cfg.github_api_url.as_deref().and_then(|url| {
            GitHubClient::new(url, cfg.github_token.clone())
                .map_err(|e| warn!(error = %e, "Console GitHub client disabled"))
                .ok()
        });
        let registry = cfg
            .cache_file
            .as_deref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<Registry>(&s).ok())
            .unwrap_or_default();
        let (events, _) = broadcast::channel(1024);
        Self(Arc::new(Inner {
            cfg,
            github,
            registry: RwLock::new(registry),
            events,
            refreshing: std::sync::Mutex::new(HashSet::new()),
            reconcile: Mutex::new(ReconcileState::default()),
            persist_lock: Mutex::new(()),
        }))
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<ConsoleEvent> {
        self.0.events.subscribe()
    }

    pub async fn fabric_rev(&self) -> u64 {
        self.0.registry.read().await.fabric_rev
    }

    pub async fn entry(&self, owner: &str, repo: &str) -> Option<RepoEntry> {
        self.0
            .registry
            .read()
            .await
            .repos
            .get(&repo_key(owner, repo))
            .cloned()
    }

    pub async fn entries(&self) -> BTreeMap<String, RepoEntry> {
        self.0.registry.read().await.repos.clone()
    }

    #[must_use]
    pub fn metadata_ttl(&self) -> Duration {
        self.0.cfg.metadata_ttl
    }

    fn emit(&self, kind: ConsoleEventKind, public: bool, data: Value) {
        let _ = self.0.events.send(ConsoleEvent { kind, public, data });
    }

    async fn persist(&self) {
        let Some(path) = self.0.cfg.cache_file.clone() else {
            return;
        };
        let _guard = self.0.persist_lock.lock().await;
        let body = {
            let reg = self.0.registry.read().await;
            match serde_json::to_string_pretty(&*reg) {
                Ok(s) => s,
                Err(_) => return,
            }
        };
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let tmp = path.with_extension("json.tmp");
        if tokio::fs::write(&tmp, body).await.is_ok() {
            if let Err(e) = tokio::fs::rename(&tmp, &path).await {
                warn!(error = %e, "Failed to persist console registry");
            }
        }
    }

    // ------------------------------------------------------------------
    // Webhook observation
    // ------------------------------------------------------------------

    /// Records repository metadata, branch lifecycle and pull-request state from an
    /// accepted (signature-verified, allow-listed) webhook. Never fails the webhook.
    pub async fn observe_webhook(&self, event: &str, payload: &Value, job_store: &JobStore) {
        let Some(full) = payload
            .pointer("/repository/full_name")
            .and_then(Value::as_str)
        else {
            return;
        };
        if !is_safe_repo_name(full) {
            return;
        }
        let Some((owner, repo)) = full.split_once('/') else {
            return;
        };
        let repo_obj = payload.get("repository").cloned().unwrap_or(Value::Null);
        let visibility = Visibility::from_repository(&repo_obj);
        let payload_default = repo_obj
            .get("default_branch")
            .and_then(Value::as_str)
            .or_else(|| payload.get("master_branch").and_then(Value::as_str))
            .or_else(|| repo_obj.get("master_branch").and_then(Value::as_str))
            .map(str::to_string);

        let jobs = job_store.list_jobs().await;
        let mut pending: Vec<(ConsoleEventKind, Value)> = Vec::new();
        let mut refresh: Option<Option<String>> = None;
        let public;
        let mut changed = false;

        {
            let mut reg = self.0.registry.write().await;
            let entry = reg
                .repos
                .entry(repo_key(owner, repo))
                .or_insert_with(|| RepoEntry::new(owner, repo));
            if visibility.is_some() && entry.visibility != visibility {
                entry.visibility = visibility;
                changed = true;
            }
            if payload_default.is_some() && entry.default_branch != payload_default {
                entry.default_branch = payload_default.clone();
                changed = true;
            }
            let default_branch = entry.default_branch().to_string();
            let fork_stage = main_line_station(&jobs, full, &default_branch);

            match event {
                "create" | "delete" => {
                    let is_branch =
                        payload.get("ref_type").and_then(Value::as_str) == Some("branch");
                    if let (true, Some(r)) = (is_branch, payload.get("ref").and_then(Value::as_str))
                    {
                        let r = normalize_ref(r).to_string();
                        let ev = if event == "create" {
                            branch_created(entry, &r, &default_branch, None, fork_stage, None)
                        } else {
                            branch_deleted(entry, &r)
                        };
                        pending.extend(ev);
                    }
                }
                "push" => {
                    let r = payload.get("ref").and_then(Value::as_str).unwrap_or("");
                    if let Some(branch) = r.strip_prefix("refs/heads/") {
                        let after = payload.get("after").and_then(Value::as_str).unwrap_or("");
                        let deleted = payload
                            .get("deleted")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                            || after == ZERO_SHA;
                        if deleted {
                            pending.extend(branch_deleted(entry, branch));
                        } else if branch == default_branch {
                            if push_touches_topology(payload, &entry.submodules)
                                || entry.submodules_ref.is_none()
                            {
                                refresh = Some(Some(after.to_string()).filter(|s| !s.is_empty()));
                            }
                        } else {
                            let created = payload
                                .get("created")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            let head = Some(after.to_string()).filter(|s| !s.is_empty());
                            if let Some(b) = entry.branches.get_mut(branch) {
                                b.head_sha = head;
                                b.updated_at = Utc::now();
                                changed = true;
                            } else if created || branch.starts_with("feat/") {
                                pending.extend(branch_created(
                                    entry,
                                    branch,
                                    &default_branch,
                                    head,
                                    fork_stage,
                                    None,
                                ));
                            }
                        }
                    }
                }
                "pull_request" => {
                    pending.extend(observe_pull_request(
                        entry,
                        payload,
                        full,
                        &default_branch,
                        fork_stage,
                    ));
                }
                _ => {}
            }

            if refresh.is_none() && entry.is_stale(self.0.cfg.metadata_ttl) {
                refresh = Some(None);
            }
            public = entry.is_public();
            if !pending.is_empty() {
                changed = true;
            }
            for (_, data) in pending.iter_mut() {
                let rev = reg.bump();
                data["fabric_rev"] = json!(rev);
            }
        }

        for (kind, data) in pending {
            debug!(kind = kind.as_str(), "Console event");
            self.emit(kind, public, data);
        }
        if changed {
            self.persist().await;
        }
        if let Some(sha) = refresh {
            self.schedule_refresh(owner, repo, sha);
        }
    }

    // ------------------------------------------------------------------
    // Metadata / submodule refresh
    // ------------------------------------------------------------------

    /// Spawns a deduplicated background refresh of repository metadata, submodules
    /// and workflow stations.
    pub fn schedule_refresh(&self, owner: &str, repo: &str, sha_hint: Option<String>) {
        let key = repo_key(owner, repo);
        {
            let Ok(mut set) = self.0.refreshing.lock() else {
                return;
            };
            if !set.insert(key.clone()) {
                return;
            }
        }
        let this = self.clone();
        let (owner, repo) = (owner.to_string(), repo.to_string());
        tokio::spawn(async move {
            this.refresh_repo(&owner, &repo, sha_hint).await;
            if let Ok(mut set) = this.0.refreshing.lock() {
                set.remove(&key);
            }
        });
    }

    /// Resolves visibility, default branch, `.gitmodules` (with gitlink SHAs) and the
    /// workflow stations, via the GitHub API first and the local CI clone second.
    pub async fn refresh_repo(&self, owner: &str, repo: &str, sha_hint: Option<String>) {
        let key = repo_key(owner, repo);
        let (mut visibility, mut default_branch) = {
            let reg = self.0.registry.read().await;
            reg.repos
                .get(&key)
                .map(|e| (e.visibility, e.default_branch.clone()))
                .unwrap_or((None, None))
        };

        let mut repo_visible_via_api = false;
        if let Some(gh) = self.0.github.as_ref() {
            match gh.get_repo(owner, repo).await {
                Ok(meta) => {
                    visibility = Some(Visibility::from_metadata(&meta));
                    if meta.default_branch.is_some() {
                        default_branch = meta.default_branch.clone();
                    }
                    repo_visible_via_api = true;
                }
                Err(GitHubError::NotFound) => {
                    debug!(repo = %key, "Repository metadata not visible to the API token");
                }
                Err(e) => warn!(repo = %key, error = %e, "Repository metadata lookup failed"),
            }
        }
        let default_ref = default_branch.clone().unwrap_or_else(|| "main".to_string());
        let git_ref = sha_hint.clone().unwrap_or_else(|| default_ref.clone());

        let gitmodules = self
            .fetch_file(
                owner,
                repo,
                ".gitmodules",
                &git_ref,
                &default_ref,
                repo_visible_via_api,
            )
            .await;

        let submodules = match gitmodules {
            Some(Some(content)) => {
                let mut subs = Vec::new();
                for e in gitmodules::parse_gitmodules(&content) {
                    let (sub_owner, sub_repo) = gitmodules::resolve_submodule_repo(
                        &e.url, owner, repo,
                    )
                    .unwrap_or_else(|| {
                        let base = e.path.rsplit('/').next().unwrap_or(&e.path);
                        (owner.to_string(), base.to_string())
                    });
                    let pinned_sha = self
                        .gitlink_sha(owner, repo, &e.path, &git_ref, &default_ref)
                        .await;
                    subs.push(SubmoduleRef {
                        path: e.path,
                        owner: sub_owner,
                        repo: sub_repo,
                        pinned_sha,
                    });
                }
                Some(subs)
            }
            Some(None) => Some(Vec::new()),
            None => None,
        };

        let mut stations: Option<Option<Vec<Station>>> = None;
        for name in ["ActionRunner.yml", "ActionRunner.yaml"] {
            let path = format!(".actionrunner/{name}");
            match self
                .fetch_file(
                    owner,
                    repo,
                    &path,
                    &git_ref,
                    &default_ref,
                    repo_visible_via_api,
                )
                .await
            {
                Some(Some(content)) => {
                    stations = Some(ActionRunnerWorkflow::from_yaml(&content).ok().map(|wf| {
                        wf.stages
                            .iter()
                            .map(|s| Station {
                                id: s.id.clone(),
                                name: s.name.clone(),
                                depends_on: s.depends_on.clone(),
                            })
                            .collect()
                    }));
                    break;
                }
                Some(None) => stations = Some(None),
                None => {}
            }
        }

        {
            let mut reg = self.0.registry.write().await;
            let entry = reg
                .repos
                .entry(key.clone())
                .or_insert_with(|| RepoEntry::new(owner, repo));
            if visibility.is_some() {
                entry.visibility = visibility;
            }
            if default_branch.is_some() {
                entry.default_branch = default_branch;
            }
            let mut graph_changed = false;
            if let Some(subs) = submodules {
                graph_changed = entry.submodules != subs;
                entry.submodules = subs;
                entry.submodules_ref = Some(git_ref.clone());
            }
            if let Some(st) = stations {
                graph_changed |= entry.stations != st;
                entry.stations = st;
            }
            entry.metadata_refreshed_at = Some(Utc::now());
            if graph_changed {
                reg.bump();
            }
        }
        info!(repo = %key, git_ref = %git_ref, "Console repository metadata refreshed");
        self.persist().await;
    }

    /// `Some(Some(content))` = found, `Some(None)` = definitively absent,
    /// `None` = could not determine.
    async fn fetch_file(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        git_ref: &str,
        default_ref: &str,
        repo_visible: bool,
    ) -> Option<Option<String>> {
        if let Some(gh) = self.0.github.as_ref() {
            match gh.get_file(owner, repo, path, git_ref).await {
                Ok(c) => return Some(Some(c)),
                Err(GitHubError::NotFound) if repo_visible => return Some(None),
                Err(_) => {}
            }
        }
        let ws = self.local_clone(owner, repo)?;
        for rev in local_revs(git_ref, default_ref) {
            let out = tokio::process::Command::new("git")
                .arg("-C")
                .arg(&ws)
                .arg("show")
                .arg(format!("{rev}:{path}"))
                .output()
                .await
                .ok()?;
            if out.status.success() {
                return Some(String::from_utf8(out.stdout).ok());
            }
        }
        None
    }

    async fn gitlink_sha(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        git_ref: &str,
        default_ref: &str,
    ) -> Option<String> {
        if let Some(gh) = self.0.github.as_ref() {
            if let Ok(sha) = gh.get_gitlink_sha(owner, repo, path, git_ref).await {
                return Some(sha);
            }
        }
        let ws = self.local_clone(owner, repo)?;
        for rev in local_revs(git_ref, default_ref) {
            let out = tokio::process::Command::new("git")
                .arg("-C")
                .arg(&ws)
                .arg("ls-tree")
                .arg(&rev)
                .arg("--")
                .arg(path)
                .output()
                .await
                .ok()?;
            if out.status.success() {
                if let Some(sha) =
                    gitmodules::parse_ls_tree_gitlink(&String::from_utf8_lossy(&out.stdout))
                {
                    return Some(sha);
                }
            }
        }
        None
    }

    fn local_clone(&self, owner: &str, repo: &str) -> Option<PathBuf> {
        let ws = self.0.cfg.workspace_dir.as_deref()?;
        let p = ws.join("repos").join(owner).join(repo);
        p.join(".git")
            .exists()
            .then_some(p.clone())
            .or_else(|| p.join("HEAD").exists().then_some(p))
    }

    // ------------------------------------------------------------------
    // Job stage / node membership reconciliation
    // ------------------------------------------------------------------

    /// Diffs stage states and cluster membership against the previous pass and emits
    /// `job_stage_changed` / `node_membership_changed`. The first pass only records a
    /// baseline.
    pub async fn reconcile(&self, job_store: &JobStore, cluster: &ClusterRegistry) {
        let jobs = job_store.list_jobs().await;
        let nodes = cluster.list_nodes_view().await;
        let mut rs = self.0.reconcile.lock().await;

        let mut stage_now: HashMap<(String, String), (StageState, Option<String>)> = HashMap::new();
        let mut stage_events: Vec<(String, Value)> = Vec::new();
        for rec in &jobs {
            for st in &rec.stages {
                let state = stage_state(&st.status);
                let node = stage_node(st);
                let key = (rec.job.id.clone(), st.id.clone());
                let prev = rs.stages.get(&key).cloned();
                let prev_state = prev.as_ref().map(|p| p.0).unwrap_or(StageState::Pending);
                let prev_node = prev.and_then(|p| p.1);
                if rs.initialized && (prev_state != state || prev_node != node) {
                    stage_events.push((
                        rec.job.repo_name.clone(),
                        json!({
                            "owner": rec.job.repo_name.split_once('/').map(|(o, _)| o).unwrap_or(""),
                            "repo": rec.job.repo_name.split_once('/').map(|(_, r)| r).unwrap_or(""),
                            "job_id": rec.job.id,
                            "ref": normalize_ref(&rec.job.ref_name),
                            "stage": st.id,
                            "state": state,
                            "previous_state": prev_state,
                            "node_id": node,
                        }),
                    ));
                }
                stage_now.insert(key, (state, node));
            }
        }
        rs.stages = stage_now;

        let mut node_events: Vec<Value> = Vec::new();
        let now_nodes: HashMap<String, bool> = nodes
            .iter()
            .map(|n| (n.node_id.clone(), n.is_online))
            .collect();
        if rs.initialized {
            let online: Vec<&String> = {
                let mut v: Vec<&String> = now_nodes
                    .iter()
                    .filter(|(_, on)| **on)
                    .map(|(id, _)| id)
                    .collect();
                v.sort();
                v
            };
            let mut ids: Vec<&String> = now_nodes.keys().chain(rs.nodes.keys()).collect();
            ids.sort();
            ids.dedup();
            for id in ids {
                let change = match (rs.nodes.get(id), now_nodes.get(id)) {
                    (None, Some(_)) => "joined",
                    (Some(_), None) => "left",
                    (Some(false), Some(true)) => "online",
                    (Some(true), Some(false)) => "offline",
                    _ => continue,
                };
                node_events.push(json!({
                    "node_id": id,
                    "change": change,
                    "online_nodes": online,
                }));
            }
        }
        rs.nodes = now_nodes;
        rs.initialized = true;
        drop(rs);

        if stage_events.is_empty() && node_events.is_empty() {
            return;
        }
        let mut out: Vec<(ConsoleEventKind, bool, Value)> = Vec::new();
        {
            let mut reg = self.0.registry.write().await;
            for (repo_name, mut data) in stage_events {
                let public = reg
                    .repos
                    .get(&repo_name.to_ascii_lowercase())
                    .map(RepoEntry::is_public)
                    .unwrap_or(false);
                data["fabric_rev"] = json!(reg.bump());
                out.push((ConsoleEventKind::JobStageChanged, public, data));
            }
            for mut data in node_events {
                data["fabric_rev"] = json!(reg.bump());
                out.push((ConsoleEventKind::NodeMembershipChanged, true, data));
            }
        }
        for (kind, public, data) in out {
            self.emit(kind, public, data);
        }
    }

    /// Schedules a refresh for every repository known from job history whose cached
    /// metadata is missing or stale.
    pub async fn warm_up(&self, job_store: &JobStore) {
        let entries = self.entries().await;
        let ttl = self.metadata_ttl();
        for (owner, repo) in api::known_repo_names(job_store, &entries)
            .await
            .into_values()
        {
            let stale = entries
                .get(&repo_key(&owner, &repo))
                .map(|e| e.is_stale(ttl))
                .unwrap_or(true);
            if stale {
                self.schedule_refresh(&owner, &repo, None);
            }
        }
    }
}

/// Spawns the background reconciler that turns job / cluster changes into console
/// SSE events (woken by job-store notifications, with a 1 s fallback tick).
pub fn spawn_reconciler(
    console: ConsoleState,
    job_store: JobStore,
    cluster: ClusterRegistry,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        console.warm_up(&job_store).await;
        loop {
            console.reconcile(&job_store, &cluster).await;
            tokio::select! {
                _ = job_store.wait_for_event() => {}
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    })
}

// ============================================================================
// Helpers
// ============================================================================

fn local_revs(git_ref: &str, default_ref: &str) -> Vec<String> {
    let mut revs = vec![git_ref.to_string()];
    let origin = format!("origin/{default_ref}");
    if !revs.contains(&origin) {
        revs.push(origin);
    }
    revs
}

fn push_touches_topology(payload: &Value, submodules: &[SubmoduleRef]) -> bool {
    let Some(commits) = payload.get("commits").and_then(Value::as_array) else {
        return true;
    };
    if commits.len() >= PUSH_COMMIT_LIST_CAP {
        return true;
    }
    let touches = |p: &str| {
        p == ".gitmodules"
            || p.starts_with(".actionrunner/")
            || submodules.iter().any(|s| s.path == p)
    };
    commits.iter().any(|c| {
        ["added", "modified", "removed"].iter().any(|k| {
            c.get(*k)
                .and_then(Value::as_array)
                .map(|files| files.iter().filter_map(Value::as_str).any(touches))
                .unwrap_or(false)
        })
    })
}

fn branch_created(
    entry: &mut RepoEntry,
    ref_name: &str,
    base_ref: &str,
    head_sha: Option<String>,
    fork_stage: Option<String>,
    pr: Option<(u32, PrState)>,
) -> Option<(ConsoleEventKind, Value)> {
    if ref_name == entry.default_branch() || entry.branches.contains_key(ref_name) {
        return None;
    }
    let now = Utc::now();
    entry.deleted_branches.remove(ref_name);
    let b = BranchEntry {
        ref_name: ref_name.to_string(),
        base_ref: base_ref.to_string(),
        fork_stage,
        pr_state: pr.map(|p| p.1).unwrap_or_default(),
        pr_number: pr.map(|p| p.0),
        head_sha,
        created_at: now,
        updated_at: now,
    };
    let ev = b.emits_events().then(|| {
        (
            ConsoleEventKind::BranchCreated,
            json!({
                "owner": entry.owner,
                "repo": entry.repo,
                "ref": b.ref_name,
                "base_ref": b.base_ref,
                "fork_stage": b.fork_stage,
                "head_sha": b.head_sha,
            }),
        )
    });
    entry.branches.insert(ref_name.to_string(), b);
    ev
}

fn branch_deleted(entry: &mut RepoEntry, ref_name: &str) -> Option<(ConsoleEventKind, Value)> {
    let now = Utc::now();
    entry
        .deleted_branches
        .retain(|_, at| now - *at < chrono::Duration::days(1));
    entry.deleted_branches.insert(ref_name.to_string(), now);
    let b = entry.branches.remove(ref_name)?;
    b.emits_events().then(|| {
        (
            ConsoleEventKind::BranchDeleted,
            json!({
                "owner": entry.owner,
                "repo": entry.repo,
                "ref": b.ref_name,
                "merged": b.pr_state == PrState::Merged,
            }),
        )
    })
}

fn observe_pull_request(
    entry: &mut RepoEntry,
    payload: &Value,
    full: &str,
    default_branch: &str,
    fork_stage: Option<String>,
) -> Vec<(ConsoleEventKind, Value)> {
    let mut out = Vec::new();
    let Some(pr) = payload.get("pull_request") else {
        return out;
    };
    let action = payload.get("action").and_then(Value::as_str).unwrap_or("");
    let number = payload
        .get("number")
        .or_else(|| pr.get("number"))
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok());
    let Some(number) = number else {
        return out;
    };
    let Some(head_ref) = pr.pointer("/head/ref").and_then(Value::as_str) else {
        return out;
    };
    let head_repo = pr
        .pointer("/head/repo/full_name")
        .and_then(Value::as_str)
        .unwrap_or(full);
    let is_fork = !head_repo.eq_ignore_ascii_case(full);
    let key = if is_fork {
        let head_owner = head_repo
            .split_once('/')
            .map(|(o, _)| o)
            .unwrap_or(head_repo);
        format!("{head_owner}:{head_ref}")
    } else {
        head_ref.to_string()
    };
    let base_ref = pr
        .pointer("/base/ref")
        .and_then(Value::as_str)
        .unwrap_or(default_branch)
        .to_string();
    let head_sha = pr
        .pointer("/head/sha")
        .and_then(Value::as_str)
        .map(str::to_string);
    let draft = pr.get("draft").and_then(Value::as_bool).unwrap_or(false);
    let merged = pr.get("merged").and_then(Value::as_bool).unwrap_or(false);
    let new_state = match action {
        "closed" if merged => PrState::Merged,
        "closed" => PrState::Closed,
        _ if draft => PrState::Draft,
        _ => PrState::Open,
    };

    if !entry.branches.contains_key(&key) {
        if matches!(new_state, PrState::Merged | PrState::Closed) {
            return out;
        }
        out.extend(branch_created(
            entry,
            &key,
            &base_ref,
            head_sha.clone(),
            fork_stage,
            Some((number, PrState::None)),
        ));
    }
    let Some(b) = entry.branches.get_mut(&key) else {
        return out;
    };
    let previous = b.pr_state;
    b.pr_number = Some(number);
    b.base_ref = base_ref.clone();
    if head_sha.is_some() {
        b.head_sha = head_sha;
    }
    b.updated_at = Utc::now();
    if previous != new_state {
        b.pr_state = new_state;
        out.push((
            ConsoleEventKind::PrStateChanged,
            json!({
                "owner": entry.owner,
                "repo": entry.repo,
                "ref": key,
                "pr_number": number,
                "pr_state": new_state,
                "previous_state": previous,
                "base_ref": base_ref,
            }),
        ));
    }
    // Fork branches never receive `delete` webhooks: forget them once closed.
    if is_fork && matches!(new_state, PrState::Merged | PrState::Closed) {
        entry.branches.remove(&key);
    }
    out
}

/// Station the main line's latest train is at (used as a new siding's `fork_stage`).
fn main_line_station(jobs: &[JobRecord], repo_full: &str, default_branch: &str) -> Option<String> {
    jobs.iter()
        .filter(|r| {
            r.job.repo_name.eq_ignore_ascii_case(repo_full)
                && normalize_ref(&r.job.ref_name) == default_branch
                && !matches!(r.status, JobStatus::Skipped { .. })
        })
        .max_by_key(|r| r.job.queued_at)
        .and_then(current_stage)
        .map(|s| s.id.clone())
}

#[must_use]
pub fn stage_state(s: &StageStatus) -> StageState {
    match s {
        StageStatus::Pending => StageState::Pending,
        StageStatus::Assigned { .. } | StageStatus::Running { .. } => StageState::Running,
        StageStatus::Completed { exit_code: 0, .. } => StageState::Passed,
        StageStatus::Completed { .. } | StageStatus::Failed { .. } => StageState::Failed,
        StageStatus::Skipped { .. } => StageState::Skipped,
    }
}

fn stage_node(s: &StageRecord) -> Option<String> {
    match &s.status {
        StageStatus::Assigned { node_id, .. } | StageStatus::Running { node_id, .. } => {
            Some(node_id.clone())
        }
        _ => s.assigned_node.clone(),
    }
}

/// The train's current station: the first running stage, else the first failed one,
/// else the first pending one, else the last stage.
#[must_use]
pub fn current_stage(rec: &JobRecord) -> Option<&StageRecord> {
    let by = |want: StageState| rec.stages.iter().find(|s| stage_state(&s.status) == want);
    by(StageState::Running)
        .or_else(|| by(StageState::Failed))
        .or_else(|| by(StageState::Pending))
        .or_else(|| rec.stages.last())
}

#[must_use]
pub fn job_state(status: &JobStatus) -> JobState {
    match status {
        JobStatus::Queued => JobState::Queued,
        JobStatus::Running { .. } => JobState::Running,
        JobStatus::Completed { exit_code: 0, .. } => JobState::Passed,
        JobStatus::Completed { .. } | JobStatus::Failed { .. } => JobState::Failed,
        JobStatus::Skipped { .. } => JobState::Skipped,
    }
}

/// Parses the first `<number> <unit>` duration in a benchmark summary into nanoseconds
/// (e.g. `"3 benches (14.2 µs/iter)"` -> `14200.0`).
#[must_use]
pub fn parse_bench_ns(summary: &str) -> Option<f64> {
    let chars: Vec<char> = summary.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let num: String = chars[start..i].iter().collect();
            let mut j = i;
            while j < chars.len() && chars[j] == ' ' {
                j += 1;
            }
            let rest: String = chars[j..chars.len().min(j + 3)].iter().collect();
            let factor = if rest.starts_with("ns") {
                Some(1.0)
            } else if rest.starts_with("µs") || rest.starts_with("us") {
                Some(1e3)
            } else if rest.starts_with("ms") {
                Some(1e6)
            } else if rest.starts_with('s')
                && !rest.starts_with("se")
                && rest
                    .chars()
                    .nth(1)
                    .map(|c| !c.is_alphabetic())
                    .unwrap_or(true)
            {
                Some(1e9)
            } else {
                None
            };
            if let (Some(f), Ok(v)) = (factor, num.parse::<f64>()) {
                return Some(v * f);
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Location of the console registry cache inside a controller workspace.
#[must_use]
pub fn default_cache_file(workspace: &Path) -> PathBuf {
    workspace.join("logs").join("console_registry.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_parsing() {
        assert_eq!(parse_bench_ns("3 benches (14.2 µs/iter)"), Some(14_200.0));
        assert_eq!(parse_bench_ns("1 benches (49.0 ns/iter)"), Some(49.0));
        assert_eq!(parse_bench_ns("2.5 ms"), Some(2_500_000.0));
        assert_eq!(parse_bench_ns("no numbers"), None);
        assert_eq!(parse_bench_ns("3 benches"), None);
    }

    #[test]
    fn visibility_from_payload() {
        assert_eq!(
            Visibility::from_repository(&json!({"private": false})),
            Some(Visibility::Public)
        );
        assert_eq!(
            Visibility::from_repository(&json!({"private": true})),
            Some(Visibility::Private)
        );
        assert_eq!(
            Visibility::from_repository(&json!({"visibility": "internal", "private": true})),
            Some(Visibility::Internal)
        );
        assert_eq!(Visibility::from_repository(&json!({})), None);
    }

    #[test]
    fn push_topology_detection() {
        let subs = vec![SubmoduleRef {
            path: "code/core".into(),
            owner: "o".into(),
            repo: "r".into(),
            pinned_sha: None,
        }];
        let p = json!({"commits": [{"added": [], "modified": ["src/lib.rs"], "removed": []}]});
        assert!(!push_touches_topology(&p, &subs));
        let p = json!({"commits": [{"modified": ["code/core"]}]});
        assert!(push_touches_topology(&p, &subs));
        let p = json!({"commits": [{"added": [".gitmodules"]}]});
        assert!(push_touches_topology(&p, &subs));
        let p = json!({});
        assert!(push_touches_topology(&p, &subs));
    }
}
