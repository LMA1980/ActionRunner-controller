//! Pluggable controller persistence abstraction (`ControllerStorage`) supporting
//! `MuObserveRemoteStorage` (Fory RPC over `step-ca` mTLS / TCP) and `InMemoryStorage`
//! (for unit/integration test harnesses following Phase 3 local DuckDB decommissioning `#45`–`#47`),
//! plus root W3C `traceparent` generation and `RegressionGateReport` evaluation (`#41`–`#44`).

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mu_observable_ipc::{
    decode_control_envelope, encode_control_envelope, encode_hex,
    encode_log_batch as encode_otel_logs_ipc, encode_span_batch as encode_otel_spans_ipc,
    read_frame, write_frame, CentralBranchSnapshot, CentralJobRecord, CentralSubmoduleSnapshot,
    ControlRpcEnvelope, DeterministicSecretRedactor, IpcHeader, OtelLogEntry, OtelSpanEntry,
    QueryBranchSnapshotsRequest, QueryJobsHistoryRequest, QuerySubmoduleSnapshotsRequest,
    RegressionGateReport, RegressionGateRequest, RegressionVerdict, SecretRedactor, TraceContext,
    UpsertJobBatchRequest, UpsertJobRecordRequest, FLAG_HIGH_PRIORITY, MSG_TYPE_ARROW_OTEL_LOGS,
    MSG_TYPE_ARROW_OTEL_SPANS, MSG_TYPE_FORY_CONTROL, MSG_TYPE_WAL_ACK, TRACE_FLAG_SAMPLED,
    W3C_TRACEPARENT_VERSION,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::db::{AuthInviteRecord, AuthUserRecord, CatalogStore, RedeemInviteError};
use crate::job::{extract_submodule_job, normalize_ref, Job, JobMetrics, JobRecord, JobStatus};

/// Storage backend mode for `mu-ci-controller` after Phase 3 local DuckDB decommissioning (`#45`–`#47`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StorageBackendMode {
    /// Remote `MuObserve` control-plane storage via Apache Fory RPC over `MUOB` framing.
    #[default]
    MuObserveRemote,
    /// Pure-Rust in-memory catalog storage for standalone unit tests when `MUOBSERVE_CONTROL_ADDR` is unset.
    InMemory,
}

impl StorageBackendMode {
    /// Resolves the storage backend mode from `ACTION_RUNNER_STORAGE_MODE` and `MUOBSERVE_CONTROL_ADDR`.
    #[must_use]
    pub fn from_env() -> Self {
        if let Ok(raw) = std::env::var("ACTION_RUNNER_STORAGE_MODE") {
            match raw.trim().to_ascii_lowercase().as_str() {
                "memory" | "in_memory" | "inmemory" => return Self::InMemory,
                "remote" | "muobserve" | "muobserve_remote" => return Self::MuObserveRemote,
                _ => {}
            }
        }
        if std::env::var("MUOBSERVE_CONTROL_ADDR")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .is_some()
        {
            Self::MuObserveRemote
        } else {
            Self::InMemory
        }
    }
}

/// Distributed single-leader lease record persisted in [`ControllerStorage`] (`#79`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderLease {
    /// Unique node identifier of the controller holding the lease (e.g. `"node-a"`).
    pub holder_id: String,
    /// Microseconds since UNIX epoch when the lease was acquired or renewed.
    pub acquired_at_us: i64,
    /// Microseconds since UNIX epoch when the lease expires if not renewed.
    pub expires_at_us: i64,
    /// Monotonically increasing fencing epoch incremented on each leader change.
    pub epoch: u64,
}

impl LeaderLease {
    /// Returns `true` if the lease has expired at `now_us`.
    #[must_use]
    pub const fn is_expired(&self, now_us: i64) -> bool {
        now_us >= self.expires_at_us
    }
}

const INTERNAL_LEASE_REPO_KEY: &str = "__ar_ha_lease__";
const INTERNAL_CONSOLE_REPO_KEY: &str = "__ar_console_registry__";
const INTERNAL_PLATFORM_AUTH_REPO_KEY: &str = "__ar_platform_auth__";
/// Read-only virtual snapshot key used by `MuObserveRemoteStorage::get_job_log` on local cache miss
/// so `MuObserve` reconstructs the job log from `v_logs` (`otel_logs`) without any `__ar_job_logs__` snapshot writes.
const INTERNAL_LOG_REPO_KEY: &str = "__ar_job_logs__";

/// Abstract persistence interface for `mu-ci-controller` job records, branch snapshots,
/// submodule snapshots, shared job logs, single-leader leases, and hardware-stratified regression gate queries (`#43`, `#78`–`#84`).
pub trait ControllerStorage: Send + Sync {
    /// Upserts a single [`JobRecord`] and synchronizes its branch and submodule snapshots.
    fn upsert_record(&self, record: &JobRecord);

    /// Upserts a batch of [`JobRecord`] entries atomically and synchronizes snapshots.
    fn upsert_records_batch(&self, records: &[JobRecord]);

    /// Loads recent jobs ordered newest-first (`queued_at_us DESC`).
    fn load_recent_jobs(&self, limit: usize) -> Vec<JobRecord>;

    /// Loads branch snapshots filtered by optional `repo_key` and `branch_key`.
    fn load_branch_snapshots(
        &self,
        repo_key: Option<&str>,
        branch_key: Option<&str>,
    ) -> Vec<CentralBranchSnapshot>;

    /// Loads submodule snapshots filtered by optional `parent_repo_key`, `submodule_key`, and `branch_key`.
    fn load_submodule_snapshots(
        &self,
        parent_repo_key: Option<&str>,
        submodule_key: Option<&str>,
        branch_key: Option<&str>,
    ) -> Vec<CentralSubmoduleSnapshot>;

    /// Looks up a single job by ID.
    fn get_job(&self, job_id: &str) -> Option<JobRecord>;

    /// Finds the latest completed (`Completed` or `Failed`) job for a repository/branch.
    fn find_latest_completed(&self, repo: &str, branch: Option<&str>) -> Option<JobRecord> {
        let (_active, completed) = self.find_card_context(repo, branch);
        completed
    }

    /// Finds `(latest_active_or_completed, latest_completed)` for a repository/branch.
    fn find_card_context(
        &self,
        repo: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>);

    /// Finds the latest completed (`Completed` or `Failed`) job for a specific submodule.
    fn find_submodule_completed(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> Option<JobRecord> {
        let (_active, completed) = self.find_submodule_card_context(parent_repo, submodule, branch);
        completed
    }

    /// Finds `(latest_active_or_completed, latest_completed)` for a specific submodule.
    fn find_submodule_card_context(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>);

    /// Evaluates the hardware-stratified regression gate for a candidate commit against a baseline branch.
    fn evaluate_regression_gate(
        &self,
        _req: &RegressionGateRequest,
    ) -> Option<RegressionGateReport> {
        None
    }

    /// Appends structured worker [`mu_ci_ipc::LogEntry`] records for `job_id` as single-line
    /// deduplicated [`OtelLogEntry`] deltas.
    fn append_structured_log_entries(&self, job_id: &str, entries: &[mu_ci_ipc::LogEntry]) {
        let chunk = crate::aggregator::format_log_entries(entries);
        if !chunk.is_empty() {
            self.append_job_log_buffered(job_id, &chunk);
        }
    }

    /// Appends controller status/note lines for `job_id` as single-line [`OtelLogEntry`] deltas.
    fn append_log_lines(&self, job_id: &str, chunk: &str) {
        self.append_job_log(job_id, chunk);
    }

    /// Appends a log chunk for `job_id` into shared persistence (`#83`).
    fn append_job_log(&self, _job_id: &str, _chunk: &str) {}

    /// Appends a streaming log chunk for `job_id` into an in-memory write-behind buffer,
    /// coalescing remote persistence flushes (`#124`).
    fn append_job_log_buffered(&self, job_id: &str, chunk: &str) {
        self.append_job_log(job_id, chunk);
    }

    /// Flushes all pending dirty log deltas across active jobs.
    fn flush_dirty_logs(&self) {
        self.flush_job_log(None);
    }

    /// Flushes buffered in-memory log chunks for `job_id` (or all dirty jobs when `None`)
    /// to shared persistence (`#124`).
    fn flush_job_log(&self, _job_id: Option<&str>) {}

    /// Retrieves the full persisted execution log for `job_id` from shared persistence (`#83`, `#84`).
    fn get_job_log(&self, _job_id: &str) -> Option<String> {
        None
    }

    /// Attempts to acquire or renew the single-leader lease for `holder_id` with `ttl_secs`.
    /// When `force` is `true`, takes over the lease even if another holder's lease has not yet expired
    /// (used for explicit operator promotion). Returns `true` if `holder_id` holds the lease (`#79`).
    fn try_acquire_or_renew_lease(&self, _holder_id: &str, _ttl_secs: u64, _force: bool) -> bool {
        true
    }

    /// Releases the single-leader lease if currently held by `holder_id` (`#79`).
    fn release_lease(&self, _holder_id: &str) {}

    /// Emits a batch of [`OtelSpanEntry`] records to shared observability telemetry.
    fn emit_trace_spans(&self, _spans: &[OtelSpanEntry]) {}

    /// Returns the current [`LeaderLease`] state from shared storage, if any (`#79`).
    fn get_leader_lease(&self) -> Option<LeaderLease> {
        None
    }

    /// Persists the serialized `ConsoleState` registry JSON in shared storage (`#82`).
    fn save_console_registry(&self, _registry_json: &str) {}

    /// Loads the serialized `ConsoleState` registry JSON from shared storage (`#82`).
    fn load_console_registry(&self) -> Option<String> {
        None
    }

    /// Configures persistent disk auth state path if supported (`#175`).
    fn configure_auth_state_path(&self, _path: &Path) {}

    /// Accesses underlying platform auth `CatalogStore` (`#172`).
    fn auth_catalog(&self) -> Option<&CatalogStore> {
        None
    }

    /// Replicates updated serialized `PlatformAuthState` JSON to remote storage (`#175`).
    fn sync_platform_auth_json(&self, _json: &str) {}

    /// Seeds `config.bootstrap_admins` as `role = "admin"`, `invited_by = "bootstrap"` (`#93`).
    fn seed_bootstrap_admins(&self, _admins: &[String]) {}

    /// Inserts a newly generated one-time invite into `auth_invites` (`#93`).
    fn create_auth_invite(&self, _invite: &AuthInviteRecord) {}

    /// Looks up a single invite by `invite_id` (`#93`).
    fn get_auth_invite(&self, _invite_id: &str) -> Option<AuthInviteRecord> {
        None
    }

    /// Lists all invites in `auth_invites` (`#93`, `#96`).
    fn list_auth_invites(&self) -> Vec<AuthInviteRecord> {
        Vec::new()
    }

    /// Atomically verifies and redeems a single-use invite token (`#93`, `#95`).
    fn redeem_auth_invite(
        &self,
        _invite_id: &str,
        _presented_hmac: &str,
        _github_login: &str,
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthUserRecord, RedeemInviteError> {
        Err(RedeemInviteError::InviteNotFound)
    }

    /// Looks up a user in `auth_users` case-insensitively (`#93`).
    fn get_auth_user(&self, _github_login: &str) -> Option<AuthUserRecord> {
        None
    }

    /// Lists all bound/revoked users in `auth_users` (`#93`, `#96`).
    fn list_auth_users(&self) -> Vec<AuthUserRecord> {
        Vec::new()
    }

    /// Revokes a user (`revoked = 1`) in `auth_users` (`#93`, `#96`).
    fn revoke_auth_user(&self, _github_login: &str) -> bool {
        false
    }
}

/// Pure-Rust in-memory implementation of [`ControllerStorage`] for unit and integration tests.
#[derive(Clone, Default)]
pub struct InMemoryStorage {
    store: Arc<CatalogStore>,
    emitted_spans: Arc<std::sync::Mutex<Vec<OtelSpanEntry>>>,
}

impl InMemoryStorage {
    /// Wraps an existing [`CatalogStore`].
    #[must_use]
    pub fn new(store: Arc<CatalogStore>) -> Self {
        Self {
            store,
            emitted_spans: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Creates a new empty [`InMemoryStorage`].
    #[must_use]
    pub fn open() -> Self {
        Self {
            store: Arc::new(CatalogStore::new()),
            emitted_spans: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    /// Returns a copy of all emitted [`OtelSpanEntry`] records.
    #[must_use]
    pub fn get_emitted_spans(&self) -> Vec<OtelSpanEntry> {
        self.emitted_spans
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Returns a reference to the underlying [`CatalogStore`].
    #[must_use]
    pub fn inner(&self) -> &Arc<CatalogStore> {
        &self.store
    }
}

impl ControllerStorage for InMemoryStorage {
    fn upsert_record(&self, record: &JobRecord) {
        self.store.upsert_record(record);
    }

    fn upsert_records_batch(&self, records: &[JobRecord]) {
        self.store.upsert_records_batch(records);
    }

    fn load_recent_jobs(&self, limit: usize) -> Vec<JobRecord> {
        self.store.load_recent_jobs(limit)
    }

    fn load_branch_snapshots(
        &self,
        repo_key: Option<&str>,
        branch_key: Option<&str>,
    ) -> Vec<CentralBranchSnapshot> {
        self.store.load_branch_snapshots(repo_key, branch_key)
    }

    fn load_submodule_snapshots(
        &self,
        parent_repo_key: Option<&str>,
        submodule_key: Option<&str>,
        branch_key: Option<&str>,
    ) -> Vec<CentralSubmoduleSnapshot> {
        self.store
            .load_submodule_snapshots(parent_repo_key, submodule_key, branch_key)
    }

    fn get_job(&self, job_id: &str) -> Option<JobRecord> {
        self.store.get_job(job_id)
    }

    fn find_latest_completed(&self, repo: &str, branch: Option<&str>) -> Option<JobRecord> {
        self.store.find_latest_completed(repo, branch)
    }

    fn find_card_context(
        &self,
        repo: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        self.store.find_card_context(repo, branch)
    }

    fn find_submodule_completed(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> Option<JobRecord> {
        self.store
            .find_submodule_completed(parent_repo, submodule, branch)
    }

    fn find_submodule_card_context(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        self.store
            .find_submodule_card_context(parent_repo, submodule, branch)
    }

    fn append_structured_log_entries(&self, job_id: &str, entries: &[mu_ci_ipc::LogEntry]) {
        let chunk = crate::aggregator::format_log_entries(entries);
        if !chunk.is_empty() {
            self.store.append_job_log(job_id, &chunk);
        }
    }

    fn append_log_lines(&self, job_id: &str, chunk: &str) {
        self.store.append_job_log(job_id, chunk);
    }

    fn append_job_log(&self, job_id: &str, chunk: &str) {
        self.store.append_job_log(job_id, chunk);
    }

    fn get_job_log(&self, job_id: &str) -> Option<String> {
        self.store.get_job_log(job_id)
    }

    fn try_acquire_or_renew_lease(&self, holder_id: &str, ttl_secs: u64, force: bool) -> bool {
        self.store
            .try_acquire_or_renew_lease(holder_id, ttl_secs, force)
    }

    fn release_lease(&self, holder_id: &str) {
        self.store.release_lease(holder_id);
    }

    fn get_leader_lease(&self) -> Option<LeaderLease> {
        self.store.get_leader_lease()
    }

    fn save_console_registry(&self, registry_json: &str) {
        self.store.save_console_registry(registry_json);
    }

    fn load_console_registry(&self) -> Option<String> {
        self.store.load_console_registry()
    }

    fn configure_auth_state_path(&self, path: &Path) {
        self.store.configure_auth_state_path(path.to_path_buf());
    }

    fn auth_catalog(&self) -> Option<&CatalogStore> {
        Some(&self.store)
    }

    fn seed_bootstrap_admins(&self, admins: &[String]) {
        self.store.seed_bootstrap_admins(admins);
    }

    fn create_auth_invite(&self, invite: &AuthInviteRecord) {
        self.store.create_auth_invite(invite);
    }

    fn get_auth_invite(&self, invite_id: &str) -> Option<AuthInviteRecord> {
        self.store.get_auth_invite(invite_id)
    }

    fn list_auth_invites(&self) -> Vec<AuthInviteRecord> {
        self.store.list_auth_invites()
    }

    fn redeem_auth_invite(
        &self,
        invite_id: &str,
        presented_hmac: &str,
        github_login: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthUserRecord, RedeemInviteError> {
        self.store
            .redeem_auth_invite(invite_id, presented_hmac, github_login, now)
    }

    fn get_auth_user(&self, github_login: &str) -> Option<AuthUserRecord> {
        self.store.get_auth_user(github_login)
    }

    fn list_auth_users(&self) -> Vec<AuthUserRecord> {
        self.store.list_auth_users()
    }

    fn revoke_auth_user(&self, github_login: &str) -> bool {
        self.store.revoke_auth_user(github_login)
    }

    fn emit_trace_spans(&self, spans: &[OtelSpanEntry]) {
        if spans.is_empty() {
            return;
        }
        if let Ok(mut lock) = self.emitted_spans.lock() {
            lock.extend(spans.iter().cloned());
        }
    }
}

/// Connection configuration for [`MuObserveRemoteStorage`].
#[derive(Debug, Clone)]
pub struct MuObserveRemoteConfig {
    /// TCP endpoint of `MuObserve` ingestion/control server (`host:port`).
    pub endpoint_addr: String,
    /// Optional TLS SNI server name when `step-ca` mTLS is enabled.
    pub tls_server_name: Option<String>,
    /// Optional PEM-encoded `step-ca` root CA bundle.
    pub ca_cert_pem: Option<String>,
    /// Optional PEM-encoded client leaf certificate.
    pub client_cert_pem: Option<String>,
    /// Optional PEM-encoded client private key.
    pub client_key_pem: Option<String>,
    /// Per-RPC timeout in milliseconds.
    pub timeout_ms: u64,
}

impl MuObserveRemoteConfig {
    /// Creates a plain-TCP configuration targeting `endpoint_addr` (for local loopback or tests).
    #[must_use]
    pub fn plain_tcp(endpoint_addr: impl Into<String>) -> Self {
        Self {
            endpoint_addr: endpoint_addr.into(),
            tls_server_name: None,
            ca_cert_pem: None,
            client_cert_pem: None,
            client_key_pem: None,
            timeout_ms: 2_500,
        }
    }

    /// Creates a `step-ca` mTLS configuration targeting `endpoint_addr`.
    #[must_use]
    pub fn with_mtls(
        endpoint_addr: impl Into<String>,
        tls_server_name: impl Into<String>,
        ca_cert_pem: impl Into<String>,
        client_cert_pem: impl Into<String>,
        client_key_pem: impl Into<String>,
    ) -> Self {
        Self {
            endpoint_addr: endpoint_addr.into(),
            tls_server_name: Some(tls_server_name.into()),
            ca_cert_pem: Some(ca_cert_pem.into()),
            client_cert_pem: Some(client_cert_pem.into()),
            client_key_pem: Some(client_key_pem.into()),
            timeout_ms: 3_000,
        }
    }

    /// Loads [`MuObserveRemoteConfig`] from environment variables (`MUOBSERVE_CONTROL_ADDR`, etc.).
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let endpoint_addr = std::env::var("MUOBSERVE_CONTROL_ADDR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let tls_server_name = std::env::var("MUOBSERVE_TLS_SERVER_NAME")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let ca_cert_pem = read_env_pem("MUOBSERVE_CA_CERT");
        let client_cert_pem = read_env_pem("MUOBSERVE_CLIENT_CERT");
        let client_key_pem = read_env_pem("MUOBSERVE_CLIENT_KEY");
        let timeout_ms = std::env::var("MUOBSERVE_RPC_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(2_500);

        Some(Self {
            endpoint_addr,
            tls_server_name,
            ca_cert_pem,
            client_cert_pem,
            client_key_pem,
            timeout_ms,
        })
    }
}

fn read_env_pem(var_name: &str) -> Option<String> {
    let raw = std::env::var(var_name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("-----BEGIN ") {
        return Some(trimmed.to_string());
    }
    // Per AGENTS.md §3: fail closed if a file path cannot be read.
    std::fs::read_to_string(trimmed)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn build_mtls_client_config(
    ca_cert_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Result<Arc<ClientConfig>, String> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let mut ca_cursor = Cursor::new(ca_cert_pem.as_bytes());
    let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut ca_cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse CA PEM: {e}"))?;
    if ca_certs.is_empty() {
        return Err("CA PEM contains no certificates".to_string());
    }

    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|e| format!("Failed to add CA cert: {e}"))?;
    }

    let mut cert_cursor = Cursor::new(client_cert_pem.as_bytes());
    let client_certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(&mut cert_cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse client cert PEM: {e}"))?;

    let mut key_cursor = Cursor::new(client_key_pem.as_bytes());
    let client_key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(&mut key_cursor)
        .map_err(|e| format!("Failed to parse client key PEM: {e}"))?;

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| format!("Failed to build mTLS ClientConfig: {e}"))?;

    Ok(Arc::new(client_config))
}

type DedupLineKey = (String, i8, u32);

#[derive(Default)]
struct JobDedupRing {
    order: std::collections::VecDeque<DedupLineKey>,
    seen: std::collections::HashSet<DedupLineKey>,
}

impl JobDedupRing {
    fn insert(&mut self, key: DedupLineKey, max_capacity: usize) -> bool {
        if self.seen.contains(&key) {
            return false;
        }
        while self.seen.len() >= max_capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            } else {
                break;
            }
        }
        self.order.push_back(key.clone());
        self.seen.insert(key)
    }
}

type JobDedupMap = BTreeMap<String, JobDedupRing>;

fn shared_redactor() -> &'static DeterministicSecretRedactor {
    static REDACTOR: std::sync::OnceLock<DeterministicSecretRedactor> = std::sync::OnceLock::new();
    REDACTOR.get_or_init(DeterministicSecretRedactor::new)
}

fn is_metric_summary_line(line: &str) -> bool {
    let body = if let Some((_, after_stream)) = line.split_once("[stdout] ") {
        after_stream
    } else if let Some((_, after_stream)) = line.split_once("[stderr] ") {
        after_stream
    } else {
        line
    };
    let trimmed = body.trim();
    body.contains("test result:")
        || trimmed.starts_with("TOTAL ")
        || (trimmed.contains(".rs ") && trimmed.contains('%'))
        || body.contains("bench:")
}

/// Remote `MuObserve` implementation of [`ControllerStorage`] communicating via
/// `MUOB`-framed Apache Fory [`ControlRpcEnvelope`] messages and Arrow IPC [`OtelLogEntry`]
/// streams over `step-ca` mTLS or TCP.
#[derive(Clone)]
pub struct MuObserveRemoteStorage {
    config: MuObserveRemoteConfig,
    tls_client_config: Option<Arc<ClientConfig>>,
    seq: Arc<AtomicU64>,
    pending_log_lines: Arc<std::sync::RwLock<Vec<OtelLogEntry>>>,
    seen_log_lines: Arc<std::sync::RwLock<JobDedupMap>>,
    controller_line_counters: Arc<std::sync::RwLock<BTreeMap<String, u32>>>,
    job_commit_shas: Arc<std::sync::RwLock<BTreeMap<String, String>>>,
    log_buffer: Arc<std::sync::RwLock<BTreeMap<String, String>>>,
    dirty_log_keys: Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>,
    last_log_flush: Arc<std::sync::Mutex<BTreeMap<String, std::time::Instant>>>,
    auth_store: Arc<CatalogStore>,
}

const MAX_BUFFERED_JOB_LOGS: usize = 100;
const MAX_LOG_BUFFER_BYTES_PER_JOB: usize = 256 * 1024;
const MAX_PRESERVED_METRIC_BYTES: usize = 16 * 1024;
const MAX_SEEN_LINES_PER_JOB: usize = 50_000;
const BUFFERED_LOG_FLUSH_INTERVAL: Duration = Duration::from_secs(10);

impl MuObserveRemoteStorage {
    /// Creates a new [`MuObserveRemoteStorage`] from `config`.
    pub fn new(config: MuObserveRemoteConfig) -> Result<Self, String> {
        let tls_client_config = match (
            config.ca_cert_pem.as_deref(),
            config.client_cert_pem.as_deref(),
            config.client_key_pem.as_deref(),
        ) {
            (Some(ca), Some(cert), Some(key)) => Some(build_mtls_client_config(ca, cert, key)?),
            (None, None, None) => None,
            _ => {
                return Err(
                    "Incomplete mTLS configuration: ca_cert_pem, client_cert_pem, and client_key_pem must all be provided together"
                        .to_string(),
                )
            }
        };

        Ok(Self {
            config,
            tls_client_config,
            seq: Arc::new(AtomicU64::new(1)),
            pending_log_lines: Arc::new(std::sync::RwLock::new(Vec::new())),
            seen_log_lines: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
            controller_line_counters: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
            job_commit_shas: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
            log_buffer: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
            dirty_log_keys: Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::new())),
            last_log_flush: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            auth_store: Arc::new(CatalogStore::new()),
        })
    }

    fn register_job_commit_sha(&self, job_id: &str, commit_sha: &str) {
        if commit_sha.is_empty() {
            return;
        }
        let key = job_id.to_ascii_lowercase();
        let Ok(mut guard) = self.job_commit_shas.write() else {
            return;
        };
        guard.insert(key.clone(), commit_sha.to_string());
        while guard.len() > MAX_BUFFERED_JOB_LOGS {
            if let Some(first_key) = guard.keys().find(|k| k.as_str() != key).cloned() {
                guard.remove(&first_key);
            } else {
                break;
            }
        }
    }

    fn resolve_job_commit_sha(&self, job_id: &str) -> String {
        let key = job_id.to_ascii_lowercase();
        self.job_commit_shas
            .read()
            .ok()
            .and_then(|g| g.get(&key).cloned())
            .unwrap_or_else(|| job_id.to_string())
    }

    fn append_to_local_log_buffer(&self, key: &str, chunk: &str) {
        if chunk.is_empty() {
            return;
        }
        let redactor = shared_redactor();
        let scrubbed = redactor.redact(chunk);
        let Ok(mut guard) = self.log_buffer.write() else {
            return;
        };
        let entry = guard.entry(key.to_string()).or_default();
        entry.push_str(&scrubbed);
        if entry.len() > MAX_LOG_BUFFER_BYTES_PER_JOB {
            let tail_budget =
                MAX_LOG_BUFFER_BYTES_PER_JOB.saturating_sub(MAX_PRESERVED_METRIC_BYTES);
            let mut cut = entry.len().saturating_sub(tail_budget);
            while cut < entry.len() && !entry.is_char_boundary(cut) {
                cut += 1;
            }
            if let Some(rel_nl) = entry[cut..].find('\n') {
                cut += rel_nl + 1;
            }
            cut = cut.min(entry.len());
            let mut preserved = String::new();
            for line in entry[..cut].lines() {
                if is_metric_summary_line(line)
                    && preserved.len().saturating_add(line.len()).saturating_add(1)
                        <= MAX_PRESERVED_METRIC_BYTES
                {
                    preserved.push_str(line);
                    preserved.push('\n');
                }
            }
            let tail = entry[cut..].to_string();
            preserved.push_str(&tail);
            *entry = preserved;
        }
        while guard.len() > MAX_BUFFERED_JOB_LOGS {
            if let Some(first_key) = guard.keys().find(|k| k.as_str() != key).cloned() {
                guard.remove(&first_key);
            } else {
                break;
            }
        }
    }

    fn record_dedup_line(&self, job_key: &str, stage_id: &str, stream: i8, line_no: u32) -> bool {
        let Ok(mut guard) = self.seen_log_lines.write() else {
            return true;
        };
        let ring = guard.entry(job_key.to_string()).or_default();
        let inserted = ring.insert(
            (stage_id.to_string(), stream, line_no),
            MAX_SEEN_LINES_PER_JOB,
        );
        while guard.len() > MAX_BUFFERED_JOB_LOGS {
            if let Some(first_key) = guard.keys().find(|k| k.as_str() != job_key).cloned() {
                guard.remove(&first_key);
            } else {
                break;
            }
        }
        inserted
    }

    fn next_controller_line_no(&self, job_key: &str) -> u32 {
        let Ok(mut guard) = self.controller_line_counters.write() else {
            return 1;
        };
        let counter = guard.entry(job_key.to_string()).or_insert(0);
        *counter = counter.saturating_add(1);
        let next = *counter;
        while guard.len() > MAX_BUFFERED_JOB_LOGS {
            if let Some(first_key) = guard.keys().find(|k| k.as_str() != job_key).cloned() {
                guard.remove(&first_key);
            } else {
                break;
            }
        }
        next
    }

    /// Synchronously converts structured worker [`mu_ci_ipc::LogEntry`] records into deduplicated,
    /// secret-redacted [`OtelLogEntry`] records queued in `pending_log_lines`, and updates the
    /// bounded local `log_buffer` fallback.
    pub fn append_structured_log_entries_sync(
        &self,
        job_id: &str,
        entries: &[mu_ci_ipc::LogEntry],
    ) -> usize {
        if entries.is_empty() {
            return 0;
        }
        let key = job_id.to_ascii_lowercase();
        let commit_sha = self.resolve_job_commit_sha(job_id);
        let redactor = shared_redactor();
        let mut new_otel = Vec::with_capacity(entries.len());
        let mut new_raw = Vec::with_capacity(entries.len());

        for entry in entries {
            if !self.record_dedup_line(&key, &entry.stage_id, entry.stream, entry.line_no) {
                continue;
            }
            new_raw.push(entry.clone());
            let ts_ns = if entry.timestamp_us > 0 {
                entry.timestamp_us.saturating_mul(1_000)
            } else {
                chrono::Utc::now()
                    .timestamp_nanos_opt()
                    .unwrap_or_else(|| chrono::Utc::now().timestamp_micros().saturating_mul(1_000))
            };
            let trace_ctx = job_stage_trace_context(job_id, &commit_sha, &entry.stage_id);
            let trace_id = encode_hex(&trace_ctx.trace_id);
            let span_id = encode_hex(&trace_ctx.span_id);
            let (severity_number, severity_text, stream_name) = if entry.stream == 2 {
                (13, "WARN".to_string(), "stderr")
            } else {
                (9, "INFO".to_string(), "stdout")
            };
            let mut otel_entry = OtelLogEntry {
                timestamp_unix_nano: ts_ns,
                trace_id,
                span_id,
                severity_number,
                severity_text,
                service_name: "action-runner-worker".to_string(),
                node_id: entry.node_id.clone(),
                body: entry.content.clone(),
                attributes_json: serde_json::json!({
                    "stream": stream_name,
                    "line_no": entry.line_no,
                })
                .to_string(),
                job_id: Some(job_id.to_string()),
                stage_id: Some(entry.stage_id.clone()),
            };
            otel_entry.redact_in_place(redactor);
            new_otel.push(otel_entry);
        }

        if new_otel.is_empty() {
            return 0;
        }

        let formatted = crate::aggregator::format_log_entries(&new_raw);
        self.append_to_local_log_buffer(&key, &formatted);

        let count = new_otel.len();
        if let Ok(mut pending) = self.pending_log_lines.write() {
            pending.extend(new_otel);
        }
        if let Ok(mut dirty) = self.dirty_log_keys.lock() {
            dirty.insert(key.clone());
        }
        if let Ok(mut last) = self.last_log_flush.lock() {
            last.entry(key).or_insert_with(std::time::Instant::now);
        }
        count
    }

    /// Asynchronously appends structured worker [`mu_ci_ipc::LogEntry`] records into `pending_log_lines`
    /// and flushes dirty delta lines if the periodic flush interval has elapsed.
    pub async fn append_structured_log_entries(
        &self,
        job_id: &str,
        entries: &[mu_ci_ipc::LogEntry],
    ) {
        let added = self.append_structured_log_entries_sync(job_id, entries);
        if added == 0 {
            return;
        }
        let key = job_id.to_ascii_lowercase();
        let should_flush = self
            .last_log_flush
            .lock()
            .ok()
            .and_then(|g| g.get(&key).copied())
            .map(|t| t.elapsed() >= BUFFERED_LOG_FLUSH_INTERVAL)
            .unwrap_or(false);
        if should_flush {
            let _ = self.flush_dirty_logs().await;
        }
    }

    /// Splits controller log `chunk` into individual lines, converts each line into a redacted
    /// [`OtelLogEntry`] with `service_name = "action-runner-controller"`, updates the bounded
    /// local `log_buffer`, and queues the delta entries in `pending_log_lines`.
    pub fn append_log_lines(&self, job_id: &str, chunk: &str) -> usize {
        if chunk.is_empty() {
            return 0;
        }
        let key = job_id.to_ascii_lowercase();
        self.append_to_local_log_buffer(&key, chunk);

        let commit_sha = self.resolve_job_commit_sha(job_id);
        let redactor = shared_redactor();
        let trace_ctx = job_stage_trace_context(job_id, &commit_sha, "controller");
        let trace_id = encode_hex(&trace_ctx.trace_id);
        let span_id = encode_hex(&trace_ctx.span_id);
        let now_ns = chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| chrono::Utc::now().timestamp_micros().saturating_mul(1_000));

        let mut new_otel = Vec::new();
        for raw_line in chunk.lines() {
            let trimmed = raw_line.trim_end_matches('\r');
            if trimmed.is_empty() {
                continue;
            }
            let line_no = self.next_controller_line_no(&key);
            if !self.record_dedup_line(&key, "controller", 1, line_no) {
                continue;
            }
            let mut otel_entry = OtelLogEntry {
                timestamp_unix_nano: now_ns,
                trace_id: trace_id.clone(),
                span_id: span_id.clone(),
                severity_number: 9,
                severity_text: "INFO".to_string(),
                service_name: "action-runner-controller".to_string(),
                node_id: "controller".to_string(),
                body: trimmed.to_string(),
                attributes_json: serde_json::json!({
                    "stream": "stdout",
                    "line_no": line_no,
                })
                .to_string(),
                job_id: Some(job_id.to_string()),
                stage_id: Some("controller".to_string()),
            };
            otel_entry.redact_in_place(redactor);
            new_otel.push(otel_entry);
        }

        let count = new_otel.len();
        if count > 0 {
            if let Ok(mut pending) = self.pending_log_lines.write() {
                pending.extend(new_otel);
            }
            if let Ok(mut dirty) = self.dirty_log_keys.lock() {
                dirty.insert(key.clone());
            }
            if let Ok(mut last) = self.last_log_flush.lock() {
                last.entry(key).or_insert_with(std::time::Instant::now);
            }
        }
        count
    }

    /// Returns a snapshot of currently queued [`OtelLogEntry`] delta records awaiting flush.
    #[must_use]
    pub fn pending_log_lines_snapshot(&self) -> Vec<OtelLogEntry> {
        self.pending_log_lines
            .read()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    fn drain_pending_log_lines(&self, job_id: Option<&str>) -> Vec<OtelLogEntry> {
        let Ok(mut pending) = self.pending_log_lines.write() else {
            return Vec::new();
        };
        if pending.is_empty() {
            return Vec::new();
        }
        let now = std::time::Instant::now();
        match job_id {
            None => {
                if let Ok(mut dirty) = self.dirty_log_keys.lock() {
                    if let Ok(mut last) = self.last_log_flush.lock() {
                        for k in dirty.iter() {
                            last.insert(k.clone(), now);
                        }
                    }
                    dirty.clear();
                }
                std::mem::take(&mut *pending)
            }
            Some(target_job) => {
                let key = target_job.to_ascii_lowercase();
                let mut drained = Vec::new();
                let mut remaining = Vec::new();
                for entry in pending.drain(..) {
                    let matches_job = entry
                        .job_id
                        .as_deref()
                        .map(|j| j.eq_ignore_ascii_case(target_job))
                        .unwrap_or(true);
                    if matches_job {
                        drained.push(entry);
                    } else {
                        remaining.push(entry);
                    }
                }
                *pending = remaining;
                if let Ok(mut dirty) = self.dirty_log_keys.lock() {
                    dirty.remove(&key);
                }
                if let Ok(mut last) = self.last_log_flush.lock() {
                    last.insert(key, now);
                }
                drained
            }
        }
    }

    fn requeue_failed_log_batch(&self, mut failed_batch: Vec<OtelLogEntry>) {
        if failed_batch.is_empty() {
            return;
        }
        if let Ok(mut dirty) = self.dirty_log_keys.lock() {
            for entry in &failed_batch {
                if let Some(ref jid) = entry.job_id {
                    dirty.insert(jid.to_ascii_lowercase());
                }
            }
        }
        if let Ok(mut pending) = self.pending_log_lines.write() {
            failed_batch.append(&mut *pending);
            *pending = failed_batch;
            if pending.len() > MAX_SEEN_LINES_PER_JOB {
                let overflow = pending.len() - MAX_SEEN_LINES_PER_JOB;
                pending.drain(..overflow);
            }
        }
    }

    /// Drains all queued delta [`OtelLogEntry`] records and streams them as a single
    /// `MSG_TYPE_ARROW_OTEL_LOGS` frame (`encode_otel_logs_ipc`) to `MuObserve`.
    /// On transient network or WAL error, re-queues the drained batch so no delta lines are lost.
    pub async fn flush_dirty_logs(&self) -> Result<usize, String> {
        let batch = self.drain_pending_log_lines(None);
        if batch.is_empty() {
            return Ok(0);
        }
        match self.send_otel_logs_async(&batch).await {
            Ok(n) => Ok(n),
            Err(e) => {
                self.requeue_failed_log_batch(batch);
                Err(e)
            }
        }
    }

    /// Synchronously drains and flushes pending [`OtelLogEntry`] delta records for `job_id`
    /// (or all jobs when `None`) via `MSG_TYPE_ARROW_OTEL_LOGS`.
    /// On transient network or WAL error, re-queues the drained batch so no delta lines are lost.
    pub fn flush_dirty_logs_blocking(&self, job_id: Option<&str>) -> Result<usize, String> {
        let batch = self.drain_pending_log_lines(job_id);
        if batch.is_empty() {
            return Ok(0);
        }
        match self.send_otel_logs_blocking(&batch) {
            Ok(n) => Ok(n),
            Err(e) => {
                self.requeue_failed_log_batch(batch);
                Err(e)
            }
        }
    }

    async fn exchange_otel_logs_stream<S>(
        stream: &mut S,
        seq: u64,
        batch: &[OtelLogEntry],
    ) -> Result<usize, String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let payload =
            encode_otel_logs_ipc(batch).map_err(|e| format!("Arrow OTel log encode error: {e}"))?;
        let flags = if batch.iter().any(|l| l.severity_number >= 13) {
            FLAG_HIGH_PRIORITY
        } else {
            0
        };
        let header = IpcHeader::new(MSG_TYPE_ARROW_OTEL_LOGS, payload.len() as u32, flags, seq);
        write_frame(stream, &header, &payload)
            .await
            .map_err(|e| format!("Write MUOB OTel log frame error: {e}"))?;
        if let Ok((resp_hdr, resp_payload)) = read_frame(stream).await {
            if resp_hdr.msg_type == MSG_TYPE_WAL_ACK || resp_hdr.msg_type == MSG_TYPE_FORY_CONTROL {
                if let Ok(ControlRpcEnvelope::WalAck(ack)) = decode_control_envelope(&resp_payload)
                {
                    if !ack.ok {
                        return Err(ack
                            .error_message
                            .unwrap_or_else(|| "MuObserve rejected OTel log batch".to_string()));
                    }
                }
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(stream).await;
        Ok(batch.len())
    }

    /// Sends a batch of [`OtelLogEntry`] records to `MuObserve` via `MSG_TYPE_ARROW_OTEL_LOGS`.
    pub async fn send_otel_logs_async(&self, batch: &[OtelLogEntry]) -> Result<usize, String> {
        if batch.is_empty() {
            return Ok(0);
        }
        let timeout_dur = Duration::from_millis(self.config.timeout_ms.max(100));
        let seq = self.next_seq();
        let addr = self.config.endpoint_addr.clone();
        let tls_cfg = self.tls_client_config.clone();
        let sni = self
            .config
            .tls_server_name
            .clone()
            .unwrap_or_else(|| "muobserve.node-a.cluster.internal".to_string());
        let batch_owned = batch.to_vec();

        tokio::time::timeout(timeout_dur, async move {
            let tcp = TcpStream::connect(&addr)
                .await
                .map_err(|e| format!("Connect to {addr} failed: {e}"))?;
            let _ = tcp.set_nodelay(true);

            if let Some(client_cfg) = tls_cfg {
                let connector = TlsConnector::from(client_cfg);
                let server_name = ServerName::try_from(sni.clone())
                    .map_err(|e| format!("Invalid TLS server name '{sni}': {e}"))?;
                let mut tls_stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| format!("mTLS handshake with {addr} failed: {e}"))?;
                Self::exchange_otel_logs_stream(&mut tls_stream, seq, &batch_owned).await
            } else {
                let mut tcp = tcp;
                Self::exchange_otel_logs_stream(&mut tcp, seq, &batch_owned).await
            }
        })
        .await
        .map_err(|_| {
            format!(
                "MuObserve OTel log flush timed out after {}ms",
                self.config.timeout_ms
            )
        })?
    }

    /// Executes `send_otel_logs_async` safely from a synchronous context.
    pub fn send_otel_logs_blocking(&self, batch: &[OtelLogEntry]) -> Result<usize, String> {
        if batch.is_empty() {
            return Ok(0);
        }
        let this = self.clone();
        let batch_clone = batch.to_vec();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("Failed to build OTel log flush runtime: {e}"))?;
            rt.block_on(this.send_otel_logs_async(&batch_clone))
        })
        .join()
        .map_err(|_| "MuObserve OTel log flush worker thread panicked".to_string())?
    }

    async fn exchange_otel_spans_stream<S>(
        stream: &mut S,
        seq: u64,
        batch: &[OtelSpanEntry],
    ) -> Result<usize, String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let payload = encode_otel_spans_ipc(batch)
            .map_err(|e| format!("Arrow OTel span encode error: {e}"))?;
        let flags = if batch.iter().any(|s| s.status_code == "ERROR") {
            FLAG_HIGH_PRIORITY
        } else {
            0
        };
        let header = IpcHeader::new(MSG_TYPE_ARROW_OTEL_SPANS, payload.len() as u32, flags, seq);
        write_frame(stream, &header, &payload)
            .await
            .map_err(|e| format!("Write MUOB OTel span frame error: {e}"))?;
        if let Ok((resp_hdr, resp_payload)) = read_frame(stream).await {
            if resp_hdr.msg_type == MSG_TYPE_WAL_ACK || resp_hdr.msg_type == MSG_TYPE_FORY_CONTROL {
                if let Ok(ControlRpcEnvelope::WalAck(ack)) = decode_control_envelope(&resp_payload)
                {
                    if !ack.ok {
                        return Err(ack
                            .error_message
                            .unwrap_or_else(|| "MuObserve rejected OTel span batch".to_string()));
                    }
                }
            }
        }
        let _ = tokio::io::AsyncWriteExt::shutdown(stream).await;
        Ok(batch.len())
    }

    /// Sends a batch of [`OtelSpanEntry`] records to `MuObserve` via `MSG_TYPE_ARROW_OTEL_SPANS`.
    pub async fn send_otel_spans_async(&self, batch: &[OtelSpanEntry]) -> Result<usize, String> {
        if batch.is_empty() {
            return Ok(0);
        }
        let timeout_dur = Duration::from_millis(self.config.timeout_ms.max(100));
        let seq = self.next_seq();
        let addr = self.config.endpoint_addr.clone();
        let tls_cfg = self.tls_client_config.clone();
        let sni = self
            .config
            .tls_server_name
            .clone()
            .unwrap_or_else(|| "muobserve.node-a.cluster.internal".to_string());
        let batch_owned = batch.to_vec();

        tokio::time::timeout(timeout_dur, async move {
            let tcp = TcpStream::connect(&addr)
                .await
                .map_err(|e| format!("Connect to {addr} failed: {e}"))?;
            let _ = tcp.set_nodelay(true);

            if let Some(client_cfg) = tls_cfg {
                let connector = TlsConnector::from(client_cfg);
                let server_name = ServerName::try_from(sni.clone())
                    .map_err(|e| format!("Invalid TLS server name '{sni}': {e}"))?;
                let mut tls_stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| format!("mTLS handshake with {addr} failed: {e}"))?;
                Self::exchange_otel_spans_stream(&mut tls_stream, seq, &batch_owned).await
            } else {
                let mut tcp = tcp;
                Self::exchange_otel_spans_stream(&mut tcp, seq, &batch_owned).await
            }
        })
        .await
        .map_err(|_| {
            format!(
                "MuObserve OTel span flush timed out after {}ms",
                self.config.timeout_ms
            )
        })?
    }

    /// Executes `send_otel_spans_async` safely from a synchronous context.
    pub fn send_otel_spans_blocking(&self, batch: &[OtelSpanEntry]) -> Result<usize, String> {
        if batch.is_empty() {
            return Ok(0);
        }
        let this = self.clone();
        let batch_clone = batch.to_vec();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("Failed to build OTel span flush runtime: {e}"))?;
            rt.block_on(this.send_otel_spans_async(&batch_clone))
        })
        .join()
        .map_err(|_| "MuObserve OTel span flush worker thread panicked".to_string())?
    }

    fn query_internal_snapshot(
        &self,
        parent_repo_key: &str,
        branch_key: &str,
        submodule_key: &str,
    ) -> Option<CentralSubmoduleSnapshot> {
        let req = ControlRpcEnvelope::QuerySubmoduleSnapshotsReq(QuerySubmoduleSnapshotsRequest {
            request_id: self.next_request_id("q-internal"),
            parent_repo_key: Some(parent_repo_key.to_string()),
            submodule_key: Some(submodule_key.to_ascii_lowercase()),
            branch_key: Some(branch_key.to_string()),
        });
        match self.send_rpc_blocking(&req) {
            Ok(ControlRpcEnvelope::QuerySubmoduleSnapshotsResp(resp)) => {
                resp.snapshots.into_iter().next()
            }
            _ => None,
        }
    }

    fn upsert_internal_snapshot(&self, snap: CentralSubmoduleSnapshot) -> bool {
        let req = ControlRpcEnvelope::UpsertJobBatchReq(UpsertJobBatchRequest {
            request_id: self.next_request_id("u-internal"),
            records: Vec::new(),
            branch_snapshots: Vec::new(),
            submodule_snapshots: vec![snap],
        });
        matches!(
            self.send_rpc_blocking(&req),
            Ok(ControlRpcEnvelope::UpsertJobRecordResp(ack)) if ack.accepted
        )
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    fn next_request_id(&self, prefix: &str) -> String {
        format!("{prefix}-{}", self.next_seq())
    }

    async fn exchange_stream<S>(
        stream: &mut S,
        seq: u64,
        req: &ControlRpcEnvelope,
    ) -> Result<ControlRpcEnvelope, String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let payload =
            encode_control_envelope(req).map_err(|e| format!("Fory encode error: {e}"))?;
        let header = IpcHeader::new(MSG_TYPE_FORY_CONTROL, payload.len() as u32, 0, seq);
        write_frame(stream, &header, &payload)
            .await
            .map_err(|e| format!("Write MUOB frame error: {e}"))?;
        let (resp_hdr, resp_payload) = read_frame(stream)
            .await
            .map_err(|e| format!("Read MUOB frame error: {e}"))?;
        let _ = tokio::io::AsyncWriteExt::shutdown(stream).await;
        if resp_hdr.msg_type != MSG_TYPE_FORY_CONTROL {
            return Err(format!(
                "Unexpected response frame msg_type: {:#06x}",
                resp_hdr.msg_type
            ));
        }
        decode_control_envelope(&resp_payload).map_err(|e| format!("Fory decode error: {e}"))
    }

    /// Sends a single [`ControlRpcEnvelope`] request to `MuObserve` and awaits the response envelope.
    pub async fn send_rpc_async(
        &self,
        req: &ControlRpcEnvelope,
    ) -> Result<ControlRpcEnvelope, String> {
        let timeout_dur = Duration::from_millis(self.config.timeout_ms.max(100));
        let seq = self.next_seq();
        let addr = self.config.endpoint_addr.clone();
        let tls_cfg = self.tls_client_config.clone();
        let sni = self
            .config
            .tls_server_name
            .clone()
            .unwrap_or_else(|| "muobserve.node-a.cluster.internal".to_string());

        tokio::time::timeout(timeout_dur, async move {
            let tcp = TcpStream::connect(&addr)
                .await
                .map_err(|e| format!("Connect to {addr} failed: {e}"))?;
            let _ = tcp.set_nodelay(true);

            if let Some(client_cfg) = tls_cfg {
                let connector = TlsConnector::from(client_cfg);
                let server_name = ServerName::try_from(sni.clone())
                    .map_err(|e| format!("Invalid TLS server name '{sni}': {e}"))?;
                let mut tls_stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| format!("mTLS handshake with {addr} failed: {e}"))?;
                Self::exchange_stream(&mut tls_stream, seq, req).await
            } else {
                let mut tcp = tcp;
                Self::exchange_stream(&mut tcp, seq, req).await
            }
        })
        .await
        .map_err(|_| format!("MuObserve RPC timed out after {}ms", self.config.timeout_ms))?
    }

    /// Executes `send_rpc_async` safely from a synchronous context (even when called inside
    /// an active single-threaded or multi-threaded Tokio runtime).
    pub fn send_rpc_blocking(
        &self,
        req: &ControlRpcEnvelope,
    ) -> Result<ControlRpcEnvelope, String> {
        let this = self.clone();
        let req_clone = req.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("Failed to build RPC runtime: {e}"))?;
            rt.block_on(this.send_rpc_async(&req_clone))
        })
        .join()
        .map_err(|_| "MuObserve RPC worker thread panicked".to_string())?
    }

    fn query_jobs_filtered(
        &self,
        repo_key: Option<String>,
        branch_key: Option<String>,
        job_id: Option<String>,
        limit: u32,
    ) -> Vec<CentralJobRecord> {
        let req = ControlRpcEnvelope::QueryJobsHistoryReq(QueryJobsHistoryRequest {
            request_id: self.next_request_id("q-jobs"),
            repo_key,
            branch_key,
            job_id,
            limit,
        });
        match self.send_rpc_blocking(&req) {
            Ok(ControlRpcEnvelope::QueryJobsHistoryResp(resp)) => resp.records,
            Ok(other) => {
                warn!("Unexpected RPC response for QueryJobsHistoryReq: {other:?}");
                Vec::new()
            }
            Err(e) => {
                debug!(error = %e, "MuObserve QueryJobsHistoryReq failed");
                Vec::new()
            }
        }
    }
}

/// Computes the updated [`CentralBranchSnapshot`] given an optional existing snapshot,
/// the newly upserted [`JobRecord`], and a fallback lookup when a `Skipped` job supersedes the active job.
pub fn compute_next_branch_snapshot<F>(
    existing: Option<&CentralBranchSnapshot>,
    record: &JobRecord,
    fallback_unskipped: F,
) -> Option<CentralBranchSnapshot>
where
    F: FnOnce(&str, &str) -> Option<(String, String, i64)>,
{
    let record_json = serde_json::to_string(record).ok()?;
    let repo_key = record.job.repo_name.to_ascii_lowercase();
    let branch_key = normalize_ref(&record.job.ref_name).to_ascii_lowercase();
    let queued_at_us = record.job.queued_at.timestamp_micros();

    let (
        mut active_id,
        mut active_json,
        mut active_q_us,
        mut comp_id,
        mut comp_json,
        mut comp_q_us,
    ) = existing
        .map(|s| {
            (
                s.latest_active_job_id.clone(),
                s.latest_active_json.clone(),
                s.latest_active_queued_us,
                s.latest_completed_job_id.clone(),
                s.latest_completed_json.clone(),
                s.latest_completed_queued_us,
            )
        })
        .unwrap_or((None, None, None, None, None, None));

    let is_skipped = matches!(record.status, JobStatus::Skipped { .. });
    let is_completed = matches!(
        record.status,
        JobStatus::Completed { .. } | JobStatus::Failed { .. }
    );

    if is_skipped {
        if active_id.as_deref() == Some(record.job.id.as_str()) {
            if let Some((fb_id, fb_json, fb_q)) = fallback_unskipped(&repo_key, &branch_key) {
                active_id = Some(fb_id);
                active_json = Some(fb_json);
                active_q_us = Some(fb_q);
            } else {
                active_id = comp_id.clone();
                active_json = comp_json.clone();
                active_q_us = comp_q_us;
            }
        }
    } else {
        let should_update_active = active_id.is_none()
            || active_id.as_deref() == Some(record.job.id.as_str())
            || queued_at_us >= active_q_us.unwrap_or(i64::MIN);

        if should_update_active {
            active_id = Some(record.job.id.clone());
            active_json = Some(record_json.clone());
            active_q_us = Some(queued_at_us);
        }

        if is_completed {
            let should_update_comp = comp_id.is_none()
                || comp_id.as_deref() == Some(record.job.id.as_str())
                || queued_at_us >= comp_q_us.unwrap_or(i64::MIN);

            if should_update_comp {
                comp_id = Some(record.job.id.clone());
                comp_json = Some(record_json);
                comp_q_us = Some(queued_at_us);
            }
        }
    }

    if active_id.is_some() || comp_id.is_some() {
        Some(CentralBranchSnapshot {
            repo_key,
            branch_key,
            repo_name: record.job.repo_name.clone(),
            ref_name: record.job.ref_name.clone(),
            latest_active_job_id: active_id,
            latest_active_json: active_json,
            latest_active_queued_us: active_q_us,
            latest_completed_job_id: comp_id,
            latest_completed_json: comp_json,
            latest_completed_queued_us: comp_q_us,
        })
    } else {
        None
    }
}

/// Computes updated [`CentralSubmoduleSnapshot`] entries for `(parent_repo_key, branch_key)`
/// given existing submodule snapshots and the newly upserted [`JobRecord`].
#[must_use]
pub fn compute_next_submodule_snapshots(
    existing_for_branch: &[CentralSubmoduleSnapshot],
    record: &JobRecord,
) -> Vec<CentralSubmoduleSnapshot> {
    let parent_repo_key = record.job.repo_name.to_ascii_lowercase();
    let branch_key = normalize_ref(&record.job.ref_name).to_ascii_lowercase();
    let queued_at_us = record.job.queued_at.timestamp_micros();
    let is_skipped = matches!(record.status, JobStatus::Skipped { .. });
    let is_completed = matches!(
        record.status,
        JobStatus::Completed { .. } | JobStatus::Failed { .. }
    );

    let mut by_sub_key: BTreeMap<String, CentralSubmoduleSnapshot> = existing_for_branch
        .iter()
        .filter(|s| s.parent_repo_key == parent_repo_key && s.branch_key == branch_key)
        .map(|s| (s.submodule_key.clone(), s.clone()))
        .collect();

    if let Some(ref metrics) = record.metrics {
        for (sub_name, sub) in &metrics.submodules {
            let Some(sub_record) = extract_submodule_job(record, sub_name) else {
                continue;
            };
            let Ok(sub_json) = serde_json::to_string(&sub_record) else {
                continue;
            };

            let sub_short = sub_name
                .rsplit_once('/')
                .map(|(_, r)| r)
                .unwrap_or(sub_name)
                .to_ascii_lowercase();
            let path_short = sub
                .path
                .rsplit_once('/')
                .map(|(_, r)| r)
                .unwrap_or(&sub.path)
                .to_ascii_lowercase();

            let existing = by_sub_key.get(&sub_short);
            let (mut act_id, mut act_json, mut act_q_us, mut comp_id, mut comp_json, mut comp_q_us) =
                existing
                    .map(|s| {
                        (
                            s.latest_active_job_id.clone(),
                            s.latest_active_json.clone(),
                            s.latest_active_queued_us,
                            s.latest_completed_job_id.clone(),
                            s.latest_completed_json.clone(),
                            s.latest_completed_queued_us,
                        )
                    })
                    .unwrap_or((None, None, None, None, None, None));

            if !is_skipped {
                let should_update_act = act_id.is_none()
                    || act_id.as_deref() == Some(record.job.id.as_str())
                    || queued_at_us >= act_q_us.unwrap_or(i64::MIN);

                if should_update_act {
                    act_id = Some(record.job.id.clone());
                    act_json = Some(sub_json.clone());
                    act_q_us = Some(queued_at_us);
                }

                if is_completed || comp_id.is_none() {
                    let should_update_comp = comp_id.is_none()
                        || comp_id.as_deref() == Some(record.job.id.as_str())
                        || queued_at_us >= comp_q_us.unwrap_or(i64::MIN);

                    if should_update_comp {
                        comp_id = Some(record.job.id.clone());
                        comp_json = Some(sub_json);
                        comp_q_us = Some(queued_at_us);
                    }
                }
            }

            by_sub_key.insert(
                sub_short.clone(),
                CentralSubmoduleSnapshot {
                    parent_repo_key: parent_repo_key.clone(),
                    branch_key: branch_key.clone(),
                    submodule_key: sub_short,
                    submodule_path_key: path_short,
                    latest_active_job_id: act_id,
                    latest_active_json: act_json,
                    latest_active_queued_us: act_q_us,
                    latest_completed_job_id: comp_id,
                    latest_completed_json: comp_json,
                    latest_completed_queued_us: comp_q_us,
                },
            );
        }
    } else {
        let owner = record
            .job
            .repo_name
            .split_once('/')
            .map(|(o, _)| o)
            .unwrap_or("LMA1980");

        for snap in by_sub_key.values_mut() {
            if is_skipped {
                if snap.latest_active_job_id.as_deref() == Some(record.job.id.as_str()) {
                    snap.latest_active_job_id = snap.latest_completed_job_id.clone();
                    snap.latest_active_json = snap.latest_completed_json.clone();
                    snap.latest_active_queued_us = snap.latest_completed_queued_us;
                }
            } else if matches!(record.status, JobStatus::Queued | JobStatus::Running { .. }) {
                let should_update = snap.latest_active_job_id.is_none()
                    || snap.latest_active_job_id.as_deref() == Some(record.job.id.as_str())
                    || queued_at_us >= snap.latest_active_queued_us.unwrap_or(i64::MIN);

                if should_update {
                    let sub_job = Job {
                        id: format!("{}-{}", record.job.id, snap.submodule_key),
                        event_type: record.job.event_type.clone(),
                        repo_name: format!("{}/{}", owner, snap.submodule_key),
                        clone_url: String::new(),
                        commit_sha: record.job.commit_sha.clone(),
                        ref_name: record.job.ref_name.clone(),
                        sender: record.job.sender.clone(),
                        pr_number: record.job.pr_number,
                        queued_at: record.job.queued_at,
                    };
                    let synth_rec = JobRecord {
                        job: sub_job,
                        status: record.status.clone(),
                        log_file: record.log_file.clone(),
                        updated_at: record.updated_at,
                        metrics: None,
                        stages: Vec::new(),
                    };
                    if let Ok(s_json) = serde_json::to_string(&synth_rec) {
                        snap.latest_active_job_id = Some(record.job.id.clone());
                        snap.latest_active_json = Some(s_json);
                        snap.latest_active_queued_us = Some(queued_at_us);
                    }
                }
            }
        }
    }

    by_sub_key.into_values().collect()
}

pub(crate) fn resolve_direct_repo_from_snapshots(
    snapshots: &[CentralBranchSnapshot],
    repo: &str,
    branch: Option<&str>,
) -> (Option<JobRecord>, Option<JobRecord>) {
    let repo_lower = repo.to_ascii_lowercase();
    let suffix = format!("/{repo_lower}");
    let branch_norm = branch.map(|b| normalize_ref(b).to_ascii_lowercase());

    let mut matching: Vec<&CentralBranchSnapshot> = snapshots
        .iter()
        .filter(|s| {
            let repo_matches = s.repo_key == repo_lower || s.repo_key.ends_with(&suffix);
            let branch_matches = branch_norm
                .as_ref()
                .map(|b| &s.branch_key == b)
                .unwrap_or(true);
            repo_matches && branch_matches
        })
        .collect();

    matching.sort_by(|a, b| {
        if branch_norm.is_none() {
            let a_main = u8::from(a.branch_key != "main");
            let b_main = u8::from(b.branch_key != "main");
            if a_main != b_main {
                return a_main.cmp(&b_main);
            }
        }
        let a_ts = a
            .latest_active_queued_us
            .or(a.latest_completed_queued_us)
            .unwrap_or(0);
        let b_ts = b
            .latest_active_queued_us
            .or(b.latest_completed_queued_us)
            .unwrap_or(0);
        b_ts.cmp(&a_ts)
    });

    let Some(best) = matching.first() else {
        return (None, None);
    };

    let active = best
        .latest_active_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<JobRecord>(s).ok());
    let completed = best
        .latest_completed_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<JobRecord>(s).ok());
    (active, completed)
}

pub(crate) fn resolve_submodule_from_snapshots(
    sub_snapshots: &[CentralSubmoduleSnapshot],
    branch_snapshots: &[CentralBranchSnapshot],
    parent_repo: Option<&str>,
    submodule: &str,
    branch: Option<&str>,
) -> (Option<JobRecord>, Option<JobRecord>) {
    let clean_target = submodule
        .rsplit_once('/')
        .map(|(_, r)| r)
        .unwrap_or(submodule)
        .to_ascii_lowercase();
    let norm_underscore = clean_target.replace('-', "_");
    let norm_hyphen = clean_target.replace('_', "-");
    let branch_norm = branch.map(|b| normalize_ref(b).to_ascii_lowercase());
    let parent_key = parent_repo.map(|p| p.to_ascii_lowercase());
    let parent_suffix = parent_key.as_ref().map(|pk| format!("/{pk}"));

    let owner = parent_repo
        .and_then(|p| p.split_once('/').map(|(o, _)| o))
        .or_else(|| submodule.split_once('/').map(|(o, _)| o))
        .unwrap_or("LMA1980");

    let mut matching: Vec<&CentralSubmoduleSnapshot> = sub_snapshots
        .iter()
        .filter(|s| {
            let parent_matches = match (&parent_key, &parent_suffix) {
                (Some(pk), Some(ps)) => &s.parent_repo_key == pk || s.parent_repo_key.ends_with(ps),
                _ => true,
            };
            let branch_matches = branch_norm
                .as_ref()
                .map(|b| &s.branch_key == b)
                .unwrap_or(true);
            let sub_matches = s.submodule_key == clean_target
                || s.submodule_key == norm_underscore
                || s.submodule_key == norm_hyphen
                || s.submodule_path_key == clean_target;
            parent_matches && branch_matches && sub_matches
        })
        .collect();

    matching.sort_by(|a, b| {
        if branch_norm.is_none() {
            let a_main = u8::from(a.branch_key != "main");
            let b_main = u8::from(b.branch_key != "main");
            if a_main != b_main {
                return a_main.cmp(&b_main);
            }
        }
        let a_ts = a
            .latest_active_queued_us
            .or(a.latest_completed_queued_us)
            .unwrap_or(0);
        let b_ts = b
            .latest_active_queued_us
            .or(b.latest_completed_queued_us)
            .unwrap_or(0);
        b_ts.cmp(&a_ts)
    });

    let parse_and_fix_owner = |opt_s: Option<&str>| -> Option<JobRecord> {
        let mut rec: JobRecord = serde_json::from_str(opt_s?).ok()?;
        let short = rec
            .job
            .repo_name
            .rsplit_once('/')
            .map(|(_, r)| r)
            .unwrap_or(&rec.job.repo_name);
        rec.job.repo_name = format!("{owner}/{short}");
        Some(rec)
    };

    if let Some(best) = matching.first() {
        let active = parse_and_fix_owner(best.latest_active_json.as_deref());
        let completed = parse_and_fix_owner(best.latest_completed_json.as_deref());
        if active.is_some() || completed.is_some() {
            return (active, completed);
        }
    }

    if parent_repo.is_some() {
        let direct_candidate = format!("{owner}/{clean_target}");
        let (d_act, d_comp) =
            resolve_direct_repo_from_snapshots(branch_snapshots, &direct_candidate, branch);
        if d_act.is_some() || d_comp.is_some() {
            return (d_act, d_comp);
        }
        if !clean_target.starts_with("k3-") {
            let k3_candidate = format!("{owner}/k3-{clean_target}");
            let (k_act, k_comp) =
                resolve_direct_repo_from_snapshots(branch_snapshots, &k3_candidate, branch);
            if k_act.is_some() || k_comp.is_some() {
                return (k_act, k_comp);
            }
        }
    }

    (None, None)
}

impl ControllerStorage for MuObserveRemoteStorage {
    fn upsert_record(&self, record: &JobRecord) {
        self.register_job_commit_sha(&record.job.id, &record.job.commit_sha);
        let Some(central_record) = CatalogStore::to_central_job_record(record) else {
            return;
        };
        let repo_key = central_record.repo_key.clone();
        let branch_key = central_record.branch_key.clone();

        let existing_branch = self
            .load_branch_snapshots(Some(&repo_key), Some(&branch_key))
            .into_iter()
            .next();
        let existing_subs = self.load_submodule_snapshots(Some(&repo_key), None, Some(&branch_key));

        let next_branch =
            compute_next_branch_snapshot(existing_branch.as_ref(), record, |rk, bk| {
                self.query_jobs_filtered(Some(rk.to_string()), Some(bk.to_string()), None, 25)
                    .into_iter()
                    .find(|j| j.status_state != "Skipped" && j.job_id != record.job.id)
                    .map(|j| (j.job_id, j.record_json, j.queued_at_us))
            });
        let next_subs = compute_next_submodule_snapshots(&existing_subs, record);

        let req = ControlRpcEnvelope::UpsertJobRecordReq(UpsertJobRecordRequest {
            request_id: self.next_request_id("upsert-job"),
            record: central_record,
            branch_snapshot: next_branch,
            submodule_snapshots: next_subs,
        });

        if let Err(e) = self.send_rpc_blocking(&req) {
            warn!(job_id = %record.job.id, error = %e, "MuObserve UpsertJobRecordReq failed");
        }
    }

    fn upsert_records_batch(&self, records: &[JobRecord]) {
        if records.is_empty() {
            return;
        }

        let mut central_records: Vec<CentralJobRecord> = Vec::with_capacity(records.len());
        let mut branch_map: BTreeMap<(String, String), CentralBranchSnapshot> = self
            .load_branch_snapshots(None, None)
            .into_iter()
            .map(|b| ((b.repo_key.clone(), b.branch_key.clone()), b))
            .collect();
        let mut sub_map: BTreeMap<(String, String, String), CentralSubmoduleSnapshot> = self
            .load_submodule_snapshots(None, None, None)
            .into_iter()
            .map(|s| {
                (
                    (
                        s.parent_repo_key.clone(),
                        s.branch_key.clone(),
                        s.submodule_key.clone(),
                    ),
                    s,
                )
            })
            .collect();

        // Keep an ordered history per (repo_key, branch_key) for Skipped fallback resolution
        let mut history_by_branch: BTreeMap<(String, String), Vec<CentralJobRecord>> =
            BTreeMap::new();

        for rec in records {
            self.register_job_commit_sha(&rec.job.id, &rec.job.commit_sha);
            let Some(central) = CatalogStore::to_central_job_record(rec) else {
                continue;
            };
            let key = (central.repo_key.clone(), central.branch_key.clone());
            history_by_branch
                .entry(key.clone())
                .or_default()
                .push(central.clone());

            let existing_branch = branch_map.get(&key).cloned();
            let history_ref = history_by_branch.get(&key);
            if let Some(next_b) =
                compute_next_branch_snapshot(existing_branch.as_ref(), rec, |_rk, _bk| {
                    history_ref.and_then(|list| {
                        list.iter()
                            .filter(|j| j.status_state != "Skipped" && j.job_id != rec.job.id)
                            .max_by_key(|j| (j.queued_at_us, j.updated_at_us))
                            .map(|j| (j.job_id.clone(), j.record_json.clone(), j.queued_at_us))
                    })
                })
            {
                branch_map.insert(key.clone(), next_b);
            }

            let existing_subs: Vec<CentralSubmoduleSnapshot> = sub_map
                .iter()
                .filter(|((prk, bk, _), _)| prk == &key.0 && bk == &key.1)
                .map(|(_, v)| v.clone())
                .collect();
            for next_s in compute_next_submodule_snapshots(&existing_subs, rec) {
                sub_map.insert(
                    (
                        next_s.parent_repo_key.clone(),
                        next_s.branch_key.clone(),
                        next_s.submodule_key.clone(),
                    ),
                    next_s,
                );
            }

            central_records.push(central);
        }

        let req = ControlRpcEnvelope::UpsertJobBatchReq(UpsertJobBatchRequest {
            request_id: self.next_request_id("upsert-batch"),
            records: central_records,
            branch_snapshots: branch_map.into_values().collect(),
            submodule_snapshots: sub_map.into_values().collect(),
        });

        if let Err(e) = self.send_rpc_blocking(&req) {
            warn!(count = records.len(), error = %e, "MuObserve UpsertJobBatchReq failed");
        }
    }

    fn load_recent_jobs(&self, limit: usize) -> Vec<JobRecord> {
        self.query_jobs_filtered(None, None, None, limit as u32)
            .into_iter()
            .filter_map(|r| serde_json::from_str::<JobRecord>(&r.record_json).ok())
            .collect()
    }

    fn load_branch_snapshots(
        &self,
        repo_key: Option<&str>,
        branch_key: Option<&str>,
    ) -> Vec<CentralBranchSnapshot> {
        let req = ControlRpcEnvelope::QueryBranchSnapshotsReq(QueryBranchSnapshotsRequest {
            request_id: self.next_request_id("q-branch"),
            repo_key: repo_key.map(|r| r.to_ascii_lowercase()),
            branch_key: branch_key.map(|b| normalize_ref(b).to_ascii_lowercase()),
        });
        match self.send_rpc_blocking(&req) {
            Ok(ControlRpcEnvelope::QueryBranchSnapshotsResp(resp)) => resp.snapshots,
            Ok(other) => {
                warn!("Unexpected RPC response for QueryBranchSnapshotsReq: {other:?}");
                Vec::new()
            }
            Err(e) => {
                debug!(error = %e, "MuObserve QueryBranchSnapshotsReq failed");
                Vec::new()
            }
        }
    }

    fn load_submodule_snapshots(
        &self,
        parent_repo_key: Option<&str>,
        submodule_key: Option<&str>,
        branch_key: Option<&str>,
    ) -> Vec<CentralSubmoduleSnapshot> {
        let req = ControlRpcEnvelope::QuerySubmoduleSnapshotsReq(QuerySubmoduleSnapshotsRequest {
            request_id: self.next_request_id("q-sub"),
            parent_repo_key: parent_repo_key.map(|p| p.to_ascii_lowercase()),
            submodule_key: submodule_key.map(|s| {
                s.rsplit_once('/')
                    .map(|(_, r)| r)
                    .unwrap_or(s)
                    .to_ascii_lowercase()
            }),
            branch_key: branch_key.map(|b| normalize_ref(b).to_ascii_lowercase()),
        });
        match self.send_rpc_blocking(&req) {
            Ok(ControlRpcEnvelope::QuerySubmoduleSnapshotsResp(resp)) => resp
                .snapshots
                .into_iter()
                .filter(|s| parent_repo_key.is_some() || !s.parent_repo_key.starts_with("__ar_"))
                .collect(),
            Ok(other) => {
                warn!("Unexpected RPC response for QuerySubmoduleSnapshotsReq: {other:?}");
                Vec::new()
            }
            Err(e) => {
                debug!(error = %e, "MuObserve QuerySubmoduleSnapshotsReq failed");
                Vec::new()
            }
        }
    }

    fn get_job(&self, job_id: &str) -> Option<JobRecord> {
        self.query_jobs_filtered(None, None, Some(job_id.to_string()), 1)
            .into_iter()
            .next()
            .and_then(|r| serde_json::from_str::<JobRecord>(&r.record_json).ok())
    }

    fn find_card_context(
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

    fn find_submodule_card_context(
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

    fn evaluate_regression_gate(
        &self,
        req: &RegressionGateRequest,
    ) -> Option<RegressionGateReport> {
        let envelope = ControlRpcEnvelope::RegressionGateReq(req.clone());
        match self.send_rpc_blocking(&envelope) {
            Ok(ControlRpcEnvelope::RegressionGateResp(report)) => Some(report),
            Ok(other) => {
                warn!("Unexpected RPC response for RegressionGateReq: {other:?}");
                None
            }
            Err(e) => {
                debug!(error = %e, "MuObserve RegressionGateReq failed");
                None
            }
        }
    }

    fn append_structured_log_entries(&self, job_id: &str, entries: &[mu_ci_ipc::LogEntry]) {
        let added = self.append_structured_log_entries_sync(job_id, entries);
        if added == 0 {
            return;
        }
        let key = job_id.to_ascii_lowercase();
        let should_flush_now = self
            .last_log_flush
            .lock()
            .ok()
            .and_then(|g| g.get(&key).copied())
            .map(|t| t.elapsed() >= BUFFERED_LOG_FLUSH_INTERVAL)
            .unwrap_or(false);
        if should_flush_now {
            if let Err(e) = self.flush_dirty_logs_blocking(Some(job_id)) {
                debug!(job_id = %job_id, error = %e, "MuObserve periodic OTel log flush failed");
            }
        }
    }

    fn append_log_lines(&self, job_id: &str, chunk: &str) {
        let _ = MuObserveRemoteStorage::append_log_lines(self, job_id, chunk);
    }

    fn append_job_log(&self, job_id: &str, chunk: &str) {
        let added = MuObserveRemoteStorage::append_log_lines(self, job_id, chunk);
        if added > 0 {
            if let Err(e) = self.flush_dirty_logs_blocking(Some(job_id)) {
                debug!(job_id = %job_id, error = %e, "MuObserve immediate OTel log flush failed");
            }
        }
    }

    fn append_job_log_buffered(&self, job_id: &str, chunk: &str) {
        let added = MuObserveRemoteStorage::append_log_lines(self, job_id, chunk);
        if added == 0 {
            return;
        }
        let key = job_id.to_ascii_lowercase();
        let should_flush_now = self
            .last_log_flush
            .lock()
            .ok()
            .and_then(|g| g.get(&key).copied())
            .map(|t| t.elapsed() >= BUFFERED_LOG_FLUSH_INTERVAL)
            .unwrap_or(false);
        if should_flush_now {
            if let Err(e) = self.flush_dirty_logs_blocking(Some(job_id)) {
                debug!(job_id = %job_id, error = %e, "MuObserve buffered OTel log flush failed");
            }
        }
    }

    fn flush_dirty_logs(&self) {
        if let Err(e) = self.flush_dirty_logs_blocking(None) {
            debug!(error = %e, "MuObserve flush_dirty_logs failed");
        }
    }

    fn flush_job_log(&self, job_id: Option<&str>) {
        if let Err(e) = self.flush_dirty_logs_blocking(job_id) {
            debug!(job_id = ?job_id, error = %e, "MuObserve flush_job_log failed");
        }
    }

    fn get_job_log(&self, job_id: &str) -> Option<String> {
        let key = job_id.to_ascii_lowercase();
        let is_local_writer = self
            .last_log_flush
            .lock()
            .ok()
            .is_some_and(|g| g.contains_key(&key));
        let cached = self
            .log_buffer
            .read()
            .ok()
            .and_then(|g| g.get(&key).cloned())
            .filter(|s| !s.is_empty());
        if is_local_writer {
            if let Some(local) = cached {
                return Some(local);
            }
        }
        if let Some(remote_log) = self
            .query_internal_snapshot(INTERNAL_LOG_REPO_KEY, "log", &key)
            .and_then(|s| s.latest_active_json)
            .filter(|s| !s.is_empty())
        {
            if cached.as_ref().is_none_or(|c| remote_log.len() >= c.len()) {
                if let Ok(mut guard) = self.log_buffer.write() {
                    guard.insert(key, remote_log.clone());
                }
                return Some(remote_log);
            }
        }
        cached
    }

    fn try_acquire_or_renew_lease(&self, holder_id: &str, ttl_secs: u64, force: bool) -> bool {
        let now_us = chrono::Utc::now().timestamp_micros();
        let ttl_us = (ttl_secs.max(1) as i64).saturating_mul(1_000_000);
        let existing = self.get_leader_lease();
        let epoch = match existing {
            None => 1,
            Some(ref lease) if lease.holder_id == holder_id => lease.epoch,
            Some(ref lease) if force || lease.is_expired(now_us) => lease.epoch.saturating_add(1),
            Some(_) => return false,
        };

        let next_lease = LeaderLease {
            holder_id: holder_id.to_string(),
            acquired_at_us: now_us,
            expires_at_us: now_us.saturating_add(ttl_us),
            epoch,
        };
        let Ok(json_str) = serde_json::to_string(&next_lease) else {
            return false;
        };

        self.upsert_internal_snapshot(CentralSubmoduleSnapshot {
            parent_repo_key: INTERNAL_LEASE_REPO_KEY.to_string(),
            branch_key: "lease".to_string(),
            submodule_key: "active_leader".to_string(),
            submodule_path_key: "lease".to_string(),
            latest_active_job_id: Some(holder_id.to_string()),
            latest_active_json: Some(json_str),
            latest_active_queued_us: Some(now_us),
            latest_completed_job_id: None,
            latest_completed_json: None,
            latest_completed_queued_us: None,
        })
    }

    fn release_lease(&self, holder_id: &str) {
        let Some(mut existing) = self.get_leader_lease() else {
            return;
        };
        if existing.holder_id != holder_id {
            return;
        }
        existing.expires_at_us = 0;
        if let Ok(json_str) = serde_json::to_string(&existing) {
            let _ = self.upsert_internal_snapshot(CentralSubmoduleSnapshot {
                parent_repo_key: INTERNAL_LEASE_REPO_KEY.to_string(),
                branch_key: "lease".to_string(),
                submodule_key: "active_leader".to_string(),
                submodule_path_key: "lease".to_string(),
                latest_active_job_id: Some(holder_id.to_string()),
                latest_active_json: Some(json_str),
                latest_active_queued_us: Some(0),
                latest_completed_job_id: None,
                latest_completed_json: None,
                latest_completed_queued_us: None,
            });
        }
    }

    fn get_leader_lease(&self) -> Option<LeaderLease> {
        let snap =
            self.query_internal_snapshot(INTERNAL_LEASE_REPO_KEY, "lease", "active_leader")?;
        let json_str = snap.latest_active_json?;
        serde_json::from_str::<LeaderLease>(&json_str).ok()
    }

    fn save_console_registry(&self, registry_json: &str) {
        let now_us = chrono::Utc::now().timestamp_micros();
        let _ = self.upsert_internal_snapshot(CentralSubmoduleSnapshot {
            parent_repo_key: INTERNAL_CONSOLE_REPO_KEY.to_string(),
            branch_key: "console".to_string(),
            submodule_key: "registry".to_string(),
            submodule_path_key: "console".to_string(),
            latest_active_job_id: Some("registry".to_string()),
            latest_active_json: Some(registry_json.to_string()),
            latest_active_queued_us: Some(now_us),
            latest_completed_job_id: None,
            latest_completed_json: None,
            latest_completed_queued_us: None,
        });
    }

    fn load_console_registry(&self) -> Option<String> {
        self.query_internal_snapshot(INTERNAL_CONSOLE_REPO_KEY, "console", "registry")
            .and_then(|s| s.latest_active_json)
            .filter(|s| !s.is_empty())
    }

    fn configure_auth_state_path(&self, path: &Path) {
        if let Some(remote_json) = self
            .query_internal_snapshot(INTERNAL_PLATFORM_AUTH_REPO_KEY, "platform", "auth")
            .and_then(|s| s.latest_active_json)
            .filter(|s| !s.is_empty())
        {
            self.auth_store
                .import_platform_auth_json_if_newer(&remote_json);
        }
        self.auth_store
            .configure_auth_state_path(path.to_path_buf());
    }

    fn auth_catalog(&self) -> Option<&CatalogStore> {
        if let Some(remote_json) = self
            .query_internal_snapshot(INTERNAL_PLATFORM_AUTH_REPO_KEY, "platform", "auth")
            .and_then(|s| s.latest_active_json)
            .filter(|s| !s.is_empty())
        {
            self.auth_store
                .import_platform_auth_json_if_newer(&remote_json);
        }
        Some(&self.auth_store)
    }

    fn sync_platform_auth_json(&self, json: &str) {
        let now_us = chrono::Utc::now().timestamp_micros();
        let _ = self.upsert_internal_snapshot(CentralSubmoduleSnapshot {
            parent_repo_key: INTERNAL_PLATFORM_AUTH_REPO_KEY.to_string(),
            branch_key: "platform".to_string(),
            submodule_key: "auth".to_string(),
            submodule_path_key: "platform".to_string(),
            latest_active_job_id: Some("state".to_string()),
            latest_active_json: Some(json.to_string()),
            latest_active_queued_us: Some(now_us),
            latest_completed_job_id: None,
            latest_completed_json: None,
            latest_completed_queued_us: None,
        });
    }

    fn seed_bootstrap_admins(&self, admins: &[String]) {
        self.auth_store.seed_bootstrap_admins(admins);
        if let Some(json) = self.auth_store.export_platform_auth_json() {
            self.sync_platform_auth_json(&json);
        }
    }

    fn create_auth_invite(&self, invite: &AuthInviteRecord) {
        self.auth_store.create_auth_invite(invite);
        if let Some(json) = self.auth_store.export_platform_auth_json() {
            self.sync_platform_auth_json(&json);
        }
    }

    fn get_auth_invite(&self, invite_id: &str) -> Option<AuthInviteRecord> {
        let _ = self.auth_catalog();
        self.auth_store.get_auth_invite(invite_id)
    }

    fn list_auth_invites(&self) -> Vec<AuthInviteRecord> {
        let _ = self.auth_catalog();
        self.auth_store.list_auth_invites()
    }

    fn redeem_auth_invite(
        &self,
        invite_id: &str,
        presented_hmac: &str,
        github_login: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthUserRecord, RedeemInviteError> {
        let res = self
            .auth_store
            .redeem_auth_invite(invite_id, presented_hmac, github_login, now);
        if res.is_ok() {
            if let Some(json) = self.auth_store.export_platform_auth_json() {
                self.sync_platform_auth_json(&json);
            }
        }
        res
    }

    fn get_auth_user(&self, github_login: &str) -> Option<AuthUserRecord> {
        let _ = self.auth_catalog();
        self.auth_store.get_auth_user(github_login)
    }

    fn list_auth_users(&self) -> Vec<AuthUserRecord> {
        let _ = self.auth_catalog();
        self.auth_store.list_auth_users()
    }

    fn revoke_auth_user(&self, github_login: &str) -> bool {
        let revoked = self.auth_store.revoke_auth_user(github_login);
        if revoked {
            if let Some(json) = self.auth_store.export_platform_auth_json() {
                self.sync_platform_auth_json(&json);
            }
        }
        revoked
    }

    fn emit_trace_spans(&self, spans: &[OtelSpanEntry]) {
        if spans.is_empty() {
            return;
        }
        if let Err(e) = self.send_otel_spans_blocking(spans) {
            debug!(error = %e, "MuObserve emit_trace_spans failed");
        }
    }
}

pub use crate::db::{
    AuthInviteRecord as StorageAuthInviteRecord, AuthInviteView as StorageAuthInviteView,
    AuthUserRecord as StorageAuthUserRecord, RedeemInviteError as StorageRedeemInviteError,
};

// ============================================================================
// Sub-task #44 (M3.057): Root W3C Trace Context & RegressionGateReport Scoring
// ============================================================================

/// Generates a deterministic root W3C [`TraceContext`] for a CI job from `(job_id, commit_sha)`.
#[must_use]
pub fn job_root_trace_context(job_id: &str, commit_sha: &str) -> TraceContext {
    let mut trace_hasher = Sha256::new();
    trace_hasher.update(b"muobserve-job-trace:");
    trace_hasher.update(job_id.as_bytes());
    trace_hasher.update(b":");
    trace_hasher.update(commit_sha.as_bytes());
    let trace_digest = trace_hasher.finalize();

    let mut trace_id = [0u8; 16];
    trace_id.copy_from_slice(&trace_digest[..16]);
    if trace_id == [0u8; 16] {
        trace_id[15] = 1;
    }

    let mut span_hasher = Sha256::new();
    span_hasher.update(b"muobserve-job-root-span:");
    span_hasher.update(job_id.as_bytes());
    span_hasher.update(b":");
    span_hasher.update(commit_sha.as_bytes());
    let span_digest = span_hasher.finalize();

    let mut span_id = [0u8; 8];
    span_id.copy_from_slice(&span_digest[..8]);
    if span_id == [0u8; 8] {
        span_id[7] = 1;
    }

    TraceContext {
        version: W3C_TRACEPARENT_VERSION,
        trace_id,
        span_id,
        trace_flags: TRACE_FLAG_SAMPLED,
    }
}

/// Formats the deterministic root W3C `traceparent` header (`00-<trace_id>-<span_id>-01`) for a CI job.
#[must_use]
pub fn job_root_traceparent(job_id: &str, commit_sha: &str) -> String {
    job_root_trace_context(job_id, commit_sha).to_traceparent()
}

/// Generates a deterministic stage-scoped W3C [`TraceContext`] for a CI job that shares the
/// exact 128-bit `trace_id` of [`job_root_trace_context`]`(job_id, commit_sha)` while deriving
/// a deterministic 64-bit `span_id` for `stage_id` (`#142`).
#[must_use]
pub fn job_stage_trace_context(job_id: &str, commit_sha: &str, stage_id: &str) -> TraceContext {
    let root = job_root_trace_context(job_id, commit_sha);
    let mut span_hasher = Sha256::new();
    span_hasher.update(b"muobserve-job-stage-span:");
    span_hasher.update(job_id.as_bytes());
    span_hasher.update(b":");
    span_hasher.update(commit_sha.as_bytes());
    span_hasher.update(b":");
    span_hasher.update(stage_id.as_bytes());
    let span_digest = span_hasher.finalize();

    let mut span_id = [0u8; 8];
    span_id.copy_from_slice(&span_digest[..8]);
    if span_id == [0u8; 8] {
        span_id[7] = 1;
    }

    TraceContext {
        version: W3C_TRACEPARENT_VERSION,
        trace_id: root.trace_id,
        span_id,
        trace_flags: TRACE_FLAG_SAMPLED,
    }
}

/// Maps a numeric quality score (`0..=100`) to `mu-ci-controller`'s letter grade scale.
#[must_use]
pub fn compute_letter_grade(score: u32) -> String {
    match score {
        95..=100 => "A+".to_string(),
        90..=94 => "A".to_string(),
        80..=89 => "B".to_string(),
        70..=79 => "C".to_string(),
        60..=69 => "D".to_string(),
        _ => "F".to_string(),
    }
}

/// Applies a [`RegressionGateReport`] returned by `MuObserve` to a completed job's
/// [`JobMetrics`] quality scorecard and [`JobStatus`] (`#44`).
///
/// - [`RegressionVerdict::Pass`]: preserves quality score and status; enriches `benchmark_summary` if unset.
/// - [`RegressionVerdict::Warn`]: deducts 5 quality points per flaky test (minimum 5 points),
///   recomputes `letter_grade`, and annotates `benchmark_summary`.
/// - [`RegressionVerdict::Fail`] (`RegressionDetected`): deducts 20 points per regressed benchmark
///   and 25 points per newly failed test (minimum 25 points), caps `quality_score <= 65` (`D`/`F`),
///   recomputes `letter_grade`, and transitions `status` to [`JobStatus::Failed`].
pub fn apply_regression_gate_to_job(
    metrics: &mut JobMetrics,
    status: &mut JobStatus,
    report: &RegressionGateReport,
) {
    match report.verdict {
        RegressionVerdict::Pass => {
            if metrics.benchmark_summary.is_none() && !report.summary.is_empty() {
                metrics.benchmark_summary = Some(report.summary.clone());
            }
        }
        RegressionVerdict::Warn => {
            let warn_items = report.flaky_or_failed_tests.len().max(1);
            let penalty = (warn_items.saturating_mul(5)).min(40) as u32;
            metrics.quality_score = metrics.quality_score.saturating_sub(penalty);
            metrics.letter_grade = compute_letter_grade(metrics.quality_score);
            if !report.summary.is_empty() {
                metrics.benchmark_summary = Some(match metrics.benchmark_summary.take() {
                    Some(existing) if !existing.is_empty() => {
                        format!("{existing} | {}", report.summary)
                    }
                    _ => report.summary.clone(),
                });
            }
        }
        RegressionVerdict::Fail => {
            let bench_penalty = report.regressed_benchmarks.len().saturating_mul(20);
            let test_penalty = report.flaky_or_failed_tests.len().saturating_mul(25);
            let raw_penalty = bench_penalty.saturating_add(test_penalty).clamp(25, 100) as u32;
            metrics.quality_score = metrics.quality_score.saturating_sub(raw_penalty).min(65);
            metrics.letter_grade = compute_letter_grade(metrics.quality_score);
            let reason = if report.summary.is_empty() {
                format!(
                    "RegressionDetected: {} benchmark regression(s), {} failing/flaky test(s)",
                    report.regressed_benchmarks.len(),
                    report.flaky_or_failed_tests.len()
                )
            } else if report.summary.starts_with("RegressionDetected") {
                report.summary.clone()
            } else {
                format!("RegressionDetected: {}", report.summary)
            };
            metrics.benchmark_summary = Some(reason.clone());
            *status = JobStatus::Failed { error: reason };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_observable_ipc::{decode_log_batch, WalBatchAck};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_delta_otel_log_streaming_dedup_and_no_full_file_snapshots() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();

        let received_otel_batches: Arc<Mutex<Vec<Vec<OtelLogEntry>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let received_control_frames: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));

        let otel_clone = received_otel_batches.clone();
        let ctrl_clone = received_control_frames.clone();

        let server = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let otel_c = otel_clone.clone();
                let ctrl_c = ctrl_clone.clone();
                tokio::spawn(async move {
                    while let Ok((hdr, payload)) = read_frame(&mut socket).await {
                        if hdr.msg_type == MSG_TYPE_ARROW_OTEL_LOGS {
                            let batch = decode_log_batch(&payload).expect("decode OTel log batch");
                            otel_c.lock().expect("lock").push(batch.clone());
                            let ack = ControlRpcEnvelope::WalAck(WalBatchAck {
                                sequence: hdr.sequence,
                                ok: true,
                                accepted_rows: batch.len() as u32,
                                error_message: None,
                            });
                            let resp_bytes = encode_control_envelope(&ack).expect("encode ack");
                            let resp_hdr = IpcHeader::new(
                                MSG_TYPE_WAL_ACK,
                                resp_bytes.len() as u32,
                                0,
                                hdr.sequence,
                            );
                            let _ = write_frame(&mut socket, &resp_hdr, &resp_bytes).await;
                        } else if hdr.msg_type == MSG_TYPE_FORY_CONTROL {
                            *ctrl_c.lock().expect("lock") += 1;
                        }
                    }
                });
            }
        });

        let storage = MuObserveRemoteStorage::new(MuObserveRemoteConfig::plain_tcp(addr))
            .expect("storage init");

        // 1. Append initial batch of structured worker log entries (including a secret token)
        let batch1 = vec![
            mu_ci_ipc::LogEntry {
                job_id: "job-delta-1".to_string(),
                stage_id: "build".to_string(),
                node_id: "node-a".to_string(),
                timestamp_us: 1_700_000_000_000_000,
                stream: 1,
                line_no: 1,
                content: "Compiling crate v0.1.0".to_string(),
            },
            mu_ci_ipc::LogEntry {
                job_id: "job-delta-1".to_string(),
                stage_id: "build".to_string(),
                node_id: "node-a".to_string(),
                timestamp_us: 1_700_000_000_100_000,
                stream: 2,
                line_no: 2,
                content: "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".to_string(),
            },
        ];
        storage
            .append_structured_log_entries("job-delta-1", &batch1)
            .await;
        assert_eq!(storage.pending_log_lines_snapshot().len(), 2);

        // First flush sends exactly those 2 delta lines via MSG_TYPE_ARROW_OTEL_LOGS
        let flushed1 = storage.flush_dirty_logs().await.expect("flush 1");
        assert_eq!(flushed1, 2);
        assert!(storage.pending_log_lines_snapshot().is_empty());

        // 2. Re-sending duplicate (stage_id, stream, line_no) + 1 new line queues ONLY the 1 new delta line
        let batch2 = vec![
            batch1[0].clone(),
            batch1[1].clone(),
            mu_ci_ipc::LogEntry {
                job_id: "job-delta-1".to_string(),
                stage_id: "build".to_string(),
                node_id: "node-a".to_string(),
                timestamp_us: 1_700_000_000_200_000,
                stream: 1,
                line_no: 3,
                content: "Finished release target".to_string(),
            },
        ];
        storage
            .append_structured_log_entries("job-delta-1", &batch2)
            .await;
        assert_eq!(
            storage.pending_log_lines_snapshot().len(),
            1,
            "duplicate lines must not be re-queued"
        );

        // Append controller status line as well
        let ctrl_added = storage.append_log_lines("job-delta-1", "Stage build succeeded\n");
        assert_eq!(ctrl_added, 1);
        assert_eq!(storage.pending_log_lines_snapshot().len(), 2);

        let flushed2 = storage.flush_dirty_logs().await.expect("flush 2");
        assert_eq!(flushed2, 2);

        // Verify local tail cache fallback still serves combined log locally
        let local_log = ControllerStorage::get_job_log(&storage, "job-delta-1").expect("local log");
        assert!(local_log.contains("Compiling crate v0.1.0"));
        assert!(local_log.contains("Finished release target"));
        assert!(local_log.contains("Stage build succeeded"));

        // Verify zero MSG_TYPE_FORY_CONTROL (__ar_job_logs__ snapshot) frames were ever sent
        assert_eq!(*received_control_frames.lock().expect("lock"), 0);

        // Verify exact delta batches received by MuObserve
        let batches = received_otel_batches.lock().expect("lock");
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[0][0].service_name, "action-runner-worker");
        assert_eq!(batches[0][0].node_id, "node-a");
        assert_eq!(batches[0][0].body, "Compiling crate v0.1.0");
        assert_eq!(
            batches[0][0].attributes_json,
            r#"{"line_no":1,"stream":"stdout"}"#
        );
        // Secret token on stderr must be redacted by DeterministicSecretRedactor
        assert!(
            !batches[0][1]
                .body
                .contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"),
            "secret token must be redacted before leaving controller"
        );
        assert_eq!(
            batches[0][1].attributes_json,
            r#"{"line_no":2,"stream":"stderr"}"#
        );

        assert_eq!(batches[1].len(), 2);
        assert_eq!(batches[1][0].body, "Finished release target");
        assert_eq!(batches[1][1].service_name, "action-runner-controller");
        assert_eq!(batches[1][1].body, "Stage build succeeded");

        // All worker stages and controller logs for job-delta-1 must share the exact same W3C trace_id (#142)
        assert_eq!(batches[0][0].trace_id, batches[1][1].trace_id);
        assert_ne!(batches[0][0].span_id, batches[1][1].span_id);

        server.abort();
    }

    #[test]
    fn test_w3c_trace_id_shared_across_stages_and_fifo_dedup_eviction() {
        let storage = MuObserveRemoteStorage::new(MuObserveRemoteConfig::plain_tcp(
            "127.0.0.1:9".to_string(),
        ))
        .expect("storage init");
        storage.register_job_commit_sha("job-trace-1", "deadbeefcafe1234");

        let root_ctx = job_root_trace_context("job-trace-1", "deadbeefcafe1234");
        let root_trace_hex = encode_hex(&root_ctx.trace_id);

        storage.append_structured_log_entries_sync(
            "job-trace-1",
            &[
                mu_ci_ipc::LogEntry {
                    job_id: "job-trace-1".to_string(),
                    stage_id: "build".to_string(),
                    node_id: "node-a".to_string(),
                    timestamp_us: 1_000,
                    stream: 1,
                    line_no: 1,
                    content: "build line".to_string(),
                },
                mu_ci_ipc::LogEntry {
                    job_id: "job-trace-1".to_string(),
                    stage_id: "test".to_string(),
                    node_id: "node-a".to_string(),
                    timestamp_us: 2_000,
                    stream: 1,
                    line_no: 1,
                    content: "test line".to_string(),
                },
            ],
        );
        storage.append_log_lines("job-trace-1", "controller summary\n");

        let snapshot = storage.pending_log_lines_snapshot();
        assert_eq!(snapshot.len(), 3);
        for entry in &snapshot {
            assert_eq!(entry.trace_id, root_trace_hex);
        }
        assert_ne!(snapshot[0].span_id, snapshot[1].span_id);
        assert_ne!(snapshot[1].span_id, snapshot[2].span_id);

        // Verify JobDedupRing evicts in strict FIFO order rather than lexicographical order (#142)
        let mut ring = JobDedupRing::default();
        assert!(ring.insert(("z-stage".to_string(), 1, 1), 2));
        assert!(ring.insert(("a-stage".to_string(), 1, 1), 2));
        // Inserting a 3rd item into capacity=2 ring must evict "z-stage" (oldest FIFO), NOT "a-stage"
        assert!(ring.insert(("m-stage".to_string(), 1, 1), 2));
        assert!(
            !ring.insert(("a-stage".to_string(), 1, 1), 2),
            "second FIFO item ('a-stage') must still be present"
        );
        assert!(
            ring.insert(("z-stage".to_string(), 1, 1), 2),
            "first FIFO item ('z-stage') must have been evicted first"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_metric_summary_lines_retained_across_log_buffer_truncation() {
        let storage = MuObserveRemoteStorage::new(MuObserveRemoteConfig::plain_tcp(
            "127.0.0.1:9".to_string(),
        ))
        .expect("storage init");

        // Emit early stage metric summaries followed by >300 KiB of verbose compiler lines
        storage.append_log_lines(
            "job-metrics-1",
            "test result: ok. 37 passed; 0 failed; 0 ignored\nTOTAL 1000 50 95.00%\nsrc/lib.rs 100 5 95.00% 100 5 95.00% 200 10 95.00%\ntest bench_fast ... bench: 12.5 ns/iter (+/- 0.4)\n",
        );
        let padding_line = format!("{}\n", "x".repeat(1024));
        for _ in 0..300 {
            storage.append_log_lines("job-metrics-1", &padding_line);
        }
        storage.append_log_lines(
            "job-metrics-1",
            "test result: ok. 13 passed; 0 failed; 0 ignored\n",
        );

        let retained =
            ControllerStorage::get_job_log(&storage, "job-metrics-1").expect("retained log buffer");
        assert!(retained.len() <= MAX_LOG_BUFFER_BYTES_PER_JOB);

        let tmp = tempfile::tempdir().expect("tempdir");
        let extracted = CatalogStore::extract_metrics_from_content_and_workspace(
            tmp.path(),
            "LMA1980/mu-ci-controller",
            &retained,
            true,
        );
        assert_eq!(extracted.tests_passed, 50);
        assert_eq!(extracted.tests_total, 50);
        assert_eq!(extracted.coverage_pct, Some(95.0));
        assert_eq!(extracted.benchmark_summary.as_deref(), Some("12.5 ns/iter"));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_failed_otel_flush_requeues_batch_for_retry() {
        let mut cfg = MuObserveRemoteConfig::plain_tcp("127.0.0.1:9".to_string());
        cfg.timeout_ms = 100;
        let storage = MuObserveRemoteStorage::new(cfg).expect("storage init");

        storage.append_log_lines("job-retry-1", "line 1\nline 2\n");
        assert_eq!(storage.pending_log_lines_snapshot().len(), 2);

        // Flush to unreachable endpoint fails, but batch must be re-queued (#141)
        let res = storage.flush_dirty_logs().await;
        assert!(res.is_err());
        let pending = storage.pending_log_lines_snapshot();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].body, "line 1");
        assert_eq!(pending[1].body, "line 2");
    }

    #[test]
    fn test_in_memory_storage_emit_trace_spans() {
        let storage = InMemoryStorage::open();
        assert!(storage.get_emitted_spans().is_empty());

        let span = OtelSpanEntry {
            trace_id: "0123456789abcdef0123456789abcdef".to_string(),
            span_id: "0123456789abcdef".to_string(),
            parent_span_id: None,
            service_name: "mu-ci-controller".to_string(),
            node_id: "controller".to_string(),
            span_name: "ci.pipeline.run:test-repo".to_string(),
            span_kind: "SERVER".to_string(),
            start_time_unix_nano: 1_000_000_000,
            end_time_unix_nano: 2_000_000_000,
            duration_ns: 1_000_000_000,
            status_code: "OK".to_string(),
            status_message: None,
            attributes_json: r#"{"job_id":"j1"}"#.to_string(),
        };

        storage.emit_trace_spans(std::slice::from_ref(&span));
        let emitted = storage.get_emitted_spans();
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].span_name, "ci.pipeline.run:test-repo");
        assert_eq!(emitted[0].trace_id, span.trace_id);
    }
}
