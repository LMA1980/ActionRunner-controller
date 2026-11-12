use chrono::{DateTime, Utc};
use mu_ci_ipc::{StageCancelTask, StageDispatchTask, WorkerHeartbeat, WorkerRegistration};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNodeView {
    pub node_id: String,
    pub arch: String,
    pub tags: Vec<String>,
    pub max_slots: u32,
    pub active_slots: u32,
    pub exclusive_locked: bool,
    pub ram_total_mb: u64,
    pub ram_used_mb: u64,
    pub cpu_load_pct: f32,
    pub btrfs_enabled: bool,
    pub toolchains: Vec<String>,
    pub last_seen_secs_ago: u64,
    pub is_online: bool,
}

pub type NodeView = ClusterNodeView;

#[allow(clippy::large_enum_variant)]
pub enum WorkerCommand {
    Dispatch(StageDispatchTask),
    Cancel(StageCancelTask),
    Disconnect,
}

pub struct ActiveWorker {
    pub registration: WorkerRegistration,
    pub leased_stages: HashSet<(String, String)>,
    pub exclusive_lease: Option<(String, String)>,
    pub pending_claims: HashSet<String>,
    pub pending_exclusive_claim: Option<String>,
    pub cpu_load_pct: f32,
    pub ram_used_mb: u64,
    pub last_heartbeat: DateTime<Utc>,
    pub last_dispatched_seq: u64,
    pub command_tx: mpsc::Sender<WorkerCommand>,
}

/// Returns `true` if a worker has critically low available RAM (`< 256 MiB` free
/// and `>= 90%` utilized), preventing new stage dispatches from triggering OOM.
pub fn is_worker_memory_exhausted(ram_total_mb: u64, ram_used_mb: u64) -> bool {
    if ram_total_mb == 0 || ram_used_mb == 0 {
        return false;
    }
    let avail_mb = ram_total_mb.saturating_sub(ram_used_mb);
    avail_mb < 256 && ram_used_mb.saturating_mul(100) >= ram_total_mb.saturating_mul(90)
}

fn heartbeat_timeout_secs() -> i64 {
    std::env::var("ACTION_RUNNER_HEARTBEAT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(15)
}

fn effective_slot_limit(max_slots: u32, max_concurrent_per_node: Option<u32>) -> u32 {
    match max_concurrent_per_node {
        Some(lim) if lim > 0 => lim.min(max_slots),
        _ => max_slots,
    }
}

const HW_EXCLUSIVE_TAGS: &[&str] = &[
    "k3",
    "spacemit",
    "x100",
    "a100",
    "native",
    "ground-truth",
    "bench",
    "verification",
];

const HYGIENE_LIGHT_TAGS: &[&str] = &["fmt", "docs", "audit"];

const EXPLICIT_AUX_ARCH_TAGS: &[&str] = &["aarch64", "arm64", "rpi4"];

const LOW_RAM_THRESHOLD_MB: u64 = 8192;

/// Computes `(hw_tier, low_ram_tier)` for ranking eligible workers (`0` = primary, `1` = overflow).
///
/// - `hw_tier = 1` when a worker advertises hardware-verification tags (`HW_EXCLUSIVE_TAGS`) and
///   the stage does not request any hardware-exclusive tag, preserving benchmark silicon unless
///   general compilation workers are saturated.
/// - `low_ram_tier = 1` when a worker has `< 8 GiB` total RAM (`ram_total_mb < 8192`) and the
///   stage is neither strictly lightweight hygiene (`fmt`, `docs`, `audit`) nor explicitly
///   targeting an auxiliary architecture (`aarch64`, `arm64`, `rpi4`). Constrained auxiliary
///   workers therefore share hygiene stages as tier-0 peers while automatically absorbing
///   overflow compilation, `clippy`, `riscv64` cross-compilation, and `test` stages whenever
///   primary `>= 8 GiB` workers are occupied.
fn worker_dispatch_tiers(worker: &ActiveWorker, required_tags: &[String]) -> (u8, u8) {
    let stage_requests_hw = required_tags
        .iter()
        .any(|req| HW_EXCLUSIVE_TAGS.contains(&req.as_str()));
    let node_is_hw = worker
        .registration
        .tags
        .iter()
        .any(|tag| HW_EXCLUSIVE_TAGS.contains(&tag.as_str()));
    let hw_tier = u8::from(!stage_requests_hw && node_is_hw);

    let stage_is_hygiene_only = !required_tags.is_empty()
        && required_tags
            .iter()
            .all(|req| HYGIENE_LIGHT_TAGS.contains(&req.as_str()));
    let stage_requests_aux_arch = required_tags
        .iter()
        .any(|req| EXPLICIT_AUX_ARCH_TAGS.contains(&req.as_str()));
    let node_is_low_ram = worker.registration.ram_total_mb > 0
        && worker.registration.ram_total_mb < LOW_RAM_THRESHOLD_MB;
    let low_ram_tier =
        u8::from(node_is_low_ram && !stage_is_hygiene_only && !stage_requests_aux_arch);

    (hw_tier, low_ram_tier)
}

#[allow(clippy::too_many_arguments)]
fn worker_can_accept_stage(
    worker: &ActiveWorker,
    now: DateTime<Utc>,
    timeout_secs: i64,
    required_tags: &[String],
    required_toolchain: Option<&str>,
    exclusive: bool,
    max_concurrent_per_node: Option<u32>,
    include_pending_claims: bool,
) -> bool {
    let secs_since_seen = (now - worker.last_heartbeat).num_seconds().max(0);
    if secs_since_seen > timeout_secs {
        return false;
    }
    if is_worker_memory_exhausted(worker.registration.ram_total_mb, worker.ram_used_mb) {
        return false;
    }
    if worker.exclusive_lease.is_some()
        || (include_pending_claims && worker.pending_exclusive_claim.is_some())
    {
        return false;
    }

    let occupied = if include_pending_claims {
        worker.leased_stages.len() + worker.pending_claims.len()
    } else {
        worker.leased_stages.len()
    };
    if exclusive {
        if occupied > 0 {
            return false;
        }
    } else {
        let limit = effective_slot_limit(worker.registration.max_slots, max_concurrent_per_node);
        if (occupied as u32) >= limit {
            return false;
        }
    }

    if let Some(tc) = required_toolchain {
        if !worker.registration.toolchains.iter().any(|t| t == tc) {
            return false;
        }
    }

    let node_tags: HashSet<&str> = worker
        .registration
        .tags
        .iter()
        .map(|s| s.as_str())
        .collect();
    required_tags.is_empty()
        || required_tags
            .iter()
            .all(|req| req == "default" || node_tags.contains(req.as_str()))
}

#[derive(Clone, Default)]
pub struct ClusterRegistry {
    workers: Arc<RwLock<HashMap<String, ActiveWorker>>>,
    stage_concurrency_limits: Arc<std::sync::RwLock<HashMap<(String, String), u32>>>,
    dispatch_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl ClusterRegistry {
    pub fn new() -> Self {
        Self {
            workers: Arc::new(RwLock::new(HashMap::new())),
            stage_concurrency_limits: Arc::new(std::sync::RwLock::new(HashMap::new())),
            dispatch_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn set_stage_concurrency_limits(
        &self,
        job_id: &str,
        limits: impl IntoIterator<Item = (String, u32)>,
    ) {
        let mut guard = self
            .stage_concurrency_limits
            .write()
            .unwrap_or_else(|e| e.into_inner());
        guard.retain(|(jid, _), _| jid != job_id);
        for (stage_id, limit) in limits {
            guard.insert((job_id.to_string(), stage_id), limit);
        }
    }

    #[must_use]
    pub fn stage_concurrency_limit(&self, job_id: &str, stage_id: &str) -> Option<u32> {
        let guard = self
            .stage_concurrency_limits
            .read()
            .unwrap_or_else(|e| e.into_inner());
        guard
            .get(&(job_id.to_string(), stage_id.to_string()))
            .copied()
    }

    pub async fn register(
        &self,
        mut reg: WorkerRegistration,
        command_tx: mpsc::Sender<WorkerCommand>,
    ) {
        let node_id = reg.node_id.clone();
        reg.max_slots = reg.max_slots.max(1);

        info!(
            node_id = %node_id,
            arch = %reg.arch,
            max_slots = reg.max_slots,
            tags = ?reg.tags,
            toolchains = ?reg.toolchains,
            "Worker node connected to cluster"
        );

        let mut workers = self.workers.write().await;
        workers.insert(
            node_id,
            ActiveWorker {
                registration: reg,
                leased_stages: HashSet::new(),
                exclusive_lease: None,
                pending_claims: HashSet::new(),
                pending_exclusive_claim: None,
                cpu_load_pct: 0.0,
                ram_used_mb: 0,
                last_heartbeat: Utc::now(),
                last_dispatched_seq: 0,
                command_tx,
            },
        );
    }

    pub async fn unregister(&self, node_id: &str) {
        let mut workers = self.workers.write().await;
        if workers.remove(node_id).is_some() {
            warn!(node_id = %node_id, "Worker node disconnected from cluster");
        }
    }

    pub async fn heartbeat(&self, hb: WorkerHeartbeat) {
        let mut workers = self.workers.write().await;
        if let Some(worker) = workers.get_mut(&hb.node_id) {
            // Note: Do NOT overwrite `leased_stages` from `hb.active_slots`.
            // Controller-side stage leases are authoritative from `lease_slot` until
            // `StageCompletionReport`, `WorkerShutdown`, or cancellation arrives.
            worker.cpu_load_pct = hb.cpu_load_pct;
            worker.ram_used_mb = hb.ram_used_mb;
            worker.last_heartbeat = Utc::now();
        }
    }

    pub async fn lease_slot(
        &self,
        job_id: &str,
        stage_id: &str,
        required_tags: &[String],
        required_toolchain: Option<&str>,
        exclusive: bool,
    ) -> Option<(String, mpsc::Sender<WorkerCommand>)> {
        self.lease_slot_with_limit(
            job_id,
            stage_id,
            required_tags,
            required_toolchain,
            exclusive,
            None,
        )
        .await
    }

    pub async fn lease_slot_with_limit(
        &self,
        job_id: &str,
        stage_id: &str,
        required_tags: &[String],
        required_toolchain: Option<&str>,
        exclusive: bool,
        max_concurrent_per_node: Option<u32>,
    ) -> Option<(String, mpsc::Sender<WorkerCommand>)> {
        let mut workers = self.workers.write().await;
        let now = Utc::now();

        // Collect all eligible idle nodes and balance dispatch across compilation workers:
        // 1. Prefer fewest currently leased stages on the node (`leased_stages.len()`).
        // 2. Prefer general compilation workers (`hw_tier = 0`) over native K3 benchmark silicon
        //    (`hw_tier = 1`) unless the stage explicitly requests hardware-exclusive tags.
        // 3. Prefer `>= 8 GiB` primary compilation workers (`low_ram_tier = 0`) over `< 8 GiB`
        //    auxiliary workers (`low_ram_tier = 1`) for heavy compilation, cross-compilation, and
        //    test stages while keeping `< 8 GiB` workers at `low_ram_tier = 0` for lightweight
        //    hygiene stages (`fmt`, `docs`, `audit`) and explicit `aarch64`/`arm64` stages.
        // 4. Round-robin (`last_dispatched_seq`) and CPU load (`load_int`) so eligible peers in
        //    the same tier share stages evenly without penalizing nodes advertising extra tags.
        let timeout_secs = heartbeat_timeout_secs();
        type NodeDispatchScore = (usize, u8, u8, u64, i32);
        let mut best_node: Option<(String, NodeDispatchScore)> = None;

        for (node_id, worker) in workers.iter() {
            if !worker_can_accept_stage(
                worker,
                now,
                timeout_secs,
                required_tags,
                required_toolchain,
                exclusive,
                max_concurrent_per_node,
                false,
            ) {
                continue;
            }

            let (hw_tier, low_ram_tier) = worker_dispatch_tiers(worker, required_tags);
            let active_leases = worker.leased_stages.len();
            let load_int = (worker.cpu_load_pct * 100.0) as i32;
            let score = (
                active_leases,
                hw_tier,
                low_ram_tier,
                worker.last_dispatched_seq,
                load_int,
            );
            if match &best_node {
                None => true,
                Some((best_id, best_score)) => {
                    (score, node_id.as_str()) < (*best_score, best_id.as_str())
                }
            } {
                best_node = Some((node_id.clone(), score));
            }
        }

        if let Some((chosen_id, _)) = best_node {
            for worker in workers.values_mut() {
                worker.pending_claims.remove(job_id);
                if worker.pending_exclusive_claim.as_deref() == Some(job_id) {
                    worker.pending_exclusive_claim = None;
                }
            }
            if let Some(worker) = workers.get_mut(&chosen_id) {
                let seq = self
                    .dispatch_counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    + 1;
                worker.last_dispatched_seq = seq;
                worker
                    .leased_stages
                    .insert((job_id.to_string(), stage_id.to_string()));
                if exclusive {
                    worker.exclusive_lease = Some((job_id.to_string(), stage_id.to_string()));
                }
                return Some((chosen_id, worker.command_tx.clone()));
            }
        }

        None
    }

    pub async fn release_stage_slot(&self, node_id: &str, job_id: &str, stage_id: &str) {
        let mut workers = self.workers.write().await;
        for worker in workers.values_mut() {
            worker.pending_claims.remove(job_id);
            if worker.pending_exclusive_claim.as_deref() == Some(job_id) {
                worker.pending_exclusive_claim = None;
            }
        }
        if let Some(worker) = workers.get_mut(node_id) {
            worker
                .leased_stages
                .remove(&(job_id.to_string(), stage_id.to_string()));
            if worker
                .exclusive_lease
                .as_ref()
                .is_some_and(|(j, s)| j == job_id && s == stage_id)
            {
                worker.exclusive_lease = None;
            }
        }
    }

    pub async fn release_slot(&self, node_id: &str) {
        let mut workers = self.workers.write().await;
        if let Some(worker) = workers.get_mut(node_id) {
            worker.leased_stages.clear();
            worker.exclusive_lease = None;
            worker.pending_claims.clear();
            worker.pending_exclusive_claim = None;
        }
    }

    pub async fn cancel_and_release_job_slots(&self, job_id: &str, reason: &str) {
        self.stage_concurrency_limits
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(jid, _), _| jid != job_id);
        let mut to_cancel = Vec::new();
        {
            let mut workers = self.workers.write().await;
            for worker in workers.values_mut() {
                worker.pending_claims.remove(job_id);
                if worker.pending_exclusive_claim.as_deref() == Some(job_id) {
                    worker.pending_exclusive_claim = None;
                }
                if worker
                    .exclusive_lease
                    .as_ref()
                    .is_some_and(|(j, _)| j == job_id)
                {
                    worker.exclusive_lease = None;
                }

                let matching: Vec<(String, String)> = worker
                    .leased_stages
                    .iter()
                    .filter(|(j_id, _)| j_id == job_id)
                    .cloned()
                    .collect();
                for (j_id, s_id) in matching {
                    worker.leased_stages.remove(&(j_id.clone(), s_id.clone()));
                    to_cancel.push((
                        worker.command_tx.clone(),
                        StageCancelTask {
                            job_id: j_id,
                            stage_id: s_id,
                            reason: reason.to_string(),
                        },
                    ));
                }
            }
        }

        for (tx, cancel_task) in to_cancel {
            let _ = tx.send(WorkerCommand::Cancel(cancel_task)).await;
        }
    }

    /// Disconnects and unregisters all currently attached worker tunnels (`#104`).
    ///
    /// Invoked when a controller instance steps down to `Standby` so workers do not remain
    /// pinned to a passive standby tunnel after HA failback.
    pub async fn disconnect_all(&self) -> usize {
        let drained: Vec<(String, mpsc::Sender<WorkerCommand>)> = {
            let mut workers = self.workers.write().await;
            workers.drain().map(|(id, w)| (id, w.command_tx)).collect()
        };
        let count = drained.len();
        for (node_id, tx) in drained {
            info!(
                node_id = %node_id,
                "Closing worker tunnel on controller demotion to Standby"
            );
            if let Err(tokio::sync::mpsc::error::TrySendError::Full(cmd)) =
                tx.try_send(WorkerCommand::Disconnect)
            {
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(
                        std::time::Duration::from_millis(500),
                        tx_clone.send(cmd),
                    )
                    .await;
                });
            }
        }
        count
    }

    pub async fn is_node_online(&self, node_id: &str) -> bool {
        let workers = self.workers.read().await;
        let now = Utc::now();
        let timeout_secs = heartbeat_timeout_secs();
        if let Some(worker) = workers.get(node_id) {
            (now - worker.last_heartbeat).num_seconds().max(0) <= timeout_secs
        } else {
            false
        }
    }

    pub async fn list_nodes_view(&self) -> Vec<ClusterNodeView> {
        let workers = self.workers.read().await;
        let now = Utc::now();
        let timeout_secs = heartbeat_timeout_secs() as u64;

        workers
            .values()
            .map(|w| {
                let last_seen_secs_ago = (now - w.last_heartbeat).num_seconds().max(0) as u64;
                let is_online = last_seen_secs_ago <= timeout_secs;

                ClusterNodeView {
                    node_id: w.registration.node_id.clone(),
                    arch: w.registration.arch.clone(),
                    tags: w.registration.tags.clone(),
                    max_slots: w.registration.max_slots,
                    active_slots: w.leased_stages.len() as u32,
                    exclusive_locked: w.exclusive_lease.is_some(),
                    ram_total_mb: w.registration.ram_total_mb,
                    ram_used_mb: w.ram_used_mb,
                    cpu_load_pct: w.cpu_load_pct,
                    btrfs_enabled: w.registration.btrfs_enabled,
                    toolchains: w.registration.toolchains.clone(),
                    last_seen_secs_ago,
                    is_online,
                }
            })
            .collect()
    }

    /// Checks whether at least one online, idle worker node in the cluster can satisfy
    /// a stage with the given `required_tags` and `required_toolchain`.
    pub async fn has_available_slot_for(
        &self,
        required_tags: &[String],
        required_toolchain: Option<&str>,
    ) -> bool {
        self.has_available_slot_for_stage(required_tags, required_toolchain, false)
            .await
    }

    pub async fn has_available_slot_for_stage(
        &self,
        required_tags: &[String],
        required_toolchain: Option<&str>,
        exclusive: bool,
    ) -> bool {
        self.has_available_slot_for_stage_with_limit(
            required_tags,
            required_toolchain,
            exclusive,
            None,
        )
        .await
    }

    pub async fn has_available_slot_for_stage_with_limit(
        &self,
        required_tags: &[String],
        required_toolchain: Option<&str>,
        exclusive: bool,
        max_concurrent_per_node: Option<u32>,
    ) -> bool {
        let workers = self.workers.read().await;
        let now = Utc::now();
        let timeout_secs = heartbeat_timeout_secs();

        workers.values().any(|worker| {
            worker_can_accept_stage(
                worker,
                now,
                timeout_secs,
                required_tags,
                required_toolchain,
                exclusive,
                max_concurrent_per_node,
                true,
            )
        })
    }

    /// Checks whether any online worker node currently has an available execution slot.
    pub async fn has_any_available_slot(&self) -> bool {
        let workers = self.workers.read().await;
        let now = Utc::now();
        let timeout_secs = heartbeat_timeout_secs();

        workers.values().any(|worker| {
            worker_can_accept_stage(worker, now, timeout_secs, &[], None, false, None, true)
        })
    }

    /// Checks whether any worker node currently holds an active stage lease (or exclusive lock)
    /// belonging to `job_id`.
    pub async fn has_active_leases_for_job(&self, job_id: &str) -> bool {
        let workers = self.workers.read().await;
        workers.values().any(|w| {
            w.exclusive_lease.as_ref().is_some_and(|(j, _)| j == job_id)
                || w.leased_stages.iter().any(|(j, _)| j == job_id)
        })
    }

    /// Checks whether `node_id` currently holds an active stage lease for `(job_id, stage_id)`.
    pub async fn has_stage_lease(&self, node_id: &str, job_id: &str, stage_id: &str) -> bool {
        let workers = self.workers.read().await;
        workers.get(node_id).is_some_and(|w| {
            w.leased_stages
                .contains(&(job_id.to_string(), stage_id.to_string()))
        })
    }

    pub async fn sync_and_try_reserve_for_claim(
        &self,
        active_unleased_job_ids: &HashSet<String>,
        job_id: &str,
        stages: &[crate::job::StageRecord],
    ) -> bool {
        let mut workers = self.workers.write().await;
        let now = Utc::now();
        let timeout_secs = heartbeat_timeout_secs();

        // 1. Prune pending claims across all workers
        for worker in workers.values_mut() {
            worker.pending_claims.retain(|jid| {
                active_unleased_job_ids.contains(jid)
                    && !worker
                        .leased_stages
                        .iter()
                        .any(|(leased_jid, _)| leased_jid == jid)
            });
            if let Some(ref jid) = worker.pending_exclusive_claim {
                if !active_unleased_job_ids.contains(jid)
                    || worker
                        .leased_stages
                        .iter()
                        .any(|(leased_jid, _)| leased_jid == jid)
                {
                    worker.pending_exclusive_claim = None;
                }
            }
        }

        // 2. Check if stages.is_empty()
        type ClaimReserveScore = (u8, u8, usize, i32);
        if stages.is_empty() {
            let mut best_node: Option<(String, ClaimReserveScore)> = None;
            for (node_id, worker) in workers.iter() {
                if !worker_can_accept_stage(worker, now, timeout_secs, &[], None, false, None, true)
                {
                    continue;
                }

                let (hw_tier, low_ram_tier) = worker_dispatch_tiers(worker, &[]);
                let tag_count = worker.registration.tags.len();
                let load_int = (worker.cpu_load_pct * 100.0) as i32;
                let score = (hw_tier, low_ram_tier, tag_count, load_int);
                if match &best_node {
                    None => true,
                    Some((best_id, best_score)) => {
                        (score, node_id.as_str()) < (*best_score, best_id.as_str())
                    }
                } {
                    best_node = Some((node_id.clone(), score));
                }
            }

            if let Some((chosen_id, _)) = best_node {
                if let Some(worker) = workers.get_mut(&chosen_id) {
                    worker.pending_claims.insert(job_id.to_string());
                    return true;
                }
            }
            return false;
        }

        // 3. If !stages.is_empty(), iterate over ready Pending stages
        for stage in stages {
            if !matches!(stage.status, crate::job::StageStatus::Pending) {
                continue;
            }
            let deps_satisfied = stage.depends_on.iter().all(|dep_id| {
                stages.iter().any(|s| {
                    s.id == *dep_id
                        && matches!(
                            s.status,
                            crate::job::StageStatus::Completed { exit_code: 0, .. }
                        )
                })
            });
            if !deps_satisfied {
                continue;
            }

            let stage_limit = self.stage_concurrency_limit(job_id, &stage.id);
            let mut best_node: Option<(String, ClaimReserveScore)> = None;
            for (node_id, worker) in workers.iter() {
                if !worker_can_accept_stage(
                    worker,
                    now,
                    timeout_secs,
                    &stage.tags,
                    stage.toolchain.as_deref(),
                    stage.exclusive,
                    stage_limit,
                    true,
                ) {
                    continue;
                }

                let (hw_tier, low_ram_tier) = worker_dispatch_tiers(worker, &stage.tags);
                let tag_count = worker.registration.tags.len();
                let load_int = (worker.cpu_load_pct * 100.0) as i32;
                let score = (hw_tier, low_ram_tier, tag_count, load_int);
                if match &best_node {
                    None => true,
                    Some((best_id, best_score)) => {
                        (score, node_id.as_str()) < (*best_score, best_id.as_str())
                    }
                } {
                    best_node = Some((node_id.clone(), score));
                }
            }

            if let Some((chosen_id, _)) = best_node {
                if let Some(worker) = workers.get_mut(&chosen_id) {
                    worker.pending_claims.insert(job_id.to_string());
                    if stage.exclusive {
                        worker.pending_exclusive_claim = Some(job_id.to_string());
                    }
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_reg(node_id: &str, tags: &[&str], max_slots: u32) -> WorkerRegistration {
        WorkerRegistration {
            node_id: node_id.to_string(),
            arch: "x86_64".to_string(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            max_slots,
            ram_total_mb: 32768,
            btrfs_enabled: true,
            toolchains: vec!["system".to_string()],
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_single_action_per_node_and_heartbeat_immunity() {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(8);

        // When node registers with max_slots = 1, controller enforces 1 stage at a time
        cluster
            .register(make_reg("node-a", &["fmt", "audit"], 1), tx)
            .await;

        let req_fmt = vec!["fmt".to_string()];
        let req_audit = vec!["audit".to_string()];

        // First lease succeeds
        let lease1 = cluster
            .lease_slot("job-repo-1", "fmt-check", &req_fmt, None, false)
            .await;
        assert!(lease1.is_some());
        assert_eq!(lease1.unwrap().0, "node-a");

        // In-flight worker heartbeat reporting active_slots = 0 must NOT clobber the controller lease
        cluster
            .heartbeat(WorkerHeartbeat {
                node_id: "node-a".to_string(),
                active_slots: 0,
                cpu_load_pct: 12.0,
                ram_used_mb: 1024,
                timestamp_epoch_ms: 1000,
            })
            .await;

        // Second lease on node-a while job-repo-1 is still running must return None
        let lease2 = cluster
            .lease_slot("job-repo-2", "audit-check", &req_audit, None, false)
            .await;
        assert!(lease2.is_none());

        // Releasing a different job/stage cannot free job-repo-1's slot
        cluster
            .release_stage_slot("node-a", "job-repo-2", "audit-check")
            .await;
        assert!(cluster
            .lease_slot("job-repo-2", "audit-check", &req_audit, None, false)
            .await
            .is_none());

        // Releasing job-repo-1's stage frees node-a for job-repo-2
        cluster
            .release_stage_slot("node-a", "job-repo-1", "fmt-check")
            .await;
        let lease3 = cluster
            .lease_slot("job-repo-2", "audit-check", &req_audit, None, false)
            .await;
        assert!(lease3.is_some());
        assert_eq!(lease3.unwrap().0, "node-a");
    }

    /// Scenario 1: Drain Before Dispatch
    /// Worker has max_slots = 3. Stage A (exclusive: false) is leased.
    /// Stage B (exclusive: true) is requested -> lease_slot returns None (holds in Pending).
    /// When Stage A releases -> Stage B leases successfully.
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_scenario_1_drain_before_dispatch() {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(8);
        let node_id = "k3-bench-node-1";

        cluster
            .register(make_reg(node_id, &["bench", "k3"], 3), tx)
            .await;

        let req_tags = vec!["bench".to_string()];

        // Step 1: Lease Stage A (shared) -> succeeds
        let lease_a = cluster
            .lease_slot("job-1", "stage-a", &req_tags, None, false)
            .await;
        assert!(
            lease_a.is_some(),
            "Stage A (exclusive: false) should lease on idle node"
        );
        assert_eq!(lease_a.unwrap().0, node_id);

        // Step 2: Request Stage B (exclusive: true) -> MUST return None (drain required)
        let lease_b_blocked = cluster
            .lease_slot("job-2", "stage-b", &req_tags, None, true)
            .await;
        assert!(
            lease_b_blocked.is_none(),
            "Stage B (exclusive: true) must NOT lease while Stage A is active"
        );

        // Step 3: Release Stage A
        cluster
            .release_stage_slot(node_id, "job-1", "stage-a")
            .await;

        // Step 4: Request Stage B (exclusive: true) again -> succeeds after drain
        let lease_b_success = cluster
            .lease_slot("job-2", "stage-b", &req_tags, None, true)
            .await;
        assert!(
            lease_b_success.is_some(),
            "Stage B (exclusive: true) should lease successfully once node has drained"
        );
        assert_eq!(lease_b_success.unwrap().0, node_id);
    }

    /// Scenario 2: Full-Node Exclusive Lock
    /// Worker has max_slots = 3. Stage B (exclusive: true) is leased.
    /// Concurrent requests for Stage C (exclusive: false) and Stage D (exclusive: true)
    /// across different jobs, plus Stage E (same job), all return None.
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_scenario_2_full_node_exclusive_lock() {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(8);
        let node_id = "k3-bench-node-2";

        cluster
            .register(make_reg(node_id, &["k3", "perf"], 3), tx)
            .await;

        let req_tags = vec!["k3".to_string()];

        // Step 1: Lease Stage B (exclusive: true) -> succeeds
        let lease_b = cluster
            .lease_slot("job-2", "stage-b", &req_tags, None, true)
            .await;
        assert!(
            lease_b.is_some(),
            "Stage B (exclusive: true) should lease on idle node"
        );
        assert_eq!(lease_b.unwrap().0, node_id);

        // Step 2: Worker heartbeat reporting active_slots = 0 must NOT clobber exclusive lock
        cluster
            .heartbeat(WorkerHeartbeat {
                node_id: node_id.to_string(),
                active_slots: 0,
                cpu_load_pct: 10.0,
                ram_used_mb: 2048,
                timestamp_epoch_ms: 1000,
            })
            .await;

        // Step 3: Concurrent request for Stage C (exclusive: false, different job) -> None
        let lease_c = cluster
            .lease_slot("job-3", "stage-c", &req_tags, None, false)
            .await;
        assert!(
            lease_c.is_none(),
            "Stage C (exclusive: false) must be rejected while exclusive lock is held"
        );

        // Step 4: Concurrent request for Stage D (exclusive: true, different job) -> None
        let lease_d = cluster
            .lease_slot("job-4", "stage-d", &req_tags, None, true)
            .await;
        assert!(
            lease_d.is_none(),
            "Stage D (exclusive: true) must be rejected while exclusive lock is held"
        );

        // Step 5: Concurrent request for Stage E (exclusive: false, SAME job-2) -> None
        let lease_e = cluster
            .lease_slot("job-2", "stage-e", &req_tags, None, false)
            .await;
        assert!(
            lease_e.is_none(),
            "Stage E (same job) must be rejected while exclusive lock is held"
        );
    }

    /// Scenario 3a: Deterministic Lock Release via release_stage_slot
    /// Release Stage B via release_stage_slot -> node immediately unblocks and accepts
    /// new shared leases up to max_slots (3).
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_scenario_3a_deterministic_release_via_release_stage_slot() {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(8);
        let node_id = "k3-bench-node-3a";

        cluster.register(make_reg(node_id, &["k3"], 3), tx).await;

        let req_tags = vec!["k3".to_string()];

        // Lease Stage B (exclusive: true)
        let lease_b = cluster
            .lease_slot("job-2", "stage-b", &req_tags, None, true)
            .await;
        assert!(lease_b.is_some());

        // False release with wrong job/stage must NOT release the exclusive lock
        cluster
            .release_stage_slot(node_id, "job-99", "stage-x")
            .await;
        assert!(cluster
            .lease_slot("job-3", "stage-c", &req_tags, None, false)
            .await
            .is_none());

        // Valid release of Stage B
        cluster
            .release_stage_slot(node_id, "job-2", "stage-b")
            .await;

        // Node is immediately unblocked: accepts up to max_slots (3) concurrent shared leases
        let l1 = cluster
            .lease_slot("job-3", "stage-c1", &req_tags, None, false)
            .await;
        let l2 = cluster
            .lease_slot("job-3", "stage-c2", &req_tags, None, false)
            .await;
        let l3 = cluster
            .lease_slot("job-4", "stage-c3", &req_tags, None, false)
            .await;
        assert!(l1.is_some(), "First slot should be leased");
        assert!(l2.is_some(), "Second slot should be leased");
        assert!(l3.is_some(), "Third slot should be leased");

        // 4th lease exceeds max_slots = 3 -> None
        let l4 = cluster
            .lease_slot("job-5", "stage-c4", &req_tags, None, false)
            .await;
        assert!(l4.is_none(), "4th slot exceeds max_slots = 3");
    }

    /// Scenario 3b: Deterministic Lock Release via cancel_and_release_job_slots
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_scenario_3b_deterministic_release_via_cancel_and_release_job_slots() {
        let cluster = ClusterRegistry::new();
        let (tx, mut rx) = mpsc::channel(8);
        let node_id = "k3-bench-node-3b";

        cluster.register(make_reg(node_id, &["k3"], 3), tx).await;

        let req_tags = vec!["k3".to_string()];

        let lease_b = cluster
            .lease_slot("job-cancel-me", "stage-b", &req_tags, None, true)
            .await;
        assert!(lease_b.is_some());

        cluster
            .cancel_and_release_job_slots("job-cancel-me", "User cancelled pipeline")
            .await;

        // Verify WorkerCommand::Cancel was sent
        let cmd = rx.try_recv();
        assert!(cmd.is_ok(), "Cancellation command must be sent to worker");
        if let Ok(WorkerCommand::Cancel(task)) = cmd {
            assert_eq!(task.job_id, "job-cancel-me");
            assert_eq!(task.stage_id, "stage-b");
            assert_eq!(task.reason, "User cancelled pipeline");
        } else {
            panic!("Expected WorkerCommand::Cancel");
        }

        // Node should immediately accept new exclusive lease
        let lease_new = cluster
            .lease_slot("job-next", "stage-bench", &req_tags, None, true)
            .await;
        assert!(
            lease_new.is_some(),
            "Node should accept new exclusive lease immediately after job cancellation"
        );
    }

    /// Scenario 3c: Deterministic Lock Release via unregister and reconnect
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_scenario_3c_deterministic_release_via_unregister_and_reconnect() {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(8);
        let node_id = "k3-bench-node-3c";

        cluster
            .register(make_reg(node_id, &["k3"], 3), tx.clone())
            .await;

        let req_tags = vec!["k3".to_string()];

        let lease_b = cluster
            .lease_slot("job-disc", "stage-b", &req_tags, None, true)
            .await;
        assert!(lease_b.is_some());

        cluster.unregister(node_id).await;

        // While unregistered, lease_slot returns None
        assert!(cluster
            .lease_slot("job-next", "stage-any", &req_tags, None, false)
            .await
            .is_none());

        // Worker reconnects with fresh registration
        cluster.register(make_reg(node_id, &["k3"], 3), tx).await;

        let lease_fresh = cluster
            .lease_slot("job-next", "stage-bench", &req_tags, None, true)
            .await;
        assert!(
            lease_fresh.is_some(),
            "Reconnected worker node should accept leases cleanly without stale locks"
        );
    }

    /// Sub-task #24: Cross-node parallel execution with per-node exclusive serialization
    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn cross_node_parallel_per_node_exclusive() {
        let cluster = ClusterRegistry::new();
        let (tx1, _rx1) = mpsc::channel(8);
        let (tx2, _rx2) = mpsc::channel(8);
        let (tx3, _rx3) = mpsc::channel(8);

        // 3-node cluster: control-node, storage-node, worker-node
        cluster
            .register(make_reg("control-node", &["control"], 4), tx1)
            .await;
        cluster
            .register(make_reg("storage-node", &["storage"], 4), tx2)
            .await;
        cluster
            .register(make_reg("worker-node", &["compute"], 4), tx3)
            .await;

        let ctrl_tag = vec!["control".to_string()];
        let stor_tag = vec!["storage".to_string()];
        let comp_tag = vec!["compute".to_string()];

        // 1. Lease shared stage on control-node with max_concurrent_per_node = 1
        let lease_ctrl_1 = cluster
            .lease_slot_with_limit("job-1", "stage-ctrl-1", &ctrl_tag, None, false, Some(1))
            .await;
        assert_eq!(
            lease_ctrl_1.as_ref().map(|(n, _)| n.as_str()),
            Some("control-node")
        );

        // 2. Second stage on control-node with limit 1 MUST be rejected (per-node serialization)
        let lease_ctrl_2 = cluster
            .lease_slot_with_limit("job-1", "stage-ctrl-2", &ctrl_tag, None, false, Some(1))
            .await;
        assert!(
            lease_ctrl_2.is_none(),
            "control-node should reject second stage when max_concurrent_per_node: 1 is reached"
        );

        // 3. Concurrently lease shared stage on storage-node (cross-node parallelism)
        let lease_stor_1 = cluster
            .lease_slot_with_limit("job-1", "stage-stor-1", &stor_tag, None, false, Some(1))
            .await;
        assert_eq!(
            lease_stor_1.as_ref().map(|(n, _)| n.as_str()),
            Some("storage-node"),
            "storage-node should execute stage in parallel with control-node"
        );

        // 4. Lease first exclusive stage on worker-node
        let lease_comp_exc1 = cluster
            .lease_slot_with_limit("job-1", "stage-comp-exc1", &comp_tag, None, true, None)
            .await;
        assert_eq!(
            lease_comp_exc1.as_ref().map(|(n, _)| n.as_str()),
            Some("worker-node")
        );

        // Check node views: worker-node has exclusive_locked = true and active_slots = 1
        let views = cluster.list_nodes_view().await;
        let worker_view = views
            .iter()
            .find(|v| v.node_id == "worker-node")
            .expect("worker-node present");
        assert_eq!(worker_view.active_slots, 1);
        assert!(worker_view.exclusive_locked);

        // 5. While worker-node holds exclusive lease, subsequent exclusive AND shared stages are blocked
        let lease_comp_blocked = cluster
            .lease_slot_with_limit("job-1", "stage-comp-exc2", &comp_tag, None, true, None)
            .await;
        assert!(
            lease_comp_blocked.is_none(),
            "worker-node should block second exclusive stage while first is active"
        );

        let lease_comp_nonexc_blocked = cluster
            .lease_slot_with_limit(
                "job-1",
                "stage-comp-shared",
                &comp_tag,
                None,
                false,
                Some(1),
            )
            .await;
        assert!(
            lease_comp_nonexc_blocked.is_none(),
            "worker-node should block shared stage while exclusive lock is held"
        );

        // 6. Release first exclusive stage on worker-node
        cluster
            .release_stage_slot("worker-node", "job-1", "stage-comp-exc1")
            .await;

        let views_post_release = cluster.list_nodes_view().await;
        let worker_view_post = views_post_release
            .iter()
            .find(|v| v.node_id == "worker-node")
            .expect("worker-node present");
        assert_eq!(worker_view_post.active_slots, 0);
        assert!(!worker_view_post.exclusive_locked);

        // 7. Now second exclusive stage can be leased (FIFO serialization)
        let lease_comp_exc2 = cluster
            .lease_slot_with_limit("job-1", "stage-comp-exc2", &comp_tag, None, true, None)
            .await;
        assert_eq!(
            lease_comp_exc2.as_ref().map(|(n, _)| n.as_str()),
            Some("worker-node"),
            "worker-node should now acquire exclusive lease for stage-comp-exc2"
        );

        // Release all remaining stages
        cluster
            .release_stage_slot("control-node", "job-1", "stage-ctrl-1")
            .await;
        cluster
            .release_stage_slot("storage-node", "job-1", "stage-stor-1")
            .await;
        cluster
            .release_stage_slot("worker-node", "job-1", "stage-comp-exc2")
            .await;

        let final_views = cluster.list_nodes_view().await;
        for view in final_views {
            assert_eq!(
                view.active_slots, 0,
                "Node {} should have zero active slots",
                view.node_id
            );
            assert!(
                !view.exclusive_locked,
                "Node {} should not have exclusive lock",
                view.node_id
            );
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_three_node_compilation_balancing_and_hw_tiering() {
        let cluster = ClusterRegistry::new();
        let (tx_a, _rx_a) = mpsc::channel(8);
        let (tx_b, _rx_b) = mpsc::channel(8);
        let (tx_k3, _rx_k3) = mpsc::channel(8);

        // node-a has extra hygiene tags (fmt, audit, docs) alongside compilation tags (12 tags)
        cluster
            .register(
                make_reg(
                    "node-a",
                    &[
                        "x86_64",
                        "linux",
                        "fmt",
                        "audit",
                        "docs",
                        "clippy",
                        "cross-compile",
                        "riscv64",
                        "build",
                        "test",
                        "sccache",
                    ],
                    1,
                ),
                tx_a,
            )
            .await;

        // node-b has fewer tags (8 tags)
        cluster
            .register(
                make_reg(
                    "node-b",
                    &[
                        "x86_64",
                        "linux",
                        "clippy",
                        "cross-compile",
                        "riscv64",
                        "build",
                        "test",
                        "sccache",
                    ],
                    1,
                ),
                tx_b,
            )
            .await;

        // worker-riscv64 carries hardware tags + riscv64
        cluster
            .register(
                make_reg(
                    "worker-riscv64",
                    &[
                        "riscv64", "spacemit", "k3", "x100", "a100", "native", "bench", "sccache",
                    ],
                    1,
                ),
                tx_k3,
            )
            .await;

        let req_riscv64 = vec!["riscv64".to_string()];

        // 1. First riscv64 compilation stage picks node-a (tier 0, seq 0), NOT penalized by having more tags!
        let l1 = cluster
            .lease_slot("job-1", "build-1", &req_riscv64, None, false)
            .await
            .expect("l1");
        assert_eq!(l1.0, "node-a");

        // 2. While node-a is busy, second concurrent riscv64 stage picks node-b (tier 0, seq 0)
        let l2 = cluster
            .lease_slot("job-1", "build-2", &req_riscv64, None, false)
            .await
            .expect("l2");
        assert_eq!(l2.0, "node-b");

        // 3. While both x86_64 cross-compile nodes are busy, third concurrent riscv64 stage spills to worker-riscv64 (tier 1)
        let l3 = cluster
            .lease_slot("job-1", "build-3", &req_riscv64, None, false)
            .await
            .expect("l3");
        assert_eq!(l3.0, "worker-riscv64");

        // Release all three
        cluster
            .release_stage_slot("node-a", "job-1", "build-1")
            .await;
        cluster
            .release_stage_slot("node-b", "job-1", "build-2")
            .await;
        cluster
            .release_stage_slot("worker-riscv64", "job-1", "build-3")
            .await;

        // 4. Next sequential stage alternates between node-a (seq 1) and node-b (seq 2) via round-robin
        let l4 = cluster
            .lease_slot("job-2", "clippy-1", &["clippy".to_string()], None, false)
            .await
            .expect("l4");
        assert_eq!(l4.0, "node-a");
        cluster
            .release_stage_slot("node-a", "job-2", "clippy-1")
            .await;

        let l5 = cluster
            .lease_slot("job-2", "clippy-2", &["clippy".to_string()], None, false)
            .await
            .expect("l5");
        assert_eq!(l5.0, "node-b");
        cluster
            .release_stage_slot("node-b", "job-2", "clippy-2")
            .await;
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_has_active_leases_for_job() {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(10);
        let reg = make_reg("node-1", &["ci"], 2);
        cluster.register(reg, tx).await;

        assert!(!cluster.has_active_leases_for_job("job-1").await);

        let lease = cluster
            .lease_slot_with_limit("job-1", "stage-1", &["ci".to_string()], None, false, None)
            .await;
        assert!(lease.is_some());
        assert!(cluster.has_active_leases_for_job("job-1").await);
        assert!(!cluster.has_active_leases_for_job("job-2").await);

        cluster
            .release_stage_slot("node-1", "job-1", "stage-1")
            .await;
        assert!(!cluster.has_active_leases_for_job("job-1").await);

        // Test exclusive lease
        let exc_lease = cluster
            .lease_slot_with_limit("job-2", "stage-2", &["ci".to_string()], None, true, None)
            .await;
        assert!(exc_lease.is_some());
        assert!(cluster.has_active_leases_for_job("job-2").await);

        cluster
            .release_stage_slot("node-1", "job-2", "stage-2")
            .await;
        assert!(!cluster.has_active_leases_for_job("job-2").await);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_oom_admission_guard_and_low_ram_tiering() {
        let cluster = ClusterRegistry::new();
        let (tx_low, _rx_low) = mpsc::channel(10);
        let (tx_high, _rx_high) = mpsc::channel(10);

        let mut reg_low = make_reg("worker-aarch64", &["aarch64", "fmt", "docs", "audit"], 1);
        reg_low.arch = "aarch64".to_string();
        reg_low.ram_total_mb = 3793; // ~3.7 GiB usable on 4 GiB board
        cluster.register(reg_low, tx_low).await;

        let mut reg_high = make_reg("node-a", &["x86_64", "fmt", "docs", "audit", "build"], 1);
        reg_high.ram_total_mb = 16384; // 16 GiB
        cluster.register(reg_high, tx_high).await;

        // 1. Untagged ("default") stage prefers >= 8 GiB worker ("node-a") over < 8 GiB auxiliary worker
        let l1 = cluster
            .lease_slot(
                "job-1",
                "default-build",
                &["default".to_string()],
                None,
                false,
            )
            .await
            .expect("should lease node-a");
        assert_eq!(l1.0, "node-a");
        cluster
            .release_stage_slot("node-a", "job-1", "default-build")
            .await;

        // 2. Explicitly tagged hygiene stage ("fmt") treats both workers as tier 0
        let l2 = cluster
            .lease_slot("job-2", "fmt-1", &["fmt".to_string()], None, false)
            .await
            .expect("should leaseworker-aarch64 (seq 0 < seq 1)");
        assert_eq!(l2.0, "worker-aarch64");
        cluster
            .release_stage_slot("worker-aarch64", "job-2", "fmt-1")
            .await;

        // 3. When 4 GiB worker reports >= 90% memory used and < 256 MiB free, OOM guard blocks dispatch
        cluster
            .heartbeat(WorkerHeartbeat {
                node_id: "worker-aarch64".to_string(),
                active_slots: 0,
                cpu_load_pct: 10.0,
                ram_used_mb: 3650, // 143 MiB free (< 256 MiB), 96.2% used
                timestamp_epoch_ms: 1000,
            })
            .await;
        assert!(is_worker_memory_exhausted(3793, 3650));

        // Requesting "aarch64" must return None while worker-aarch64 is in OOM exhaustion
        let blocked = cluster
            .lease_slot("job-3", "arm-stage", &["aarch64".to_string()], None, false)
            .await;
        assert!(
            blocked.is_none(),
            "Worker under OOM memory exhaustion must not receive new stage leases"
        );

        // Once memory frees up, dispatch succeeds again
        cluster
            .heartbeat(WorkerHeartbeat {
                node_id: "worker-aarch64".to_string(),
                active_slots: 0,
                cpu_load_pct: 5.0,
                ram_used_mb: 600,
                timestamp_epoch_ms: 2000,
            })
            .await;
        let recovered = cluster
            .lease_slot("job-3", "arm-stage", &["aarch64".to_string()], None, false)
            .await
            .expect("should lease after memory pressure subsides");
        assert_eq!(recovered.0, "worker-aarch64");
    }

    #[test]
    fn test_worker_dispatch_tiers_classification_under_miri() {
        let (tx, _rx) = mpsc::channel(1);
        let now = Utc::now();

        let make_worker = |node_id: &str, arch: &str, tags: &[&str], ram_total_mb: u64| {
            let mut reg = make_reg(node_id, tags, 1);
            reg.arch = arch.to_string();
            reg.ram_total_mb = ram_total_mb;
            ActiveWorker {
                registration: reg,
                leased_stages: HashSet::new(),
                exclusive_lease: None,
                pending_claims: HashSet::new(),
                pending_exclusive_claim: None,
                cpu_load_pct: 0.0,
                ram_used_mb: 0,
                last_heartbeat: now,
                last_dispatched_seq: 0,
                command_tx: tx.clone(),
            }
        };

        let primary = make_worker(
            "node-a",
            "x86_64",
            &[
                "x86_64",
                "fmt",
                "docs",
                "audit",
                "clippy",
                "cross-compile",
                "riscv64",
                "build",
                "test",
            ],
            16384,
        );
        let aux_low_ram = make_worker(
            "worker-aarch64",
            "aarch64",
            &[
                "aarch64",
                "arm64",
                "rpi4",
                "fmt",
                "docs",
                "audit",
                "clippy",
                "cross-compile",
                "riscv64",
                "build",
                "test",
            ],
            3793,
        );
        let hw_riscv64 = make_worker(
            "worker-riscv64",
            "riscv64gc",
            &["riscv64", "spacemit", "k3", "x100", "a100", "native"],
            32768,
        );

        // Hygiene stages keep < 8 GiB auxiliary worker in tier (0, 0)
        for tag in ["fmt", "docs", "audit"] {
            let req = vec![tag.to_string()];
            assert_eq!(worker_dispatch_tiers(&primary, &req), (0, 0));
            assert_eq!(worker_dispatch_tiers(&aux_low_ram, &req), (0, 0));
        }

        // Explicit auxiliary architecture stages keep < 8 GiB worker in tier (0, 0)
        for tag in ["aarch64", "arm64", "rpi4"] {
            let req = vec![tag.to_string(), "build".to_string()];
            assert_eq!(worker_dispatch_tiers(&aux_low_ram, &req), (0, 0));
        }

        // Heavy compilation, clippy, test, and riscv64 cross-compile stages rank:
        // primary (0, 0) < aux_low_ram (0, 1) < hw_riscv64 (1, 0)
        for req in [
            vec![],
            vec!["default".to_string()],
            vec!["clippy".to_string()],
            vec!["build".to_string()],
            vec!["test".to_string()],
            vec!["riscv64".to_string()],
            vec!["cross-compile".to_string(), "riscv64".to_string()],
        ] {
            assert_eq!(worker_dispatch_tiers(&primary, &req), (0, 0));
            assert_eq!(worker_dispatch_tiers(&aux_low_ram, &req), (0, 1));
            assert_eq!(worker_dispatch_tiers(&hw_riscv64, &req), (1, 0));
        }

        // Explicit K3 hardware stages promote hw_riscv64 to tier (0, 0)
        let req_k3 = vec!["k3".to_string(), "native".to_string()];
        assert_eq!(worker_dispatch_tiers(&hw_riscv64, &req_k3), (0, 0));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_low_ram_overflow_compilation_and_riscv64_cross_compile() {
        let cluster = ClusterRegistry::new();
        let (tx_a, _rx_a) = mpsc::channel(8);
        let (tx_b, _rx_b) = mpsc::channel(8);
        let (tx_aux, _rx_aux) = mpsc::channel(8);
        let (tx_k3, _rx_k3) = mpsc::channel(8);

        let mut reg_a = make_reg(
            "node-a",
            &[
                "x86_64",
                "linux",
                "fmt",
                "audit",
                "docs",
                "clippy",
                "cross-compile",
                "riscv64",
                "build",
                "test",
            ],
            1,
        );
        reg_a.ram_total_mb = 16384;
        cluster.register(reg_a, tx_a).await;

        let mut reg_b = make_reg(
            "node-b",
            &[
                "x86_64",
                "linux",
                "clippy",
                "cross-compile",
                "riscv64",
                "build",
                "test",
            ],
            1,
        );
        reg_b.ram_total_mb = 32768;
        cluster.register(reg_b, tx_b).await;

        let mut reg_aux = make_reg(
            "worker-aarch64",
            &[
                "aarch64",
                "arm64",
                "linux",
                "rpi4",
                "fmt",
                "docs",
                "audit",
                "clippy",
                "cross-compile",
                "riscv64",
                "build",
                "test",
                "sccache",
            ],
            1,
        );
        reg_aux.arch = "aarch64".to_string();
        reg_aux.ram_total_mb = 3793;
        cluster.register(reg_aux, tx_aux).await;

        let mut reg_k3 = make_reg(
            "worker-riscv64",
            &["riscv64", "spacemit", "k3", "x100", "a100", "native"],
            1,
        );
        reg_k3.arch = "riscv64gc".to_string();
        reg_k3.ram_total_mb = 32768;
        cluster.register(reg_k3, tx_k3).await;

        // 1. When primary >= 8 GiB nodes are idle, tagged build/clippy/riscv64 stages use node-a & node-b first
        let req_riscv64 = vec!["cross-compile".to_string(), "riscv64".to_string()];
        let l1 = cluster
            .lease_slot("job-1", "riscv64-build-1", &req_riscv64, None, false)
            .await
            .expect("primary node-a");
        assert_eq!(l1.0, "node-a");

        let l2 = cluster
            .lease_slot("job-2", "riscv64-build-2", &req_riscv64, None, false)
            .await
            .expect("primary node-b");
        assert_eq!(l2.0, "node-b");

        // 2. Once both >= 8 GiB x86_64 nodes are occupied, worker-aarch64 absorbs overflow
        //    for riscv64 cross-compile / build / clippy / test BEFORE touching K3 silicon!
        let l3 = cluster
            .lease_slot("job-3", "riscv64-build-3", &req_riscv64, None, false)
            .await
            .expect("overflow worker-aarch64");
        assert_eq!(l3.0, "worker-aarch64");

        // 3. If a 4th riscv64 stage arrives while node-a, node-b, and worker-aarch64 are all busy,
        //    worker-riscv64 takes last-resort overflow when tags match ("riscv64").
        let l4 = cluster
            .lease_slot(
                "job-4",
                "riscv64-only-4",
                &["riscv64".to_string()],
                None,
                false,
            )
            .await
            .expect("last-resort worker-riscv64");
        assert_eq!(l4.0, "worker-riscv64");

        cluster
            .release_stage_slot("node-a", "job-1", "riscv64-build-1")
            .await;
        cluster
            .release_stage_slot("node-b", "job-2", "riscv64-build-2")
            .await;
        cluster
            .release_stage_slot("worker-aarch64", "job-3", "riscv64-build-3")
            .await;
        cluster
            .release_stage_slot("worker-riscv64", "job-4", "riscv64-only-4")
            .await;

        // 4. Verify sync_and_try_reserve_for_claim mirrors the exact same primary -> low-RAM overflow tiering
        let build_stages = vec![crate::job::StageRecord {
            id: "build-check".to_string(),
            name: "Build Workspace".to_string(),
            tags: vec!["build".to_string()],
            threads: 2,
            toolchain: None,
            depends_on: Vec::new(),
            status: crate::job::StageStatus::Pending,
            assigned_node: None,
            exclusive: false,
        }];
        let mut active_unleased = HashSet::new();
        for jid in ["claim-1", "claim-2", "claim-3"] {
            active_unleased.insert(jid.to_string());
            assert!(
                cluster
                    .sync_and_try_reserve_for_claim(&active_unleased, jid, &build_stages)
                    .await,
                "{jid} should reserve an available build slot"
            );
        }
        // All 3 build-capable nodes (node-a, node-b, worker-aarch64) now hold pending claims;
        // worker-riscv64 lacks the "build" tag, so a 4th claim returns false.
        active_unleased.insert("claim-4".to_string());
        assert!(
            !cluster
                .sync_and_try_reserve_for_claim(&active_unleased, "claim-4", &build_stages)
                .await
        );
    }
}
