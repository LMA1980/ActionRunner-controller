use action_runner_ipc::{StageCancelTask, StageDispatchTask, WorkerHeartbeat, WorkerRegistration};
use chrono::{DateTime, Utc};
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
    pub cpu_load_pct: f32,
    pub ram_used_mb: u64,
    pub last_heartbeat: DateTime<Utc>,
    pub last_dispatched_seq: u64,
    pub command_tx: mpsc::Sender<WorkerCommand>,
}

#[derive(Clone, Default)]
pub struct ClusterRegistry {
    workers: Arc<RwLock<HashMap<String, ActiveWorker>>>,
    dispatch_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl ClusterRegistry {
    pub fn new() -> Self {
        Self {
            workers: Arc::new(RwLock::new(HashMap::new())),
            dispatch_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
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
        // 1. Prefer fewest currently leased stages on the node (`leased_stages.len()`)
        // 2. When a stage does not explicitly require native K3 hardware tags (`k3`, `spacemit`,
        //    `x100`, `a100`, `native`, `ground-truth`, `bench`, `verification`), prefer general
        //    compilation/cross-compilation nodes (`tier = 0`) over native K3 hardware (`tier = 1`)
        //    so native silicon remains available for hardware verification/benchmarks unless all
        //    x86_64 workers are busy.
        // 3. Round-robin (`last_dispatched_seq`) and CPU load (`load_int`) so all eligible nodes
        //    (e.g. `node-a` / `entrance` and `node-b` / `rubicon`) share compilation evenly
        //    without penalizing nodes that advertise extra hygiene tags (`fmt`, `audit`, `docs`).
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
        let stage_requests_hw = required_tags
            .iter()
            .any(|req| HW_EXCLUSIVE_TAGS.contains(&req.as_str()));

        let mut best_node: Option<(String, (usize, u8, u64, i32))> = None;

        for (node_id, worker) in workers.iter() {
            // Heartbeat timeout check: 15 seconds (default) or configurable
            let timeout_secs = std::env::var("ACTION_RUNNER_HEARTBEAT_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(15);
            let secs_since_seen = (now - worker.last_heartbeat).num_seconds().max(0);
            if secs_since_seen > timeout_secs {
                continue;
            }

            // Scenario 2 (Full-Node Exclusive Lock):
            // If worker has an active exclusive lease, reject ALL requests.
            if worker.exclusive_lease.is_some() {
                continue;
            }

            if exclusive {
                // Scenario 1 (Drain Before Dispatch):
                // Exclusive stage requires a completely idle worker (zero active leased stages).
                if !worker.leased_stages.is_empty() {
                    continue;
                }
            } else {
                // Shared stage: limit by max_concurrent_per_node.min(node.max_slots)
                let limit = match max_concurrent_per_node {
                    Some(lim) if lim > 0 => lim.min(worker.registration.max_slots),
                    _ => worker.registration.max_slots,
                };
                if (worker.leased_stages.len() as u32) >= limit {
                    continue;
                }
            }

            // Verify toolchain if requested
            if let Some(tc) = required_toolchain {
                if !worker.registration.toolchains.iter().any(|t| t == tc) {
                    continue;
                }
            }

            // Verify required tags (empty tags or "default" matches any available node)
            let node_tags: HashSet<&str> = worker
                .registration
                .tags
                .iter()
                .map(|s| s.as_str())
                .collect();
            let matches_tags = required_tags.is_empty()
                || required_tags
                    .iter()
                    .all(|req| req == "default" || node_tags.contains(req.as_str()));

            if matches_tags {
                let node_is_hw = HW_EXCLUSIVE_TAGS.iter().any(|t| node_tags.contains(t));
                let hw_tier = u8::from(!stage_requests_hw && node_is_hw);
                let active_leases = worker.leased_stages.len();
                let load_int = (worker.cpu_load_pct * 100.0) as i32;
                let score = (active_leases, hw_tier, worker.last_dispatched_seq, load_int);
                if match &best_node {
                    None => true,
                    Some((best_id, best_score)) => {
                        (score, node_id.as_str()) < (*best_score, best_id.as_str())
                    }
                } {
                    best_node = Some((node_id.clone(), score));
                }
            }
        }

        if let Some((chosen_id, _)) = best_node {
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
        }
    }

    pub async fn cancel_and_release_job_slots(&self, job_id: &str, reason: &str) {
        let mut to_cancel = Vec::new();
        {
            let mut workers = self.workers.write().await;
            for worker in workers.values_mut() {
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
            let _ = tx.try_send(WorkerCommand::Disconnect);
        }
        count
    }

    pub async fn is_node_online(&self, node_id: &str) -> bool {
        let workers = self.workers.read().await;
        let now = Utc::now();
        let timeout_secs = std::env::var("ACTION_RUNNER_HEARTBEAT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);
        if let Some(worker) = workers.get(node_id) {
            (now - worker.last_heartbeat).num_seconds().max(0) <= timeout_secs
        } else {
            false
        }
    }

    pub async fn list_nodes_view(&self) -> Vec<ClusterNodeView> {
        let workers = self.workers.read().await;
        let now = Utc::now();
        let timeout_secs = std::env::var("ACTION_RUNNER_HEARTBEAT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(15);

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
        let workers = self.workers.read().await;
        let now = Utc::now();
        let timeout_secs = std::env::var("ACTION_RUNNER_HEARTBEAT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);

        for worker in workers.values() {
            let secs_since_seen = (now - worker.last_heartbeat).num_seconds().max(0);
            if secs_since_seen > timeout_secs {
                continue;
            }
            if worker.exclusive_lease.is_some() {
                continue;
            }
            if (worker.leased_stages.len() as u32) >= worker.registration.max_slots {
                continue;
            }
            if let Some(tc) = required_toolchain {
                if !worker.registration.toolchains.iter().any(|t| t == tc) {
                    continue;
                }
            }
            let node_tags: HashSet<&str> = worker
                .registration
                .tags
                .iter()
                .map(|s| s.as_str())
                .collect();
            let matches_tags = required_tags.is_empty()
                || required_tags
                    .iter()
                    .all(|req| req == "default" || node_tags.contains(req.as_str()));
            if matches_tags {
                return true;
            }
        }
        false
    }

    /// Checks whether any online worker node currently has an available execution slot.
    pub async fn has_any_available_slot(&self) -> bool {
        let workers = self.workers.read().await;
        let now = Utc::now();
        let timeout_secs = std::env::var("ACTION_RUNNER_HEARTBEAT_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);

        for worker in workers.values() {
            let secs_since_seen = (now - worker.last_heartbeat).num_seconds().max(0);
            if secs_since_seen > timeout_secs {
                continue;
            }
            if worker.exclusive_lease.is_some() {
                continue;
            }
            if (worker.leased_stages.len() as u32) < worker.registration.max_slots {
                return true;
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
}
