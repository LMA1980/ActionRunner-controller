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
    pub ram_total_mb: u64,
    pub ram_used_mb: u64,
    pub cpu_load_pct: f32,
    pub btrfs_enabled: bool,
    pub toolchains: Vec<String>,
    pub last_seen_secs_ago: u64,
    pub is_online: bool,
}

pub enum WorkerCommand {
    Dispatch(StageDispatchTask),
    Cancel(StageCancelTask),
}

pub struct ActiveWorker {
    pub registration: WorkerRegistration,
    pub leased_stages: HashSet<(String, String)>,
    pub exclusive_lease: Option<(String, String)>,
    pub cpu_load_pct: f32,
    pub ram_used_mb: u64,
    pub last_heartbeat: DateTime<Utc>,
    pub command_tx: mpsc::Sender<WorkerCommand>,
}

#[derive(Clone, Default)]
pub struct ClusterRegistry {
    workers: Arc<RwLock<HashMap<String, ActiveWorker>>>,
}

impl ClusterRegistry {
    pub fn new() -> Self {
        Self {
            workers: Arc::new(RwLock::new(HashMap::new())),
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
        let mut workers = self.workers.write().await;
        let now = Utc::now();

        // Collect all eligible idle nodes and pick the most specific match (fewest tags, then lowest CPU load)
        let mut best_node: Option<(String, usize, i32)> = None;

        for (node_id, worker) in workers.iter() {
            // Heartbeat timeout check: 15 seconds
            let secs_since_seen = (now - worker.last_heartbeat).num_seconds().max(0);
            if secs_since_seen > 15 {
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
                // Non-exclusive stage: require available slot capacity under max_slots.
                if worker.leased_stages.len() >= worker.registration.max_slots as usize {
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
                let tag_count = worker.registration.tags.len();
                let load_int = (worker.cpu_load_pct * 100.0) as i32;
                let candidate = (node_id.clone(), tag_count, load_int);
                if match &best_node {
                    None => true,
                    Some((best_id, best_tags, best_load)) => {
                        (tag_count, load_int, node_id.as_str())
                            < (*best_tags, *best_load, best_id.as_str())
                    }
                } {
                    best_node = Some(candidate);
                }
            }
        }

        if let Some((chosen_id, _, _)) = best_node {
            if let Some(worker) = workers.get_mut(&chosen_id) {
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

    pub async fn is_node_online(&self, node_id: &str) -> bool {
        let workers = self.workers.read().await;
        let now = Utc::now();
        if let Some(worker) = workers.get(node_id) {
            (now - worker.last_heartbeat).num_seconds().max(0) <= 15
        } else {
            false
        }
    }

    pub async fn list_nodes_view(&self) -> Vec<ClusterNodeView> {
        let workers = self.workers.read().await;
        let now = Utc::now();

        workers
            .values()
            .map(|w| {
                let last_seen_secs_ago = (now - w.last_heartbeat).num_seconds().max(0) as u64;
                let is_online = last_seen_secs_ago <= 15;

                ClusterNodeView {
                    node_id: w.registration.node_id.clone(),
                    arch: w.registration.arch.clone(),
                    tags: w.registration.tags.clone(),
                    max_slots: w.registration.max_slots,
                    active_slots: w.leased_stages.len() as u32,
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
    async fn test_single_action_per_node_and_heartbeat_immunity() {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(8);

        // When node registers with max_slots = 1, controller enforces 1 stage at a time
        cluster
            .register(make_reg("entrance", &["fmt", "audit"], 1), tx)
            .await;

        let req_fmt = vec!["fmt".to_string()];
        let req_audit = vec!["audit".to_string()];

        // First lease succeeds
        let lease1 = cluster
            .lease_slot("job-repo-1", "fmt-check", &req_fmt, None, false)
            .await;
        assert!(lease1.is_some());
        assert_eq!(lease1.unwrap().0, "entrance");

        // In-flight worker heartbeat reporting active_slots = 0 must NOT clobber the controller lease
        cluster
            .heartbeat(WorkerHeartbeat {
                node_id: "entrance".to_string(),
                active_slots: 0,
                cpu_load_pct: 12.0,
                ram_used_mb: 1024,
                timestamp_epoch_ms: 1000,
            })
            .await;

        // Second lease on entrance while job-repo-1 is still running must return None
        let lease2 = cluster
            .lease_slot("job-repo-2", "audit-check", &req_audit, None, false)
            .await;
        assert!(lease2.is_none());

        // Releasing a different job/stage cannot free job-repo-1's slot
        cluster
            .release_stage_slot("entrance", "job-repo-2", "audit-check")
            .await;
        assert!(cluster
            .lease_slot("job-repo-2", "audit-check", &req_audit, None, false)
            .await
            .is_none());

        // Releasing job-repo-1's stage frees entrance for job-repo-2
        cluster
            .release_stage_slot("entrance", "job-repo-1", "fmt-check")
            .await;
        let lease3 = cluster
            .lease_slot("job-repo-2", "audit-check", &req_audit, None, false)
            .await;
        assert!(lease3.is_some());
        assert_eq!(lease3.unwrap().0, "entrance");
    }

    /// Scenario 1: Drain Before Dispatch
    /// Worker has max_slots = 3. Stage A (exclusive: false) is leased.
    /// Stage B (exclusive: true) is requested -> lease_slot returns None (holds in Pending).
    /// When Stage A releases -> Stage B leases successfully.
    #[tokio::test]
    async fn test_scenario_1_drain_before_dispatch() {
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(8);
        let node_id = "k3-bench-node-1";

        cluster
            .register(make_reg(node_id, &["bench", "k3"], 3), tx)
            .await;

        let req_tags = vec!["bench".to_string()];

        // Step 1: Lease Stage A (non-exclusive) -> succeeds
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
    /// new non-exclusive leases up to max_slots (3).
    #[tokio::test]
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

        // Node is immediately unblocked: accepts up to max_slots (3) concurrent non-exclusive leases
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
}
