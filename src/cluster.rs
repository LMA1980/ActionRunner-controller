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
        // Each worker node is strictly limited to executing 1 action (stage) at a time.
        // Node thread budgets govern intra-stage parallelism (CARGO_BUILD_JOBS / RUST_TEST_THREADS),
        // not concurrent stage slots on the same node.
        reg.max_slots = 1;

        info!(
            node_id = %node_id,
            arch = %reg.arch,
            max_slots = reg.max_slots,
            tags = ?reg.tags,
            toolchains = ?reg.toolchains,
            "Worker node connected to cluster (strictly 1 stage slot enforced)"
        );

        let mut workers = self.workers.write().await;
        workers.insert(
            node_id,
            ActiveWorker {
                registration: reg,
                leased_stages: HashSet::new(),
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

            // Strictly 1 action (stage) at a time per worker node
            if !worker.leased_stages.is_empty() {
                continue;
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
        }
    }

    pub async fn release_slot(&self, node_id: &str) {
        let mut workers = self.workers.write().await;
        if let Some(worker) = workers.get_mut(node_id) {
            worker.leased_stages.clear();
        }
    }

    pub async fn cancel_and_release_job_slots(&self, job_id: &str, reason: &str) {
        let mut to_cancel = Vec::new();
        {
            let mut workers = self.workers.write().await;
            for worker in workers.values_mut() {
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
                    max_slots: 1,
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

        // Even if worker registers with max_slots = 6, controller enforces 1 stage at a time
        cluster
            .register(make_reg("entrance", &["fmt", "audit"], 6), tx)
            .await;

        let req_fmt = vec!["fmt".to_string()];
        let req_audit = vec!["audit".to_string()];

        // First lease succeeds
        let lease1 = cluster
            .lease_slot("job-repo-1", "fmt-check", &req_fmt, None)
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
            .lease_slot("job-repo-2", "audit-check", &req_audit, None)
            .await;
        assert!(lease2.is_none());

        // Releasing a different job/stage cannot free job-repo-1's slot
        cluster
            .release_stage_slot("entrance", "job-repo-2", "audit-check")
            .await;
        assert!(cluster
            .lease_slot("job-repo-2", "audit-check", &req_audit, None)
            .await
            .is_none());

        // Releasing job-repo-1's stage frees entrance for job-repo-2
        cluster
            .release_stage_slot("entrance", "job-repo-1", "fmt-check")
            .await;
        let lease3 = cluster
            .lease_slot("job-repo-2", "audit-check", &req_audit, None)
            .await;
        assert!(lease3.is_some());
        assert_eq!(lease3.unwrap().0, "entrance");
    }
}
