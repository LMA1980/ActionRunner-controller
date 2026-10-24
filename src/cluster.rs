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
    pub active_slots: u32,
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
        reg: WorkerRegistration,
        command_tx: mpsc::Sender<WorkerCommand>,
    ) {
        let node_id = reg.node_id.clone();
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
                active_slots: 0,
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
            worker.active_slots = hb.active_slots;
            worker.cpu_load_pct = hb.cpu_load_pct;
            worker.ram_used_mb = hb.ram_used_mb;
            worker.last_heartbeat = Utc::now();
        }
    }

    pub async fn lease_slot(
        &self,
        required_tags: &[String],
        required_toolchain: Option<&str>,
    ) -> Option<(String, mpsc::Sender<WorkerCommand>)> {
        let mut workers = self.workers.write().await;
        let now = Utc::now();

        for (node_id, worker) in workers.iter_mut() {
            // Heartbeat timeout check: 15 seconds
            let secs_since_seen = (now - worker.last_heartbeat).num_seconds().max(0);
            if secs_since_seen > 15 {
                continue;
            }

            if worker.active_slots >= worker.registration.max_slots {
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
                worker.active_slots += 1;
                return Some((node_id.clone(), worker.command_tx.clone()));
            }
        }

        None
    }

    pub async fn release_slot(&self, node_id: &str) {
        let mut workers = self.workers.write().await;
        if let Some(worker) = workers.get_mut(node_id) {
            if worker.active_slots > 0 {
                worker.active_slots -= 1;
            }
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
                    active_slots: w.active_slots,
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
