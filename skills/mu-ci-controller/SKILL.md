---
name: mu-ci-controller
description: "Develop and maintain the mu-ci-controller webhook ingress, DAG stage scheduler, secret resolution, and dual-stack workflow configuration parser."
---

# `mu-ci-controller` Ingress, DAG Scheduler & Security Invariants

## 1. Secret Path vs. Literal Value Resolution

- Environment variables accepting either a file path or a literal secret (such as `GITHUB_WEBHOOK_SECRET`) **must** read and trim the file when given a path, and fail closed (`None`) if the path cannot be read—never fall back to using the file path string itself as the secret token.

## 2. Three-Phase Configuration Migration

- When evolving workflow configuration schemas (`.muci/mu-ci.yml`, `.actionrunner/ActionRunner.yml`, and security profiles), enforce a strict 3-phase transition:
  1. Side-by-side introduction with backward-compatible fallback.
  2. Production deployment and verification of the updated controller/worker.
  3. Post-deployment removal of legacy configuration files and fallback code.

## 3. DAG Scheduler Concurrency, Slot Reservation & HA Rehydration Invariants (`#106`–`#109`)

- **Leader Rehydration Monotonicity (`#107`)**:
  - `JobStore::update_stage_running` and `JobStore::update_stage_status` **must** always bump `record.updated_at = Utc::now()`, promote `JobStatus::Queued` to `JobStatus::Running` whenever a stage enters `Assigned` or `Running`, persist to `jobs_index.json`, and notify scheduler waiters.
  - On an active HA leader (`self.is_leader() && !recover_running`), `JobStore::rehydrate_from_storage(false)` **must** treat in-memory `self.inner` records as authoritative (`should_preserve_local_record`) and never overwrite in-flight `Running` jobs, stage PIDs, or requeued jobs with completed stages from stale storage snapshots.
- **Job-Stage Status Invariants & Single In-Flight Task Guard (`#108`)**:
  - A job holding any `StageStatus::Assigned` or `StageStatus::Running` stage **must** never remain in or transition to `JobStatus::Queued` (`requeue_preserving_priority` returns `false` if any stage or cluster lease is active).
  - `JobStore` tracks active `execute_job` tasks via `in_flight_jobs` and RAII `InFlightJobGuard` so at most one `execute_job` task can run per `job_id` at a time.
- **Pending Slot Reservation & Exclusive Stage Probe (`#109`)**:
  - `ClusterRegistry::sync_and_try_reserve_for_claim` atomically reserves a worker slot (`pending_claims` / `pending_exclusive_claim`) when `claim_next_queued_job_for_cluster` claims a job, preventing `DAGScheduler::run_loop` from over-claiming multiple queued jobs against the same single idle worker slot before `execute_job` finishes `git fetch` and calls `lease_slot`.
  - `StageRecord` persists `#[serde(default)] pub exclusive: bool` and `has_available_slot_for_stage` enforces "Drain Before Dispatch" (`worker.leased_stages.is_empty() && worker.pending_claims.is_empty()`) when `exclusive: true`.

## 4. Declarative `sccache` Policy & Tag Routing (`#105`, `#128`)

- `.muci/mu-ci.yml` and `.actionrunner/ActionRunner.yml` support `sccache: try | mandatory | false` at workflow, stage, and task levels (`resolve_task_sccache`: `task.sccache -> stage.sccache -> workflow.sccache -> SccacheMode::Try`).
- `ActionRunnerWorkflow::effective_stage_tags` appends `"sccache"` to a stage's required worker capability tags (used in both `StageRecord.tags` for pre-claim slot reservation and `lease_slot` at dispatch time) whenever the stage or any of its eligible compiler tasks (`cargo-build`, `cargo-check`, `cargo-test`, `cargo-clippy`, `cargo-bench`, `trunk`) resolves to `SccacheMode::Mandatory`.

## 5. Gray-Failure Health Probe, Bounded Tunnel I/O & Delta Line Streaming (`specs/gray-failure-health-and-delta-log-streaming.md`)

- **Fail-Closed `GET /health` (`src/app.rs`)**: Probes `workspace_dir` metadata with a 2-second timeout and checks HA leadership (`HaRoleConfig::Leader` demoted to `HaRole::Standby` returns `503 Service Unavailable`), triggering immediate HAProxy failover on storage gray failure or lease loss.
- **Bounded Tunnel & Persistence I/O (`src/tunnel.rs`, `src/job.rs`)**: Runs `append_logs` inside `tokio::task::spawn_blocking` with a 5s timeout, bounds `ws_sender.send` with a 10s timeout, and bounds `JobStore::persist` disk writes with a 5s timeout.
- **Delta `MSG_TYPE_ARROW_OTEL_LOGS` Streaming (`src/storage_backend.rs`)**: Streams each worker and controller log line once as a single-line `OtelLogEntry` (`line_no`, `stream`, `node_id`, `job_id`, `stage_id`) instead of re-flushing full-file `__ar_job_logs__` blobs.
