---
name: action-runner-controller-dag
description: "Develop and maintain the ActionRunner-controller webhook ingress, DAG stage scheduler, secret resolution, and 3-phase workflow configuration parser."
---

# `action-runner-controller` Ingress, DAG Scheduler & Security Invariants

## 1. Secret Path vs. Literal Value Resolution

- Environment variables accepting either a file path or a literal secret (such as `GITHUB_WEBHOOK_SECRET`) **must** read and trim the file when given a path, and fail closed (`None`) if the path cannot be read—never fall back to using the file path string itself as the secret token.

## 2. Three-Phase Configuration Migration

- When evolving workflow configuration schemas (`.actionrunner/ActionRunner.yml` and `.actionrunner/security.yml`), enforce a strict 3-phase transition:
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
