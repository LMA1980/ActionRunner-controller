# Spec: Disk/HA-Leader-Aware `/health` Probe, Bounded Tunnel I/O & Delta `OtelLogEntry` Streaming

## Location: `specs/gray-failure-health-and-delta-log-streaming.md`

### 1. Overview

`mu-ci-controller` hardens active-passive High Availability (HA) failover against userspace/storage gray failures (`D`-state filesystem stalls and leader lease demotions) and replaces $O(N^2)$ full-file `__ar_job_logs__` (`CentralSubmoduleSnapshot`) log re-writes with deduplicated single-line `MSG_TYPE_ARROW_OTEL_LOGS` delta streaming.

---

### 2. Disk- & HA-Leadership-Aware `GET /health` (`src/app.rs`)

`GET /health` (`/api/health`) enforces two fail-closed checks before returning `200 OK`:

1. **Bounded Storage I/O Probe (`2s` Timeout)**:
   - Executes `tokio::time::timeout(Duration::from_secs(2), tokio::fs::metadata(&state.config.workspace_dir)).await`.
   - If the filesystem metadata probe returns `Err` or times out (e.g., local Btrfs/ext4 mount wedged in uninterruptible `D`-state), `GET /health` immediately returns **`503 Service Unavailable`**:
     ```json
     {
       "status": "unhealthy",
       "reason": "workspace_dir_io_unavailable",
       "ha_role": "leader"
     }
     ```
2. **HA Leadership Verification (`HaRoleConfig::Leader` Demotion Guard)**:
   - When a controller configured with `HaRoleConfig::Leader` (`ACTION_RUNNER_HA_ROLE=leader`) loses its `MuObserve` leader lease and demotes its runtime state to `HaRole::Standby`, `GET /health` returns **`503 Service Unavailable`**:
     ```json
     {
       "status": "standby_demoted",
       "reason": "leader_lease_lost",
       "ha_role": "standby"
     }
     ```
   - Upstream HAProxy (`option httpchk GET /health`, `on-marked-down shutdown-sessions`, `on-marked-up shutdown-backup-sessions`) immediately marks the unhealthy or demoted primary down, terminates pinned WebSocket worker tunnels, and routes traffic to the active backup controller.
3. **Healthy Response (`200 OK`)**:
   - Returns `200 OK` with `"status": "ok"`, `"ha_role"`, `"queued_jobs"`, `"running_jobs"`, `"completed_jobs"`, and queue telemetry when storage I/O and leadership invariants hold.

---

### 3. Non-Blocking Tunnel Log Appends & Bounded Async I/O (`src/tunnel.rs`, `src/job.rs`)

- **Offloaded File Appends (`spawn_blocking` + `5s` Timeout)**:
  - In `src/tunnel.rs`, synchronous `append_logs(&full_path, &entries)` is executed inside `tokio::task::spawn_blocking` guarded by `tokio::time::timeout(Duration::from_secs(5), ...)` so a degraded local disk never blocks Tokio worker threads handling WebSocket heartbeats (`Ping`/`Pong`).
- **Bounded WebSocket Send Timeout (`10s`)**:
  - All `ws_sender.send(...)` calls in `handle_socket` are wrapped in `tokio::time::timeout(Duration::from_secs(10), ...)`, terminating half-open or stalled TCP connections deterministically.
- **Bounded Index Persistence Timeout (`5s`)**:
  - `JobStore::persist` wraps `tokio::fs::create_dir_all` and `tokio::fs::write` in `tokio::time::timeout(Duration::from_secs(5), ...)`.

---

### 4. Delta Single-Line `MSG_TYPE_ARROW_OTEL_LOGS` Streaming (`src/storage_backend.rs`)

`MuObserveRemoteStorage` eliminates full-file `__ar_job_logs__` (`CentralSubmoduleSnapshot`) re-flushes:
- **Structured Worker Log Lines (`append_structured_log_entries`)**:
  - Converts each incoming `mu_ci_ipc::LogEntry` from `MSG_TYPE_ARROW_LOG` into a single-line `OtelLogEntry` (`service_name = "action-runner-worker"`, `node_id = entry.node_id`, `job_id = Some(job_id)`, `stage_id = Some(entry.stage_id)`, `attributes_json = {"stream": "stdout"|"stderr", "line_no": entry.line_no}`), scrubs secrets via `DeterministicSecretRedactor`, deduplicates per `(job_id, stage_id, stream, line_no)`, and queues only unseen lines in `pending_log_lines`.
- **Controller Status Lines (`append_log_lines`)**:
  - Splits controller status messages into single-line `OtelLogEntry` records (`service_name = "action-runner-controller"`, `stage_id = Some("__controller__")`) with monotonically increasing per-job `line_no` values (`1_000_000+`).
- **Delta Arrow IPC Flush (`flush_dirty_logs` / `flush_job_log`)**:
  - Drains `pending_log_lines` in chunks of `512` records and transmits them to `MuObserve` via `encode_otel_logs_ipc` (`MSG_TYPE_ARROW_OTEL_LOGS`), reducing log network and DuckDB write volume from $O(N^2)$ to $O(N)$.
