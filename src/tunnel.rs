use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, State, WebSocketUpgrade,
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use mu_ci_ipc::{
    create_fory_runtime, decode_log_batch, decode_metric_batch, IpcHeader, StageCompletionReport,
    StageStarted, WorkerHeartbeat, WorkerRegistration, WorkerShutdown, MSG_TYPE_ARROW_LOG,
    MSG_TYPE_ARROW_METRIC, MSG_TYPE_STAGE_CANCEL, MSG_TYPE_STAGE_COMPLETION,
    MSG_TYPE_STAGE_DISPATCH, MSG_TYPE_STAGE_STARTED, MSG_TYPE_WORKER_HEARTBEAT,
    MSG_TYPE_WORKER_REGISTRATION, MSG_TYPE_WORKER_SHUTDOWN,
};

use crate::aggregator::{aggregate_metrics, append_logs, format_log_entries};
use crate::cluster::WorkerCommand;
use crate::job::StageStatus;
use crate::storage_backend::{job_root_trace_context, job_stage_trace_context};
use crate::webhook::AppState;
use mu_observable_ipc::{encode_hex, OtelSpanEntry};

#[derive(Deserialize)]
pub struct TunnelQuery {
    pub token: Option<String>,
}

pub async fn handle_cluster_tunnel(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TunnelQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    // Validate cluster authentication token
    let auth_header = headers
        .get("x-cluster-token")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let provided_token = auth_header.or(query.token).unwrap_or_default();
    if provided_token != state.config.cluster_token {
        warn!("Unauthorized worker connection attempt to /api/cluster/tunnel");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Reject connection if this controller is not the active leader (#104).
    if !state.job_store.is_leader() {
        warn!(
            controller_id = %state.config.node_id,
            ha_role = %state.job_store.ha_role().as_str(),
            "Rejecting worker tunnel connection attempt: controller is in Standby"
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state)))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let fory = match create_fory_runtime() {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to create Fory runtime: {}", e);
            return;
        }
    };

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(32);
    let mut registered_node_id: Option<String> = None;
    let mut seq = 0u64;

    // Guard against role changes occurring during WebSocket upgrade handshake (#104)
    if !state.job_store.is_leader() {
        warn!(
            controller_id = %state.config.node_id,
            "Controller transitioned to Standby before worker registration; closing tunnel"
        );
        let close_frame = axum::extract::ws::CloseFrame {
            code: axum::extract::ws::close_code::NORMAL,
            reason: "controller in standby".into(),
        };
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ws_sender.send(Message::Close(Some(close_frame))),
        )
        .await;
        return;
    }

    // First message must be WorkerRegistration
    if let Some(Ok(Message::Binary(bin))) = ws_receiver.next().await {
        if let Ok((hdr, payload)) = IpcHeader::parse(&bin) {
            if hdr.msg_type == MSG_TYPE_WORKER_REGISTRATION {
                if let Ok(reg) = fory.deserialize::<WorkerRegistration>(payload) {
                    let node_id = reg.node_id.clone();
                    state.cluster.register(reg, cmd_tx).await;
                    registered_node_id = Some(node_id);
                }
            }
        }
    }

    let node_id = match registered_node_id {
        Some(id) => id,
        None => {
            warn!("Worker failed to register within initial frame; terminating tunnel");
            return;
        }
    };

    info!(node = %node_id, "Cluster tunnel session active");

    loop {
        tokio::select! {
            // Outbound commands dispatched to worker
            cmd_opt = cmd_rx.recv() => {
                let Some(cmd) = cmd_opt else {
                    break;
                };
                seq += 1;
                match cmd {
                    WorkerCommand::Dispatch(task) => {
                        match fory.serialize(&task) {
                            Ok(payload) => {
                                let header = IpcHeader::new(MSG_TYPE_STAGE_DISPATCH, payload.len() as u32, 0, seq);
                                let mut frame = Vec::with_capacity(mu_ci_ipc::HEADER_SIZE + payload.len());
                                frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
                                frame.extend_from_slice(&payload);
                                match tokio::time::timeout(
                                    std::time::Duration::from_secs(10),
                                    ws_sender.send(Message::Binary(frame.into())),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {
                                        info!(stage = %task.stage_id, "Dispatched stage frame successfully sent to ws_sender");
                                    }
                                    Ok(Err(e)) => {
                                        error!("Failed to send dispatch frame over ws: {}", e);
                                        break;
                                    }
                                    Err(_) => {
                                        error!(node = %node_id, stage = %task.stage_id, "Timed out (10s) sending dispatch frame over ws");
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                error!(stage = %task.stage_id, error = %e, "Failed to serialize StageDispatchTask with Fory");
                            }
                        }
                    }
                    WorkerCommand::Cancel(cancel) => {
                        if let Ok(payload) = fory.serialize(&cancel) {
                            let header = IpcHeader::new(MSG_TYPE_STAGE_CANCEL, payload.len() as u32, 0, seq);
                            let mut frame = Vec::with_capacity(mu_ci_ipc::HEADER_SIZE + payload.len());
                            frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
                            frame.extend_from_slice(&payload);
                            if tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                ws_sender.send(Message::Binary(frame.into())),
                            )
                            .await
                            .is_err()
                            {
                                warn!(node = %node_id, "Timed out (10s) sending cancel frame over ws");
                                break;
                            }
                        }
                    }
                    WorkerCommand::Disconnect => {
                        let close_frame = axum::extract::ws::CloseFrame {
                            code: axum::extract::ws::close_code::NORMAL,
                            reason: "controller demoted to standby".into(),
                        };
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            ws_sender.send(Message::Close(Some(close_frame))),
                        )
                        .await;
                        break;
                    }
                }
            }

            // Inbound messages received from worker
            msg_res = ws_receiver.next() => {
                let msg = match msg_res {
                    Some(Ok(m)) => m,
                    _ => break, // Disconnected
                };

                match msg {
                    Message::Ping(payload) => {
                        if !state.job_store.is_leader() {
                            warn!(
                                node = %node_id,
                                controller_id = %state.config.node_id,
                                "Evicting worker tunnel on Ping: controller is not Leader"
                            );
                            let close_frame = axum::extract::ws::CloseFrame {
                                code: axum::extract::ws::close_code::NORMAL,
                                reason: "controller demoted to standby".into(),
                            };
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(10),
                                ws_sender.send(Message::Close(Some(close_frame))),
                            )
                            .await;
                            break;
                        }
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            ws_sender.send(Message::Pong(payload)),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            _ => break,
                        }
                    }
                    Message::Close(_) => break,
                    Message::Binary(bin) => {
                        if let Ok((hdr, payload)) = IpcHeader::parse(&bin) {
                            match hdr.msg_type {
                                MSG_TYPE_WORKER_HEARTBEAT => {
                                    if !state.job_store.is_leader() {
                                        warn!(
                                            node = %node_id,
                                            controller_id = %state.config.node_id,
                                            "Evicting worker tunnel on Heartbeat: controller is not Leader"
                                        );
                                        let close_frame = axum::extract::ws::CloseFrame {
                                            code: axum::extract::ws::close_code::NORMAL,
                                            reason: "controller demoted to standby".into(),
                                        };
                                        let _ = tokio::time::timeout(
                                            std::time::Duration::from_secs(10),
                                            ws_sender.send(Message::Close(Some(close_frame))),
                                        )
                                        .await;
                                        break;
                                    }
                                    if let Ok(hb) = fory.deserialize::<WorkerHeartbeat>(payload) {
                                        state.cluster.heartbeat(hb).await;
                                        // Acknowledge heartbeat at application layer so the worker's
                                        // inbound read-liveness deadline is refreshed every 5s (#104, #39).
                                        match tokio::time::timeout(
                                            std::time::Duration::from_secs(10),
                                            ws_sender.send(Message::Pong(Vec::new().into())),
                                        )
                                        .await
                                        {
                                            Ok(Ok(())) => {}
                                            _ => break,
                                        }
                                    }
                                }
                            MSG_TYPE_STAGE_COMPLETION => {
                                if let Ok(report) = fory.deserialize::<StageCompletionReport>(payload) {
                                    info!(
                                        node = %node_id,
                                        job_id = %report.job_id,
                                        stage = %report.stage_id,
                                        exit_code = report.exit_code,
                                        duration = report.duration_secs,
                                        "Stage completed by worker"
                                    );

                                    let status = if report.exit_code == 0 {
                                        StageStatus::Completed {
                                            duration_secs: report.duration_secs,
                                            exit_code: report.exit_code,
                                        }
                                    } else {
                                        StageStatus::Failed {
                                            error: report.error_message.clone().unwrap_or_else(|| {
                                                format!("Process exited with code {}", report.exit_code)
                                            }),
                                        }
                                    };

                                    // Flush any buffered stage logs and release the stage slot so any job woken by
                                    // `update_stage_status` / `notify_event` sees the freed node slot and completed status.
                                    state.job_store.flush_job_log(Some(&report.job_id));

                                    // Emit stage W3C trace span to MuObserve telemetry
                                    let commit_sha = state
                                        .job_store
                                        .get_job(&report.job_id)
                                        .await
                                        .map(|j| j.job.commit_sha)
                                        .unwrap_or_default();
                                    let root_ctx =
                                        job_root_trace_context(&report.job_id, &commit_sha);
                                    let stage_ctx = job_stage_trace_context(
                                        &report.job_id,
                                        &commit_sha,
                                        &report.stage_id,
                                    );
                                    let now_ns = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_nanos() as i64;
                                    let duration_ns = report.duration_secs.saturating_mul(1_000_000_000);
                                    let start_ns = (now_ns - duration_ns as i64).max(0);
                                    let (span_status_code, span_status_msg) = if report.exit_code == 0 {
                                        ("OK".to_string(), None)
                                    } else {
                                        ("ERROR".to_string(), report.error_message.clone())
                                    };
                                    let span_entry = OtelSpanEntry {
                                        trace_id: encode_hex(&stage_ctx.trace_id),
                                        span_id: encode_hex(&stage_ctx.span_id),
                                        parent_span_id: Some(encode_hex(&root_ctx.span_id)),
                                        service_name: "mu-ci-controller".to_string(),
                                        node_id: node_id.clone(),
                                        span_name: format!("ci.stage.dispatch:{}", report.stage_id),
                                        span_kind: "INTERNAL".to_string(),
                                        start_time_unix_nano: start_ns,
                                        end_time_unix_nano: now_ns,
                                        duration_ns,
                                        status_code: span_status_code,
                                        status_message: span_status_msg,
                                        attributes_json: format!(
                                            r#"{{"job_id":"{}","stage_id":"{}","exit_code":{}}}"#,
                                            report.job_id, report.stage_id, report.exit_code
                                        ),
                                    };
                                    state.job_store.emit_trace_spans(&[span_entry]);

                                    state
                                        .cluster
                                        .release_stage_slot(
                                            &node_id,
                                            &report.job_id,
                                            &report.stage_id,
                                        )
                                        .await;
                                    state
                                        .job_store
                                        .update_stage_status(
                                            &report.job_id,
                                            &report.stage_id,
                                            status,
                                        )
                                        .await;
                                    state.job_store.notify_event();
                                }
                            }
                            MSG_TYPE_WORKER_SHUTDOWN => {
                                if let Ok(shutdown) = fory.deserialize::<WorkerShutdown>(payload) {
                                    info!(
                                        node = %node_id,
                                        reason = %shutdown.reason,
                                        interrupted = ?shutdown.interrupted_stages,
                                        "Worker signaled shutdown/restart"
                                    );
                                    state.cluster.release_slot(&node_id).await;
                                    let recovered = state
                                        .job_store
                                        .recover_stages_for_node(
                                            &node_id,
                                            Some(&shutdown.interrupted_stages),
                                        )
                                        .await;
                                    for (job_id, stage_id) in &recovered {
                                        if let Some(record) = state.job_store.get_job(job_id).await
                                        {
                                            let note = format!(
                                                "{} [{}] [{}] [stderr] Worker signaled restart; stage execution interrupted and returned to queue for re-dispatch\n",
                                                chrono::Utc::now().to_rfc3339(),
                                                node_id,
                                                stage_id
                                            );
                                            append_note_to_job_log_bounded(
                                                &state,
                                                &record.log_file,
                                                &note,
                                            )
                                            .await;
                                            state.job_store.append_log_lines(job_id, &note);
                                            state.broadcast_log(job_id, &note);
                                        }
                                    }
                                    state.job_store.notify_event();
                                }
                            }
                            MSG_TYPE_STAGE_STARTED => {
                                if let Ok(started) = fory.deserialize::<StageStarted>(payload) {
                                    info!(
                                        job_id = %started.job_id,
                                        stage_id = %started.stage_id,
                                        node_id = %started.node_id,
                                        pid = started.pid,
                                        "Worker reported stage process spawned with PID"
                                    );
                                    state
                                        .job_store
                                        .update_stage_running(
                                            &started.job_id,
                                            &started.stage_id,
                                            &started.node_id,
                                            started.pid,
                                        )
                                        .await;
                                }
                            }
                            MSG_TYPE_ARROW_LOG => {
                                if let Ok(entries) = decode_log_batch(payload) {
                                    if let Some(first) = entries.first() {
                                        let job_id = first.job_id.clone();
                                        if let Some(record) = state.job_store.get_job(&job_id).await {
                                            let ws_dir = state.config.workspace_dir.clone();
                                            let rel_log = record.log_file.clone();
                                            let entries_for_disk = entries.clone();
                                            let disk_res = tokio::time::timeout(
                                                std::time::Duration::from_secs(5),
                                                tokio::task::spawn_blocking(
                                                    move || -> std::io::Result<()> {
                                                        let Some(full_path) =
                                                            resolve_safe_log_path(&ws_dir, &rel_log)
                                                        else {
                                                            return Err(std::io::Error::new(
                                                                std::io::ErrorKind::InvalidInput,
                                                                "invalid log path",
                                                            ));
                                                        };
                                                        append_logs(&full_path, &entries_for_disk)
                                                    },
                                                ),
                                            )
                                            .await;
                                            match disk_res {
                                                Ok(Ok(Ok(()))) => {
                                                    state.job_store.mark_disk_io_healthy();
                                                }
                                                _ => {
                                                    state.job_store.mark_disk_io_unhealthy();
                                                }
                                            }
                                            state
                                                .job_store
                                                .append_structured_log_entries(&job_id, &entries)
                                                .await;
                                            let chunk = format_log_entries(&entries);
                                            let _ = state.log_broadcaster.send(crate::webhook::LogBroadcast {
                                                job_id,
                                                chunk,
                                            });
                                        }
                                    }
                                }
                            }
                            MSG_TYPE_ARROW_METRIC => {
                                if let Ok(metric_entries) = decode_metric_batch(payload) {
                                    if let Some(first) = metric_entries.first() {
                                        let aggregated = aggregate_metrics(&metric_entries, true);
                                        state.job_store.update_metrics(&first.job_id, aggregated).await;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    }
                    _ => {}
                }
            }
        }
    }

    state.cluster.unregister(&node_id).await;
    // Auto-recover any remaining stages assigned to this worker node
    let recovered = state
        .job_store
        .recover_stages_for_node(&node_id, None)
        .await;
    if !recovered.is_empty() {
        warn!(
            node = %node_id,
            count = recovered.len(),
            "Worker disconnected; recovered orphan stages back to Pending"
        );
        for (job_id, stage_id) in &recovered {
            if let Some(record) = state.job_store.get_job(job_id).await {
                let note = format!(
                    "{} [controller] [{}] [stderr] Worker '{}' disconnected unexpectedly; stage returned to queue for recovery\n",
                    chrono::Utc::now().to_rfc3339(),
                    stage_id,
                    node_id
                );
                append_note_to_job_log_bounded(&state, &record.log_file, &note).await;
                state.job_store.append_log_lines(job_id, &note);
                state.broadcast_log(job_id, &note);
            }
        }
        state.job_store.notify_event();
    }
    info!(node = %node_id, "Cluster tunnel session terminated");
}

pub(crate) fn resolve_safe_log_path(
    workspace_dir: &std::path::Path,
    rel_log_file: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let canonical_ws = std::fs::canonicalize(workspace_dir).ok()?;
    let mut safe_rel = std::path::PathBuf::new();
    for comp in rel_log_file.components() {
        match comp {
            std::path::Component::Normal(seg) => {
                let s = seg.to_str()?;
                if s.is_empty() || s == "." || s == ".." || s.contains('/') || s.contains('\\') {
                    return None;
                }
                safe_rel.push(s);
            }
            _ => return None,
        }
    }
    if safe_rel.as_os_str().is_empty() {
        return None;
    }
    let joined = canonical_ws.join(&safe_rel);
    if !joined.starts_with(&canonical_ws) {
        return None;
    }
    let parent = joined.parent()?;
    if !parent.starts_with(&canonical_ws) {
        return None;
    }
    std::fs::create_dir_all(parent).ok()?;
    let canonical_parent = std::fs::canonicalize(parent).ok()?;
    if !canonical_parent.starts_with(&canonical_ws) {
        return None;
    }
    let file_name = joined.file_name()?.to_str()?;
    if file_name.contains("..") || file_name.contains('/') || file_name.contains('\\') {
        return None;
    }
    let final_path = canonical_parent.join(file_name);
    if !final_path.starts_with(&canonical_ws) {
        return None;
    }
    Some(final_path)
}

pub(crate) async fn append_note_to_job_log_bounded(
    state: &Arc<AppState>,
    rel_log_file: &std::path::Path,
    note: &str,
) {
    let ws_dir = state.config.workspace_dir.clone();
    let rel = rel_log_file.to_path_buf();
    let note_owned = note.to_string();
    let write_res = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let Some(full_path) = resolve_safe_log_path(&ws_dir, &rel) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "invalid log path",
                ));
            };
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&full_path)?;
            f.write_all(note_owned.as_bytes())
        }),
    )
    .await;
    match write_res {
        Ok(Ok(Ok(()))) => state.job_store.mark_disk_io_healthy(),
        _ => state.job_store.mark_disk_io_unhealthy(),
    }
}
