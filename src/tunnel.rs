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

use action_runner_ipc::{
    create_fory_runtime, decode_log_batch, decode_metric_batch, IpcHeader, StageCompletionReport,
    WorkerHeartbeat, WorkerRegistration, MSG_TYPE_ARROW_LOG, MSG_TYPE_ARROW_METRIC,
    MSG_TYPE_STAGE_CANCEL, MSG_TYPE_STAGE_COMPLETION, MSG_TYPE_STAGE_DISPATCH,
    MSG_TYPE_WORKER_HEARTBEAT, MSG_TYPE_WORKER_REGISTRATION,
};

use crate::aggregator::{aggregate_metrics, append_logs};
use crate::cluster::WorkerCommand;
use crate::job::StageStatus;
use crate::webhook::AppState;

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
            Some(cmd) = cmd_rx.recv() => {
                seq += 1;
                match cmd {
                    WorkerCommand::Dispatch(task) => {
                        if let Ok(payload) = fory.serialize(&task) {
                            let header = IpcHeader::new(MSG_TYPE_STAGE_DISPATCH, payload.len() as u32, 0, seq);
                            let mut frame = Vec::with_capacity(action_runner_ipc::HEADER_SIZE + payload.len());
                            frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
                            frame.extend_from_slice(&payload);
                            let _ = ws_sender.send(Message::Binary(frame.into())).await;
                        }
                    }
                    WorkerCommand::Cancel(cancel) => {
                        if let Ok(payload) = fory.serialize(&cancel) {
                            let header = IpcHeader::new(MSG_TYPE_STAGE_CANCEL, payload.len() as u32, 0, seq);
                            let mut frame = Vec::with_capacity(action_runner_ipc::HEADER_SIZE + payload.len());
                            frame.extend_from_slice(zerocopy::IntoBytes::as_bytes(&header));
                            frame.extend_from_slice(&payload);
                            let _ = ws_sender.send(Message::Binary(frame.into())).await;
                        }
                    }
                }
            }

            // Inbound messages received from worker
            msg_res = ws_receiver.next() => {
                let msg = match msg_res {
                    Some(Ok(m)) => m,
                    _ => break, // Disconnected
                };

                if let Message::Binary(bin) = msg {
                    if let Ok((hdr, payload)) = IpcHeader::parse(&bin) {
                        match hdr.msg_type {
                            MSG_TYPE_WORKER_HEARTBEAT => {
                                if let Ok(hb) = fory.deserialize::<WorkerHeartbeat>(payload) {
                                    state.cluster.heartbeat(hb).await;
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
                                            error: report.error_message.unwrap_or_else(|| {
                                                format!("Process exited with code {}", report.exit_code)
                                            }),
                                        }
                                    };

                                    state.job_store.update_stage_status(&report.job_id, &report.stage_id, status).await;
                                    state.cluster.release_slot(&node_id).await;
                                    state.job_store.notify_event();
                                }
                            }
                            MSG_TYPE_ARROW_LOG => {
                                if let Ok(entries) = decode_log_batch(payload) {
                                    if let Some(first) = entries.first() {
                                        if let Some(record) = state.job_store.get_job(&first.stage_id).await {
                                            let _ = append_logs(&record.log_file, &entries);
                                        }
                                    }
                                }
                            }
                            MSG_TYPE_ARROW_METRIC => {
                                if let Ok(metric_entries) = decode_metric_batch(payload) {
                                    if let Some(first) = metric_entries.first() {
                                        let aggregated = aggregate_metrics(&metric_entries, true);
                                        state.job_store.update_metrics(&first.stage_id, aggregated).await;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    state.cluster.unregister(&node_id).await;
    info!(node = %node_id, "Cluster tunnel session terminated");
}
