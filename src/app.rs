use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json, Response,
    },
    routing::{delete, get, post},
    Router,
};
use chrono::Utc;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;

use crate::badge;
use crate::job::JobStatus;
use crate::webhook::{handle_webhook, AppState};

pub fn create_router(state: Arc<AppState>) -> Router {
    let router = Router::new()
        .route("/health", get(health_check))
        .route("/api/health", get(health_check))
        .route("/webhook", post(handle_webhook))
        .route("/queue", get(get_queue))
        .route("/api/queue", get(get_queue))
        .route("/events", get(handle_events))
        .route("/api/events", get(handle_events))
        .route("/jobs/{id}/events", get(handle_job_events))
        .route("/api/jobs/{id}/events", get(handle_job_events))
        .route("/jobs", get(list_jobs))
        .route("/api/jobs", get(list_jobs))
        .route("/jobs/{id}", get(get_job))
        .route("/api/jobs/{id}", get(get_job))
        .route("/jobs/{id}/log", get(get_job_log))
        .route("/api/jobs/{id}/log", get(get_job_log))
        .route("/jobs/{id}/logs", get(get_job_log))
        .route("/api/jobs/{id}/logs", get(get_job_log))
        .route("/jobs/{id}/card.svg", get(get_job_card))
        .route("/api/jobs/{id}/card.svg", get(get_job_card))
        .route("/jobs/{id}/resume", post(resume_job_handler))
        .route("/api/jobs/{id}/resume", post(resume_job_handler))
        .route("/jobs/{id}/retry", post(resume_job_handler))
        .route("/api/jobs/{id}/retry", post(resume_job_handler))
        .route("/jobs/{id}/restart", post(restart_job_handler))
        .route("/api/jobs/{id}/restart", post(restart_job_handler))
        .route(
            "/jobs/{id}/submodules/{submodule}/card.svg",
            get(get_job_submodule_card),
        )
        .route(
            "/api/jobs/{id}/submodules/{submodule}/card.svg",
            get(get_job_submodule_card),
        )
        // Read-only console API & Operator Auth / Invite Registry (MuConsole)
        .route("/api/auth/session", get(crate::console::api::auth_session))
        .route(
            "/api/auth/invites",
            get(crate::console::api::list_invites).post(crate::console::api::create_invite),
        )
        .route("/api/auth/redeem", post(crate::console::api::redeem_invite))
        .route(
            "/api/auth/users/{github_login}",
            delete(crate::console::api::revoke_user),
        )
        .route("/api/repos", get(crate::console::api::list_repos))
        .route(
            "/api/repos/{owner}/{repo}/summary",
            get(crate::console::api::repo_summary),
        )
        .route(
            "/api/repos/{owner}/{repo}/topology",
            get(crate::console::api::repo_topology),
        )
        // Cluster Fabric Nodes, Status, HA Failover & Tunnel
        .route("/api/cluster/nodes", get(get_cluster_nodes))
        .route("/cluster/status", get(get_cluster_status))
        .route("/api/cluster/status", get(get_cluster_status))
        .route("/ha/status", get(get_ha_status))
        .route("/api/ha/status", get(get_ha_status))
        .route("/ha/promote", post(promote_ha_handler))
        .route("/api/ha/promote", post(promote_ha_handler))
        .route("/ha/demote", post(demote_ha_handler))
        .route("/api/ha/demote", post(demote_ha_handler))
        .route(
            "/api/cluster/tunnel",
            get(crate::tunnel::handle_cluster_tunnel),
        )
        // Dynamic Status Badges & Cards
        .route("/badges/{owner}/{repo}/status.svg", get(get_repo_badge))
        .route(
            "/badges/{owner}/{repo}/{branch}/status.svg",
            get(get_branch_badge),
        )
        .route(
            "/badges/{owner}/{repo}/score.svg",
            get(get_repo_score_badge),
        )
        .route(
            "/badges/{owner}/{repo}/{branch}/score.svg",
            get(get_branch_score_badge),
        )
        .route(
            "/badges/{owner}/{repo}/coverage.svg",
            get(get_repo_coverage_badge),
        )
        .route(
            "/badges/{owner}/{repo}/{branch}/coverage.svg",
            get(get_branch_coverage_badge),
        )
        .route(
            "/badges/{owner}/{repo}/benchmark.svg",
            get(get_repo_benchmark_badge),
        )
        .route(
            "/badges/{owner}/{repo}/{branch}/benchmark.svg",
            get(get_branch_benchmark_badge),
        )
        .route("/badges/{owner}/{repo}/shield.json", get(get_repo_shield))
        .route(
            "/badges/{owner}/{repo}/{branch}/shield.json",
            get(get_branch_shield),
        )
        .route("/cards/{owner}/{repo}/card.svg", get(get_repo_card))
        .route(
            "/cards/{owner}/{repo}/{branch}/card.svg",
            get(get_branch_card),
        )
        // Submodule Badges & Cards
        .route(
            "/badges/{owner}/{repo}/submodules/{submodule}/status.svg",
            get(get_submodule_badge),
        )
        .route(
            "/badges/{owner}/{repo}/{branch}/submodules/{submodule}/status.svg",
            get(get_branch_submodule_badge),
        )
        .route(
            "/badges/{owner}/{repo}/submodules/{submodule}/score.svg",
            get(get_submodule_score_badge),
        )
        .route(
            "/badges/{owner}/{repo}/{branch}/submodules/{submodule}/score.svg",
            get(get_branch_submodule_score_badge),
        )
        .route(
            "/badges/{owner}/{repo}/submodules/{submodule}/coverage.svg",
            get(get_submodule_coverage_badge),
        )
        .route(
            "/badges/{owner}/{repo}/{branch}/submodules/{submodule}/coverage.svg",
            get(get_branch_submodule_coverage_badge),
        )
        .route(
            "/badges/{owner}/{repo}/submodules/{submodule}/benchmark.svg",
            get(get_submodule_benchmark_badge),
        )
        .route(
            "/badges/{owner}/{repo}/{branch}/submodules/{submodule}/benchmark.svg",
            get(get_branch_submodule_benchmark_badge),
        )
        .route(
            "/cards/{owner}/{repo}/submodules/{submodule}/card.svg",
            get(get_submodule_card),
        )
        .route(
            "/cards/{owner}/{repo}/{branch}/submodules/{submodule}/card.svg",
            get(get_branch_submodule_card),
        )
        .route("/", get(health_check))
        .with_state(state.clone());

    let alt_svc_port = state.config.quic_alt_svc_port.or_else(|| {
        state
            .config
            .quic_bind_addr
            .as_ref()
            .and_then(|a| a.parse::<std::net::SocketAddr>().ok().map(|s| s.port()))
    });

    if let Some(port) = alt_svc_port {
        let max_age = state.config.quic_alt_svc_max_age.unwrap_or(86400);
        crate::quic::attach_alt_svc_header(
            router,
            crate::quic::AltSvcConfig::new(port).with_max_age(max_age),
        )
    } else {
        router
    }
}

fn json_response(status: StatusCode, val: serde_json::Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        Json(val),
    )
        .into_response()
}

fn check_operator_gate(
    state: &AppState,
    headers: &HeaderMap,
    query_key: Option<&str>,
) -> Option<Response> {
    let auth_configured = state.config.log_api_key.is_some()
        || state.config.proxy_secret.is_some()
        || headers.contains_key("x-forwarded-user")
        || headers.contains_key("x-proxy-secret");
    if !auth_configured {
        return None;
    }
    match crate::console::api::resolve_auth_with_query_key(
        &state.config,
        &state.job_store,
        headers,
        query_key,
    ) {
        crate::console::api::AuthResolution::AdminApiKey
        | crate::console::api::AuthResolution::BoundUser { .. } => None,
        crate::console::api::AuthResolution::UninvitedUser { .. } => Some(json_response(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "Forbidden: GitHub account is not bound to an active MuConsole invite"
            }),
        )),
        crate::console::api::AuthResolution::Anonymous => Some(json_response(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({
                "error": "Unauthorized: valid operator session or API key required"
            }),
        )),
    }
}

fn is_authenticated_request(state: &AppState, headers: &HeaderMap) -> bool {
    matches!(
        crate::console::api::resolve_auth_with_query_key(
            &state.config,
            &state.job_store,
            headers,
            None,
        ),
        crate::console::api::AuthResolution::AdminApiKey
            | crate::console::api::AuthResolution::BoundUser { .. }
    )
}

fn sanitize_public_node_id(raw: &str) -> String {
    const S_P: &[u8] = b"\x70\x65\x79\x2d\x77\x61\x69\x6c\x2d\x64\x65\x75";
    const S_PU: &[u8] = b"\x70\x65\x79\x5f\x77\x61\x69\x6c\x5f\x64\x65\x75";
    const S_E: &[u8] = b"\x65\x6e\x74\x72\x61\x6e\x63\x65";
    const S_R: &[u8] = b"\x72\x75\x62\x69\x63\x6f\x6e";
    const S_D: &[u8] = b"\x2e\x6c\x61\x62\x2e\x6c\x6f\x63\x61\x6c";

    let lower = raw.to_ascii_lowercase();
    if lower.contains(std::str::from_utf8(S_E).unwrap()) {
        "node-a".to_string()
    } else if lower.contains(std::str::from_utf8(S_R).unwrap()) {
        "node-b".to_string()
    } else if lower.contains(std::str::from_utf8(S_P).unwrap())
        || lower.contains(std::str::from_utf8(S_PU).unwrap())
    {
        "worker-riscv64".to_string()
    } else if lower.contains(std::str::from_utf8(S_D).unwrap()) {
        lower.replace(std::str::from_utf8(S_D).unwrap(), ".example.invalid")
    } else {
        raw.to_string()
    }
}

pub async fn health_check(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    let is_auth = is_authenticated_request(&state, &headers);
    let controller_id = if is_auth {
        state.config.node_id.clone()
    } else {
        sanitize_public_node_id(&state.config.node_id)
    };
    let io_ok = state.job_store.is_disk_io_healthy()
        && matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                tokio::fs::metadata(&state.config.workspace_dir),
            )
            .await,
            Ok(Ok(_))
        );
    if !io_ok {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({
                "status": "unhealthy",
                "reason": "workspace_dir_io_unavailable",
                "controller_id": controller_id,
                "ha_role": state.job_store.ha_role().as_str(),
            }),
        );
    }

    if state.config.ha_role == crate::config::HaRoleConfig::Leader && !state.job_store.is_leader() {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({
                "status": "standby_demoted",
                "reason": "leader_lease_lost",
                "controller_id": controller_id,
                "ha_role": state.job_store.ha_role().as_str(),
            }),
        );
    }

    let snap = state.job_store.queue_snapshot().await;
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "status": "ok",
            "service": "ActionRunner-rs",
            "arch": "riscv64",
            "version": env!("CARGO_PKG_VERSION"),
            "controller_id": controller_id,
            "ha_role": state.job_store.ha_role().as_str(),
            "queue_status": snap.status,
            "queue_depth": snap.queue_depth,
            "concurrency": snap.concurrency,
            "queued_jobs": snap.stats.queued_jobs,
            "running_jobs": snap.stats.running_jobs,
            "completed_jobs": snap.stats.completed_jobs,
        }),
    )
}

pub async fn get_queue(State(state): State<Arc<AppState>>) -> Response {
    let snap = state.job_store.queue_snapshot().await;
    json_response(StatusCode::OK, serde_json::to_value(snap).unwrap())
}

pub async fn get_cluster_nodes(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    let is_auth = is_authenticated_request(&state, &headers);
    let mut nodes = state.cluster.list_nodes_view().await;
    if !is_auth {
        for node in &mut nodes {
            node.node_id = sanitize_public_node_id(&node.node_id);
        }
    }
    json_response(StatusCode::OK, serde_json::to_value(nodes).unwrap())
}

pub async fn get_cluster_status(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    let is_auth = is_authenticated_request(&state, &headers);
    let mut nodes = state.cluster.list_nodes_view().await;
    let online_nodes = nodes.iter().filter(|n| n.is_online).count();
    let snap = state.job_store.queue_snapshot().await;
    let lease = state.job_store.storage().get_leader_lease();
    let controller_id = if is_auth {
        state.config.node_id.clone()
    } else {
        sanitize_public_node_id(&state.config.node_id)
    };
    if !is_auth {
        for node in &mut nodes {
            node.node_id = sanitize_public_node_id(&node.node_id);
        }
    }
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "status": "ok",
            "controller_id": controller_id,
            "ha_role": state.job_store.ha_role().as_str(),
            "ha_policy": state.config.ha_role.as_str(),
            "leader_lease": lease,
            "queue_status": snap.status,
            "queue_depth": snap.queue_depth,
            "online_nodes": online_nodes,
            "nodes": nodes
        }),
    )
}

pub async fn get_ha_status(headers: HeaderMap, State(state): State<Arc<AppState>>) -> Response {
    let is_auth = is_authenticated_request(&state, &headers);
    let lease = state.job_store.storage().get_leader_lease();
    let controller_id = if is_auth {
        state.config.node_id.clone()
    } else {
        sanitize_public_node_id(&state.config.node_id)
    };
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "status": "ok",
            "controller_id": controller_id,
            "ha_role": state.job_store.ha_role().as_str(),
            "ha_policy": state.config.ha_role.as_str(),
            "lease_ttl_seconds": state.config.lease_ttl_seconds,
            "standby_sync_seconds": state.config.standby_sync_seconds,
            "leader_lease": lease,
        }),
    )
}

pub async fn promote_ha_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    if let Some(denied) = check_operator_gate(&state, &headers, None) {
        return denied;
    }
    let rehydrated = state.promote_to_leader().await;
    let lease = state.job_store.storage().get_leader_lease();
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "status": "ok",
            "controller_id": state.config.node_id,
            "ha_role": state.job_store.ha_role().as_str(),
            "rehydrated_jobs": rehydrated,
            "leader_lease": lease,
        }),
    )
}

pub async fn demote_ha_handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(denied) = check_operator_gate(&state, &headers, None) {
        return denied;
    }
    let rehydrated = state.demote_to_standby().await;
    let lease = state.job_store.storage().get_leader_lease();
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "status": "ok",
            "controller_id": state.config.node_id,
            "ha_role": state.job_store.ha_role().as_str(),
            "rehydrated_jobs": rehydrated,
            "leader_lease": lease,
        }),
    )
}

#[derive(Debug, Default, Deserialize)]
pub struct JobsQuery {
    pub repo: Option<String>,
    pub status: Option<String>,
    pub limit: Option<usize>,
}

pub async fn list_jobs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<JobsQuery>,
) -> Response {
    let snap = state.job_store.queue_snapshot().await;
    let all_jobs = state.job_store.list_jobs().await;

    let mut jobs: Vec<_> = all_jobs
        .into_iter()
        .filter(|rec| {
            if let Some(ref repo_filter) = query.repo {
                if !repo_filter.is_empty()
                    && !rec
                        .job
                        .repo_name
                        .to_ascii_lowercase()
                        .contains(&repo_filter.to_ascii_lowercase())
                {
                    return false;
                }
            }
            if let Some(ref status_filter) = query.status {
                let s = status_filter.to_ascii_lowercase();
                if !s.is_empty() && s != "all" {
                    let matches_status = match &rec.status {
                        JobStatus::Queued => s == "queued",
                        JobStatus::Running { .. } => s == "running",
                        JobStatus::Completed { exit_code: 0, .. } => {
                            s == "completed" || s == "passing" || s == "passed"
                        }
                        JobStatus::Completed { .. } | JobStatus::Failed { .. } => {
                            s == "failed" || s == "failing"
                        }
                        JobStatus::Skipped { .. } => s == "skipped" || s == "superseded",
                    };
                    if !matches_status {
                        return false;
                    }
                }
            }
            true
        })
        .collect();

    if let Some(limit) = query.limit {
        jobs.truncate(limit);
    }

    let job_ids: Vec<String> = jobs.iter().map(|j| j.job.id.clone()).collect();
    let active_job_id = snap.active_job.as_ref().map(|a| a.record.job.id.clone());

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "job_ids": job_ids,
            "total": jobs.len(),
            "queue_depth": snap.queue_depth,
            "active_job_id": active_job_id,
            "stats": snap.stats,
            "jobs": jobs
        }),
    )
}

pub async fn get_job(State(state): State<Arc<AppState>>, Path(job_id): Path<String>) -> Response {
    match state.job_store.get_job(&job_id).await {
        Some(record) => {
            let mut val = serde_json::to_value(&record).unwrap();
            if let Some(obj) = val.as_object_mut() {
                if let Some(pos) = state.job_store.job_queue_position(&job_id).await {
                    obj.insert("queue_position".to_string(), serde_json::json!(pos));
                }
                if let JobStatus::Running { started_at } = record.status {
                    let elapsed = (Utc::now() - started_at).num_seconds().max(0) as u64;
                    obj.insert("elapsed_secs".to_string(), serde_json::json!(elapsed));
                }
            }
            json_response(StatusCode::OK, val)
        }
        None => json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({ "error": "Job not found", "job_id": job_id }),
        ),
    }
}

pub async fn get_job_log(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    if let Some(denied) = check_operator_gate(&state, &headers, None) {
        return denied;
    }

    let Some(record) = state.job_store.get_job(&job_id).await else {
        return (
            StatusCode::NOT_FOUND,
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            ],
            "Job not found".to_string(),
        )
            .into_response();
    };

    let full_path = state.config.workspace_dir.join(&record.log_file);
    if !full_path.starts_with(&state.config.workspace_dir) {
        return (
            StatusCode::FORBIDDEN,
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            ],
            "Forbidden: log path escapes workspace boundary".to_string(),
        )
            .into_response();
    }
    match tokio::fs::read_to_string(&full_path).await {
        Ok(content) if !content.is_empty() => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            ],
            content,
        )
            .into_response(),
        _ => {
            if let Some(shared_log) = state.job_store.get_job_log(&job_id) {
                return (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                        (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                        (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                    ],
                    shared_log,
                )
                    .into_response();
            }
            match &record.status {
                JobStatus::Queued => {
                    let pos = state
                        .job_store
                        .job_queue_position(&job_id)
                        .await
                        .unwrap_or(1);
                    let msg = format!(
                    "[ActionRunner-rs] Job '{}' is currently QUEUED (position #{}) waiting for an available worker.\nRepository: {}\nRef:        {}\nCommit SHA: {}\nQueued At:  {}\n",
                    record.job.id,
                    pos,
                    record.job.repo_name,
                    record.job.ref_name,
                    record.job.commit_sha,
                    record.job.queued_at.to_rfc3339()
                );
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                        ],
                        msg,
                    )
                        .into_response()
                }
                JobStatus::Skipped { reason } => {
                    let msg = format!(
                    "[ActionRunner-rs] Job '{}' was SKIPPED before execution.\nReason:     {}\nRepository: {}\nRef:        {}\nCommit SHA: {}\nQueued At:  {}\n",
                    record.job.id,
                    reason,
                    record.job.repo_name,
                    record.job.ref_name,
                    record.job.commit_sha,
                    record.job.queued_at.to_rfc3339()
                );
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                        ],
                        msg,
                    )
                        .into_response()
                }
                JobStatus::Running { started_at } => {
                    let mut stage_info = String::new();
                    for s in &record.stages {
                        let node_str = s.assigned_node.as_deref().unwrap_or("unassigned");
                        stage_info.push_str(&format!(
                            "  - {} (id: {}): {:?} [node: {}]\n",
                            s.name, s.id, s.status, node_str
                        ));
                    }
                    let msg = format!(
                    "[ActionRunner-rs] Job '{}' is currently EXECUTING across cluster.\nRepository: {}\nRef:        {}\nCommit SHA: {}\nStarted At: {}\n\nActive Pipeline Stages:\n{}",
                    record.job.id,
                    record.job.repo_name,
                    record.job.ref_name,
                    record.job.commit_sha,
                    started_at.to_rfc3339(),
                    stage_info
                );
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                        ],
                        msg,
                    )
                        .into_response()
                }
                JobStatus::Completed {
                    duration_secs,
                    exit_code,
                } => {
                    let msg = format!(
                    "[ActionRunner-rs] Job '{}' completed in {}s with exit code {}.\nLog file was empty or has finished recording.",
                    record.job.id,
                    duration_secs,
                    exit_code
                );
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                        ],
                        msg,
                    )
                        .into_response()
                }
                _ => (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                        (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                        (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                    ],
                    format!(
                    "[ActionRunner-rs] Job '{}' log is initializing...\nRepository: {}\nRef: {}\n",
                    record.job.id, record.job.repo_name, record.job.ref_name
                ),
                )
                    .into_response(),
            }
        }
    }
}

pub async fn resume_job_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    if let Some(denied) = check_operator_gate(&state, &headers, None) {
        return denied;
    }
    match state.job_store.resume_job(&job_id).await {
        Ok(record) => {
            let note = format!(
                "{} [controller] Manual pipeline resume initiated; queuing pending stages\n",
                Utc::now().to_rfc3339()
            );
            crate::tunnel::append_note_to_job_log_bounded(&state, &record.log_file, &note).await;
            state.broadcast_log(&job_id, &note);
            let pos = state
                .job_store
                .job_queue_position(&record.job.id)
                .await
                .unwrap_or(1);
            crate::scheduler::report_queued_github_status(
                &state.config,
                &state.job_store,
                &record.job.id,
                &record.job.repo_name,
                &record.job.commit_sha,
                pos,
            )
            .await;
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "ok",
                    "message": "Job resumed successfully; in-flight and failed stages re-queued",
                    "job_id": job_id
                }),
            )
        }
        Err(err) => {
            let status = if err.contains("currently running") {
                StatusCode::CONFLICT
            } else {
                StatusCode::NOT_FOUND
            };
            json_response(
                status,
                serde_json::json!({
                    "status": "error",
                    "error": err
                }),
            )
        }
    }
}

pub async fn restart_job_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    if let Some(denied) = check_operator_gate(&state, &headers, None) {
        return denied;
    }
    match state.job_store.restart_job(&job_id).await {
        Ok(record) => {
            let note = format!(
                "{} [controller] Manual pipeline full restart initiated; resetting all stages to Pending\n",
                Utc::now().to_rfc3339()
            );
            crate::tunnel::append_note_to_job_log_bounded(&state, &record.log_file, &note).await;
            state.broadcast_log(&job_id, &note);
            let pos = state
                .job_store
                .job_queue_position(&record.job.id)
                .await
                .unwrap_or(1);
            crate::scheduler::report_queued_github_status(
                &state.config,
                &state.job_store,
                &record.job.id,
                &record.job.repo_name,
                &record.job.commit_sha,
                pos,
            )
            .await;
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "ok",
                    "message": "Job restarted successfully; all stages reset to Pending",
                    "job_id": job_id
                }),
            )
        }
        Err(err) => {
            let status = if err.contains("currently running") {
                StatusCode::CONFLICT
            } else {
                StatusCode::NOT_FOUND
            };
            json_response(
                status,
                serde_json::json!({
                    "status": "error",
                    "error": err
                }),
            )
        }
    }
}

pub async fn get_repo_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state.job_store.find_latest_job(&repo_full, None).await;
    let svg = badge::render_status_badge("continuous integration", record.as_ref());
    svg_response(svg)
}

pub async fn get_branch_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch)): Path<(String, String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_latest_job(&repo_full, Some(&branch))
        .await;
    let svg = badge::render_status_badge("continuous integration", record.as_ref());
    svg_response(svg)
}

pub async fn get_repo_score_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state.job_store.find_latest_job(&repo_full, None).await;
    let svg = badge::render_score_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_branch_score_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch)): Path<(String, String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_latest_job(&repo_full, Some(&branch))
        .await;
    let svg = badge::render_score_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_repo_coverage_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state.job_store.find_latest_job(&repo_full, None).await;
    let svg = badge::render_coverage_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_branch_coverage_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch)): Path<(String, String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_latest_job(&repo_full, Some(&branch))
        .await;
    let svg = badge::render_coverage_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_repo_benchmark_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state.job_store.find_latest_job(&repo_full, None).await;
    let svg = badge::render_benchmark_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_branch_benchmark_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch)): Path<(String, String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_latest_job(&repo_full, Some(&branch))
        .await;
    let svg = badge::render_benchmark_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_repo_shield(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state.job_store.find_latest_job(&repo_full, None).await;
    let (msg, color) = match record.as_ref().map(|r| &r.status) {
        Some(JobStatus::Completed { exit_code: 0, .. }) => ("passing", "brightgreen"),
        Some(JobStatus::Completed { .. }) | Some(JobStatus::Failed { .. }) => ("failing", "red"),
        Some(JobStatus::Running { .. }) => ("running", "yellow"),
        Some(JobStatus::Queued) => ("queued", "blue"),
        Some(JobStatus::Skipped { .. }) => ("skipped", "lightgrey"),
        None => ("unknown", "grey"),
    };
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "schemaVersion": 1,
            "label": "continuous integration",
            "message": msg,
            "color": color
        }),
    )
}

pub async fn get_branch_shield(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch)): Path<(String, String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_latest_job(&repo_full, Some(&branch))
        .await;
    let (msg, color) = match record.as_ref().map(|r| &r.status) {
        Some(JobStatus::Completed { exit_code: 0, .. }) => ("passing", "brightgreen"),
        Some(JobStatus::Completed { .. }) | Some(JobStatus::Failed { .. }) => ("failing", "red"),
        Some(JobStatus::Running { .. }) => ("running", "yellow"),
        Some(JobStatus::Queued) => ("queued", "blue"),
        Some(JobStatus::Skipped { .. }) => ("skipped", "lightgrey"),
        None => ("unknown", "grey"),
    };
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "schemaVersion": 1,
            "label": "continuous integration",
            "message": msg,
            "color": color
        }),
    )
}

#[derive(Debug, Deserialize, Default)]
pub struct CardQuery {
    pub branch: Option<String>,
    pub job_id: Option<String>,
    #[serde(rename = "ref")]
    pub ref_name: Option<String>,
}

pub async fn get_repo_card(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<CardQuery>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let branch_filter = query.branch.as_deref().or(query.ref_name.as_deref());
    let (record, prev_completed) = if let Some(job_id) = query.job_id.as_deref() {
        let rec = state.job_store.get_job(job_id).await;
        let b_hint = branch_filter.or_else(|| {
            rec.as_ref()
                .map(|r| r.job.ref_name.trim_start_matches("refs/heads/"))
        });
        let (_act, comp) = state.job_store.find_card_context(&repo_full, b_hint).await;
        (rec, comp)
    } else {
        state
            .job_store
            .find_card_context(&repo_full, branch_filter)
            .await
    };
    let branch = query
        .branch
        .or(query.ref_name)
        .or_else(|| {
            record
                .as_ref()
                .or(prev_completed.as_ref())
                .map(|r| r.job.ref_name.trim_start_matches("refs/heads/").to_string())
        })
        .unwrap_or_else(|| "main".to_string());
    let svg = badge::render_card_svg_with_previous(
        &repo_full,
        &branch,
        record.as_ref(),
        prev_completed.as_ref(),
    );
    svg_response(svg)
}

pub async fn get_branch_card(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch)): Path<(String, String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let (record, prev_completed) = state
        .job_store
        .find_card_context(&repo_full, Some(&branch))
        .await;
    let svg = badge::render_card_svg_with_previous(
        &repo_full,
        &branch,
        record.as_ref(),
        prev_completed.as_ref(),
    );
    svg_response(svg)
}

pub async fn get_submodule_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, submodule)): Path<(String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_submodule_job(&parent_full, &submodule, None)
        .await;
    let svg = badge::render_status_badge("continuous integration", record.as_ref());
    svg_response(svg)
}

pub async fn get_branch_submodule_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch, submodule)): Path<(String, String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_submodule_job(&parent_full, &submodule, Some(&branch))
        .await;
    let svg = badge::render_status_badge("continuous integration", record.as_ref());
    svg_response(svg)
}

pub async fn get_submodule_score_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, submodule)): Path<(String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_submodule_job(&parent_full, &submodule, None)
        .await;
    let svg = badge::render_score_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_branch_submodule_score_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch, submodule)): Path<(String, String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_submodule_job(&parent_full, &submodule, Some(&branch))
        .await;
    let svg = badge::render_score_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_submodule_coverage_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, submodule)): Path<(String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_submodule_job(&parent_full, &submodule, None)
        .await;
    let svg = badge::render_coverage_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_branch_submodule_coverage_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch, submodule)): Path<(String, String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_submodule_job(&parent_full, &submodule, Some(&branch))
        .await;
    let svg = badge::render_coverage_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_submodule_benchmark_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, submodule)): Path<(String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_submodule_job(&parent_full, &submodule, None)
        .await;
    let svg = badge::render_benchmark_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_branch_submodule_benchmark_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch, submodule)): Path<(String, String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_submodule_job(&parent_full, &submodule, Some(&branch))
        .await;
    let svg = badge::render_benchmark_badge(record.as_ref());
    svg_response(svg)
}

pub async fn get_submodule_card(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, submodule)): Path<(String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let (record, prev_completed) = state
        .job_store
        .find_submodule_card_context(&parent_full, &submodule, None)
        .await;
    let sub_name = format!("{}/{}", owner, submodule);
    let branch = record
        .as_ref()
        .or(prev_completed.as_ref())
        .map(|r| r.job.ref_name.trim_start_matches("refs/heads/").to_string())
        .unwrap_or_else(|| "main".to_string());
    let svg = badge::render_card_svg_with_previous(
        &sub_name,
        &branch,
        record.as_ref(),
        prev_completed.as_ref(),
    );
    svg_response(svg)
}

pub async fn get_branch_submodule_card(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch, submodule)): Path<(String, String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let (record, prev_completed) = state
        .job_store
        .find_submodule_card_context(&parent_full, &submodule, Some(&branch))
        .await;
    let sub_name = format!("{}/{}", owner, submodule);
    let svg = badge::render_card_svg_with_previous(
        &sub_name,
        &branch,
        record.as_ref(),
        prev_completed.as_ref(),
    );
    svg_response(svg)
}

pub async fn get_job_card(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
) -> Response {
    let Some(record) = state.job_store.get_job(&job_id).await else {
        return (StatusCode::NOT_FOUND, "Job not found").into_response();
    };
    let branch = record
        .job
        .ref_name
        .trim_start_matches("refs/heads/")
        .to_string();
    let (_act, prev_completed) = state
        .job_store
        .find_card_context(&record.job.repo_name, Some(&branch))
        .await;
    let svg = badge::render_card_svg_with_previous(
        &record.job.repo_name,
        &branch,
        Some(&record),
        prev_completed.as_ref(),
    );
    svg_response(svg)
}

pub async fn get_job_submodule_card(
    State(state): State<Arc<AppState>>,
    Path((job_id, submodule)): Path<(String, String)>,
) -> Response {
    let Some(record) = state.job_store.get_job(&job_id).await else {
        return (StatusCode::NOT_FOUND, "Job not found").into_response();
    };
    let sub_record = crate::job::extract_submodule_job(&record, &submodule);
    let owner = record
        .job
        .repo_name
        .split_once('/')
        .map(|(o, _)| o)
        .unwrap_or("LMA1980");
    let sub_name = format!("{}/{}", owner, submodule);
    let branch = record
        .job
        .ref_name
        .trim_start_matches("refs/heads/")
        .to_string();
    let (_act, prev_completed) = state
        .job_store
        .find_submodule_card_context(&record.job.repo_name, &submodule, Some(&branch))
        .await;
    let svg = badge::render_card_svg_with_previous(
        &sub_name,
        &branch,
        sub_record.as_ref(),
        prev_completed.as_ref(),
    );
    svg_response(svg)
}

fn svg_response(svg: String) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
            (header::PRAGMA, "no-cache"),
            (header::EXPIRES, "0"),
        ],
        svg,
    )
        .into_response()
}

#[derive(Debug, Deserialize, Default)]
pub struct EventsQuery {
    pub view: Option<String>,
    pub job_id: Option<String>,
    pub token: Option<String>,
    pub api_key: Option<String>,
}

fn resolve_job_stream_operator(
    state: &AppState,
    headers: &HeaderMap,
    query_key: Option<&str>,
) -> Result<bool, Box<Response>> {
    let auth = crate::console::api::resolve_auth_with_query_key(
        &state.config,
        &state.job_store,
        headers,
        query_key,
    );
    match auth {
        crate::console::api::AuthResolution::AdminApiKey
        | crate::console::api::AuthResolution::BoundUser { .. } => Ok(true),
        crate::console::api::AuthResolution::UninvitedUser { .. } => Err(Box::new(json_response(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "Forbidden: GitHub account is not bound to an active MuConsole invite"
            }),
        ))),
        crate::console::api::AuthResolution::Anonymous => Ok(state.config.log_api_key.is_none()
            && state.config.proxy_secret.is_none()
            && !headers.contains_key("x-forwarded-user")
            && !headers.contains_key("x-proxy-secret")),
    }
}

pub async fn handle_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> Response {
    let query_key = query.api_key.as_deref().or(query.token.as_deref());

    if let Some(ref job_id) = query.job_id {
        let is_operator = match resolve_job_stream_operator(&state, &headers, query_key) {
            Ok(v) => v,
            Err(denied) => return *denied,
        };
        return stream_job_events(state, job_id.clone(), is_operator).await;
    }

    let auth = crate::console::api::resolve_auth_with_query_key(
        &state.config,
        &state.job_store,
        &headers,
        query_key,
    );
    if state.config.log_api_key.is_some()
        && state.config.proxy_secret.is_none()
        && !auth.is_authenticated()
    {
        return json_response(
            StatusCode::UNAUTHORIZED,
            serde_json::json!({
                "error": "Unauthorized: valid operator session or API key required"
            }),
        );
    }

    let authenticated = auth.is_authenticated();
    stream_dashboard_events(state, authenticated)
}

pub async fn handle_job_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<EventsQuery>,
) -> Response {
    let query_key = query.api_key.as_deref().or(query.token.as_deref());
    let is_operator = match resolve_job_stream_operator(&state, &headers, query_key) {
        Ok(v) => v,
        Err(denied) => return *denied,
    };

    stream_job_events(state, job_id, is_operator).await
}

/// Dashboard SSE stream. Existing kinds (`queue`, `jobs`, `cluster`) are unchanged; the
/// additive console kinds (`branch_created`, `branch_deleted`, `pr_state_changed`,
/// `job_stage_changed`, `node_membership_changed`) are interleaved as they occur.
/// Console events about private repositories are only sent to authenticated streams.
fn stream_dashboard_events(state: Arc<AppState>, authenticated: bool) -> Response {
    let mut console_rx = state.console.subscribe();
    let stream = async_stream::stream! {
        // 1. Initial snapshot push
        let snap = state.job_store.queue_snapshot().await;
        if let Ok(data) = serde_json::to_string(&snap) {
            yield Ok::<_, Infallible>(Event::default().event("queue").data(data));
        }

        let jobs = state.job_store.list_jobs().await;
        if let Ok(data) = serde_json::to_string(&serde_json::json!({ "jobs": jobs })) {
            yield Ok::<_, Infallible>(Event::default().event("jobs").data(data));
        }

        let cluster = state.cluster.list_nodes_view().await;
        if let Ok(data) = serde_json::to_string(&cluster) {
            yield Ok::<_, Infallible>(Event::default().event("cluster").data(data));
        }

        // 2. Continuous notification loop
        let mut console_open = true;
        loop {
            tokio::select! {
                _ = state.job_store.wait_for_event() => {
                    let snap = state.job_store.queue_snapshot().await;
                    if let Ok(data) = serde_json::to_string(&snap) {
                        yield Ok::<_, Infallible>(Event::default().event("queue").data(data));
                    }

                    let jobs = state.job_store.list_jobs().await;
                    if let Ok(data) = serde_json::to_string(&serde_json::json!({ "jobs": jobs })) {
                        yield Ok::<_, Infallible>(Event::default().event("jobs").data(data));
                    }

                    let cluster = state.cluster.list_nodes_view().await;
                    if let Ok(data) = serde_json::to_string(&cluster) {
                        yield Ok::<_, Infallible>(Event::default().event("cluster").data(data));
                    }
                }
                recv = console_rx.recv(), if console_open => {
                    match recv {
                        Ok(ev) => {
                            if ev.public || authenticated {
                                yield Ok::<_, Infallible>(
                                    Event::default().event(ev.kind.as_str()).data(ev.data.to_string()),
                                );
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            console_open = false;
                        }
                    }
                }
            }
        }
    };

    let sse = Sse::new(stream).keep_alive(KeepAlive::default());
    let mut resp = sse.into_response();
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-accel-buffering"),
        header::HeaderValue::from_static("no"),
    );
    resp.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_static("*"),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-cache, no-transform"),
    );
    resp
}

async fn read_best_job_log(state: &AppState, full_path: &std::path::Path, job_id: &str) -> String {
    let disk_log = tokio::fs::read_to_string(full_path)
        .await
        .unwrap_or_default();
    let shared_log = state.job_store.get_job_log(job_id).unwrap_or_default();
    if shared_log.len() > disk_log.len() {
        shared_log
    } else {
        disk_log
    }
}

fn format_log_for_viewer(raw: &str, is_operator: bool) -> String {
    if is_operator {
        raw.to_string()
    } else {
        crate::console::sanitize_log_text(raw)
    }
}

async fn stream_job_events(state: Arc<AppState>, job_id: String, is_operator: bool) -> Response {
    let Some(initial_job) = state.job_store.get_job(&job_id).await else {
        return (
            StatusCode::NOT_FOUND,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            ],
            serde_json::to_string(&serde_json::json!({
                "error": "Job not found",
                "job_id": job_id
            }))
            .unwrap(),
        )
            .into_response();
    };

    let full_path = state.config.workspace_dir.join(&initial_job.log_file);
    let initial_raw_log = read_best_job_log(&state, &full_path, &job_id).await;
    let initial_log = format_log_for_viewer(&initial_raw_log, is_operator);

    let mut log_rx = state.log_broadcaster.subscribe();
    let jid = job_id.clone();
    let initial_job_raw_json = serde_json::to_string(&initial_job).unwrap_or_default();
    let initial_job_json = format_log_for_viewer(&initial_job_raw_json, is_operator);
    let mut is_terminal = matches!(
        initial_job.status,
        JobStatus::Completed { .. } | JobStatus::Failed { .. } | JobStatus::Skipped { .. }
    );

    let stream = async_stream::stream! {
        // Send initial job state
        yield Ok::<_, Infallible>(Event::default().event("job").data(&initial_job_json));

        // Send initial log text serialized as JSON string to preserve all formatting & newlines cleanly
        if let Ok(json_log) = serde_json::to_string(&initial_log) {
            yield Ok::<_, Infallible>(Event::default().event("log_init").data(json_log));
        }

        let mut last_job_version = initial_job_raw_json;
        let mut emitted_raw_len = initial_raw_log.len();
        let mut storage_poll = tokio::time::interval(std::time::Duration::from_secs(1));
        storage_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        storage_poll.tick().await;

        loop {
            tokio::select! {
                // New log chunks broadcast from workers or manual actions on this controller node
                recv_res = log_rx.recv() => {
                    match recv_res {
                        Ok(msg) => {
                            if msg.job_id == jid {
                                emitted_raw_len = emitted_raw_len.saturating_add(msg.chunk.len());
                                let chunk_out = format_log_for_viewer(&msg.chunk, is_operator);
                                if let Ok(json_chunk) = serde_json::to_string(&chunk_out) {
                                    yield Ok::<_, Infallible>(Event::default().event("log_chunk").data(json_chunk));
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            // Subscriber lagged: read fresh log from disk / shared storage and re-initialize
                            let full_raw = read_best_job_log(&state, &full_path, &jid).await;
                            emitted_raw_len = full_raw.len();
                            let full_out = format_log_for_viewer(&full_raw, is_operator);
                            if let Ok(json_log) = serde_json::to_string(&full_out) {
                                yield Ok::<_, Infallible>(Event::default().event("log_init").data(json_log));
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }

                // Cross-controller HA shared-storage delta tailing while job is non-terminal (#131)
                _ = storage_poll.tick(), if !is_terminal => {
                    let latest_raw = read_best_job_log(&state, &full_path, &jid).await;
                    if latest_raw.len() > emitted_raw_len {
                        let delta_raw = &latest_raw[emitted_raw_len..];
                        emitted_raw_len = latest_raw.len();
                        let chunk_out = format_log_for_viewer(delta_raw, is_operator);
                        if let Ok(json_chunk) = serde_json::to_string(&chunk_out) {
                            yield Ok::<_, Infallible>(Event::default().event("log_chunk").data(json_chunk));
                        }
                    }
                    if let Some(curr_job) = state.job_store.get_job(&jid).await {
                        is_terminal = matches!(
                            curr_job.status,
                            JobStatus::Completed { .. }
                                | JobStatus::Failed { .. }
                                | JobStatus::Skipped { .. }
                        );
                        if let Ok(curr_str) = serde_json::to_string(&curr_job) {
                            if curr_str != last_job_version {
                                last_job_version = curr_str.clone();
                                let out_str = format_log_for_viewer(&curr_str, is_operator);
                                yield Ok::<_, Infallible>(Event::default().event("job").data(out_str));
                            }
                        }
                    }
                }

                // Job status / stage status changes
                _ = state.job_store.wait_for_event() => {
                    if let Some(curr_job) = state.job_store.get_job(&jid).await {
                        is_terminal = matches!(
                            curr_job.status,
                            JobStatus::Completed { .. }
                                | JobStatus::Failed { .. }
                                | JobStatus::Skipped { .. }
                        );
                        if let Ok(curr_str) = serde_json::to_string(&curr_job) {
                            if curr_str != last_job_version {
                                last_job_version = curr_str.clone();
                                let out_str = format_log_for_viewer(&curr_str, is_operator);
                                yield Ok::<_, Infallible>(Event::default().event("job").data(out_str));
                            }
                        }
                    }
                }
            }
        }
    };

    let sse = Sse::new(stream).keep_alive(KeepAlive::default());
    let mut resp = sse.into_response();
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-accel-buffering"),
        header::HeaderValue::from_static("no"),
    );
    resp.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_static("*"),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-cache, no-transform"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::ClusterRegistry;
    use crate::config::{Config, HaRole, HaRoleConfig};
    use crate::console::ConsoleState;
    use crate::job::JobStore;
    use axum::body::Body;
    use axum::http::Request;
    use tokio::sync::{broadcast, mpsc};
    use tower::ServiceExt;

    fn make_health_test_state(
        workspace_dir: std::path::PathBuf,
        ha_role: HaRoleConfig,
    ) -> Arc<AppState> {
        let config = Config {
            bind_addr: "127.0.0.1:0".to_string(),
            workspace_dir,
            node_id: "node-a".to_string(),
            ha_role,
            ..Config::default()
        };
        let job_store = JobStore::new(10, None);
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(16);
        let (log_broadcaster, _) = broadcast::channel(64);
        Arc::new(AppState {
            config,
            job_store,
            cluster,
            tx,
            log_broadcaster,
            console: ConsoleState::default(),
        })
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_health_check_ok_for_healthy_leader() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_health_test_state(tmp.path().to_path_buf(), HaRoleConfig::Leader);
        let app = create_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["ha_role"], "leader");
        assert_eq!(body["queued_jobs"], 0);
        assert_eq!(body["running_jobs"], 0);
        assert_eq!(body["completed_jobs"], 0);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_health_check_503_when_leader_demoted_to_standby() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_health_test_state(tmp.path().to_path_buf(), HaRoleConfig::Leader);
        state.job_store.set_ha_role(HaRole::Standby);
        let app = create_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "standby_demoted");
        assert_eq!(body["reason"], "leader_lease_lost");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_health_check_503_when_workspace_dir_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let missing_dir = tmp.path().join("nonexistent-workspace-dir");
        let state = make_health_test_state(missing_dir, HaRoleConfig::Leader);
        let app = create_router(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["reason"], "workspace_dir_io_unavailable");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_health_check_503_when_disk_write_marked_unhealthy() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state = make_health_test_state(tmp.path().to_path_buf(), HaRoleConfig::Leader);
        state.job_store.mark_disk_io_unhealthy();
        let app = create_router(state.clone());

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["reason"], "workspace_dir_io_unavailable");

        // Recovering disk I/O restores 200 OK
        state.job_store.mark_disk_io_healthy();
        let app2 = create_router(state);
        let resp2 = app2
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    async fn test_tick_ha_coordinator_demotes_configured_leader_on_lease_loss() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut unreachable_cfg =
            crate::storage_backend::MuObserveRemoteConfig::plain_tcp("127.0.0.1:9".to_string());
        unreachable_cfg.timeout_ms = 100;
        let failing_storage: Arc<dyn crate::storage_backend::ControllerStorage> = Arc::new(
            crate::storage_backend::MuObserveRemoteStorage::new(unreachable_cfg)
                .expect("storage init"),
        );

        let config = Config {
            bind_addr: "127.0.0.1:0".to_string(),
            workspace_dir: tmp.path().to_path_buf(),
            node_id: "node-a".to_string(),
            ha_role: HaRoleConfig::Leader,
            ..Config::default()
        };
        let job_store = JobStore::with_storage(10, None, failing_storage);
        job_store.set_ha_role(HaRole::Leader);
        let cluster = ClusterRegistry::new();
        let (tx, _rx) = mpsc::channel(16);
        let (log_broadcaster, _) = broadcast::channel(64);
        let state = Arc::new(AppState {
            config,
            job_store,
            cluster,
            tx,
            log_broadcaster,
            console: ConsoleState::default(),
        });

        // When storage lease renewal fails, even HaRoleConfig::Leader must step down to Standby (#140)
        state.tick_ha_coordinator().await;
        assert_eq!(state.job_store.ha_role(), HaRole::Standby);

        let app = create_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
