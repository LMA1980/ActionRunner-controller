use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Json, Response,
    },
    routing::{get, post},
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
    Router::new()
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
        // Cluster Fabric Nodes & Tunnel
        .route("/api/cluster/nodes", get(get_cluster_nodes))
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
        .with_state(state)
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

pub async fn health_check(State(state): State<Arc<AppState>>) -> Response {
    let snap = state.job_store.queue_snapshot().await;
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "status": "ok",
            "service": "ActionRunner-rs",
            "arch": "riscv64",
            "version": env!("CARGO_PKG_VERSION"),
            "queue_status": snap.status,
            "queue_depth": snap.queue_depth,
            "concurrency": snap.concurrency
        }),
    )
}

pub async fn get_queue(State(state): State<Arc<AppState>>) -> Response {
    let snap = state.job_store.queue_snapshot().await;
    json_response(StatusCode::OK, serde_json::to_value(snap).unwrap())
}

pub async fn get_cluster_nodes(State(state): State<Arc<AppState>>) -> Response {
    let nodes = state.cluster.list_nodes_view().await;
    json_response(StatusCode::OK, serde_json::to_value(nodes).unwrap())
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
    if let Some(ref required_key) = state.config.log_api_key {
        let auth_hdr = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let api_key_hdr = headers.get("x-api-key").and_then(|h| h.to_str().ok());

        let authed =
            auth_hdr == Some(required_key.as_str()) || api_key_hdr == Some(required_key.as_str());
        if !authed {
            return (
                StatusCode::UNAUTHORIZED,
                [
                    (header::CONTENT_TYPE, "application/json; charset=utf-8"),
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                ],
                serde_json::to_string(&serde_json::json!({
                    "error": "Unauthorized: valid X-Api-Key or Authorization Bearer token required to access execution logs"
                })).unwrap(),
            )
                .into_response();
        }
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
        Ok(content) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
                (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            ],
            content,
        )
            .into_response(),
        Err(_) => match &record.status {
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
        },
    }
}

pub async fn resume_job_handler(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
) -> Response {
    match state.job_store.resume_job(&job_id).await {
        Ok(record) => {
            let full_path = state.config.workspace_dir.join(&record.log_file);
            let note = format!(
                "{} [controller] Manual pipeline resume initiated; queuing pending stages\n",
                Utc::now().to_rfc3339()
            );
            if let Ok(mut f) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&full_path)
                .await
            {
                use tokio::io::AsyncWriteExt;
                let _ = f.write_all(note.as_bytes()).await;
            }
            state.broadcast_log(&job_id, &note);
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "ok",
                    "message": "Job resumed successfully; in-flight and failed stages re-queued",
                    "job_id": job_id
                }),
            )
        }
        Err(err) => json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "status": "error",
                "error": err
            }),
        ),
    }
}

pub async fn restart_job_handler(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
) -> Response {
    match state.job_store.restart_job(&job_id).await {
        Ok(record) => {
            let full_path = state.config.workspace_dir.join(&record.log_file);
            let note = format!(
                "{} [controller] Manual pipeline full restart initiated; resetting all stages to Pending\n",
                Utc::now().to_rfc3339()
            );
            if let Ok(mut f) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&full_path)
                .await
            {
                use tokio::io::AsyncWriteExt;
                let _ = f.write_all(note.as_bytes()).await;
            }
            state.broadcast_log(&job_id, &note);
            json_response(
                StatusCode::OK,
                serde_json::json!({
                    "status": "ok",
                    "message": "Job restarted successfully; all stages reset to Pending",
                    "job_id": job_id
                }),
            )
        }
        Err(err) => json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({
                "status": "error",
                "error": err
            }),
        ),
    }
}

pub async fn get_repo_badge(
    State(state): State<Arc<AppState>>,
    Path((owner, repo)): Path<(String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state.job_store.find_latest_job(&repo_full, None).await;
    let svg = badge::render_status_badge("k3-ci", record.as_ref());
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
    let svg = badge::render_status_badge("k3-ci", record.as_ref());
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
            "label": "k3-ci",
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
            "label": "k3-ci",
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
    let record = if let Some(job_id) = query.job_id.as_deref() {
        state.job_store.get_job(job_id).await
    } else {
        let branch_filter = query.branch.as_deref().or(query.ref_name.as_deref());
        state
            .job_store
            .find_latest_job(&repo_full, branch_filter)
            .await
    };
    let branch = query
        .branch
        .or(query.ref_name)
        .or_else(|| {
            record
                .as_ref()
                .map(|r| r.job.ref_name.trim_start_matches("refs/heads/").to_string())
        })
        .unwrap_or_else(|| "main".to_string());
    let svg = badge::render_card_svg(&repo_full, &branch, record.as_ref());
    svg_response(svg)
}

pub async fn get_branch_card(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch)): Path<(String, String, String)>,
) -> Response {
    let repo_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_latest_job(&repo_full, Some(&branch))
        .await;
    let svg = badge::render_card_svg(&repo_full, &branch, record.as_ref());
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
    let svg = badge::render_status_badge("k3-ci", record.as_ref());
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
    let svg = badge::render_status_badge("k3-ci", record.as_ref());
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
    let record = state
        .job_store
        .find_submodule_job(&parent_full, &submodule, None)
        .await;
    let sub_name = format!("{}/{}", owner, submodule);
    let branch = record
        .as_ref()
        .map(|r| r.job.ref_name.trim_start_matches("refs/heads/").to_string())
        .unwrap_or_else(|| "main".to_string());
    let svg = badge::render_card_svg(&sub_name, &branch, record.as_ref());
    svg_response(svg)
}

pub async fn get_branch_submodule_card(
    State(state): State<Arc<AppState>>,
    Path((owner, repo, branch, submodule)): Path<(String, String, String, String)>,
) -> Response {
    let parent_full = format!("{}/{}", owner, repo);
    let record = state
        .job_store
        .find_submodule_job(&parent_full, &submodule, Some(&branch))
        .await;
    let sub_name = format!("{}/{}", owner, submodule);
    let svg = badge::render_card_svg(&sub_name, &branch, record.as_ref());
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
    let svg = badge::render_card_svg(&record.job.repo_name, &branch, Some(&record));
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
    let svg = badge::render_card_svg(&sub_name, &branch, sub_record.as_ref());
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

pub async fn handle_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> Response {
    if let Some(ref required_key) = state.config.log_api_key {
        let auth_hdr = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let api_key_hdr = headers.get("x-api-key").and_then(|h| h.to_str().ok());
        let query_key = query.api_key.as_deref().or(query.token.as_deref());

        let authed = auth_hdr == Some(required_key.as_str())
            || api_key_hdr == Some(required_key.as_str())
            || query_key == Some(required_key.as_str());
        if !authed {
            return (
                StatusCode::UNAUTHORIZED,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                ],
                serde_json::to_string(&serde_json::json!({
                    "error": "Unauthorized: valid api key or bearer token required"
                }))
                .unwrap(),
            )
                .into_response();
        }
    }

    if let Some(ref job_id) = query.job_id {
        return stream_job_events(state, job_id.clone()).await;
    }

    if let Some(ref view) = query.view {
        if view == "job" {
            if let Some(ref job_id) = query.job_id {
                return stream_job_events(state, job_id.clone()).await;
            }
        }
    }

    stream_dashboard_events(state)
}

pub async fn handle_job_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Query(query): Query<EventsQuery>,
) -> Response {
    if let Some(ref required_key) = state.config.log_api_key {
        let auth_hdr = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let api_key_hdr = headers.get("x-api-key").and_then(|h| h.to_str().ok());
        let query_key = query.api_key.as_deref().or(query.token.as_deref());

        let authed = auth_hdr == Some(required_key.as_str())
            || api_key_hdr == Some(required_key.as_str())
            || query_key == Some(required_key.as_str());
        if !authed {
            return (
                StatusCode::UNAUTHORIZED,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                ],
                serde_json::to_string(&serde_json::json!({
                    "error": "Unauthorized: valid api key or bearer token required"
                }))
                .unwrap(),
            )
                .into_response();
        }
    }

    stream_job_events(state, job_id).await
}

fn stream_dashboard_events(state: Arc<AppState>) -> Response {
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
        loop {
            state.job_store.wait_for_event().await;

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

async fn stream_job_events(state: Arc<AppState>, job_id: String) -> Response {
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
    let initial_log = tokio::fs::read_to_string(&full_path)
        .await
        .unwrap_or_default();

    let mut log_rx = state.log_broadcaster.subscribe();
    let jid = job_id.clone();
    let initial_job_json = serde_json::to_string(&initial_job).unwrap_or_default();

    let stream = async_stream::stream! {
        // Send initial job state
        yield Ok::<_, Infallible>(Event::default().event("job").data(&initial_job_json));

        // Send initial log text serialized as JSON string to preserve all formatting & newlines cleanly
        if let Ok(json_log) = serde_json::to_string(&initial_log) {
            yield Ok::<_, Infallible>(Event::default().event("log_init").data(json_log));
        }

        let mut last_job_version = initial_job_json;

        loop {
            tokio::select! {
                // New log chunks broadcast from workers or manual actions
                recv_res = log_rx.recv() => {
                    match recv_res {
                        Ok(msg) => {
                            if msg.job_id == jid {
                                if let Ok(json_chunk) = serde_json::to_string(&msg.chunk) {
                                    yield Ok::<_, Infallible>(Event::default().event("log_chunk").data(json_chunk));
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            // Subscriber lagged: read fresh log from disk and re-initialize
                            if let Ok(full_log) = tokio::fs::read_to_string(&full_path).await {
                                if let Ok(json_log) = serde_json::to_string(&full_log) {
                                    yield Ok::<_, Infallible>(Event::default().event("log_init").data(json_log));
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }

                // Job status / stage status changes
                _ = state.job_store.wait_for_event() => {
                    if let Some(curr_job) = state.job_store.get_job(&jid).await {
                        if let Ok(curr_str) = serde_json::to_string(&curr_job) {
                            if curr_str != last_job_version {
                                last_job_version = curr_str.clone();
                                yield Ok::<_, Infallible>(Event::default().event("job").data(curr_str));
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
