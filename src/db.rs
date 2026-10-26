use chrono::{DateTime, Utc};
use duckdb::{params, Connection, OptionalExt};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{info, warn};

use crate::job::{extract_submodule_job, normalize_ref, Job, JobMetrics, JobRecord, JobStatus};

pub struct DuckDbStore {
    conn: Mutex<Connection>,
}

impl DuckDbStore {
    pub fn open(db_path: Option<&Path>) -> Result<Self, String> {
        let conn = match db_path {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                Connection::open(path)
                    .map_err(|e| format!("Failed to open DuckDB at {}: {}", path.display(), e))?
            }
            None => Connection::open_in_memory()
                .map_err(|e| format!("Failed to open in-memory DuckDB: {}", e))?,
        };

        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "DuckDB mutex poisoned".to_string())?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS jobs_history (
                job_id VARCHAR PRIMARY KEY,
                event_type VARCHAR NOT NULL,
                repo_name VARCHAR NOT NULL,
                repo_key VARCHAR NOT NULL,
                clone_url VARCHAR NOT NULL,
                commit_sha VARCHAR NOT NULL,
                ref_name VARCHAR NOT NULL,
                branch_key VARCHAR NOT NULL,
                sender VARCHAR NOT NULL,
                queued_at_us BIGINT NOT NULL,
                updated_at_us BIGINT NOT NULL,
                status_state VARCHAR NOT NULL,
                exit_code INTEGER,
                duration_secs BIGINT,
                quality_score INTEGER,
                letter_grade VARCHAR,
                coverage_pct DOUBLE,
                benchmark_summary VARCHAR,
                tests_passed INTEGER,
                tests_total INTEGER,
                advisories_count INTEGER,
                clippy_warnings INTEGER,
                record_json VARCHAR NOT NULL
            );

            CREATE TABLE IF NOT EXISTS branch_snapshots (
                repo_key VARCHAR NOT NULL,
                branch_key VARCHAR NOT NULL,
                repo_name VARCHAR NOT NULL,
                ref_name VARCHAR NOT NULL,
                latest_active_job_id VARCHAR,
                latest_active_json VARCHAR,
                latest_active_queued_us BIGINT,
                latest_completed_job_id VARCHAR,
                latest_completed_json VARCHAR,
                latest_completed_queued_us BIGINT,
                PRIMARY KEY (repo_key, branch_key)
            );

            CREATE TABLE IF NOT EXISTS submodule_snapshots (
                parent_repo_key VARCHAR NOT NULL,
                branch_key VARCHAR NOT NULL,
                submodule_key VARCHAR NOT NULL,
                submodule_path_key VARCHAR NOT NULL,
                latest_active_job_id VARCHAR,
                latest_active_json VARCHAR,
                latest_active_queued_us BIGINT,
                latest_completed_job_id VARCHAR,
                latest_completed_json VARCHAR,
                latest_completed_queued_us BIGINT,
                PRIMARY KEY (parent_repo_key, branch_key, submodule_key)
            );
            "#,
        )
        .map_err(|e| format!("Failed to initialize DuckDB schema: {}", e))?;

        Ok(())
    }

    pub fn upsert_record(&self, record: &JobRecord) {
        let Ok(conn) = self.conn.lock() else {
            warn!("DuckDB mutex poisoned during upsert_record");
            return;
        };
        Self::upsert_record_on_conn(&conn, record);
    }

    pub fn upsert_records_batch(&self, records: &[JobRecord]) {
        let Ok(conn) = self.conn.lock() else {
            warn!("DuckDB mutex poisoned during upsert_records_batch");
            return;
        };
        let _ = conn.execute_batch("BEGIN TRANSACTION;");
        for rec in records {
            Self::upsert_record_on_conn(&conn, rec);
        }
        let _ = conn.execute_batch("COMMIT;");
    }

    fn upsert_record_on_conn(conn: &Connection, record: &JobRecord) {
        let Ok(record_json) = serde_json::to_string(record) else {
            return;
        };

        let repo_key = record.job.repo_name.to_ascii_lowercase();
        let branch_key = normalize_ref(&record.job.ref_name).to_ascii_lowercase();
        let queued_at_us = record.job.queued_at.timestamp_micros();
        let updated_at_us = record.updated_at.timestamp_micros();

        let (status_state, exit_code, duration_secs) = match &record.status {
            JobStatus::Queued => ("Queued", None, None),
            JobStatus::Running { .. } => ("Running", None, None),
            JobStatus::Completed {
                duration_secs,
                exit_code,
            } => ("Completed", Some(*exit_code), Some(*duration_secs as i64)),
            JobStatus::Failed { .. } => ("Failed", None, None),
            JobStatus::Skipped { .. } => ("Skipped", None, None),
        };

        let (
            quality_score,
            letter_grade,
            coverage_pct,
            benchmark_summary,
            tests_passed,
            tests_total,
            advisories_count,
            clippy_warnings,
        ) = match &record.metrics {
            Some(m) => (
                Some(m.quality_score as i32),
                Some(m.letter_grade.clone()),
                m.coverage_pct,
                m.benchmark_summary.clone(),
                Some(m.tests_passed as i32),
                Some(m.tests_total as i32),
                Some(m.advisories_count as i32),
                Some(m.clippy_warnings as i32),
            ),
            None => (None, None, None, None, None, None, None, None),
        };

        if let Err(e) = conn.execute(
            r#"
            INSERT OR REPLACE INTO jobs_history (
                job_id, event_type, repo_name, repo_key, clone_url, commit_sha,
                ref_name, branch_key, sender, queued_at_us, updated_at_us,
                status_state, exit_code, duration_secs, quality_score, letter_grade,
                coverage_pct, benchmark_summary, tests_passed, tests_total,
                advisories_count, clippy_warnings, record_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                record.job.id,
                record.job.event_type,
                record.job.repo_name,
                repo_key,
                record.job.clone_url,
                record.job.commit_sha,
                record.job.ref_name,
                branch_key,
                record.job.sender,
                queued_at_us,
                updated_at_us,
                status_state,
                exit_code,
                duration_secs,
                quality_score,
                letter_grade,
                coverage_pct,
                benchmark_summary,
                tests_passed,
                tests_total,
                advisories_count,
                clippy_warnings,
                record_json,
            ],
        ) {
            warn!(job_id = %record.job.id, error = %e, "Failed to upsert into jobs_history");
        }

        Self::sync_branch_snapshot(
            conn,
            record,
            &repo_key,
            &branch_key,
            queued_at_us,
            &record_json,
        );
        Self::sync_submodule_snapshots(conn, record, &repo_key, &branch_key, queued_at_us);
    }

    fn sync_branch_snapshot(
        conn: &Connection,
        record: &JobRecord,
        repo_key: &str,
        branch_key: &str,
        queued_at_us: i64,
        record_json: &str,
    ) {
        type SnapshotRow = (
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<i64>,
        );

        let existing: Option<SnapshotRow> = conn
            .query_row(
                r#"
                SELECT
                    latest_active_job_id,
                    latest_active_json,
                    latest_active_queued_us,
                    latest_completed_job_id,
                    latest_completed_json,
                    latest_completed_queued_us
                FROM branch_snapshots
                WHERE repo_key = ? AND branch_key = ?
                "#,
                params![repo_key, branch_key],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .unwrap_or(None);

        let (
            mut active_id,
            mut active_json,
            mut active_q_us,
            mut comp_id,
            mut comp_json,
            mut comp_q_us,
        ) = existing.unwrap_or((None, None, None, None, None, None));

        let is_skipped = matches!(record.status, JobStatus::Skipped { .. });
        let is_completed = matches!(
            record.status,
            JobStatus::Completed { .. } | JobStatus::Failed { .. }
        );

        if is_skipped {
            // Skipped jobs are ignored by both pills and scorecards.
            // If this job was previously the active job on this branch, fallback to the newest non-skipped job.
            if active_id.as_deref() == Some(record.job.id.as_str()) {
                let fallback: Option<(String, String, i64)> = conn
                    .query_row(
                        r#"
                        SELECT job_id, record_json, queued_at_us
                        FROM jobs_history
                        WHERE repo_key = ? AND branch_key = ? AND status_state != 'Skipped'
                        ORDER BY queued_at_us DESC, updated_at_us DESC
                        LIMIT 1
                        "#,
                        params![repo_key, branch_key],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                    )
                    .optional()
                    .unwrap_or(None);

                if let Some((fb_id, fb_json, fb_q)) = fallback {
                    active_id = Some(fb_id);
                    active_json = Some(fb_json);
                    active_q_us = Some(fb_q);
                } else {
                    active_id = comp_id.clone();
                    active_json = comp_json.clone();
                    active_q_us = comp_q_us;
                }
            }
        } else {
            // Non-skipped job (Queued, Running, Completed, Failed)
            let should_update_active = active_id.is_none()
                || active_id.as_deref() == Some(record.job.id.as_str())
                || queued_at_us >= active_q_us.unwrap_or(i64::MIN);

            if should_update_active {
                active_id = Some(record.job.id.clone());
                active_json = Some(record_json.to_string());
                active_q_us = Some(queued_at_us);
            }

            if is_completed {
                let should_update_comp = comp_id.is_none()
                    || comp_id.as_deref() == Some(record.job.id.as_str())
                    || queued_at_us >= comp_q_us.unwrap_or(i64::MIN);

                if should_update_comp {
                    comp_id = Some(record.job.id.clone());
                    comp_json = Some(record_json.to_string());
                    comp_q_us = Some(queued_at_us);
                }
            }
        }

        // Only persist snapshot row if we have at least an active or completed job
        if active_id.is_some() || comp_id.is_some() {
            let _ = conn.execute(
                r#"
                INSERT OR REPLACE INTO branch_snapshots (
                    repo_key, branch_key, repo_name, ref_name,
                    latest_active_job_id, latest_active_json, latest_active_queued_us,
                    latest_completed_job_id, latest_completed_json, latest_completed_queued_us
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
                params![
                    repo_key,
                    branch_key,
                    record.job.repo_name,
                    record.job.ref_name,
                    active_id,
                    active_json,
                    active_q_us,
                    comp_id,
                    comp_json,
                    comp_q_us,
                ],
            );
        }
    }

    fn sync_submodule_snapshots(
        conn: &Connection,
        record: &JobRecord,
        parent_repo_key: &str,
        branch_key: &str,
        queued_at_us: i64,
    ) {
        let is_skipped = matches!(record.status, JobStatus::Skipped { .. });
        let is_completed = matches!(
            record.status,
            JobStatus::Completed { .. } | JobStatus::Failed { .. }
        );

        if let Some(ref metrics) = record.metrics {
            for (sub_name, sub) in &metrics.submodules {
                let Some(sub_record) = extract_submodule_job(record, sub_name) else {
                    continue;
                };
                let Ok(sub_json) = serde_json::to_string(&sub_record) else {
                    continue;
                };

                let sub_short = sub_name
                    .rsplit_once('/')
                    .map(|(_, r)| r)
                    .unwrap_or(sub_name)
                    .to_ascii_lowercase();
                let path_short = sub
                    .path
                    .rsplit_once('/')
                    .map(|(_, r)| r)
                    .unwrap_or(&sub.path)
                    .to_ascii_lowercase();

                Self::upsert_single_submodule_snapshot(
                    conn,
                    parent_repo_key,
                    branch_key,
                    &sub_short,
                    &path_short,
                    &record.job.id,
                    &sub_json,
                    queued_at_us,
                    is_skipped,
                    is_completed,
                );
            }
        } else {
            // Parent job has no metrics yet (e.g., Queued or Running, or Skipped).
            // Propagate active status to any already-known submodules of (parent_repo_key, branch_key)
            // while preserving their latest_completed_json.
            let mut existing_subs = Vec::new();
            if let Ok(mut stmt) = conn.prepare(
                r#"
                SELECT
                    submodule_key,
                    submodule_path_key,
                    latest_active_job_id,
                    latest_active_json,
                    latest_active_queued_us,
                    latest_completed_job_id,
                    latest_completed_json,
                    latest_completed_queued_us
                FROM submodule_snapshots
                WHERE parent_repo_key = ? AND branch_key = ?
                "#,
            ) {
                if let Ok(rows) = stmt.query_map(params![parent_repo_key, branch_key], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                    ))
                }) {
                    for r in rows.flatten() {
                        existing_subs.push(r);
                    }
                }
            }

            let owner = record
                .job
                .repo_name
                .split_once('/')
                .map(|(o, _)| o)
                .unwrap_or("LMA1980");

            for (
                sub_key,
                path_key,
                mut act_id,
                mut act_json,
                mut act_q_us,
                comp_id,
                comp_json,
                comp_q_us,
            ) in existing_subs
            {
                if is_skipped {
                    if act_id.as_deref() == Some(record.job.id.as_str()) {
                        act_id = comp_id.clone();
                        act_json = comp_json.clone();
                        act_q_us = comp_q_us;
                    }
                } else if matches!(record.status, JobStatus::Queued | JobStatus::Running { .. }) {
                    let should_update = act_id.is_none()
                        || act_id.as_deref() == Some(record.job.id.as_str())
                        || queued_at_us >= act_q_us.unwrap_or(i64::MIN);

                    if should_update {
                        let sub_job = Job {
                            id: format!("{}-{}", record.job.id, sub_key),
                            event_type: record.job.event_type.clone(),
                            repo_name: format!("{}/{}", owner, sub_key),
                            clone_url: String::new(),
                            commit_sha: record.job.commit_sha.clone(),
                            ref_name: record.job.ref_name.clone(),
                            sender: record.job.sender.clone(),
                            queued_at: record.job.queued_at,
                        };
                        let synth_rec = JobRecord {
                            job: sub_job,
                            status: record.status.clone(),
                            log_file: record.log_file.clone(),
                            updated_at: record.updated_at,
                            metrics: None,
                            stages: Vec::new(),
                        };
                        if let Ok(s_json) = serde_json::to_string(&synth_rec) {
                            act_id = Some(record.job.id.clone());
                            act_json = Some(s_json);
                            act_q_us = Some(queued_at_us);
                        }
                    }
                }

                let _ = conn.execute(
                    r#"
                    INSERT OR REPLACE INTO submodule_snapshots (
                        parent_repo_key, branch_key, submodule_key, submodule_path_key,
                        latest_active_job_id, latest_active_json, latest_active_queued_us,
                        latest_completed_job_id, latest_completed_json, latest_completed_queued_us
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                    params![
                        parent_repo_key,
                        branch_key,
                        sub_key,
                        path_key,
                        act_id,
                        act_json,
                        act_q_us,
                        comp_id,
                        comp_json,
                        comp_q_us,
                    ],
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_single_submodule_snapshot(
        conn: &Connection,
        parent_repo_key: &str,
        branch_key: &str,
        sub_key: &str,
        path_key: &str,
        parent_job_id: &str,
        sub_json: &str,
        queued_at_us: i64,
        is_skipped: bool,
        is_completed: bool,
    ) {
        type SubRow = (
            Option<String>,
            Option<String>,
            Option<i64>,
            Option<String>,
            Option<String>,
            Option<i64>,
        );

        let existing: Option<SubRow> = conn
            .query_row(
                r#"
                SELECT
                    latest_active_job_id,
                    latest_active_json,
                    latest_active_queued_us,
                    latest_completed_job_id,
                    latest_completed_json,
                    latest_completed_queued_us
                FROM submodule_snapshots
                WHERE parent_repo_key = ? AND branch_key = ? AND submodule_key = ?
                "#,
                params![parent_repo_key, branch_key, sub_key],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .unwrap_or(None);

        let (mut act_id, mut act_json, mut act_q_us, mut comp_id, mut comp_json, mut comp_q_us) =
            existing.unwrap_or((None, None, None, None, None, None));

        if !is_skipped {
            let should_update_act = act_id.is_none()
                || act_id.as_deref() == Some(parent_job_id)
                || queued_at_us >= act_q_us.unwrap_or(i64::MIN);

            if should_update_act {
                act_id = Some(parent_job_id.to_string());
                act_json = Some(sub_json.to_string());
                act_q_us = Some(queued_at_us);
            }

            // Update completed snapshot if parent job is completed, or if no completed snapshot exists yet
            if is_completed || comp_id.is_none() {
                let should_update_comp = comp_id.is_none()
                    || comp_id.as_deref() == Some(parent_job_id)
                    || queued_at_us >= comp_q_us.unwrap_or(i64::MIN);

                if should_update_comp {
                    comp_id = Some(parent_job_id.to_string());
                    comp_json = Some(sub_json.to_string());
                    comp_q_us = Some(queued_at_us);
                }
            }
        }

        let _ = conn.execute(
            r#"
            INSERT OR REPLACE INTO submodule_snapshots (
                parent_repo_key, branch_key, submodule_key, submodule_path_key,
                latest_active_job_id, latest_active_json, latest_active_queued_us,
                latest_completed_job_id, latest_completed_json, latest_completed_queued_us
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
            params![
                parent_repo_key,
                branch_key,
                sub_key,
                path_key,
                act_id,
                act_json,
                act_q_us,
                comp_id,
                comp_json,
                comp_q_us,
            ],
        );
    }

    /// Loads recent jobs from DuckDB `jobs_history` ordered newest-first.
    pub fn load_recent_jobs(&self, limit: usize) -> Vec<JobRecord> {
        let Ok(conn) = self.conn.lock() else {
            return Vec::new();
        };

        let mut records = Vec::new();
        if let Ok(mut stmt) = conn.prepare(
            r#"
            SELECT record_json
            FROM jobs_history
            ORDER BY queued_at_us DESC, updated_at_us DESC
            LIMIT ?
            "#,
        ) {
            if let Ok(rows) = stmt.query_map(params![limit as i64], |row| row.get::<_, String>(0)) {
                for r in rows.flatten() {
                    if let Ok(rec) = serde_json::from_str::<JobRecord>(&r) {
                        records.push(rec);
                    }
                }
            }
        }
        records
    }

    /// Looks up a single job by ID from `jobs_history`.
    pub fn get_job(&self, job_id: &str) -> Option<JobRecord> {
        let conn = self.conn.lock().ok()?;
        let json_str: String = conn
            .query_row(
                "SELECT record_json FROM jobs_history WHERE job_id = ?",
                params![job_id],
                |row| row.get(0),
            )
            .optional()
            .ok()??;
        serde_json::from_str(&json_str).ok()
    }

    /// Finds the latest completed (`Completed` or `Failed`) job for a repository/branch,
    /// falling back to `submodule_snapshots` if the target refers to a submodule.
    pub fn find_latest_completed(&self, repo: &str, branch: Option<&str>) -> Option<JobRecord> {
        let conn = self.conn.lock().ok()?;
        let (_active, completed) = Self::resolve_repo_snapshots(&conn, repo, branch);
        completed
    }

    /// Finds `(latest_active_or_completed, latest_completed)` for a repository/branch,
    /// ignoring `Skipped` jobs and falling back to `submodule_snapshots` if needed.
    pub fn find_card_context(
        &self,
        repo: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        let Ok(conn) = self.conn.lock() else {
            return (None, None);
        };
        Self::resolve_repo_snapshots(&conn, repo, branch)
    }

    /// Finds the latest completed (`Completed` or `Failed`) job for a specific submodule.
    pub fn find_submodule_completed(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> Option<JobRecord> {
        let conn = self.conn.lock().ok()?;
        let (_active, completed) =
            Self::resolve_submodule_snapshots(&conn, Some(parent_repo), submodule, branch);
        completed
    }

    /// Finds `(latest_active_or_completed, latest_completed)` for a specific submodule.
    pub fn find_submodule_card_context(
        &self,
        parent_repo: &str,
        submodule: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        let Ok(conn) = self.conn.lock() else {
            return (None, None);
        };
        Self::resolve_submodule_snapshots(&conn, Some(parent_repo), submodule, branch)
    }

    fn resolve_repo_snapshots(
        conn: &Connection,
        repo: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        let repo_lower = repo.to_ascii_lowercase();
        let suffix_pattern = format!("%/{}", repo_lower);
        let branch_norm = branch.map(|b| normalize_ref(b).to_ascii_lowercase());

        // 1. Direct lookup in branch_snapshots
        let row: Option<(Option<String>, Option<String>)> = if let Some(ref b_key) = branch_norm {
            conn.query_row(
                r#"
                SELECT latest_active_json, latest_completed_json
                FROM branch_snapshots
                WHERE (repo_key = ? OR repo_key LIKE ?) AND branch_key = ?
                ORDER BY COALESCE(latest_active_queued_us, latest_completed_queued_us, 0) DESC
                LIMIT 1
                "#,
                params![repo_lower, suffix_pattern, b_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap_or(None)
        } else {
            // Prefer 'main' if no branch specified and 'main' exists, else newest branch overall
            conn.query_row(
                r#"
                SELECT latest_active_json, latest_completed_json
                FROM branch_snapshots
                WHERE (repo_key = ? OR repo_key LIKE ?)
                ORDER BY
                    CASE WHEN branch_key = 'main' THEN 0 ELSE 1 END ASC,
                    COALESCE(latest_active_queued_us, latest_completed_queued_us, 0) DESC
                LIMIT 1
                "#,
                params![repo_lower, suffix_pattern],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap_or(None)
        };

        let mut direct_active = row
            .as_ref()
            .and_then(|(a, _)| a.as_deref())
            .and_then(|s| serde_json::from_str::<JobRecord>(s).ok());
        let mut direct_completed = row
            .as_ref()
            .and_then(|(_, c)| c.as_deref())
            .and_then(|s| serde_json::from_str::<JobRecord>(s).ok());

        // 2. Also check submodule_snapshots in case repo is a standalone submodule (e.g. LMA1980/k3-core)
        let (sub_active, sub_completed) =
            Self::resolve_submodule_snapshots(conn, None, repo, branch);

        // Enrich direct_completed with submodule metrics if the direct repo build had no metrics
        if let (Some(ref mut d_comp), Some(ref s_comp)) = (&mut direct_completed, &sub_completed) {
            if d_comp.metrics.is_none() && s_comp.metrics.is_some() {
                d_comp.metrics = s_comp.metrics.clone();
            }
        }
        if let (Some(ref mut d_act), Some(ref s_act)) = (&mut direct_active, &sub_active) {
            if matches!(
                d_act.status,
                JobStatus::Completed { .. } | JobStatus::Failed { .. }
            ) && d_act.metrics.is_none()
                && s_act.metrics.is_some()
            {
                d_act.metrics = s_act.metrics.clone();
            }
        }

        if direct_active.is_some() || direct_completed.is_some() {
            return (direct_active, direct_completed);
        }

        (sub_active, sub_completed)
    }

    fn resolve_submodule_snapshots(
        conn: &Connection,
        parent_repo: Option<&str>,
        submodule: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        let clean_target = submodule
            .rsplit_once('/')
            .map(|(_, r)| r)
            .unwrap_or(submodule)
            .to_ascii_lowercase();
        let norm_underscore = clean_target.replace('-', "_");
        let norm_hyphen = clean_target.replace('_', "-");
        let branch_norm = branch.map(|b| normalize_ref(b).to_ascii_lowercase());

        let owner = parent_repo
            .and_then(|p| p.split_once('/').map(|(o, _)| o))
            .or_else(|| submodule.split_once('/').map(|(o, _)| o))
            .unwrap_or("LMA1980");

        let parent_key = parent_repo.map(|p| p.to_ascii_lowercase());

        let row: Option<(Option<String>, Option<String>)> = match (&parent_key, &branch_norm) {
            (Some(pk), Some(bk)) => {
                let ps = format!("%/{}", pk);
                conn.query_row(
                        r#"
                        SELECT latest_active_json, latest_completed_json
                        FROM submodule_snapshots
                        WHERE (parent_repo_key = ? OR parent_repo_key LIKE ?)
                          AND branch_key = ?
                          AND (submodule_key = ? OR submodule_key = ? OR submodule_key = ? OR submodule_path_key = ?)
                        ORDER BY COALESCE(latest_active_queued_us, latest_completed_queued_us, 0) DESC
                        LIMIT 1
                        "#,
                        params![pk, ps, bk, clean_target, norm_underscore, norm_hyphen, clean_target],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()
                    .unwrap_or(None)
            }
            (Some(pk), None) => {
                let ps = format!("%/{}", pk);
                conn.query_row(
                        r#"
                        SELECT latest_active_json, latest_completed_json
                        FROM submodule_snapshots
                        WHERE (parent_repo_key = ? OR parent_repo_key LIKE ?)
                          AND (submodule_key = ? OR submodule_key = ? OR submodule_key = ? OR submodule_path_key = ?)
                        ORDER BY
                            CASE WHEN branch_key = 'main' THEN 0 ELSE 1 END ASC,
                            COALESCE(latest_active_queued_us, latest_completed_queued_us, 0) DESC
                        LIMIT 1
                        "#,
                        params![pk, ps, clean_target, norm_underscore, norm_hyphen, clean_target],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()
                    .unwrap_or(None)
            }
            (None, Some(bk)) => conn
                    .query_row(
                        r#"
                        SELECT latest_active_json, latest_completed_json
                        FROM submodule_snapshots
                        WHERE branch_key = ?
                          AND (submodule_key = ? OR submodule_key = ? OR submodule_key = ? OR submodule_path_key = ?)
                        ORDER BY COALESCE(latest_active_queued_us, latest_completed_queued_us, 0) DESC
                        LIMIT 1
                        "#,
                        params![bk, clean_target, norm_underscore, norm_hyphen, clean_target],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()
                    .unwrap_or(None),
            (None, None) => conn
                    .query_row(
                        r#"
                        SELECT latest_active_json, latest_completed_json
                        FROM submodule_snapshots
                        WHERE (submodule_key = ? OR submodule_key = ? OR submodule_key = ? OR submodule_path_key = ?)
                        ORDER BY
                            CASE WHEN branch_key = 'main' THEN 0 ELSE 1 END ASC,
                            COALESCE(latest_active_queued_us, latest_completed_queued_us, 0) DESC
                        LIMIT 1
                        "#,
                        params![clean_target, norm_underscore, norm_hyphen, clean_target],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()
                    .unwrap_or(None),
        };

        let parse_and_fix_owner = |opt_s: Option<&str>| -> Option<JobRecord> {
            let mut rec: JobRecord = serde_json::from_str(opt_s?).ok()?;
            let short = rec
                .job
                .repo_name
                .rsplit_once('/')
                .map(|(_, r)| r)
                .unwrap_or(&rec.job.repo_name);
            rec.job.repo_name = format!("{}/{}", owner, short);
            Some(rec)
        };

        let active = row
            .as_ref()
            .and_then(|(a, _)| parse_and_fix_owner(a.as_deref()));
        let completed = row
            .as_ref()
            .and_then(|(_, c)| parse_and_fix_owner(c.as_deref()));

        (active, completed)
    }

    /// Scans `workspace_dir/logs/<owner>/<repo>/job-*.log` and imports any historical log files
    /// that were previously evicted from `jobs_index.json` into DuckDB.
    pub fn backfill_from_logs_dir(&self, workspace_dir: &Path) -> usize {
        let logs_root = workspace_dir.join("logs");
        if !logs_root.is_dir() {
            return 0;
        }

        let Ok(owners) = std::fs::read_dir(&logs_root) else {
            return 0;
        };

        let mut recovered_records = Vec::new();

        for owner_entry in owners.flatten() {
            let owner_path = owner_entry.path();
            if !owner_path.is_dir() {
                continue;
            }
            let Some(owner_name) = owner_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };

            let Ok(repos) = std::fs::read_dir(&owner_path) else {
                continue;
            };

            for repo_entry in repos.flatten() {
                let repo_path = repo_entry.path();
                if !repo_path.is_dir() {
                    continue;
                }
                let Some(repo_short) = repo_path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let repo_full = format!("{}/{}", owner_name, repo_short);

                let Ok(log_files) = std::fs::read_dir(&repo_path) else {
                    continue;
                };

                for log_entry in log_files.flatten() {
                    let log_path = log_entry.path();
                    if log_path.extension().and_then(|e| e.to_str()) != Some("log") {
                        continue;
                    }
                    let Some(job_id) = log_path.file_stem().and_then(|s| s.to_str()) else {
                        continue;
                    };
                    if !job_id.starts_with("job-") {
                        continue;
                    }

                    if self.get_job(job_id).is_some() {
                        continue;
                    }

                    if let Some(rec) =
                        Self::reconstruct_record_from_log(&repo_full, job_id, &log_path)
                    {
                        recovered_records.push(rec);
                    }
                }
            }
        }

        if recovered_records.is_empty() {
            return 0;
        }

        // Sort oldest-first by queued_at so snapshots advance monotonically
        recovered_records.sort_by_key(|r| r.job.queued_at);
        let count = recovered_records.len();
        self.upsert_records_batch(&recovered_records);
        info!(
            recovered_count = count,
            "Backfilled historical job records from workspace log files into DuckDB"
        );
        count
    }

    fn reconstruct_record_from_log(
        repo_full: &str,
        job_id: &str,
        log_path: &Path,
    ) -> Option<JobRecord> {
        // Parse job-<timestamp>-<sha_short>[-suffix]
        let rest = job_id.strip_prefix("job-")?;
        let mut parts = rest.split('-');
        let ts_secs: i64 = parts.next()?.parse().ok()?;
        let sha_short = parts.next().unwrap_or("unknown").to_string();

        let queued_at = DateTime::<Utc>::from_timestamp(ts_secs, 0).unwrap_or_else(Utc::now);
        let mtime_dt = std::fs::metadata(log_path)
            .and_then(|m| m.modified())
            .ok()
            .map(DateTime::<Utc>::from)
            .unwrap_or(queued_at);

        let duration_secs = (mtime_dt - queued_at).num_seconds().max(1) as u64;
        let content = std::fs::read_to_string(log_path).unwrap_or_default();

        // Determine if any stage failed or if all passed
        let has_failure = content.contains("Process exited with code")
            || content.contains("Stage failed")
            || content.contains("test result: FAILED.");

        // Count passed/failed unit tests from standard cargo test output lines
        let mut tests_passed = 0u32;
        let mut tests_total = 0u32;
        for line in content.lines() {
            if let Some(idx) = line.find("test result:") {
                let after = &line[idx..];
                // e.g. "test result: ok. 12 passed; 0 failed;"
                let tokens: Vec<&str> = after.split_whitespace().collect();
                for window in tokens.windows(2) {
                    if window[1].starts_with("passed") {
                        if let Ok(n) = window[0].parse::<u32>() {
                            tests_passed += n;
                            tests_total += n;
                        }
                    } else if window[1].starts_with("failed") {
                        if let Ok(n) = window[0].parse::<u32>() {
                            tests_total += n;
                        }
                    }
                }
            }
        }

        let status = if has_failure {
            JobStatus::Completed {
                duration_secs,
                exit_code: 1,
            }
        } else {
            JobStatus::Completed {
                duration_secs,
                exit_code: 0,
            }
        };

        let quality_score = if has_failure { 40 } else { 100 };
        let letter_grade = if has_failure {
            "F".to_string()
        } else {
            "A+".to_string()
        };

        let metrics = Some(JobMetrics {
            quality_score,
            letter_grade,
            coverage_pct: None,
            benchmark_summary: None,
            tests_passed,
            tests_total,
            advisories_count: 0,
            clippy_warnings: 0,
            submodules: BTreeMap::new(),
        });

        let rel_log_file = PathBuf::from("logs")
            .join(repo_full)
            .join(format!("{}.log", job_id));

        Some(JobRecord {
            job: Job {
                id: job_id.to_string(),
                event_type: "push".to_string(),
                repo_name: repo_full.to_string(),
                clone_url: format!("https://github.com/{}.git", repo_full),
                commit_sha: sha_short,
                ref_name: "refs/heads/main".to_string(),
                sender: "LMA1980".to_string(),
                queued_at,
            },
            status,
            log_file: rel_log_file,
            updated_at: mtime_dt,
            metrics,
            stages: Vec::new(),
        })
    }
}
