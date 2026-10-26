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

    fn resolve_direct_repo_snapshots(
        conn: &Connection,
        repo: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        let repo_lower = repo.to_ascii_lowercase();
        let suffix_pattern = format!("%/{}", repo_lower);
        let branch_norm = branch.map(|b| normalize_ref(b).to_ascii_lowercase());

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

        let direct_active = row
            .as_ref()
            .and_then(|(a, _)| a.as_deref())
            .and_then(|s| serde_json::from_str::<JobRecord>(s).ok());
        let direct_completed = row
            .as_ref()
            .and_then(|(_, c)| c.as_deref())
            .and_then(|s| serde_json::from_str::<JobRecord>(s).ok());

        (direct_active, direct_completed)
    }

    fn resolve_repo_snapshots(
        conn: &Connection,
        repo: &str,
        branch: Option<&str>,
    ) -> (Option<JobRecord>, Option<JobRecord>) {
        let (mut direct_active, mut direct_completed) =
            Self::resolve_direct_repo_snapshots(conn, repo, branch);

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

        if active.is_some() || completed.is_some() {
            return (active, completed);
        }

        // If queried under a parent repo (e.g. /cards/LMA1980/model-runner/submodules/k3-core/card.svg)
        // and submodule_snapshots had no entry yet, fall back to direct standalone repository snapshots
        if parent_repo.is_some() {
            let direct_candidate = format!("{}/{}", owner, clean_target);
            let (d_act, d_comp) =
                Self::resolve_direct_repo_snapshots(conn, &direct_candidate, branch);
            if d_act.is_some() || d_comp.is_some() {
                return (d_act, d_comp);
            }
            if !clean_target.starts_with("k3-") {
                let k3_candidate = format!("{}/k3-{}", owner, clean_target);
                let (k_act, k_comp) =
                    Self::resolve_direct_repo_snapshots(conn, &k3_candidate, branch);
                if k_act.is_some() || k_comp.is_some() {
                    return (k_act, k_comp);
                }
            }
        }

        (None, None)
    }

    /// Scans `workspace_dir/logs/<owner>/<repo>/job-*.log` and imports any historical log files
    /// that were previously evicted from `jobs_index.json` into DuckDB, as well as enriching
    /// existing completed/failed records whose `metrics` or `metrics.submodules` were missing.
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
                let has_gitmodules = workspace_dir
                    .join("repos")
                    .join(&repo_full)
                    .join(".gitmodules")
                    .is_file();

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

                    if let Some(mut existing) = self.get_job(job_id) {
                        let is_terminal = matches!(
                            existing.status,
                            JobStatus::Completed { .. } | JobStatus::Failed { .. }
                        );
                        let needs_metrics = existing.metrics.is_none()
                            || (has_gitmodules
                                && existing
                                    .metrics
                                    .as_ref()
                                    .map(|m| m.submodules.is_empty())
                                    .unwrap_or(true));
                        if is_terminal && needs_metrics {
                            let is_success = matches!(
                                existing.status,
                                JobStatus::Completed { exit_code: 0, .. }
                            );
                            if let Some(extracted) = Self::extract_metrics_from_log_and_workspace(
                                workspace_dir,
                                &repo_full,
                                &log_path,
                                is_success,
                            ) {
                                existing.metrics = Some(extracted);
                                recovered_records.push(existing);
                            }
                        }
                        continue;
                    }

                    if let Some(rec) = Self::reconstruct_record_from_log(
                        &repo_full,
                        job_id,
                        &log_path,
                        workspace_dir,
                    ) {
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
            "Backfilled and enriched historical job records from workspace log files into DuckDB"
        );
        count
    }

    pub fn extract_metrics_from_log_and_workspace(
        workspace_dir: &Path,
        repo_full: &str,
        log_path: &Path,
        is_success: bool,
    ) -> Option<JobMetrics> {
        let content = std::fs::read_to_string(log_path).ok()?;
        if content.trim().is_empty() {
            return None;
        }
        Some(Self::extract_metrics_from_content_and_workspace(
            workspace_dir,
            repo_full,
            &content,
            is_success,
        ))
    }

    fn extract_metrics_from_content_and_workspace(
        workspace_dir: &Path,
        repo_full: &str,
        content: &str,
        is_success: bool,
    ) -> JobMetrics {
        let mut tests_passed = 0u32;
        let mut tests_total = 0u32;
        let mut overall_coverage: Option<f64> = None;
        let mut best_bench_ns: Option<f64> = None;
        let mut per_dir_lines: BTreeMap<String, (u64, u64)> = BTreeMap::new();

        for line in content.lines() {
            // Strip optional "<rfc3339> [<node>] [<stage>] [<stream>] " prefix
            let body = if let Some((_, after_stream)) = line.split_once("[stdout] ") {
                after_stream
            } else if let Some((_, after_stream)) = line.split_once("[stderr] ") {
                after_stream
            } else {
                line
            };

            if let Some(idx) = body.find("test result:") {
                let after = &body[idx..];
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

            // Parse cargo-llvm-cov TOTAL or per-file coverage row
            let trimmed = body.trim();
            if trimmed.starts_with("TOTAL ") {
                // Format: TOTAL <regions> <missed> <reg_cov>% <funcs> <missed> <fn_cov>% <lines> <missed> <line_cov>%
                let pcts: Vec<f64> = trimmed
                    .split_whitespace()
                    .filter_map(|tok| tok.strip_suffix('%'))
                    .filter_map(|num| num.parse::<f64>().ok())
                    .collect();
                if let Some(&cov) = pcts.get(2).or_else(|| pcts.first()) {
                    overall_coverage = Some(cov);
                }
            } else if trimmed.contains(".rs ") && trimmed.contains('%') {
                let cols: Vec<&str> = trimmed.split_whitespace().collect();
                // cols: [filename, regions, missed_reg, reg_pct, funcs, missed_fn, fn_pct, lines, missed_lines, line_pct, ...]
                if cols.len() >= 10 {
                    if let Some((dir_prefix, _)) = cols[0].split_once('/') {
                        if let (Ok(total_l), Ok(missed_l)) =
                            (cols[7].parse::<u64>(), cols[8].parse::<u64>())
                        {
                            let entry = per_dir_lines
                                .entry(dir_prefix.to_ascii_lowercase())
                                .or_insert((0, 0));
                            entry.0 += total_l;
                            entry.1 += missed_l;
                        }
                    }
                }
            }

            // Parse benchmark summary: "... bench:       53.4 ns/iter"
            if let Some(b_idx) = body.find("bench:") {
                let after_b = body[b_idx + "bench:".len()..].trim();
                if let Some(first_tok) = after_b.split_whitespace().next() {
                    let clean_num = first_tok.replace(',', "");
                    if let Ok(ns) = clean_num.parse::<f64>() {
                        if ns > 0.0 {
                            best_bench_ns = Some(match best_bench_ns {
                                Some(curr) => curr.min(ns),
                                None => ns,
                            });
                        }
                    }
                }
            }
        }

        let benchmark_summary = best_bench_ns.map(|ns| format!("{:.1} ns/iter", ns));

        // Build submodule metrics from workspace_dir/repos/<repo_full>/.gitmodules if present
        let mut submodules = BTreeMap::new();
        let gitmodules_path = workspace_dir
            .join("repos")
            .join(repo_full)
            .join(".gitmodules");
        if let Ok(gm_content) = std::fs::read_to_string(&gitmodules_path) {
            for (sub_name, sub_path) in Self::parse_gitmodules(&gm_content) {
                let path_short = sub_path
                    .rsplit_once('/')
                    .map(|(_, s)| s)
                    .unwrap_or(&sub_path)
                    .to_ascii_lowercase();
                let name_short = sub_name
                    .strip_prefix("k3-")
                    .unwrap_or(&sub_name)
                    .to_ascii_lowercase();

                let sub_cov = per_dir_lines
                    .get(&path_short)
                    .or_else(|| per_dir_lines.get(&name_short))
                    .and_then(|&(tot, missed)| {
                        if tot > 0 {
                            Some(
                                ((tot.saturating_sub(missed) as f64 / tot as f64) * 1000.0).round()
                                    / 10.0,
                            )
                        } else {
                            None
                        }
                    })
                    .or(overall_coverage);

                let sub_score = if is_success { 100 } else { 40 };
                let sub_grade = if is_success {
                    "A+".to_string()
                } else {
                    "F".to_string()
                };

                submodules.insert(
                    sub_name.clone(),
                    crate::job::SubmoduleMetrics {
                        name: sub_name,
                        path: sub_path,
                        quality_score: sub_score,
                        letter_grade: sub_grade,
                        tests_passed: 0,
                        tests_total: 0,
                        coverage_pct: sub_cov,
                        benchmark_summary: benchmark_summary.clone(),
                        clippy_warnings: 0,
                    },
                );
            }
        }

        let quality_score = if is_success { 100 } else { 40 };
        let letter_grade = if is_success {
            "A+".to_string()
        } else {
            "F".to_string()
        };

        JobMetrics {
            quality_score,
            letter_grade,
            coverage_pct: overall_coverage,
            benchmark_summary,
            tests_passed,
            tests_total,
            advisories_count: 0,
            clippy_warnings: 0,
            submodules,
        }
    }

    fn parse_gitmodules(gm_content: &str) -> Vec<(String, String)> {
        let mut result = Vec::new();
        let mut curr_path: Option<String> = None;
        let mut curr_url: Option<String> = None;

        let flush = |p: Option<String>, u: Option<String>, out: &mut Vec<(String, String)>| {
            if let Some(path_val) = p {
                let name = u
                    .and_then(|url_str| {
                        let trimmed = url_str.trim().trim_end_matches(".git");
                        trimmed
                            .rsplit_once('/')
                            .or_else(|| trimmed.rsplit_once(':'))
                            .map(|(_, repo)| repo.to_string())
                    })
                    .unwrap_or_else(|| {
                        path_val
                            .rsplit_once('/')
                            .map(|(_, s)| s.to_string())
                            .unwrap_or_else(|| path_val.clone())
                    });
                out.push((name, path_val));
            }
        };

        for line in gm_content.lines() {
            let t = line.trim();
            if t.starts_with("[submodule ") {
                flush(curr_path.take(), curr_url.take(), &mut result);
            } else if let Some((k, v)) = t.split_once('=') {
                let key = k.trim();
                let val = v.trim().to_string();
                if key == "path" {
                    curr_path = Some(val);
                } else if key == "url" {
                    curr_url = Some(val);
                }
            }
        }
        flush(curr_path.take(), curr_url.take(), &mut result);
        result
    }

    fn reconstruct_record_from_log(
        repo_full: &str,
        job_id: &str,
        log_path: &Path,
        workspace_dir: &Path,
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

        let content = std::fs::read_to_string(log_path).unwrap_or_default();
        if content.trim().is_empty() {
            return None;
        }

        // Determine if any stage failed or if all passed
        let has_failure = content.contains("Process exited with code")
            || content.contains("Stage failed")
            || content.contains("=== Pipeline Status: FAILED")
            || content.contains("test result: FAILED.")
            || content.contains("error: test failed")
            || content.contains("error: could not compile");

        let mut first_log_ts: Option<DateTime<Utc>> = None;
        let mut last_log_ts: Option<DateTime<Utc>> = None;
        let mut stage_order: Vec<String> = Vec::new();
        let mut stage_info: BTreeMap<String, (String, DateTime<Utc>, DateTime<Utc>)> =
            BTreeMap::new();

        for line in content.lines() {
            // Parse "<rfc3339> [<node_id>] [<stage_id>] [<stream>] <content>"
            if let Some((ts_tok, rest_line)) = line.split_once(" [") {
                if let Ok(parsed_dt) = DateTime::parse_from_rfc3339(ts_tok.trim()) {
                    let dt_utc = parsed_dt.with_timezone(&Utc);
                    if first_log_ts.is_none() {
                        first_log_ts = Some(dt_utc);
                    }
                    last_log_ts = Some(dt_utc);

                    if let Some((node_id, after_node)) = rest_line.split_once("] [") {
                        if let Some((stage_id, _after_stage)) = after_node.split_once(']') {
                            if stage_id != "controller" && !stage_id.is_empty() {
                                if !stage_info.contains_key(stage_id) {
                                    stage_order.push(stage_id.to_string());
                                    stage_info.insert(
                                        stage_id.to_string(),
                                        (node_id.to_string(), dt_utc, dt_utc),
                                    );
                                } else if let Some(entry) = stage_info.get_mut(stage_id) {
                                    entry.2 = dt_utc;
                                }
                            }
                        }
                    }
                }
            }
        }

        let duration_secs = match (first_log_ts, last_log_ts) {
            (Some(f), Some(l)) => (l - f).num_seconds().max(1) as u64,
            _ => (mtime_dt - queued_at).num_seconds().max(1) as u64,
        };

        let stages: Vec<crate::job::StageRecord> = stage_order
            .into_iter()
            .filter_map(|sid| {
                let (node_id, s_first, s_last) = stage_info.remove(&sid)?;
                let st_dur = (s_last - s_first).num_seconds().max(1) as u64;
                Some(crate::job::StageRecord {
                    id: sid.clone(),
                    name: sid,
                    tags: Vec::new(),
                    threads: 1,
                    toolchain: None,
                    depends_on: Vec::new(),
                    status: crate::job::StageStatus::Completed {
                        duration_secs: st_dur,
                        exit_code: 0,
                    },
                    assigned_node: Some(node_id),
                })
            })
            .collect();

        // Attempt to resolve full 40-char commit SHA and branch from workspace_dir/repos/<repo_full>
        let (resolved_sha, resolved_ref) =
            Self::resolve_git_commit_and_ref(workspace_dir, repo_full, &sha_short);

        let status = if has_failure {
            JobStatus::Failed {
                error: "Stage failed during execution".to_string(),
            }
        } else {
            JobStatus::Completed {
                duration_secs,
                exit_code: 0,
            }
        };

        let metrics = Some(Self::extract_metrics_from_content_and_workspace(
            workspace_dir,
            repo_full,
            &content,
            !has_failure,
        ));

        let rel_log_file = PathBuf::from("logs")
            .join(repo_full)
            .join(format!("{}.log", job_id));

        Some(JobRecord {
            job: Job {
                id: job_id.to_string(),
                event_type: "push".to_string(),
                repo_name: repo_full.to_string(),
                clone_url: format!("https://github.com/{}.git", repo_full),
                commit_sha: resolved_sha,
                ref_name: resolved_ref,
                sender: "LMA1980".to_string(),
                queued_at,
            },
            status,
            log_file: rel_log_file,
            updated_at: last_log_ts.unwrap_or(mtime_dt),
            metrics,
            stages,
        })
    }

    fn resolve_git_commit_and_ref(
        workspace_dir: &Path,
        repo_full: &str,
        sha_short: &str,
    ) -> (String, String) {
        let repo_dir = workspace_dir.join("repos").join(repo_full);
        if !repo_dir.is_dir() || sha_short == "unknown" {
            return (sha_short.to_string(), "refs/heads/main".to_string());
        }

        let full_sha = std::process::Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args([
                "rev-parse",
                "--verify",
                &format!("{}^{{commit}}", sha_short),
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| sha_short.to_string());

        let branches_out = std::process::Command::new("git")
            .arg("-C")
            .arg(&repo_dir)
            .args(["branch", "-a", "--contains", &full_sha])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();

        let mut candidate_branch: Option<String> = None;
        for line in branches_out.lines() {
            let trimmed = line.trim().trim_start_matches('*').trim();
            if trimmed.is_empty() || trimmed.contains("->") || trimmed.starts_with('(') {
                continue;
            }
            let b = trimmed.strip_prefix("remotes/origin/").unwrap_or(trimmed);
            if b == "main" || b == "master" {
                return (full_sha, format!("refs/heads/{}", b));
            }
            if !b.starts_with("pr/") && candidate_branch.is_none() {
                candidate_branch = Some(format!("refs/heads/{}", b));
            }
        }

        (
            full_sha,
            candidate_branch.unwrap_or_else(|| "refs/heads/main".to_string()),
        )
    }
}
