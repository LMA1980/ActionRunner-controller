use crate::job::{JobMetrics, SubmoduleMetrics};
use action_runner_ipc::{LogEntry, MetricEntry};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

pub fn append_logs(log_file_path: &Path, entries: &[LogEntry]) -> Result<(), std::io::Error> {
    if let Some(parent) = log_file_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file_path)?;

    for entry in entries {
        let ts_sec = entry.timestamp_us / 1_000_000;
        let ts_nsec = ((entry.timestamp_us % 1_000_000) * 1000) as u32;
        let dt = DateTime::<Utc>::from_timestamp(ts_sec, ts_nsec).unwrap_or_else(Utc::now);

        let stream_tag = if entry.stream == 2 { "[stderr]" } else { "[stdout]" };
        writeln!(
            file,
            "{} [{}] [{}] {} {}",
            dt.to_rfc3339(),
            entry.node_id,
            entry.stage_id,
            stream_tag,
            entry.content
        )?;
    }

    file.flush()?;
    Ok(())
}

pub fn aggregate_metrics(metrics: &[MetricEntry], is_success: bool) -> JobMetrics {
    let mut submodules = BTreeMap::new();
    let mut total_tests_passed = 0;
    let mut total_tests = 0;
    let mut total_clippy = 0;
    let mut total_advisories = 0;

    let mut sum_coverage = 0.0;
    let mut cov_count = 0;
    let mut best_bench: Option<f64> = None;

    for m in metrics {
        total_tests_passed += m.tests_passed;
        total_tests += m.tests_total;
        total_clippy += m.clippy_warnings;
        total_advisories += m.advisories_count;

        if let Some(cov) = m.coverage_pct {
            sum_coverage += cov;
            cov_count += 1;
        }

        if let Some(bench) = m.bench_ns_per_iter {
            best_bench = Some(match best_bench {
                Some(curr) => curr.min(bench),
                None => bench,
            });
        }

        let sub_score = if is_success {
            let mut s = 100u32;
            if m.clippy_warnings > 0 {
                s = s.saturating_sub((m.clippy_warnings * 5).min(20));
            }
            if m.tests_total > 0 && m.tests_passed < m.tests_total {
                let fail_ratio = (m.tests_total - m.tests_passed) as f64 / m.tests_total as f64;
                s = s.saturating_sub((fail_ratio * 40.0) as u32);
            }
            if let Some(c) = m.coverage_pct {
                if c < 80.0 {
                    s = s.saturating_sub(((80.0 - c) * 0.5) as u32);
                }
            }
            s.max(1)
        } else {
            40u32
        };

        let sub_grade = score_to_grade(sub_score);

        submodules.insert(
            m.submodule.clone(),
            SubmoduleMetrics {
                name: m.submodule.clone(),
                path: format!("code/{}", m.submodule),
                quality_score: sub_score,
                letter_grade: sub_grade,
                tests_passed: m.tests_passed,
                tests_total: m.tests_total,
                coverage_pct: m.coverage_pct,
                benchmark_summary: m.bench_ns_per_iter.map(|ns| format!("{:.1} ns/iter", ns)),
                clippy_warnings: m.clippy_warnings,
            },
        );
    }

    let overall_coverage = if cov_count > 0 {
        Some((sum_coverage / cov_count as f64 * 10.0).round() / 10.0)
    } else {
        None
    };

    let overall_score = if is_success {
        let mut s = 100u32;
        if total_clippy > 0 {
            s = s.saturating_sub((total_clippy * 5).min(20));
        }
        if total_advisories > 0 {
            s = s.saturating_sub((total_advisories * 10).min(30));
        }
        if total_tests > 0 && total_tests_passed < total_tests {
            let fail_ratio = (total_tests - total_tests_passed) as f64 / total_tests as f64;
            s = s.saturating_sub((fail_ratio * 40.0) as u32);
        }
        if let Some(c) = overall_coverage {
            if c < 80.0 {
                s = s.saturating_sub(((80.0 - c) * 0.5) as u32);
            }
        }
        s.max(1)
    } else {
        40u32
    };

    let letter_grade = score_to_grade(overall_score);
    let benchmark_summary = best_bench.map(|ns| format!("{:.1} ns/iter", ns));

    JobMetrics {
        quality_score: overall_score,
        letter_grade,
        coverage_pct: overall_coverage,
        benchmark_summary,
        tests_passed: total_tests_passed,
        tests_total: total_tests,
        advisories_count: total_advisories,
        clippy_warnings: total_clippy,
        submodules,
    }
}

fn score_to_grade(score: u32) -> String {
    match score {
        95..=100 => "A+".to_string(),
        90..=94 => "A".to_string(),
        80..=89 => "B".to_string(),
        70..=79 => "C".to_string(),
        _ => "F".to_string(),
    }
}
