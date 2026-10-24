use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowConfig {
    pub version: Option<String>,
    pub name: String,
    pub env: Option<HashMap<String, String>>,
    #[serde(default)]
    pub stages: Vec<StageConfig>,
    // For backwards compatibility with v1 workflows
    #[serde(default)]
    pub steps: Vec<StepConfigLegacy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageConfig {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_threads")]
    pub threads: u32,
    pub toolchain: Option<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub run: String,
    pub working_dir: Option<String>,
    pub env: Option<HashMap<String, String>>,
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub continue_on_error: bool,
}

fn default_threads() -> u32 {
    2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepConfigLegacy {
    pub name: String,
    pub run: String,
    pub working_dir: Option<String>,
    pub env: Option<HashMap<String, String>>,
    pub timeout_seconds: Option<u64>,
}

impl WorkflowConfig {
    pub fn load_from_str(
        content: &str,
        repo_root: &Path,
        max_timeout: u64,
    ) -> Result<Self, String> {
        let mut workflow: WorkflowConfig = serde_yaml::from_str(content)
            .map_err(|e| format!("Failed to parse YAML workflow: {}", e))?;

        // If v1 steps were provided and no stages, convert linear steps into stages
        if workflow.stages.is_empty() && !workflow.steps.is_empty() {
            let mut prev_id: Option<String> = None;
            for (idx, step) in workflow.steps.iter().enumerate() {
                let stage_id = format!("step-{}", idx + 1);
                let mut depends_on = Vec::new();
                if let Some(ref p) = prev_id {
                    depends_on.push(p.clone());
                }
                prev_id = Some(stage_id.clone());

                workflow.stages.push(StageConfig {
                    id: stage_id,
                    name: step.name.clone(),
                    tags: vec!["default".to_string()],
                    threads: 2,
                    toolchain: None,
                    depends_on,
                    run: step.run.clone(),
                    working_dir: step.working_dir.clone(),
                    env: step.env.clone(),
                    timeout_seconds: step.timeout_seconds,
                    continue_on_error: false,
                });
            }
        }

        if workflow.stages.is_empty() {
            return Err("Workflow must contain at least one stage (or step)".to_string());
        }

        let mut seen_ids = HashSet::new();
        for (idx, stage) in workflow.stages.iter().enumerate() {
            if stage.id.trim().is_empty() {
                return Err(format!("Stage #{} has an empty 'id'", idx + 1));
            }
            if !seen_ids.insert(stage.id.clone()) {
                return Err(format!("Duplicate stage id '{}' detected", stage.id));
            }
            if stage.run.trim().is_empty() {
                return Err(format!("Stage '{}' has an empty 'run' command", stage.id));
            }

            if let Some(ref dir) = stage.working_dir {
                let path = PathBuf::from(dir);
                if path.is_absolute() || dir.contains("..") {
                    return Err(format!(
                        "Stage '{}' working_dir '{}' is invalid: path traversal is forbidden",
                        stage.id, dir
                    ));
                }
                let resolved = repo_root.join(dir);
                if !resolved.starts_with(repo_root) {
                    return Err(format!(
                        "Stage '{}' working_dir escapes repository boundary",
                        stage.id
                    ));
                }
            }

            if let Some(timeout) = stage.timeout_seconds {
                if timeout == 0 || timeout > max_timeout {
                    return Err(format!(
                        "Stage '{}' timeout_seconds ({}s) must be between 1 and {}s",
                        stage.id, timeout, max_timeout
                    ));
                }
            }
        }

        // Validate dependencies and ensure DAG is acyclic
        workflow.validate_dag()?;

        Ok(workflow)
    }

    pub fn validate_dag(&self) -> Result<(), String> {
        let all_ids: HashSet<&str> = self.stages.iter().map(|s| s.id.as_str()).collect();
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

        for stage in &self.stages {
            in_degree.entry(&stage.id).or_insert(0);
            for dep in &stage.depends_on {
                if !all_ids.contains(dep.as_str()) {
                    return Err(format!(
                        "Stage '{}' depends on nonexistent stage '{}'",
                        stage.id, dep
                    ));
                }
                if dep == &stage.id {
                    return Err(format!("Stage '{}' cannot depend on itself", stage.id));
                }
                adj.entry(dep.as_str()).or_default().push(&stage.id);
                *in_degree.entry(&stage.id).or_insert(0) += 1;
            }
        }

        // Kahn's algorithm for cycle detection
        let mut queue: VecDeque<&str> = VecDeque::new();
        for (&id, &deg) in &in_degree {
            if deg == 0 {
                queue.push_back(id);
            }
        }

        let mut visited_count = 0;
        while let Some(u) = queue.pop_front() {
            visited_count += 1;
            if let Some(neighbors) = adj.get(u) {
                for &v in neighbors {
                    let deg = in_degree.get_mut(v).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push_back(v);
                    }
                }
            }
        }

        if visited_count != self.stages.len() {
            return Err("Cyclic dependency detected in workflow stages DAG".to_string());
        }

        Ok(())
    }
}
