use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ============================================================================
// v3 3-Tier Declarative Configuration Models (Sub-task #20)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionRunnerWorkflow {
    pub version: String, // must be "3"
    pub name: String,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub tasks: HashMap<String, TaskConfig>,
    pub stages: Vec<StageConfig>,
    pub on_action: HashMap<String, Vec<String>>, // keys: push, pull_request, merge, tag
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskConfig {
    pub tool: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub working_dir: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub timeout_seconds: Option<u64>,
    pub sandbox_profile: Option<String>,
}

pub fn default_threads() -> u32 {
    2
}

pub fn default_max_concurrent_per_node() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageConfig {
    pub id: String,
    pub name: String,
    pub tasks: Vec<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_threads")]
    pub threads: u32,
    pub toolchain: Option<String>,
    #[serde(default, alias = "isolate_node")]
    pub exclusive: bool,
    #[serde(default = "default_max_concurrent_per_node")]
    pub max_concurrent_per_node: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkflowValidationError {
    #[error("Unsupported workflow version '{0}', expected '3'")]
    UnsupportedVersion(String),
    #[error("Unknown task reference '{task_id}' in stage '{stage_id}'")]
    UnknownTaskReference { stage_id: String, task_id: String },
    #[error("Unknown stage reference '{stage_id}' in context '{context}'")]
    UnknownStageReference { context: String, stage_id: String },
    #[error("Cyclic dependency detected: {0:?}")]
    CycleDetected(Vec<String>),
    #[error("Duplicate stage id '{0}'")]
    DuplicateStageId(String),
    #[error("Workflow must contain at least one stage")]
    EmptyStages,
}

impl ActionRunnerWorkflow {
    pub fn from_yaml(content: &str) -> Result<Self, String> {
        let wf: ActionRunnerWorkflow = serde_yaml::from_str(content)
            .map_err(|e| format!("Failed to parse 3-tier ActionRunner.yml: {}", e))?;
        wf.validate().map_err(|e| e.to_string())?;
        Ok(wf)
    }

    /// Validate the workflow and return stage IDs in topological execution order.
    pub fn validate(&self) -> Result<Vec<String>, WorkflowValidationError> {
        // 1. Reject version != "3"
        if self.version != "3" {
            return Err(WorkflowValidationError::UnsupportedVersion(
                self.version.clone(),
            ));
        }

        // 2. Reject empty stages
        if self.stages.is_empty() {
            return Err(WorkflowValidationError::EmptyStages);
        }

        let mut stage_ids = HashSet::new();
        for stage in &self.stages {
            if !stage_ids.insert(stage.id.as_str()) {
                return Err(WorkflowValidationError::DuplicateStageId(stage.id.clone()));
            }
        }

        // 3. Verify every task ID in stage.tasks exists in self.tasks
        for stage in &self.stages {
            for task_id in &stage.tasks {
                if !self.tasks.contains_key(task_id) {
                    return Err(WorkflowValidationError::UnknownTaskReference {
                        stage_id: stage.id.clone(),
                        task_id: task_id.clone(),
                    });
                }
            }
        }

        // 4. Verify every stage ID in stage.depends_on exists in self.stages
        for stage in &self.stages {
            for dep in &stage.depends_on {
                if !stage_ids.contains(dep.as_str()) {
                    return Err(WorkflowValidationError::UnknownStageReference {
                        context: format!("stage '{}' depends_on", stage.id),
                        stage_id: dep.clone(),
                    });
                }
                if dep == &stage.id {
                    return Err(WorkflowValidationError::CycleDetected(vec![
                        stage.id.clone(),
                        stage.id.clone(),
                    ]));
                }
            }
        }

        // 5. Verify every stage ID in self.on_action exists in self.stages
        for (action, target_stages) in &self.on_action {
            for s_id in target_stages {
                if !stage_ids.contains(s_id.as_str()) {
                    return Err(WorkflowValidationError::UnknownStageReference {
                        context: format!("on_action.{}", action),
                        stage_id: s_id.clone(),
                    });
                }
            }
        }

        // 6. Kahn's algorithm for topological ordering and cycle detection
        let mut in_degree: HashMap<&str, usize> = HashMap::new();
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();

        for stage in &self.stages {
            in_degree.entry(&stage.id).or_insert(0);
            for dep in &stage.depends_on {
                adj.entry(dep.as_str()).or_default().push(&stage.id);
                *in_degree.entry(&stage.id).or_insert(0) += 1;
            }
        }

        let mut queue: VecDeque<&str> = VecDeque::new();
        for stage in &self.stages {
            if in_degree.get(stage.id.as_str()) == Some(&0) {
                queue.push_back(stage.id.as_str());
            }
        }

        let mut topo_order = Vec::new();
        while let Some(u) = queue.pop_front() {
            topo_order.push(u.to_string());
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

        if topo_order.len() != self.stages.len() {
            let cycle_path = find_cycle_path(&self.stages);
            return Err(WorkflowValidationError::CycleDetected(cycle_path));
        }

        Ok(topo_order)
    }

    /// Select the DAG subgraph required for a specific event trigger (e.g. push, pull_request).
    pub fn subgraph_for_event(
        &self,
        event: &str,
    ) -> Result<ActionRunnerWorkflow, WorkflowValidationError> {
        self.validate()?;
        let alias = match event {
            "pull_request" => Some("pullrequest"),
            "pullrequest" => Some("pull_request"),
            "release" => Some("tag"),
            _ => None,
        };
        let target_stage_ids = match self
            .on_action
            .get(event)
            .or_else(|| alias.and_then(|a| self.on_action.get(a)))
        {
            Some(stages) => stages,
            None => {
                return Ok(ActionRunnerWorkflow {
                    version: self.version.clone(),
                    name: self.name.clone(),
                    env: self.env.clone(),
                    tasks: HashMap::new(),
                    stages: Vec::new(),
                    on_action: HashMap::new(),
                });
            }
        };

        let stage_map: HashMap<&str, &StageConfig> =
            self.stages.iter().map(|s| (s.id.as_str(), s)).collect();
        let mut required_stage_ids: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();

        for s_id in target_stage_ids {
            required_stage_ids.insert(s_id.clone());
            queue.push_back(s_id.as_str());
        }

        while let Some(curr) = queue.pop_front() {
            if let Some(stage) = stage_map.get(curr) {
                for dep in &stage.depends_on {
                    if required_stage_ids.insert(dep.clone()) {
                        queue.push_back(dep.as_str());
                    }
                }
            }
        }

        let filtered_stages: Vec<StageConfig> = self
            .stages
            .iter()
            .filter(|s| required_stage_ids.contains(&s.id))
            .cloned()
            .collect();

        let mut required_task_ids: HashSet<String> = HashSet::new();
        for stage in &filtered_stages {
            for task_id in &stage.tasks {
                required_task_ids.insert(task_id.clone());
            }
        }

        let filtered_tasks: HashMap<String, TaskConfig> = self
            .tasks
            .iter()
            .filter(|(k, _)| required_task_ids.contains(k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let mut filtered_on_action = HashMap::new();
        filtered_on_action.insert(event.to_string(), target_stage_ids.clone());

        Ok(ActionRunnerWorkflow {
            version: self.version.clone(),
            name: self.name.clone(),
            env: self.env.clone(),
            tasks: filtered_tasks,
            stages: filtered_stages,
            on_action: filtered_on_action,
        })
    }
}

fn find_cycle_path(stages: &[StageConfig]) -> Vec<String> {
    let mut stage_deps: HashMap<&str, &[String]> = HashMap::new();
    for s in stages {
        stage_deps.insert(&s.id, &s.depends_on);
    }

    let mut state: HashMap<&str, u8> = HashMap::new();
    let mut path: Vec<String> = Vec::new();

    fn dfs<'a>(
        node: &'a str,
        stage_deps: &HashMap<&'a str, &'a [String]>,
        state: &mut HashMap<&'a str, u8>,
        path: &mut Vec<String>,
        cycle: &mut Option<Vec<String>>,
    ) -> bool {
        state.insert(node, 1);
        path.push(node.to_string());

        if let Some(deps) = stage_deps.get(node) {
            for dep in *deps {
                let dep_str = dep.as_str();
                match state.get(dep_str).copied().unwrap_or(0) {
                    1 => {
                        let mut cycle_nodes = Vec::new();
                        let mut recording = false;
                        for p in path.iter() {
                            if p == dep_str {
                                recording = true;
                            }
                            if recording {
                                cycle_nodes.push(p.clone());
                            }
                        }
                        cycle_nodes.push(dep_str.to_string());
                        *cycle = Some(cycle_nodes);
                        return true;
                    }
                    0 if dfs(dep_str, stage_deps, state, path, cycle) => {
                        return true;
                    }
                    _ => {}
                }
            }
        }

        path.pop();
        state.insert(node, 2);
        false
    }

    let mut cycle = None;
    for s in stages {
        if state.get(s.id.as_str()).copied().unwrap_or(0) == 0
            && dfs(
                s.id.as_str(),
                &stage_deps,
                &mut state,
                &mut path,
                &mut cycle,
            )
        {
            break;
        }
    }

    cycle.unwrap_or_else(|| stages.iter().map(|s| s.id.clone()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Sub-task #20 Tests: Serde YAML Roundtrip ---

    #[test]
    fn test_v3_actionrunner_workflow_roundtrip_yaml() {
        let yaml = r#"
version: "3"
name: "Continuous Integration Workflow"
env:
  CI: "true"
  RUST_BACKTRACE: "1"
tasks:
  fmt-task:
    tool: "cargo-fmt"
    args: ["--check"]
  clippy-task:
    tool: "cargo-clippy"
    args: ["--all-targets", "--", "-D", "warnings"]
  test-task:
    tool: "cargo-test"
    args: ["--workspace", "--", "--nocapture"]
    timeout_seconds: 900
stages:
  - id: formatting
    name: "Check Formatting"
    tasks: ["fmt-task"]
    threads: 2
    exclusive: false
    max_concurrent_per_node: 1
  - id: linting
    name: "Check Linter Hygiene"
    tasks: ["clippy-task"]
    depends_on: ["formatting"]
    threads: 4
    exclusive: false
    max_concurrent_per_node: 1
  - id: testing
    name: "Run Test Suite"
    tasks: ["test-task"]
    depends_on: ["linting"]
    threads: 6
    exclusive: true
    max_concurrent_per_node: 1
on_action:
  push: ["formatting", "linting", "testing"]
  pull_request: ["formatting", "linting"]
"#;

        let wf: ActionRunnerWorkflow =
            serde_yaml::from_str(yaml).expect("should deserialize v3 workflow");
        assert_eq!(wf.version, "3");
        assert_eq!(wf.name, "Continuous Integration Workflow");
        assert_eq!(wf.tasks.len(), 3);
        assert_eq!(wf.stages.len(), 3);
        assert_eq!(wf.on_action.get("push").unwrap().len(), 3);
        assert_eq!(wf.on_action.get("pull_request").unwrap().len(), 2);

        // Verify topological order validation
        let topo = wf.validate().expect("should validate successfully");
        assert_eq!(topo, vec!["formatting", "linting", "testing"]);

        // Reserialize and verify roundtrip
        let serialized = serde_yaml::to_string(&wf).expect("should serialize v3 workflow");
        let roundtrip: ActionRunnerWorkflow =
            serde_yaml::from_str(&serialized).expect("should deserialize serialized v3 workflow");
        assert_eq!(wf, roundtrip);
    }

    // --- Sub-task #21 Tests: Cyclic Dependency & Unknown Reference Validator ---

    #[test]
    fn test_v3_validation_unsupported_version() {
        let yaml = r#"
version: "2"
name: "Invalid Version"
tasks: {}
stages:
  - id: s1
    name: "Stage 1"
    tasks: []
on_action: {}
"#;
        let wf: ActionRunnerWorkflow = serde_yaml::from_str(yaml).unwrap();
        let err = wf.validate().unwrap_err();
        match err {
            WorkflowValidationError::UnsupportedVersion(v) => assert_eq!(v, "2"),
            other => panic!("Expected UnsupportedVersion, got {:?}", other),
        }
    }

    #[test]
    fn test_v3_validation_unknown_task_reference() {
        let yaml = r#"
version: "3"
name: "Dangling Task Reference"
tasks:
  valid-task:
    tool: "cargo-test"
stages:
  - id: stage-a
    name: "Stage A"
    tasks: ["valid-task", "nonexistent-task"]
on_action:
  push: ["stage-a"]
"#;
        let wf: ActionRunnerWorkflow = serde_yaml::from_str(yaml).unwrap();
        let err = wf.validate().unwrap_err();
        match err {
            WorkflowValidationError::UnknownTaskReference { stage_id, task_id } => {
                assert_eq!(stage_id, "stage-a");
                assert_eq!(task_id, "nonexistent-task");
            }
            other => panic!("Expected UnknownTaskReference, got {:?}", other),
        }
    }

    #[test]
    fn test_v3_validation_unknown_stage_reference_in_depends_on() {
        let yaml = r#"
version: "3"
name: "Dangling Depends On"
tasks:
  t1:
    tool: "cargo-build"
stages:
  - id: stage-a
    name: "Stage A"
    tasks: ["t1"]
    depends_on: ["missing-stage"]
on_action:
  push: ["stage-a"]
"#;
        let wf: ActionRunnerWorkflow = serde_yaml::from_str(yaml).unwrap();
        let err = wf.validate().unwrap_err();
        match err {
            WorkflowValidationError::UnknownStageReference { stage_id, .. } => {
                assert_eq!(stage_id, "missing-stage");
            }
            other => panic!("Expected UnknownStageReference, got {:?}", other),
        }
    }

    #[test]
    fn test_v3_validation_unknown_stage_reference_in_on_action() {
        let yaml = r#"
version: "3"
name: "Dangling OnAction Reference"
tasks:
  t1:
    tool: "cargo-build"
stages:
  - id: stage-a
    name: "Stage A"
    tasks: ["t1"]
on_action:
  push: ["nonexistent-stage"]
"#;
        let wf: ActionRunnerWorkflow = serde_yaml::from_str(yaml).unwrap();
        let err = wf.validate().unwrap_err();
        match err {
            WorkflowValidationError::UnknownStageReference {
                context, stage_id, ..
            } => {
                assert_eq!(stage_id, "nonexistent-stage");
                assert!(context.contains("on_action.push"));
            }
            other => panic!("Expected UnknownStageReference, got {:?}", other),
        }
    }

    #[test]
    fn test_v3_validation_cycle_detected_2_nodes() {
        let yaml = r#"
version: "3"
name: "2-Node Cycle"
tasks:
  t1:
    tool: "cargo-build"
stages:
  - id: stage-a
    name: "Stage A"
    tasks: ["t1"]
    depends_on: ["stage-b"]
  - id: stage-b
    name: "Stage B"
    tasks: ["t1"]
    depends_on: ["stage-a"]
on_action:
  push: ["stage-a"]
"#;
        let wf: ActionRunnerWorkflow = serde_yaml::from_str(yaml).unwrap();
        let err = wf.validate().unwrap_err();
        match err {
            WorkflowValidationError::CycleDetected(cycle) => {
                assert!(
                    cycle.contains(&"stage-a".to_string())
                        && cycle.contains(&"stage-b".to_string()),
                    "Cycle must contain both stage-a and stage-b: {:?}",
                    cycle
                );
            }
            other => panic!("Expected CycleDetected, got {:?}", other),
        }
    }

    #[test]
    fn test_v3_validation_cycle_detected_3_nodes() {
        let yaml = r#"
version: "3"
name: "3-Node Cycle"
tasks:
  t1:
    tool: "cargo-build"
stages:
  - id: stage-a
    name: "Stage A"
    tasks: ["t1"]
    depends_on: ["stage-c"]
  - id: stage-b
    name: "Stage B"
    tasks: ["t1"]
    depends_on: ["stage-a"]
  - id: stage-c
    name: "Stage C"
    tasks: ["t1"]
    depends_on: ["stage-b"]
on_action:
  push: ["stage-a"]
"#;
        let wf: ActionRunnerWorkflow = serde_yaml::from_str(yaml).unwrap();
        let err = wf.validate().unwrap_err();
        match err {
            WorkflowValidationError::CycleDetected(cycle) => {
                assert!(
                    cycle.contains(&"stage-a".to_string())
                        && cycle.contains(&"stage-b".to_string())
                        && cycle.contains(&"stage-c".to_string()),
                    "Cycle must contain all 3 nodes: {:?}",
                    cycle
                );
            }
            other => panic!("Expected CycleDetected, got {:?}", other),
        }
    }

    #[test]
    fn test_v3_subgraph_for_event() {
        let yaml = r#"
version: "3"
name: "Selective Trigger"
tasks:
  t-fmt:
    tool: "cargo-fmt"
  t-test:
    tool: "cargo-test"
  t-deploy:
    tool: "cargo-publish"
stages:
  - id: fmt
    name: "Fmt"
    tasks: ["t-fmt"]
  - id: test
    name: "Test"
    tasks: ["t-test"]
    depends_on: ["fmt"]
  - id: deploy
    name: "Deploy"
    tasks: ["t-deploy"]
    depends_on: ["test"]
on_action:
  push: ["test"]
  release: ["deploy"]
"#;
        let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("valid yaml");
        let push_sub = wf.subgraph_for_event("push").expect("push subgraph");
        assert_eq!(push_sub.stages.len(), 2); // fmt and test
        assert!(push_sub.stages.iter().any(|s| s.id == "fmt"));
        assert!(push_sub.stages.iter().any(|s| s.id == "test"));
        assert!(!push_sub.stages.iter().any(|s| s.id == "deploy"));
        assert_eq!(push_sub.tasks.len(), 2);
    }

    #[test]
    fn test_v3_stage_config_exclusive_field_deserialization() {
        let yaml = r#"
version: "3"
name: "Exclusive Pipeline"
tasks:
  bench-task:
    tool: "cargo-bench"
stages:
  - id: bench-run
    name: "Hardware Micro-benchmark"
    tasks: ["bench-task"]
    tags: ["k3", "bench"]
    threads: 8
    exclusive: true
on_action:
  push: ["bench-run"]
"#;
        let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("should parse exclusive: true");
        assert_eq!(wf.stages.len(), 1);
        assert_eq!(wf.stages[0].id, "bench-run");
        assert!(wf.stages[0].exclusive, "exclusive must be true");
    }

    #[test]
    fn test_v3_stage_config_isolate_node_alias_deserialization() {
        let yaml = r#"
version: "3"
name: "Isolate Node Pipeline"
tasks:
  bench-task:
    tool: "cargo-bench"
stages:
  - id: bench-run
    name: "Hardware Micro-benchmark"
    tasks: ["bench-task"]
    tags: ["k3", "bench"]
    threads: 8
    isolate_node: true
on_action:
  push: ["bench-run"]
"#;
        let wf = ActionRunnerWorkflow::from_yaml(yaml)
            .expect("should parse isolate_node: true as exclusive: true");
        assert_eq!(wf.stages.len(), 1);
        assert_eq!(wf.stages[0].id, "bench-run");
        assert!(
            wf.stages[0].exclusive,
            "isolate_node: true must deserialize into exclusive = true"
        );
    }

    #[test]
    fn test_v3_stage_config_default_exclusive_is_false() {
        let yaml = r#"
version: "3"
name: "Default Pipeline"
tasks:
  test-task:
    tool: "cargo-test"
stages:
  - id: normal-test
    name: "Standard Tests"
    tasks: ["test-task"]
    tags: ["default"]
on_action:
  push: ["normal-test"]
"#;
        let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("should parse default exclusive");
        assert_eq!(wf.stages.len(), 1);
        assert_eq!(wf.stages[0].id, "normal-test");
        assert!(!wf.stages[0].exclusive, "exclusive must default to false");
    }
}
