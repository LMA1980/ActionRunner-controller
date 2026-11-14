use mu_ci_ipc::SccacheMode;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

// ============================================================================
// v3 / v4 3-Tier Declarative Configuration Models (#20, #184)
// ============================================================================

/// Parsed Rust compiler semantic version (`major.minor[.patch][-prerelease]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustSemver {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub prerelease: Option<String>,
}

impl fmt::Display for RustSemver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(ref pre) = self.prerelease {
            write!(f, "-{}", pre)?;
        }
        Ok(())
    }
}

impl Ord for RustSemver {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (&self.prerelease, &other.prerelease) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => compare_prerelease(a, b),
            })
    }
}

impl PartialOrd for RustSemver {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_prerelease(a: &str, b: &str) -> Ordering {
    let mut a_parts = a.split('.');
    let mut b_parts = b.split('.');
    loop {
        match (a_parts.next(), b_parts.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(ap), Some(bp)) => {
                let ord = match (ap.parse::<u64>(), bp.parse::<u64>()) {
                    (Ok(an), Ok(bn)) => an.cmp(&bn),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => ap.cmp(bp),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// Parse a Rust semantic version string (e.g. `"1.86.0"`, `"1.86"`, `"1.86.0-nightly"`).
pub fn parse_rust_semver(raw: &str) -> Result<RustSemver, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty Rust semver string".to_string());
    }
    let without_build = trimmed.split('+').next().unwrap_or(trimmed);
    let (core, prerelease) = match without_build.split_once('-') {
        Some((c, p)) => {
            if p.is_empty() {
                return Err(format!("invalid empty prerelease suffix in '{}'", raw));
            }
            (c, Some(p.to_string()))
        }
        None => (without_build, None),
    };

    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() < 2 || parts.len() > 3 {
        return Err(format!(
            "invalid Rust semver '{}': expected 'major.minor' or 'major.minor.patch'",
            raw
        ));
    }

    let parse_num = |s: &str| -> Result<u64, String> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!(
                "invalid numeric component '{}' in semver '{}'",
                s, raw
            ));
        }
        s.parse::<u64>()
            .map_err(|_| format!("overflow in semver '{}'", raw))
    };

    let major = parse_num(parts[0])?;
    let minor = parse_num(parts[1])?;
    let patch = if parts.len() == 3 {
        parse_num(parts[2])?
    } else {
        0
    };

    Ok(RustSemver {
        major,
        minor,
        patch,
        prerelease,
    })
}

/// Structured compiler and C-toolchain requirements declared in `version: "4"` workflows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ToolchainRequirement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub c_toolchain: Option<String>,
}

/// Action taken when zero live workers satisfy a stage's capability requirements.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableAction {
    #[default]
    Queue,
    Skip,
}

/// Optional fallback policy on a stage when zero capable live workers exist.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct StageUnavailablePolicy {
    #[serde(default)]
    pub policy: UnavailableAction,
    #[serde(default)]
    pub pr_comment: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_label: Option<String>,
}

#[derive(Deserialize)]
struct StageUnavailablePolicyRaw {
    #[serde(default)]
    policy: UnavailableAction,
    #[serde(default)]
    pr_comment: bool,
    #[serde(default)]
    capability_label: Option<String>,
}

impl<'de> Deserialize<'de> for StageUnavailablePolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PolicyVisitor;

        impl<'de> Visitor<'de> for PolicyVisitor {
            type Value = StageUnavailablePolicy;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a policy string ('queue' or 'skip') or an if_unavailable map")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let policy = match v.trim().to_ascii_lowercase().as_str() {
                    "queue" => UnavailableAction::Queue,
                    "skip" => UnavailableAction::Skip,
                    other => {
                        return Err(E::custom(format!(
                            "invalid if_unavailable policy '{}', expected 'queue' or 'skip'",
                            other
                        )));
                    }
                };
                Ok(StageUnavailablePolicy {
                    policy,
                    pr_comment: false,
                    capability_label: None,
                })
            }

            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let raw = StageUnavailablePolicyRaw::deserialize(
                    de::value::MapAccessDeserializer::new(map),
                )?;
                Ok(StageUnavailablePolicy {
                    policy: raw.policy,
                    pr_comment: raw.pr_comment,
                    capability_label: raw.capability_label,
                })
            }
        }

        deserializer.deserialize_any(PolicyVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionRunnerWorkflow {
    pub version: String, // "3" or "4"
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolchain: Option<ToolchainRequirement>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub sccache: Option<SccacheMode>,
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
    #[serde(default)]
    pub sccache: Option<SccacheMode>,
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
    #[serde(default)]
    pub sccache: Option<SccacheMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_unavailable: Option<StageUnavailablePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkflowValidationError {
    #[error("Unsupported workflow version '{0}', expected '3' or '4'")]
    UnsupportedVersion(String),
    #[error("Invalid workflow toolchain requirement: {0}")]
    InvalidToolchainRequirement(String),
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
            .map_err(|e| format!("Failed to parse ActionRunner/mu-ci YAML workflow: {}", e))?;
        wf.validate().map_err(|e| e.to_string())?;
        Ok(wf)
    }

    /// Validate the workflow and return stage IDs in topological execution order.
    pub fn validate(&self) -> Result<Vec<String>, WorkflowValidationError> {
        // 1. Reject version not in {"3", "4"}
        if self.version != "3" && self.version != "4" {
            return Err(WorkflowValidationError::UnsupportedVersion(
                self.version.clone(),
            ));
        }

        // Validate structured toolchain requirements when provided
        if let Some(ref tc) = self.toolchain {
            if let Some(ref min_ver) = tc.min_version {
                parse_rust_semver(min_ver)
                    .map_err(WorkflowValidationError::InvalidToolchainRequirement)?;
            }
            if let Some(ref channel) = tc.channel {
                if channel.trim().is_empty() {
                    return Err(WorkflowValidationError::InvalidToolchainRequirement(
                        "toolchain.channel must not be blank".to_string(),
                    ));
                }
            }
            if let Some(ref c_tc) = tc.c_toolchain {
                if c_tc.trim().is_empty() {
                    return Err(WorkflowValidationError::InvalidToolchainRequirement(
                        "toolchain.c_toolchain must not be blank".to_string(),
                    ));
                }
            }
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
        let target_stage_ids = match self.on_action.get(event) {
            Some(stages) => stages,
            None => {
                return Ok(ActionRunnerWorkflow {
                    version: self.version.clone(),
                    name: self.name.clone(),
                    toolchain: self.toolchain.clone(),
                    env: self.env.clone(),
                    sccache: self.sccache,
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
            toolchain: self.toolchain.clone(),
            env: self.env.clone(),
            sccache: self.sccache,
            tasks: filtered_tasks,
            stages: filtered_stages,
            on_action: filtered_on_action,
        })
    }

    /// Resolve a human-readable capability label for an optional `if_unavailable` stage.
    pub fn stage_capability_label(stage: &StageConfig) -> String {
        if let Some(label) = stage
            .if_unavailable
            .as_ref()
            .and_then(|p| p.capability_label.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return label.to_string();
        }
        if let Some(tag) = stage
            .tags
            .iter()
            .map(|t| t.trim())
            .find(|t| !t.is_empty() && !t.eq_ignore_ascii_case("default"))
        {
            return if tag.eq_ignore_ascii_case("kva23") {
                "KVA23".to_string()
            } else {
                tag.to_string()
            };
        }
        if let Some(tc) = stage
            .toolchain
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return tc.to_string();
        }
        "capable".to_string()
    }

    /// Resolve effective `SccacheMode` for a stage (`StageConfig.sccache -> ActionRunnerWorkflow.sccache -> SccacheMode::Try`).
    pub fn resolve_stage_sccache(&self, stage: &StageConfig) -> SccacheMode {
        stage.sccache.or(self.sccache).unwrap_or(SccacheMode::Try)
    }

    /// Resolve effective `SccacheMode` for a task (`TaskConfig.sccache -> StageConfig.sccache -> ActionRunnerWorkflow.sccache -> SccacheMode::Try`).
    pub fn resolve_task_sccache(&self, stage: &StageConfig, task: &TaskConfig) -> SccacheMode {
        task.sccache
            .or(stage.sccache)
            .or(self.sccache)
            .unwrap_or(SccacheMode::Try)
    }

    /// Return true if a tool invokes Rust/WASM compilation eligible for `sccache`.
    pub fn is_sccache_eligible_tool(tool_name: &str) -> bool {
        matches!(
            tool_name.trim(),
            "cargo-build" | "cargo-check" | "cargo-test" | "cargo-clippy" | "cargo-bench" | "trunk"
        )
    }

    /// Return true if a stage requires the `"sccache"` worker capability tag.
    pub fn stage_requires_mandatory_sccache(&self, stage: &StageConfig) -> bool {
        if stage.sccache == Some(SccacheMode::Mandatory) {
            return true;
        }
        if stage.tasks.is_empty() {
            return self.resolve_stage_sccache(stage) == SccacheMode::Mandatory;
        }
        stage.tasks.iter().any(|tid| {
            self.tasks.get(tid).map_or_else(
                || self.resolve_stage_sccache(stage) == SccacheMode::Mandatory,
                |tcfg| {
                    tcfg.sccache == Some(SccacheMode::Mandatory)
                        || (self.resolve_task_sccache(stage, tcfg) == SccacheMode::Mandatory
                            && Self::is_sccache_eligible_tool(&tcfg.tool))
                },
            )
        })
    }

    /// Resolve effective worker capability tags for a stage, appending `"sccache"` when mandatory.
    pub fn effective_stage_tags(&self, stage: &StageConfig) -> Vec<String> {
        let mut tags = stage.tags.clone();
        if self.stage_requires_mandatory_sccache(stage) && !tags.iter().any(|t| t == "sccache") {
            tags.push("sccache".to_string());
        }
        tags
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

    #[test]
    fn test_v3_sccache_policy_deserialization_and_inheritance() {
        let yaml = r#"
version: "3"
name: "Sccache Policy Pipeline"
sccache: try
tasks:
  build-default:
    tool: "cargo-build"
  build-off:
    tool: "cargo-build"
    sccache: false
  build-mandatory:
    tool: "cargo-build"
    sccache: mandatory
  build-true:
    tool: "cargo-build"
    sccache: true
stages:
  - id: stage-inherit
    name: "Inherit Workflow Sccache"
    tasks: ["build-default", "build-off", "build-mandatory"]
  - id: stage-disabled
    name: "Stage Sccache Disabled"
    sccache: false
    tasks: ["build-default", "build-true"]
  - id: stage-mandatory
    name: "Stage Sccache Mandatory"
    sccache: mandatory
    tasks: ["build-default"]
on_action:
  push: ["stage-inherit", "stage-disabled", "stage-mandatory"]
"#;
        let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("should parse sccache policies");
        assert_eq!(wf.sccache, Some(SccacheMode::Try));

        let s_inherit = &wf.stages[0];
        let s_disabled = &wf.stages[1];
        let s_mandatory = &wf.stages[2];

        assert_eq!(wf.resolve_stage_sccache(s_inherit), SccacheMode::Try);
        assert_eq!(wf.resolve_stage_sccache(s_disabled), SccacheMode::Off);
        assert_eq!(
            wf.resolve_stage_sccache(s_mandatory),
            SccacheMode::Mandatory
        );

        let t_default = wf.tasks.get("build-default").unwrap();
        let t_off = wf.tasks.get("build-off").unwrap();
        let t_mandatory = wf.tasks.get("build-mandatory").unwrap();
        let t_true = wf.tasks.get("build-true").unwrap();

        assert_eq!(
            wf.resolve_task_sccache(s_inherit, t_default),
            SccacheMode::Try
        );
        assert_eq!(wf.resolve_task_sccache(s_inherit, t_off), SccacheMode::Off);
        assert_eq!(
            wf.resolve_task_sccache(s_inherit, t_mandatory),
            SccacheMode::Mandatory
        );
        assert_eq!(
            wf.resolve_task_sccache(s_disabled, t_default),
            SccacheMode::Off
        );
        assert_eq!(
            wf.resolve_task_sccache(s_disabled, t_true),
            SccacheMode::Try
        );
        assert_eq!(
            wf.resolve_task_sccache(s_mandatory, t_default),
            SccacheMode::Mandatory
        );
    }

    #[test]
    fn test_effective_stage_tags_for_mandatory_sccache() {
        let yaml = r#"
version: "3"
name: "Mandatory Sccache Tag Resolution"
sccache: mandatory
tasks:
  fmt:
    tool: "cargo-fmt"
  clippy:
    tool: "cargo-clippy"
  build-off:
    tool: "cargo-build"
    sccache: false
stages:
  - id: fmt-only
    name: "Fmt Only"
    tags: ["fmt"]
    tasks: ["fmt"]
  - id: clippy-compile
    name: "Clippy Compile"
    tags: ["clippy"]
    tasks: ["clippy"]
  - id: build-overridden-off
    name: "Build Overridden Off"
    tags: ["build"]
    tasks: ["build-off"]
  - id: already-tagged
    name: "Already Tagged"
    tags: ["build", "sccache"]
    tasks: ["clippy"]
on_action:
  push: ["fmt-only", "clippy-compile", "build-overridden-off", "already-tagged"]
"#;
        let wf = ActionRunnerWorkflow::from_yaml(yaml).expect("valid workflow");
        assert_eq!(
            wf.effective_stage_tags(&wf.stages[0]),
            vec!["fmt".to_string()],
            "Non-compiler hygiene stage should not force sccache tag when inherited from workflow root"
        );
        assert_eq!(
            wf.effective_stage_tags(&wf.stages[1]),
            vec!["clippy".to_string(), "sccache".to_string()],
            "Compiler stage with mandatory sccache must append sccache tag"
        );
        assert_eq!(
            wf.effective_stage_tags(&wf.stages[2]),
            vec!["build".to_string()],
            "Stage where all tasks override sccache: false must not append sccache tag"
        );
        assert_eq!(
            wf.effective_stage_tags(&wf.stages[3]),
            vec!["build".to_string(), "sccache".to_string()],
            "Must not duplicate existing sccache tag"
        );
    }

    #[test]
    fn test_v4_workflow_toolchain_and_if_unavailable_parsing_and_v3_side_by_side() {
        let v3_yaml = r#"
version: "3"
name: "Legacy v3 Pipeline"
tasks:
  check:
    tool: "cargo-check"
stages:
  - id: check
    name: "Check"
    tasks: ["check"]
    toolchain: "stable"
on_action:
  pull_request: ["check"]
"#;
        let v3_wf = ActionRunnerWorkflow::from_yaml(v3_yaml).expect("v3 workflow parses");
        assert_eq!(v3_wf.version, "3");
        assert_eq!(v3_wf.toolchain, None);
        assert_eq!(v3_wf.stages[0].toolchain.as_deref(), Some("stable"));
        assert_eq!(v3_wf.stages[0].if_unavailable, None);

        let v4_yaml = r#"
version: "4"
name: "v4 Toolchain & KVA23 Skip Pipeline"
toolchain:
  min_version: "1.82.0"
  channel: "stable"
  c_toolchain: "gcc"
tasks:
  check:
    tool: "cargo-check"
  bench:
    tool: "cargo-bench"
stages:
  - id: check
    name: "Check"
    tasks: ["check"]
    tags: ["rust"]
    toolchain: "stable"
  - id: bench_kva23
    name: "KVA23 Benchmark"
    tasks: ["bench"]
    depends_on: ["check"]
    tags: ["kva23"]
    if_unavailable:
      policy: skip
      pr_comment: true
      capability_label: "KVA23"
  - id: bench_shorthand
    name: "Optional Shorthand Bench"
    tasks: ["bench"]
    tags: ["kva23"]
    if_unavailable: "skip"
on_action:
  pull_request: ["bench_kva23", "bench_shorthand"]
"#;
        let v4_wf = ActionRunnerWorkflow::from_yaml(v4_yaml).expect("v4 workflow parses");
        assert_eq!(v4_wf.version, "4");
        assert_eq!(
            v4_wf.toolchain,
            Some(ToolchainRequirement {
                min_version: Some("1.82.0".to_string()),
                channel: Some("stable".to_string()),
                c_toolchain: Some("gcc".to_string()),
            })
        );
        let kva_stage = &v4_wf.stages[1];
        assert_eq!(
            kva_stage.if_unavailable,
            Some(StageUnavailablePolicy {
                policy: UnavailableAction::Skip,
                pr_comment: true,
                capability_label: Some("KVA23".to_string()),
            })
        );
        assert_eq!(
            ActionRunnerWorkflow::stage_capability_label(kva_stage),
            "KVA23"
        );

        let shorthand_stage = &v4_wf.stages[2];
        assert_eq!(
            shorthand_stage.if_unavailable,
            Some(StageUnavailablePolicy {
                policy: UnavailableAction::Skip,
                pr_comment: false,
                capability_label: None,
            })
        );
        assert_eq!(
            ActionRunnerWorkflow::stage_capability_label(shorthand_stage),
            "KVA23"
        );

        let sub = v4_wf
            .subgraph_for_event("pull_request")
            .expect("subgraph builds");
        assert_eq!(sub.toolchain, v4_wf.toolchain);
        assert_eq!(sub.stages.len(), 3);
    }

    #[test]
    fn test_v4_invalid_min_version_rejected_in_validation() {
        let bad_yaml = r#"
version: "4"
name: "Bad Toolchain Semver"
toolchain:
  min_version: "1.invalid.0"
tasks:
  check:
    tool: "cargo-check"
stages:
  - id: check
    name: "Check"
    tasks: ["check"]
on_action:
  push: ["check"]
"#;
        let wf: ActionRunnerWorkflow = serde_yaml::from_str(bad_yaml).expect("YAML syntax ok");
        match wf.validate() {
            Err(WorkflowValidationError::InvalidToolchainRequirement(msg)) => {
                assert!(msg.contains("1.invalid.0"), "unexpected error: {msg}");
            }
            other => panic!("Expected InvalidToolchainRequirement, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_rust_semver_ordering() {
        let a = parse_rust_semver("1.82").expect("major.minor");
        let b = parse_rust_semver("1.82.0").expect("exact patch");
        let c = parse_rust_semver("1.86.0-nightly").expect("prerelease");
        let d = parse_rust_semver("1.86.0").expect("stable release");
        let e = parse_rust_semver("1.86.1+abcdef").expect("build metadata");
        assert_eq!(a, b);
        assert!(b < c);
        assert!(c < d);
        assert!(d < e);
        assert!(parse_rust_semver("latest").is_err());
        assert!(parse_rust_semver("1").is_err());
        assert!(parse_rust_semver("1.2.3.4").is_err());
    }
}
