use action_runner_controller::workflow::WorkflowConfig;
use std::path::Path;

#[test]
fn test_workflow_dag_validation_valid() {
    let yaml = r#"
version: "2"
name: "Test Pipeline"
stages:
  - id: fmt
    name: "Format"
    tags: ["fmt"]
    threads: 2
    run: "cargo fmt --check"
  - id: clippy
    name: "Clippy"
    tags: ["clippy"]
    threads: 4
    run: "cargo clippy"
  - id: test-native
    name: "Native Test"
    tags: ["k3"]
    depends_on: ["fmt", "clippy"]
    run: "cargo test"
"#;
    let wf = WorkflowConfig::load_from_str(yaml, Path::new("."), 600).expect("valid workflow");
    assert_eq!(wf.stages.len(), 3);
    assert_eq!(wf.stages[2].depends_on, vec!["fmt", "clippy"]);
}

#[test]
fn test_workflow_dag_cycle_detection() {
    let yaml = r#"
version: "2"
name: "Cyclic Pipeline"
stages:
  - id: stage-a
    name: "A"
    tags: ["test"]
    depends_on: ["stage-b"]
    run: "echo a"
  - id: stage-b
    name: "B"
    tags: ["test"]
    depends_on: ["stage-a"]
    run: "echo b"
"#;
    let err = WorkflowConfig::load_from_str(yaml, Path::new("."), 600).unwrap_err();
    assert!(err.contains("Cyclic dependency detected"));
}

#[test]
fn test_workflow_v1_backwards_compatibility() {
    let yaml = r#"
name: "V1 Pipeline"
steps:
  - name: "Step 1"
    run: "cargo fmt"
  - name: "Step 2"
    run: "cargo test"
"#;
    let wf = WorkflowConfig::load_from_str(yaml, Path::new("."), 600).expect("valid v1");
    assert_eq!(wf.stages.len(), 2);
    assert_eq!(wf.stages[0].id, "step-1");
    assert_eq!(wf.stages[1].id, "step-2");
    assert_eq!(wf.stages[1].depends_on, vec!["step-1"]);
}
