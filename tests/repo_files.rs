use std::path::PathBuf;

fn repo_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative)
}

#[test]
fn ci_workflow_exists() {
    assert!(repo_path(".github/workflows/ci.yml").is_file());
}

#[test]
fn license_file_exists() {
    assert!(repo_path("LICENSE").is_file());
}
