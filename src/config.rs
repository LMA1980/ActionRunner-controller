use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub workspace_dir: PathBuf,
    pub allowed_repositories: Vec<String>,
    pub allowed_actors: Vec<String>,
    pub allow_fork_prs: bool,
    pub allowed_pr_authors: Vec<String>,
    pub log_api_key: Option<String>,
    pub webhook_secret: Option<String>,
    pub cluster_token: String,
    pub job_timeout_seconds: u64,
    pub allow_insecure_no_secret: bool,
}

impl Config {
    pub fn load() -> Self {
        let bind_addr = std::env::var("ACTION_RUNNER_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8000".to_string());

        let workspace_dir = std::env::var("ACTION_RUNNER_WORKSPACE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/var/lib/action-runner/workspace"));

        let allowed_repositories = std::env::var("ACTION_RUNNER_ALLOWED_REPOS")
            .unwrap_or_else(|_| "LMA1980/*".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let allowed_actors = std::env::var("ACTION_RUNNER_ALLOWED_ACTORS")
            .unwrap_or_else(|_| "*".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let allow_fork_prs = std::env::var("ACTION_RUNNER_ALLOW_FORK_PRS")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let allowed_pr_authors = std::env::var("ACTION_RUNNER_ALLOWED_PR_AUTHORS")
            .unwrap_or_else(|_| "OWNER,MEMBER,COLLABORATOR".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let log_api_key = std::env::var("ACTION_RUNNER_LOG_API_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let allow_insecure_no_secret = std::env::var("ACTION_RUNNER_ALLOW_INSECURE_NO_SECRET")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let webhook_secret = Self::resolve_secret("GITHUB_WEBHOOK_SECRET");
        let cluster_token = Self::resolve_secret("ACTION_RUNNER_CLUSTER_TOKEN")
            .unwrap_or_else(|| "action-runner-default-cluster-token".to_string());

        let job_timeout_seconds = std::env::var("ACTION_RUNNER_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(600);

        Self {
            bind_addr,
            workspace_dir,
            allowed_repositories,
            allowed_actors,
            allow_fork_prs,
            allowed_pr_authors,
            log_api_key,
            webhook_secret,
            cluster_token,
            job_timeout_seconds,
            allow_insecure_no_secret,
        }
    }

    pub fn is_repo_allowed(&self, repo: &str) -> bool {
        if !is_safe_repo_name(repo) {
            return false;
        }

        for pattern in &self.allowed_repositories {
            if pattern == "*" {
                return true;
            }
            if let Some(prefix) = pattern.strip_suffix("/*") {
                if let Some((owner, _)) = repo.split_once('/') {
                    if owner.eq_ignore_ascii_case(prefix) {
                        return true;
                    }
                }
            } else if pattern.eq_ignore_ascii_case(repo) {
                return true;
            }
        }
        false
    }

    pub fn is_actor_allowed(&self, actor: &str) -> bool {
        if self.allowed_actors.is_empty() {
            return true;
        }
        self.allowed_actors
            .iter()
            .any(|a| a == "*" || a.eq_ignore_ascii_case(actor))
    }

    pub fn is_pr_author_allowed(&self, association: &str) -> bool {
        self.allowed_pr_authors
            .iter()
            .any(|a| a.eq_ignore_ascii_case(association))
    }

    fn resolve_secret(env_var: &str) -> Option<String> {
        let val = std::env::var(env_var).ok()?.trim().to_string();
        if val.is_empty() {
            return None;
        }

        let path = Path::new(&val);
        if path.is_file() {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let secret = content.trim().to_string();
                    if secret.is_empty() {
                        warn!("Secret file at {} is empty", path.display());
                        None
                    } else {
                        info!("Loaded secret for {} from {}", env_var, path.display());
                        Some(secret)
                    }
                }
                Err(err) => {
                    warn!(
                        "Failed to read secret file at {} for {}: {}",
                        path.display(),
                        env_var,
                        err
                    );
                    None
                }
            }
        } else {
            Some(val)
        }
    }
}

pub fn is_safe_repo_name(repo: &str) -> bool {
    let parts: Vec<&str> = repo.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let owner = parts[0];
    let name = parts[1];
    if owner.is_empty() || name.is_empty() {
        return false;
    }
    if owner.contains("..") || name.contains("..") {
        return false;
    }
    let is_valid_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';
    owner.chars().all(is_valid_char) && name.chars().all(is_valid_char)
}
