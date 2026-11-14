use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Configured High-Availability role policy for a controller instance (`#78`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HaRoleConfig {
    /// Automatically acquires or renews the single-leader lease in `ControllerStorage`;
    /// starts in `standby` if another node holds a valid lease, and promotes to `leader`
    /// when the primary lease expires.
    Auto,
    /// Explicitly starts as the active `leader`.
    #[default]
    Leader,
    /// Explicitly starts as a hot `standby` replica (does not claim jobs until promoted).
    Standby,
}

impl HaRoleConfig {
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Self::Auto,
            "standby" | "follower" | "backup" => Self::Standby,
            _ => Self::Leader,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Leader => "leader",
            Self::Standby => "standby",
        }
    }
}

/// Runtime High-Availability role of a controller instance (`#78`–`#80`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HaRole {
    #[default]
    Leader,
    Standby,
}

impl HaRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Leader => "leader",
            Self::Standby => "standby",
        }
    }

    #[must_use]
    pub const fn is_leader(self) -> bool {
        matches!(self, Self::Leader)
    }
}

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
    pub max_concurrent_jobs: usize,
    pub github_token: Option<String>,
    pub node_id: String,
    pub ha_role: HaRoleConfig,
    pub lease_ttl_seconds: u64,
    pub standby_sync_seconds: u64,
    pub proxy_secret: Option<String>,
    pub invite_signing_key: Option<String>,
    pub bootstrap_admins: Vec<String>,
    pub quic_bind_addr: Option<String>,
    pub quic_alt_svc_port: Option<u16>,
    pub quic_alt_svc_max_age: Option<u64>,
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub tls_ca_path: Option<PathBuf>,
    /// WebAuthn Relying Party ID (domain, e.g., `localhost` or `console.example.org`).
    pub webauthn_rp_id: String,
    /// WebAuthn Relying Party human-readable display name.
    pub webauthn_rp_name: String,
    /// WebAuthn expected origin (`http://localhost` or `https://console.example.org`).
    pub webauthn_rp_origin: String,
    /// Dedicated HMAC secret for `__Host-mu_elevated` cookies (falls back to `invite_signing_key`).
    pub host_elevation_secret: Option<String>,
    /// Optional explicit path for persistent platform auth state JSON.
    pub auth_state_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8000".to_string(),
            workspace_dir: PathBuf::from(format!("/var/lib/{}-runner/workspace", "action")),
            allowed_repositories: vec!["LMA1980/*".to_string()],
            allowed_actors: vec!["*".to_string()],
            allow_fork_prs: false,
            allowed_pr_authors: vec![
                "OWNER".to_string(),
                "MEMBER".to_string(),
                "COLLABORATOR".to_string(),
            ],
            log_api_key: None,
            webhook_secret: None,
            cluster_token: "actionrunner_default_cluster_token".to_string(),
            job_timeout_seconds: 1800,
            allow_insecure_no_secret: false,
            max_concurrent_jobs: 3,
            github_token: None,
            node_id: "node-a".to_string(),
            ha_role: HaRoleConfig::Leader,
            lease_ttl_seconds: 15,
            standby_sync_seconds: 5,
            proxy_secret: None,
            invite_signing_key: None,
            bootstrap_admins: Vec::new(),
            quic_bind_addr: None,
            quic_alt_svc_port: None,
            quic_alt_svc_max_age: None,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            webauthn_rp_id: "localhost".to_string(),
            webauthn_rp_name: "MuConsole Platform".to_string(),
            webauthn_rp_origin: "http://localhost".to_string(),
            host_elevation_secret: None,
            auth_state_file: None,
        }
    }
}

impl Config {
    pub fn load() -> Self {
        let bind_addr =
            std::env::var("ACTION_RUNNER_BIND").unwrap_or_else(|_| "127.0.0.1:8000".to_string());

        let workspace_dir = std::env::var("ACTION_RUNNER_WORKSPACE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(format!("/var/lib/{}-runner/workspace", "action")));

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

        let log_api_key = Self::resolve_secret("ACTION_RUNNER_LOG_API_KEY");

        let allow_insecure_no_secret = std::env::var("ACTION_RUNNER_ALLOW_INSECURE_NO_SECRET")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let webhook_secret = Self::resolve_secret("GITHUB_WEBHOOK_SECRET");
        let cluster_token = Self::resolve_secret("ACTION_RUNNER_CLUSTER_TOKEN")
            .unwrap_or_else(|| "actionrunner_default_cluster_token".to_string());

        let job_timeout_seconds = std::env::var("ACTION_RUNNER_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1800);

        let max_concurrent_jobs = std::env::var("ACTION_RUNNER_MAX_CONCURRENT_JOBS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);

        let github_token = Self::resolve_secret("GITHUB_TOKEN");

        let node_id = std::env::var("ACTION_RUNNER_NODE_ID")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "node-a".to_string());

        let ha_role = std::env::var("ACTION_RUNNER_HA_ROLE")
            .map(|s| HaRoleConfig::parse(&s))
            .unwrap_or(HaRoleConfig::Leader);

        let lease_ttl_seconds = std::env::var("ACTION_RUNNER_LEASE_TTL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(15);

        let standby_sync_seconds = std::env::var("ACTION_RUNNER_STANDBY_SYNC_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(5);

        let proxy_secret = Self::resolve_secret_with_file_var(
            "ACTION_RUNNER_PROXY_SECRET",
            "ACTION_RUNNER_PROXY_SECRET_FILE",
        );

        let invite_signing_key = Self::resolve_secret_with_file_var(
            "ACTION_RUNNER_INVITE_SIGNING_KEY",
            "ACTION_RUNNER_INVITE_SIGNING_KEY_FILE",
        );

        let bootstrap_admins = std::env::var("ACTION_RUNNER_BOOTSTRAP_ADMINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let quic_bind_addr = std::env::var("ACTION_RUNNER_QUIC_BIND").ok();
        let quic_alt_svc_port = std::env::var("ACTION_RUNNER_QUIC_ALT_SVC_PORT")
            .ok()
            .and_then(|s| s.parse().ok());
        let quic_alt_svc_max_age = std::env::var("ACTION_RUNNER_QUIC_ALT_SVC_MAX_AGE")
            .ok()
            .and_then(|s| s.parse().ok());
        let tls_cert_path = std::env::var("ACTION_RUNNER_TLS_CERT")
            .ok()
            .map(PathBuf::from);
        let tls_key_path = std::env::var("ACTION_RUNNER_TLS_KEY")
            .ok()
            .map(PathBuf::from);
        let tls_ca_path = std::env::var("ACTION_RUNNER_TLS_CA")
            .ok()
            .map(PathBuf::from);

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
            max_concurrent_jobs,
            github_token,
            node_id,
            ha_role,
            lease_ttl_seconds,
            standby_sync_seconds,
            proxy_secret,
            invite_signing_key,
            bootstrap_admins,
            quic_bind_addr,
            quic_alt_svc_port,
            quic_alt_svc_max_age,
            tls_cert_path,
            tls_key_path,
            tls_ca_path,
            webauthn_rp_id: std::env::var("ACTION_RUNNER_WEBAUTHN_RP_ID")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "localhost".to_string()),
            webauthn_rp_name: std::env::var("ACTION_RUNNER_WEBAUTHN_RP_NAME")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "MuConsole Platform".to_string()),
            webauthn_rp_origin: std::env::var("ACTION_RUNNER_WEBAUTHN_ORIGIN")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "http://localhost".to_string()),
            host_elevation_secret: Self::resolve_secret_with_file_var(
                "ACTION_RUNNER_HOST_ELEVATION_SECRET",
                "ACTION_RUNNER_HOST_ELEVATION_SECRET_FILE",
            ),
            auth_state_file: std::env::var("ACTION_RUNNER_AUTH_STATE_FILE")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
        }
    }

    /// Returns the HMAC secret used to sign `__Host-mu_elevated` session cookies.
    /// Prefers `ACTION_RUNNER_HOST_ELEVATION_SECRET`, falls back to `invite_signing_key`,
    /// or generates an ephemeral per-process secret if neither is configured.
    #[must_use]
    pub fn elevation_signing_key(&self) -> String {
        static EPHEMERAL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        if let Some(ref s) = self.host_elevation_secret {
            return format!("elev:{s}");
        }
        if let Some(ref s) = self.invite_signing_key {
            return format!("elev:{s}");
        }
        EPHEMERAL
            .get_or_init(|| format!("ephemeral:{}", uuid::Uuid::new_v4()))
            .clone()
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

    pub fn resolve_secret(env_var: &str) -> Option<String> {
        let val = std::env::var(env_var).ok()?;
        Self::resolve_secret_value(&val)
    }

    pub fn resolve_secret_with_file_var(env_var: &str, file_env_var: &str) -> Option<String> {
        if let Ok(file_val) = std::env::var(file_env_var) {
            let trimmed = file_val.trim();
            if !trimmed.is_empty() {
                return Self::resolve_secret_file(trimmed);
            }
        }
        Self::resolve_secret(env_var)
    }

    pub fn resolve_secret_file(path_str: &str) -> Option<String> {
        let trimmed = path_str.trim();
        if trimmed.is_empty() {
            return None;
        }
        let path = Path::new(trimmed);
        if !path.is_file() {
            warn!(
                "Secret file '{}' does not exist or is not a readable file; failing closed",
                path.display()
            );
            return None;
        }
        match std::fs::read_to_string(path) {
            Ok(content) => {
                let secret = content.trim().to_string();
                if secret.is_empty() {
                    warn!("Secret file at {} is empty; failing closed", path.display());
                    None
                } else {
                    info!("Loaded secret from {}", path.display());
                    Some(secret)
                }
            }
            Err(err) => {
                warn!("Failed to read secret file at {}: {}", path.display(), err);
                None
            }
        }
    }

    pub fn resolve_secret_value(val: &str) -> Option<String> {
        let val = val.trim();
        if val.is_empty() {
            return None;
        }

        let is_path = val.starts_with('/')
            || val.starts_with("./")
            || val.starts_with("../")
            || val.contains('/')
            || val.contains('\\');

        let path = Path::new(val);
        if path.is_file() {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    let secret = content.trim().to_string();
                    if secret.is_empty() {
                        warn!("Secret file at {} is empty", path.display());
                        None
                    } else {
                        info!("Loaded secret from {}", path.display());
                        Some(secret)
                    }
                }
                Err(err) => {
                    warn!("Failed to read secret file at {}: {}", path.display(), err);
                    None
                }
            }
        } else if is_path {
            warn!(
                "Secret path '{}' does not exist or is not a readable file; failing closed",
                val
            );
            None
        } else {
            Some(val.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_secret_value_literal() {
        let literal = "ghp_super_secret_token_12345";
        assert_eq!(
            Config::resolve_secret_value(literal),
            Some(literal.to_string())
        );
    }

    #[test]
    fn test_resolve_secret_value_from_valid_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("secret.key");
        std::fs::write(&file_path, "  my-secret-from-disk \n\t").unwrap();

        assert_eq!(
            Config::resolve_secret_value(file_path.to_str().unwrap()),
            Some("my-secret-from-disk".to_string())
        );
    }

    #[test]
    fn test_resolve_secret_value_missing_path_fail_closed() {
        // Absolute path missing
        assert_eq!(
            Config::resolve_secret_value("/nonexistent/secrets/webhook.key"),
            None,
            "Missing absolute secret file must fail closed to None, never returning path string"
        );

        // Relative path missing
        assert_eq!(
            Config::resolve_secret_value("./missing_secret.txt"),
            None,
            "Missing relative secret file must fail closed to None"
        );
    }

    #[test]
    fn test_resolve_secret_value_empty_file_fail_closed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("empty.key");
        std::fs::write(&file_path, "   \n\t").unwrap();

        assert_eq!(
            Config::resolve_secret_value(file_path.to_str().unwrap()),
            None,
            "Empty secret file must fail closed to None"
        );
    }

    #[test]
    fn test_resolve_secret_env_var_fail_closed() {
        let var_name = "TEST_CONTROLLER_SECRET_FAIL_CLOSED_VAR";
        std::env::set_var(var_name, "/nonexistent/path/to/token.secret");
        assert_eq!(
            Config::resolve_secret(var_name),
            None,
            "Environment variable pointing to nonexistent path must fail closed"
        );
        std::env::remove_var(var_name);
    }

    #[test]
    fn test_ha_role_config_parse_and_defaults() {
        assert_eq!(HaRoleConfig::parse("auto"), HaRoleConfig::Auto);
        assert_eq!(HaRoleConfig::parse("AUTO"), HaRoleConfig::Auto);
        assert_eq!(HaRoleConfig::parse("standby"), HaRoleConfig::Standby);
        assert_eq!(HaRoleConfig::parse("follower"), HaRoleConfig::Standby);
        assert_eq!(HaRoleConfig::parse("backup"), HaRoleConfig::Standby);
        assert_eq!(HaRoleConfig::parse("leader"), HaRoleConfig::Leader);
        assert_eq!(HaRoleConfig::parse("unknown"), HaRoleConfig::Leader);

        assert_eq!(HaRoleConfig::Auto.as_str(), "auto");
        assert_eq!(HaRoleConfig::Leader.as_str(), "leader");
        assert_eq!(HaRoleConfig::Standby.as_str(), "standby");

        assert!(HaRole::Leader.is_leader());
        assert!(!HaRole::Standby.is_leader());
        assert_eq!(HaRole::Leader.as_str(), "leader");
        assert_eq!(HaRole::Standby.as_str(), "standby");

        let default_cfg = Config::default();
        assert_eq!(default_cfg.node_id, "node-a");
        assert_eq!(default_cfg.ha_role, HaRoleConfig::Leader);
        assert_eq!(default_cfg.lease_ttl_seconds, 15);
        assert_eq!(default_cfg.standby_sync_seconds, 5);
        assert_eq!(default_cfg.proxy_secret, None);
        assert_eq!(default_cfg.invite_signing_key, None);
        assert!(default_cfg.bootstrap_admins.is_empty());
    }

    #[test]
    fn test_resolve_secret_with_file_var_and_fail_closed() {
        let temp_dir = tempfile::tempdir().unwrap();
        let valid_file = temp_dir.path().join("proxy.secret");
        std::fs::write(&valid_file, "  proxy-secret-from-file \n").unwrap();

        let env_lit = "TEST_PROXY_SECRET_LIT_92";
        let env_file = "TEST_PROXY_SECRET_FILE_92";

        std::env::set_var(env_file, valid_file.to_str().unwrap());
        assert_eq!(
            Config::resolve_secret_with_file_var(env_lit, env_file),
            Some("proxy-secret-from-file".to_string())
        );

        // Missing file in *_FILE must fail closed to None even if literal var is set
        std::env::set_var(env_lit, "fallback-literal");
        std::env::set_var(env_file, "/nonexistent/proxy.secret");
        assert_eq!(
            Config::resolve_secret_with_file_var(env_lit, env_file),
            None
        );

        // When *_FILE is unset, falls back to env_lit
        std::env::remove_var(env_file);
        assert_eq!(
            Config::resolve_secret_with_file_var(env_lit, env_file),
            Some("fallback-literal".to_string())
        );
        std::env::remove_var(env_lit);
    }
}
