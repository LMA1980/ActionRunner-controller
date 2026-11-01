//! Read-only GitHub REST client used to resolve repository metadata, `.gitmodules`,
//! gitlink SHAs and the `.actionrunner` workflow on the default branch.
//!
//! The base URL is configurable so tests can point it at a local mock server.

use serde::Deserialize;
use std::time::Duration;

/// Errors that distinguish "definitely absent" (`NotFound`) from transport or
/// server failures, so callers can fall back to the local clone only when GitHub
/// could not answer.
#[derive(Debug, thiserror::Error)]
pub enum GitHubError {
    #[error("not found")]
    NotFound,
    #[error("GitHub API error: {0}")]
    Api(String),
}

/// Repository metadata subset returned by `GET /repos/{owner}/{repo}`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RepoMetadata {
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default)]
    pub default_branch: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ContentEntry {
    #[serde(rename = "type")]
    kind: String,
    sha: String,
}

#[derive(Clone)]
pub struct GitHubClient {
    base_url: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl GitHubClient {
    /// Builds a client. `token` is optional: public repositories resolve anonymously.
    pub fn new(base_url: &str, token: Option<String>) -> Result<Self, GitHubError> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| GitHubError::Api(e.to_string()))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.filter(|t| !t.trim().is_empty()),
            http,
        })
    }

    fn request(&self, url: &str, accept: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .http
            .get(url)
            .header("Accept", accept)
            .header("User-Agent", "ActionRunner-Controller/0.1.0")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(ref t) = self.token {
            req = req.header("Authorization", format!("Bearer {}", t.trim()));
        }
        req
    }

    async fn send(&self, url: &str, accept: &str) -> Result<reqwest::Response, GitHubError> {
        let resp = self
            .request(url, accept)
            .send()
            .await
            .map_err(|e| GitHubError::Api(e.to_string()))?;
        match resp.status() {
            s if s.is_success() => Ok(resp),
            reqwest::StatusCode::NOT_FOUND => Err(GitHubError::NotFound),
            s => Err(GitHubError::Api(format!("HTTP {s} for {url}"))),
        }
    }

    /// `GET /repos/{owner}/{repo}`. Private repositories that the token cannot see
    /// return [`GitHubError::NotFound`].
    pub async fn get_repo(&self, owner: &str, repo: &str) -> Result<RepoMetadata, GitHubError> {
        let url = format!("{}/repos/{}/{}", self.base_url, owner, repo);
        self.send(&url, "application/vnd.github+json")
            .await?
            .json::<RepoMetadata>()
            .await
            .map_err(|e| GitHubError::Api(e.to_string()))
    }

    /// Raw contents of `path` at `git_ref`.
    pub async fn get_file(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        git_ref: &str,
    ) -> Result<String, GitHubError> {
        let url = format!(
            "{}/repos/{}/{}/contents/{}?ref={}",
            self.base_url, owner, repo, path, git_ref
        );
        self.send(&url, "application/vnd.github.raw+json")
            .await?
            .text()
            .await
            .map_err(|e| GitHubError::Api(e.to_string()))
    }

    /// Gitlink SHA of the submodule at `path` on `git_ref`.
    pub async fn get_gitlink_sha(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        git_ref: &str,
    ) -> Result<String, GitHubError> {
        let url = format!(
            "{}/repos/{}/{}/contents/{}?ref={}",
            self.base_url, owner, repo, path, git_ref
        );
        let entry = self
            .send(&url, "application/vnd.github+json")
            .await?
            .json::<ContentEntry>()
            .await
            .map_err(|e| GitHubError::Api(e.to_string()))?;
        if entry.kind == "submodule" && entry.sha.chars().all(|c| c.is_ascii_hexdigit()) {
            Ok(entry.sha)
        } else {
            Err(GitHubError::NotFound)
        }
    }
}
