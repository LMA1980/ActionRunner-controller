//! Minimal `.gitmodules` parser and submodule URL resolver.
//!
//! Only the keys the console needs (`path`, `url`) are interpreted. Unknown keys,
//! comments (`#`, `;`) and non-`submodule` sections are ignored.

use crate::config::is_safe_repo_name;

/// One `[submodule "<name>"]` section of a `.gitmodules` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitmoduleEntry {
    pub name: String,
    pub path: String,
    pub url: String,
}

/// Parses a `.gitmodules` file, keeping declaration order.
///
/// Sections without both `path` and `url` are dropped.
#[must_use]
pub fn parse_gitmodules(content: &str) -> Vec<GitmoduleEntry> {
    let mut out = Vec::new();
    let mut current: Option<(String, Option<String>, Option<String>)> = None;

    let flush = |cur: Option<(String, Option<String>, Option<String>)>,
                 out: &mut Vec<GitmoduleEntry>| {
        if let Some((name, Some(path), Some(url))) = cur {
            if !path.is_empty() && !url.is_empty() {
                out.push(GitmoduleEntry { name, path, url });
            }
        }
    };

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            flush(current.take(), &mut out);
            let inner = line[1..line.len() - 1].trim();
            if let Some(rest) = inner.strip_prefix("submodule") {
                let name = rest.trim().trim_matches('"').to_string();
                current = Some((name, None, None));
            }
            continue;
        }
        let Some(cur) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_matches('"').to_string();
        match key.as_str() {
            "path" => cur.1 = Some(value.trim_end_matches('/').to_string()),
            "url" => cur.2 = Some(value),
            _ => {}
        }
    }
    flush(current.take(), &mut out);
    out
}

/// Resolves a submodule URL to an `(owner, repo)` pair.
///
/// Supports `https://`, `http://`, `ssh://`, `git://`, scp-style (`git@host:owner/repo.git`)
/// and relative URLs (`../repo.git`, resolved against the parent `owner/repo`). Returns
/// `None` when the URL cannot be mapped to a safe `owner/repo` name.
#[must_use]
pub fn resolve_submodule_repo(
    url: &str,
    parent_owner: &str,
    parent_repo: &str,
) -> Option<(String, String)> {
    let url = url.trim();
    let segments: Vec<String> = if url.starts_with("./") || url.starts_with("../") {
        let mut base = vec![parent_owner.to_string(), parent_repo.to_string()];
        for seg in url.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    base.pop();
                }
                other => base.push(other.to_string()),
            }
        }
        base
    } else if let Some((_, rest)) = url.split_once("://") {
        // Drop the authority (`user@host:port`).
        let path = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
        path.split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    } else if let Some((_, path)) = url.split_once(':') {
        // scp-like syntax: `git@github.com:owner/repo.git`
        path.split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    } else {
        return None;
    };

    if segments.len() < 2 {
        return None;
    }
    let owner = segments[segments.len() - 2].clone();
    let repo = segments[segments.len() - 1]
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .to_string();
    if is_safe_repo_name(&format!("{owner}/{repo}")) {
        Some((owner, repo))
    } else {
        None
    }
}

/// Parses `git ls-tree <rev> -- <path>` output and returns the gitlink SHA, if the
/// entry is a submodule (`160000 commit <sha>\t<path>`).
#[must_use]
pub fn parse_ls_tree_gitlink(output: &str) -> Option<String> {
    for line in output.lines() {
        let (meta, _path) = line.split_once('\t')?;
        let mut parts = meta.split_whitespace();
        let mode = parts.next()?;
        let kind = parts.next()?;
        let sha = parts.next()?;
        if mode == "160000" && kind == "commit" && sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(sha.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sections_in_order_and_ignores_noise() {
        let content = r#"
# comment
[core]
    bare = false
[submodule "code/core"]
	path = code/core
	url = https://github.com/LMA1980/k3-core.git
	branch = main
; another comment
[submodule "code/engine"]
	path = code/engine/
	url = ../k3-engine.git
[submodule "broken"]
	path = nowhere
"#;
        let entries = parse_gitmodules(content);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "code/core");
        assert_eq!(entries[0].path, "code/core");
        assert_eq!(entries[0].url, "https://github.com/LMA1980/k3-core.git");
        assert_eq!(entries[1].path, "code/engine");
    }

    #[test]
    fn resolves_url_shapes() {
        let p = ("LMA1980", "parent");
        let cases = [
            (
                "https://github.com/LMA1980/k3-core.git",
                ("LMA1980", "k3-core"),
            ),
            ("https://github.com/LMA1980/k3-core", ("LMA1980", "k3-core")),
            ("git@github.com:Other/thing.git", ("Other", "thing")),
            ("ssh://git@github.com/Other/thing.git", ("Other", "thing")),
            ("../sibling.git", ("LMA1980", "sibling")),
            ("../../Elsewhere/lib.git", ("Elsewhere", "lib")),
        ];
        for (url, (o, r)) in cases {
            assert_eq!(
                resolve_submodule_repo(url, p.0, p.1),
                Some((o.to_string(), r.to_string())),
                "url {url}"
            );
        }
        assert_eq!(resolve_submodule_repo("not a url", p.0, p.1), None);
        assert_eq!(
            resolve_submodule_repo("https://github.com/LMA1980/../x", p.0, p.1),
            None
        );
    }

    #[test]
    fn parses_gitlink_from_ls_tree() {
        let out = "160000 commit 0123456789abcdef0123456789abcdef01234567\tcode/core\n";
        assert_eq!(
            parse_ls_tree_gitlink(out).as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(
            parse_ls_tree_gitlink("100644 blob abcdef\tREADME.md\n"),
            None
        );
    }
}
