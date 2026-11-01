# Console API (read-only)

Read-only endpoints and SSE kinds that feed the MuConsole data worker. All of them are
additive: existing endpoints and the existing `/api/events` kinds (`queue`, `jobs`,
`cluster`) are unchanged.

This document is the JSON contract for these endpoints. Field names are `snake_case`,
enums are lower-case strings, and optional values are `null` rather than omitted.

## Authentication and visibility

- Public repositories are readable anonymously.
- Private, internal and **not yet classified** repositories are only returned when the
  request presents the controller API key, either as `Authorization: Bearer <key>` or as
  `X-Api-Key: <key>`. The key is the existing `ACTION_RUNNER_LOG_API_KEY` setting, which
  takes a literal value or a path to a file. If the path can't be read, the key resolves to
  unset; it never falls back to the path string.
- With no key configured, no request is authenticated, so private repositories are never
  returned (fail closed).
- An anonymous request for a private repository gets the same `404` as an unknown
  repository, never a `403`.
- Visibility comes from webhook payloads (`repository.private` / `repository.visibility`)
  and from `GET /repos/{owner}/{repo}` on the GitHub API. A repository known only from job
  history stays hidden from anonymous callers until GitHub confirms it is public.
- Responses carry `Cache-Control: no-cache, no-store, must-revalidate` and
  `Vary: Authorization, X-Api-Key`.

## `GET /api/repos`

```json
{
  "fabric_rev": 482,
  "authenticated": false,
  "repos": [
    {
      "owner": "LMA1980",
      "repo": "parent",
      "visibility": "public",
      "default_branch": "main",
      "latest_job_id": "job-1793563200-44444444",
      "score": 92,
      "coverage": 87.5,
      "bench_delta": 10.0,
      "status": "passing",
      "submodules": [
        { "path": "code/core", "owner": "LMA1980", "repo": "child", "pinned_sha": "aaaaaaaa…" }
      ],
      "parents": []
    },
    {
      "owner": "LMA1980",
      "repo": "child",
      "visibility": "public",
      "default_branch": "main",
      "latest_job_id": null,
      "score": null,
      "coverage": null,
      "bench_delta": null,
      "status": "unknown",
      "submodules": [],
      "parents": [{ "owner": "LMA1980", "repo": "parent", "path": "code/core" }]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `visibility` | `public` \| `private` \| `internal` \| `null` (not yet known; only authenticated callers see these) |
| `latest_job_id` | Newest active-or-completed job on the default branch |
| `score` | Quality score `0..=100` of the latest completed default-branch job |
| `coverage` | Line coverage in percent |
| `bench_delta` | Benchmark time change vs. the previous completed default-branch job, in percent (positive = slower) |
| `status` | `unknown` \| `passing` \| `running` \| `failing` (a queued job counts as `running`) |
| `submodules[]` | From `.gitmodules` on the default branch. `pinned_sha` is the gitlink commit (or `null` if it couldn't be resolved) |
| `parents[]` | Superprojects whose `.gitmodules` reference this repo. Private parents are only listed for authenticated callers |

The list includes every repository the controller knows: from webhooks, the job history
snapshots and in-memory jobs.

### Submodule resolution and caching

- `.gitmodules` and the gitlink SHAs are read from the default branch through the GitHub
  contents API (`GITHUB_TOKEN` if set, anonymous otherwise). If the API can't answer, the
  controller falls back to its CI clone at `<workspace>/repos/<owner>/<repo>`.
- Results are cached in `<workspace>/logs/console_registry.json`.
- A refresh runs:
  - on a `push` to the default branch whose commits touch `.gitmodules`, `.actionrunner/*`
    or a known submodule path (a gitlink bump), or whose commit list is truncated;
  - when a repo is first seen;
  - when the cached metadata is older than `ACTION_RUNNER_CONSOLE_METADATA_TTL_SECS`
    (default 6 h).
- Submodule URLs can be `https`, `ssh`, scp-style or relative (`../repo.git`).

## `GET /api/repos/{owner}/{repo}/summary[?branch=<ref>]`

The CI half of the scorecard. `branch` defaults to the default branch.

```json
{
  "owner": "LMA1980",
  "repo": "parent",
  "visibility": "public",
  "default_branch": "main",
  "branch": "main",
  "status": "passing",
  "latest_job_id": "job-1793563200-44444444",
  "latest_completed_job_id": "job-1793563200-44444444",
  "commit_sha": "4444444444444444444444444444444444444444",
  "score": 92,
  "letter_grade": "A",
  "coverage": 87.5,
  "coverage_bp": 8750,
  "bench_summary": "1 benches (11.0 µs/iter)",
  "bench_delta": 10.0,
  "tests_passed": 10,
  "tests_total": 10,
  "clippy_warnings": 0,
  "advisories_count": 0,
  "updated_at": "2026-11-01T20:00:00Z",
  "history": [
    { "job_id": "job-…-33333333", "commit_sha": "3333…", "status": "passed", "score": 88, "coverage": 80.0, "updated_at": "…" },
    { "job_id": "job-…-44444444", "commit_sha": "4444…", "status": "passed", "score": 92, "coverage": 87.5, "updated_at": "…" }
  ],
  "submodules": [
    { "path": "code/core", "owner": "LMA1980", "repo": "child", "pinned_sha": "aaaa…", "score": 95, "letter_grade": "A+", "coverage": 91.2 }
  ]
}
```

- `history` lists up to 20 completed jobs on `branch`, oldest first (for the sparkline).
- `coverage_bp` is coverage in basis points (`0..=10_000`).
- Returns `404` for an unknown repository, and for a private repository when the request is anonymous.

## `GET /api/repos/{owner}/{repo}/topology`

The `RepoTopology` consumed by Trainway.

```json
{
  "owner": "LMA1980",
  "repo": "railway",
  "default_branch": "main",
  "fabric_rev": 482,
  "stations_source": "workflow",
  "stations": [
    { "id": "fmt", "name": "FMT", "depends_on": [] },
    { "id": "clippy", "name": "CLIPPY", "depends_on": ["fmt"] },
    { "id": "test", "name": "TEST", "depends_on": ["clippy"] }
  ],
  "branches": [
    {
      "ref": "feat/rail",
      "base_ref": "main",
      "fork_stage": "clippy",
      "pr_state": "open",
      "pr_number": 7,
      "head_sha": "7777…",
      "last_job": { "job_id": "job-…-77777777", "status": "running", "commit_sha": "7777…", "stage": "clippy" }
    }
  ],
  "trains": [
    {
      "job_id": "job-…-77777777",
      "ref": "feat/rail",
      "status": "running",
      "commit_sha": "7777…",
      "stage": "clippy",
      "node_id": "node-a",
      "stage_states": [
        { "station": "fmt", "state": "passed", "node_id": null },
        { "station": "clippy", "state": "running", "node_id": "node-a" },
        { "station": "test", "state": "pending", "node_id": null }
      ]
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `stations_source` | `workflow` (`.actionrunner/ActionRunner.yml` on the default branch) → `job` (stage list of the repo's latest job) → `default` (controller default pipeline: `fmt-check`, `clippy-check`, `native-k3`) |
| `branches[]` | `feat/**` branches plus branches with an open or draft PR. `feat/**` refs with a live job are included even without a webhook record. Deleted refs are excluded |
| `base_ref` | The default branch for `create`/`push`, or the PR base for pull requests |
| `fork_stage` | Station the main line's latest train was at when the branch was first seen (`null` if unknown) |
| `pr_state` | `none` \| `open` \| `draft` \| `merged` \| `closed`. Fork PR branches are keyed `owner:ref` |
| `trains[]` | Every queued or running job, plus the latest job on the main line and on each listed branch |
| `trains[].stage` | Current station: the first running stage, else the first failed one, else the first pending one, else the last stage |
| `stage_states[].state` | `pending` \| `running` \| `passed` \| `failed` \| `skipped` |
| `status` (job) | `queued` \| `running` \| `passed` \| `failed` \| `skipped` |
| `fabric_rev` | Global `u64` counter, bumped on every topology change: branch create/delete, PR state, stage change, node membership, or a submodule/station graph change. It is persisted, so it stays monotonic across restarts |

## SSE: additive kinds on `/api/events`

Each frame is `event: <kind>` followed by `data: <json>`. Every payload carries the
`fabric_rev` the change produced.

| Kind | Payload |
|---|---|
| `branch_created` | `{owner, repo, ref, base_ref, fork_stage, head_sha, fabric_rev}` |
| `branch_deleted` | `{owner, repo, ref, merged, fabric_rev}` |
| `pr_state_changed` | `{owner, repo, ref, pr_number, pr_state, previous_state, base_ref, fabric_rev}` |
| `job_stage_changed` | `{owner, repo, job_id, ref, stage, state, previous_state, node_id, fabric_rev}` |
| `node_membership_changed` | `{node_id, change: joined\|left\|online\|offline, online_nodes[], fabric_rev}` |

- `branch_created` and `branch_deleted` are emitted for `feat/**` branches and for branches
  that have a PR.
- `job_stage_changed` and `node_membership_changed` come from a reconciler that diffs job
  stages and cluster membership. It runs on job-store notifications, with a 1 s fallback tick.
- Events about private or unclassified repositories are only delivered to authenticated
  streams.
- Authentication on `/api/events` itself is unchanged: when `ACTION_RUNNER_LOG_API_KEY` is
  set, the stream requires the key (`Authorization`, `X-Api-Key`, or `?token=` / `?api_key=`
  for `EventSource`). Node events are not repo-scoped and go to every subscriber.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `ACTION_RUNNER_LOG_API_KEY` | unset | API key that authenticates private-repo access (literal or file path, fail closed) |
| `GITHUB_TOKEN` | unset | Reused for read-only metadata, `.gitmodules` and workflow lookups |
| `ACTION_RUNNER_GITHUB_API_URL` | `https://api.github.com` | GitHub REST base URL. `off` disables API lookups (local-clone fallback only) |
| `ACTION_RUNNER_CONSOLE_METADATA_TTL_SECS` | `21600` | Freshness window for cached metadata and submodules |
