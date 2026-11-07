# ActionRunner-controller

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/ActionRunner-controller/card.svg" alt="ActionRunner-controller Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/ActionRunner-controller/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/ActionRunner-controller/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/ActionRunner-controller/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/ActionRunner-controller/benchmark.svg" alt="Benchmark"/></a>
</p>

---

WebAPI, Ingress Gateway, DAG Stage Scheduler, and SVG Scorecard Controller for the Distributed **ActionRunner** Platform.

## Architecture

- **Ingress & Authentication**: GitHub webhook receiver (`POST /webhook`) with constant-time HMAC-SHA256 payload verification and anti-RCE fork PR validation.
- **Coalescing FIFO Queue & Persistent DuckDB Store**: Serializes builds, persists full execution history (`jobs_history`) and pinned latest `(repository, branch, submodule)` snapshots (`branch_snapshots`, `submodule_snapshots`) into DuckDB (`logs/jobs.duckdb`), and automatically backfills evicted historical runs from on-disk `job-*.log` artifacts on startup.
- **DAG Stage Scheduler & Concurrency Invariants**: Evaluates stage dependencies (`depends_on`), matches required stage tags and toolchains against worker node capabilities, enforces per-job in-flight deduplication (`InFlightJobGuard`) and `JobStatus::Running` stage invariants, reserves pending worker slots during claim before `git fetch` (`sync_and_try_reserve_for_claim`), respects `exclusive: true` ("Drain Before Dispatch"), and preserves priority during yield-and-requeue ("food sample" execution) and HA leader rehydration (`should_preserve_local_record`).
- **Zero-Copy IPC Cluster Tunnel**: Coordinates with distributed workers via WebSocket (`/api/cluster/tunnel`) using **`zerocopy`** framing, **`Apache Fory`** control message contracts, and **`Apache Arrow`** columnar log and metric streaming.
- **Factory Pipeline Quality Scoring**: Computes letter grade (`A+` to `F`), pass ratios, coverage summaries, advisories, and micro-benchmarks across submodules.
- **Vectorized SVG Badges & Cards**: Serves dynamic SVG badges (`/badges/*`, pinned to the last completed `Success`/`Failed` build) and live multi-metric scorecard cards (`/cards/*`, showing live `queued`/`running`/`passing`/`failing` status while retaining and attributing the previous completed execution's score and metrics during active builds).

- **Read-only Console API**: `GET /api/repos` (with the `.gitmodules` submodule/parent graph), `GET /api/repos/{owner}/{repo}/summary`, `GET /api/repos/{owner}/{repo}/topology` (branches, stations, trains, `fabric_rev`), and additive SSE kinds on `/api/events` for MuConsole. Private repositories are only served to requests that present the API key. See [docs/console-api.md](docs/console-api.md).

## Declarative `sccache` Compiler Cache Configuration (`.actionrunner/ActionRunner.yml`)

`ActionRunner-controller` supports declarative [`sccache`](https://github.com/mozilla/sccache) compiler cache policies at the **workflow**, **stage**, and **task** levels inside `.actionrunner/ActionRunner.yml`.

> **Complete Operator & Workflow Portal Guide**: See [**Operator & Workflow Guide: Distributed `sccache` Compilation Caching**](https://github.com/LMA1980/lma1980.github.io/blob/main/content/docs/sccache-guide.md) for a complete walkthrough of how `sccache` influences build timings (cold Build #1 vs. warm Build #2+), `CARGO_INCREMENTAL=0`, cross-node toolchain alignment, and worker setup.

### 1. Policy Modes (`SccacheMode`) & How They Influence Scheduling & Reliability

| Policy Value | Accepted YAML Literals | Scheduling & Runtime Experience |
| :--- | :--- | :--- |
| **`try`** *(default)* | `try`, `true`, `auto`, `yes`, `1` | **Default when `sccache:` is omitted.** Dispatches to any worker matching the stage's `tags`. Uses `sccache` (`RUSTC_WRAPPER` + `CARGO_INCREMENTAL=0` + `SCCACHE_IDLE_TIMEOUT=0`) on eligible compiler tasks when `sccache` is installed and healthy on the assigned worker; **never breaks your build**—falls back cleanly to uncached `rustc` compilation if `sccache` is not installed or if the S3 backend is temporarily unreachable. |
| **`mandatory`** | `mandatory`, `required`, `strict` | Strictly requires `sccache` for compilation. The DAG scheduler automatically appends `"sccache"` to the stage's required worker capability tags (both during pre-claim slot reservation and `lease_slot`—if no matching online worker advertises `"sccache"`, the stage remains `Queued`), and the worker fails closed (`exit_code = 126`) if `sccache` is missing or fails its pre-flight `--show-stats` health check. |
| **`false`** | `false`, `off`, `disabled`, `no`, `0` | Disables `sccache` and strips `RUSTC_WRAPPER` / `CARGO_BUILD_RUSTC_WRAPPER` from the task environment. |

### 2. Hierarchical Inheritance & Tool Eligibility

- **Resolution Precedence**:
  $$\text{tasks.\<id\>.sccache} \longrightarrow \text{stages}[i]\text{.sccache} \longrightarrow \text{workflow.sccache} \longrightarrow \text{try}$$
- **Eligible Compiler Tools**: `cargo-build`, `cargo-check`, `cargo-test`, `cargo-clippy`, `cargo-bench`, and `trunk`.
- **Excluded Tools**: `cargo-fmt`, `cargo-audit`, `mdformat`, `cargo-llvm-cov`, and `cargo-miri` automatically bypass `sccache` so Miri's wrapper and LLVM coverage instrumentation are never clobbered. When `sccache: mandatory` is set at the workflow root, pure hygiene stages containing only non-compiler tasks (e.g., `cargo-fmt`, `mdformat`, `cargo-audit`) do not force the `"sccache"` worker tag requirement.

### 3. Example `.actionrunner/ActionRunner.yml`

```yaml
version: "3"
name: "Distributed Pipeline with Shared sccache"
sccache: try # Workflow-wide default (try | mandatory | false)

tasks:
  fmt-task:
    tool: "cargo-fmt"
    args: ["--all", "--", "--check"]

  clippy-task:
    tool: "cargo-clippy"
    args: ["--workspace", "--all-targets", "--", "-D", "warnings"]

  release-build-task:
    tool: "cargo-build"
    args: ["--workspace", "--release"]
    sccache: mandatory # Task-level override requiring sccache

  uncached-test-task:
    tool: "cargo-test"
    args: ["--workspace"]
    sccache: false # Task-level override disabling sccache

stages:
  - id: fmt-check
    name: "Verify Formatting"
    tasks: ["fmt-task"]
    tags: ["fmt"]

  - id: clippy-check
    name: "Verify Linter Hygiene"
    tasks: ["clippy-task"]
    depends_on: ["fmt-check"]
    tags: ["clippy"]

  - id: build-release
    name: "Build Release Binaries"
    tasks: ["release-build-task"]
    depends_on: ["clippy-check"]
    tags: ["build"] # Controller automatically appends "sccache" tag due to mandatory task

  - id: test-suite
    name: "Run Uncached Tests"
    tasks: ["uncached-test-task"]
    depends_on: ["build-release"]
    tags: ["test"]
    sccache: false # Stage-level override

on_action:
  push: ["fmt-check", "clippy-check", "build-release", "test-suite"]
  pull_request: ["fmt-check", "clippy-check", "build-release", "test-suite"]
```

For worker-side `sccache` binary installation and `/etc/action-runner/sccache.env` S3/Garage configuration, see the Operator Guide in [`ActionRunner-rs/README.md`](https://github.com/LMA1980/ActionRunner-rs#operator-guide-shared-sccache-compiler-cache-integration).

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See LICENSE for details.
