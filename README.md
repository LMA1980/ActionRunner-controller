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

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See LICENSE for details.
