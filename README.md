# ActionRunner-controller

<p align="center">
  <img src="https://hook.lma1980.duckdns.org/badges/LMA1980/ActionRunner-controller/status.svg" alt="Status"/>
  <img src="https://hook.lma1980.duckdns.org/badges/LMA1980/ActionRunner-controller/score.svg" alt="Score"/>
</p>

WebAPI, Ingress Gateway, DAG Stage Scheduler, and SVG Scorecard Controller for the Distributed **ActionRunner** Platform.

## Architecture

- **Ingress & Authentication**: GitHub webhook receiver (`POST /webhook`) with constant-time HMAC-SHA256 payload verification and anti-RCE fork PR validation.
- **Coalescing FIFO Queue**: Serializes builds, persists queue state to `jobs_index.json`, and automatically supersedes older queued commits when newer pushes arrive for the same `(repository, ref, event)`.
- **DAG Stage Scheduler**: Evaluates stage dependencies (`depends_on`), matches required stage tags against worker node tags, and dispatches parallel tasks to available worker slots.
- **Zero-Copy IPC Cluster Tunnel**: Coordinates with distributed workers via WebSocket (`/api/cluster/tunnel`) using **`zerocopy`** framing, **`Apache Fory`** control message contracts, and **`Apache Arrow`** columnar log and metric streaming.
- **Factory Pipeline Quality Scoring**: Computes letter grade (`A+` to `F`), pass ratios, coverage summaries, advisories, and micro-benchmarks across submodules.
- **Vectorized SVG Badges & Cards**: Serves dynamic SVG badges and multi-metric scorecard cards (`/cards/*`, `/badges/*`).

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0-only). See LICENSE for details.
