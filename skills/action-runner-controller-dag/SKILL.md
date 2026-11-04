---
name: action-runner-controller-dag
description: "Develop and maintain the ActionRunner-controller webhook ingress, DAG stage scheduler, secret resolution, and 3-phase workflow configuration parser."
---

# `action-runner-controller` Ingress, DAG Scheduler & Security Invariants

## 1. Secret Path vs. Literal Value Resolution

- Environment variables accepting either a file path or a literal secret (such as `GITHUB_WEBHOOK_SECRET`) **must** read and trim the file when given a path, and fail closed (`None`) if the path cannot be read—never fall back to using the file path string itself as the secret token.

## 2. Three-Phase Configuration Migration

- When evolving workflow configuration schemas (`.actionrunner/ActionRunner.yml` and `.actionrunner/security.yml`), enforce a strict 3-phase transition:
  1. Side-by-side introduction with backward-compatible fallback.
  2. Production deployment and verification of the updated controller/worker.
  3. Post-deployment removal of legacy configuration files and fallback code.
