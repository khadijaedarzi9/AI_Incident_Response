# Verification proof index

Captured on 2026-09-13 for the BCP-1 reference implementation.

- `install.txt` — pinned editable installation with test extras.
- `schema-export.txt` — regenerated protocol and typed event-payload schemas.
- `pytest-coverage.txt` — full configured test suite: 32 passed, 80% combined
  statement/branch coverage.
- `judge-scenarios.txt` — allowed, unauthorized-egress, canary, and unsafe
  second-hop scenarios: four passed.
- `ablation-benchmark.txt` — five weaker architectures failed their designated
  metric; full BCP-1 failed zero.
- `auditability-gap.txt` — access logs verify 0/5 containment claims,
  signed-line logs 1/5, and BCP-1 5/5 with 12,500× fewer records.
- `demo-generation.txt` — signed canary-kill scenario summary: zero forbidden
  requests forwarded and four canonical events.
- `offline-audit.txt` — independent streaming verification result:
  `"valid": true`.
- `docker-boundary-smoke.txt` — unprivileged container probe showing
  `"raw_public_socket_blocked": true` and
  `"gateway_dispatch_succeeded": true`.
- `network-ablation.txt` — the public socket succeeds on the open bridge and
  fails on the internal network; approved gateway dispatch succeeds on both.
- `environment.json` — interpreter and container runtime versions.
- `final-gate-summary.json` — machine-readable ship-gate result.
- `checksums.json` — SHA-256 digests for the proof logs and signed demo bundle.

These logs support reproducibility; they do not replace the signed evidence
bundle or prove microVM-grade production conformance. The Docker test covers
only the explicitly stated container-network scope.

An initial 13 September attempt encountered a transient Docker Hub DNS failure.
After name resolution recovered, `python:3.12.5-slim` was pulled from Docker
Hub and both proof logs above were regenerated from the clean pinned base.
