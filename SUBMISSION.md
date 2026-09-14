# BCP-1: Proof-Carrying Containment for Guardrails-Off Evaluations

## Abstract

The July 2026 incident was not principally an alerting failure or an anomaly
classification failure. It was a failure to make evaluation boundaries
enforceable, escalation automatic and compliance externally verifiable.
Project Ballistic proposes BCP-1, a minimum containment profile for
dangerous-capability evaluations with production safeguards disabled.

BCP-1 requires an operator-signed run contract, OS/hypervisor default-deny
isolation, closed egress execution, brokered per-request credentials,
deterministic kill criteria, a second-hop contract, and independently signed
evidence. A reference implementation demonstrates canonical contracts,
race-resistant single-use dispatch capabilities, bounded overload behavior,
trigger-bound kill acknowledgements and an O(1)-memory offline auditor.

Five incident-grounded control ablations give the standard an empirical result:
each weaker architecture fails its designated metric, while full BCP-1 passes
all five. Alert-only forwards one canary request, a stale permit dispatches once
after kill, a weak provider check admits one unsafe harness, a hash chain
without a witness accepts one conflicting root, and per-drop logging allocates
49,998 post-kill records. The corresponding BCP-1 unsafe count is zero in every
scenario.

A separate auditability-gap study runs the same 50,000-request post-kill burst
through three evidence profiles. Ordinary access logs verify 0/5 defined
containment claims, per-line authenticated logs verify 1/5, and BCP-1 verifies
5/5 for the mediated path. BCP-1 emits four events rather than 50,000 records
and is 732× smaller than the measured access log. Complete observation still
depends on the independently enforced workload boundary.

## Research question

What is the least set of controls and evidence that allows an independent
auditor to determine—without access to a lab network—whether a guardrails-off
evaluation prevented unauthorized external effects and automatically contained
hard violations?

## Answer

A sandbox label and application log are insufficient. Minimum adequacy requires
all of:

1. an OS/hypervisor boundary that makes unmediated egress unreachable;
2. an immutable signed contract defining targets, identities, budgets and kill
   criteria;
3. a lower-layer executor that accepts only one-use, action-bound,
   kill-epoch-bound capabilities;
4. credentials released only to that executor after durable authorization;
5. an independently keyed supervisor with out-of-band isolation authority;
6. canonical evidence whose root, counters and kill acknowledgement are signed
   and externally witnessed;
7. explicit sponsor accountability for every reachable second hop;
8. a tested incident declaration and re-enable gate.

## Why this would have interrupted the incident

The earliest break is the package-service boundary. Per-run read-only package
access prevents mutable cross-run coordination. A closed package API removes
arbitrary fetch and administrative surfaces. If the broker is nevertheless
compromised, independent default-deny networking prevents it from becoming
open internet egress. A public unauthenticated execution harness fails
second-hop preflight. No anomaly score or human page is required for these
decisions.

## Implemented

- strict canonical JSON profile with duplicate-key, float, unsafe-integer,
  Unicode and size rejection;
- operator-signed manifest with distinct pinned gateway, supervisor and witness
  keys;
- exact origin, path, method, resolved-IP, SPKI, byte and request constraints;
- gateway-signed decision bound to request event, action digest and manifest;
- short-lived, `max_uses=1`, kill-epoch-bound dispatch capability;
- bounded dispatch admission and evidence commit without holding the state lock
  over broker or transport I/O;
- worst-case egress reservation, inflight cancellation signalling, runtime
  watchdog, and bounded evidence-commit admission;
- credential references in agent-visible structures and executor-only secret
  release;
- bounded pre-parse admission and constant evidence growth after overload kill;
- authenticated control-plane completion and terminal-only frozen receipts;
- truthful `SIMULATED` kill acknowledgement with no false network-isolation
  claim;
- provider-signed, run-bound second-hop assertions with evidence digests;
- one-root-per-run reference witness;
- streaming semantic verification of request, decision, dispatch,
  result/cancellation, authorization, counters, trigger, and latency;
- five control ablations, four judge-facing scenarios, and adversarial contract
  and evidence tests.

## Specified but not falsely claimed as implemented

- microVM/hypervisor isolation and raw-socket enforcement;
- atomic capability consumption coupled to kernel network send;
- HSM/TPM/TEE key protection and measured software identity;
- independently operated public transparency log;
- production IAM and credential revocation;
- payload-level information-flow and data-loss prevention.

The included container network smoke test is not represented as equivalent to
microVM conformance.

## Verification artifact

The demo exports four files: signed manifest, canonical event JSONL, signed
receipt and trusted operator public key. The auditor requires no internal
network connectivity. It detects event modification, truncation, reorder,
counter mismatch, signature substitution, stale capability use and witness
root conflict.

## Framework mapping

BCP-1 operationalizes CSA AICM v1.1 AIS-13 sandbox isolation and audit
requirements; CoSAI v1.0 telemetry, RACI, containment, forensics and recovery;
and NIST SP 800-61r3 governance, adverse-event declaration, incident
management, evidence provenance, third-party communication and mitigation.
Exact mappings appear in `STANDARD.md`.

## Principal limitation

Cryptographic evidence proves consistency and signer authorization, not
complete observation. Only an independently enforced workload boundary can
make unobserved external actions impossible. This limitation is part of the
standard rather than hidden in implementation notes.

## Limitations and Dual-Use Considerations

### Limitations

- The reference implementation validates protocol and evidence properties; it
  does not attest microVM isolation, kernel-level dispatch atomicity, HSM-backed
  keys, production IAM, or an independently operated transparency service.
- The Docker demonstration tests an internal container network only. It is not
  evidence of hardware-backed isolation and does not cover UDP/QUIC, metadata,
  sidecar, inherited-file-descriptor, or hypervisor escape paths.
- A valid signature proves control of a key, not software identity or complete
  observation. Production claims require measured attestation, independently
  observed flow evidence, and non-equivocation witnesses.
- Exact destination allowlisting does not prevent harmful or secret-bearing
  content over an approved channel. Production executors need payload schemas,
  information-flow controls, and data-loss prevention.
- The local kill-latency measurement is a reference-runtime result, not a
  production containment service-level measurement.

### Dual-use considerations

Publishing bypass test categories can help adversaries enumerate weak
evaluation boundaries. This release therefore provides defensive conformance
tests and abstract attack classes, but no exploit for a real package service,
cloud control plane, credential broker, or third-party harness. Canary values
are nonfunctional, demo credentials are synthetic, and the executor performs
no real external request. Operators should run production escape tests only in
authorized isolated environments, protect topology and credential material,
and disclose newly discovered bypasses through the affected provider's
coordinated vulnerability process.
