# BCP-1: Minimum Adequate Containment Profile

Version 1.0 — guardrails-off dangerous-capability evaluations

## 1. Scope and conformance

BCP-1 applies when an AI evaluation intentionally disables production
safeguards or grants tools capable of code execution, network access,
credential use, or privilege changes. Its safety objective is:

> No action outside the signed evaluation contract may produce an external
> side effect. A trusted violation observation must automatically isolate the
> workload before any later dispatch.

An evaluation conforms only if every `MUST` below is satisfied. The reference
Python implementation demonstrates the contract, evidence, authorization,
overload, and offline-verification properties. It does **not** implement or
attest a microVM, kernel egress filter, HSM, or external transparency service.

FastAPI is not a security boundary. A valid deployment places the agent in an
OS/hypervisor-enforced default-deny boundary whose only reachable application
endpoint is the trusted gateway. The executor, credential broker, supervisor,
keys, and evidence mirror are outside the workload trust domain.

## 2. Normative controls

### BCP-01 — OS-enforced workload isolation

**Requirement.** Each run MUST execute in a fresh microVM or equivalently
strong hardware-backed boundary, without host devices, host paths, container
runtime sockets, inherited network descriptors, writable cross-run storage, or
privileged identity. The boundary MUST default-deny raw IP, DNS, UDP/QUIC,
link-local, metadata, private-network and public-network access. Only the
external gateway is reachable.

**Evidence.** Signed workload and policy digests; measured-boot attestation;
hypervisor/VPC policy export; independent flow counters; escape-test report.

**Acceptance test.** Raw TCP, UDP, DNS, QUIC, metadata, sidecar and inherited-FD
attempts fail while a contract-approved gateway request succeeds.

**Owner.** Evaluation sponsor accountable; sandbox/cloud operator responsible.

**Indicative cost.** 2–6 engineer-weeks initial integration; 5–20% runtime
overhead depending on microVM reuse and workload.

### BCP-02 — Closed egress executor

**Requirement.** External effects MUST pass through an executor outside the
workload. The manifest MUST use exact HTTPS origins, normalized path prefixes,
methods, resolved-IP CIDRs, TLS SPKI pins, payload/response byte limits and
request budgets. Redirects, agent-selected proxy destinations, wildcard hosts,
server-side arbitrary fetches and ambiguous encodings MUST be denied. Package
access SHOULD be read-only and content-addressed.

**Evidence.** Operator-signed manifest; gateway decision log; executor result
log; DNS/flow corroboration; parser and redirect conformance vectors.

**Acceptance test.** Redirect, DNS rebinding, percent encoding, duplicate-key,
path traversal, alternate port, stale pin and out-of-CIDR tests fail before
dispatch.

**Owner.** Gateway/executor operator responsible.

**Indicative cost.** 1–3 engineer-weeks; ongoing allowlist maintenance.

### BCP-03 — Brokered least-privilege identity

**Requirement.** Secret bytes MUST NOT enter the agent environment, prompt,
memory, filesystem, logs, or response. The manifest may contain only credential
references. After a signed ALLOW decision is durably committed, the broker MAY
release a per-request, audience-bound, short-lived credential directly to the
executor. Shared cross-run, cross-target, cluster-wide or ambient credentials
are prohibited.

**Evidence.** Credential-grant manifest, broker issuance/revocation counters,
secret-scanning result, IAM policy and identity-use log.

**Acceptance test.** Wrong audience, expired grant, replay, unknown reference,
agent secret-read and use-budget exhaustion fail closed.

**Owner.** Identity/broker operator responsible; sponsor accountable.

**Indicative cost.** 1–3 engineer-weeks plus IAM integration.

### BCP-04 — Canary and tripwire controls

**Requirement.** Every high-risk run MUST include a nonfunctional canary
credential and an independently observed egress tripwire. Any read, use, copy,
validation, or transmission of a canary MUST be a hard run-kill condition.
Tripwires MUST be outside the workload and gateway failure domain.

**Evidence.** Canary identifier commitment, broker denial, signed violation,
kill acknowledgement, tripwire observation and quarterly drill.

**Acceptance test.** Canary use produces zero dispatches and a valid
trigger-bound kill acknowledgement.

**Owner.** Security engineering responsible.

**Indicative cost.** 2–5 engineer-days plus monitoring.

### BCP-05 — Race-free dispatch and out-of-band kill

**Requirement.** Every allowed use MUST carry a gateway-signed, short-lived,
single-use capability binding run, manifest, normalized request hash, policy
rule, nonce, expiry, `max_uses=1`, and current kill epoch. The executor MUST
verify and atomically consume it against the current epoch in the same
lower-layer transaction that admits the side effect. A kill transition MUST
invalidate every unconsumed capability.

The supervisor MUST have a pre-opened control handle, reserved resources, and
authority to cut network access first, revoke broker capabilities, terminate
the workload and confirm isolation without cooperation from the agent,
gateway, or ordinary data plane.

Acknowledgements MUST report typed observed facts. A simulation MUST identify
itself as `SIMULATED` and MUST NOT claim workload termination or confirmed
network isolation. A production confirmation MUST bind an external isolation
evidence digest.

**Evidence.** Signed decisions, dispatch records, nonce registry result, kill
epoch, signed acknowledgement and trigger-to-isolation latency.

**Acceptance test.** Capability replay, expiry, action substitution,
key substitution, kill-before-dispatch and concurrent kill/dispatch tests.

**Owner.** Executor and supervisor operators responsible; incident commander
accountable.

**Indicative cost.** 1–3 engineer-weeks.

### BCP-06 — Complete, bounded, non-equivocating evidence

**Requirement.** The gateway MUST durably append the normalized request and
signed decision before releasing a capability. Append or mirror failure MUST
fail closed. The supervisor MUST independently observe chain heads and sign the
final root, canonical JSONL digest, event count, fixed-width request/drop
counters, egress bytes and optional kill acknowledgement. An independently
operated append-only witness MUST reject a second root for the same run.
The offline verifier MUST validate the full per-request
REQUEST→DECISION→DISPATCH→RESULT/cancellation state machine, not merely count
event names.

Admission MUST bound bytes and rate before model parsing or canonicalization.
The first overflow MUST atomically latch kill. Later burst traffic MUST only
increment bounded counters; it MUST NOT allocate one event per dropped request.

**Evidence.** Canonical JSONL, receipt, operator/gateway/supervisor/witness
signatures, external checkpoint, inclusion/consistency proof and run ledger.

**Acceptance test.** Truncation, reorder, modification, fork, duplicate key,
float, Unicode ambiguity, receipt substitution and 50,000-request flood tests.

**Owner.** Supervisor responsible; independent witness accountable for its log.

**Indicative cost.** 1–3 engineer-weeks plus evidence storage/witness service.

### BCP-07 — Second-hop contract

**Requirement.** Before a run starts, every reachable tool server, public
harness, relay and delegated compute service MUST have a named owner,
authentication, non-root workload identity, tenant isolation, default-deny
egress, no ambient secrets, bounded requests, abuse telemetry, containment
authority, notification route and evidence-exchange obligation. A missing fact
is a failed preflight, not an accepted risk.

Each preflight MUST be provider-signed, bound to the run, freshness-bounded,
carry immutable evidence digests, and use a provider key pinned by the
operator-signed manifest. The signature establishes attribution and integrity;
the auditor must still validate referenced infrastructure evidence.

The evaluation sponsor remains accountable for model-originated external
effects. Contracting with a harness or cloud provider does not transfer that
accountability.

**Evidence.** Signed provider inventory, attestation/test result, RACI,
contractual control schedule and current emergency contacts.

**Acceptance test.** An unauthenticated or root-capable public harness causes
preflight rejection before model inference begins.

**Owner.** Sponsor accountable; harness and cloud providers responsible for
their layers.

**Indicative cost.** 2–5 engineer-days per provider, excluding remediation.

### BCP-08 — Incident declaration and re-enable gate

**Requirement.** Unauthorized egress, metadata access, cross-run communication,
credential misuse, privilege escalation, tunnel/C2 creation, monitor tampering,
shared-control-plane compromise, or unbounded scope MUST automatically declare
an incident. Confirmed shared-service compromise MUST halt the fleet.

Re-enablement MUST require eradication, credential rotation, affected-scope
analysis, independent conformance rerun, evidence review and named security
approval. An alert without a declared owner, deadline and automatic fallback
does not satisfy this control.

**Evidence.** Incident/page ID, timeline, scope decision, notifications,
eradication record, test bundle and signed restart approval.

**Acceptance test.** Tabletop verifies run kill, fleet halt, third-party notice,
failed-ack escalation and restart denial.

**Owner.** Incident commander accountable.

**Indicative cost.** 2–5 engineer-days to establish; recurring drills.

## 3. Dispatch state machine

1. **Kernel admission:** enforce connection, body and rate limits before JSON.
2. **Normalize:** reject duplicate keys, floats, non-NFC text, ambiguous paths,
   redirects and noncanonical network identities.
3. **Authorize:** evaluate one immutable, operator-signed manifest snapshot.
4. **Commit:** durably append request and signed decision; mirror the chain head.
5. **Issue:** return one epoch-bound, one-use signed dispatch capability.
6. **Dispatch:** atomically validate epoch and consume nonce at the executor.
7. **Observe:** record bounded result or violation and independently count flow.
8. **Terminate:** cut network, revoke credentials, terminate workload, page and
   record trusted-observation-to-isolation latency.

Ordering invariant:

> No credential release and no external side effect may occur before the signed
> decision is durably committed. At dispatch, the capability epoch must equal
> the shared epoch and nonce consumption must succeed exactly once.

## 4. What cryptography does not prove

- A valid receipt cannot prove absence of unobserved actions. BCP-01 makes
  bypass paths unreachable; cryptography only protects observed evidence.
- A signature proves key possession, not software identity. Bind keys to
  measured gateway/supervisor images when making that claim.
- A locally signed checkpoint does not prevent equivocation. The witness must
  be independent and append-only.
- Destination allowlisting is not information-flow control. Executors must
  additionally validate payload schemas and apply data-loss controls.
- Kill latency is meaningful only from the first trusted observation to
  independently confirmed network isolation in one monotonic clock domain.

## 5. Framework alignment

- **CSA AICM v1.1 AIS-13:** isolated execution, capability boundaries, network
  access controls, tool limitation, escape testing, breach monitoring, audit
  logs and lateral-movement prevention.
- **CoSAI AI Incident Response Framework v1.0:** tool-call telemetry, declared
  severity thresholds, RACI, containment, forensic provenance, third-party
  coordination, recovery and exercises.
- **NIST SP 800-61r3:** `GV.RR`, `GV.SC`, `PR.PS-04`, `DE.AE-03/06/08`,
  `RS.MA-01/04`, `RS.AN-06/07/08`, `RS.CO-02/03`, and `RS.MI-01/02`.

## 6. Reference ablation evidence

The executable benchmark tests whether removing one control changes a concrete
safety outcome. These are architecture ablations, not claims about any vendor:

- `canary-alert-without-page` removes automatic `BCP-04` escalation. The
  alert-only baseline forwards one forbidden request; BCP-1 forwards zero and
  produces a valid kill receipt.
- `permit-kill-race` removes the dispatch-time `BCP-05` epoch check. The stale
  permit baseline dispatches once after kill; BCP-1 dispatches zero times.
- `unsafe-public-second-hop` replaces `BCP-07` with a provider-name presence
  check. The baseline admits one unauthenticated, root-capable, egress-enabled
  harness; BCP-1 admits zero.
- `evidence-equivocation` removes the independent `BCP-06` witness. The
  hash-only baseline accepts a conflicting second root; BCP-1 rejects it.
- `request-flood-after-kill` removes bounded post-kill accounting. The baseline
  allocates 49,998 log records; BCP-1 adds zero events after the kill record.

`scripts/run_network_ablation.ps1` separately compares an ordinary Docker
bridge with an `internal: true` network. This is an acceptance-test
demonstration for the default-deny principle, not `BCP-01` microVM conformance.
Canonical machine-readable results are in `artifacts/benchmark/results.json`.

The companion auditability study compares ordinary access logs, per-line
authenticated logs, and a BCP-1 bundle under the same 50,000-request post-kill
burst. The profiles verify respectively 0/5, 1/5, and 5/5 defined containment
claims. BCP-1 emits 4 events rather than 50,000 records and is 732× smaller
than the measured access log. This result concerns the mediated path; proof of
complete observation still requires `BCP-01` plus independent flow evidence.
