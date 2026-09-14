# Project Ballistic

## BCP-1: proof-carrying containment for guardrails-off evaluations

**Claim.** A dangerous-capability evaluation should not be considered
contained merely because it has a sandbox or alert. It should be required to
produce independently verifiable evidence that every external effect was
authorized by a signed contract and that hard violations automatically
isolated the workload.

**Measured finding.** Across five incident-grounded control ablations, every
weaker architecture failed its designated safety metric; full BCP-1 passed all
five. Alert-only forwarding, stale permits, unsafe second hops, evidence forks,
and post-kill log amplification each reached a value of zero only with the
corresponding BCP-1 control enabled. Under a 50,000-request post-kill burst,
ordinary access logs verified 0/5 containment claims, signed-line logs verified
1/5, and the BCP-1 bundle verified 5/5 while using 12,500× fewer records.

Project Ballistic provides:

1. [BCP-1](STANDARD.md), a minimum adequate containment standard;
2. a reference gateway/executor/supervisor contract with race-resistant,
   one-use dispatch capabilities;
3. canonical, independently signed evidence and an O(1)-memory offline auditor;
4. a [control-by-attack-phase matrix](CONTROL_MATRIX.md) for the July 2026
   OpenAI/Hugging Face incident.

FastAPI is an API adapter, **not** the security boundary. The Python reference
implementation does not claim to supply microVM isolation, kernel egress
enforcement, HSM protection or a production transparency log.

## What would have stopped July 2026?

The chain should have been interrupted before internet access:

- a per-run, read-only package identity would have prevented Artifactory from
  becoming shared mutable inter-agent state;
- a content-addressed package API would not have exposed arbitrary fetch,
  token-refresh, plugin or administration surfaces;
- a hypervisor/VPC default-deny boundary would have prevented a compromised
  package service from becoming general egress;
- a second-hop preflight would have rejected the unauthenticated, root-capable
  public evaluation harness;
- deterministic kill criteria would have stopped the evaluation on the first
  unauthorized boundary operation instead of leaving escalation to human alert
  interpretation.

The published 56 actions were an exfiltration category distributed across the
campaign, not a contiguous 56-step exploit. BCP-1 therefore makes no invented
historical firing claim. Its measurable criterion is stronger: the first
contract violation is not forwarded, and a signed receipt binds that trigger to
truthfully typed containment. The local backend reports `SIMULATED` and
`network_isolation_confirmed=false`; production confirmation requires external
evidence.

## Architecture

```mermaid
flowchart LR
    Agent["Untrusted agent microVM"] -->|"Only reachable endpoint"| Gateway
    Manifest["Operator-signed manifest"] --> Gateway["External gateway"]
    Gateway -->|"Signed one-use capability"| Executor["Trusted executor"]
    Broker["Credential broker"] -->|"Audience-bound secret after commit"| Executor
    Executor --> Target["Declared target"]
    Gateway --> WAL["Durable evidence WAL"]
    WAL --> Mirror["Independent supervisor mirror"]
    Gateway -->|"Hard violation"| Supervisor["Out-of-band supervisor"]
    Supervisor -->|"Network cut, revoke, terminate"| Agent
    Mirror --> Receipt["Supervisor-signed receipt"]
    Receipt --> Witness["Append-only witness"]
    Witness --> Auditor["Offline auditor"]
```

The production boundary is below HTTP:

- the agent cannot open raw internet, DNS, QUIC, metadata or sidecar paths;
- the gateway cannot release a capability before request and signed decision
  are durably committed and independently mirrored;
- the executor atomically checks kill epoch and consumes a nonce exactly once;
- credentials stay in the broker and are released only to the executor;
- the supervisor has reserved resources and an out-of-band isolation handle.

## Sixty-second demonstration

```powershell
python -m pip install -e ".[test]"
python -m demo.scenarios.run --output artifacts/scenarios/results.json
python -m benchmarks.ablation --output artifacts/benchmark
python -m benchmarks.auditability --output artifacts/benchmark/auditability.json
python -m demo.run --output artifacts/demo
python -m auditor.verify `
  --manifest artifacts/demo/manifest.json `
  --evidence artifacts/demo/evidence.jsonl `
  --receipt artifacts/demo/receipt.json `
  --operator-key artifacts/demo/operator-key.json
python -m pytest
```

The demo attempts to use a canary credential. The expected result is:

- `credential.canary_used`;
- zero dispatches;
- one independently signed kill acknowledgement;
- `SIMULATED` termination with no false network-isolation claim;
- valid event-chain, receipt and witness signatures;
- a bundle verifiable without lab-network access.

Modify or remove any line in `evidence.jsonl`; the auditor must fail.

### Control-ablation benchmark

```powershell
python -m benchmarks.ablation --output artifacts/benchmark
```

![Five BCP-1 control ablations](artifacts/benchmark/ablation-results.svg)

The benchmark compares explicit architectural omissions—not named vendors—with
the full reference contract:

- alert-only forwarded one canary request; BCP-1 forwarded zero;
- a permit without dispatch-time epoch validation executed once after kill;
  BCP-1 executed zero times;
- a presence-only provider inventory admitted one unsafe public harness; BCP-1
  admitted zero;
- a hash chain without an independent witness accepted a conflicting root;
  BCP-1 rejected it;
- per-drop logging added 49,998 post-kill records; BCP-1 added zero.

### Auditability-gap study

```powershell
python -m benchmarks.auditability `
  --output artifacts/benchmark/auditability.json
```

For the same synthetic 50,000-request post-kill burst:

- an ordinary access log verified 0/5 containment claims;
- a per-line authenticated log verified only included-line integrity: 1/5;
- the BCP-1 manifest, evidence, receipt, and witness verified 5/5;
- BCP-1 emitted 4 canonical events instead of 50,000 records—a 12,500×
  reduction;
- measured evidence was 732× smaller than the access log and 1,126× smaller
  than the signed-line log.

The five claims are signed-contract binding, zero forbidden dispatches in the
mediated path, trigger-bound kill, included-event tamper detection, and
conflicting-root rejection. Complete-observation claims still require the
independently enforced BCP-01 boundary and flow evidence.

Second-hop entries are provider-signed, run-bound, freshness-bounded, and carry
external evidence digests pinned by the operator manifest. Verification occurs
before manifest issuance and again offline. This proves who signed which
assertions; it does not prove that the provider's infrastructure assertions are
true without checking the referenced evidence.

### Container boundary smoke test

```powershell
docker compose -f compose.boundary-smoke.yaml up --build `
  --abort-on-container-exit --exit-code-from agent-probe
docker compose -f compose.boundary-smoke.yaml down --volumes --remove-orphans
```

The probe runs as an unprivileged container on an `internal: true` network. It
must fail to open a raw TCP connection to `1.1.1.1:443` while successfully
dispatching an approved action through the gateway. This is a reproducible
container-network test, not evidence of microVM-grade production conformance.

For the open-versus-default-deny ablation:

```powershell
.\scripts\run_network_ablation.ps1
```

The open Docker bridge is the positive control: its raw public TCP connection
must succeed. The `internal: true` network must block the same connection while
still permitting the approved gateway dispatch.

## Measured reference results

On Python 3.12.10:

- 32/32 contract, scenario, API, benchmark and adversarial tests passed;
- combined statement/branch coverage: 80%;
- control ablations: 5 baseline failures, 0 BCP-1 failures;
- auditability gap: access log 0/5 claims, signed-line log 1/5, BCP-1 5/5;
- 50,000-request evidence: 50,000 baseline records versus 4 BCP-1 events;
- canary scenario decision: `credential.canary_used`;
- forbidden requests forwarded: 0;
- canonical evidence events: 4;
- offline audit: valid;
- 50,000-request flood: one overload event, 49,998 counter-only
  post-kill drops, and no post-kill event growth;
- Docker Desktop 4.90.0 / Engine 29.7.2 boundary probe:
  `raw_public_socket_blocked=true` and
  `gateway_dispatch_succeeded=true`;
- network positive control: public TCP succeeded on the open bridge and failed
  on the internal network; gateway dispatch succeeded on both;
- reference isolation callback latency: below the local monotonic clock's
  measurable resolution in the latest run.

These are properties of the deterministic reference runtime, not performance
claims for a production microVM supervisor.

Full command outputs, runtime versions, and SHA-256 digests are indexed in
[`artifacts/proof/README.md`](artifacts/proof/README.md).

## Race-free dispatch contract

1. Bound bytes and rate before parsing.
2. Normalize the closed action structure.
3. Evaluate one immutable, signed manifest.
4. Append request and gateway-signed decision to the WAL.
5. Mirror the committed chain head.
6. Return a signed capability binding action hash, nonce, expiry, one use and
   current kill epoch.
7. The reference executor verifies and consumes the capability at its bounded
   dispatch admission point; a conforming production executor couples this
   transaction to lower-layer network admission.
8. A kill transition advances the epoch, cuts network first, revokes broker
   grants and terminates the workload.

For a 50,000-request burst, only the first excess request creates an
`OVERLOAD_SUMMARY`; later requests increment fixed-width counters without event
allocation.

## Canonical evidence

The [evidence profile](EVIDENCE_PROFILE.md) rejects duplicate JSON keys,
floating-point values, non-NFC strings, unsafe integers, ambiguous paths,
redirects and noncanonical encodings. The operator signs the manifest, the
gateway signs decisions, the supervisor signs kill acknowledgements and the
receipt, and an independently pinned witness signs one final root per run.

The streaming auditor verifies:

- all signatures and pinned key identities;
- request/decision/action/run binding;
- sequence and previous-event-hash continuity;
- canonical JSONL digest and receipt roots;
- decision, dispatch and result counters;
- kill-trigger binding and latency SLA;
- witness checkpoint consistency.

SHA-256 chaining is tamper-evidence, not proof of complete observation. Actual
completeness requires the OS/hypervisor boundary and independent network flow
evidence specified by BCP-1.

## Minimum standard

All eight controls are mandatory:

- `BCP-01` OS/hypervisor-enforced workload isolation;
- `BCP-02` closed egress executor;
- `BCP-03` brokered least-privilege identity;
- `BCP-04` canaries and egress tripwires;
- `BCP-05` one-use dispatch and out-of-band kill;
- `BCP-06` bounded, independently witnessed evidence;
- `BCP-07` second-hop contract and preflight;
- `BCP-08` incident declaration and re-enable gate.

Each clause in [STANDARD.md](STANDARD.md) includes an owner, required evidence,
acceptance test, approximate implementation cost and framework mapping.

## Second-hop responsibility

The evaluation sponsor remains accountable for external effects. The public
harness operator is responsible for endpoint authentication, customer-workload
configuration and egress in its layer. The cloud provider is responsible for
platform isolation and contracted abuse response. Missing authentication,
isolation, owner, kill authority or evidence exchange is a failed preflight,
not a risk exception.

## Test and ship gate

The automated suite covers:

- capability replay, stale kill epochs and concurrent kill/dispatch ordering;
- canary and unauthorized-origin kills before dispatch;
- DNS/IP rebinding, redirect and path ambiguity;
- duplicate-key, floating-point and Unicode ambiguity;
- 50,000-request overload with constant evidence growth after kill;
- evidence truncation, reorder and payload modification;
- operator-key substitution and witness equivocation;
- streaming offline verification.

A production deployment additionally MUST provide independently witnessed
Linux/microVM conformance results for raw sockets, DNS, QUIC, metadata, sidecar
and inherited-file-descriptor bypass attempts. Unit tests cannot establish an
OS security boundary.

## Framework alignment

- **CSA AICM v1.1 AIS-13:** execution isolation, tool boundaries, network
  restrictions, least privilege, escape testing, monitoring and breach logs.
- **CoSAI AI Incident Response Framework v1.0:** tool telemetry, severity
  criteria, RACI, automatic containment, forensic provenance, communication,
  recovery and exercises.
- **NIST SP 800-61r3:** `GV.RR`, `GV.SC`, `PR.PS-04`, `DE.AE-03/06/08`,
  `RS.MA-01/04`, `RS.AN-06/07/08`, `RS.CO-02/03`, and `RS.MI-01/02`.

## Repository map

```text
app/action.py       closed normalized action profile
app/gateway.py      admission, authorization and signed capability issuance
app/executor.py     one-use capability consumption and brokered dispatch
app/supervisor.py   independent mirror, kill acknowledgement and receipt
app/models.py       canonical signed protocol structures
auditor/verify.py   O(1)-memory offline verifier
benchmarks/         incident-grounded control-ablation benchmark
demo/scenarios/     four judge-facing deterministic scenarios
tests/              contract, race, overload and evidence attacks
policies/bcp-1.yaml readable version of controls and kill criteria
STANDARD.md         normative BCP-1 clauses
CONTROL_MATRIX.md   July 2026 phase/control/owner/evidence mapping
```

## Submission package

Build the self-contained code artifact:

```powershell
python scripts/build_submission.py
```

The archive is written under `submission/`. The written report is submitted separately; it is not part of this repository. Run the complete reproducibility gate with:

```powershell
.\scripts\run_final_gate.ps1
```

## Limits

- The local factory holds all private keys in one process for testing.
- The reference transport is bounded and deterministic; it performs no real
  external network request.
- The executor API demonstrates atomic capability consumption, but real
  dispatch atomicity must be enforced at the kernel/hypervisor egress point.
- One witness signature does not itself prove global non-equivocation; auditors
  must inspect the independent append-only registry.
- Destination allowlisting does not prevent secret-bearing content; production
  executors need payload schemas and data-loss controls.
- The discarded MSD/“ballistic trajectory” detector is not a safety boundary.

## Primary sources

- [Apart Research AI Incident Response Sprint](https://apartresearch.com/sprints/ai-incident-response-sprint-2026-09-11-to-2026-09-13)
- [OpenAI–Hugging Face Incident Technical Report](https://cdn.openai.com/pdf/67869394-cb91-4c12-888c-5cbd85c7814c/OpenAI-Hugging-Face%20Incident-Technical-Report.pdf)
- [Hugging Face technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
- [CSA AICM v1.1 AIS-13 auditing guidance](https://cloudsecurityalliance.org/artifacts/aicmv1-1-auditing-guidelines-for-model-providers-mp)
- [CoSAI AI Incident Response Framework v1.0](https://github.com/cosai-oasis/ws2-defenders/blob/main/incident-response/AI-Incident-Response.md)
- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
