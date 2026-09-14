# BCP-1 demonstration script (approximately 4 minutes)

## 0:00–0:30 — The failure

“The July incident was not primarily a missing anomaly detector. The model used
allowed egress, detections did not become an automatic page and kill, shared
credentials expanded the blast radius, and an unsafe public second hop became
part of the attack chain. Our question is: what minimum standard makes those
failures technically impossible or externally visible?”

Show the headline in `README.md`.

## 0:30–1:10 — The three invariants

Show the architecture diagram and say:

1. “No credential or side effect before the signed decision is durably
   committed.”
2. “Every ALLOW is short-lived, bound to one action, usable once, and checked
   against the current kill epoch at dispatch.”
3. “A hard violation cuts the network and produces a supervisor-signed
   acknowledgement; it does not wait for a human to interpret an alert.”

Emphasize that FastAPI is an adapter, not the security boundary.

## 1:10–1:50 — Canary kill and offline proof

Run:

```powershell
python -m demo.run --output artifacts/demo
python -m auditor.verify `
  --manifest artifacts/demo/manifest.json `
  --evidence artifacts/demo/evidence.jsonl `
  --receipt artifacts/demo/receipt.json `
  --operator-key artifacts/demo/operator-key.json
```

Point to:

- `decision = credential.canary_used`;
- `forbidden_requests_forwarded = 0`;
- `run_status = KILLED`;
- `valid = true`.

Say: “This is how BCP-1 solves alerted-but-did-not-page: the canary observation
is a state transition, not a dashboard notification.”

## 1:50–2:45 — The research result

Run:

```powershell
python -m benchmarks.ablation --output artifacts/benchmark
```

Show `artifacts/benchmark/ablation-results.svg`.

Say: “We removed one control at a time. Alert-only forwarded once. A stale
permit dispatched once after kill. A weak provider check admitted one unsafe
harness. A hash chain without a witness accepted a conflicting root. Per-drop
logging allocated 49,998 post-kill records. Full BCP-1 reduced every unsafe
count to zero. These are explicit architecture ablations, not allegations
about a vendor.”

## 2:45–3:20 — Boundary positive control

Run:

```powershell
.\scripts\run_network_ablation.ps1
```

Point to the two JSON objects:

- open bridge: `public_socket_succeeded = true`;
- internal boundary: `public_socket_succeeded = false`;
- both: `gateway_dispatch_succeeded = true`.

Say: “This proves the default-deny principle in Docker. It does not prove
microVM conformance.”

## 3:20–3:50 — Third-party verification and second hop

Show `EVIDENCE_PROFILE.md` and `CONTROL_MATRIX.md`.

“An auditor needs only the signed manifest, canonical JSONL, signed receipt,
trusted operator key, and deployment evidence digests—not the lab network. The
evaluation sponsor remains accountable. Harness and cloud operators are
responsible for their layers. Missing authentication, isolation, kill
authority, ownership, or evidence exchange fails preflight.”

## 3:50–4:05 — Close with the limitation

“BCP-1 combines established security primitives; the contribution is the
minimum proof-carrying contract and evidence that each omitted control changes
a measured safety outcome. The reference code does not claim hardware-backed
isolation. The next test is an independently witnessed microVM deployment.”

