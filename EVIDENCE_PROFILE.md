# BCP-1 canonical evidence profile

## Purpose

The evidence bundle lets an auditor verify contract signatures, request and
decision binding, event continuity, counters, kill-trigger binding, latency and
an independently witnessed final root without access to the lab network.

It cannot prove complete observation by itself. Completeness depends on the
BCP-01 OS/hypervisor boundary and independent network corroboration.

## Bundle

An offline bundle contains exactly:

- `manifest.json` — operator-signed immutable policy and pinned public keys;
- `evidence.jsonl` — canonical hash-chained events;
- `receipt.json` — supervisor-signed roots, counters and kill acknowledgement;
- `operator-key.json` — externally trusted operator public key;
- deployment evidence referenced by digest: attestations, firewall exports,
  flow-counter statements and conformance reports.

## Canonical wire profile

- UTF-8 without BOM;
- every string and object key in Unicode NFC;
- no Unicode surrogate code points;
- objects have unique keys, including after NFC normalization;
- RFC 8785 UTF-16 object-key ordering;
- arrays preserve order;
- booleans, null and I-JSON safe integers only;
- no floats, NaN, infinity or integers outside ±(2^53−1);
- no insignificant whitespace;
- JSONL uses one canonical object followed by one LF per event;
- timestamps use `YYYY-MM-DDTHH:MM:SS.ffffffZ`;
- SHA-256 uses lowercase hexadecimal;
- Ed25519 keys/signatures use unpadded canonical base64url.

The code enforces depth, node-count, input-byte and event-payload limits before
constructing signed protocol objects.

## Domain separation

Every digest is:

```text
SHA-256("BCP-1" || 0x00 || DOMAIN || 0x00 || canonical_json(value))
```

Every signature covers:

```text
"BCP-1" || 0x00 || SIGNATURE_DOMAIN || 0x00 ||
"SHA-256" || 0x00 || digest_bytes
```

Manifest, event, decision, kill acknowledgement, witness checkpoint and receipt
use distinct hash/signature domains.

## Event requirements

Every event binds:

- protocol and schema version;
- run ID and manifest hash;
- zero-based sequence and previous event hash;
- producer instance;
- wall and monotonic observations;
- event kind and optional request ID;
- canonical payload and payload SHA-256;
- event SHA-256.

`REQUEST` payloads contain the normalized action and action digest. `DECISION`
payloads contain the complete gateway-signed decision. `ALLOW` decisions carry
an action-bound nonce, expiry, `max_uses=1` and kill epoch. `DISPATCH` records
bind the consumed authorization and decision. `RESULT` records contain bounded
status, response bytes and response digest, never secret material.

## Independent signatures

- The operator signs the manifest and pins separate gateway, supervisor and
  witness keys.
- The gateway signs each decision.
- The supervisor signs kill acknowledgements and the receipt.
- The witness signs one evidence root for a `(run_id, manifest_hash)` pair and
  refuses conflicting roots.

Production keys must be protected independently. The reference factory keeps
them in one process strictly for executable tests and makes no HSM or
attestation claim.

## Streaming verification

`python -m auditor.verify` uses O(1) chain memory. It verifies:

1. operator signature and key pinning;
2. exact canonical encodings;
3. run/manifest binding;
4. event sequence, previous hash and monotonic ordering;
5. request action digests;
6. gateway decision signatures and immediate request binding;
7. supervisor receipt and kill-ack signatures;
8. event count, first/final roots and canonical JSONL digest;
9. decision/dispatch/result counters;
10. trigger-event binding and kill-latency SLA;
11. witness signature and receipt/checkpoint consistency.

Non-equivocation still relies on querying or auditing the independent witness's
append-only run registry. Possessing one valid checkpoint cannot prove that the
witness never signed another checkpoint.
