"""Streaming offline verifier for BCP-1 evidence bundles."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from app.action import Action
from app.evidence import iter_canonical_jsonl
from app.models import (
    CancellationEventPayload,
    Decision,
    DispatchEventPayload,
    Ed25519PublicKey,
    Event,
    EventKind,
    KillAcknowledgement,
    Manifest,
    OverloadSummaryPayload,
    Receipt,
    RequestEventPayload,
    ResultEventPayload,
    RunStatus,
    ViolationEventPayload,
    Verdict,
    canonical_json_bytes,
)


@dataclass(frozen=True)
class VerificationReport:
    valid: bool
    event_count: int
    decision_count: int
    dispatch_count: int
    result_count: int
    killed: bool
    witness_checkpoint_hash: str


@dataclass
class _RequestTrace:
    event: Event
    action_sha256: str
    decision: Decision | None = None
    dispatched: bool = False
    completed: bool = False
    cancellation_confirmed: bool = False


def _inspect_events(
    events: Iterable[Event],
    *,
    manifest: Manifest,
    receipt: Receipt,
    stats: dict[str, int],
) -> Iterator[Event]:
    traces: dict[str, _RequestTrace] = {}
    request_sequences: dict[int, _RequestTrace] = {}
    authorization_ids: set[str] = set()
    event_hashes: dict[int, str] = {}
    kill_barrier: int | None = None
    logged_ack: KillAcknowledgement | None = None
    for event in events:
        event_hashes[event.body.sequence] = event.event_hash
        if event.body.kind == EventKind.REQUEST:
            payload = RequestEventPayload.model_validate_json(
                event.body.payload_canonical_json
            )
            action = Action.model_validate(payload.action)
            if event.body.request_id != action.request_id:
                raise ValueError("REQUEST event request_id does not match action")
            if action.request_id in traces:
                raise ValueError("duplicate REQUEST request_id")
            if action.digest() != payload.action_sha256:
                raise ValueError("REQUEST action digest does not match")
            trace = _RequestTrace(event=event, action_sha256=payload.action_sha256)
            traces[action.request_id] = trace
            request_sequences[event.body.sequence] = trace
        elif event.body.kind == EventKind.DECISION:
            decision = Decision.model_validate_json(event.body.payload_canonical_json)
            decision.verify(manifest.body.gateway_key)
            if (
                decision.body.run_id != manifest.body.run_id
                or decision.body.manifest_hash != manifest.manifest_hash
            ):
                raise ValueError("DECISION is bound to another run")
            trace = request_sequences.get(decision.body.request_event_sequence)
            if trace is None:
                raise ValueError("DECISION references an absent REQUEST")
            if (
                decision.body.request_event_hash != trace.event.event_hash
                or decision.body.request_id != trace.event.body.request_id
                or event.body.request_id != trace.event.body.request_id
                or decision.body.action_sha256 != trace.action_sha256
            ):
                raise ValueError("DECISION request binding is invalid")
            if trace.decision is not None:
                raise ValueError("REQUEST has multiple DECISION events")
            trace.decision = decision
            stats["decisions"] += 1
            if decision.body.verdict == Verdict.ALLOW:
                stats["allowed"] += 1
            else:
                stats["denied"] += 1
            if decision.body.hard_violation:
                kill_barrier = event.body.sequence
        elif event.body.kind == EventKind.DISPATCH:
            payload = DispatchEventPayload.model_validate_json(
                event.body.payload_canonical_json
            )
            if kill_barrier is not None:
                raise ValueError("DISPATCH occurs after a kill barrier")
            trace = traces.get(event.body.request_id or "")
            if trace is None or trace.decision is None:
                raise ValueError("DISPATCH has no bound DECISION")
            decision = trace.decision
            body = decision.body
            if body.verdict != Verdict.ALLOW:
                raise ValueError("DISPATCH is bound to a non-ALLOW decision")
            if trace.dispatched:
                raise ValueError("authorization was dispatched more than once")
            if (
                payload.action_sha256 != trace.action_sha256
                or payload.decision_hash != decision.decision_hash
                or payload.authorization_id != body.authorization_id
                or payload.kill_epoch != body.kill_epoch
            ):
                raise ValueError("DISPATCH capability binding is invalid")
            if payload.authorization_id in authorization_ids:
                raise ValueError("authorization_id was reused")
            if event.body.monotonic_ns > body.authorization_expires_monotonic_ns:
                raise ValueError("DISPATCH used an expired authorization")
            authorization_ids.add(payload.authorization_id)
            trace.dispatched = True
            stats["dispatches"] += 1
        elif event.body.kind == EventKind.RESULT:
            payload = ResultEventPayload.model_validate_json(
                event.body.payload_canonical_json
            )
            trace = traces.get(event.body.request_id or "")
            if trace is None or trace.decision is None or not trace.dispatched:
                raise ValueError("RESULT has no bound DISPATCH")
            decision = trace.decision
            if trace.completed:
                raise ValueError("DISPATCH has multiple RESULT events")
            if (
                payload.action_sha256 != trace.action_sha256
                or payload.decision_hash != decision.decision_hash
                or payload.authorization_id != decision.body.authorization_id
                or payload.kill_epoch != decision.body.kill_epoch
            ):
                raise ValueError("RESULT dispatch binding is invalid")
            trace.completed = True
            stats["results"] += 1
        elif event.body.kind == EventKind.CANCELLATION:
            payload = CancellationEventPayload.model_validate_json(
                event.body.payload_canonical_json
            )
            trace = traces.get(event.body.request_id or "")
            if trace is None or trace.decision is None or not trace.dispatched:
                raise ValueError("CANCELLATION has no bound DISPATCH")
            decision = trace.decision
            if trace.completed or trace.cancellation_confirmed:
                raise ValueError("CANCELLATION contradicts a terminal dispatch state")
            if (
                payload.action_sha256 != trace.action_sha256
                or payload.decision_hash != decision.decision_hash
                or payload.authorization_id != decision.body.authorization_id
                or payload.kill_epoch != decision.body.kill_epoch
            ):
                raise ValueError("CANCELLATION dispatch binding is invalid")
            trace.cancellation_confirmed = payload.status == "CONFIRMED"
        elif event.body.kind == EventKind.VIOLATION:
            ViolationEventPayload.model_validate_json(
                event.body.payload_canonical_json
            )
            kill_barrier = event.body.sequence
        elif event.body.kind == EventKind.OVERLOAD_SUMMARY:
            OverloadSummaryPayload.model_validate_json(
                event.body.payload_canonical_json
            )
            kill_barrier = event.body.sequence
        elif event.body.kind == EventKind.KILL_ACKNOWLEDGED:
            if logged_ack is not None:
                raise ValueError("multiple KILL_ACKNOWLEDGED events")
            logged_ack = KillAcknowledgement.model_validate_json(
                event.body.payload_canonical_json
            )
            logged_ack.verify(manifest.body.supervisor_key)
            trigger_sequence = logged_ack.body.trigger_event_sequence
            if trigger_sequence >= event.body.sequence:
                raise ValueError("kill acknowledgement does not follow its trigger")
            if event_hashes.get(trigger_sequence) != logged_ack.body.trigger_event_hash:
                raise ValueError("kill acknowledgement trigger binding is invalid")
            if (
                receipt.body.kill_acknowledgement is None
                or logged_ack.acknowledgement_hash
                != receipt.body.kill_acknowledgement.acknowledgement_hash
            ):
                raise ValueError("logged kill acknowledgement differs from receipt")
            stats["kill_acks"] += 1
        elif event.body.kind == EventKind.KILL_REQUESTED:
            raise ValueError("unsupported KILL_REQUESTED event")
        stats["events"] += 1
        yield event

    if any(trace.decision is None for trace in traces.values()):
        raise ValueError("REQUEST is missing its DECISION")
    incomplete = sum(
        trace.dispatched
        and not trace.completed
        and not trace.cancellation_confirmed
        for trace in traces.values()
    )
    if receipt.body.status == RunStatus.COMPLETED and incomplete:
        raise ValueError("completed run contains an unfinished DISPATCH")
    if incomplete:
        ack = receipt.body.kill_acknowledgement
        if ack is None or incomplete > ack.body.inflight_at_trigger:
            raise ValueError("unfinished DISPATCH is not explained by containment")


def verify_bundle(
    *,
    manifest: Manifest,
    receipt: Receipt,
    evidence_lines: Iterable[bytes | str],
    operator_public_key: Ed25519PublicKey,
) -> VerificationReport:
    if operator_public_key.key_id != manifest.body.operator_key_id:
        raise ValueError("operator verification key ID does not match manifest")
    manifest.verify(operator_public_key.as_bytes())
    stats = {
        "events": 0,
        "decisions": 0,
        "allowed": 0,
        "denied": 0,
        "dispatches": 0,
        "results": 0,
        "kill_acks": 0,
    }
    events = _inspect_events(
        iter_canonical_jsonl(evidence_lines),
        manifest=manifest,
        receipt=receipt,
        stats=stats,
    )
    receipt.verify_against(manifest=manifest, events=events)
    body = receipt.body
    expected = {
        "events": body.event_count,
        "allowed": body.allowed_request_count,
        "denied": body.denied_request_count,
        "dispatches": body.dispatched_request_count,
        "results": body.completed_request_count,
    }
    for key, value in expected.items():
        if stats[key] != value:
            raise ValueError(
                f"receipt {key} counter {value} does not match evidence {stats[key]}"
            )
    if body.kill_acknowledgement is not None and stats["kill_acks"] != 1:
        raise ValueError("killed receipt requires one logged kill acknowledgement")
    if body.kill_acknowledgement is None and stats["kill_acks"] != 0:
        raise ValueError("unexpected kill acknowledgement event")
    return VerificationReport(
        valid=True,
        event_count=stats["events"],
        decision_count=stats["decisions"],
        dispatch_count=stats["dispatches"],
        result_count=stats["results"],
        killed=body.kill_acknowledgement is not None,
        witness_checkpoint_hash=body.witness_checkpoint.checkpoint_hash,
    )


def _load_exact_model(path: Path, model_type):
    raw = path.read_bytes()
    value = model_type.model_validate_json(raw)
    if canonical_json_bytes(value) != raw:
        raise ValueError(f"{path}: file is not canonical JSON")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--operator-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = _load_exact_model(args.manifest, Manifest)
        receipt = _load_exact_model(args.receipt, Receipt)
        operator_key = _load_exact_model(args.operator_key, Ed25519PublicKey)
        with args.evidence.open("rb") as evidence:
            report = verify_bundle(
                manifest=manifest,
                receipt=receipt,
                evidence_lines=evidence,
                operator_public_key=operator_key,
            )
    except Exception as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(report.__dict__, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
