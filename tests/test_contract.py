from __future__ import annotations

import time
from threading import Barrier, Event as ThreadEvent, Thread

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.action import Action
from app.factory import build_reference_runtime, demo_spki_pin
from app.models import (
    Ed25519PublicKey,
    Ed25519Signature,
    EventKind,
    HttpMethod,
    Manifest,
    SecondHopAttestation,
    SecondHopAttestationBody,
    canonical_json_bytes,
    parse_canonical_json,
)
from auditor.verify import verify_bundle


def action(
    *,
    request_id: str = "request:allowed",
    host: str = "packages.example.test",
    path: str = "/v1/packages/resolve",
    resolved_ip: str = "203.0.113.17",
    credential_id: str | None = "credential:package-read",
) -> Action:
    return Action.build(
        request_id=request_id,
        method=HttpMethod.POST,
        host=host,
        port=443,
        path=path,
        resolved_ip=resolved_ip,
        tls_spki_sha256=demo_spki_pin(),
        body={"name": "numpy", "version": "2.0.0"},
        credential_id=credential_id,
    )


def operator_public(runtime) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_bytes(
        key_id=runtime.manifest.body.operator_key_id,
        value=runtime.keys.operator.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def finish_and_verify(runtime):
    receipt = runtime.supervisor.complete()
    report = verify_bundle(
        manifest=runtime.manifest,
        receipt=receipt,
        evidence_lines=runtime.ledger.canonical_jsonl_bytes().splitlines(
            keepends=True
        ),
        operator_public_key=operator_public(runtime),
    )
    return receipt, report


def test_allowed_dispatch_is_single_use_and_offline_verifiable() -> None:
    runtime = build_reference_runtime()
    request = action()
    authorized = runtime.gateway.submit_raw(canonical_json_bytes(request))
    assert authorized.accepted
    assert authorized.decision is not None
    result = runtime.executor.dispatch(
        action=request,
        decision=authorized.decision,
        now_ns=time.monotonic_ns(),
    )
    assert result.status_code == 200

    with pytest.raises(PermissionError, match="already consumed"):
        runtime.executor.dispatch(
            action=request,
            decision=authorized.decision,
            now_ns=time.monotonic_ns(),
        )

    receipt = runtime.supervisor.receipt()
    report = verify_bundle(
        manifest=runtime.manifest,
        receipt=receipt,
        evidence_lines=runtime.ledger.canonical_jsonl_bytes().splitlines(
            keepends=True
        ),
        operator_public_key=operator_public(runtime),
    )
    assert report.valid
    assert report.killed
    assert report.dispatch_count == 1
    assert receipt.body.allowed_request_count == 1
    assert b"demo-package-secret" not in runtime.ledger.canonical_jsonl_bytes()


def test_canary_kills_before_dispatch_and_pages_supervisor() -> None:
    runtime = build_reference_runtime()
    request = action(
        request_id="request:canary",
        credential_id="credential:canary",
    )
    denied = runtime.gateway.submit_raw(canonical_json_bytes(request))
    assert not denied.accepted
    assert denied.reason_code == "credential.canary_used"
    receipt = runtime.supervisor.receipt()
    report = verify_bundle(
        manifest=runtime.manifest,
        receipt=receipt,
        evidence_lines=runtime.ledger.canonical_jsonl_bytes().splitlines(
            keepends=True
        ),
        operator_public_key=operator_public(runtime),
    )
    assert report.killed
    assert report.dispatch_count == 0
    assert runtime.isolated_workloads == ["simulation:demo"]
    assert receipt.body.kill_acknowledgement is not None
    isolation = receipt.body.kill_acknowledgement.body
    assert isolation.termination_mode == "SIMULATED"
    assert isolation.network_isolation_confirmed is False
    assert isolation.terminated_workload_ids == ()


def test_kill_epoch_invalidates_previously_allowed_capability() -> None:
    runtime = build_reference_runtime()
    request = action()
    authorized = runtime.gateway.submit_raw(canonical_json_bytes(request))
    assert authorized.decision is not None
    runtime.gateway.fail_closed("test.concurrent_kill", request.request_id)
    with pytest.raises(PermissionError, match="not dispatchable"):
        runtime.executor.dispatch(
            action=request,
            decision=authorized.decision,
            now_ns=time.monotonic_ns(),
        )
    assert runtime.state.snapshot().dispatched_request_count == 0


def test_concurrent_kill_and_dispatch_are_linearized() -> None:
    runtime = build_reference_runtime()
    request = action()
    authorized = runtime.gateway.submit_raw(canonical_json_bytes(request))
    assert authorized.decision is not None
    barrier = Barrier(3)
    outcomes: list[str] = []

    def dispatch_worker() -> None:
        barrier.wait()
        try:
            runtime.executor.dispatch(
                action=request,
                decision=authorized.decision,
                now_ns=time.monotonic_ns(),
            )
            outcomes.append("dispatch")
        except PermissionError:
            outcomes.append("rejected")

    def kill_worker() -> None:
        barrier.wait()
        runtime.gateway.fail_closed("test.racing_kill", request.request_id)
        outcomes.append("kill")

    dispatch_thread = Thread(target=dispatch_worker)
    kill_thread = Thread(target=kill_worker)
    dispatch_thread.start()
    kill_thread.start()
    barrier.wait()
    dispatch_thread.join(timeout=2)
    kill_thread.join(timeout=2)
    assert not dispatch_thread.is_alive() and not kill_thread.is_alive()
    assert "kill" in outcomes
    assert ("dispatch" in outcomes) != ("rejected" in outcomes)

    kinds = [event.body.kind for event in runtime.ledger.events()]
    if "DISPATCH" in kinds:
        assert kinds.index("DISPATCH") < kinds.index("VIOLATION")
    receipt = runtime.supervisor.receipt()
    report = verify_bundle(
        manifest=runtime.manifest,
        receipt=receipt,
        evidence_lines=runtime.ledger.canonical_jsonl_bytes().splitlines(
            keepends=True
        ),
        operator_public_key=operator_public(runtime),
    )
    assert report.valid and report.killed


def test_kill_preempts_slow_transport_without_false_cancellation_claim() -> None:
    runtime = build_reference_runtime()
    request = action(request_id="request:slow")
    authorized = runtime.gateway.submit_raw(canonical_json_bytes(request))
    entered = ThreadEvent()
    outcome: list[str] = []

    def slow_transport(action, secret, max_response_bytes, cancel_event):
        entered.set()
        if not cancel_event.wait(timeout=2):
            raise TimeoutError("containment did not signal inflight transport")
        raise RuntimeError("transport observed cancellation")

    runtime.executor.transport = slow_transport

    def dispatch_worker() -> None:
        try:
            runtime.executor.dispatch(
                action=request,
                decision=authorized.decision,
                now_ns=time.monotonic_ns(),
            )
        except PermissionError:
            outcome.append("cancelled")

    worker = Thread(target=dispatch_worker)
    worker.start()
    assert entered.wait(timeout=1)
    started = time.monotonic()
    runtime.gateway.fail_closed("test.slow_transport_kill", request.request_id)
    assert time.monotonic() - started < 0.5
    worker.join(timeout=1)
    assert not worker.is_alive()
    assert outcome == ["cancelled"]

    receipt = runtime.supervisor.receipt()
    ack = receipt.body.kill_acknowledgement
    assert ack is not None
    assert ack.body.inflight_at_trigger == 1
    assert ack.body.inflight_cancel_signalled == 1
    assert ack.body.inflight_cancelled == 0
    assert ack.body.network_isolation_confirmed is False
    assert verify_bundle(
        manifest=runtime.manifest,
        receipt=receipt,
        evidence_lines=runtime.ledger.canonical_jsonl_bytes().splitlines(
            keepends=True
        ),
        operator_public_key=operator_public(runtime),
    ).valid


def test_egress_budget_is_reserved_before_transport_and_triggers_containment() -> None:
    runtime = build_reference_runtime(max_total_egress_bytes=1024)
    request = action(request_id="request:over-budget")
    authorized = runtime.gateway.submit_raw(canonical_json_bytes(request))
    called = False

    def transport(*args):
        nonlocal called
        called = True
        raise AssertionError("transport must not run")

    runtime.executor.transport = transport
    with pytest.raises(PermissionError, match="egress budget"):
        runtime.executor.dispatch(
            action=request,
            decision=authorized.decision,
            now_ns=time.monotonic_ns(),
        )
    assert called is False
    assert runtime.state.snapshot().dispatched_request_count == 0
    assert runtime.state.snapshot().phase.value == "KILLED"
    assert runtime.isolated_workloads == ["simulation:demo"]


def test_runtime_watchdog_contains_without_waiting_for_another_request() -> None:
    runtime = build_reference_runtime(max_runtime_ms=1)
    deadline_now = runtime.supervisor.started_monotonic_ns + 1_000_001
    runtime.supervisor.monotonic_clock = lambda: deadline_now
    assert runtime.supervisor.enforce_runtime_deadline(monotonic_ns=deadline_now)
    assert runtime.state.snapshot().phase.value == "KILLED"
    assert runtime.isolated_workloads == ["simulation:demo"]
    assert not runtime.supervisor.enforce_runtime_deadline(
        monotonic_ns=runtime.supervisor.started_monotonic_ns + 2_000_000
    )


def test_bounded_commit_admission_fails_closed_when_queue_is_full() -> None:
    runtime = build_reference_runtime(max_queued_events=1)
    entered = ThreadEvent()
    release = ThreadEvent()

    def blocking_observer(event) -> None:
        entered.set()
        release.wait(timeout=2)

    holder = Thread(
        target=lambda: runtime.ledger.commit(
            blocking_observer,
            EventKind.VIOLATION,
            {"reason_code": "test.hold_commit_slot"},
        )
    )
    holder.start()
    assert entered.wait(timeout=1)
    with pytest.raises(BufferError, match="queue budget"):
        runtime.gateway.submit_raw(canonical_json_bytes(action()))
    assert runtime.state.snapshot().phase.value == "KILLED"
    release.set()
    holder.join(timeout=1)


def test_evidence_commit_failure_emergency_isolates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = build_reference_runtime()

    def fail_append(*args, **kwargs):
        raise OSError("simulated WAL failure")

    monkeypatch.setattr(runtime.ledger, "append", fail_append)
    with pytest.raises(OSError, match="WAL failure"):
        runtime.gateway.submit_raw(canonical_json_bytes(action()))
    assert runtime.state.snapshot().phase.value == "KILLED"
    assert runtime.isolated_workloads == ["simulation:demo"]


@pytest.mark.parametrize(
    "change",
    [
        {"path": "/v1/packages/%2e%2e/secrets"},
        {"path": "/v1//packages"},
        {"path": "/v1/packages/../secrets"},
        {"redirects": True},
        {"host": "packages.example.test."},
    ],
)
def test_url_and_redirect_ambiguity_is_rejected(change: dict[str, object]) -> None:
    raw = action().model_dump(mode="python")
    raw.update(change)
    with pytest.raises(ValidationError):
        Action.model_validate(raw)


def test_resolved_ip_and_spki_are_bound_to_policy() -> None:
    runtime = build_reference_runtime()
    rebound = action(resolved_ip="198.51.100.9")
    denied = runtime.gateway.submit_raw(canonical_json_bytes(rebound))
    assert not denied.accepted
    assert denied.reason_code == "egress.constraint_mismatch"
    assert runtime.state.snapshot().dispatched_request_count == 0


def test_strict_json_rejects_duplicate_keys_floats_and_non_nfc() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        parse_canonical_json('{"a":1,"a":2}')
    with pytest.raises(ValueError, match="floating"):
        parse_canonical_json('{"a":1.5}')
    with pytest.raises(ValueError, match="NFC"):
        parse_canonical_json('{"e\u0301":1}')


def test_unauthenticated_second_hop_fails_preflight() -> None:
    with pytest.raises(ValidationError, match="true"):
        SecondHopAttestationBody(
            run_id="run:test",
            provider_id="provider:public-harness",
            provider_key_id="provider-key:test",
            endpoint_host="harness.example.test",
            accountable_org="evaluation:sponsor",
            responsible_operator="harness:operator",
            security_contact="security@example.test",
            issued_at="2026-09-13T00:00:00.000000Z",
            expires_at="2026-09-14T00:00:00.000000Z",
            evidence_sha256=("a" * 64,),
            authenticated=False,
            non_root_workload=True,
            tenant_isolation=True,
            default_deny_egress=True,
            no_ambient_secrets=True,
            bounded_requests=True,
            abuse_monitoring=True,
            automatic_containment_authorized=True,
            evidence_exchange_required=True,
        )


def test_second_hop_preflight_binds_provider_signature_and_evidence() -> None:
    runtime = build_reference_runtime()
    provider = Ed25519PrivateKey.generate()
    provider_public = Ed25519PublicKey.from_bytes(
        key_id="provider-key:harness",
        value=provider.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )
    body = SecondHopAttestationBody(
        run_id=runtime.manifest.body.run_id,
        provider_id="provider:public-harness",
        provider_key_id=provider_public.key_id,
        endpoint_host="harness.example.test",
        accountable_org="evaluation:sponsor",
        responsible_operator="harness:operator",
        security_contact="security@example.test",
        issued_at=runtime.manifest.body.not_before,
        expires_at=runtime.manifest.body.expires_at,
        evidence_sha256=("a" * 64,),
        authenticated=True,
        non_root_workload=True,
        tenant_isolation=True,
        default_deny_egress=True,
        no_ambient_secrets=True,
        bounded_requests=True,
        abuse_monitoring=True,
        automatic_containment_authorized=True,
        evidence_exchange_required=True,
    )
    attestation = SecondHopAttestation.sign(body, provider, provider_public)
    manifest = Manifest.sign(
        runtime.manifest.body.model_copy(
            update={"second_hops": (attestation,)},
        ),
        runtime.keys.operator,
    )
    manifest.verify(operator_public(runtime).as_bytes())

    foreign = Ed25519PrivateKey.generate().sign(b"not-the-attestation")
    forged = attestation.model_copy(
        update={
            "provider_signature": Ed25519Signature.from_bytes(
                key_id=provider_public.key_id,
                value=foreign,
            )
        }
    )
    with pytest.raises(ValueError, match="signature"):
        Manifest.sign(
            runtime.manifest.body.model_copy(update={"second_hops": (forged,)}),
            runtime.keys.operator,
        )


def test_50000_request_flood_has_constant_evidence_growth() -> None:
    runtime = build_reference_runtime(
        max_requests_per_window=1,
        max_admitted_requests=50_000,
    )
    first = canonical_json_bytes(action(request_id="request:first"))
    assert runtime.gateway.submit_raw(first).accepted
    excess = canonical_json_bytes(action(request_id="request:excess"))
    assert not runtime.gateway.submit_raw(excess).accepted
    events_after_kill = len(runtime.ledger)
    for _ in range(49_998):
        runtime.gateway.submit_raw(excess)
    snapshot = runtime.state.snapshot()
    assert len(runtime.ledger) == events_after_kill
    assert snapshot.observed_request_count == 50_000
    assert snapshot.rejected_overload_count == 1
    assert snapshot.dropped_after_kill_count == 49_998


def test_truncation_reorder_and_tampering_fail_offline_audit() -> None:
    runtime = build_reference_runtime()
    request = action()
    authorized = runtime.gateway.submit_raw(canonical_json_bytes(request))
    runtime.executor.dispatch(
        action=request,
        decision=authorized.decision,
        now_ns=time.monotonic_ns(),
    )
    receipt, _ = finish_and_verify(runtime)
    lines = runtime.ledger.canonical_jsonl_bytes().splitlines(keepends=True)

    with pytest.raises(ValueError):
        verify_bundle(
            manifest=runtime.manifest,
            receipt=receipt,
            evidence_lines=lines[:-1],
            operator_public_key=operator_public(runtime),
        )
    with pytest.raises(ValueError):
        verify_bundle(
            manifest=runtime.manifest,
            receipt=receipt,
            evidence_lines=[lines[1], lines[0], *lines[2:]],
            operator_public_key=operator_public(runtime),
        )
    tampered = bytearray(lines[0])
    location = tampered.find(b"numpy")
    assert location >= 0
    tampered[location : location + 5] = b"scipy"
    with pytest.raises((ValueError, ValidationError)):
        verify_bundle(
            manifest=runtime.manifest,
            receipt=receipt,
            evidence_lines=[bytes(tampered), *lines[1:]],
            operator_public_key=operator_public(runtime),
        )


@pytest.mark.parametrize(
    "kind,payload",
    [
        (EventKind.DISPATCH, {"garbage": True}),
        (
            EventKind.DISPATCH,
            {
                "action_sha256": "0" * 64,
                "authorization_id": "auth:forged",
                "decision_hash": "1" * 64,
                "kill_epoch": 0,
            },
        ),
        (
            EventKind.RESULT,
            {
                "action_sha256": "0" * 64,
                "authorization_id": "auth:orphan",
                "decision_hash": "1" * 64,
                "kill_epoch": 0,
                "response_bytes": 1,
                "response_sha256": "2" * 64,
                "status_code": 200,
            },
        ),
    ],
)
def test_semantic_auditor_rejects_garbage_forgery_and_orphans(
    kind: EventKind,
    payload: dict[str, object],
) -> None:
    runtime = build_reference_runtime()
    request = action(request_id="request:semantic-probe")
    assert runtime.gateway.submit_raw(canonical_json_bytes(request)).accepted
    runtime.ledger.commit(
        runtime.supervisor.commit_observation,
        kind,
        payload,
        request_id=request.request_id,
    )
    receipt = runtime.supervisor.complete()
    with pytest.raises((ValueError, ValidationError)):
        verify_bundle(
            manifest=runtime.manifest,
            receipt=receipt,
            evidence_lines=runtime.ledger.canonical_jsonl_bytes().splitlines(
                keepends=True
            ),
            operator_public_key=operator_public(runtime),
        )


def test_operator_key_substitution_and_witness_equivocation_fail() -> None:
    runtime = build_reference_runtime()
    foreign = Ed25519PrivateKey.generate()
    foreign_public = Ed25519PublicKey.from_bytes(
        key_id=runtime.manifest.body.operator_key_id,
        value=foreign.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )
    receipt = runtime.supervisor.complete()
    with pytest.raises(ValueError, match="signature"):
        verify_bundle(
            manifest=runtime.manifest,
            receipt=receipt,
            evidence_lines=(),
            operator_public_key=foreign_public,
        )

    checkpoint = receipt.body.witness_checkpoint.body
    with pytest.raises(ValueError, match="equivocal"):
        runtime.supervisor.witness.checkpoint(
            manifest=runtime.manifest,
            event_count=checkpoint.event_count,
            final_event_hash=checkpoint.final_event_hash,
            evidence_file_sha256="f" * 64,
        )
