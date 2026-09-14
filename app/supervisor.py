"""Independently keyed supervisor, evidence mirror, and witness checkpoint."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.evidence import EvidenceLedger
from app.models import (
    Event,
    EventKind,
    KillAcknowledgement,
    KillAcknowledgementBody,
    Manifest,
    Receipt,
    ReceiptBody,
    RunStatus,
    TerminationMode,
    WitnessCheckpoint,
    WitnessCheckpointBody,
    canonical_json_bytes,
    format_utc_timestamp,
)
from app.state import RunPhase, RunState


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class IsolationResult:
    """Facts returned by the isolation backend, never inferred by Supervisor."""

    termination_mode: TerminationMode
    terminated_workload_ids: tuple[str, ...] = ()
    inflight_cancelled: int = 0
    network_isolation_confirmed: bool = False
    isolation_evidence_sha256: str | None = None


class EvidenceMirror:
    """O(1)-memory independent observation of committed event heads."""

    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        self._lock = RLock()
        self._digest = hashlib.sha256()
        self._count = 0
        self._first_hash: str | None = None
        self._final_hash: str | None = None
        self._last_sequence: int | None = None
        self._last_monotonic_ns: int | None = None

    def observe(self, event: Event) -> None:
        with self._lock:
            body = event.body
            if (
                body.run_id != self.manifest.body.run_id
                or body.manifest_hash != self.manifest.manifest_hash
            ):
                raise ValueError("mirrored event belongs to another run")
            if self._count == 0:
                if body.sequence != 0:
                    raise ValueError("mirror must begin at sequence zero")
                self._first_hash = event.event_hash
            else:
                assert self._last_sequence is not None
                assert self._last_monotonic_ns is not None
                if body.sequence != self._last_sequence + 1:
                    raise ValueError("mirror observed a sequence gap")
                if body.previous_event_hash != self._final_hash:
                    raise ValueError("mirror observed a chain fork")
                if body.monotonic_ns < self._last_monotonic_ns:
                    raise ValueError("mirror observed monotonic time reversal")
            self._digest.update(canonical_json_bytes(event))
            self._digest.update(b"\n")
            self._count += 1
            self._last_sequence = body.sequence
            self._last_monotonic_ns = body.monotonic_ns
            self._final_hash = event.event_hash

    def snapshot(self) -> tuple[int, str | None, str | None, str]:
        with self._lock:
            return (
                self._count,
                self._first_hash,
                self._final_hash,
                self._digest.copy().hexdigest(),
            )


class TransparencyWitness:
    """Reference one-time run registry.

    A production witness must be operated independently and expose inclusion
    and consistency proofs. This class demonstrates refusal to sign two roots
    for the same manifest.
    """

    def __init__(
        self,
        *,
        key: Ed25519PrivateKey,
        key_id: str,
        wall_clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.key = key
        self.key_id = key_id
        self.wall_clock = wall_clock
        self._lock = RLock()
        self._run_roots: dict[tuple[str, str], WitnessCheckpoint] = {}

    def checkpoint(
        self,
        *,
        manifest: Manifest,
        event_count: int,
        final_event_hash: str | None,
        evidence_file_sha256: str,
    ) -> WitnessCheckpoint:
        body = WitnessCheckpointBody(
            run_id=manifest.body.run_id,
            manifest_hash=manifest.manifest_hash,
            witness_key_id=self.key_id,
            witnessed_at=format_utc_timestamp(self.wall_clock()),
            event_count=event_count,
            final_event_hash=final_event_hash,
            evidence_file_sha256=evidence_file_sha256,
        )
        checkpoint = WitnessCheckpoint.sign(body, self.key)
        registry_key = (body.run_id, body.manifest_hash)
        with self._lock:
            existing = self._run_roots.get(registry_key)
            if existing is not None:
                prior = existing.body
                same_root = (
                    prior.event_count == body.event_count
                    and prior.final_event_hash == body.final_event_hash
                    and prior.evidence_file_sha256 == body.evidence_file_sha256
                )
                if not same_root:
                    raise ValueError("witness refuses an equivocal root for this run")
                return existing
            self._run_roots[registry_key] = checkpoint
        return checkpoint


class Supervisor:
    """Reference control-plane supervisor outside the workload trust domain."""

    def __init__(
        self,
        *,
        manifest: Manifest,
        state: RunState,
        ledger: EvidenceLedger,
        private_key: Ed25519PrivateKey,
        instance_id: str,
        witness: TransparencyWitness,
        isolate: Callable[[], IsolationResult],
        cancel_inflight: Callable[[], int] = lambda: 0,
        wall_clock: Callable[[], datetime] = _utc_now,
        monotonic_clock: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.manifest = manifest
        self.state = state
        self.ledger = ledger
        self.private_key = private_key
        self.instance_id = instance_id
        self.witness = witness
        self.isolate = isolate
        self.cancel_inflight = cancel_inflight
        self.wall_clock = wall_clock
        self.monotonic_clock = monotonic_clock
        self.mirror = EvidenceMirror(manifest)
        self.started_at = wall_clock()
        self.started_monotonic_ns = monotonic_clock()
        self.kill_acknowledgement: KillAcknowledgement | None = None
        self._contain_lock = RLock()
        self._emergency_failure = False
        self._isolation_done = False
        self._isolation_result: IsolationResult | None = None
        self._receipt: Receipt | None = None
        self._receipt_lock = RLock()

    def commit_observation(self, event: Event) -> Event:
        self.mirror.observe(event)
        return event

    def contain(
        self,
        *,
        trigger_event: Event,
        trigger_monotonic_ns: int,
    ) -> KillAcknowledgement:
        with self._contain_lock:
            return self._contain_locked(
                trigger_event=trigger_event,
                trigger_monotonic_ns=trigger_monotonic_ns,
            )

    def _contain_locked(
        self,
        *,
        trigger_event: Event,
        trigger_monotonic_ns: int,
    ) -> KillAcknowledgement:
        if self.kill_acknowledgement is not None:
            return self.kill_acknowledgement
        _, _, inflight = self.state.latch_kill()
        cancellation_signals = self.cancel_inflight()
        requested_at = self.wall_clock()
        requested_ns = self.monotonic_clock()

        # The trusted isolate callback represents network cut first, identity
        # revocation, and workload termination through an out-of-band handle.
        if not self._isolation_done:
            self._isolation_result = self.isolate()
            self._isolation_done = True
        assert self._isolation_result is not None
        isolation = self._isolation_result
        acknowledged_ns = self.monotonic_clock()
        acknowledged_at = self.wall_clock()
        self.state.mark_killed()

        body = KillAcknowledgementBody(
            run_id=self.manifest.body.run_id,
            manifest_hash=self.manifest.manifest_hash,
            supervisor_key_id=self.manifest.body.supervisor_key.key_id,
            supervisor_instance_id=self.instance_id,
            trigger_event_sequence=trigger_event.body.sequence,
            trigger_event_hash=trigger_event.event_hash,
            trigger_monotonic_ns=trigger_monotonic_ns,
            kill_requested_at=format_utc_timestamp(requested_at),
            kill_requested_monotonic_ns=requested_ns,
            kill_acknowledged_at=format_utc_timestamp(acknowledged_at),
            kill_acknowledged_monotonic_ns=acknowledged_ns,
            kill_latency_ns=acknowledged_ns - trigger_monotonic_ns,
            termination_mode=isolation.termination_mode,
            terminated_workload_ids=tuple(
                sorted(set(isolation.terminated_workload_ids))
            ),
            inflight_at_trigger=inflight,
            inflight_cancel_signalled=min(cancellation_signals, inflight),
            inflight_cancelled=isolation.inflight_cancelled,
            network_isolation_confirmed=isolation.network_isolation_confirmed,
            isolation_evidence_sha256=isolation.isolation_evidence_sha256,
        )
        acknowledgement = KillAcknowledgement.sign(body, self.private_key)
        self.kill_acknowledgement = acknowledgement
        try:
            self.ledger.commit(
                self.commit_observation,
                EventKind.KILL_ACKNOWLEDGED,
                acknowledgement,
                monotonic_ns=acknowledged_ns,
            )
        except Exception:
            self._emergency_failure = True
            self.kill_acknowledgement = None
            raise
        return acknowledgement

    def emergency_isolate(self) -> None:
        """Contain even when no trustworthy evidence event can be committed."""
        with self._contain_lock:
            self._emergency_failure = True
            self.state.latch_kill()
            if not self._isolation_done:
                self._isolation_result = self.isolate()
                self._isolation_done = True
            self.state.mark_killed()

    def complete(self) -> Receipt:
        """Complete a running reference run through the trusted control plane."""
        self.state.mark_completed()
        return self.receipt()

    def enforce_runtime_deadline(self, *, monotonic_ns: int | None = None) -> bool:
        """Watchdog hook: contain a still-running workload after its deadline."""
        now_ns = self.monotonic_clock() if monotonic_ns is None else monotonic_ns
        deadline_ns = (
            self.started_monotonic_ns
            + self.manifest.body.kill_criteria.max_runtime_ms * 1_000_000
        )
        if self.state.snapshot().phase != RunPhase.RUNNING or now_ns <= deadline_ns:
            return False
        self.state.latch_kill()
        event = self.ledger.commit(
            self.commit_observation,
            EventKind.VIOLATION,
            {"reason_code": "runtime.budget_exhausted"},
            monotonic_ns=now_ns,
        )
        self.contain(trigger_event=event, trigger_monotonic_ns=now_ns)
        return True

    def receipt(self, *, status: RunStatus | None = None) -> Receipt:
        with self._receipt_lock:
            return self._receipt_locked(status=status)

    def _receipt_locked(self, *, status: RunStatus | None = None) -> Receipt:
        if self._receipt is not None:
            if status is not None and status != self._receipt.body.status:
                raise ValueError("receipt status conflicts with frozen receipt")
            return self._receipt
        snapshot = self.state.snapshot()
        if snapshot.phase in {RunPhase.RUNNING, RunPhase.KILLING}:
            raise RuntimeError("receipt requires a terminal run state")
        if self._emergency_failure:
            derived_status = RunStatus.SUPERVISOR_FAILURE
        elif snapshot.phase is RunPhase.KILLED:
            derived_status = RunStatus.KILLED
        elif snapshot.phase is RunPhase.COMPLETED:
            derived_status = RunStatus.COMPLETED
        else:  # pragma: no cover - enum exhaustiveness
            raise RuntimeError("unsupported terminal run state")
        if status is not None and status != derived_status:
            raise ValueError("requested receipt status conflicts with run state")
        status = derived_status
        self.ledger.seal()
        finished_at = self.wall_clock()
        finished_ns = self.monotonic_clock()
        event_count, first_hash, final_hash, evidence_digest = self.mirror.snapshot()
        checkpoint = self.witness.checkpoint(
            manifest=self.manifest,
            event_count=event_count,
            final_event_hash=final_hash,
            evidence_file_sha256=evidence_digest,
        )
        body = ReceiptBody(
            run_id=self.manifest.body.run_id,
            manifest_hash=self.manifest.manifest_hash,
            supervisor_key_id=self.manifest.body.supervisor_key.key_id,
            supervisor_instance_id=self.instance_id,
            status=status,
            started_at=format_utc_timestamp(self.started_at),
            finished_at=format_utc_timestamp(finished_at),
            started_monotonic_ns=self.started_monotonic_ns,
            finished_monotonic_ns=finished_ns,
            event_count=event_count,
            first_event_hash=first_hash,
            final_event_hash=final_hash,
            evidence_file_sha256=evidence_digest,
            observed_request_count=snapshot.observed_request_count,
            admitted_request_count=snapshot.admitted_request_count,
            allowed_request_count=snapshot.allowed_request_count,
            denied_request_count=snapshot.denied_request_count,
            dispatched_request_count=snapshot.dispatched_request_count,
            completed_request_count=snapshot.completed_request_count,
            rejected_overload_count=snapshot.rejected_overload_count,
            dropped_after_kill_count=snapshot.dropped_after_kill_count,
            total_egress_bytes=snapshot.total_egress_bytes,
            kill_acknowledgement=self.kill_acknowledgement,
            witness_checkpoint=checkpoint,
        )
        self._receipt = Receipt.sign(body, self.private_key)
        return self._receipt


__all__ = [
    "EvidenceMirror",
    "IsolationResult",
    "Supervisor",
    "TransparencyWitness",
]
