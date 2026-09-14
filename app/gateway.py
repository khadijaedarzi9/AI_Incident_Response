"""Race-aware authorization gateway.

FastAPI may expose this object, but the security claim starts at the external
gateway/executor boundary described in STANDARD.md.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.action import Action
from app.evidence import EvidenceLedger
from app.models import (
    Decision,
    DecisionBody,
    Event,
    EventKind,
    Manifest,
    Verdict,
    format_utc_timestamp,
)
from app.policy import PolicyEngine
from app.state import Admission, RunState
from app.supervisor import Supervisor


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class GatewayResult:
    accepted: bool
    reason_code: str
    action: Action | None = None
    decision: Decision | None = None


class Gateway:
    def __init__(
        self,
        *,
        manifest: Manifest,
        private_key: Ed25519PrivateKey,
        instance_id: str,
        state: RunState,
        ledger: EvidenceLedger,
        supervisor: Supervisor,
        policy: PolicyEngine | None = None,
        wall_clock: Callable[[], datetime] = _utc_now,
        monotonic_clock: Callable[[], int] = time.monotonic_ns,
        authorization_ttl_ns: int = 1_000_000_000,
    ) -> None:
        self.manifest = manifest
        self.private_key = private_key
        self.instance_id = instance_id
        self.state = state
        self.ledger = ledger
        self.supervisor = supervisor
        self.policy = policy or PolicyEngine(manifest)
        self.wall_clock = wall_clock
        self.monotonic_clock = monotonic_clock
        self.authorization_ttl_ns = authorization_ttl_ns
        self._overload_event: Event | None = None

    def _commit(
        self,
        kind: EventKind,
        payload: object,
        *,
        request_id: str | None = None,
        monotonic_ns: int | None = None,
    ) -> Event:
        try:
            return self.ledger.commit(
                self.supervisor.commit_observation,
                kind,
                payload,
                request_id=request_id,
                monotonic_ns=monotonic_ns,
            )
        except Exception:
            self.supervisor.emergency_isolate()
            raise

    def submit_raw(self, raw: bytes) -> GatewayResult:
        admitted_ns = self.monotonic_clock()
        runtime_limit_ns = (
            self.manifest.body.kill_criteria.max_runtime_ms * 1_000_000
        )
        if admitted_ns - self.supervisor.started_monotonic_ns > runtime_limit_ns:
            self.state.latch_kill()
            event = self._commit(
                EventKind.VIOLATION,
                {"reason_code": "runtime.budget_exhausted"},
                monotonic_ns=admitted_ns,
            )
            self.supervisor.contain(
                trigger_event=event,
                trigger_monotonic_ns=admitted_ns,
            )
            return GatewayResult(False, "runtime.budget_exhausted")
        admission = self.state.admit(raw_bytes=len(raw), now_ns=admitted_ns)
        if admission is Admission.DROPPED_AFTER_KILL:
            return GatewayResult(False, "run.not_dispatchable")
        if admission is Admission.FIRST_OVERLOAD:
            event = self._commit(
                EventKind.OVERLOAD_SUMMARY,
                {
                    "first_excess_monotonic_ns": admitted_ns,
                    "raw_bytes": len(raw),
                    "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    "reason_code": "admission.overload",
                },
                monotonic_ns=admitted_ns,
            )
            self._overload_event = event
            self.supervisor.contain(
                trigger_event=event,
                trigger_monotonic_ns=admitted_ns,
            )
            return GatewayResult(False, "admission.overload")

        try:
            action = Action.from_wire(raw)
        except Exception:
            event = self._commit(
                EventKind.VIOLATION,
                {
                    "raw_bytes": len(raw),
                    "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    "reason_code": "request.ambiguous_or_invalid",
                },
                monotonic_ns=admitted_ns,
            )
            self.state.latch_kill()
            self.supervisor.contain(
                trigger_event=event,
                trigger_monotonic_ns=admitted_ns,
            )
            return GatewayResult(False, "request.ambiguous_or_invalid")

        request_event = self._commit(
            EventKind.REQUEST,
            {"action": action, "action_sha256": action.digest()},
            request_id=action.request_id,
            monotonic_ns=admitted_ns,
        )
        decided_ns = self.monotonic_clock()
        decided_at = format_utc_timestamp(self.wall_clock())
        result = self.policy.authorize(action, now_timestamp=decided_at)
        if result.verdict is Verdict.KILL:
            self.state.latch_kill()
        kill_epoch = self.state.current_epoch()

        authorization_id = None
        authorization_expiry = None
        authorization_max_uses = None
        if result.verdict is Verdict.ALLOW:
            authorization_id = "auth:" + secrets.token_hex(16)
            authorization_expiry = decided_ns + self.authorization_ttl_ns
            authorization_max_uses = 1

        decision = Decision.sign(
            DecisionBody(
                run_id=self.manifest.body.run_id,
                manifest_hash=self.manifest.manifest_hash,
                request_id=action.request_id,
                request_event_sequence=request_event.body.sequence,
                request_event_hash=request_event.event_hash,
                action_sha256=action.digest(),
                gateway_key_id=self.manifest.body.gateway_key.key_id,
                gateway_instance_id=self.instance_id,
                decided_at=decided_at,
                decision_monotonic_ns=decided_ns,
                kill_epoch=kill_epoch,
                verdict=result.verdict,
                reason_code=result.reason_code,
                matched_rule_id=result.matched_rule_id,
                hard_violation=result.hard_violation,
                authorization_id=authorization_id,
                authorization_expires_monotonic_ns=authorization_expiry,
                authorization_max_uses=authorization_max_uses,
            ),
            self.private_key,
        )
        decision_event = self._commit(
            EventKind.DECISION,
            decision,
            request_id=action.request_id,
            monotonic_ns=decided_ns,
        )
        self.state.record_decision(result.verdict)

        if result.verdict is Verdict.KILL:
            violation = self._commit(
                EventKind.VIOLATION,
                {
                    "action_sha256": action.digest(),
                    "decision_hash": decision.decision_hash,
                    "reason_code": result.reason_code,
                },
                request_id=action.request_id,
            )
            self.supervisor.contain(
                trigger_event=violation,
                trigger_monotonic_ns=violation.body.monotonic_ns,
            )
            return GatewayResult(
                False,
                result.reason_code,
                action=action,
                decision=decision,
            )

        # Returning the signed Decision is capability issuance. It happens only
        # after the decision event has been committed and independently mirrored.
        return GatewayResult(
            True,
            result.reason_code,
            action=action,
            decision=decision,
        )

    def fail_closed(self, reason_code: str, request_id: str | None) -> None:
        trigger_ns = self.monotonic_clock()
        self.state.latch_kill()
        try:
            trigger = self._commit(
                EventKind.VIOLATION,
                {"reason_code": reason_code},
                request_id=request_id,
                monotonic_ns=trigger_ns,
            )
        except Exception:
            events = self.ledger.events()
            if not events:
                raise RuntimeError(
                    "evidence failed before any trusted trigger could be recorded"
                )
            trigger = events[-1]
        self.supervisor.contain(
            trigger_event=trigger,
            trigger_monotonic_ns=trigger_ns,
        )


__all__ = ["Gateway", "GatewayResult"]
