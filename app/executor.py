"""Trusted dispatch executor and credential broker interfaces."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Event as ThreadEvent, RLock
from typing import Callable, Mapping

from app.action import Action
from app.evidence import EvidenceLedger
from app.models import Decision, Event, EventKind, Manifest
from app.state import RunState


@dataclass(frozen=True)
class TransportResult:
    status_code: int
    response_bytes: int
    response_sha256: str


Transport = Callable[[Action, bytes | None, int, ThreadEvent], TransportResult]
FailClosed = Callable[[str, str | None], None]
Mirror = Callable[[Event], Event]


class InflightRegistry:
    """Cancellation handles shared with the out-of-band supervisor."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._events: dict[str, ThreadEvent] = {}

    def register(self, authorization_id: str) -> ThreadEvent:
        with self._lock:
            if authorization_id in self._events:
                raise RuntimeError("inflight authorization is already registered")
            event = ThreadEvent()
            self._events[authorization_id] = event
            return event

    def unregister(self, authorization_id: str) -> None:
        with self._lock:
            self._events.pop(authorization_id, None)

    def signal_all(self) -> int:
        with self._lock:
            events = tuple(self._events.values())
            for event in events:
                event.set()
            return len(events)


class CredentialBroker:
    """Secret store available only to the trusted executor."""

    def __init__(self, secrets: Mapping[str, bytes]) -> None:
        self._secrets = {key: bytes(value) for key, value in secrets.items()}

    def release(self, *, manifest: Manifest, action: Action) -> bytes | None:
        if action.credential_id is None:
            return None
        grant = next(
            (
                item
                for item in manifest.body.credentials
                if item.credential_id == action.credential_id
            ),
            None,
        )
        if grant is None or grant.is_canary or grant.audience != action.host:
            raise PermissionError("credential is not releasable for this action")
        try:
            return self._secrets[grant.broker_ref]
        except KeyError as exc:
            raise PermissionError("credential broker reference is unavailable") from exc


class Executor:
    """Verifies and atomically consumes a signed one-use dispatch decision."""

    def __init__(
        self,
        *,
        manifest: Manifest,
        state: RunState,
        ledger: EvidenceLedger,
        broker: CredentialBroker,
        transport: Transport,
        fail_closed: FailClosed,
        mirror: Mirror,
        inflight_registry: InflightRegistry | None = None,
    ) -> None:
        self.manifest = manifest
        self.state = state
        self.ledger = ledger
        self.broker = broker
        self.transport = transport
        self.fail_closed = fail_closed
        self.mirror = mirror
        self.inflight_registry = inflight_registry or InflightRegistry()

    def dispatch(
        self,
        *,
        action: Action,
        decision: Decision,
        now_ns: int,
    ) -> TransportResult:
        decision.verify(self.manifest.body.gateway_key)
        body = decision.body
        if (
            body.run_id != self.manifest.body.run_id
            or body.manifest_hash != self.manifest.manifest_hash
            or body.request_id != action.request_id
            or body.action_sha256 != action.digest()
        ):
            raise PermissionError("decision is not bound to this action and run")

        rule = next(
            item
            for item in self.manifest.body.allowed_egress
            if item.rule_id == body.matched_rule_id
        )

        authorization_id = body.authorization_id
        if authorization_id is None:
            raise PermissionError("decision has no authorization ID")
        cancel_event = self.inflight_registry.register(authorization_id)

        def commit_dispatch() -> None:
            self.ledger.commit(
                self.mirror,
                EventKind.DISPATCH,
                {
                    "action_sha256": action.digest(),
                    "authorization_id": body.authorization_id,
                    "decision_hash": decision.decision_hash,
                    "kill_epoch": body.kill_epoch,
                },
                request_id=action.request_id,
            )

        lease = None
        try:
            lease = self.state.begin_authorized(
                decision,
                now_ns=now_ns,
                reserve_egress_bytes=rule.max_response_bytes,
                commit_dispatch=commit_dispatch,
            )
            secret = self.broker.release(manifest=self.manifest, action=action)
            result = self.transport(
                action,
                secret,
                rule.max_response_bytes,
                cancel_event,
            )
            if result.response_bytes > rule.max_response_bytes:
                raise RuntimeError("transport exceeded response byte bound")

            def commit_result() -> None:
                self.ledger.commit(
                    self.mirror,
                    EventKind.RESULT,
                    {
                        "action_sha256": action.digest(),
                        "authorization_id": body.authorization_id,
                        "decision_hash": decision.decision_hash,
                        "kill_epoch": body.kill_epoch,
                        "response_bytes": result.response_bytes,
                        "response_sha256": result.response_sha256,
                        "status_code": result.status_code,
                    },
                    request_id=action.request_id,
                )

            self.state.finish_authorized(
                lease,
                egress_bytes=result.response_bytes,
                commit_result=commit_result,
            )
        except Exception:
            if lease is not None:
                self.state.abort_authorized(lease)
            if cancel_event.is_set():
                raise PermissionError("dispatch cancelled by containment")
            self.fail_closed("executor.atomic_dispatch_failed", action.request_id)
            raise
        finally:
            self.inflight_registry.unregister(authorization_id)
        return result


__all__ = [
    "CredentialBroker",
    "Executor",
    "InflightRegistry",
    "Transport",
    "TransportResult",
]
