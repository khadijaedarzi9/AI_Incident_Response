"""Bounded, lock-protected run state shared with the trusted executor.

In production this state must live below the workload boundary (for example in
the egress executor or hypervisor supervisor), not in the FastAPI process.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Callable

from app.models import Decision, KillCriteria, Verdict


class RunPhase(str, Enum):
    RUNNING = "RUNNING"
    KILLING = "KILLING"
    KILLED = "KILLED"
    COMPLETED = "COMPLETED"


class Admission(str, Enum):
    ADMITTED = "ADMITTED"
    FIRST_OVERLOAD = "FIRST_OVERLOAD"
    DROPPED_AFTER_KILL = "DROPPED_AFTER_KILL"


@dataclass(frozen=True)
class CounterSnapshot:
    observed_request_count: int
    admitted_request_count: int
    allowed_request_count: int
    denied_request_count: int
    dispatched_request_count: int
    completed_request_count: int
    rejected_overload_count: int
    dropped_after_kill_count: int
    total_egress_bytes: int
    inflight: int
    kill_epoch: int
    phase: RunPhase


@dataclass(frozen=True)
class DispatchLease:
    authorization_id: str
    reserved_egress_bytes: int


class RunState:
    """Atomic authorization consumption and bounded admission counters."""

    def __init__(self, criteria: KillCriteria) -> None:
        self.criteria = criteria
        self._lock = RLock()
        self._phase = RunPhase.RUNNING
        self._kill_epoch = 0
        self._consumed_authorizations: set[str] = set()
        self._window_started_ns: int | None = None
        self._window_count = 0
        self._observed = 0
        self._admitted = 0
        self._allowed = 0
        self._denied = 0
        self._dispatched = 0
        self._completed = 0
        self._rejected_overload = 0
        self._dropped_after_kill = 0
        self._egress_bytes = 0
        self._reserved_egress_bytes = 0
        self._inflight = 0
        self._active_authorizations: dict[str, int] = {}

    def admit(self, *, raw_bytes: int, now_ns: int) -> Admission:
        """Perform fixed-cost limits before parsing or hashing."""
        with self._lock:
            self._observed += 1
            if self._phase is not RunPhase.RUNNING:
                self._dropped_after_kill += 1
                return Admission.DROPPED_AFTER_KILL

            window_ns = self.criteria.rate_window_ms * 1_000_000
            if (
                self._window_started_ns is None
                or now_ns - self._window_started_ns >= window_ns
            ):
                self._window_started_ns = now_ns
                self._window_count = 0

            would_overload = (
                raw_bytes > self.criteria.max_event_payload_bytes
                or self._admitted >= self.criteria.max_admitted_requests
                or self._window_count >= self.criteria.max_requests_per_window
                or self._inflight >= self.criteria.max_inflight_requests
            )
            if would_overload:
                self._rejected_overload += 1
                self._latch_kill_locked()
                return Admission.FIRST_OVERLOAD

            self._window_count += 1
            self._admitted += 1
            return Admission.ADMITTED

    def latch_kill(self) -> tuple[bool, int, int]:
        """Atomically transition RUNNING to KILLING and advance the epoch."""
        with self._lock:
            first = self._phase is RunPhase.RUNNING
            if first:
                self._latch_kill_locked()
            return first, self._kill_epoch, self._inflight

    def _latch_kill_locked(self) -> None:
        if self._phase is RunPhase.RUNNING:
            self._phase = RunPhase.KILLING
            self._kill_epoch += 1

    def current_epoch(self) -> int:
        with self._lock:
            return self._kill_epoch

    def record_decision(self, verdict: Verdict) -> None:
        with self._lock:
            if verdict is Verdict.ALLOW:
                self._allowed += 1
            else:
                self._denied += 1

    def begin_authorized(
        self,
        decision: Decision,
        *,
        now_ns: int,
        reserve_egress_bytes: int,
        commit_dispatch: Callable[[], None],
    ) -> DispatchLease:
        """Linearize admission and evidence without holding the lock over I/O.

        Either kill latches first and this method rejects, or authorization
        consumption and the DISPATCH evidence commit happen first. Credential
        release and transport run only after this bounded critical section.
        """
        body = decision.body
        with self._lock:
            if self._phase is not RunPhase.RUNNING:
                raise PermissionError("run is not dispatchable")
            if body.verdict != Verdict.ALLOW:
                raise PermissionError("decision is not an ALLOW capability")
            if body.kill_epoch != self._kill_epoch:
                raise PermissionError("authorization kill epoch is stale")
            if (
                body.authorization_expires_monotonic_ns is None
                or now_ns > body.authorization_expires_monotonic_ns
            ):
                raise PermissionError("authorization expired")
            authorization_id = body.authorization_id
            if authorization_id is None:
                raise PermissionError("authorization ID is absent")
            if authorization_id in self._consumed_authorizations:
                raise PermissionError("authorization was already consumed")
            if (
                reserve_egress_bytes <= 0
                or self._egress_bytes
                + self._reserved_egress_bytes
                + reserve_egress_bytes
                > self.criteria.max_total_egress_bytes
            ):
                self._latch_kill_locked()
                raise PermissionError("egress budget cannot be reserved")
            self._consumed_authorizations.add(authorization_id)
            self._dispatched += 1
            self._inflight += 1
            self._reserved_egress_bytes += reserve_egress_bytes
            self._active_authorizations[authorization_id] = reserve_egress_bytes
            try:
                commit_dispatch()
            except Exception:
                self._active_authorizations.pop(authorization_id, None)
                self._reserved_egress_bytes -= reserve_egress_bytes
                self._inflight -= 1
                self._latch_kill_locked()
                raise
            return DispatchLease(authorization_id, reserve_egress_bytes)

    def finish_authorized(
        self,
        lease: DispatchLease,
        *,
        egress_bytes: int,
        commit_result: Callable[[], None],
    ) -> None:
        with self._lock:
            reserved = self._active_authorizations.get(
                lease.authorization_id,
                None,
            )
            if reserved is None:
                raise RuntimeError("dispatch lease is not active")
            if egress_bytes < 0 or egress_bytes > reserved:
                self._latch_kill_locked()
                raise RuntimeError("transport exceeded reserved egress bytes")
            try:
                commit_result()
            except Exception:
                self._latch_kill_locked()
                raise
            self._active_authorizations.pop(lease.authorization_id)
            self._reserved_egress_bytes -= reserved
            self._inflight -= 1
            self._completed += 1
            self._egress_bytes += egress_bytes

    def abort_authorized(self, lease: DispatchLease) -> None:
        with self._lock:
            reserved = self._active_authorizations.pop(
                lease.authorization_id,
                None,
            )
            if reserved is None:
                return
            self._reserved_egress_bytes -= reserved
            self._inflight -= 1

    def mark_killed(self) -> None:
        with self._lock:
            if self._phase not in {RunPhase.KILLING, RunPhase.KILLED}:
                raise RuntimeError("cannot acknowledge kill before kill latch")
            self._phase = RunPhase.KILLED
            self._inflight = 0
            self._active_authorizations.clear()
            self._reserved_egress_bytes = 0

    def mark_completed(self) -> None:
        with self._lock:
            if self._phase is not RunPhase.RUNNING:
                raise RuntimeError("only a running run can complete")
            self._phase = RunPhase.COMPLETED

    def snapshot(self) -> CounterSnapshot:
        with self._lock:
            return CounterSnapshot(
                observed_request_count=self._observed,
                admitted_request_count=self._admitted,
                allowed_request_count=self._allowed,
                denied_request_count=self._denied,
                dispatched_request_count=self._dispatched,
                completed_request_count=self._completed,
                rejected_overload_count=self._rejected_overload,
                dropped_after_kill_count=self._dropped_after_kill,
                total_egress_bytes=self._egress_bytes,
                inflight=self._inflight,
                kill_epoch=self._kill_epoch,
                phase=self._phase,
            )


__all__ = [
    "Admission",
    "CounterSnapshot",
    "DispatchLease",
    "RunPhase",
    "RunState",
]
