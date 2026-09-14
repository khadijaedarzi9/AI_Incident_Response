"""Bounded canonical JSONL evidence ledger."""

from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import BoundedSemaphore, RLock
from typing import Any, Callable, Iterable

from app.models import (
    GENESIS_HASH,
    Event,
    EventKind,
    Manifest,
    canonical_json_bytes,
    format_utc_timestamp,
)


WallClock = Callable[[], datetime]
MonotonicClock = Callable[[], int]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceLedger:
    """Append-only ledger with optional fsync-backed WAL.

    The in-memory copy is bounded and exists for the reference implementation.
    Production deployments should mirror each committed head to a separately
    protected supervisor and use durable storage on another failure domain.
    """

    def __init__(
        self,
        *,
        manifest: Manifest,
        producer_instance_id: str,
        max_events: int,
        max_pending_commits: int | None = None,
        wal_path: Path | None = None,
        wall_clock: WallClock = utc_now,
        monotonic_clock: MonotonicClock = time.monotonic_ns,
    ) -> None:
        self.manifest = manifest
        self.producer_instance_id = producer_instance_id
        self.max_events = max_events
        self.max_pending_commits = max_pending_commits or max_events
        self._commit_slots = BoundedSemaphore(self.max_pending_commits)
        self.wal_path = wal_path
        self.wall_clock = wall_clock
        self.monotonic_clock = monotonic_clock
        self._events: list[Event] = []
        self._lock = RLock()
        self._sealed = False
        if wal_path is not None:
            wal_path.parent.mkdir(parents=True, exist_ok=True)
            if wal_path.exists() and wal_path.stat().st_size:
                raise ValueError("WAL path must be new and empty")

    def append(
        self,
        kind: EventKind,
        payload: Any,
        *,
        request_id: str | None = None,
        observed_at: datetime | None = None,
        monotonic_ns: int | None = None,
    ) -> Event:
        with self._lock:
            if self._sealed:
                raise RuntimeError("evidence ledger is sealed")
            if len(self._events) >= self.max_events:
                raise BufferError("evidence ledger event budget exhausted")
            previous_hash = (
                self._events[-1].event_hash if self._events else GENESIS_HASH
            )
            event = Event.create(
                payload=payload,
                run_id=self.manifest.body.run_id,
                manifest_hash=self.manifest.manifest_hash,
                sequence=len(self._events),
                previous_event_hash=previous_hash,
                kind=kind,
                producer_instance_id=self.producer_instance_id,
                observed_at=format_utc_timestamp(observed_at or self.wall_clock()),
                monotonic_ns=(
                    monotonic_ns
                    if monotonic_ns is not None
                    else self.monotonic_clock()
                ),
                request_id=request_id,
            )
            encoded = canonical_json_bytes(event) + b"\n"
            if self.wal_path is not None:
                with self.wal_path.open("ab", buffering=0) as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
            self._events.append(event)
            return event

    def commit(
        self,
        observer: Callable[[Event], Any],
        kind: EventKind,
        payload: Any,
        *,
        request_id: str | None = None,
        observed_at: datetime | None = None,
        monotonic_ns: int | None = None,
    ) -> Event:
        """Serialize WAL append and independent-head observation."""
        if not self._commit_slots.acquire(blocking=False):
            raise BufferError("evidence commit queue budget exhausted")
        try:
            with self._lock:
                event = self.append(
                    kind,
                    payload,
                    request_id=request_id,
                    observed_at=observed_at,
                    monotonic_ns=monotonic_ns,
                )
                observer(event)
                return event
        finally:
            self._commit_slots.release()

    def events(self) -> tuple[Event, ...]:
        with self._lock:
            return tuple(self._events)

    def seal(self) -> None:
        """Prevent evidence mutation before a terminal receipt snapshots roots."""
        with self._lock:
            self._sealed = True

    def canonical_jsonl_bytes(self) -> bytes:
        with self._lock:
            return b"".join(canonical_json_bytes(event) + b"\n" for event in self._events)

    def evidence_digest(self) -> str:
        return hashlib.sha256(self.canonical_jsonl_bytes()).hexdigest()

    def first_hash(self) -> str | None:
        with self._lock:
            return self._events[0].event_hash if self._events else None

    def final_hash(self) -> str | None:
        with self._lock:
            return self._events[-1].event_hash if self._events else None

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


def iter_canonical_jsonl(lines: Iterable[bytes | str]) -> Iterable[Event]:
    """Stream canonical events without retaining the chain in memory."""
    for line_number, line in enumerate(lines, start=1):
        if isinstance(line, bytes):
            raw = line
        else:
            raw = line.encode("utf-8")
        if not raw.endswith(b"\n"):
            raise ValueError(f"line {line_number}: missing canonical newline")
        event_raw = raw[:-1]
        event = Event.model_validate_json(event_raw)
        if canonical_json_bytes(event) != event_raw:
            raise ValueError(f"line {line_number}: event is not canonical JSON")
        yield event


__all__ = ["EvidenceLedger", "iter_canonical_jsonl", "utc_now"]
