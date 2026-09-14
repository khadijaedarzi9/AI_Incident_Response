"""Reference runtime factory used by tests and the local demonstration."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.evidence import EvidenceLedger
from app.executor import CredentialBroker, Executor, InflightRegistry, TransportResult
from app.gateway import Gateway
from app.models import (
    CredentialGrant,
    Ed25519PublicKey,
    EgressRule,
    HttpMethod,
    KillCriteria,
    Manifest,
    ManifestBody,
    TerminationMode,
    format_utc_timestamp,
)
from app.state import RunState
from app.supervisor import IsolationResult, Supervisor, TransparencyWitness


def _public(key: Ed25519PrivateKey, key_id: str) -> Ed25519PublicKey:
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return Ed25519PublicKey.from_bytes(key_id=key_id, value=raw)


def demo_spki_pin() -> str:
    return base64.urlsafe_b64encode(b"P" * 32).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class KeyBundle:
    operator: Ed25519PrivateKey
    gateway: Ed25519PrivateKey
    supervisor: Ed25519PrivateKey
    witness: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "KeyBundle":
        return cls(
            operator=Ed25519PrivateKey.generate(),
            gateway=Ed25519PrivateKey.generate(),
            supervisor=Ed25519PrivateKey.generate(),
            witness=Ed25519PrivateKey.generate(),
        )


@dataclass
class ReferenceRuntime:
    manifest: Manifest
    keys: KeyBundle
    state: RunState
    ledger: EvidenceLedger
    supervisor: Supervisor
    gateway: Gateway
    executor: Executor
    inflight_registry: InflightRegistry
    isolated_workloads: list[str]


def build_reference_runtime(
    *,
    now: datetime | None = None,
    max_requests_per_window: int = 128,
    max_admitted_requests: int = 10_000,
    max_total_events: int = 40_000,
    max_runtime_ms: int = 3_600_000,
    max_queued_events: int = 1024,
    max_total_egress_bytes: int = 8_388_608,
) -> ReferenceRuntime:
    """Build a local reference runtime.

    Keys are process-local only for tests. Production keys must be protected by
    separate operator, gateway, supervisor and witness trust domains.
    """
    now = now or datetime.now(timezone.utc)
    keys = KeyBundle.generate()
    issued = now - timedelta(seconds=1)
    expires = now + timedelta(hours=1)
    rule = EgressRule(
        rule_id="package-read",
        host="packages.example.test",
        port=443,
        methods=(HttpMethod.POST,),
        path_prefixes=("/v1/packages",),
        resolved_ip_cidrs=("203.0.113.0/24",),
        tls_spki_sha256=(demo_spki_pin(),),
        max_requests=max_admitted_requests,
        max_request_bytes=65_536,
        max_response_bytes=1_048_576,
    )
    criteria = KillCriteria(
        max_runtime_ms=max_runtime_ms,
        max_total_events=max_total_events,
        max_admitted_requests=max_admitted_requests,
        max_inflight_requests=64,
        max_requests_per_window=max_requests_per_window,
        rate_window_ms=1_000,
        max_queued_events=max_queued_events,
        max_event_payload_bytes=262_144,
        max_total_egress_bytes=max_total_egress_bytes,
        supervisor_kill_latency_sla_ms=1_000,
    )
    body = ManifestBody(
        manifest_id="manifest:demo",
        run_id="run:demo",
        issued_at=format_utc_timestamp(issued),
        not_before=format_utc_timestamp(issued),
        expires_at=format_utc_timestamp(expires),
        operator_key_id="operator:demo",
        gateway_key=_public(keys.gateway, "gateway:demo"),
        supervisor_key=_public(keys.supervisor, "supervisor:demo"),
        witness_key=_public(keys.witness, "witness:demo"),
        allowed_egress=(rule,),
        credentials=(
            CredentialGrant(
                credential_id="credential:canary",
                broker_ref="broker:canary",
                audience="packages.example.test",
                allowed_rule_ids=("package-read",),
                scopes=("tripwire",),
                expires_at=format_utc_timestamp(expires),
                max_uses=1,
                is_canary=True,
            ),
            CredentialGrant(
                credential_id="credential:package-read",
                broker_ref="broker:package-read",
                audience="packages.example.test",
                allowed_rule_ids=("package-read",),
                scopes=("packages:read",),
                expires_at=format_utc_timestamp(expires),
                max_uses=max_admitted_requests,
            ),
        ),
        kill_criteria=criteria,
    )
    manifest = Manifest.sign(body, keys.operator)
    state = RunState(criteria)
    ledger = EvidenceLedger(
        manifest=manifest,
        producer_instance_id="gateway-instance:demo",
        max_events=max_total_events,
        max_pending_commits=criteria.max_queued_events,
    )
    isolated_workloads: list[str] = []

    def isolate() -> IsolationResult:
        isolated_workloads.append("simulation:demo")
        return IsolationResult(termination_mode=TerminationMode.SIMULATED)

    witness = TransparencyWitness(
        key=keys.witness,
        key_id=body.witness_key.key_id,
    )
    inflight_registry = InflightRegistry()
    supervisor = Supervisor(
        manifest=manifest,
        state=state,
        ledger=ledger,
        private_key=keys.supervisor,
        instance_id="supervisor-instance:demo",
        witness=witness,
        isolate=isolate,
        cancel_inflight=inflight_registry.signal_all,
    )
    gateway = Gateway(
        manifest=manifest,
        private_key=keys.gateway,
        instance_id="gateway-instance:demo",
        state=state,
        ledger=ledger,
        supervisor=supervisor,
    )

    def transport(action, secret, max_response_bytes, cancel_event):
        if cancel_event.is_set():
            raise PermissionError("transport cancelled before side effect")
        response = b'{"ok":true}'
        if len(response) > max_response_bytes:
            raise RuntimeError("response bound exceeded")
        if action.credential_id and secret != b"demo-package-secret":
            raise PermissionError("executor did not receive brokered credential")
        return TransportResult(
            status_code=200,
            response_bytes=len(response),
            response_sha256=hashlib.sha256(response).hexdigest(),
        )

    executor = Executor(
        manifest=manifest,
        state=state,
        ledger=ledger,
        broker=CredentialBroker(
            {
                "broker:package-read": b"demo-package-secret",
                "broker:canary": b"never-release-canary",
            }
        ),
        transport=transport,
        fail_closed=gateway.fail_closed,
        mirror=supervisor.commit_observation,
        inflight_registry=inflight_registry,
    )
    return ReferenceRuntime(
        manifest=manifest,
        keys=keys,
        state=state,
        ledger=ledger,
        supervisor=supervisor,
        gateway=gateway,
        executor=executor,
        inflight_registry=inflight_registry,
        isolated_workloads=isolated_workloads,
    )


__all__ = [
    "KeyBundle",
    "ReferenceRuntime",
    "build_reference_runtime",
    "demo_spki_pin",
]
