"""FastAPI demonstration adapter.

This adapter is intentionally not part of the trusted security claim. A real
deployment places kernel/hypervisor admission and the executor below it.
"""

from __future__ import annotations

import hmac
import time

from fastapi import FastAPI, Request
from fastapi.responses import Response

from app.factory import ReferenceRuntime, build_reference_runtime
from app.models import canonical_json


def _json_response(value: object, *, status_code: int = 200) -> Response:
    return Response(
        content=canonical_json(value),
        status_code=status_code,
        media_type="application/json",
    )


async def _bounded_body(request: Request, runtime: ReferenceRuntime) -> bytes:
    """Reject declared or streamed overflow before constructing an Action."""
    limit = runtime.manifest.body.kill_criteria.max_event_payload_bytes
    content_length = request.headers.get("content-length")
    if content_length is None:
        raise ValueError("content-length is required")
    try:
        declared = int(content_length)
    except ValueError as exc:
        raise ValueError("content-length is invalid") from exc
    if declared < 0 or declared > limit:
        raise OverflowError("request body exceeds admission limit")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise OverflowError("request body exceeds admission limit")
    if len(body) != declared:
        raise ValueError("content-length does not match streamed body")
    return bytes(body)


def create_agent_app(runtime: ReferenceRuntime) -> FastAPI:
    app = FastAPI(
        title="BCP-1 agent-facing reference adapter",
        description="Demonstration only; FastAPI is not the containment boundary.",
        version="1.0.0",
    )

    @app.post("/v1/dispatch")
    async def dispatch(request: Request) -> Response:
        if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
            runtime.gateway.fail_closed("request.content_type_invalid", None)
            return _json_response(
                {"accepted": False, "reason_code": "request.content_type_invalid"},
                status_code=415,
            )
        try:
            raw = await _bounded_body(request, runtime)
        except OverflowError:
            runtime.gateway.fail_closed("admission.body_too_large", None)
            return _json_response(
                {"accepted": False, "reason_code": "admission.body_too_large"},
                status_code=413,
            )
        except ValueError:
            runtime.gateway.fail_closed("request.length_invalid", None)
            return _json_response(
                {"accepted": False, "reason_code": "request.length_invalid"},
                status_code=400,
            )
        authorized = runtime.gateway.submit_raw(raw)
        if not authorized.accepted:
            return _json_response(
                {
                    "accepted": False,
                    "reason_code": authorized.reason_code,
                    "phase": runtime.state.snapshot().phase.value,
                },
                status_code=403,
            )
        assert authorized.action is not None and authorized.decision is not None
        result = runtime.executor.dispatch(
            action=authorized.action,
            decision=authorized.decision,
            now_ns=time.monotonic_ns(),
        )
        return _json_response(
            {
                "accepted": True,
                "decision_hash": authorized.decision.decision_hash,
                "response_bytes": result.response_bytes,
                "response_sha256": result.response_sha256,
                "status_code": result.status_code,
            }
        )

    @app.get("/v1/status")
    async def status() -> Response:
        snapshot = runtime.state.snapshot()
        return _json_response(
            {
                "counters": {
                    "admitted": snapshot.admitted_request_count,
                    "allowed": snapshot.allowed_request_count,
                    "denied": snapshot.denied_request_count,
                    "dispatched": snapshot.dispatched_request_count,
                    "dropped_after_kill": snapshot.dropped_after_kill_count,
                    "observed": snapshot.observed_request_count,
                    "overload": snapshot.rejected_overload_count,
                },
                "kill_epoch": snapshot.kill_epoch,
                "phase": snapshot.phase.value,
            }
        )

    return app


def create_control_app(runtime: ReferenceRuntime, *, bearer_token: str) -> FastAPI:
    if not bearer_token:
        raise ValueError("control bearer token must not be empty")
    app = FastAPI(
        title="BCP-1 privileged reference control plane",
        description="Bind to a supervisor-only listener outside the agent network.",
        version="1.0.0",
    )

    def authenticated(request: Request) -> bool:
        supplied = request.headers.get("authorization", "")
        expected = f"Bearer {bearer_token}"
        return hmac.compare_digest(supplied.encode(), expected.encode())

    @app.post("/v1/complete")
    async def complete(request: Request) -> Response:
        if not authenticated(request):
            return _json_response({"error": "unauthorized"}, status_code=401)
        try:
            receipt = runtime.supervisor.complete()
        except RuntimeError as exc:
            return _json_response({"error": str(exc)}, status_code=409)
        return _json_response(receipt)

    @app.get("/v1/receipt")
    async def receipt(request: Request) -> Response:
        if not authenticated(request):
            return _json_response({"error": "unauthorized"}, status_code=401)
        try:
            value = runtime.supervisor.receipt()
        except RuntimeError as exc:
            return _json_response({"error": str(exc)}, status_code=409)
        return _json_response(value)

    return app


def create_app(runtime: ReferenceRuntime) -> FastAPI:
    """Backward-compatible name for the agent-facing app only."""
    return create_agent_app(runtime)


# Local demonstration only. These keys share one process and therefore do not
# satisfy BCP-1's independent-key deployment requirement.
app = create_agent_app(build_reference_runtime())


__all__ = ["app", "create_agent_app", "create_app", "create_control_app"]
