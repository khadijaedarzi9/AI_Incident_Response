"""Normalized executor actions.

The agent never supplies a URL string to a generic HTTP client.  It supplies
this closed structure; policy and executor consume the same validated object.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from pathlib import PurePosixPath
from typing import Any, Literal, Self

from pydantic import Field, StringConstraints, field_validator, model_validator
from typing_extensions import Annotated

from app.models import (
    ContractModel,
    HttpMethod,
    OpaqueId,
    Port,
    SafeNonNegativeInt,
    Sha256Hex,
    canonical_json,
    domain_hash,
    parse_canonical_json,
    payload_sha256,
)


_HOST_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$"
)
_SPKI_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
NormalizedHost = Annotated[str, StringConstraints(strict=True, min_length=1)]


class Action(ContractModel):
    """The sole action shape accepted by the trusted executor."""

    request_id: OpaqueId
    method: HttpMethod
    scheme: Literal["https"] = "https"
    host: NormalizedHost
    port: Port
    path: str
    resolved_ip: str
    tls_spki_sha256: str
    body_canonical_json: str
    body_sha256: Sha256Hex
    body_bytes: SafeNonNegativeInt
    credential_id: OpaqueId | None = None
    redirects: Literal[False] = False

    @field_validator("host")
    @classmethod
    def host_is_exact_ascii_origin(cls, value: str) -> str:
        if (
            value != value.lower()
            or value.endswith(".")
            or "*" in value
            or not _HOST_RE.fullmatch(value)
        ):
            raise ValueError("host must be an exact lowercase ASCII DNS name")
        return value

    @field_validator("path")
    @classmethod
    def path_is_unambiguous(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or any(token in value for token in ("\\", "%", "?", "#"))
            or "//" in value
            or any(part in {".", ".."} for part in value.split("/"))
        ):
            raise ValueError("path is ambiguous or not normalized")
        if value != "/" and str(PurePosixPath(value)) != value.rstrip("/"):
            raise ValueError("path is not in canonical POSIX form")
        return value

    @field_validator("resolved_ip")
    @classmethod
    def ip_is_canonical(cls, value: str) -> str:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("resolved_ip must be an IP address") from exc
        if parsed.compressed != value:
            raise ValueError(f"resolved_ip must use canonical form {parsed.compressed}")
        return value

    @field_validator("tls_spki_sha256")
    @classmethod
    def spki_is_canonical_sha256(cls, value: str) -> str:
        if not _SPKI_RE.fullmatch(value):
            raise ValueError("TLS SPKI pin must be unpadded base64url SHA-256")
        decoded = base64.urlsafe_b64decode(value + "=")
        if len(decoded) != 32:
            raise ValueError("TLS SPKI pin must decode to 32 bytes")
        return value

    @field_validator("body_canonical_json")
    @classmethod
    def body_is_canonical(cls, value: str) -> str:
        parsed = parse_canonical_json(value)
        if canonical_json(parsed) != value:
            raise ValueError("body_canonical_json is not canonical")
        return value

    @model_validator(mode="after")
    def body_binding_is_correct(self) -> Self:
        encoded = self.body_canonical_json.encode("utf-8")
        if len(encoded) != self.body_bytes:
            raise ValueError("body_bytes does not match canonical body")
        if payload_sha256(self.body_canonical_json) != self.body_sha256:
            raise ValueError("body_sha256 does not match canonical body")
        return self

    @classmethod
    def from_wire(cls, raw: bytes | str) -> Self:
        """Parse strict JSON with duplicate-key, float and size rejection."""
        return cls.model_validate(parse_canonical_json(raw))

    @classmethod
    def build(
        cls,
        *,
        request_id: str,
        method: HttpMethod,
        host: str,
        port: int,
        path: str,
        resolved_ip: str,
        tls_spki_sha256: str,
        body: Any,
        credential_id: str | None = None,
    ) -> Self:
        body_json = canonical_json(body)
        return cls(
            request_id=request_id,
            method=method,
            host=host,
            port=port,
            path=path,
            resolved_ip=resolved_ip,
            tls_spki_sha256=tls_spki_sha256,
            body_canonical_json=body_json,
            body_sha256=payload_sha256(body_json),
            body_bytes=len(body_json.encode("utf-8")),
            credential_id=credential_id,
        )

    def digest(self) -> str:
        return domain_hash("ACTION-HASH", self)


__all__ = ["Action"]
