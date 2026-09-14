"""BCP-1 proof-carrying evaluation contract models.

The wire format is a deliberately small subset of RFC 8785/JCS:

* UTF-8, NFC-normalized strings
* JSON objects with unique string keys
* arrays, booleans, null, and I-JSON safe integers
* no floats

Every digest and signature is domain separated. Ed25519 signatures are encoded
as unpadded base64url. Timestamps always use six fractional digits and ``Z``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import unicodedata
from datetime import datetime, timezone
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, ClassVar, Iterable, Literal, Mapping, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey as CryptoEd25519PublicKey,
)
from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from typing_extensions import Annotated


PROTOCOL = "BCP-1"
SCHEMA_VERSION = "1.0"
GENESIS_HASH = "0" * 64
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_CANONICAL_JSON_BYTES = 4_194_304
MAX_EVENT_PAYLOAD_BYTES = 1_048_576
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000

_ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._:-]{0,127})$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _require_nfc(value: str, *, label: str = "string") -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{label} must be NFC-normalized")
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError(f"{label} must not contain Unicode surrogates")
    return value


def _validate_timestamp(value: str) -> str:
    _require_nfc(value, label="timestamp")
    if not _TIMESTAMP_RE.fullmatch(value):
        raise ValueError(
            "timestamp must be UTC RFC 3339 with six fractional digits "
            "(YYYY-MM-DDTHH:MM:SS.ffffffZ)"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as exc:
        raise ValueError("timestamp is not a real calendar time") from exc
    if format_utc_timestamp(parsed.replace(tzinfo=timezone.utc)) != value:
        raise ValueError("timestamp is not in canonical form")
    return value


def format_utc_timestamp(value: datetime) -> str:
    """Return the sole timestamp representation accepted by BCP-1."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _reject_float(_: str) -> None:
    raise ValueError("floating-point JSON numbers are forbidden; use a string")


def _parse_safe_int(value: str) -> int:
    parsed = int(value)
    if abs(parsed) > MAX_SAFE_INTEGER:
        raise ValueError("JSON integer exceeds the I-JSON safe range")
    return parsed


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is forbidden")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    normalized_keys: set[str] = set()
    for key, value in pairs:
        _require_nfc(key, label="JSON object key")
        normalized = unicodedata.normalize("NFC", key)
        if key in result or normalized in normalized_keys:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        result[key] = value
        normalized_keys.add(normalized)
    return result


def parse_canonical_json(value: str | bytes | bytearray) -> Any:
    """Parse strict BCP-1 JSON, rejecting duplicate keys and floats."""
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid UTF-8 JSON") from exc
    if not isinstance(value, str):
        raise TypeError("JSON input must be str, bytes, or bytearray")
    if value.startswith("\ufeff"):
        raise ValueError("UTF-8 BOM is forbidden")
    if len(value.encode("utf-8")) > MAX_CANONICAL_JSON_BYTES:
        raise ValueError("JSON input exceeds the BCP-1 hard byte limit")
    try:
        parsed = json.loads(
            value,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_int=_parse_safe_int,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid JSON") from exc
    return _validate_json_value(parsed)


def _validate_json_value(
    value: Any,
    path: str = "$",
    *,
    _depth: int = 0,
    _budget: list[int] | None = None,
) -> Any:
    if _depth > MAX_JSON_DEPTH:
        raise ValueError(f"{path}: JSON nesting exceeds {MAX_JSON_DEPTH}")
    if _budget is None:
        _budget = [MAX_JSON_NODES]
    _budget[0] -= 1
    if _budget[0] < 0:
        raise ValueError(f"JSON value exceeds {MAX_JSON_NODES} nodes")

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python", by_alias=True, exclude_none=False)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ValueError(f"{path}: integer exceeds the I-JSON safe range")
        return value
    if isinstance(value, float):
        raise TypeError(f"{path}: floats are forbidden; encode decimals as strings")
    if isinstance(value, str):
        return _require_nfc(value, label=path)
    if isinstance(value, (list, tuple)):
        return [
            _validate_json_value(
                item,
                f"{path}[{index}]",
                _depth=_depth + 1,
                _budget=_budget,
            )
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        normalized_keys: set[str] = set()
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path}: JSON object keys must be strings")
            _require_nfc(key, label=f"{path} object key")
            normalized = unicodedata.normalize("NFC", key)
            if normalized in normalized_keys:
                raise ValueError(f"{path}: duplicate key after NFC normalization")
            normalized_keys.add(normalized)
            result[key] = _validate_json_value(
                item,
                f"{path}.{key}",
                _depth=_depth + 1,
                _budget=_budget,
            )
        return result
    raise TypeError(f"{path}: unsupported canonical JSON type {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a model or JSON value to deterministic BCP-1 JSON bytes."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python", by_alias=True, exclude_none=False)
    validated = _validate_json_value(value)
    ordered = _order_for_jcs(validated)
    encoded = json.dumps(
        ordered,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=False,
    ).encode("utf-8")
    if len(encoded) > MAX_CANONICAL_JSON_BYTES:
        raise ValueError("canonical JSON exceeds the BCP-1 hard byte limit")
    return encoded


def _order_for_jcs(value: Any) -> Any:
    """Order object keys by UTF-16 code units as required by RFC 8785."""
    if isinstance(value, dict):
        return {
            key: _order_for_jcs(value[key])
            for key in sorted(value, key=lambda item: item.encode("utf-16-be"))
        }
    if isinstance(value, list):
        return [_order_for_jcs(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def canonicalize_json_text(value: str) -> str:
    _require_nfc(value, label="canonical JSON")
    canonical = canonical_json(parse_canonical_json(value))
    if not hmac.compare_digest(canonical.encode(), value.encode()):
        raise ValueError("JSON text is valid but is not in canonical BCP-1 form")
    return value


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def payload_sha256(payload_canonical_json: str) -> str:
    return sha256_hex(payload_canonical_json.encode("utf-8"))


def domain_hash(domain: str, value: Any) -> str:
    domain_bytes = domain.encode("ascii")
    return sha256_hex(
        PROTOCOL.encode("ascii")
        + b"\x00"
        + domain_bytes
        + b"\x00"
        + canonical_json_bytes(value)
    )


def signing_message(domain: str, digest: str) -> bytes:
    if not _SHA256_RE.fullmatch(digest):
        raise ValueError("digest must be lowercase SHA-256 hex")
    return (
        PROTOCOL.encode("ascii")
        + b"\x00"
        + domain.encode("ascii")
        + b"\x00SHA-256\x00"
        + bytes.fromhex(digest)
    )


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str, *, expected_length: int) -> bytes:
    if not isinstance(value, str) or not value or not _B64URL_RE.fullmatch(value):
        raise ValueError("value must be unpadded base64url")
    if "=" in value:
        raise ValueError("base64url padding is forbidden")
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64url value") from exc
    if len(decoded) != expected_length:
        raise ValueError(f"decoded value must be exactly {expected_length} bytes")
    if _b64url_encode(decoded) != value:
        raise ValueError("base64url value is not canonical")
    return decoded


def _private_key(value: Ed25519PrivateKey | bytes) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if isinstance(value, bytes) and len(value) == 32:
        return Ed25519PrivateKey.from_private_bytes(value)
    raise TypeError("private key must be Ed25519PrivateKey or 32 raw bytes")


def _public_key(
    value: CryptoEd25519PublicKey | bytes,
) -> CryptoEd25519PublicKey:
    if isinstance(value, CryptoEd25519PublicKey):
        return value
    if isinstance(value, bytes) and len(value) == 32:
        return CryptoEd25519PublicKey.from_public_bytes(value)
    raise TypeError("public key must be Ed25519PublicKey or 32 raw bytes")


def _verify_signature(
    public_key: CryptoEd25519PublicKey | bytes,
    signature: "Ed25519Signature",
    message: bytes,
) -> None:
    try:
        _public_key(public_key).verify(signature.as_bytes(), message)
    except InvalidSignature as exc:
        raise ValueError("invalid Ed25519 signature") from exc


def _sorted_unique(values: Iterable[str], *, label: str) -> tuple[str, ...]:
    result = tuple(values)
    if result != tuple(sorted(set(result))):
        raise ValueError(f"{label} must be sorted and contain no duplicates")
    return result


def _canonical_host(value: str) -> str:
    _require_nfc(value, label="host")
    if value != value.lower() or value.endswith(".") or "*" in value:
        raise ValueError("host must be lowercase, exact, and contain no wildcard")
    try:
        canonical = ipaddress.ip_address(value).compressed
    except ValueError:
        canonical = None
    if canonical is not None:
        if canonical != value:
            raise ValueError(f"IP address must use canonical spelling: {canonical}")
        return value

    labels = value.split(".")
    if not labels or any(
        not label
        or len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("host must be an ASCII DNS name or canonical IP")
    if len(value) > 253:
        raise ValueError("DNS name is too long")
    return value


def _strict_bool(value: Any) -> bool:
    if type(value) is not bool:
        raise ValueError("value must be a JSON boolean")
    return value


def _strict_true(value: Any) -> bool:
    if value is not True:
        raise ValueError("value must be the JSON boolean true")
    return value


def _canonical_cidr(value: str) -> str:
    _require_nfc(value, label="CIDR")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError("CIDR must be a canonical network address") from exc
    canonical = network.with_prefixlen
    if canonical != value:
        raise ValueError(f"CIDR must use canonical spelling: {canonical}")
    return value


def _canonical_path_prefix(value: str) -> str:
    _require_nfc(value, label="path prefix")
    if not value.startswith("/") or "?" in value or "#" in value or "\\" in value:
        raise ValueError("path prefix must be an absolute URL path only")
    if "%" in value:
        raise ValueError("percent escapes are forbidden in manifest path prefixes")
    if "//" in value or any(part in {".", ".."} for part in value.split("/")):
        raise ValueError("path prefix must not contain empty or dot segments")
    if str(PurePosixPath(value)) != value.rstrip("/") and value != "/":
        raise ValueError("path prefix is not normalized")
    return value


OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[a-z0-9](?:[a-z0-9._:-]{0,127})$"),
]
Sha256Hex = Annotated[
    str, StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$")
]
UtcTimestamp = Annotated[
    str,
    StringConstraints(
        strict=True,
        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$",
    ),
    AfterValidator(_validate_timestamp),
]
SafeNonNegativeInt = Annotated[
    int, Field(strict=True, ge=0, le=MAX_SAFE_INTEGER)
]
SafePositiveInt = Annotated[int, Field(strict=True, ge=1, le=MAX_SAFE_INTEGER)]
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]
Host = Annotated[
    str, StringConstraints(strict=True), AfterValidator(_canonical_host)
]
CanonicalCidr = Annotated[
    str, StringConstraints(strict=True), AfterValidator(_canonical_cidr)
]
CanonicalPathPrefix = Annotated[
    str, StringConstraints(strict=True), AfterValidator(_canonical_path_prefix)
]
CanonicalBool = Annotated[bool, BeforeValidator(_strict_bool)]
CanonicalTrue = Annotated[Literal[True], BeforeValidator(_strict_true)]


class ContractModel(BaseModel):
    """Immutable, closed-world base model for every signed structure."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_default=True,
        use_enum_values=True,
    )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    def canonical_json(self) -> str:
        return canonical_json(self)

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        context: Any | None = None,
    ) -> Self:
        # Pydantic's normal JSON parser accepts duplicate keys. Signed contracts
        # cannot, so all protocol parsing goes through the strict parser.
        parsed = parse_canonical_json(json_data)
        return cls.model_validate(parsed, strict=strict, context=context)


class Ed25519Signature(ContractModel):
    key_id: OpaqueId
    algorithm: Literal["Ed25519"] = "Ed25519"
    value: str

    @field_validator("value")
    @classmethod
    def signature_is_canonical(cls, value: str) -> str:
        _b64url_decode(value, expected_length=64)
        return value

    @classmethod
    def from_bytes(cls, *, key_id: str, value: bytes) -> Self:
        if len(value) != 64:
            raise ValueError("Ed25519 signature must be 64 bytes")
        return cls(key_id=key_id, value=_b64url_encode(value))

    def as_bytes(self) -> bytes:
        return _b64url_decode(self.value, expected_length=64)


class Ed25519PublicKey(ContractModel):
    key_id: OpaqueId
    algorithm: Literal["Ed25519"] = "Ed25519"
    value: str

    @field_validator("value")
    @classmethod
    def key_is_canonical(cls, value: str) -> str:
        _b64url_decode(value, expected_length=32)
        return value

    @classmethod
    def from_bytes(cls, *, key_id: str, value: bytes) -> Self:
        if len(value) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        return cls(key_id=key_id, value=_b64url_encode(value))

    def as_bytes(self) -> bytes:
        return _b64url_decode(self.value, expected_length=32)


class HttpMethod(str, Enum):
    DELETE = "DELETE"
    GET = "GET"
    HEAD = "HEAD"
    PATCH = "PATCH"
    POST = "POST"
    PUT = "PUT"


class EgressRule(ContractModel):
    rule_id: OpaqueId
    scheme: Literal["https"] = "https"
    host: Host
    port: Port
    methods: tuple[HttpMethod, ...] = Field(min_length=1)
    path_prefixes: tuple[CanonicalPathPrefix, ...] = Field(min_length=1)
    resolved_ip_cidrs: tuple[CanonicalCidr, ...] = Field(min_length=1)
    tls_spki_sha256: tuple[str, ...] = ()
    max_requests: SafePositiveInt
    max_request_bytes: SafePositiveInt
    max_response_bytes: SafePositiveInt

    @field_validator("methods")
    @classmethod
    def methods_are_canonical(
        cls, values: tuple[HttpMethod, ...]
    ) -> tuple[HttpMethod, ...]:
        raw = tuple(value.value if isinstance(value, HttpMethod) else value for value in values)
        _sorted_unique(raw, label="methods")
        return values

    @field_validator(
        "path_prefixes", "resolved_ip_cidrs", "tls_spki_sha256"
    )
    @classmethod
    def string_lists_are_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        _sorted_unique(values, label="manifest lists")
        return values

    @field_validator("tls_spki_sha256")
    @classmethod
    def spki_pins_are_sha256(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _b64url_decode(value, expected_length=32)
        return values

    @model_validator(mode="after")
    def tls_policy_is_closed(self) -> Self:
        if not self.tls_spki_sha256:
            raise ValueError("HTTPS rules require at least one TLS SPKI SHA-256 pin")
        return self


class CredentialGrant(ContractModel):
    """A capability reference. Secret material is never part of a manifest."""

    credential_id: OpaqueId
    broker_ref: OpaqueId
    audience: Host
    allowed_rule_ids: tuple[OpaqueId, ...] = Field(min_length=1)
    scopes: tuple[str, ...] = ()
    expires_at: UtcTimestamp
    max_uses: SafePositiveInt
    is_canary: CanonicalBool = False

    @field_validator("allowed_rule_ids", "scopes")
    @classmethod
    def grants_are_canonical(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _require_nfc(value, label="credential grant value")
        _sorted_unique(values, label="credential grant values")
        return values


class KillCriteria(ContractModel):
    deny_is_kill: CanonicalTrue = True
    max_runtime_ms: SafePositiveInt
    max_total_events: SafePositiveInt
    max_admitted_requests: SafePositiveInt
    max_inflight_requests: SafePositiveInt
    max_requests_per_window: SafePositiveInt
    rate_window_ms: SafePositiveInt
    max_queued_events: SafePositiveInt
    max_event_payload_bytes: SafePositiveInt
    max_total_egress_bytes: SafePositiveInt
    supervisor_kill_latency_sla_ms: SafePositiveInt

    @model_validator(mode="after")
    def capacities_are_coherent(self) -> Self:
        if self.max_event_payload_bytes > MAX_EVENT_PAYLOAD_BYTES:
            raise ValueError(
                f"max_event_payload_bytes exceeds protocol hard limit "
                f"{MAX_EVENT_PAYLOAD_BYTES}"
            )
        if self.max_requests_per_window > self.max_admitted_requests:
            raise ValueError(
                "max_requests_per_window cannot exceed max_admitted_requests"
            )
        if self.max_inflight_requests > self.max_admitted_requests:
            raise ValueError(
                "max_inflight_requests cannot exceed max_admitted_requests"
            )
        if self.max_queued_events > self.max_total_events:
            raise ValueError("max_queued_events cannot exceed max_total_events")
        return self


class SecondHopAttestationBody(ContractModel):
    """Provider assertions plus immutable external evidence references."""

    run_id: OpaqueId
    provider_id: OpaqueId
    provider_key_id: OpaqueId
    endpoint_host: Host
    accountable_org: OpaqueId
    responsible_operator: OpaqueId
    security_contact: str
    issued_at: UtcTimestamp
    expires_at: UtcTimestamp
    evidence_sha256: tuple[Sha256Hex, ...]
    authenticated: CanonicalTrue
    non_root_workload: CanonicalTrue
    tenant_isolation: CanonicalTrue
    default_deny_egress: CanonicalTrue
    no_ambient_secrets: CanonicalTrue
    bounded_requests: CanonicalTrue
    abuse_monitoring: CanonicalTrue
    automatic_containment_authorized: CanonicalTrue
    evidence_exchange_required: CanonicalTrue

    @field_validator("security_contact")
    @classmethod
    def contact_is_canonical(cls, value: str) -> str:
        return _require_nfc(value, label="second-hop security contact")

    @model_validator(mode="after")
    def evidence_is_fresh_and_present(self) -> Self:
        if self.issued_at >= self.expires_at:
            raise ValueError("second-hop evidence must expire after issue")
        if not self.evidence_sha256:
            raise ValueError("second-hop evidence requires at least one digest")
        _sorted_unique(self.evidence_sha256, label="second-hop evidence digests")
        return self


class SecondHopAttestation(ContractModel):
    """Provider-signed preflight envelope pinned into the operator manifest."""

    HASH_DOMAIN: ClassVar[str] = "SECOND-HOP-ATTESTATION-HASH"
    SIGNATURE_DOMAIN: ClassVar[str] = "SECOND-HOP-ATTESTATION-SIGNATURE"

    body: SecondHopAttestationBody
    provider_key: Ed25519PublicKey
    attestation_hash: Sha256Hex
    provider_signature: Ed25519Signature

    @model_validator(mode="after")
    def envelope_is_coherent(self) -> Self:
        if self.provider_key.key_id != self.body.provider_key_id:
            raise ValueError("second-hop provider key ID does not match body")
        if self.provider_signature.key_id != self.body.provider_key_id:
            raise ValueError("second-hop signature key ID does not match body")
        expected = domain_hash(self.HASH_DOMAIN, self.body)
        if not hmac.compare_digest(expected, self.attestation_hash):
            raise ValueError("second-hop attestation hash does not match body")
        return self

    @classmethod
    def sign(
        cls,
        body: SecondHopAttestationBody,
        private_key: Ed25519PrivateKey | bytes,
        provider_key: Ed25519PublicKey,
    ) -> Self:
        digest = domain_hash(cls.HASH_DOMAIN, body)
        signature = _private_key(private_key).sign(
            signing_message(cls.SIGNATURE_DOMAIN, digest)
        )
        return cls(
            body=body,
            provider_key=provider_key,
            attestation_hash=digest,
            provider_signature=Ed25519Signature.from_bytes(
                key_id=body.provider_key_id,
                value=signature,
            ),
        )

    def verify(self) -> None:
        _verify_signature(
            self.provider_key.as_bytes(),
            self.provider_signature,
            signing_message(self.SIGNATURE_DOMAIN, self.attestation_hash),
        )


class ManifestBody(ContractModel):
    protocol: Literal["BCP-1"] = PROTOCOL
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    manifest_id: OpaqueId
    run_id: OpaqueId
    issued_at: UtcTimestamp
    not_before: UtcTimestamp
    expires_at: UtcTimestamp
    operator_key_id: OpaqueId
    gateway_key: Ed25519PublicKey
    supervisor_key: Ed25519PublicKey
    witness_key: Ed25519PublicKey
    allowed_egress: tuple[EgressRule, ...] = ()
    credentials: tuple[CredentialGrant, ...] = ()
    second_hops: tuple[SecondHopAttestation, ...] = ()
    kill_criteria: KillCriteria

    @field_validator("allowed_egress")
    @classmethod
    def egress_rules_are_canonical(
        cls, values: tuple[EgressRule, ...]
    ) -> tuple[EgressRule, ...]:
        ids = tuple(rule.rule_id for rule in values)
        _sorted_unique(ids, label="egress rule IDs")
        return values

    @field_validator("credentials")
    @classmethod
    def credentials_are_canonical(
        cls, values: tuple[CredentialGrant, ...]
    ) -> tuple[CredentialGrant, ...]:
        ids = tuple(grant.credential_id for grant in values)
        _sorted_unique(ids, label="credential IDs")
        return values

    @field_validator("second_hops")
    @classmethod
    def second_hops_are_canonical(
        cls, values: tuple[SecondHopAttestation, ...]
    ) -> tuple[SecondHopAttestation, ...]:
        ids = tuple(item.body.provider_id for item in values)
        _sorted_unique(ids, label="second-hop provider IDs")
        return values

    @model_validator(mode="after")
    def policy_is_coherent(self) -> Self:
        if not self.not_before < self.expires_at:
            raise ValueError("not_before must be earlier than expires_at")
        if not self.issued_at <= self.not_before:
            raise ValueError("issued_at must not be later than not_before")
        key_ids = (
            self.operator_key_id,
            self.gateway_key.key_id,
            self.supervisor_key.key_id,
            self.witness_key.key_id,
        )
        if len(set(key_ids)) != len(key_ids):
            raise ValueError(
                "operator, gateway, supervisor, and witness keys must be distinct"
            )

        rules = {rule.rule_id: rule for rule in self.allowed_egress}
        for grant in self.credentials:
            for rule_id in grant.allowed_rule_ids:
                if rule_id not in rules:
                    raise ValueError(
                        f"credential {grant.credential_id!r} references unknown "
                        f"egress rule {rule_id!r}"
                    )
                if rules[rule_id].host != grant.audience:
                    raise ValueError(
                        f"credential {grant.credential_id!r} audience does not "
                        f"match rule {rule_id!r}"
                    )
            if grant.expires_at > self.expires_at:
                raise ValueError("credential expiry exceeds manifest expiry")
        return self


class Manifest(ContractModel):
    HASH_DOMAIN: ClassVar[str] = "MANIFEST-HASH"
    SIGNATURE_DOMAIN: ClassVar[str] = "MANIFEST-SIGNATURE"

    body: ManifestBody
    manifest_hash: Sha256Hex
    operator_signature: Ed25519Signature

    @model_validator(mode="after")
    def envelope_is_coherent(self) -> Self:
        expected = domain_hash(self.HASH_DOMAIN, self.body)
        if not hmac.compare_digest(expected, self.manifest_hash):
            raise ValueError("manifest_hash does not match manifest body")
        if self.operator_signature.key_id != self.body.operator_key_id:
            raise ValueError("operator signature key ID does not match manifest")
        return self

    @classmethod
    def sign(
        cls,
        body: ManifestBody,
        private_key: Ed25519PrivateKey | bytes,
    ) -> Self:
        cls._verify_second_hops(body)
        digest = domain_hash(cls.HASH_DOMAIN, body)
        signature = _private_key(private_key).sign(
            signing_message(cls.SIGNATURE_DOMAIN, digest)
        )
        return cls(
            body=body,
            manifest_hash=digest,
            operator_signature=Ed25519Signature.from_bytes(
                key_id=body.operator_key_id, value=signature
            ),
        )

    def verify(self, operator_public_key: CryptoEd25519PublicKey | bytes) -> None:
        _verify_signature(
            operator_public_key,
            self.operator_signature,
            signing_message(self.SIGNATURE_DOMAIN, self.manifest_hash),
        )
        self._verify_second_hops(self.body)

    @staticmethod
    def _verify_second_hops(body: ManifestBody) -> None:
        for attestation in body.second_hops:
            attestation.verify()
            if attestation.body.run_id != body.run_id:
                raise ValueError("second-hop attestation is bound to another run")
            if (
                attestation.body.issued_at > body.not_before
                or attestation.body.expires_at < body.expires_at
            ):
                raise ValueError(
                    "second-hop attestation does not cover the manifest lifetime"
                )


class EventKind(str, Enum):
    REQUEST = "REQUEST"
    DECISION = "DECISION"
    DISPATCH = "DISPATCH"
    RESULT = "RESULT"
    CANCELLATION = "CANCELLATION"
    VIOLATION = "VIOLATION"
    KILL_REQUESTED = "KILL_REQUESTED"
    KILL_ACKNOWLEDGED = "KILL_ACKNOWLEDGED"
    OVERLOAD_SUMMARY = "OVERLOAD_SUMMARY"


class RequestEventPayload(ContractModel):
    action: dict[str, Any]
    action_sha256: Sha256Hex


class DispatchEventPayload(ContractModel):
    action_sha256: Sha256Hex
    authorization_id: OpaqueId
    decision_hash: Sha256Hex
    kill_epoch: SafeNonNegativeInt


class ResultEventPayload(ContractModel):
    action_sha256: Sha256Hex
    authorization_id: OpaqueId
    decision_hash: Sha256Hex
    kill_epoch: SafeNonNegativeInt
    response_bytes: SafeNonNegativeInt
    response_sha256: Sha256Hex
    status_code: Annotated[int, Field(strict=True, ge=100, le=599)]


class CancellationEventPayload(ContractModel):
    action_sha256: Sha256Hex
    authorization_id: OpaqueId
    decision_hash: Sha256Hex
    kill_epoch: SafeNonNegativeInt
    status: Literal["SIGNALLED", "CONFIRMED"]
    evidence_sha256: Sha256Hex | None = None

    @model_validator(mode="after")
    def confirmation_has_evidence(self) -> Self:
        if self.status == "CONFIRMED" and self.evidence_sha256 is None:
            raise ValueError("confirmed cancellation requires evidence")
        if self.status == "SIGNALLED" and self.evidence_sha256 is not None:
            raise ValueError("a cancellation signal cannot carry confirmation evidence")
        return self


class ViolationEventPayload(ContractModel):
    reason_code: OpaqueId
    raw_bytes: SafeNonNegativeInt | None = None
    raw_sha256: Sha256Hex | None = None
    action_sha256: Sha256Hex | None = None
    decision_hash: Sha256Hex | None = None

    @model_validator(mode="after")
    def optional_bindings_are_complete_pairs(self) -> Self:
        if (self.raw_bytes is None) != (self.raw_sha256 is None):
            raise ValueError("raw violation fields must be supplied together")
        if (self.action_sha256 is None) != (self.decision_hash is None):
            raise ValueError("action violation fields must be supplied together")
        if self.raw_bytes is not None and self.action_sha256 is not None:
            raise ValueError("violation cannot mix raw and action bindings")
        return self


class OverloadSummaryPayload(ContractModel):
    first_excess_monotonic_ns: SafeNonNegativeInt
    raw_bytes: SafeNonNegativeInt
    raw_sha256: Sha256Hex
    reason_code: Literal["admission.overload"]


class EventBody(ContractModel):
    protocol: Literal["BCP-1"] = PROTOCOL
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: OpaqueId
    manifest_hash: Sha256Hex
    sequence: SafeNonNegativeInt
    previous_event_hash: Sha256Hex
    kind: EventKind
    request_id: OpaqueId | None = None
    producer_instance_id: OpaqueId
    observed_at: UtcTimestamp
    monotonic_ns: SafeNonNegativeInt
    payload_canonical_json: str
    payload_sha256: Sha256Hex

    @field_validator("payload_canonical_json")
    @classmethod
    def payload_is_canonical(cls, value: str) -> str:
        canonicalize_json_text(value)
        if len(value.encode("utf-8")) > MAX_EVENT_PAYLOAD_BYTES:
            raise ValueError("event payload exceeds the protocol hard byte limit")
        return value

    @model_validator(mode="after")
    def payload_digest_matches(self) -> Self:
        expected = payload_sha256(self.payload_canonical_json)
        if not hmac.compare_digest(expected, self.payload_sha256):
            raise ValueError("payload_sha256 does not match payload_canonical_json")
        if self.sequence == 0 and self.previous_event_hash != GENESIS_HASH:
            raise ValueError("event zero must reference the genesis hash")
        if self.sequence > 0 and self.previous_event_hash == GENESIS_HASH:
            raise ValueError("only event zero may reference the genesis hash")
        return self


class Event(ContractModel):
    HASH_DOMAIN: ClassVar[str] = "EVENT-HASH"

    body: EventBody
    event_hash: Sha256Hex

    @model_validator(mode="after")
    def event_digest_matches(self) -> Self:
        expected = domain_hash(self.HASH_DOMAIN, self.body)
        if not hmac.compare_digest(expected, self.event_hash):
            raise ValueError("event_hash does not match event body")
        return self

    @classmethod
    def create(
        cls,
        *,
        payload: Any,
        run_id: str,
        manifest_hash: str,
        sequence: int,
        previous_event_hash: str,
        kind: EventKind,
        producer_instance_id: str,
        observed_at: str,
        monotonic_ns: int,
        request_id: str | None = None,
    ) -> Self:
        payload_json = canonical_json(payload)
        body = EventBody(
            run_id=run_id,
            manifest_hash=manifest_hash,
            sequence=sequence,
            previous_event_hash=previous_event_hash,
            kind=kind,
            request_id=request_id,
            producer_instance_id=producer_instance_id,
            observed_at=observed_at,
            monotonic_ns=monotonic_ns,
            payload_canonical_json=payload_json,
            payload_sha256=payload_sha256(payload_json),
        )
        return cls(body=body, event_hash=domain_hash(cls.HASH_DOMAIN, body))

    def follows(self, previous: "Event") -> bool:
        return (
            self.body.run_id == previous.body.run_id
            and self.body.manifest_hash == previous.body.manifest_hash
            and self.body.sequence == previous.body.sequence + 1
            and hmac.compare_digest(
                self.body.previous_event_hash, previous.event_hash
            )
            and self.body.monotonic_ns >= previous.body.monotonic_ns
        )


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    KILL = "KILL"


class DecisionBody(ContractModel):
    protocol: Literal["BCP-1"] = PROTOCOL
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: OpaqueId
    manifest_hash: Sha256Hex
    request_id: OpaqueId
    request_event_sequence: SafeNonNegativeInt
    request_event_hash: Sha256Hex
    action_sha256: Sha256Hex
    gateway_key_id: OpaqueId
    gateway_instance_id: OpaqueId
    decided_at: UtcTimestamp
    decision_monotonic_ns: SafeNonNegativeInt
    kill_epoch: SafeNonNegativeInt
    verdict: Verdict
    reason_code: OpaqueId
    matched_rule_id: OpaqueId | None = None
    hard_violation: CanonicalBool
    authorization_id: OpaqueId | None = None
    authorization_expires_monotonic_ns: SafeNonNegativeInt | None = None
    authorization_max_uses: Literal[1] | None = None

    @model_validator(mode="after")
    def capability_matches_verdict(self) -> Self:
        capability = (
            self.authorization_id,
            self.authorization_expires_monotonic_ns,
            self.authorization_max_uses,
        )
        if self.verdict == Verdict.ALLOW:
            if any(value is None for value in capability):
                raise ValueError("ALLOW requires a complete single-use authorization")
            if self.matched_rule_id is None:
                raise ValueError("ALLOW requires matched_rule_id")
            if self.hard_violation:
                raise ValueError("ALLOW cannot be a hard violation")
            if self.authorization_expires_monotonic_ns <= self.decision_monotonic_ns:
                raise ValueError("authorization must expire after the decision")
        else:
            if any(value is not None for value in capability):
                raise ValueError("DENY/KILL decisions cannot carry authorization")
            if self.verdict == Verdict.KILL and not self.hard_violation:
                raise ValueError("KILL must be marked as a hard violation")
        return self


class Decision(ContractModel):
    HASH_DOMAIN: ClassVar[str] = "DECISION-HASH"
    SIGNATURE_DOMAIN: ClassVar[str] = "DECISION-SIGNATURE"

    body: DecisionBody
    decision_hash: Sha256Hex
    gateway_signature: Ed25519Signature

    @model_validator(mode="after")
    def envelope_is_coherent(self) -> Self:
        expected = domain_hash(self.HASH_DOMAIN, self.body)
        if not hmac.compare_digest(expected, self.decision_hash):
            raise ValueError("decision_hash does not match decision body")
        if self.gateway_signature.key_id != self.body.gateway_key_id:
            raise ValueError("gateway signature key ID does not match decision")
        return self

    @classmethod
    def sign(
        cls,
        body: DecisionBody,
        private_key: Ed25519PrivateKey | bytes,
    ) -> Self:
        digest = domain_hash(cls.HASH_DOMAIN, body)
        signature = _private_key(private_key).sign(
            signing_message(cls.SIGNATURE_DOMAIN, digest)
        )
        return cls(
            body=body,
            decision_hash=digest,
            gateway_signature=Ed25519Signature.from_bytes(
                key_id=body.gateway_key_id, value=signature
            ),
        )

    def verify(self, gateway_key: Ed25519PublicKey) -> None:
        if gateway_key.key_id != self.body.gateway_key_id:
            raise ValueError("wrong gateway verification key")
        _verify_signature(
            gateway_key.as_bytes(),
            self.gateway_signature,
            signing_message(self.SIGNATURE_DOMAIN, self.decision_hash),
        )


class TerminationMode(str, Enum):
    SIMULATED = "SIMULATED"
    CGROUP_KILL = "CGROUP_KILL"
    JOB_OBJECT_TERMINATE = "JOB_OBJECT_TERMINATE"
    MICROVM_DESTROY = "MICROVM_DESTROY"
    PROCESS_NAMESPACE_KILL = "PROCESS_NAMESPACE_KILL"


class KillAcknowledgementBody(ContractModel):
    protocol: Literal["BCP-1"] = PROTOCOL
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: OpaqueId
    manifest_hash: Sha256Hex
    supervisor_key_id: OpaqueId
    supervisor_instance_id: OpaqueId
    trigger_event_sequence: SafeNonNegativeInt
    trigger_event_hash: Sha256Hex
    trigger_monotonic_ns: SafeNonNegativeInt
    kill_requested_at: UtcTimestamp
    kill_requested_monotonic_ns: SafeNonNegativeInt
    kill_acknowledged_at: UtcTimestamp
    kill_acknowledged_monotonic_ns: SafeNonNegativeInt
    kill_latency_ns: SafeNonNegativeInt
    termination_mode: TerminationMode
    terminated_workload_ids: tuple[OpaqueId, ...] = ()
    inflight_at_trigger: SafeNonNegativeInt
    inflight_cancel_signalled: SafeNonNegativeInt = 0
    inflight_cancelled: SafeNonNegativeInt
    network_isolation_confirmed: CanonicalBool
    isolation_evidence_sha256: Sha256Hex | None = None

    @field_validator("terminated_workload_ids")
    @classmethod
    def workload_ids_are_canonical(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        _sorted_unique(values, label="terminated workload IDs")
        return values

    @model_validator(mode="after")
    def timing_is_coherent(self) -> Self:
        if self.kill_requested_monotonic_ns < self.trigger_monotonic_ns:
            raise ValueError("kill request precedes violation trigger")
        if self.kill_acknowledged_monotonic_ns < self.kill_requested_monotonic_ns:
            raise ValueError("kill acknowledgement precedes kill request")
        expected = self.kill_acknowledged_monotonic_ns - self.trigger_monotonic_ns
        if self.kill_latency_ns != expected:
            raise ValueError("kill_latency_ns must span trigger to acknowledgement")
        if self.kill_acknowledged_at < self.kill_requested_at:
            raise ValueError("kill wall-clock acknowledgement precedes request")
        if self.inflight_cancelled > self.inflight_at_trigger:
            raise ValueError("cancelled inflight count exceeds trigger count")
        if self.inflight_cancel_signalled > self.inflight_at_trigger:
            raise ValueError("signalled inflight count exceeds trigger count")
        if self.inflight_cancelled > self.inflight_cancel_signalled:
            raise ValueError("cancelled inflight exceeds cancellation signals")
        if self.termination_mode == TerminationMode.SIMULATED:
            if self.terminated_workload_ids:
                raise ValueError("simulated isolation cannot claim terminated workloads")
            if self.network_isolation_confirmed:
                raise ValueError("simulated isolation cannot confirm network isolation")
            if self.isolation_evidence_sha256 is not None:
                raise ValueError("simulated isolation cannot carry production evidence")
        else:
            if not self.terminated_workload_ids:
                raise ValueError("production isolation requires terminated workloads")
            if (
                self.network_isolation_confirmed
                and self.isolation_evidence_sha256 is None
            ):
                raise ValueError(
                    "confirmed network isolation requires an evidence digest"
                )
        return self


class KillAcknowledgement(ContractModel):
    HASH_DOMAIN: ClassVar[str] = "KILL-ACK-HASH"
    SIGNATURE_DOMAIN: ClassVar[str] = "KILL-ACK-SIGNATURE"

    body: KillAcknowledgementBody
    acknowledgement_hash: Sha256Hex
    supervisor_signature: Ed25519Signature

    @model_validator(mode="after")
    def envelope_is_coherent(self) -> Self:
        expected = domain_hash(self.HASH_DOMAIN, self.body)
        if not hmac.compare_digest(expected, self.acknowledgement_hash):
            raise ValueError("acknowledgement_hash does not match body")
        if self.supervisor_signature.key_id != self.body.supervisor_key_id:
            raise ValueError("supervisor signature key ID does not match body")
        return self

    @classmethod
    def sign(
        cls,
        body: KillAcknowledgementBody,
        private_key: Ed25519PrivateKey | bytes,
    ) -> Self:
        digest = domain_hash(cls.HASH_DOMAIN, body)
        signature = _private_key(private_key).sign(
            signing_message(cls.SIGNATURE_DOMAIN, digest)
        )
        return cls(
            body=body,
            acknowledgement_hash=digest,
            supervisor_signature=Ed25519Signature.from_bytes(
                key_id=body.supervisor_key_id, value=signature
            ),
        )

    def verify(self, supervisor_key: Ed25519PublicKey) -> None:
        if supervisor_key.key_id != self.body.supervisor_key_id:
            raise ValueError("wrong supervisor verification key")
        _verify_signature(
            supervisor_key.as_bytes(),
            self.supervisor_signature,
            signing_message(self.SIGNATURE_DOMAIN, self.acknowledgement_hash),
        )


class RunStatus(str, Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    KILLED = "KILLED"
    SUPERVISOR_FAILURE = "SUPERVISOR_FAILURE"


class WitnessCheckpointBody(ContractModel):
    """Evidence root signed by an independently operated witness."""

    protocol: Literal["BCP-1"] = PROTOCOL
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: OpaqueId
    manifest_hash: Sha256Hex
    witness_key_id: OpaqueId
    witnessed_at: UtcTimestamp
    event_count: SafeNonNegativeInt
    final_event_hash: Sha256Hex | None
    evidence_file_sha256: Sha256Hex

    @model_validator(mode="after")
    def root_matches_count(self) -> Self:
        if self.event_count == 0 and self.final_event_hash is not None:
            raise ValueError("empty evidence cannot have a final event hash")
        if self.event_count > 0 and self.final_event_hash is None:
            raise ValueError("non-empty evidence requires a final event hash")
        return self


class WitnessCheckpoint(ContractModel):
    HASH_DOMAIN: ClassVar[str] = "WITNESS-CHECKPOINT-HASH"
    SIGNATURE_DOMAIN: ClassVar[str] = "WITNESS-CHECKPOINT-SIGNATURE"

    body: WitnessCheckpointBody
    checkpoint_hash: Sha256Hex
    witness_signature: Ed25519Signature

    @model_validator(mode="after")
    def envelope_is_coherent(self) -> Self:
        expected = domain_hash(self.HASH_DOMAIN, self.body)
        if not hmac.compare_digest(expected, self.checkpoint_hash):
            raise ValueError("checkpoint_hash does not match checkpoint body")
        if self.witness_signature.key_id != self.body.witness_key_id:
            raise ValueError("witness signature key ID does not match checkpoint")
        return self

    @classmethod
    def sign(
        cls,
        body: WitnessCheckpointBody,
        private_key: Ed25519PrivateKey | bytes,
    ) -> Self:
        digest = domain_hash(cls.HASH_DOMAIN, body)
        signature = _private_key(private_key).sign(
            signing_message(cls.SIGNATURE_DOMAIN, digest)
        )
        return cls(
            body=body,
            checkpoint_hash=digest,
            witness_signature=Ed25519Signature.from_bytes(
                key_id=body.witness_key_id, value=signature
            ),
        )

    def verify(self, witness_key: Ed25519PublicKey) -> None:
        if witness_key.key_id != self.body.witness_key_id:
            raise ValueError("wrong witness verification key")
        _verify_signature(
            witness_key.as_bytes(),
            self.witness_signature,
            signing_message(self.SIGNATURE_DOMAIN, self.checkpoint_hash),
        )


class ReceiptBody(ContractModel):
    protocol: Literal["BCP-1"] = PROTOCOL
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    run_id: OpaqueId
    manifest_hash: Sha256Hex
    supervisor_key_id: OpaqueId
    supervisor_instance_id: OpaqueId
    status: RunStatus
    started_at: UtcTimestamp
    finished_at: UtcTimestamp
    started_monotonic_ns: SafeNonNegativeInt
    finished_monotonic_ns: SafeNonNegativeInt
    event_count: SafeNonNegativeInt
    first_event_hash: Sha256Hex | None
    final_event_hash: Sha256Hex | None
    evidence_format: Literal["canonical-jsonl-v1"] = "canonical-jsonl-v1"
    evidence_file_sha256: Sha256Hex
    observed_request_count: SafeNonNegativeInt
    admitted_request_count: SafeNonNegativeInt
    allowed_request_count: SafeNonNegativeInt
    denied_request_count: SafeNonNegativeInt
    dispatched_request_count: SafeNonNegativeInt
    completed_request_count: SafeNonNegativeInt
    rejected_overload_count: SafeNonNegativeInt
    dropped_after_kill_count: SafeNonNegativeInt
    total_egress_bytes: SafeNonNegativeInt
    kill_acknowledgement: KillAcknowledgement | None = None
    witness_checkpoint: WitnessCheckpoint

    @model_validator(mode="after")
    def receipt_is_coherent(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("receipt finish time precedes start time")
        if self.finished_monotonic_ns < self.started_monotonic_ns:
            raise ValueError("receipt monotonic finish precedes start")
        if self.event_count == 0:
            if self.first_event_hash is not None or self.final_event_hash is not None:
                raise ValueError("empty evidence cannot have event hashes")
        elif self.first_event_hash is None or self.final_event_hash is None:
            raise ValueError("non-empty evidence requires first and final hashes")

        if self.admitted_request_count > self.observed_request_count:
            raise ValueError("admitted requests exceed observed requests")
        if self.allowed_request_count + self.denied_request_count > self.admitted_request_count:
            raise ValueError("decisions exceed admitted requests")
        if self.dispatched_request_count > self.allowed_request_count:
            raise ValueError("dispatches exceed allowed requests")
        if self.completed_request_count > self.dispatched_request_count:
            raise ValueError("completed requests exceed dispatches")
        if (
            self.rejected_overload_count + self.dropped_after_kill_count
            > self.observed_request_count
        ):
            raise ValueError("rejected/dropped counters exceed observed requests")

        if self.status == RunStatus.KILLED:
            if self.kill_acknowledgement is None:
                raise ValueError("KILLED receipt requires kill acknowledgement")
        elif self.kill_acknowledgement is not None:
            raise ValueError("only KILLED receipts may contain kill acknowledgement")

        if self.kill_acknowledgement is not None:
            ack = self.kill_acknowledgement.body
            if ack.run_id != self.run_id or ack.manifest_hash != self.manifest_hash:
                raise ValueError("kill acknowledgement belongs to another run")
            if ack.supervisor_key_id != self.supervisor_key_id:
                raise ValueError("kill acknowledgement uses another supervisor key")
            if ack.kill_acknowledged_monotonic_ns > self.finished_monotonic_ns:
                raise ValueError("kill acknowledgement occurs after receipt finish")
        checkpoint = self.witness_checkpoint.body
        if (
            checkpoint.run_id != self.run_id
            or checkpoint.manifest_hash != self.manifest_hash
            or checkpoint.event_count != self.event_count
            or checkpoint.final_event_hash != self.final_event_hash
            or checkpoint.evidence_file_sha256 != self.evidence_file_sha256
        ):
            raise ValueError("witness checkpoint does not match receipt evidence")
        return self


class Receipt(ContractModel):
    HASH_DOMAIN: ClassVar[str] = "RECEIPT-HASH"
    SIGNATURE_DOMAIN: ClassVar[str] = "RECEIPT-SIGNATURE"

    body: ReceiptBody
    receipt_hash: Sha256Hex
    supervisor_signature: Ed25519Signature

    @model_validator(mode="after")
    def envelope_is_coherent(self) -> Self:
        expected = domain_hash(self.HASH_DOMAIN, self.body)
        if not hmac.compare_digest(expected, self.receipt_hash):
            raise ValueError("receipt_hash does not match receipt body")
        if self.supervisor_signature.key_id != self.body.supervisor_key_id:
            raise ValueError("supervisor signature key ID does not match receipt")
        return self

    @classmethod
    def sign(
        cls,
        body: ReceiptBody,
        private_key: Ed25519PrivateKey | bytes,
    ) -> Self:
        digest = domain_hash(cls.HASH_DOMAIN, body)
        signature = _private_key(private_key).sign(
            signing_message(cls.SIGNATURE_DOMAIN, digest)
        )
        return cls(
            body=body,
            receipt_hash=digest,
            supervisor_signature=Ed25519Signature.from_bytes(
                key_id=body.supervisor_key_id, value=signature
            ),
        )

    def verify(self, supervisor_key: Ed25519PublicKey) -> None:
        if supervisor_key.key_id != self.body.supervisor_key_id:
            raise ValueError("wrong supervisor verification key")
        _verify_signature(
            supervisor_key.as_bytes(),
            self.supervisor_signature,
            signing_message(self.SIGNATURE_DOMAIN, self.receipt_hash),
        )

    def verify_against(
        self,
        *,
        manifest: Manifest,
        events: Iterable[Event],
    ) -> None:
        """Verify run binding, chain continuity, root, count, and kill SLA."""
        self.verify(manifest.body.supervisor_key)
        if self.body.run_id != manifest.body.run_id:
            raise ValueError("receipt run_id does not match manifest")
        if self.body.manifest_hash != manifest.manifest_hash:
            raise ValueError("receipt manifest_hash does not match manifest")
        if self.body.supervisor_key_id != manifest.body.supervisor_key.key_id:
            raise ValueError("receipt is not signed by the manifest supervisor")
        self.body.witness_checkpoint.verify(manifest.body.witness_key)

        ack = self.body.kill_acknowledgement
        evidence_digest = hashlib.sha256()
        previous: Event | None = None
        trigger_event_hash: str | None = None
        count = 0

        for event in events:
            if count >= self.body.event_count:
                raise ValueError("evidence contains more events than receipt")
            if (
                event.body.run_id != self.body.run_id
                or event.body.manifest_hash != self.body.manifest_hash
            ):
                raise ValueError("event belongs to another run or manifest")
            if previous is None:
                if event.body.sequence != 0:
                    raise ValueError("evidence must start at sequence zero")
                if event.body.previous_event_hash != GENESIS_HASH:
                    raise ValueError("first event does not reference genesis")
                if event.event_hash != self.body.first_event_hash:
                    raise ValueError("first event hash does not match receipt")
            elif not event.follows(previous):
                raise ValueError(
                    f"broken event chain at sequence {event.body.sequence}"
                )
            if ack is not None and event.body.sequence == ack.body.trigger_event_sequence:
                trigger_event_hash = event.event_hash
            evidence_digest.update(event.canonical_bytes())
            evidence_digest.update(b"\n")
            previous = event
            count += 1

        if count != self.body.event_count:
            raise ValueError("event count does not match receipt")
        if previous is not None and previous.event_hash != self.body.final_event_hash:
            raise ValueError("final event hash does not match receipt")
        if not hmac.compare_digest(
            evidence_digest.hexdigest(), self.body.evidence_file_sha256
        ):
            raise ValueError("canonical evidence file digest does not match receipt")

        if ack is not None:
            ack.verify(manifest.body.supervisor_key)
            sla_ns = (
                manifest.body.kill_criteria.supervisor_kill_latency_sla_ms
                * 1_000_000
            )
            if ack.body.kill_latency_ns > sla_ns:
                raise ValueError("supervisor kill latency exceeded manifest SLA")
            if trigger_event_hash is None:
                raise ValueError("kill trigger event is absent from evidence")
            if trigger_event_hash != ack.body.trigger_event_hash:
                raise ValueError("kill trigger hash does not match evidence")


__all__ = [
    "GENESIS_HASH",
    "PROTOCOL",
    "SCHEMA_VERSION",
    "CancellationEventPayload",
    "CredentialGrant",
    "Decision",
    "DecisionBody",
    "DispatchEventPayload",
    "Ed25519PublicKey",
    "Ed25519Signature",
    "EgressRule",
    "Event",
    "EventBody",
    "EventKind",
    "HttpMethod",
    "KillAcknowledgement",
    "KillAcknowledgementBody",
    "KillCriteria",
    "Manifest",
    "ManifestBody",
    "OverloadSummaryPayload",
    "Receipt",
    "ReceiptBody",
    "RequestEventPayload",
    "ResultEventPayload",
    "RunStatus",
    "SecondHopAttestation",
    "SecondHopAttestationBody",
    "TerminationMode",
    "ViolationEventPayload",
    "Verdict",
    "WitnessCheckpoint",
    "WitnessCheckpointBody",
    "canonical_json",
    "canonical_json_bytes",
    "canonicalize_json_text",
    "domain_hash",
    "format_utc_timestamp",
    "parse_canonical_json",
    "payload_sha256",
    "sha256_hex",
    "signing_message",
]
