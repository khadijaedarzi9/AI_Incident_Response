"""Closed-world BCP-1 authorization policy."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from threading import RLock

from app.action import Action
from app.models import EgressRule, Manifest, Verdict


@dataclass(frozen=True)
class PolicyResult:
    verdict: Verdict
    reason_code: str
    matched_rule_id: str | None
    hard_violation: bool


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(normalized + "/")


def _ip_matches(ip: str, cidrs: tuple[str, ...]) -> bool:
    address = ipaddress.ip_address(ip)
    return any(address in ipaddress.ip_network(cidr) for cidr in cidrs)


class PolicyEngine:
    """Evaluates the immutable signed manifest snapshot."""

    def __init__(self, manifest: Manifest) -> None:
        self.manifest = manifest
        self._lock = RLock()
        self._rule_uses: dict[str, int] = {}
        self._credential_uses: dict[str, int] = {}

    def authorize(self, action: Action, *, now_timestamp: str) -> PolicyResult:
        body = self.manifest.body
        if not body.not_before <= now_timestamp <= body.expires_at:
            return self._kill("manifest.inactive")

        origin_rules = tuple(
            rule
            for rule in body.allowed_egress
            if (
                rule.scheme == action.scheme
                and rule.host == action.host
                and rule.port == action.port
            )
        )
        if not origin_rules:
            return self._kill("egress.origin_not_allowed")

        matching_rule = next(
            (rule for rule in origin_rules if self._rule_matches(rule, action)),
            None,
        )
        if matching_rule is None:
            return self._kill("egress.constraint_mismatch")

        grant = None
        if action.credential_id is not None:
            grant = next(
                (
                    item
                    for item in body.credentials
                    if item.credential_id == action.credential_id
                ),
                None,
            )
            if grant is None:
                return self._kill("credential.unknown")
            if grant.is_canary:
                return self._kill("credential.canary_used")
            if (
                grant.audience != action.host
                or matching_rule.rule_id not in grant.allowed_rule_ids
                or grant.expires_at < now_timestamp
            ):
                return self._kill("credential.scope_violation")

        with self._lock:
            rule_uses = self._rule_uses.get(matching_rule.rule_id, 0)
            if rule_uses >= matching_rule.max_requests:
                return self._kill("egress.rule_budget_exhausted")
            if grant is not None:
                grant_uses = self._credential_uses.get(grant.credential_id, 0)
                if grant_uses >= grant.max_uses:
                    return self._kill("credential.use_budget_exhausted")
                self._credential_uses[grant.credential_id] = grant_uses + 1
            self._rule_uses[matching_rule.rule_id] = rule_uses + 1

        return PolicyResult(
            verdict=Verdict.ALLOW,
            reason_code="policy.allowed",
            matched_rule_id=matching_rule.rule_id,
            hard_violation=False,
        )

    @staticmethod
    def _rule_matches(rule: EgressRule, action: Action) -> bool:
        return (
            action.method in rule.methods
            and any(_path_matches(action.path, prefix) for prefix in rule.path_prefixes)
            and _ip_matches(action.resolved_ip, rule.resolved_ip_cidrs)
            and action.tls_spki_sha256 in rule.tls_spki_sha256
            and action.body_bytes <= rule.max_request_bytes
        )

    @staticmethod
    def _kill(reason_code: str) -> PolicyResult:
        return PolicyResult(
            verdict=Verdict.KILL,
            reason_code=reason_code,
            matched_rule_id=None,
            hard_violation=True,
        )


__all__ = ["PolicyEngine", "PolicyResult"]
