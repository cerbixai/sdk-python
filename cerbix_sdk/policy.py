"""Policy evaluation layer — scope resolution, policy checks, decision logic.

Components:
  1. ScopeResolver  — maps (method, host, path) → semantic scope
  2. PolicyEngine   — evaluates scope+resource against cached policy bundle
  3. DecisionResolver — applies shadow/bypass overrides to raw decisions

Data flows:  request → ScopeResolver → PolicyEngine → DecisionResolver → decision
"""

import fnmatch
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cerbix_sdk")


# ─── Enums ────────────────────────────────────────────────────────


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    SHADOW = "shadow"
    BYPASS = "bypass"


# ─── Data Structures ─────────────────────────────────────────────


@dataclass
class ScopeRule:
    """Maps an HTTP pattern to a semantic scope and resource name."""
    method_pattern: str   # "GET" | "POST" | "*"
    host_pattern: str     # "customer-db.acme.internal" | "*.acme.internal"
    path_pattern: str     # "/customers/*" | "/api/v2/*"
    scope: str            # "db:read:customers"
    resource: str         # "customer_db"


@dataclass
class OrgPolicy:
    """Organisation-level policy ceiling."""
    allowed_scopes: List[str] = field(default_factory=list)
    denied_resources: List[str] = field(default_factory=list)
    allowed_resources: List[str] = field(default_factory=list)


@dataclass
class PolicyBundle:
    """Complete policy context for an agent. Cached locally."""
    agent_id: str
    agent_status: str              # "shadow" | "enforced"
    declared_scope: List[str]      # ["db:read:customers", "api:read"]
    scope_map: List[ScopeRule]     # URL pattern → scope mapping
    org_policy: OrgPolicy
    loaded_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyBundle":
        """Construct from API response dict."""
        rules = [
            ScopeRule(**r) for r in data.get("scope_map", [])
        ]
        org = data.get("org_policy", {})
        return cls(
            agent_id=data.get("agent_id", ""),
            agent_status=data.get("status", "shadow"),
            declared_scope=data.get("declared_scope", []),
            scope_map=rules,
            org_policy=OrgPolicy(
                allowed_scopes=org.get("allowed_scopes", []),
                denied_resources=org.get("denied_resources", []),
                allowed_resources=org.get("allowed_resources", []),
            ),
        )


@dataclass
class PolicyDecision:
    """Raw result from PolicyEngine.evaluate()."""
    result: Decision        # ALLOW or DENY
    scope: str
    resource: str
    deny_reason: Optional[str] = None
    checked_at: Optional[str] = None


@dataclass
class FinalDecision:
    """After shadow/bypass override is applied."""
    decision: Decision       # ALLOW | DENY | SHADOW | BYPASS
    raw_decision: Decision   # ALLOW | DENY (before override)
    deny_reason: Optional[str] = None
    agent_status: str = "shadow"
    sdk_state: str = "enforced"


# ─── Component 1: Scope Resolver ─────────────────────────────────


class ScopeResolver:
    """Translates (method, host, path) into a semantic scope name.

    Uses a scope_map loaded from the agent's policy bundle.
    Falls back to a generic scope if no rule matches.
    """

    def __init__(self, scope_map: Optional[List[ScopeRule]] = None):
        self._rules = scope_map or []

    def resolve(
        self, method: str, host: str, path: str,
    ) -> Tuple[str, str]:
        """Resolve an HTTP call to (scope_name, resource_name).

        Tries each rule in order; first match wins.
        Returns ("unknown", host_label) if no rule matches.
        """
        for rule in self._rules:
            if (
                self._matches(method.upper(), rule.method_pattern)
                and self._matches(host, rule.host_pattern)
                and self._matches(path, rule.path_pattern)
            ):
                return (rule.scope, rule.resource)

        # No match — generate a generic scope
        return ("unknown", self._extract_host_label(host))

    @staticmethod
    def _matches(value: str, pattern: str) -> bool:
        """Pattern matching with wildcards.

        Supports:
          "*"           → matches everything
          "GET"         → exact match
          "/customers/*"→ prefix match (path starts with /customers/)
          "*.acme.internal" → suffix match (host ends with .acme.internal)
        """
        if pattern == "*":
            return True
        if pattern.endswith("/*"):
            prefix = pattern[:-1]  # "/customers/"
            return value == pattern[:-2] or value.startswith(prefix)
        if pattern.startswith("*."):
            suffix = pattern[1:]   # ".acme.internal"
            return value.endswith(suffix) or value == pattern[2:]
        return value == pattern

    @staticmethod
    def _extract_host_label(host: str) -> str:
        """Extract a short label from a hostname."""
        if not host:
            return "unknown"
        # Take first segment: "billing-api.acme.internal" → "billing-api"
        return host.split(".")[0]


# ─── Component 2: Policy Engine ──────────────────────────────────


class PolicyEngine:
    """Evaluates a (scope, resource) pair against the cached policy bundle.

    Four sequential checks — first DENY wins:
      1. Is scope in the agent's declared_scope?
      2. Is scope permitted by the org ceiling policy?
      3. Is the resource explicitly denied?
      4. Is the resource in the allowed_resources allowlist?
    """

    def __init__(self, bundle: PolicyBundle):
        self.agent_id = bundle.agent_id
        self.agent_status = bundle.agent_status
        self.declared_scope = set(bundle.declared_scope)
        self.org_policy = bundle.org_policy

    def evaluate(
        self, scope: str, resource: str,
    ) -> PolicyDecision:
        """Run all four checks. Returns ALLOW or DENY with reason."""

        # Check 1: Is scope in agent's declared_scope?
        if not self._scope_declared(scope):
            return PolicyDecision(
                result=Decision.DENY,
                deny_reason="scope_not_declared",
                checked_at="declared_scope",
                scope=scope,
                resource=resource,
            )

        # Check 2: Is scope permitted by org ceiling policy?
        if not self._scope_in_org_policy(scope):
            return PolicyDecision(
                result=Decision.DENY,
                deny_reason="org_policy_ceiling",
                checked_at="org_policy.allowed_scopes",
                scope=scope,
                resource=resource,
            )

        # Check 3: Is resource explicitly denied?
        if self._resource_is_denied(resource):
            return PolicyDecision(
                result=Decision.DENY,
                deny_reason="resource_denied",
                checked_at="org_policy.denied_resources",
                scope=scope,
                resource=resource,
            )

        # Check 4: Is resource in allowlist?
        if not self._resource_in_allowlist(resource):
            return PolicyDecision(
                result=Decision.DENY,
                deny_reason="resource_not_in_allowlist",
                checked_at="org_policy.allowed_resources",
                scope=scope,
                resource=resource,
            )

        # All checks passed
        return PolicyDecision(
            result=Decision.ALLOW,
            scope=scope,
            resource=resource,
        )

    def _scope_declared(self, scope: str) -> bool:
        """Check if scope is in the agent's declared_scope."""
        if not self.declared_scope:
            return True  # no scope declared = open policy
        for declared in self.declared_scope:
            if declared == scope:
                return True
            # Wildcard: "db:read:*" matches "db:read:customers"
            if declared.endswith(":*"):
                prefix = declared[:-1]  # "db:read:"
                if scope.startswith(prefix):
                    return True
            # Slash wildcard: "api/*" matches "api/read"
            if declared.endswith("/*"):
                prefix = declared[:-1]  # "api/"
                if scope.startswith(prefix):
                    return True
        return False

    def _scope_in_org_policy(self, scope: str) -> bool:
        """Check scope against org allowed_scopes ceiling."""
        if not self.org_policy.allowed_scopes:
            return True  # no ceiling = everything permitted
        for allowed in self.org_policy.allowed_scopes:
            if allowed == scope:
                return True
            if allowed.endswith(":*"):
                prefix = allowed[:-1]
                if scope.startswith(prefix):
                    return True
            if allowed.endswith("/*"):
                prefix = allowed[:-1]
                if scope.startswith(prefix):
                    return True
        return False

    def _resource_is_denied(self, resource: str) -> bool:
        """Check if resource is in the deny list."""
        for denied in self.org_policy.denied_resources:
            if denied == resource or denied in resource:
                return True
        return False

    def _resource_in_allowlist(self, resource: str) -> bool:
        """Check resource against allowlist (empty = all allowed)."""
        if not self.org_policy.allowed_resources:
            return True
        for allowed in self.org_policy.allowed_resources:
            if allowed == resource or allowed in resource:
                return True
        return False


# ─── Component 3: Decision Resolver ──────────────────────────────


class DecisionResolver:
    """Applies shadow and bypass overrides to raw policy decisions.

    Shadow mode:  evaluate everything, block nothing.
    Bypass mode:  Cerbix unreachable, forward everything.
    Enforced mode: raw decision is final.
    """

    @staticmethod
    def resolve_final(
        policy_decision: PolicyDecision,
        agent_status: str,
        sdk_state: str,
    ) -> FinalDecision:
        """Apply overrides and return the final decision."""

        raw = policy_decision.result

        # Shadow mode: observe but don't block
        if agent_status == "shadow":
            if raw == Decision.DENY:
                final = Decision.SHADOW
            else:
                final = Decision.ALLOW

        # Bypass mode: Cerbix unreachable
        elif sdk_state.lower() == "bypass":
            final = Decision.BYPASS

        # Enforced mode: raw decision stands
        else:
            final = raw

        return FinalDecision(
            decision=final,
            raw_decision=raw,
            deny_reason=(
                policy_decision.deny_reason
                if raw == Decision.DENY else None
            ),
            agent_status=agent_status,
            sdk_state=sdk_state,
        )
