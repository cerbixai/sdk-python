"""Audit level definitions for CerbiX.

Three tiers of audit granularity. Each level includes all fields
from the previous level plus additional fields.

Mandatory fields (always captured, cannot be disabled):
    agent_id, org_id, timestamp, decision, sdk_state

Never-captured fields (architectural guarantee, not configurable):
    Request body, response body, Authorization header value,
    cookies, query parameter values, PII from URL paths

Privacy boundary: the SDK transport layer NEVER reads request or
response bodies. This is enforced at code level, not policy.
"""

from enum import Enum
from typing import Dict, FrozenSet, Optional, Set


class AuditLevel(str, Enum):
    """Audit granularity levels, ordered from least to most verbose."""
    STANDARD = "standard"
    ENHANCED = "enhanced"
    FORENSIC = "forensic"


# ─── Mandatory fields (non-negotiable, every event) ──────────────

MANDATORY_FIELDS: FrozenSet[str] = frozenset({
    "agent_id",
    "org_id",
    "timestamp",
    "decision",       # allow | deny | shadow | bypass
    "sdk_state",      # enforced | degraded | bypass
})

# ─── Per-level additional fields ─────────────────────────────────

_STANDARD_FIELDS: FrozenSet[str] = frozenset({
    "action",         # semantic scope (api/read, db/write)
    "resource",       # host + path
    "http_method",    # GET, POST, DELETE
    "target_host",    # full hostname
    "target_path",    # URL path
    "status_code",    # HTTP response status
    "latency_ms",     # measured round-trip time
})

_ENHANCED_FIELDS: FrozenSet[str] = frozenset({
    "scope_matched",       # which policy scope allowed this
    "policy_id",           # which policy was evaluated
    "call_id",             # correlation ID for log joining
    "response_size_bytes", # size of response (not content)
    "delegation_depth",    # for multi-hop agent chains
})

_FORENSIC_FIELDS: FrozenSet[str] = frozenset({
    "session_id",          # groups all calls in one agent run
    "sdk_version",         # SDK version for compatibility tracking
    "retry_count",         # how many retries were attempted
    "deny_reason",         # detailed reason when decision=deny
    "source_ip",           # agent's outbound IP (if available)
    "user_agent",          # SDK user-agent string
})


# ─── Level → cumulative field set ────────────────────────────────

LEVEL_FIELDS: Dict[AuditLevel, FrozenSet[str]] = {
    AuditLevel.STANDARD: (
        MANDATORY_FIELDS | _STANDARD_FIELDS
    ),
    AuditLevel.ENHANCED: (
        MANDATORY_FIELDS | _STANDARD_FIELDS | _ENHANCED_FIELDS
    ),
    AuditLevel.FORENSIC: (
        MANDATORY_FIELDS | _STANDARD_FIELDS
        | _ENHANCED_FIELDS | _FORENSIC_FIELDS
    ),
}


# ─── Never-captured fields (privacy boundary) ────────────────────

NEVER_CAPTURED: FrozenSet[str] = frozenset({
    "request_body",
    "response_body",
    "authorization_header_value",
    "cookies",
    "query_parameter_values",
    "pii_from_url_paths",
})


# ─── Helpers ──────────────────────────────────────────────────────


def fields_for_level(level: AuditLevel) -> FrozenSet[str]:
    """Return the set of fields captured at a given audit level."""
    return LEVEL_FIELDS[level]


def filter_event(
    event: Dict[str, object],
    level: AuditLevel,
) -> Dict[str, object]:
    """Filter an audit event dict to only include fields for the level.

    Mandatory fields are always included regardless of level.
    Fields not in the level's field set are stripped.
    """
    allowed = LEVEL_FIELDS[level]
    return {k: v for k, v in event.items() if k in allowed}


def effective_level(
    org_level: AuditLevel,
    agent_level: Optional[AuditLevel] = None,
) -> AuditLevel:
    """Resolve the effective audit level for an agent.

    Rules:
    - Org level sets the floor.
    - Agent level can elevate above the floor but never go below.
    - A forensic-level org cannot have standard-level agents.
    """
    if agent_level is None:
        return org_level

    order = [
        AuditLevel.STANDARD,
        AuditLevel.ENHANCED,
        AuditLevel.FORENSIC,
    ]
    org_idx = order.index(org_level)
    agent_idx = order.index(agent_level)
    return order[max(org_idx, agent_idx)]


def validate_level(level_str: str) -> AuditLevel:
    """Parse and validate an audit level string."""
    try:
        return AuditLevel(level_str.lower())
    except ValueError:
        valid = ", ".join(l.value for l in AuditLevel)
        raise ValueError(
            f"Invalid audit level '{level_str}'. "
            f"Must be one of: {valid}"
        )
