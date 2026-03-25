"""CerbiX SDK — AI agent identity & access control in three lines of code.

Usage:
    from cerbix_sdk import CerbixSDK, wrap

    cerbix = CerbixSDK(org_id="...", agent_id="...")
    client = wrap(httpx.AsyncClient(), org_id="...", agent_id="...")
"""

from cerbix_sdk.audit_levels import AuditLevel, effective_level
from cerbix_sdk.auth import generate_pkce_pair
from cerbix_sdk.bundle import PolicyBundleLoader
from cerbix_sdk.client import AgentGateClient
from cerbix_sdk.interceptor import (
    wrap, wrap_sync, resolve_scope, check_scope, setup_structured_logging,
)
from cerbix_sdk.mcp import AgentGateMCPClient
from cerbix_sdk.policy import (
    Decision,
    DecisionResolver,
    OrgPolicy,
    PolicyBundle,
    PolicyEngine,
    ScopeResolver,
    ScopeRule,
)
from cerbix_sdk.resilience import ResilientClient

# User-friendly alias matching the get-started wizard
CerbixSDK = AgentGateClient

__version__ = "0.4.0"

__all__ = [
    # Core
    "CerbixSDK",
    "AgentGateClient",
    "AgentGateMCPClient",
    "ResilientClient",
    # Auth
    "generate_pkce_pair",
    # Interceptor
    "wrap",
    "wrap_sync",
    "resolve_scope",
    "check_scope",
    "setup_structured_logging",
    # Policy layer
    "Decision",
    "DecisionResolver",
    "OrgPolicy",
    "PolicyBundle",
    "PolicyBundleLoader",
    "PolicyEngine",
    "ScopeResolver",
    "ScopeRule",
    # Audit levels
    "AuditLevel",
    "effective_level",
]
