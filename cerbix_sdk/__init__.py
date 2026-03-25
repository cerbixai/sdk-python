"""CerbiX SDK — AI agent identity & access control in three lines of code.

Usage:
    from cerbix_sdk import CerbixSDK, wrap

    cerbix = CerbixSDK(org_id="...", agent_id="...")
    client = wrap(httpx.AsyncClient(), org_id="...", agent_id="...")
"""

from cerbix_sdk.auth import generate_pkce_pair
from cerbix_sdk.client import AgentGateClient
from cerbix_sdk.interceptor import wrap, wrap_sync, resolve_scope, check_scope
from cerbix_sdk.mcp import AgentGateMCPClient
from cerbix_sdk.resilience import ResilientClient

# User-friendly alias matching the get-started wizard
CerbixSDK = AgentGateClient

__version__ = "0.2.0"

__all__ = [
    "CerbixSDK",
    "AgentGateClient",
    "AgentGateMCPClient",
    "ResilientClient",
    "generate_pkce_pair",
    "wrap",
    "wrap_sync",
    "resolve_scope",
    "check_scope",
]
