"""Transparent HTTP interceptor for CerbiX credential injection.

Wraps any httpx.AsyncClient to automatically:
1. Inject CerbiX Bearer token on every outbound request
2. Auto-refresh token before expiry
3. Log requests to CerbiX audit trail
4. Graceful degradation: bypass mode when CerbiX is unreachable

Developer experience — 3 lines of code:

    from sdk.interceptor import wrap

    client = wrap(httpx.AsyncClient(), org_id="...", agent_id="...")
    # Works whether CerbiX is up or down. Zero behaviour change.
"""

import logging
from typing import Optional

import httpx

from sdk.client import AgentGateClient
from sdk.resilience import ProxyState, ResilientClient

logger = logging.getLogger(__name__)


class CerbiTransport(httpx.AsyncBaseTransport):
    """Transport that injects CerbiX tokens with graceful degradation."""

    def __init__(
        self,
        wrapped: httpx.AsyncBaseTransport,
        resilient: ResilientClient,
    ):
        self._wrapped = wrapped
        self._resilient = resilient

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        state = self._resilient.state
        token = await self._resilient.get_token()

        if token:
            request.headers["Authorization"] = f"Bearer {token}"

        # Add state header for observability
        request.headers["X-Cerbi-State"] = state.value

        # Forward to actual destination
        response = await self._wrapped.handle_async_request(request)

        # Record audit event asynchronously
        try:
            await self._resilient.record_event({
                "org_id": self._resilient.org_id,
                "agent_id": self._resilient.agent_id,
                "action": request.method,
                "resource": str(request.url.path),
                "decision": (
                    "observe" if state == ProxyState.BYPASS
                    else "allow"
                ),
                "latency_ms": 0,
            })
        except Exception:
            pass  # never block the response

        logger.debug(
            "CerbiX [%s]: %s %s → %s",
            state.value, request.method,
            request.url, response.status_code,
        )
        return response


def wrap(
    client: httpx.AsyncClient,
    org_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    control_url: str = "https://cerbix-ai.web.app/api/control",
    proxy_url: str = "https://cerbix-ai.web.app",
    audit_url: str = "https://cerbix-ai.web.app/api/audit",
    bypass_on_failure: bool = True,
    gate_client: Optional[AgentGateClient] = None,
) -> httpx.AsyncClient:
    """Wrap an httpx.AsyncClient with resilient CerbiX governance.

    Usage:
        import httpx
        from sdk.interceptor import wrap

        client = wrap(httpx.AsyncClient(), org_id="...", agent_id="...")
        resp = await client.get("https://api.example.com/data")
        # Works whether CerbiX is up or down

    Three operating states:
        ENFORCED — CerbiX healthy, full governance
        DEGRADED — CerbiX slow, async audit
        BYPASS   — CerbiX down, local buffer, direct calls
    """
    resilient = ResilientClient(
        control_url=control_url,
        proxy_url=proxy_url,
        audit_url=audit_url,
        org_id=org_id or "",
        agent_id=agent_id or "",
        bypass_on_failure=bypass_on_failure,
    )

    original_transport = client._transport
    client._transport = CerbiTransport(original_transport, resilient)

    original_close = client.aclose

    async def _close_with_resilient():
        await resilient.stop()
        await original_close()

    client.aclose = _close_with_resilient  # type: ignore

    # Attach status method for observability
    client.cerbi_status = resilient.get_status  # type: ignore

    return client


def wrap_sync(
    org_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    control_url: str = "https://cerbix-ai.web.app/api/control",
) -> dict:
    """Get headers dict for synchronous HTTP clients.

    Usage:
        from sdk.interceptor import wrap_sync
        headers = wrap_sync(org_id="...", agent_id="...")
        requests.get("https://api.example.com", headers=headers)
    """
    import requests

    try:
        resp = requests.post(
            f"{control_url}/orgs/{org_id}/agents/{agent_id}/token",
            timeout=5,
        )
        resp.raise_for_status()
        token = resp.json()["data"]["access_token"]
    except Exception:
        logger.warning("CerbiX unreachable — proceeding without token")
        token = ""

    headers = {
        "X-Cerbi-Agent": agent_id or "",
        "X-Cerbi-Org": org_id or "",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    return headers
