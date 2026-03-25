"""Transparent HTTP interceptor with policy enforcement and audit.

Wraps any httpx.AsyncClient to automatically:
1. Evaluate declared scopes before forwarding (deny out-of-scope)
2. Inject CerbiX Bearer token on every outbound request
3. Measure real latency and record timestamp
4. Log rich audit events (host, status code, scope, decision)
5. Graceful degradation: bypass mode when CerbiX is unreachable

Developer experience — 3 lines of code:

    from cerbix_sdk.interceptor import wrap

    client = wrap(httpx.AsyncClient(), org_id="...", agent_id="...")
    # Works whether CerbiX is up or down. Zero behaviour change.
"""

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

from cerbix_sdk.client import AgentGateClient
from cerbix_sdk.resilience import ProxyState, ResilientClient

logger = logging.getLogger(__name__)


# ─── Scope Resolver ───────────────────────────────────────────────


# Default mapping: HTTP method → scope verb
_METHOD_TO_VERB: Dict[str, str] = {
    "GET": "read",
    "HEAD": "read",
    "OPTIONS": "read",
    "POST": "write",
    "PUT": "write",
    "PATCH": "write",
    "DELETE": "execute",
}

# Well-known path prefix → scope category
_PATH_TO_CATEGORY: List[tuple] = [
    ("/api/", "api"),
    ("/db/", "db"),
    ("/tools/", "tools"),
    ("/resources/", "resources"),
    ("/files/", "files"),
    ("/search", "search"),
    ("/email/", "email"),
    ("/slack/", "slack"),
    ("/calendar/", "calendar"),
    ("/billing/", "billing"),
]


def resolve_scope(method: str, host: str, path: str) -> str:
    """Map (HTTP method, host, path) → semantic scope string.

    Examples:
        GET  /api/users      → api/read
        POST /db/records     → db/write
        GET  /billing/invoices → billing/read
        DELETE /tools/cache   → tools/execute

    Falls back to "http/{verb}" for unrecognised paths.
    """
    verb = _METHOD_TO_VERB.get(method.upper(), "read")

    path_lower = path.lower()
    for prefix, category in _PATH_TO_CATEGORY:
        if path_lower.startswith(prefix):
            return f"{category}/{verb}"

    return f"http/{verb}"


def check_scope(
    resolved: str, declared_scopes: List[str]
) -> tuple:
    """Check if a resolved scope is allowed by declared scopes.

    Returns (allowed: bool, matched_scope: str | None).
    Supports wildcard scopes like 'api/*' and 'tools/*'.
    """
    if not declared_scopes:
        # No scopes declared = allow everything (open policy)
        return True, None

    for scope in declared_scopes:
        # Exact match
        if scope == resolved:
            return True, scope
        # Wildcard: "api/*" matches "api/read", "api/write"
        if scope.endswith("/*"):
            prefix = scope[:-1]  # "api/"
            if resolved.startswith(prefix):
                return True, scope

    return False, None


# ─── Transport ────────────────────────────────────────────────────


class CerbiTransport(httpx.AsyncBaseTransport):
    """Transport that enforces policy and records full audit events."""

    def __init__(
        self,
        wrapped: httpx.AsyncBaseTransport,
        resilient: ResilientClient,
        declared_scopes: Optional[List[str]] = None,
        enforce_policy: bool = True,
    ):
        self._wrapped = wrapped
        self._resilient = resilient
        self._declared_scopes = declared_scopes or []
        self._enforce_policy = enforce_policy

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        state = self._resilient.state
        call_id = f"c_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # ── Resolve scope ──
        host = str(request.url.host or "")
        path = str(request.url.raw_path, "utf-8") if isinstance(
            request.url.raw_path, bytes
        ) else str(request.url.path)
        resolved_scope = resolve_scope(request.method, host, path)

        # ── Policy evaluation (Gap 1) ──
        allowed, matched_scope = check_scope(
            resolved_scope, self._declared_scopes
        )

        if (
            not allowed
            and self._enforce_policy
            and state == ProxyState.ENFORCED
        ):
            # Deny: record event and return 403
            try:
                await self._resilient.record_event({
                    "org_id": self._resilient.org_id,
                    "agent_id": self._resilient.agent_id,
                    "action": resolved_scope,
                    "resource": f"{host}{path}",
                    "http_method": request.method,
                    "target_host": host,
                    "target_path": path,
                    "decision": "deny",
                    "scope_matched": None,
                    "timestamp": timestamp,
                    "latency_ms": 0,
                    "status_code": 403,
                    "sdk_state": state.value,
                    "call_id": call_id,
                })
            except Exception:
                pass

            logger.warning(
                "CerbiX DENY: %s %s://%s%s (scope=%s not in %s)",
                request.method, request.url.scheme, host,
                path, resolved_scope, self._declared_scopes,
            )

            return httpx.Response(
                status_code=403,
                headers={"X-Cerbi-Decision": "deny"},
                content=b'{"error":"scope_denied","message":'
                b'"Request blocked by CerbiX policy"}',
            )

        # ── Inject token ──
        token = await self._resilient.get_token()
        if token:
            request.headers["Authorization"] = f"Bearer {token}"
        request.headers["X-Cerbi-State"] = state.value
        request.headers["X-Cerbi-Call-Id"] = call_id

        # ── Forward + measure latency (Gap 2) ──
        t0 = time.perf_counter()
        response = await self._wrapped.handle_async_request(request)
        latency_ms = round((time.perf_counter() - t0) * 1000)

        # ── Determine decision ──
        if state == ProxyState.BYPASS:
            decision = "bypass"
        elif not allowed:
            # Non-enforced mode (shadow) — log but don't block
            decision = "shadow"
        else:
            decision = "allow"

        # ── Record full audit event (Gaps 2,3,5,6,7) ──
        try:
            await self._resilient.record_event({
                "org_id": self._resilient.org_id,
                "agent_id": self._resilient.agent_id,
                "action": resolved_scope,
                "resource": f"{host}{path}",
                "http_method": request.method,
                "target_host": host,
                "target_path": path,
                "decision": decision,
                "scope_matched": matched_scope,
                "timestamp": timestamp,
                "latency_ms": latency_ms,
                "status_code": response.status_code,
                "sdk_state": state.value,
                "call_id": call_id,
            })
        except Exception:
            pass  # never block the response

        logger.debug(
            "CerbiX [%s] %s: %s %s://%s%s → %s (%dms)",
            state.value, decision, request.method,
            request.url.scheme, host, path,
            response.status_code, latency_ms,
        )
        return response


# ─── Wrap functions ───────────────────────────────────────────────


def wrap(
    client: httpx.AsyncClient,
    org_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    control_url: str = "https://cerbix-ai.web.app/api/control",
    proxy_url: str = "https://cerbix-ai.web.app",
    audit_url: str = "https://cerbix-ai.web.app/api/audit",
    bypass_on_failure: bool = True,
    declared_scopes: Optional[List[str]] = None,
    enforce_policy: bool = True,
    gate_client: Optional[AgentGateClient] = None,
) -> httpx.AsyncClient:
    """Wrap an httpx.AsyncClient with resilient CerbiX governance.

    Usage:
        import httpx
        from cerbix_sdk.interceptor import wrap

        client = wrap(
            httpx.AsyncClient(),
            org_id="...", agent_id="...",
            declared_scopes=["api/read", "db/read"],
        )
        resp = await client.get("https://api.example.com/data")
        # Works whether CerbiX is up or down

    Args:
        declared_scopes: List of allowed scope strings (e.g.
            ["api/read", "api/write", "db/read"]).
            If empty, all calls are allowed (open policy).
        enforce_policy: If True, out-of-scope calls return 403.
            If False, out-of-scope calls are logged as "shadow"
            but still forwarded.

    Three operating states:
        ENFORCED — CerbiX healthy, full governance + deny
        DEGRADED — CerbiX slow, async audit, no deny
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
    client._transport = CerbiTransport(
        original_transport, resilient,
        declared_scopes=declared_scopes,
        enforce_policy=enforce_policy,
    )

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
        from cerbix_sdk.interceptor import wrap_sync
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
