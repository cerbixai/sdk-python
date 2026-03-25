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

import json as _json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

import httpx

from cerbix_sdk.audit_levels import AuditLevel, filter_event, effective_level
from cerbix_sdk.client import AgentGateClient
from cerbix_sdk.resilience import ProxyState, ResilientClient

logger = logging.getLogger("cerbix_sdk")


# ─── Structured Logging ──────────────────────────────────────────


class _StructuredFormatter(logging.Formatter):
    """JSON log formatter for production log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Merge extra fields (call_id, decision, etc.)
        if hasattr(record, "cerbi_data"):
            entry.update(record.cerbi_data)
        return _json.dumps(entry)


def setup_structured_logging(
    level: int = logging.DEBUG,
    handler: Optional[logging.Handler] = None,
) -> None:
    """Enable structured JSON logging for the CerbiX SDK.

    Usage:
        from cerbix_sdk.interceptor import setup_structured_logging
        setup_structured_logging()

    This configures the 'cerbix_sdk' logger to emit JSON lines like:
        {"timestamp":"2026-03-25T12:00:00Z","level":"DEBUG",
         "logger":"cerbix_sdk","message":"...",
         "call_id":"c_abc123","decision":"allow",...}
    """
    target = handler or logging.StreamHandler()
    target.setFormatter(_StructuredFormatter())
    sdk_logger = logging.getLogger("cerbix_sdk")
    sdk_logger.setLevel(level)
    sdk_logger.addHandler(target)


def _log_event(
    level: int,
    msg: str,
    call_id: str,
    **extra: object,
) -> None:
    """Log with call_id correlation and optional structured data."""
    record = logger.makeRecord(
        logger.name, level, "(interceptor)", 0,
        f"[{call_id}] {msg}", (), None,
    )
    record.cerbi_data = {"call_id": call_id, **extra}  # type: ignore
    logger.handle(record)


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
        audit_level: AuditLevel = AuditLevel.STANDARD,
        session_id: Optional[str] = None,
    ):
        self._wrapped = wrapped
        self._resilient = resilient
        self._declared_scopes = declared_scopes or []
        self._enforce_policy = enforce_policy
        self._audit_level = audit_level
        self._session_id = session_id or f"s_{uuid.uuid4().hex[:12]}"
        from cerbix_sdk import __version__ as _sdk_version
        self._sdk_version = _sdk_version

    def _build_event(
        self,
        call_id: str,
        timestamp: str,
        resolved_scope: str,
        host: str,
        path: str,
        method: str,
        decision: str,
        matched_scope: Optional[str],
        latency_ms: int,
        status_code: int,
        state: ProxyState,
        deny_reason: str = "",
        response_size: int = 0,
    ) -> Dict[str, object]:
        """Build a full event dict then filter to the configured level."""
        # Full forensic-level event (superset of all fields)
        full_event: Dict[str, object] = {
            # ── Mandatory (always included) ──
            "org_id": self._resilient.org_id,
            "agent_id": self._resilient.agent_id,
            "timestamp": timestamp,
            "decision": decision,
            "sdk_state": state.value,
            # ── Minimal ──
            "action": resolved_scope,
            "resource": f"{host}{path}",
            # ── Standard ──
            "http_method": method,
            "target_host": host,
            "target_path": path,
            "status_code": status_code,
            "latency_ms": latency_ms,
            # ── Enhanced ──
            "scope_matched": matched_scope,
            "policy_id": None,  # set by backend after eval
            "call_id": call_id,
            "response_size_bytes": response_size,
            "delegation_depth": 0,
            # ── Forensic ──
            "session_id": self._session_id,
            "sdk_version": self._sdk_version,
            "retry_count": 0,
            "deny_reason": deny_reason,
            "source_ip": "",
            "user_agent": f"cerbix-sdk/{self._sdk_version}",
        }
        return filter_event(full_event, self._audit_level)

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
                deny_event = self._build_event(
                    call_id=call_id, timestamp=timestamp,
                    resolved_scope=resolved_scope,
                    host=host, path=path,
                    method=request.method, decision="deny",
                    matched_scope=None, latency_ms=0,
                    status_code=403, state=state,
                    deny_reason=f"scope {resolved_scope} not in "
                    f"declared scopes",
                )
                await self._resilient.record_event(deny_event)
            except Exception:
                pass

            _log_event(
                logging.WARNING,
                f"DENY {request.method} {request.url.scheme}://{host}{path}"
                f" (scope={resolved_scope})",
                call_id,
                decision="deny",
                http_method=request.method,
                target_host=host,
                target_path=path,
                scope=resolved_scope,
                status_code=403,
                sdk_state=state.value,
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

        # ── Record audit event (filtered by audit level) ──
        try:
            event = self._build_event(
                call_id=call_id, timestamp=timestamp,
                resolved_scope=resolved_scope,
                host=host, path=path,
                method=request.method, decision=decision,
                matched_scope=matched_scope,
                latency_ms=latency_ms,
                status_code=response.status_code,
                state=state,
                response_size=len(response.content)
                if hasattr(response, 'content') else 0,
            )
            await self._resilient.record_event(event)
        except Exception:
            pass  # never block the response

        _log_event(
            logging.DEBUG,
            f"[{state.value}] {decision}: {request.method}"
            f" {request.url.scheme}://{host}{path}"
            f" → {response.status_code} ({latency_ms}ms)",
            call_id,
            decision=decision,
            http_method=request.method,
            target_host=host,
            target_path=path,
            scope=resolved_scope,
            scope_matched=matched_scope,
            status_code=response.status_code,
            latency_ms=latency_ms,
            sdk_state=state.value,
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
    audit_level: str = "standard",
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

    from cerbix_sdk.audit_levels import validate_level
    level = validate_level(audit_level)

    original_transport = client._transport
    client._transport = CerbiTransport(
        original_transport, resilient,
        declared_scopes=declared_scopes,
        enforce_policy=enforce_policy,
        audit_level=level,
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
