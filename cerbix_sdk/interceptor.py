"""Transparent HTTP interceptor with full policy enforcement.

Component 4 of the policy layer. Orchestrates:
  ScopeResolver → PolicyEngine → DecisionResolver → forward/deny → AuditWriter

Developer experience — 3 lines of code:

    from cerbix_sdk import wrap
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

from cerbix_sdk.audit_levels import AuditLevel, filter_event
from cerbix_sdk.bundle import PolicyBundleLoader
from cerbix_sdk.client import AgentGateClient
from cerbix_sdk.policy import (
    Decision,
    DecisionResolver,
    OrgPolicy,
    PolicyBundle,
    PolicyEngine,
    ScopeResolver,
)
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
        if hasattr(record, "cerbi_data"):
            entry.update(record.cerbi_data)
        return _json.dumps(entry)


def setup_structured_logging(
    level: int = logging.DEBUG,
    handler: Optional[logging.Handler] = None,
) -> None:
    """Enable structured JSON logging for the CerbiX SDK."""
    target = handler or logging.StreamHandler()
    target.setFormatter(_StructuredFormatter())
    sdk_logger = logging.getLogger("cerbix_sdk")
    sdk_logger.setLevel(level)
    sdk_logger.addHandler(target)


def _log_event(
    level: int, msg: str, call_id: str, **extra: object,
) -> None:
    """Log with call_id correlation and optional structured data."""
    record = logger.makeRecord(
        logger.name, level, "(interceptor)", 0,
        f"[{call_id}] {msg}", (), None,
    )
    record.cerbi_data = {"call_id": call_id, **extra}  # type: ignore
    logger.handle(record)


# ─── Legacy scope helpers (kept for back-compat) ─────────────────


_METHOD_TO_VERB: Dict[str, str] = {
    "GET": "read", "HEAD": "read", "OPTIONS": "read",
    "POST": "write", "PUT": "write", "PATCH": "write",
    "DELETE": "execute",
}

_PATH_TO_CATEGORY: List[tuple] = [
    ("/api/", "api"), ("/db/", "db"), ("/tools/", "tools"),
    ("/resources/", "resources"), ("/files/", "files"),
    ("/search", "search"), ("/email/", "email"),
    ("/slack/", "slack"), ("/calendar/", "calendar"),
    ("/billing/", "billing"),
]


def resolve_scope(method: str, host: str, path: str) -> str:
    """Legacy scope resolver (used when no scope_map is provided)."""
    verb = _METHOD_TO_VERB.get(method.upper(), "read")
    path_lower = path.lower()
    for prefix, category in _PATH_TO_CATEGORY:
        if path_lower.startswith(prefix):
            return f"{category}/{verb}"
    return f"http/{verb}"


def check_scope(
    resolved: str, declared_scopes: List[str],
) -> tuple:
    """Legacy scope check (used when no PolicyBundle)."""
    if not declared_scopes:
        return True, None
    for scope in declared_scopes:
        if scope == resolved:
            return True, scope
        if scope.endswith("/*"):
            if resolved.startswith(scope[:-1]):
                return True, scope
    return False, None


# ─── Component 4: Transport Interceptor ──────────────────────────


class CerbiTransport(httpx.AsyncBaseTransport):
    """Full policy-enforcing transport.

    Orchestrates: ScopeResolver → PolicyEngine → DecisionResolver
    Then either blocks (DENY) or forwards and audits.
    """

    def __init__(
        self,
        wrapped: httpx.AsyncBaseTransport,
        resilient: ResilientClient,
        bundle_loader: Optional[PolicyBundleLoader] = None,
        # Legacy fallbacks (used when no bundle)
        declared_scopes: Optional[List[str]] = None,
        enforce_policy: bool = True,
        audit_level: AuditLevel = AuditLevel.STANDARD,
        session_id: Optional[str] = None,
    ):
        self._wrapped = wrapped
        self._resilient = resilient
        self._bundle_loader = bundle_loader
        self._declared_scopes = declared_scopes or []
        self._enforce_policy = enforce_policy
        self._audit_level = audit_level
        self._session_id = session_id or f"s_{uuid.uuid4().hex[:12]}"
        from cerbix_sdk import __version__ as _v
        self._sdk_version = _v

    def _get_engine_components(self):
        """Build resolver + engine from bundle or legacy config."""
        loader = self._bundle_loader
        bundle = loader.bundle if loader else None

        if bundle and bundle.scope_map:
            resolver = ScopeResolver(bundle.scope_map)
            engine = PolicyEngine(bundle)
            agent_status = bundle.agent_status
        else:
            # Legacy mode: use flat declared_scopes
            resolver = None
            engine = None
            agent_status = "enforced" if self._enforce_policy else "shadow"

        return resolver, engine, agent_status

    async def handle_async_request(
        self, request: httpx.Request,
    ) -> httpx.Response:
        state = self._resilient.state
        call_id = f"c_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        t0 = time.perf_counter()

        # Parse request target
        host = str(request.url.host or "")
        path = str(request.url.raw_path, "utf-8") if isinstance(
            request.url.raw_path, bytes,
        ) else str(request.url.path)

        resolver, engine, agent_status = self._get_engine_components()

        # ── Step 1: Resolve scope ─────────────────────────────────
        if resolver:
            scope, resource = resolver.resolve(
                request.method, host, path,
            )
        else:
            scope = resolve_scope(request.method, host, path)
            resource = f"{host}{path}"

        # ── Step 2: Evaluate policy ───────────────────────────────
        if engine:
            policy_decision = engine.evaluate(scope, resource)
        else:
            # Legacy: simple scope check
            allowed, matched = check_scope(
                scope, self._declared_scopes,
            )
            from cerbix_sdk.policy import PolicyDecision, Decision
            if allowed:
                policy_decision = PolicyDecision(
                    result=Decision.ALLOW,
                    scope=scope, resource=resource,
                )
            else:
                policy_decision = PolicyDecision(
                    result=Decision.DENY,
                    deny_reason="scope_not_declared",
                    checked_at="declared_scope",
                    scope=scope, resource=resource,
                )

        # ── Step 3: Apply shadow / bypass override ────────────────
        final = DecisionResolver.resolve_final(
            policy_decision=policy_decision,
            agent_status=agent_status,
            sdk_state=state.value,
        )

        # ── Step 4: If DENY in enforced mode — block ─────────────
        if final.decision == Decision.DENY:
            latency_ms = round((time.perf_counter() - t0) * 1000)
            event = self._build_event(
                call_id=call_id, timestamp=timestamp,
                scope=scope, resource=resource,
                method=request.method, host=host, path=path,
                decision="deny",
                deny_reason=final.deny_reason or "",
                latency_ms=latency_ms, status_code=403,
                state=state, agent_status=agent_status,
                matched_scope=None,
            )
            try:
                await self._resilient.record_event(event)
            except Exception:
                pass

            _log_event(
                logging.WARNING,
                f"DENY {request.method} {host}{path} "
                f"({final.deny_reason})",
                call_id,
                decision="deny",
                deny_reason=final.deny_reason,
                scope=scope,
            )

            return httpx.Response(
                status_code=403,
                headers={"X-Cerbi-Decision": "deny"},
                content=_json.dumps({
                    "error": "policy_denied",
                    "reason": final.deny_reason,
                    "scope": scope,
                    "agent_id": (
                        engine.agent_id if engine
                        else self._resilient.agent_id
                    ),
                }).encode(),
            )

        # ── Step 5: Inject token and forward ──────────────────────
        token = await self._resilient.get_token()
        if token:
            request.headers["Authorization"] = f"Bearer {token}"
        request.headers["X-Cerbi-State"] = state.value
        request.headers["X-Cerbi-Call-Id"] = call_id

        response = await self._wrapped.handle_async_request(request)
        latency_ms = round((time.perf_counter() - t0) * 1000)

        # ── Step 6: Write audit event (async, non-blocking) ───────
        event = self._build_event(
            call_id=call_id, timestamp=timestamp,
            scope=scope, resource=resource,
            method=request.method, host=host, path=path,
            decision=final.decision.value,
            deny_reason=final.deny_reason or "",
            latency_ms=latency_ms,
            status_code=response.status_code,
            state=state, agent_status=agent_status,
            matched_scope=scope if final.decision == Decision.ALLOW else None,
            response_size=len(response.content)
            if hasattr(response, "content") else 0,
        )
        try:
            await self._resilient.record_event(event)
        except Exception:
            pass

        _log_event(
            logging.DEBUG,
            f"[{state.value}] {final.decision.value}: "
            f"{request.method} {host}{path} "
            f"→ {response.status_code} ({latency_ms}ms)",
            call_id,
            decision=final.decision.value,
            scope=scope,
            status_code=response.status_code,
            latency_ms=latency_ms,
        )
        return response

    def _build_event(
        self, *,
        call_id: str, timestamp: str,
        scope: str, resource: str,
        method: str, host: str, path: str,
        decision: str, deny_reason: str,
        latency_ms: int, status_code: int,
        state: ProxyState, agent_status: str,
        matched_scope: Optional[str] = None,
        response_size: int = 0,
    ) -> Dict[str, object]:
        """Build full event then filter by audit level."""
        full: Dict[str, object] = {
            # Mandatory
            "org_id": self._resilient.org_id,
            "agent_id": self._resilient.agent_id,
            "timestamp": timestamp,
            "decision": decision,
            "sdk_state": state.value,
            # Standard
            "action": scope,
            "resource": resource,
            "http_method": method,
            "target_host": host,
            "target_path": path,
            "status_code": status_code,
            "latency_ms": latency_ms,
            # Enhanced
            "scope_matched": matched_scope,
            "policy_id": None,
            "call_id": call_id,
            "response_size_bytes": response_size,
            "delegation_depth": 0,
            # Forensic
            "session_id": self._session_id,
            "sdk_version": self._sdk_version,
            "retry_count": 0,
            "deny_reason": deny_reason,
            "source_ip": "",
            "user_agent": f"cerbix-sdk/{self._sdk_version}",
        }
        return filter_event(full, self._audit_level)


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
    load_policy_bundle: bool = False,
    gate_client: Optional[AgentGateClient] = None,
) -> httpx.AsyncClient:
    """Wrap an httpx.AsyncClient with resilient CerbiX governance.

    Usage:
        import httpx
        from cerbix_sdk import wrap

        # Simple mode (flat scope list):
        client = wrap(
            httpx.AsyncClient(),
            org_id="...", agent_id="...",
            declared_scopes=["api/read", "db/read"],
        )

        # Full mode (policy bundle from server):
        client = wrap(
            httpx.AsyncClient(),
            org_id="...", agent_id="...",
            load_policy_bundle=True,
        )

    Args:
        declared_scopes: Flat list of allowed scopes (simple mode).
        load_policy_bundle: If True, fetches full policy bundle from
            control service at startup (scope_map, org_policy, etc.).
        enforce_policy: If True, out-of-scope calls return 403.
            If False, runs in shadow mode locally.
        audit_level: "standard" | "enhanced" | "forensic"
    """
    from cerbix_sdk.audit_levels import validate_level
    level = validate_level(audit_level)

    resilient = ResilientClient(
        control_url=control_url,
        proxy_url=proxy_url,
        audit_url=audit_url,
        org_id=org_id or "",
        agent_id=agent_id or "",
        bypass_on_failure=bypass_on_failure,
    )

    bundle_loader = None
    if load_policy_bundle and org_id and agent_id:
        bundle_loader = PolicyBundleLoader(
            control_url=control_url,
            org_id=org_id,
            agent_id=agent_id,
        )

    original_transport = client._transport
    client._transport = CerbiTransport(
        original_transport, resilient,
        bundle_loader=bundle_loader,
        declared_scopes=declared_scopes,
        enforce_policy=enforce_policy,
        audit_level=level,
    )

    original_close = client.aclose

    async def _close():
        if bundle_loader:
            await bundle_loader.stop()
        await resilient.stop()
        await original_close()

    client.aclose = _close  # type: ignore
    client.cerbi_status = resilient.get_status  # type: ignore

    # Attach bundle loader for manual control
    if bundle_loader:
        client.cerbi_bundle = bundle_loader  # type: ignore

    return client


def wrap_sync(
    org_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    control_url: str = "https://cerbix-ai.web.app/api/control",
) -> dict:
    """Get headers dict for synchronous HTTP clients."""
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
