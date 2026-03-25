"""AgentGate MCP client — JSON-RPC 2.0 wrapper with audit logging.

Every MCP call (tools/call, resources/read, etc.) is recorded as an
audit event so that MCP tool invocations are visible alongside HTTP
calls in the audit trail.
"""

import itertools
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, List, Optional

from cerbix_sdk.client import AgentGateClient

logger = logging.getLogger(__name__)

# Type alias for the optional audit recorder
AuditRecorder = Optional[
    Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]
]


class AgentGateMCPClient:
    """MCP client that sends JSON-RPC 2.0 requests through the proxy.

    When an audit_recorder is provided, every MCP call generates an
    audit event with the same shape as HTTP audit events.
    """

    def __init__(
        self,
        client: AgentGateClient,
        audit_recorder: AuditRecorder = None,
    ):
        self._client = client
        self._id_counter = itertools.count(1)
        self._audit = audit_recorder

    async def _record(self, event: Dict[str, Any]) -> None:
        """Record an audit event if a recorder is available."""
        if self._audit:
            try:
                await self._audit(event)
            except Exception:
                pass  # never block the MCP response

    async def call(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Send a JSON-RPC 2.0 request and return the result.

        Records an audit event for every call.
        Raises RuntimeError on JSON-RPC errors.
        """
        req_id = next(self._id_counter)
        call_id = f"mcp_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "id": req_id,
        }
        if params is not None:
            payload["params"] = params

        headers = await self._client._auth_headers()

        # Measure latency
        t0 = time.perf_counter()
        resp = await self._client._http.post(
            f"{self._client.proxy_url}/mcp",
            headers=headers,
            json=payload,
        )
        latency_ms = round((time.perf_counter() - t0) * 1000)

        resp.raise_for_status()
        body = resp.json()

        # Determine scope from MCP method
        scope = _mcp_method_to_scope(method, params)
        has_error = "error" in body
        decision = "allow" if not has_error else "deny"

        # Record audit event
        await self._record({
            "org_id": self._client.org_id or "",
            "agent_id": self._client.agent_id or "",
            "action": scope,
            "resource": f"mcp://{method}",
            "http_method": "POST",
            "target_host": "mcp-proxy",
            "target_path": f"/mcp/{method}",
            "decision": decision,
            "scope_matched": scope,
            "timestamp": timestamp,
            "latency_ms": latency_ms,
            "status_code": resp.status_code,
            "sdk_state": "enforced",
            "call_id": call_id,
        })

        if has_error:
            err = body["error"]
            raise RuntimeError(
                f"MCP error {err['code']}: {err['message']}"
            )

        return body.get("result")

    async def list_tools(self) -> List[Dict[str, Any]]:
        """Discover available tools via tools/list."""
        result = await self.call("tools/list")
        return result.get("tools", []) if result else []

    async def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Call a tool by name."""
        params: Dict[str, Any] = {"name": name}
        if arguments:
            params["arguments"] = arguments
        return await self.call("tools/call", params)

    async def list_resources(self) -> List[Dict[str, Any]]:
        """Discover available resources via resources/list."""
        result = await self.call("resources/list")
        return result.get("resources", []) if result else []

    async def read_resource(self, uri: str) -> Any:
        """Read a resource by URI."""
        return await self.call("resources/read", {"uri": uri})


def _mcp_method_to_scope(
    method: str, params: Optional[Dict[str, Any]] = None
) -> str:
    """Map MCP method to a semantic scope string.

    tools/list      → tools/read
    tools/call      → tools/execute
    resources/list  → resources/read
    resources/read  → resources/read
    """
    mapping = {
        "tools/list": "tools/read",
        "tools/call": "tools/execute",
        "resources/list": "resources/read",
        "resources/read": "resources/read",
        "prompts/list": "resources/read",
        "prompts/get": "resources/read",
    }

    scope = mapping.get(method, f"mcp/{method}")

    # Append tool name for tools/call
    if method == "tools/call" and params and params.get("name"):
        scope = f"tools/execute:{params['name']}"

    return scope
