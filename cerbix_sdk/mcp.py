"""AgentGate MCP client — JSON-RPC 2.0 wrapper through the proxy."""

import itertools
from typing import Any, Dict, List, Optional

from cerbix_sdk.client import AgentGateClient


class AgentGateMCPClient:
    """MCP client that sends JSON-RPC 2.0 requests through the AgentGate proxy."""

    def __init__(self, client: AgentGateClient):
        self._client = client
        self._id_counter = itertools.count(1)

    async def call(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Send a JSON-RPC 2.0 request and return the result.

        Raises RuntimeError on JSON-RPC errors.
        """
        req_id = next(self._id_counter)
        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "id": req_id,
        }
        if params is not None:
            payload["params"] = params

        headers = await self._client._auth_headers()
        resp = await self._client._http.post(
            f"{self._client.proxy_url}/mcp",
            headers=headers,
            json=payload,
        )
        resp.raise_for_status()
        body = resp.json()

        if "error" in body:
            err = body["error"]
            raise RuntimeError(f"MCP error {err['code']}: {err['message']}")

        return body.get("result")

    async def list_tools(self) -> List[Dict[str, Any]]:
        """Discover available tools via tools/list."""
        result = await self.call("tools/list")
        return result.get("tools", []) if result else []

    async def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
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
