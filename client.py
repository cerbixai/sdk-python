"""AgentGate SDK client — handles authentication and token lifecycle."""

import time
from typing import Any, Dict, Optional

import httpx


class AgentGateClient:
    """Client for interacting with AgentGate services.

    Handles token acquisition from the Control service and auto-refreshes
    60 seconds before expiry.
    """

    def __init__(
        self,
        control_url: str = "http://localhost:8081",
        proxy_url: str = "http://localhost:8080",
        org_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ):
        self.control_url = control_url.rstrip("/")
        self.proxy_url = proxy_url.rstrip("/")
        self.org_id = org_id
        self.agent_id = agent_id
        self._token: Optional[str] = None
        self._token_expires_at: float = 0
        self._http = httpx.AsyncClient(timeout=30.0)

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AgentGateClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def get_token(self) -> str:
        """Get a valid token, refreshing if needed (60s before expiry)."""
        if self._token and time.time() < (self._token_expires_at - 60):
            return self._token
        return await self._refresh_token()

    async def _refresh_token(self) -> str:
        """Request a new token from the Control service."""
        if not self.org_id or not self.agent_id:
            raise ValueError("org_id and agent_id must be set to acquire a token")

        resp = await self._http.post(
            f"{self.control_url}/orgs/{self.org_id}/agents/{self.agent_id}/token"
        )
        resp.raise_for_status()
        body = resp.json()
        if not body.get("success"):
            raise RuntimeError(f"Token request failed: {body.get('error')}")

        data = body["data"]
        self._token = data["access_token"]
        self._token_expires_at = time.time() + data["expires_in"]
        return self._token

    async def _auth_headers(self) -> Dict[str, str]:
        token = await self.get_token()
        return {"Authorization": f"Bearer {token}"}

    async def request(
        self,
        method: str,
        path: str,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make an authenticated REST request through the proxy."""
        headers = await self._auth_headers()
        resp = await self._http.request(
            method,
            f"{self.proxy_url}/api/{path.lstrip('/')}",
            headers=headers,
            json=json,
        )
        resp.raise_for_status()
        return resp.json()

    async def get(self, path: str) -> Dict[str, Any]:
        return await self.request("GET", path)

    async def post(self, path: str, json: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self.request("POST", path, json=json)
