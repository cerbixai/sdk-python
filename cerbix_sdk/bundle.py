"""Policy bundle loader — fetches and caches agent policy context.

Component 7: Runs once at SDK startup, refreshes every 5 minutes
in the background. Never on the hot path.
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import httpx

from cerbix_sdk.policy import PolicyBundle

logger = logging.getLogger("cerbix_sdk")

_DEFAULT_REFRESH_SECONDS = 300  # 5 minutes


class PolicyBundleLoader:
    """Loads and refreshes the policy bundle from the control service."""

    def __init__(
        self,
        control_url: str,
        org_id: str,
        agent_id: str,
        refresh_interval: int = _DEFAULT_REFRESH_SECONDS,
    ):
        self.control_url = control_url.rstrip("/")
        self.org_id = org_id
        self.agent_id = agent_id
        self.refresh_interval = refresh_interval
        self._bundle: Optional[PolicyBundle] = None
        self._loaded_at: float = 0
        self._refresh_task: Optional[asyncio.Task] = None
        self._http = httpx.AsyncClient(timeout=10.0)

    @property
    def bundle(self) -> Optional[PolicyBundle]:
        return self._bundle

    async def load(self) -> PolicyBundle:
        """Fetch the policy bundle from the control service.

        GET /orgs/{org_id}/agents/{agent_id}/policy
        Returns a PolicyBundle parsed from the response.
        """
        url = (
            f"{self.control_url}/orgs/{self.org_id}"
            f"/agents/{self.agent_id}/policy"
        )
        try:
            resp = await self._http.get(url)
            resp.raise_for_status()
            body = resp.json()
            data = body.get("data", body)
            self._bundle = PolicyBundle.from_dict(data)
            self._loaded_at = time.time()
            logger.info(
                "Policy bundle loaded: agent=%s, status=%s, "
                "scopes=%d, rules=%d",
                self._bundle.agent_id,
                self._bundle.agent_status,
                len(self._bundle.declared_scope),
                len(self._bundle.scope_map),
            )
            return self._bundle
        except Exception as e:
            logger.warning(
                "Failed to load policy bundle: %s", e,
            )
            # Return a permissive default bundle
            if self._bundle is None:
                self._bundle = PolicyBundle(
                    agent_id=self.agent_id,
                    agent_status="shadow",
                    declared_scope=[],
                    scope_map=[],
                    org_policy=PolicyBundle.from_dict({}).org_policy,
                )
            return self._bundle

    async def refresh_if_stale(self) -> PolicyBundle:
        """Refresh the bundle if older than refresh_interval."""
        if (
            self._bundle is not None
            and time.time() - self._loaded_at < self.refresh_interval
        ):
            return self._bundle
        return await self.load()

    async def start_background_refresh(self) -> None:
        """Start periodic background refresh."""
        self._refresh_task = asyncio.create_task(self._loop())

    async def _loop(self) -> None:
        while True:
            await asyncio.sleep(self.refresh_interval)
            try:
                await self.load()
            except Exception as e:
                logger.warning("Bundle refresh failed: %s", e)

    async def stop(self) -> None:
        """Stop background refresh."""
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
        await self._http.aclose()
