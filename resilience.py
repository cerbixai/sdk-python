"""Resilient SDK layer — graceful degradation when CerbiX is down.

Three operating states:
  ENFORCED — CerbiX healthy, full proxy → auth → policy → audit
  DEGRADED — CerbiX slow (>500ms), SDK goes direct, async audit
  BYPASS   — CerbiX unreachable, SDK goes direct, local buffer

The customer's agent NEVER stops working. Policy enforcement
degrades gracefully instead of failing hard.
"""

import asyncio
import json
import logging
import sqlite3
import time
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class ProxyState(str, Enum):
    ENFORCED = "enforced"
    DEGRADED = "degraded"
    BYPASS = "bypass"


class HealthChecker:
    """Periodically checks CerbiX proxy health and determines state."""

    def __init__(
        self,
        proxy_url: str = "http://localhost:8080",
        check_interval: float = 30.0,
        degraded_threshold_ms: float = 500.0,
        timeout_ms: float = 3000.0,
    ):
        self.proxy_url = proxy_url.rstrip("/")
        self.check_interval = check_interval
        self.degraded_threshold = degraded_threshold_ms
        self.timeout = timeout_ms / 1000.0
        self.state = ProxyState.ENFORCED
        self._last_check = 0.0
        self._task: Optional[asyncio.Task] = None
        self._bypass_start: Optional[datetime] = None
        self._bypass_windows: List[Dict[str, Any]] = []

    async def check_once(self) -> ProxyState:
        """Single health check against the proxy."""
        try:
            start = time.perf_counter()
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                resp = await c.get(f"{self.proxy_url}/health")
            elapsed_ms = (time.perf_counter() - start) * 1000

            if resp.status_code != 200:
                return self._transition(ProxyState.BYPASS)

            if elapsed_ms > self.degraded_threshold:
                logger.warning(
                    "CerbiX proxy slow: %.0fms (threshold: %.0fms)",
                    elapsed_ms, self.degraded_threshold,
                )
                return self._transition(ProxyState.DEGRADED)

            return self._transition(ProxyState.ENFORCED)

        except (httpx.ConnectError, httpx.TimeoutException):
            return self._transition(ProxyState.BYPASS)
        except Exception as e:
            logger.warning("Health check error: %s", e)
            return self._transition(ProxyState.BYPASS)

    def _transition(self, new_state: ProxyState) -> ProxyState:
        old = self.state
        self.state = new_state

        if old != ProxyState.BYPASS and new_state == ProxyState.BYPASS:
            self._bypass_start = datetime.utcnow()
            logger.warning("CerbiX UNREACHABLE — entering BYPASS mode")

        if old == ProxyState.BYPASS and new_state != ProxyState.BYPASS:
            if self._bypass_start:
                window = {
                    "start": self._bypass_start.isoformat(),
                    "end": datetime.utcnow().isoformat(),
                    "duration_s": (
                        datetime.utcnow() - self._bypass_start
                    ).total_seconds(),
                }
                self._bypass_windows.append(window)
                logger.info(
                    "CerbiX recovered — bypass window: %s", window
                )
                self._bypass_start = None

        if old != new_state:
            logger.info("Proxy state: %s → %s", old.value, new_state.value)

        return new_state

    async def start(self) -> None:
        """Start periodic health checking."""
        self._task = asyncio.create_task(self._loop())

    async def _loop(self) -> None:
        while True:
            await self.check_once()
            await asyncio.sleep(self.check_interval)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    @property
    def bypass_windows(self) -> List[Dict[str, Any]]:
        return list(self._bypass_windows)


class TokenCache:
    """Persist JWT tokens to disk to survive process restarts."""

    def __init__(self, cache_dir: str = ".cerbi"):
        self._dir = Path(cache_dir)
        self._dir.mkdir(exist_ok=True)
        self._file = self._dir / "token_cache.json"

    def get(self, agent_id: str) -> Optional[str]:
        """Get cached token if still valid."""
        try:
            data = json.loads(self._file.read_text())
            entry = data.get(agent_id)
            if entry and entry.get("expires_at", 0) > time.time() + 30:
                return entry["token"]
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            pass
        return None

    def set(self, agent_id: str, token: str, expires_in: int) -> None:
        """Cache a token with its expiry."""
        try:
            data = json.loads(self._file.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}

        data[agent_id] = {
            "token": token,
            "expires_at": time.time() + expires_in,
            "cached_at": datetime.utcnow().isoformat(),
        }
        self._file.write_text(json.dumps(data, indent=2))

    def clear(self) -> None:
        if self._file.exists():
            self._file.unlink()


class AuditBuffer:
    """Local SQLite buffer for audit events when CerbiX is unreachable.

    Events are stored locally and synced when CerbiX recovers.
    """

    def __init__(self, db_path: str = ".cerbi/audit_buffer.db"):
        Path(db_path).parent.mkdir(exist_ok=True)
        self._db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS buffered_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                synced INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def buffer(self, event: Dict[str, Any]) -> None:
        """Store an event locally."""
        conn = sqlite3.connect(self._db_path)
        conn.execute(
            "INSERT INTO buffered_events (event_json, created_at) "
            "VALUES (?, ?)",
            (json.dumps(event), datetime.utcnow().isoformat()),
        )
        conn.commit()
        conn.close()

    def pending_count(self) -> int:
        conn = sqlite3.connect(self._db_path)
        cur = conn.execute(
            "SELECT COUNT(*) FROM buffered_events WHERE synced = 0"
        )
        count = cur.fetchone()[0]
        conn.close()
        return count

    def get_pending(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get unsynced events."""
        conn = sqlite3.connect(self._db_path)
        cur = conn.execute(
            "SELECT id, event_json FROM buffered_events "
            "WHERE synced = 0 ORDER BY id LIMIT ?",
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
        return [
            {"buffer_id": r[0], **json.loads(r[1])} for r in rows
        ]

    def mark_synced(self, buffer_ids: List[int]) -> None:
        """Mark events as synced after upload."""
        if not buffer_ids:
            return
        conn = sqlite3.connect(self._db_path)
        placeholders = ",".join("?" for _ in buffer_ids)
        conn.execute(
            f"UPDATE buffered_events SET synced = 1 "
            f"WHERE id IN ({placeholders})",
            buffer_ids,
        )
        conn.commit()
        conn.close()

    async def sync_to_cerbi(self, audit_url: str) -> int:
        """Upload buffered events to CerbiX audit service.

        Returns number of events synced.
        """
        pending = self.get_pending(limit=500)
        if not pending:
            return 0

        synced = 0
        buffer_ids = []

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                for event in pending:
                    bid = event.pop("buffer_id")
                    event["decision"] = event.get(
                        "decision", "bypass"
                    )
                    resp = await client.post(
                        f"{audit_url}/events", json=event
                    )
                    if resp.status_code == 200:
                        buffer_ids.append(bid)
                        synced += 1
        except Exception as e:
            logger.warning("Buffer sync failed: %s", e)

        if buffer_ids:
            self.mark_synced(buffer_ids)
            logger.info("Synced %d buffered events to Cerbi", synced)

        return synced


class ResilientClient:
    """Wraps AgentGateClient with health checking, caching, and buffering.

    Usage:
        from sdk.resilience import ResilientClient

        client = ResilientClient(
            control_url="https://cerbix-ai.web.app/api/control",
            proxy_url="https://cerbix-ai.web.app",
            audit_url="https://cerbix-ai.web.app/api/audit",
            org_id="...",
            agent_id="...",
        )
        await client.start()

        # Get token (cached, resilient)
        token = await client.get_token()

        # Check current state
        print(client.state)  # ENFORCED / DEGRADED / BYPASS

        await client.stop()
    """

    def __init__(
        self,
        control_url: str = "http://localhost:8081",
        proxy_url: str = "http://localhost:8080",
        audit_url: str = "http://localhost:8082",
        org_id: str = "",
        agent_id: str = "",
        bypass_on_failure: bool = True,
        health_check_interval: float = 30.0,
        cache_dir: str = ".cerbi",
    ):
        self.control_url = control_url.rstrip("/")
        self.proxy_url = proxy_url.rstrip("/")
        self.audit_url = audit_url.rstrip("/")
        self.org_id = org_id
        self.agent_id = agent_id
        self.bypass_on_failure = bypass_on_failure

        self.health = HealthChecker(
            proxy_url=proxy_url,
            check_interval=health_check_interval,
        )
        self.token_cache = TokenCache(cache_dir)
        self.audit_buffer = AuditBuffer(
            f"{cache_dir}/audit_buffer.db"
        )
        self._http = httpx.AsyncClient(timeout=10.0)

    @property
    def state(self) -> ProxyState:
        return self.health.state

    async def start(self) -> None:
        """Start health checking and buffer sync."""
        await self.health.start()

    async def stop(self) -> None:
        """Stop health checking, sync remaining buffer."""
        await self.health.stop()
        # Final sync attempt
        if self.state != ProxyState.BYPASS:
            await self.audit_buffer.sync_to_cerbi(self.audit_url)
        await self._http.aclose()

    async def get_token(self) -> str:
        """Get a valid token — from cache, Cerbi, or raises."""
        # Try memory/disk cache first
        cached = self.token_cache.get(self.agent_id)
        if cached:
            return cached

        # Try fetching from Cerbi
        try:
            resp = await self._http.post(
                f"{self.control_url}/orgs/{self.org_id}"
                f"/agents/{self.agent_id}/token"
            )
            if resp.status_code == 200:
                data = resp.json()["data"]
                token = data["access_token"]
                self.token_cache.set(
                    self.agent_id, token, data["expires_in"]
                )
                return token
        except Exception as e:
            logger.warning("Token fetch failed: %s", e)

        # No token available
        if self.bypass_on_failure:
            return ""  # empty token = bypass mode
        raise ConnectionError("Cannot reach CerbiX for token")

    async def record_event(
        self, event: Dict[str, Any]
    ) -> None:
        """Record an audit event — to CerbiX or local buffer."""
        if self.state == ProxyState.BYPASS:
            event["decision"] = "bypass"
            self.audit_buffer.buffer(event)
            return

        try:
            await self._http.post(
                f"{self.audit_url}/events", json=event
            )
        except Exception:
            # CerbiX unreachable mid-request — buffer locally
            event["decision"] = "bypass"
            self.audit_buffer.buffer(event)

    def get_status(self) -> Dict[str, Any]:
        """Get current resilience status for dashboard."""
        return {
            "state": self.state.value,
            "buffered_events": self.audit_buffer.pending_count(),
            "bypass_windows": self.health.bypass_windows,
            "token_cached": self.token_cache.get(
                self.agent_id
            ) is not None,
        }
