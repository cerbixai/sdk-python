<div align="center">

# cerbix-sdk · Python

**Three lines to give your AI agent a verified identity, bounded permissions, and a full audit trail.**

[![PyPI](https://img.shields.io/badge/pip%20install-cerbix--sdk-00C9B1?style=flat-square)](https://pypi.org/project/cerbix-sdk)
[![Python](https://img.shields.io/badge/Python-3.10%2B-0D1421?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-0D1421?style=flat-square)](LICENSE)
[![Docs](https://img.shields.io/badge/Docs-cerbix.ai-00C9B1?style=flat-square)](https://cerbix.ai/docs)

</div>

---

## What this is

The Cerbix Python SDK wraps your agent's HTTP client. Every outbound call is silently intercepted — a short-lived scoped token is injected, the action is logged, and the request continues. Your agent code does not change.

```python
from cerbi import CerbixSDK
cerbix = CerbixSDK(agent_id=os.environ['CERBIX_AGENT_ID'])
http   = cerbix.wrap(requests.Session())
response = http.get('https://internal-api/billing/summary')
```

## Installation

```bash
pip install cerbix-sdk
```

Requires Python 3.10+.

## Quickstart

### 1. Register your agent (once, in CI/CD)

```bash
curl -X POST https://api.cerbix.ai/v1/agents/register \
  -H "Authorization: Bearer $CERBIX_ORG_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "billing-reconciliation-agent",
    "owner_email": "sarah@acme.com",
    "framework": "langchain",
    "declared_scope": ["db:read:billing", "api:read:invoices"],
    "environment": "production"
  }'
```

Set the returned `agent_id` as `CERBIX_AGENT_ID` in your deployment environment.

### 2. Wrap your HTTP client

```python
import os, requests
from cerbi import CerbixSDK

cerbix = CerbixSDK(agent_id=os.environ['CERBIX_AGENT_ID'])
http   = cerbix.wrap(requests.Session())
response = http.get('https://internal-api/billing/summary')
```

### 3. LangChain integration

```python
from cerbi import CerbixSDK
cerbix = CerbixSDK(agent_id=os.environ['CERBIX_AGENT_ID'])
llm = cerbix.wrap_langchain(your_llm)
```

### 4. MCP integration

```python
from cerbi import CerbixSDK
from mcp import ClientSession
cerbix  = CerbixSDK(agent_id=os.environ['CERBIX_AGENT_ID'])
session = cerbix.wrap_mcp(ClientSession(...))
```

## How it works

Every outbound call goes through the SDK middleware:

1. Token checked — refreshed automatically 60 seconds before expiry
2. 2. Bearer header injected silently
   3. 3. Request forwarded to Cerbix proxy
      4. 4. OPA policy evaluated in under 3ms — allow or deny
         5. 5. Action written to immutable BigQuery audit log
           
            6. If the Cerbix endpoint is unavailable the SDK falls back to your original credentials silently. Cerbix is never a single point of failure.
           
            7. ## Configuration
           
            8. | Variable | Default | Description |
            9. |---|---|---|
            10. | `CERBIX_AGENT_ID` | required | Agent UUID from registration |
            11. | `CERBIX_API_URL` | `https://api.cerbix.ai` | Override for BYOC deployments |
            12. | `CERBIX_REFRESH_BUFFER_SECONDS` | `60` | Seconds before expiry to refresh token |
            13. | `CERBIX_FALLBACK_ON_ERROR` | `true` | Fall back silently if unavailable |
           
            14. ## SDK modules
           
            15. | File | What it does |
            16. |---|---|
            17. | `client.py` | `CerbixSDK` main entry point |
            18. | `interceptor.py` | HTTP client wrapper and token injection |
            19. | `auth.py` | Token fetch, cache, and refresh |
            20. | `mcp.py` | MCP ClientSession wrapper |
            21. | `langchain.py` | LangChain LLM wrapper |
            22. | `resilience.py` | Fallback and retry logic |
           
            23. ## License
           
            24. Apache 2.0 — see [LICENSE](LICENSE).
           
            25. ---
           
            26. <div align="center">
            <a href="https://cerbix.ai">cerbix.ai</a> ·
            <a href="https://cerbix.ai/docs">Docs</a> ·
            <a href="mailto:hello@cerbix.ai">hello@cerbix.ai</a> ·
            <a href="https://github.com/cerbixai">GitHub org</a>
            </div>
