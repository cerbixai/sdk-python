# CerbiX Python SDK

Official Python SDK for [CerbiX](https://cerbix.ai) — AI agent identity, policy enforcement, and MCP interception.

## Install

```bash
pip install cerbix
```

## Quick start

```python
from cerbix import CerbiXClient

client = CerbiXClient(api_url="https://cerbix-ai.web.app/api/control")

# Register an agent
agent = client.register_agent(
    org_id="your-org-id",
    name="research-agent",
    purpose="market-analysis",
    framework="langchain",
)

# Get a short-lived access token
token = client.get_token(agent_id=agent["id"])

# Check policy before acting
decision = client.check_policy(
    token=token,
    resource="database:read",
    action="query",
)
```

## Modules

| Module | Description |
|--------|-------------|
| `client.py` | Core API client — agent registration, token management, policy checks |
| `auth.py` | OAuth 2.1 + PKCE token handling |
| `mcp.py` | MCP (JSON-RPC 2.0) interceptor client |
| `interceptor.py` | Request/response interception and audit logging |
| `langchain.py` | LangChain toolkit integration |
| `resilience.py` | Retry, circuit breaker, and timeout utilities |

## LangChain integration

```python
from cerbix.langchain import CerbiXToolkit

toolkit = CerbiXToolkit(api_url="https://cerbix-ai.web.app/api/control")
tools = toolkit.get_tools()
```

## Links

- [Documentation](https://github.com/cerbixai/docs)
- [Dashboard](https://cerbix-ai.web.app)
- [Security Policy](https://github.com/cerbixai/.github/blob/main/SECURITY.md)

## License

MIT
