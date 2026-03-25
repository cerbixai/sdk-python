"""LangChain-compatible toolkit that discovers tools via AgentGate MCP."""

from typing import Any, List

from cerbix_sdk.client import AgentGateClient
from cerbix_sdk.mcp import AgentGateMCPClient, AuditRecorder

# LangChain is an optional dependency
try:
    from langchain_core.tools import BaseTool
    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False
    BaseTool = object  # type: ignore


class AgentGateTool(BaseTool):  # type: ignore
    """A LangChain tool backed by an AgentGate MCP tool."""

    name: str = ""
    description: str = ""
    _mcp_client: Any = None
    _tool_name: str = ""

    class Config:
        arbitrary_types_allowed = True

    def __init__(self, mcp_client: AgentGateMCPClient, tool_name: str, tool_description: str):
        if not HAS_LANGCHAIN:
            raise ImportError("langchain-core is required: pip install langchain-core")
        super().__init__(
            name=tool_name,
            description=tool_description or f"MCP tool: {tool_name}",
        )
        self._mcp_client = mcp_client
        self._tool_name = tool_name

    def _run(self, **kwargs: Any) -> Any:
        raise NotImplementedError("Use async version: _arun")

    async def _arun(self, **kwargs: Any) -> Any:
        return await self._mcp_client.call_tool(self._tool_name, kwargs or None)


class AgentGateToolkit:
    """LangChain toolkit that dynamically discovers tools from AgentGate.

    Usage:
        client = AgentGateClient(org_id="...", agent_id="...")
        toolkit = AgentGateToolkit(client)
        tools = await toolkit.get_tools()
        # Use tools with a LangChain agent
    """

    def __init__(
        self,
        client: AgentGateClient,
        audit_recorder: AuditRecorder = None,
    ):
        if not HAS_LANGCHAIN:
            raise ImportError("langchain-core is required: pip install langchain-core")
        self._client = client
        self._mcp = AgentGateMCPClient(client, audit_recorder=audit_recorder)

    async def get_tools(self) -> List[AgentGateTool]:
        """Discover tools via MCP tools/list and wrap as LangChain tools."""
        raw_tools = await self._mcp.list_tools()
        return [
            AgentGateTool(
                mcp_client=self._mcp,
                tool_name=t.get("name", "unknown"),
                tool_description=t.get("description", ""),
            )
            for t in raw_tools
        ]
