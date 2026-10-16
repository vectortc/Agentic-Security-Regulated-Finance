"""McpToolAdapter: the `casebound.ToolAdapter` port, reaching tools over MCP.

The engine is synchronous and the MCP SDK is async, so the adapter owns an event loop in a
background thread (an anyio blocking portal) and keeps one session open per server for its
lifetime. Algorithm 2 still decides everything: this class only runs after the gates have passed
and TOOL_INVOKED is on the ledger.
"""
from __future__ import annotations

from contextlib import ExitStack
from functools import partial
from typing import Any, Mapping

from anyio.from_thread import start_blocking_portal
from mcp import Client
from mcp.server import MCPServer

from .contract import CAPABILITY_META, ToolExecutionError, check_response, to_arguments


class McpToolAdapter:
    """`servers` maps a label to a target: a Streamable HTTP URL, or an in-process MCPServer.

    Use as a context manager, or call close(). Tool names must be unique across servers.
    """

    def __init__(self, servers: Mapping[str, str | MCPServer], read_timeout_seconds: float = 30) -> None:
        self._stack = ExitStack()
        self._routes: dict[str, tuple[Any, str]] = {}          # tool -> (client, capability)
        try:
            self._portal = self._stack.enter_context(start_blocking_portal())
            for label, target in servers.items():
                client = self._stack.enter_context(self._portal.wrap_async_context_manager(
                    Client(target, read_timeout_seconds=read_timeout_seconds)))
                for tool in self._list_tools(client):
                    if tool.name in self._routes:
                        raise ValueError(f"tool {tool.name!r} is served by more than one server (again by {label!r})")
                    self._routes[tool.name] = (client, (tool.meta or {}).get(CAPABILITY_META, tool.name))
        except BaseException:
            self._stack.close()
            raise

    def _list_tools(self, client: Client) -> list[Any]:
        tools, cursor = [], None
        while True:
            page = self._portal.call(partial(client.list_tools, cursor=cursor))
            tools += page.tools
            cursor = page.next_cursor
            if not cursor:
                return tools

    # --- casebound.ToolAdapter ------------------------------------------------------------
    def names(self) -> list[str]:
        return list(self._routes)

    def capability(self, tool: str) -> str:
        return self._routes[tool][1]

    def invoke(self, tool: str, envelope: dict[str, Any]) -> dict[str, Any]:
        client, _ = self._routes[tool]
        args = to_arguments(envelope)
        r = self._portal.call(client.call_tool, tool, args)
        if r.is_error:
            text = " ".join(getattr(c, "text", "") for c in r.content)
            raise ToolExecutionError(f"{tool} failed for case {args['case_id']}: {text}")
        return check_response(tool, args["case_id"], args["envelope"].get("idempotency_key"), r.structured_content)

    # --- lifecycle ------------------------------------------------------------------------
    def close(self) -> None:
        self._stack.close()

    def __enter__(self) -> "McpToolAdapter":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
