"""Serve controlled tools as MCP servers that meet the case-bound contract (contract.py).

Each downstream tool (document verification, bureau, ACH) runs as its own MCP server,
as in Figure 3. The server knows nothing about the gates: it trusts that its caller is the
gateway. What it does guarantee is the interface: no call without a case id, and every answer
tagged with the case and the attempt it belongs to. Its own call log is keyed by the same case id,
which is what makes the case id the join key across the orchestrator log, the tool log and the
ledger (Section 5.2).
"""
from __future__ import annotations

from typing import Any, Iterable

from mcp.server import MCPServer

from casebound import ToolRegistry

from .contract import CAPABILITY_META, CaseId, respond


def build_tool_server(name: str, registry: ToolRegistry, tools: Iterable[str] | None = None,
                      log: list[dict[str, Any]] | None = None) -> MCPServer:
    """An MCP server exposing `tools` (default: all) from an in-process registry.

    The tool function receives exactly what it would in process (envelope, payload and context
    merged), so a tool behaves identically whether Algorithm 2 reaches it directly or over MCP.
    """
    server = MCPServer(name, instructions="Every tool here requires the case_id of the case it serves.")
    for tool in (registry.names() if tools is None else list(tools)):
        server.add_tool(_handler(registry, tool, log), name=tool,
                        description=f"{tool} (case-bound: requires case_id; echoes case_id and idempotency_key)",
                        meta={CAPABILITY_META: registry.capability(tool)})
    return server


def _handler(registry: ToolRegistry, tool: str, log: list[dict[str, Any]] | None):
    def handler(case_id: CaseId, payload: dict[str, Any], envelope: dict[str, Any],
                context: dict[str, Any] | None = None) -> dict[str, Any]:
        key = envelope.get("idempotency_key")
        if log is not None:
            log.append({"case_id": case_id, "tool": tool, "idempotency_key": key})
        result = registry.invoke(tool, {**envelope, "case_id": case_id, "payload": payload, **(context or {})})
        return respond(case_id, key, result)
    handler.__name__ = tool
    return handler
