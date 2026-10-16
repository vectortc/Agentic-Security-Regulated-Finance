"""The KYC tools of Section 5.1 as separate MCP servers over the synthetic back ends in demo/kyc/tools.py.

Section 3.4 names four MCP tools: bureau retrieval, document verification, policy lookup and ACH
checks. Policy lookup is Algorithm 3's own gate rather than an Algorithm 2 tool call, so it is not
served here. `accounts` serves account_close, a capability no KYC role is allowed:
the tool exists on the network, and C2 at the gateway is what keeps the agent from it.
"""
from __future__ import annotations

from typing import Any

from mcp.server import MCPServer

from demo.kyc.tools import registry

from .tool_server import build_tool_server

KYC_SERVERS: dict[str, tuple[str, ...]] = {
    "identity": ("doc_verify",),
    "bureau": ("bureau_pull",),
    "ach": ("ach_check",),
    "accounts": ("account_close",),
}


def kyc_tool_servers(log: list[dict[str, Any]] | None = None) -> dict[str, MCPServer]:
    """One MCPServer per back end, sharing `log` (the tool-side call log, keyed by case id)."""
    return {name: build_tool_server(f"kyc-{name}", registry, tools, log) for name, tools in KYC_SERVERS.items()}
