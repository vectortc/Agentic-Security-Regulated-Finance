"""casebound-mcp: the case-bound MCP tool contract, tool servers, client adapter and gateway.

  contract     what a tool must accept and echo to sit behind the gateway (Sections 5.2, 7.2)
  tool_server  serve a ToolRegistry's tools as MCP servers that meet the contract
  client       McpToolAdapter: casebound's ToolAdapter port over MCP
  gateway      Casebound as an MCP server: case_id mandatory, Algorithm 2 on every call
  kyc          the KYC tools of Figure 3 as separate servers with synthetic back ends
"""
from .client import McpToolAdapter
from .contract import (CAPABILITY_META, CASE_ID_PATTERN, ToolContractError, ToolExecutionError,
                       check_response, to_arguments)
from .gateway import build_gateway
from .tool_server import build_tool_server

__version__ = "0.4.0"
__all__ = ["CAPABILITY_META", "CASE_ID_PATTERN", "McpToolAdapter", "ToolContractError", "ToolExecutionError",
           "build_gateway", "build_tool_server", "check_response", "to_arguments"]
