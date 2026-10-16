from datetime import date
from typing import Any

import anyio
import pytest
from mcp import Client

from casebound import EventType, retrieve_current_policy
from casebound.workflow import new_case_id
from casebound_mcp import McpToolAdapter
from casebound_mcp.kyc import kyc_tool_servers
from demo.kyc.data import TODAY
from demo.kyc.scenarios import policy_store
from demo.kyc.tools import ROLE, WORKFLOW


@pytest.fixture
def tool_log() -> list[dict[str, Any]]:
    return []


@pytest.fixture
def kyc_tools(tool_log):
    """The KYC tools as separate MCP servers, reached through the real protocol in process."""
    with McpToolAdapter(kyc_tool_servers(tool_log)) as adapter:
        yield adapter


@pytest.fixture
def store():
    return policy_store(stale=False)


def call(server, tool: str, arguments: dict[str, Any]):
    """One tool call from a fresh MCP client (the agent's side of the connection)."""
    async def go():
        async with Client(server) as c:
            return await c.call_tool(tool, arguments)
    return anyio.run(go)


def list_tools(server):
    async def go():
        async with Client(server) as c:
            return (await c.list_tools()).tools
    return anyio.run(go)


def open_case(ledger, store, today: date = TODAY, retrieve_policy: bool = True) -> str:
    """What the orchestrator does before any tool call: open the case and ground it in a policy (Alg 3)."""
    case_id = new_case_id()
    ledger.append(case_id, EventType.CASE_OPENED, {"workflow": WORKFLOW, "jurisdiction": "US",
                                                   "agent_role": ROLE, "input_digest": "synthetic"})
    if retrieve_policy:
        retrieve_current_policy(ledger, case_id, store, WORKFLOW, "US", today, store)
    return case_id
