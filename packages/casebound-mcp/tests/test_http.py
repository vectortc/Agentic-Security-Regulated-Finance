"""The same guarantees over Streamable HTTP, the transport a deployment runs."""
import anyio
from mcp import Client

from casebound import AllowRedactedOnly, EventType, InMemoryLedger
from casebound_mcp import McpToolAdapter, build_gateway
from casebound_mcp.http import serve_in_thread, urls
from casebound_mcp.kyc import KYC_SERVERS, kyc_tool_servers
from conftest import open_case
from demo.kyc.data import applicant
from demo.kyc.run import run_scenario
from demo.kyc.tools import ROLE, authorizer


def test_the_workflow_reaches_tool_servers_over_http():
    with serve_in_thread(kyc_tool_servers()) as base, McpToolAdapter(urls(base, KYC_SERVERS)) as tools:
        happy = run_scenario("happy", tools=tools)
        crash = run_scenario("crash", tools=tools)
    assert (happy[0].outcome, happy[1].status) == ("REFER", "COMPLETE")
    assert (crash[0], crash[1].status) == (None, "INCOMPLETE")      # tool died after TOOL_INVOKED



def test_the_demo_cli_reaches_the_tools_over_http(capsys):
    from demo.kyc.run import main
    with serve_in_thread(kyc_tool_servers()) as base:
        main(["--tools-url", base, "--scenario", "happy"])
    out = capsys.readouterr().out
    assert "verdict  COMPLETE" in out and out.count("TOOL_COMPLETED") == 3


def test_an_agent_reaches_the_tools_only_through_the_gateway_over_http(store):
    ledger = InMemoryLedger()
    fixture = applicant("borderline")["fixture"]
    with serve_in_thread(kyc_tool_servers()) as tools_base, McpToolAdapter(urls(tools_base, KYC_SERVERS)) as tools:
        gateway = build_gateway(ledger, authorizer, AllowRedactedOnly(), tools, store, ROLE,
                                context_for=lambda _: {"fixture": fixture})
        with serve_in_thread({"gateway": gateway}) as gw_base:
            case_id = open_case(ledger, store)

            async def agent():
                async with Client(urls(gw_base, ["gateway"])["gateway"]) as c:
                    ok = await c.call_tool("bureau_pull", {"case_id": case_id, "payload": {"state": "MD"}})
                    denied = await c.call_tool("account_close", {"case_id": case_id, "payload": {}})
                    return ok, denied
            ok, denied = anyio.run(agent)
    assert not ok.is_error and ok.structured_content["result"]["score"] == fixture["score"]
    assert denied.is_error
    assert [e.type for e in ledger.fetch_by_case(case_id)][2:] == [
        EventType.TOOL_INVOKED, EventType.TOOL_COMPLETED, EventType.TOOL_AUTHZ_DENIED]
