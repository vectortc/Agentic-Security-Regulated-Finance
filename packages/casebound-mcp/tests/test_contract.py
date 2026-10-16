"""The case-bound tool contract: no call without a case id, no answer recorded for the wrong case."""
from typing import Any

import pytest
from mcp.server import MCPServer

from casebound import ToolRegistry
from casebound_mcp import (CAPABILITY_META, McpToolAdapter, ToolContractError, build_tool_server, check_response,
                           to_arguments)
from casebound_mcp.contract import respond
from casebound_mcp.kyc import kyc_tool_servers
from conftest import call, list_tools
from demo.kyc.run import run_scenario

CASE = "c-0123456789ab"


def test_every_tool_server_requires_a_case_id_in_its_published_schema():
    for server in kyc_tool_servers().values():
        for tool in list_tools(server):
            assert "case_id" in tool.input_schema["required"], tool.name
            assert tool.input_schema["properties"]["case_id"]["pattern"] == r"^c-[0-9a-f]{12}$"


def test_a_call_without_a_case_id_is_refused_before_the_tool_runs(tool_log):
    server = kyc_tool_servers(tool_log)["bureau"]
    r = call(server, "bureau_pull", {"payload": {}, "envelope": {}, "context": {"fixture": {"score": 700}}})
    assert r.is_error and "case_id" in r.content[0].text
    assert call(server, "bureau_pull", {"case_id": "not-a-case", "payload": {}, "envelope": {}}).is_error
    assert tool_log == []                        # the tool never ran, so no untagged call exists


def test_the_tool_echoes_the_case_and_attempt_and_logs_under_the_case_id(tool_log):
    server = kyc_tool_servers(tool_log)["bureau"]
    r = call(server, "bureau_pull", {"case_id": CASE, "payload": {}, "envelope": {"idempotency_key": "k1"},
                                     "context": {"fixture": {"score": 700}}})
    assert r.structured_content == respond(CASE, "k1", {"score": 700, "bureau": "synthetic-bureau"})
    assert tool_log == [{"case_id": CASE, "tool": "bureau_pull", "idempotency_key": "k1"}]


def test_the_adapter_reads_capabilities_from_the_published_tool_metadata():
    reg = ToolRegistry()
    reg.controlled_tool("pull_report", capability="bureau.read")(lambda env: {})
    server = build_tool_server("s", reg)
    assert list_tools(server)[0].meta[CAPABILITY_META] == "bureau.read"
    with McpToolAdapter({"s": server}) as adapter:
        assert adapter.names() == ["pull_report"] and adapter.capability("pull_report") == "bureau.read"


def test_a_tool_name_served_twice_is_refused():
    with pytest.raises(ValueError, match="more than one server"):
        McpToolAdapter({"a": kyc_tool_servers()["bureau"], "b": kyc_tool_servers()["bureau"]})


def test_to_arguments_separates_provenance_payload_and_synthetic_context():
    args = to_arguments({"case_id": CASE, "tool": "t", "attempt": 2, "idempotency_key": "k",
                         "payload": {"city": "Rockville"}, "fixture": {"score": 1}, "crash_on": "x"})
    assert args == {"case_id": CASE, "payload": {"city": "Rockville"},
                    "envelope": {"tool": "t", "attempt": 2, "idempotency_key": "k"},
                    "context": {"fixture": {"score": 1}, "crash_on": "x"}}


def test_check_response_rejects_an_answer_for_another_case_or_attempt():
    assert check_response("t", CASE, "k", respond(CASE, "k", {"a": 1})) == {"a": 1}
    for bad in (respond("c-ffffffffffff", "k", {}), respond(CASE, "other", {}), {"a": 1}, None):
        with pytest.raises(ToolContractError):
            check_response("t", CASE, "k", bad)


def _misrouting_bureau() -> MCPServer:
    """A bureau that answers every call with another case's record (a propagation bug)."""
    server = MCPServer("bad-bureau")

    def bureau_pull(case_id: str, payload: dict[str, Any], envelope: dict[str, Any],
                    context: dict[str, Any] | None = None) -> dict[str, Any]:
        return respond("c-ffffffffffff", envelope.get("idempotency_key"), {"score": 820, "bureau": "x"})
    server.add_tool(bureau_pull, name="bureau_pull", meta={CAPABILITY_META: "bureau_pull"})
    return server


def test_a_tool_that_answers_for_another_case_routes_the_case_to_human_review():
    with McpToolAdapter({**kyc_tool_servers(), "bureau": _misrouting_bureau()}) as adapter:
        outcome, verdict, _, ledger = run_scenario("happy", tools=adapter, return_ledger=True)
    assert outcome.outcome == "HUMAN_REVIEW" and "ToolContractError" in outcome.reason
    assert verdict.status != "COMPLETE"
    types = [e.type.value for e in ledger.fetch_by_case(outcome.case_id)]
    assert types.count("TOOL_INVOKED") == types.count("TOOL_COMPLETED") + 1   # the answer was never recorded
