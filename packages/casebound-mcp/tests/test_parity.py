"""Moving the tools behind MCP changes the transport, not the evidence: every scenario in the fault
matrix produces the same outcome, the same chain shape and the same Algorithm 5 checks."""
import pytest

from casebound import EventType
from demo.kyc.run import run_scenario
from demo.kyc.scenarios import SCENARIOS


def _shape(outcome, verdict, ledger):
    return {"outcome": (outcome.outcome, outcome.reason) if outcome else "CRASHED",
            "status": verdict.status,
            "chain": [e.type.value for e in verdict.events],
            "checks": [(c.line, c.name, c.passed) for c in verdict.checks],
            "findings": sorted(f["kind"] for f in verdict.findings)}


@pytest.mark.parametrize("paper_literal", [False, True], ids=["extended", "literal"])
@pytest.mark.parametrize("scenario", list(SCENARIOS))
def test_scenario_is_identical_over_mcp(scenario, paper_literal, kyc_tools):
    local = run_scenario(scenario, paper_literal=paper_literal, return_ledger=True)
    remote = run_scenario(scenario, paper_literal=paper_literal, return_ledger=True, tools=kyc_tools)
    assert remote[2] == local[2]
    assert _shape(remote[0], remote[1], remote[3]) == _shape(local[0], local[1], local[3])


def test_the_tool_log_and_the_ledger_join_on_case_id_and_idempotency_key(kyc_tools, tool_log):
    """Section 5.3: the case id is the join key across the orchestrator log, the tool log and the ledger."""
    outcome, _, _, ledger = run_scenario("happy", tools=kyc_tools, return_ledger=True)
    completed = [(outcome.case_id, e.data["tool"], e.data["idempotency_key"])
                 for e in ledger.fetch_by_case(outcome.case_id) if e.type == EventType.TOOL_COMPLETED]
    assert len(completed) == 3
    assert completed == [(r["case_id"], r["tool"], r["idempotency_key"]) for r in tool_log]
