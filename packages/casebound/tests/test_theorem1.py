"""Theorem 1 as a property: over random gate-mediated executions with random policy
effective windows and random plans, reconstruct() returns COMPLETE iff phi(c) holds."""
from datetime import date, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from casebound import (COMPLETE, AllowRedactedOnly, InMemoryLedger, InMemoryPolicyStore, Plan, Request, StaticAuthorizer,
                       ToolRegistry, WorkflowContext, execute_regulated_workflow, make_version, phi, reconstruct, steps_for)
from casebound.ports import Decision
from demo.kyc.data import SCHEMA

TODAY = date(2026, 9, 5)
registry = ToolRegistry()
for n in ["t1", "t2", "t3", "t4"]:
    registry.controlled_tool(n)(lambda env, n=n: {"tool": n, "ok": True})


class P:
    def __init__(self, names): self.names = names
    def plan(self, wf, pol, red): return Plan(steps_for(registry, self.names, "r", wf))


class D:
    def decide(self, results, pol, red): return Decision("PASS", ("all_checks_passed",))


@settings(max_examples=150, deadline=None)
@given(allowed=st.frozensets(st.sampled_from(["t1", "t2", "t3", "t4"])),
       plan=st.lists(st.sampled_from(["t1", "t2", "t3", "t4"]), max_size=4),
       eff_offset=st.integers(-400, 30), exp_len=st.one_of(st.none(), st.integers(0, 400)),
       approved=st.booleans())
def test_gate_decides_phi(allowed, plan, eff_offset, exp_len, approved):
    L = InMemoryLedger()
    store = InMemoryPolicyStore()
    eff = TODAY + timedelta(days=eff_offset)
    exp = None if exp_len is None else eff + timedelta(days=exp_len)
    store.deliver(make_version("p", 1, "APPROVED" if approved else "DELIVERED", eff, exp, workflow="w", jurisdiction="US"))
    store.ingest()
    ctx = WorkflowContext(L, store, store, StaticAuthorizer({("r", "w"): set(allowed)}), AllowRedactedOnly(), registry,
                          P(plan), D(), SCHEMA, today=lambda: TODAY)
    try:
        execute_regulated_workflow(ctx, Request("w", "US", "r", {"employer_name": "x", "product": "y"}))
    except Exception:
        raise
    case_id = L._events[0].case_id
    v = reconstruct(L, case_id, ctx.authorizer, store)
    assert (v.status == COMPLETE) == all(phi(case_id, L.fetch_by_case(case_id), ctx.authorizer, store).values())
