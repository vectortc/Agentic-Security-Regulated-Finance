"""Mock tools: stand-ins for the KYC pipeline's tool calls in Section 5.1 (identity document
verification, bureau data retrieval, ACH policy applicability check). Policy lookup is Algorithm 3.

They read synthetic fixtures from the request context; a real adapter would call the provider.
The fixtures are the ground truth the model never sees: they enter through the tool boundary,
which is what makes the recorded tool responses the reconstructable basis for the decision.
"""
from __future__ import annotations

from casebound import StaticAuthorizer, ToolRegistry

registry = ToolRegistry()
ROLE, WORKFLOW = "kyc_agent", "kyc_onboarding"
ALLOWED = {"doc_verify", "bureau_pull", "ach_check"}
authorizer = StaticAuthorizer({(ROLE, WORKFLOW): set(ALLOWED)})


@registry.controlled_tool("doc_verify")
def doc_verify(env):
    f = env["fixture"]
    return {"id_match": f["id_match"], "doc_quality": f.get("doc_quality", "ok"),
            "address_match": f.get("address_match", True)}


@registry.controlled_tool("bureau_pull")
def bureau_pull(env):
    return {"score": env["fixture"]["score"], "bureau": "synthetic-bureau"}


@registry.controlled_tool("ach_check")
def ach_check(env):
    if env.get("crash_on") == "ach_check":
        raise RuntimeError("worker died after TOOL_INVOKED")   # not a ControlException: simulates a crash
    # Section 5.1 names an "ACH policy applicability check" but not its rule. The stand-in records
    # whether the ACH policy applies to the application's product; it is evidence on the chain, not
    # a decision factor, so the demo invents no rule the paper does not state.
    product = env.get("payload", {}).get("product")
    return {"ach_policy_applicable": product == "consumer_credit", "product": product}


@registry.controlled_tool("account_close")   # registered but never in the allowed set (the C2 target)
def account_close(env):
    return {"closed": True}
