"""The KYC deployment's model-backed planner and decider (casebound.llm, configured for KYC).

Swapped in for the stubs by `casebound-demo --model anthropic`. The catalogue is the set of tools
the KYC agent is authorized for, which is where Algorithm 1 draws plan steps from; the factor
codes are the ones the policy-grounded rule in stubs.policy_decision produces, so a model
decision and the Proposition 1 comparator speak the same vocabulary.
"""
from __future__ import annotations

from casebound import LLMDecider, LLMPlanner

from .tools import ALLOWED, ROLE, registry

CATALOGUE = {
    "doc_verify": "Verify the applicant's identity document against the application; returns id_match, doc_quality, address_match.",
    "bureau_pull": "Retrieve the applicant's credit bureau score; returns score.",
    "ach_check": "Check whether the ACH policy applies to this application; returns ach_policy_applicable.",
}
assert set(CATALOGUE) == ALLOWED, "the planner is offered exactly the tools the KYC role is authorized for"

FACTOR_CODES = (
    "identity_document_mismatch",
    "score_below_stepup_threshold",
    "all_checks_passed",
)

BRIEF = ("The workflow is Know Your Customer onboarding for a consumer credit product. "
         "The applied policy's required_checks list names the checks this case needs.")
DECISION_BRIEF = ("REJECT on an identity document mismatch. REFER for step-up verification when the score "
                  "is below the policy's stepup_threshold. PASS otherwise, with the factor all_checks_passed.")


def kyc_planner() -> LLMPlanner:
    return LLMPlanner(registry, ROLE, CATALOGUE, BRIEF)


def kyc_decider() -> LLMDecider:
    return LLMDecider(("PASS", "REFER", "REJECT"), FACTOR_CODES, f"{BRIEF} {DECISION_BRIEF}")
