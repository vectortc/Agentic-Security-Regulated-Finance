"""CLI: run a scenario, then audit the case from its id alone.

  casebound-demo --scenario stale-policy
  casebound-demo --scenario bypass --paper-literal   # the manuscript's line 8, read literally
  casebound-demo --batch 140                         # the whole population; prints the funnel
  casebound-demo --list
  casebound-demo --tools mcp                         # tools as MCP servers (in process, real protocol)
  casebound-demo --tools-url http://127.0.0.1:8765   # tools served by `casebound-mcp serve-tools`
"""
from __future__ import annotations

import argparse
import json
from collections import Counter

from casebound import adverse_action_statement, art12_record, reconcile, reconstruct
from casebound.workflow import execute_regulated_workflow

from .data import POPULATION, ExcludedAtIntake, admitted, applicant as resolve_applicant, reason_text
from .scenarios import SCENARIOS, build, comparator


def run_scenario(scenario: str, applicant: str = "borderline", ledger=None, return_ledger: bool = False,
                 paper_literal: bool = False, model_client=None, tools=None):
    """Returns (outcome, verdict, expected). The verdict is Algorithm 5 alone; call
    casebound.reconcile(ledger, verdict) separately for deployment-level findings.

    Raises ExcludedAtIntake for an applicant with a single contact channel (Section 7.3): such an
    applicant never enters the pipeline, so there is no case to run or reconstruct."""
    if not admitted(resolve_applicant(applicant)):
        raise ExcludedAtIntake(f"{applicant}: one contact channel; excluded at intake (Section 7.3)")
    s = build(scenario, applicant, ledger, paper_literal, model_client, tools)
    try:
        outcome = execute_regulated_workflow(s.ctx, s.request)
        case_id = outcome.case_id
    except RuntimeError as e:                      # simulated worker crash: nothing after TOOL_INVOKED ran
        case_id, outcome = e.case_id, None
    if s.post is not None:                         # post-hoc failure modes: tampering, entitlement drift
        s.post(s.ctx.ledger, case_id)
    verdict = reconstruct(s.ctx.ledger, case_id, s.ctx.authorizer, s.store, comparator,
                          paper_literal=paper_literal)
    if return_ledger:
        return outcome, verdict, s.expect, s.ctx.ledger
    return outcome, verdict, s.expect


def batch(n: int, scenario: str = "happy", paper_literal: bool = False, model_client=None, tools=None) -> dict:
    """Run the first n applicants of the population and report the outcome mix.

    Applicants with a single contact channel are excluded at intake and never become cases
    (Section 7.3), so outcome shares are over admitted applicants. The population's parameters are
    illustrative (demo/kyc/generate.py): these shares are not evidence for the paper's figures.
    """
    outcomes: Counter = Counter()
    verdicts: Counter = Counter()
    pool = POPULATION[:n]
    for a in pool:
        if not admitted(a):
            continue
        outcome, v, _ = run_scenario(scenario, a["id"], paper_literal=paper_literal, model_client=model_client,
                                     tools=tools)
        outcomes[outcome.outcome if outcome else "CRASHED"] += 1
        verdicts[v.status] += 1
    total = sum(outcomes.values()) or 1
    return {"applicants": len(pool), "excluded_at_intake": len(pool) - sum(outcomes.values()),
            "n": total, "outcomes": dict(outcomes), "verdicts": dict(verdicts),
            "straight_through_pct": round(100 * outcomes["PASS"] / total, 1),
            "referral_pct": round(100 * outcomes["REFER"] / total, 1),
            "human_review_pct": round(100 * outcomes["HUMAN_REVIEW"] / total, 1)}


def _model_client(a):
    """None for the stubs; otherwise a casebound-models client (imported lazily: the core and the
    stub demo have no third-party dependencies)."""
    if a.model == "stub" and not a.replay:
        return None
    try:
        import casebound_models as cm
    except ImportError as e:
        raise SystemExit("--model / --replay need casebound-models: "
                         'pip install -e "packages/casebound-models[vertex]"') from e
    if a.replay:
        return cm.ReplayClient(a.replay)
    if a.model == "gemini":
        client = cm.GeminiModelClient(a.model_id or cm.DEFAULT_GEMINI_MODEL, project=a.gcp_project,
                                      location=a.gcp_location)
    elif a.model == "claude-vertex":
        client = cm.AnthropicModelClient.on_vertex(a.gcp_project, a.gcp_location, a.model_id or cm.DEFAULT_MODEL)
    else:
        client = cm.AnthropicModelClient(a.model_id or cm.DEFAULT_MODEL, inference_geo=a.inference_geo)
    return cm.RecordingClient(client, a.record) if a.record else client


def _tool_adapter(a):
    """None for the in-process registry; otherwise a casebound-mcp McpToolAdapter (imported lazily)."""
    if a.tools == "local" and not a.tools_url:
        return None
    try:
        from casebound_mcp import McpToolAdapter
        from casebound_mcp.http import urls
        from casebound_mcp.kyc import KYC_SERVERS, kyc_tool_servers
    except ModuleNotFoundError as e:
        if e.name not in ("casebound_mcp", "mcp"):
            raise
        raise SystemExit('--tools mcp / --tools-url need casebound-mcp: pip install -e "packages/casebound-mcp"') from e
    return McpToolAdapter(urls(a.tools_url, KYC_SERVERS) if a.tools_url else kyc_tool_servers())


def _list_models(a) -> None:
    """Print the Gemini models this project can call on Vertex (ground truth for --model-id)."""
    from casebound_models import vertex_genai_client
    # Keep the client referenced while iterating: models.list() is a lazy pager, and a google-genai
    # Client closes its HTTP connection when it is garbage-collected.
    client = vertex_genai_client(a.gcp_project, a.gcp_location)
    for m in client.models.list():
        actions = getattr(m, "supported_actions", None)
        if not actions or "generateContent" in actions:
            print(m.name)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="casebound-demo")
    ap.add_argument("--scenario", default="happy", choices=list(SCENARIOS))
    ap.add_argument("--applicant", default="borderline",
                    help="APP-#### id, or one of: clean, borderline, mismatch, single-channel")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--batch", type=int, metavar="N", help="run N applicants and print the funnel")
    ap.add_argument("--paper-literal", action="store_true",
                    help="read Alg 5 exactly as the manuscript writes it (see casebound.reconstruct)")
    ap.add_argument("--json", action="store_true", help="print the full verdict as JSON")
    ap.add_argument("--model", choices=["stub", "anthropic", "claude-vertex", "gemini"], default="stub",
                    help="stub: deterministic planner/decider (default). anthropic: Claude on the Anthropic API. "
                         "claude-vertex / gemini: Claude or Gemini on Google Vertex AI with Application Default Credentials")
    ap.add_argument("--model-id", default=None, help="override the provider's default model id")
    ap.add_argument("--inference-geo", default=None, help="Anthropic API only: pin where inference runs (us, eu)")
    ap.add_argument("--gcp-project", default=None, help="Vertex AI project (default: $GOOGLE_CLOUD_PROJECT)")
    ap.add_argument("--gcp-location", default="global",
                    help="Vertex AI location: global, or a region such as us-central1 for data residency")
    ap.add_argument("--list-models", action="store_true", help="with --model gemini: list callable Gemini models")
    ap.add_argument("--record", metavar="CASSETTE", help="append real model calls to this JSON-lines cassette")
    ap.add_argument("--replay", metavar="CASSETTE", help="serve model calls from a recorded cassette (no network)")
    ap.add_argument("--tools", choices=["local", "mcp"], default="local",
                    help="local: in-process tool registry (default). mcp: each KYC tool as its own MCP server, "
                         "reached over the MCP protocol in process")
    ap.add_argument("--tools-url", metavar="URL", help="reach the KYC tool servers over Streamable HTTP at this base "
                                                       "URL (see `casebound-mcp serve-tools`)")
    a = ap.parse_args(argv)
    try:
        if a.list_models:
            return _list_models(a)
        client = _model_client(a)
    except ValueError as e:                      # missing project or credentials: a setup problem, not a bug
        raise SystemExit(f"casebound-demo: {e}") from None

    if a.list:
        return _list_scenarios()
    tools = _tool_adapter(a)
    try:
        _run(a, client, tools)
    finally:
        if tools is not None:
            tools.close()


def _list_scenarios() -> None:
    for k, v in SCENARIOS.items():
        lit = f" (literal {v['expect_literal']})" if "expect_literal" in v else ""
        print(f"{k:20s} {v['group']:12s} expect {v['expect']:10s}{lit}\n{'':20s} {v['why']}")


def _run(a, client, tools) -> None:
    if a.batch:
        r = batch(a.batch, a.scenario, a.paper_literal, client, tools)
        print(f"{r['applicants']} applicants · {r['excluded_at_intake']} excluded at intake (Section 7.3) "
              f"· {r['n']} cases · scenario {a.scenario}")
        print(f"  outcomes  {r['outcomes']}")
        print(f"  verdicts  {r['verdicts']}")
        print(f"  straight-through {r['straight_through_pct']}% · referred {r['referral_pct']}% "
              f"· human review {r['human_review_pct']}%")
        return

    try:
        outcome, v, expected, ledger = run_scenario(a.scenario, a.applicant, return_ledger=True,
                                                    paper_literal=a.paper_literal, model_client=client, tools=tools)
    except ExcludedAtIntake as e:
        print(f"no case opened: {e}")
        return
    print(f"scenario {a.scenario} · applicant {a.applicant} · mode {v.mode}")
    print(f"outcome  {outcome.outcome if outcome else 'CRASHED'} ({outcome.reason if outcome else 'worker crash'})")
    print(f"verdict  {v.status}   (expected {expected})   read {len(v.events)} case events "
          f"(ledger holds {ledger.count()})")
    for c in v.checks:
        print(f"  line {c.line}: {'ok ' if c.passed else 'NO '} {c.invariant:5s} {c.name} — {c.note}")
    for f in v.findings:
        print(f"  FINDING [{f['severity']}] {f['kind']}: {f['note']}")
    for f in reconcile(ledger, v):
        flag = "EXPLAINS UNCOVERED STEP" if f["explains_uncovered_step"] else "unattributed"
        print(f"  RECONCILIATION [{flag}]: {f['type']} {f['tool']} ({f['source_event']}) — {f['note']}")
    if v.divergence:
        print(f"  PROP.1 divergence: recorded {v.divergence['recorded']} vs policy-grounded {v.divergence['policy_grounded']}")
    print("chain:")
    for e in v.events:
        print(f"  {e.seq:2d} {e.type.value:26s} {e.hash}  {json.dumps({k: e.data[k] for k in list(e.data)[:3]}, default=str)[:90]}")
    print("adverse action:", json.dumps(adverse_action_statement(v, reason_text), indent=1))
    if a.json:
        print(json.dumps({"art12": art12_record(v, "kyc_onboarding"), "verdict": v.to_dict()}, indent=1, default=str))


if __name__ == "__main__":
    main()
