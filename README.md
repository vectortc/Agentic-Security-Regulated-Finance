# casebound

Reference implementation accompanying the manuscript *Agent Security Meets Regulatory Reality: A
Practitioner Systematization of Autonomous-Agent Threats and Controls in Regulated Financial
Systems* (under review at *Software: Practice and Experience*). Appendix A of the manuscript
describes this repository.

It implements the paper's five case-bound control invariants (C1–C5), its reference algorithms
(Algorithms 1–5), and the audit-reconstruction gate of Theorem 1. For an agent running a regulated
workflow, "was this decision compliant?" becomes a computable function of the case identifier
alone.

**Everything here runs on synthetic data.** This is not the production system the paper describes,
and none of the paper's production observations come from it.

## Contents

| Package | What it is |
|---|---|
| [`packages/casebound`](packages/casebound) | The core: hash-chained ledger, Algorithms 1–5, the predicate Φ(c), and the gated model adapter. Depends only on the Python standard library. Also holds a synthetic KYC workload, a command-line demo, a single-file browser demo (`demo/demo.html`) and the test suite. |
| [`packages/casebound-models`](packages/casebound-models) | Model clients behind the core's model interface: Claude through the Anthropic API or Google Vertex AI, and Gemini through Vertex AI. Recorded runs replay without network access. |
| [`packages/casebound-mcp`](packages/casebound-mcp) | The case-bound tool-call contract for the Model Context Protocol: tool servers that refuse a call without a case identifier, a client adapter, and a gateway that applies Algorithm 2 to every call. |

## Where each part of the paper lives

Paths are relative to `packages/casebound/src/casebound/` unless stated otherwise.

| Paper | Implementation | Checked by |
|---|---|---|
| Algorithm 1, Execute_Regulated_Workflow | `workflow.py` | `tests/test_scenarios.py` |
| Algorithm 2, Invoke_Controlled_Tool (C2) | `gateway.py` | `tests/test_scenarios.py`, `tests/test_tool_boundary.py` |
| Algorithm 3, Retrieve_Current_Policy (C3) | `policy.py` | `tests/test_scenarios.py` |
| Algorithm 4, Redact_Before_Inference (C4) | `redaction.py`, `model.py` | `tests/test_payload_scan.py`, `tests/test_model_gate.py` |
| Algorithm 5, Reconstruct_Decision_Evidence (C5) | `reconstruct.py` | `tests/test_scenarios.py`, `tests/test_paper_alignment.py` |
| Case-bound, hash-chained ledger (C1) | `ledger.py`, `events.py` | the `tampered-ledger` scenario |
| Φ(c) and Theorem 1 | `reconstruct.phi` | `tests/test_theorem1.py` (property-based) |
| Case-ID propagation (Section 5.2) | `packages/casebound-mcp` | its `tests/` |
| Inference mediation (Assumption A1) | `model.py` | `tests/test_model_gate.py` |

## Reproducing the checks

Requires Python 3.11 or later. One test compares the browser demo's JavaScript engine with the
Python core and is skipped when Node.js is not installed. No credentials or network access are
needed. Run these from the repository root in a fresh virtual environment (POSIX shell):

```bash
pip install -e "packages/casebound[dev]"
(cd packages/casebound && pytest -q)          # includes the Theorem 1 property test
casebound-demo --list                         # every scenario and its expected verdict
casebound-demo --scenario stale-policy        # one scenario, with its reconstructed evidence

pip install -e "packages/casebound-models[dev,vertex]" -e "packages/casebound-mcp[dev]"
(cd packages/casebound-models && PYTHONPATH=../casebound pytest -q)
(cd packages/casebound-mcp && PYTHONPATH=../casebound pytest -q)
casebound-demo --tools mcp --scenario happy   # every tool call over MCP
```

Open `packages/casebound/demo/demo.html` in a browser for the auditor console. It is one file, with no server.

Continuous integration (`.github/workflows/ci.yml`) runs the same commands on every change.

## Synthetic data

`packages/casebound/demo/kyc/generate.py` produces the applicant population and the versioned
policy corpus from a fixed seed. Its parameters are illustrative, so the outcome shares the demo
reports are not evidence for the paper's production observations. As in Section 7.3, applicants with
a single contact channel are excluded at intake and never become cases. Identifiers are drawn from ranges reserved for fiction: Social
Security numbers in the 900–999 area, which is never issued; telephone numbers in 555-01XX; and
e-mail addresses under `.test`.

## AI usage

Generative AI tools assisted in developing this software and in generating the synthetic dataset.
The authors reviewed all AI-assisted output. The manuscript's AI usage statement covers this.

## Licence and citation

The licence will be added before this repository is made public. Citation details will follow the
archived release.
