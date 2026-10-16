# casebound

Reference implementation of the five **case-bound control invariants (C1–C5)** and the
**audit-reconstruction gate** from *Agent Security Meets Regulatory Reality* (Guda, under review at
*Software: Practice and Experience*). It makes one claim executable: for an LLM agent running a regulated workflow,
"was this decision compliant?" is a computable function of the case identifier alone.

| Invariant | Meaning | Enforced in |
|---|---|---|
| C1 case-bound continuity | every action carries the case id and a per-case sequence number, hash-chained | `ledger.py`, `gateway.py` |
| C2 least-privilege tool access | only capabilities allowed for the agent's role and workflow | `gateway.py` (Alg 2) |
| C3 current-policy grounding | every policy-dependent step uses the approved version effective at that time | `policy.py` (Alg 3) |
| C4 inference-boundary redaction | only redacted, structured fields cross to the model | `redaction.py` (Alg 4) |
| C5 decision-evidence reconstruction | the full decision basis is reconstructable from the case id | `reconstruct.py` (Alg 5) |

`workflow.py` is Algorithm 1. `reconstruct.phi()` is the formal predicate Φ(c); `tests/test_theorem1.py`
checks Theorem 1 (gate returns COMPLETE ⇔ Φ(c)) with property-based testing.

The manuscript is the specification for every algorithm. Where a predicate admits more than one
reading, the implementation provides each one behind a switch rather than choosing silently (see
"Two readings of Algorithm 5" below).

## Quickstart

```bash
pip install -e ".[dev]"
pytest -q                                    # incl. the Theorem 1 property and engine parity
casebound-demo --list                        # the fault matrix, with the status each must produce
casebound-demo --scenario stale-policy       # Section 7.1, caught at audit
casebound-demo --scenario pii-in-field       # Alg 5 line 6, second leg: redaction ran and still leaked
casebound-demo --scenario bypass             # Section 7.2, caught by the plan-commitment reading
casebound-demo --scenario bypass --paper-literal   # ... and what the manuscript's literal line 8 returns
casebound-demo --batch 140                   # the whole population; prints the outcome funnel
```

Then open **`demo/demo.html`** in a browser: an auditor console with a case queue, evidence packs, a live
policy-lifecycle console, portfolio metrics and every fault above as a switch. One file, no server,
no network.

Everything in `demo/` is synthetic and generated from a fixed seed by `demo/kyc/generate.py`. The
planner, decider and tools are deterministic stand-ins; the ledger, gates and reconstruction are the
real thing.

## The demo dashboard

`demo/demo.html` is **generated**. Edit the parts, not the output:

```
demo/dashboard.template.html   markup and design tokens
demo/engine.js                 port of src/casebound (no DOM)
demo/harness.js                port of demo/kyc (no DOM)
demo/ui.js                     rendering only
demo/kyc/dataset.json          generated population + policy corpus, shared with the Python demo
demo/demo.html                 the build output; never edit it directly

python -m demo.kyc.generate      # regenerate the dataset from its seed
python -m demo.build_dashboard   # reassemble demo/demo.html
```

The dashboard runs a second implementation of Algorithms 1-5 in JavaScript, which is how it stays a
single file with no server. `tests/test_engine_parity.py` runs that engine in Node over the same
fault matrix and the same generated data and fails if any verdict, invariant vector or failing check
number disagrees with the Python core, so the second implementation cannot drift unnoticed.

## Two readings of Algorithm 5

Two places in the manuscript admit more than one reading, and the code implements both rather than
picking one silently. `reconstruct(..., paper_literal=True)` (or the switch in the dashboard) selects
the manuscript's literal text:

| | default (`extended`) | `paper_literal=True` |
|---|---|---|
| line 8 `Is_Chain_Traversable` | also requires every declared plan step to have reached the gate | every `TOOL_INVOKED` has a `TOOL_COMPLETED` |
| line 9 status on a violated invariant | `FAILED`, per the status-semantics paragraph | `INCOMPLETE`, per the pseudocode |
| a Section 7.2 gate bypass | `INCOMPLETE` | `COMPLETE`, with the bypass reported as a finding |

The second column is what the manuscript states for a violation of Assumption A1: "the ledger does
not observe it, Lemma 1 fails, and Algorithm 5 may return COMPLETE for a case whose true execution
violates an invariant."

## Layout

```
src/casebound/        core, domain-neutral, no third-party dependencies
  events.py           Event schema + hashing            ledger.py      Ledger port, InMemory + SQLite adapters
  ports.py            Protocols + control exceptions    policy.py      Alg 3 (+ Section 7.1 fix)
  redaction.py        Alg 4                             gateway.py     Alg 2, ToolRegistry, @controlled_tool
  workflow.py         Alg 1                             reconstruct.py Alg 5, phi(), Prop. 1 comparator hook
  evidence.py         adverse-action / Art. 12 views
                      reconstruct.reconcile() is a deployment-level control, outside Alg 5
  model.py            gated model adapter: the only path to the model, emits INFERENCE
demo/kyc/             synthetic KYC: generator, dataset, mock tools, stubs, fault matrix, CLI
demo/*.js             the browser engine, harness and UI that build demo/demo.html
demo/demo.html        the built dashboard, generated; open this one
tests/                fault matrix, Theorem 1 property, paper-alignment, engine parity, build freshness
```

## Using the core in your own workflow

1. Register tools with `ToolRegistry.controlled_tool(name, capability)`.
2. Implement `Authorizer`, `PolicyIndex`/`ComplianceFeed`, `Planner`, `Decider` (see `ports.py`).
3. Build a `WorkflowContext`, call `execute_regulated_workflow(ctx, Request(...))`.
4. Audit any case later with `reconstruct(ledger, case_id, authorizer, feed)`; render with `evidence.py`.

## Status

v0.3.0, pre-publication. License: Apache-2.0 is proposed in
`pyproject.toml` but no LICENSE file is committed, because licensing and attribution are the author's
call, not the code's.

Algorithm 5 line 6 checks that the inference payload is PII-free, not merely that a redaction record
exists; INFERENCE events are emitted by a gated model adapter; and the two readings above are
switchable.

Known limitations: PII detection is field-name plus regex, tool responses are stored inline by default,
C2 is checked against the current authorizer rather than the entitlements in force at the time of the
event (drift is now reported, not fixed), the ledger adapters are in-memory and SQLite, and the
implementation is single-agent. This is a reference implementation with a conformance suite, not a
production system. Generative AI tools assisted in developing this software and in generating the
synthetic dataset; the authors reviewed all AI-assisted output (see the manuscript's AI usage
statement).

## Citation

Guda, K. M. N. S. "Agent Security Meets Regulatory Reality: A Practitioner Systematization of
Autonomous-Agent Threats and Controls in Regulated Financial Systems." *Software: Practice and
Experience* (under review, 2026). Citation will be updated on publication.
