/* casebound engine — a faithful port of src/casebound, with no DOM dependency.
 *
 * This block is the demo's second implementation of Algorithms 1–5. It exists so the prototype
 * is one double-clickable file with no server, and it is kept honest by tests/test_engine_parity.py,
 * which loads exactly this script in Node, runs the same scenario matrix over the same generated
 * dataset, and fails if any verdict disagrees with the Python core.
 *
 * Where the two must agree: statuses, invariant predicates, and which check fires. Where they
 * need not: hash function (fnv-1a here, SHA-256 there) and timestamp formatting.
 *
 * Generated data and policy corpus come from demo/kyc/dataset.json, embedded into demo.html by
 * demo/build_dashboard.py. Nothing here is real.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.CB = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const COMPLETE = 'COMPLETE', INCOMPLETE = 'INCOMPLETE', FAILED = 'FAILED';
  const GENESIS = '0000000000000000';

  /* ---------- hashing (src/casebound/events.py) ---------- */
  function fnv(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return h.toString(16).padStart(8, '0');
  }
  function canon(v) {                                   // JSON with sorted keys, like json.dumps(sort_keys=True)
    if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : v);
    if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  const digest = o => fnv(canon(o)) + fnv(canon(o) + '');   // 16 hex chars, as in Python
  const hashEvent = e => digest([e.case_id, e.seq, e.type, e.ts, e.data, e.prev_hash]);
  const verify = e => e.hash === hashEvent(e);

  /* ---------- ledger (src/casebound/ledger.py) ---------- */
  class Ledger {
    constructor(startISO, archive = 0) {
      this.events = []; this.seq = {}; this.prev = {};
      this.archive = archive;
      this.t0 = new Date(startISO || '2026-09-05T14:00:00Z').getTime();
    }
    append(caseId, type, data = {}) {
      const seq = caseId ? (this.seq[caseId] = (this.seq[caseId] || 0) + 1) : null;
      const prev = caseId ? (this.prev[caseId] || GENESIS) : GENESIS;
      const e = {
        case_id: caseId || null, seq, type,
        ts: new Date(this.t0 + this.events.length * 137).toISOString(),
        data, prev_hash: prev, hash: '',
      };
      e.hash = hashEvent(e);
      if (caseId) this.prev[caseId] = e.hash;
      this.events.push(e);
      return e;
    }
    fetchByCase(c) { return this.events.filter(e => e.case_id === c); }
    untagged() { return this.events.filter(e => e.case_id === null); }
    count() { return this.events.length; }
    get total() { return this.archive + this.events.length; }
    reset() { this.events = []; this.seq = {}; this.prev = {}; }
  }

  /* ---------- redaction, Algorithm 4 (src/casebound/redaction.py) ---------- */
  const PII_PATTERNS = {
    ssn: /\b\d{3}-\d{2}-\d{4}\b/,
    email: /[\w.+-]+@[\w-]+\.[\w.-]+/,
    phone: /(?<![\d-])(?!\d{4}-\d{2}-\d{2}(?!\d))\+?\d[\d\s().\-]{8,}\d/,   // not mid-number, not an ISO date (mirrors redaction.py)
  };
  const anyPII = v => typeof v === 'string' && Object.values(PII_PATTERNS).some(p => p.test(v));

  function detectPII(fields, schema) {
    const hits = Object.keys(fields).filter(k => schema.pii_fields.includes(k));
    for (const [k, v] of Object.entries(fields)) if (!hits.includes(k) && anyPII(v)) hits.push(k);
    return hits;
  }
  const SSN_ONLY = /\b\d{3}-\d{2}-\d{4}\b/;
  function narrowDetector(fields, schema) {            // Assumption A3: a detector with a blind spot
    const hits = Object.keys(fields).filter(k => schema.pii_fields.includes(k));
    for (const [k, v] of Object.entries(fields))
      if (!hits.includes(k) && typeof v === 'string' && SSN_ONLY.test(v)) hits.push(k);
    return hits;
  }
  const classifyBoundary = p => Object.values(p).some(anyPII) ? 'raw-pii' : 'redacted-structured';
  const narrowClassifier = p =>
    Object.values(p).some(v => SSN_ONLY.test(String(v))) ? 'raw-pii' : 'redacted-structured';

  /** Field names in an outbound payload that still carry PII: `Some_Inference_Payload_Unredacted`. */
  function scanPayloadPII(payload) {
    return Object.keys(payload).filter(k => anyPII(payload[k])).sort();
  }

  function redactBeforeInference(L, caseId, raw, schema, boundary, classifier, detector) {
    const fields = {};
    for (const k of schema.fields) if (k in raw) fields[k] = raw[k];        // Structured_Extraction
    const pii = (detector || detectPII)(fields, schema);
    const vault = {}, sanitized = Object.assign({}, fields);
    for (const k of pii) {                                                  // Redact_Or_Tokenize
      const tok = 'TOK_' + digest([caseId, k, fields[k]]).slice(0, 8);
      vault[tok] = fields[k]; sanitized[k] = tok;
    }
    for (const k of schema.free_text_fields) delete sanitized[k];           // Remove_Free_Text
    const bclass = (classifier || classifyBoundary)(sanitized);
    if (!boundary.allow(bclass)) {
      const e = L.append(caseId, 'REDACTION_BOUNDARY_FAILED', { boundary_class: bclass, decision: 'DENY' });
      throw new ControlException('InferenceBoundaryError', `boundary class ${bclass} denied (evidence ${e.hash})`);
    }
    const e = L.append(caseId, 'REDACTION_COMPLETED', {
      boundary_class: bclass, decision: 'ALLOW', pii_fields: pii,
      tokens: Object.keys(vault).sort(), payload_digest: digest(sanitized),
      dropped_fields: schema.free_text_fields.filter(k => k in fields),
      fields_in: Object.keys(raw).length, fields_out: Object.keys(sanitized).length,
    });
    return { sanitized, redEv: { event_hash: e.hash, boundary_class: bclass, pii_fields: pii }, vault };
  }

  /* ---------- errors ---------- */
  class ControlException extends Error { constructor(name, msg) { super(msg); this.name = name; } }
  class WorkerCrash extends Error {}

  /* ---------- policy, Algorithm 3 (src/casebound/policy.py) ---------- */
  const policyDigest = v => digest([v.policy_id, v.version, v.body]);
  const withinWindow = (d, from, to) => d >= from && (!to || d <= to);

  function makePolicyStore(policies) {
    const feed = policies.map(p => ({ ...p, body: { ...p.body }, digest: policyDigest(p) }));
    const store = {
      feed, index: [],
      deliver(v) { if (!feed.some(x => x.policy_id === v.policy_id && x.version === v.version)) feed.push(v); },
      approve(policyId, version) {
        const v = feed.find(x => x.policy_id === policyId && x.version === version);
        if (v) v.state = 'APPROVED';
      },
      retire(policyId, version, effectiveTo) {
        const v = feed.find(x => x.policy_id === policyId && x.version === version);
        if (v) v.effective_to = effectiveTo;
      },
      ingest() { store.index = feed.filter(v => v.state === 'APPROVED').map(v => ({ ...v, body: { ...v.body } })); },
      query(workflow, jurisdiction) {
        return store.index.filter(v => v.body.workflow === workflow && v.body.jurisdiction === jurisdiction);
      },
      versions(policyId) { return feed.filter(v => v.policy_id === policyId); },
    };
    store.ingest();
    return store;
  }

  function retrieveCurrentPolicy(L, caseId, store, workflow, jurisdiction, today, effectiveDatingAuthoritative) {
    const current = store.query(workflow, jurisdiction)
      .filter(v => v.state === 'APPROVED' && withinWindow(today, v.effective_from, v.effective_to));
    if (!current.length) {
      L.append(caseId, 'NO_CURRENT_POLICY', { workflow, jurisdiction });
      throw new ControlException('NoCurrentPolicyError', `no approved policy effective on ${today}`);
    }
    const sel = current.reduce((a, b) => (b.version > a.version ? b : a));
    if (effectiveDatingAuthoritative) {
      const succ = store.versions(sel.policy_id)
        .filter(v => v.version > sel.version && v.state !== 'APPROVED' && v.effective_from <= today)
        .sort((a, b) => a.version - b.version)[0];
      if (succ) {
        L.append(caseId, 'POLICY_PENDING_SUPERSEDED', {
          incumbent: `${sel.policy_id}@v${sel.version}`, successor: `${succ.policy_id}@v${succ.version}`,
          successor_effective: succ.effective_from,
        });
        throw new ControlException('PendingSupersededError',
          `${sel.policy_id}@v${sel.version} pending-superseded by v${succ.version}`);
      }
    }
    if (sel.digest !== policyDigest(sel)) {
      L.append(caseId, 'POLICY_INTEGRITY_FAILED', { policy_ref: `${sel.policy_id}@v${sel.version}` });
      throw new ControlException('PolicyIntegrityError', 'digest mismatch');
    }
    const ref = `${sel.policy_id}@v${sel.version}`;
    const e = L.append(caseId, 'POLICY_RETRIEVED', {
      policy_ref: ref, policy_id: sel.policy_id, version: sel.version, digest: sel.digest,
      effective_from: sel.effective_from, effective_to: sel.effective_to,
    });
    return { ref, version: sel, event_hash: e.hash };
  }

  /* ---------- authorization + gateway, Algorithm 2 (src/casebound/gateway.py) ---------- */
  function makeAuthorizer(allowed) {
    return {
      allowed,
      authorize: (role, wf, cap) => (allowed[`${role}/${wf}`] || []).includes(cap),
      policySetDigest: () => digest(Object.keys(allowed).sort().map(k => [k, [...allowed[k]].sort()])),
    };
  }
  const allowRedactedOnly = { allow: cls => cls === 'redacted-structured' };

  function buildEnvelope(caseId, step, payload, policy, authorizer, attempt) {
    const env = {
      case_id: caseId, tool: step.tool, capability: step.capability, agent_role: step.agent_role,
      workflow: step.workflow, payload_digest: digest(payload),
      policy_ref: policy ? policy.ref : null, boundary_class: 'redacted-structured', attempt,
    };
    env.idempotency_key = digest([caseId, step.tool, step.capability, env.payload_digest, attempt]);
    const d = authorizer.policySetDigest && authorizer.policySetDigest();
    if (d) env.authz_digest = d;
    return env;
  }

  function invokeControlledTool(L, caseId, step, payload, policy, authorizer, boundary, tools, ctx, attempt = 1) {
    const env = buildEnvelope(caseId, step, payload, policy, authorizer, attempt);
    if (!authorizer.authorize(step.agent_role, step.workflow, step.capability)) {          // C2
      L.append(caseId, 'TOOL_AUTHZ_DENIED', env);
      throw new ControlException('AuthorizationError',
        `${step.capability} not allowed for ${step.agent_role}/${step.workflow}`);
    }
    if (!boundary.allow(env.boundary_class)) {                                             // C4
      L.append(caseId, 'BOUNDARY_VIOLATION', env);
      throw new ControlException('BoundaryViolationError', env.boundary_class);
    }
    if (!policy || !policy.ref || policy.version.state !== 'APPROVED') {                    // C3
      L.append(caseId, 'POLICY_GROUNDING_FAILED', env);
      throw new ControlException('PolicyGroundingError', 'policy evidence missing or unapproved');
    }
    L.append(caseId, 'TOOL_INVOKED', env);                                                  // C1: before execution
    const response = tools[step.tool]({ ...env, payload, ...ctx });   // as gateway.py: envelope, payload, context
    L.append(caseId, 'TOOL_COMPLETED', {
      tool: step.tool, capability: step.capability, payload_digest: env.payload_digest,
      response_digest: digest(response), response, policy_ref: policy.ref,
      attempt, idempotency_key: env.idempotency_key,
    });
    return response;
  }

  /* ---------- the gated model adapter (src/casebound/model.py) ---------- */
  function makeModelAdapter(L, planner, decider, modelId) {
    const emit = (caseId, purpose, redacted, leaked, redEv, extra) => L.append(caseId, 'INFERENCE', {
      purpose, model: modelId || 'stub',
      redaction_ev: redEv ? redEv.event_hash : null,
      boundary_class: redEv ? redEv.boundary_class : 'UNMEDIATED',
      payload_digest: digest(redacted), payload_fields: Object.keys(redacted).sort(),
      payload_pii: leaked, ...(extra || {}),
    });
    return {
      plan(caseId, workflow, policy, redacted, redEv) {
        const leaked = scanPayloadPII(redacted);
        const plan = planner.plan(workflow, policy, redacted);
        const steps = plan.map(s => s.tool);
        emit(caseId, 'plan', redacted, leaked, redEv, { plan_steps: steps, plan_digest: digest(steps) });
        return plan;
      },
      decide(caseId, results, policy, redacted, redEv) {
        const leaked = scanPayloadPII(redacted);
        const d = decider.decide(results, policy, redacted);
        emit(caseId, 'decide', redacted, leaked, redEv, { decision_digest: digest([d.decision, d.factors]) });
        return d;
      },
    };
  }

  /* ---------- Algorithm 1 ---------- */
  let caseCounter = 0;
  const newCaseId = () => 'c-' + digest(['case', ++caseCounter, Date.now()]).slice(0, 12);

  function executeRegulatedWorkflow(cfg) {
    const { ledger: L, request, schema, store, authorizer, boundary, tools, planner, decider } = cfg;
    const caseId = newCaseId();
    L.append(caseId, 'CASE_OPENED', {
      workflow: request.workflow, jurisdiction: request.jurisdiction,
      agent_role: request.agent_role, input_digest: digest(request.input),
      applicant_ref: 'TOK_' + digest(['applicant', request.applicant_id]).slice(0, 8),
    });
    let policy = null, decision = null;
    try {
      let redacted, redEv;
      if (cfg.redactHook) { ({ redacted, redEv } = cfg.redactHook()); }
      else {
        const r = redactBeforeInference(L, caseId, request.input, schema, boundary,
          cfg.boundaryClassifier, cfg.piiDetector);
        redacted = r.sanitized; redEv = r.redEv;
      }
      policy = retrieveCurrentPolicy(L, caseId, store, request.workflow, request.jurisdiction,
        cfg.today, !!cfg.effectiveDatingAuthoritative);
      const model = makeModelAdapter(L, planner, decider, cfg.modelId);
      const plan = model.plan(caseId, request.workflow, policy, redacted, redEv);
      const results = [];
      for (const step of plan) {
        const response = cfg.toolInvokerHook
          ? cfg.toolInvokerHook(step, caseId, redacted, policy)
          : invokeControlledTool(L, caseId, step, redacted, policy, authorizer, boundary, tools, cfg.toolContext);
        results.push({ tool: step.tool, response });
      }
      decision = model.decide(caseId, results, policy, redacted, redEv);
      L.append(caseId, 'DECISION_RECORDED', { decision: decision.decision, factors: decision.factors });
    } catch (e) {
      if (e instanceof ControlException) {
        L.append(caseId, 'ROUTED_TO_HUMAN_REVIEW',
          { reason: 'CONTROL_EXCEPTION', exception: e.name, detail: e.message });
        return { case_id: caseId, outcome: 'HUMAN_REVIEW', reason: `${e.name}: ${e.message}` };
      }
      if (e instanceof WorkerCrash) return { case_id: caseId, outcome: 'CRASHED', reason: e.message };
      throw e;
    }
    const v = reconstruct(L, caseId, authorizer, store, null, cfg);
    if (v.status !== COMPLETE) {
      L.append(caseId, 'ROUTED_TO_HUMAN_REVIEW', { reason: 'INCOMPLETE_EVIDENCE', status: v.status });
      return { case_id: caseId, outcome: 'HUMAN_REVIEW', reason: `gate returned ${v.status}`, status: v.status };
    }
    L.append(caseId, 'DECISION_PERSISTED',
      { decision: decision.decision, factors: decision.factors, policy_ref: policy.ref });
    return { case_id: caseId, outcome: decision.decision, reason: decision.factors.join(', '), status: v.status };
  }

  /** Extension beyond the paper: a reviewer closes a routed case. Does not make it COMPLETE. */
  function recordReviewDecision(L, caseId, reviewer, outcome, rationale) {
    return L.append(caseId, 'REVIEW_DECISION', { reviewer, outcome, rationale: rationale || '' });
  }

  /* ---------- Algorithm 5 (src/casebound/reconstruct.py) ---------- */
  const by = (ev, t) => ev.filter(e => e.type === t);

  function planCoverage(ev) {
    const plan = by(ev, 'INFERENCE').find(e => e.data.purpose === 'plan');
    if (!plan) return [];
    const reached = new Set([...by(ev, 'TOOL_INVOKED'), ...by(ev, 'TOOL_AUTHZ_DENIED')].map(e => e.data.tool));
    return plan.data.plan_steps.filter(t => !reached.has(t));
  }
  function orphanInvocations(ev) {
    const key = e => e.data.idempotency_key || e.data.tool;
    const done = new Set(by(ev, 'TOOL_COMPLETED').map(key));
    return [...new Set(by(ev, 'TOOL_INVOKED').filter(e => !done.has(key(e))).map(e => e.data.tool))].sort();
  }
  function unredactedInferences(ev) {
    const inf = by(ev, 'INFERENCE');
    return {
      missingEv: inf.filter(e => !e.data.redaction_ev),
      leaked: inf.filter(e => (e.data.payload_pii || []).length),
    };
  }
  function policyEffective(pol, store) {
    if (!pol) return false;
    const ref = store.versions(pol.data.policy_id).find(v => v.version === pol.data.version);
    return !!ref && withinWindow(pol.ts.slice(0, 10), ref.effective_from, ref.effective_to);
  }

  function phi(caseId, ev, authorizer, store, planCommitment) {
    const invoked = new Set(by(ev, 'TOOL_INVOKED').map(e => e.data.tool));
    const completed = by(ev, 'TOOL_COMPLETED');
    const c1 = ev.length > 0 && ev.every(e => e.case_id === caseId)
      && ev.every((e, i) => e.seq === i + 1) && ev.every(verify);
    const c2 = by(ev, 'TOOL_INVOKED')
      .every(e => authorizer.authorize(e.data.agent_role || '', e.data.workflow || '', e.data.capability));
    const pol = by(ev, 'POLICY_RETRIEVED');
    const c3 = pol.length > 0 && pol.every(p => policyEffective(p, store));
    const { missingEv, leaked } = unredactedInferences(ev);
    const c4 = !missingEv.length && !leaked.length;
    const dec = by(ev, 'DECISION_RECORDED');
    const doneSet = new Set(completed.map(e => e.data.tool));
    const c5 = dec.length === 1 && completed.length > 0
      && invoked.size === doneSet.size && [...invoked].every(t => doneSet.has(t))
      && !(planCommitment && planCoverage(ev).length);
    return { C1: c1, C2: c2, C3: c3, C4: c4, C5: c5 };
  }

  function reconstruct(L, caseId, authorizer, store, comparator, opts) {
    const o = opts || {};
    const paperLiteral = !!o.paperLiteral;
    const planCommitment = !paperLiteral;
    const line9 = paperLiteral ? INCOMPLETE : FAILED;
    const t0 = (typeof performance !== 'undefined' ? performance.now() : Date.now());

    const ev = L.fetchByCase(caseId);                                       // line 1: O(E_case)
    const v = {
      case_id: caseId, status: COMPLETE, checks: [], events: ev, invariants: {},
      divergence: null, findings: [], mode: paperLiteral ? 'paper-literal' : 'extended',
    };
    const ck = (line, inv, name, passed, note, onFail) => {
      v.checks.push({ line, invariant: inv, name, passed, note });
      if (!passed && v.status === COMPLETE) v.status = onFail || INCOMPLETE;
    };

    if (!ev.length) {                                                        // line 2
      ck(2, 'C1', 'events non-empty', false, 'no events for case', FAILED);
      v.status = FAILED; v.ms = 0; v.read = 0;
      return v;
    }
    const gaps = !ev.every((e, i) => e.seq === i + 1);
    const broken = ev.filter(e => !verify(e)).map(e => e.seq);
    ck(3, 'C1', 'sequence gaps / malformed events', !gaps && !broken.length,   // line 3
      gaps ? 'seq not contiguous (event lost after its number was assigned)'
        : broken.length ? `hash mismatch at seq ${broken.join(', ')} (ledger tampering: A5 violated)`
          : `seq 1..${ev.length} contiguous, hash chain intact`, FAILED);

    const pol = by(ev, 'POLICY_RETRIEVED');
    ck(5, 'C3', 'policy evidence present', !!pol.length,                       // line 5
      pol.length ? pol[0].data.policy_ref : 'no POLICY_RETRIEVED event');

    const inf = by(ev, 'INFERENCE');
    const { missingEv, leaked } = unredactedInferences(ev);
    const leakedFields = [...new Set(leaked.flatMap(e => e.data.payload_pii))].sort();
    ck(6, 'C4', 'inference redacted (evidence reference and PII-free payload)',  // line 6
      !missingEv.length && !leaked.length,
      missingEv.length ? 'inference occurred without redaction evidence (raw payload crossed the boundary)'
        : leaked.length ? `redaction ran but the payload sent to the model still carried PII in ${leakedFields.join(', ')} (Some_Inference_Payload_Unredacted)`
          : `${inf.length} inference event(s) reference REDACTION_COMPLETED, payloads PII-free`, FAILED);

    const dec = by(ev, 'DECISION_RECORDED'), tools = by(ev, 'TOOL_COMPLETED');
    ck(7, 'C5', 'decision recorded and tool chain non-empty', dec.length === 1 && !!tools.length,  // line 7
      !dec.length ? 'no DECISION_RECORDED' : !tools.length ? 'tool chain empty (zero-tool plan)'
        : `${dec[0].data.decision} with ${tools.length} tool event(s)`);

    const orphan = orphanInvocations(ev);
    const uncovered = planCommitment ? planCoverage(ev) : [];
    ck(8, 'C5', 'chain traversable (every INVOKED has COMPLETED'                 // line 8
      + (planCommitment ? '; declared steps reached the gate)' : ')'),
      !orphan.length && !uncovered.length,
      orphan.length ? `TOOL_INVOKED ${orphan.join(', ')} without TOOL_COMPLETED (crash between invoke and complete)`
        : uncovered.length ? `declared plan step(s) ${uncovered.join(', ')} have no case-tagged tool event — evidence absent, violation not proven from E(c); run reconcile()`
          : 'traversable end to end');

    const p = phi(caseId, ev, authorizer, store, planCommitment);                 // line 9
    v.invariants = p;
    ck(9, 'C1–C5', 'per-event invariant checks', Object.values(p).every(Boolean),
      Object.entries(p).map(([k, ok]) => `${k} ${ok ? 'ok' : 'VIOLATED'}`).join(' · '), line9);

    v.findings = findings(ev, authorizer, paperLiteral);
    if (comparator && v.status === COMPLETE) v.divergence = comparator(v);
    v.ms = (typeof performance !== 'undefined' ? performance.now() : Date.now()) - t0;
    v.read = ev.length;
    return v;
  }

  function findings(ev, authorizer, paperLiteral) {
    const out = [];
    const now = authorizer.policySetDigest && authorizer.policySetDigest();
    const recorded = [...new Set(by(ev, 'TOOL_INVOKED').map(e => e.data.authz_digest).filter(Boolean))];
    if (now && recorded.length && (recorded.length > 1 || recorded[0] !== now)) {
      out.push({
        kind: 'entitlement_drift', severity: 'warn', recorded, current: now,
        note: "the authorizer's entitlement set changed since this case ran; C2 above was evaluated against "
          + "today's allowed set, not the one in force at t(e) (Eq. 2 has no time index)",
      });
    }
    if (paperLiteral && planCoverage(ev).length) {
      out.push({
        kind: 'plan_step_unevidenced', severity: 'serious', steps: planCoverage(ev),
        note: "a declared plan step has no case-tagged tool event. Under the manuscript's literal line 8 this "
          + 'does not affect the status, which is the A1 gate-bypass hazard the paper names in Section 7.2; '
          + 'only cross-source reconciliation can prove it',
      });
    }
    const review = by(ev, 'REVIEW_DECISION');
    if (review.length) {
      const r = review[review.length - 1].data;
      out.push({
        kind: 'human_review_closed', severity: 'info', outcome: r.outcome, reviewer: r.reviewer,
        note: `case closed by ${r.reviewer} as ${r.outcome}${r.rationale ? ': ' + r.rationale : ''}`,
      });
    }
    return out;
  }

  function reconcile(L, verdict) {
    const uncovered = planCoverage(verdict.events);
    return L.untagged().map(e => ({
      source_event: e.hash, tool: e.data.tool, type: e.type,
      explains_uncovered_step: uncovered.includes(e.data.tool),
      note: uncovered.includes(e.data.tool)
        ? 'untagged record matches a declared plan step with no case-tagged evidence'
        : 'untagged record not attributable to this case',
    }));
  }

  /* ---------- evidence packs (src/casebound/evidence.py) ---------- */
  function adverseActionStatement(v, reasonText, adverse = ['REJECT', 'REFER']) {
    const d = by(v.events, 'DECISION_RECORDED')[0];
    if (!d) return { issuable: false, why: 'no decision recorded; case is in human review' };
    if (!adverse.includes(d.data.decision)) return { issuable: false, why: `decision ${d.data.decision} is not adverse` };
    if (v.status !== COMPLETE) return { issuable: false, why: `gate returned ${v.status}; notice withheld pending human review` };
    const pol = by(v.events, 'POLICY_RETRIEVED')[0];
    return {
      issuable: true, case_id: v.case_id, action: d.data.decision,
      principal_reasons: d.data.factors.map(reasonText),
      basis: {
        decision_event: d.seq, policy_ref: pol ? pol.data.policy_ref : null,
        tool_events: by(v.events, 'TOOL_COMPLETED').map(t => t.seq),
      },
    };
  }

  function art12Record(v, systemId) {
    const inf = by(v.events, 'INFERENCE');
    return {
      system: systemId, case_id: v.case_id,
      period: v.events.length ? [v.events[0].ts, v.events[v.events.length - 1].ts] : null,
      events_logged: v.events.length,
      policy_versions: [...new Set(by(v.events, 'POLICY_RETRIEVED').map(e => e.data.policy_ref))].sort(),
      inference_boundary: inf.map(e => e.data.redaction_ev
        ? ((e.data.payload_pii || []).length ? 'REDACTED BUT LEAKING' : 'redacted-structured') : 'RAW'),
      tools: by(v.events, 'TOOL_COMPLETED').map(t => t.data.tool),
      human_oversight: v.events.some(e => e.type === 'ROUTED_TO_HUMAN_REVIEW'),
      human_review_closed: v.events.some(e => e.type === 'REVIEW_DECISION'),
      verdict: v.status, invariants: v.invariants,
    };
  }

  return {
    COMPLETE, INCOMPLETE, FAILED, Ledger, ControlException, WorkerCrash,
    digest, hashEvent, verify, canon,
    detectPII, narrowDetector, classifyBoundary, narrowClassifier, scanPayloadPII,
    redactBeforeInference, allowRedactedOnly,
    makePolicyStore, retrieveCurrentPolicy, policyDigest, withinWindow,
    makeAuthorizer, buildEnvelope, invokeControlledTool, makeModelAdapter,
    executeRegulatedWorkflow, recordReviewDecision,
    reconstruct, phi, reconcile, planCoverage, orphanInvocations,
    adverseActionStatement, art12Record, by,
  };
}));
