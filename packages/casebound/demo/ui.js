/* Auditor console UI. All logic lives in engine.js / harness.js; this file only renders.
 *
 * Layout rule that drives the structure below: the controls sit above the pipeline, and only the
 * panel the auditor asked for is on screen at once. Everything else is one tab or one disclosure
 * away. A run always animates in view because Run is in a bar pinned above the pipeline.
 */
(function () {
  'use strict';
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));
  const esc = s => String(s == null ? '' : s)
    .replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const pct = (a, b) => (b ? Math.round(1000 * a / b) / 10 : 0);
  const REDUCED = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const DATA = JSON.parse($('#dataset').textContent);
  const ARCHIVE = 1000000;                    // simulated archived events, for the O(E_case) contrast
  const CLS = { COMPLETE: 'ok', FAILED: 'fail', INCOMPLETE: 'inc' };

  const state = {
    ledger: new CB.Ledger(DATA.meta.today + 'T14:00:00Z', ARCHIVE),
    store: KYC.buildStore(DATA, false),
    authorizerRef: { current: CB.makeAuthorizer(KYC.ALLOWED) },
    comparator: KYC.makeComparator(DATA),
    cases: [],
    selected: null,
    verdict: null,
    tab: 'verdict',
    caseFilter: '',
    packView: 'aa',
  };
  const literal = () => $('#literal').checked;

  /* ============================ controls ============================ */

  function fillApplicants() {
    const roles = DATA.roles || {};
    const suggested = ['borderline', 'clean', 'mismatch', 'single-channel']
      .map(k => [k, roles[k]]).filter(([, id]) => id);
    const opt = a => `<option value="${a.id}">${esc(a.id)} · ${esc(a.label)}</option>`;
    const byId = id => DATA.applicants.find(a => a.id === id);
    $('#applicant').innerHTML =
      `<optgroup label="Worth starting with">${suggested.map(([k, id]) => {
        const a = byId(id);
        return a ? `<option value="${a.id}">${esc(k)} — ${esc(a.label)}</option>` : '';
      }).join('')}</optgroup>`
      + `<optgroup label="All ${DATA.applicants.length} applicants">${DATA.applicants.map(opt).join('')}</optgroup>`;
    $('#applicant').value = DATA.meta.default_applicant || DATA.applicants[0].id;
  }

  function fillFaults() {
    const groups = {};
    KYC.FAULTS.forEach(([k, label, group, why]) => (groups[group] = groups[group] || []).push({ k, label, why }));
    $('#fault').innerHTML = '<option value="">None — clean run</option>'
      + Object.entries(groups).map(([g, items]) =>
        `<optgroup label="${esc(g)}">${items.map(i => `<option value="${i.k}">${esc(i.label)}</option>`).join('')}</optgroup>`
      ).join('');
  }

  const faultWhy = k => (KYC.FAULTS.find(f => f[0] === k) || [])[3];

  function renderFaultNote() {
    const a = DATA.applicants.find(x => x.id === $('#applicant').value);
    const f = $('#fault').value;
    const who = a
      ? `<b>${esc(a.doc.full_name)}</b> · score ${a.fixture.score} · ${a.fixture.channels} contact channel${a.fixture.channels > 1 ? 's' : ''}`
        + (a.fixture.id_match ? '' : ' · identity mismatch')
        + (KYC.admitted(a) ? '' : ' · <b>excluded at intake</b> (Section 7.3): no case is opened')
      : '';
    $('#faultNote').innerHTML = f ? `${who} — ${esc(faultWhy(f))}` : who;
  }

  /* ============================ pipeline ============================ */

  const STAGES = [
    ['intake', 'Intake', 'case id · C1'],
    ['redact', 'Redact', 'Alg 4 · C4'],
    ['policy', 'Policy', 'Alg 3 · C3'],
    ['plan', 'Plan', 'model call'],
    ['tools', 'Tools', 'Alg 2 · C2'],
    ['decide', 'Decide', 'model call'],
    ['gate', 'Gate', 'Alg 5 · C5'],
  ];
  $('#flow').innerHTML = STAGES.map(([id, name, sub], i) =>
    `<div class="stage" id="st-${id}" role="listitem"><b>${name}</b><small>${sub}</small></div>`
    + (i < STAGES.length - 1 ? '<span class="arrow" aria-hidden="true">→</span>' : '')
  ).join('');

  let animTimer = null;
  let lastRun = null;                          // {events, outcome} so Replay can re-run the animation

  function stageStates(events, outcome) {
    const map = {
      CASE_OPENED: 'intake', REDACTION_COMPLETED: 'redact', REDACTION_BOUNDARY_FAILED: 'redact',
      POLICY_RETRIEVED: 'policy', POLICY_PENDING_SUPERSEDED: 'policy', NO_CURRENT_POLICY: 'policy',
      TOOL_INVOKED: 'tools', TOOL_AUTHZ_DENIED: 'tools', DECISION_RECORDED: 'decide',
      ROUTED_TO_HUMAN_REVIEW: 'gate', DECISION_PERSISTED: 'gate',
    };
    const bad = { TOOL_AUTHZ_DENIED: 1, POLICY_PENDING_SUPERSEDED: 1, NO_CURRENT_POLICY: 1, REDACTION_BOUNDARY_FAILED: 1 };
    const seq = [];
    for (const e of events) {
      if (e.type === 'INFERENCE') {
        const cls = (!e.data.redaction_ev || (e.data.payload_pii || []).length) ? 'bad' : 'on';
        seq.push([e.data.purpose === 'plan' ? 'plan' : 'decide', cls]);
        seq.push(['model', cls]);
        continue;
      }
      const n = map[e.type];
      if (!n) continue;
      seq.push([n, bad[e.type] ? 'bad' : e.type === 'ROUTED_TO_HUMAN_REVIEW' ? 'warn' : 'on']);
    }
    if (outcome === 'CRASHED') seq.push(['tools', 'bad']);
    return seq;
  }

  function paint(id, cls) {
    const el = document.getElementById('st-' + id);
    if (el) el.className = 'stage' + (cls ? ' ' + cls : '');
  }

  function animate(events, outcome, opts) {
    clearTimeout(animTimer);
    lastRun = { events, outcome };
    STAGES.forEach(([id]) => paint(id, ''));
    paint('model', '');
    const seq = stageStates(events, outcome);
    if (REDUCED || (opts && opts.instant)) { seq.forEach(([n, c]) => paint(n, c)); return; }
    let i = 0;
    const tick = () => {
      if (i >= seq.length) return;
      const [n, c] = seq[i++];
      paint(n, c);
      animTimer = setTimeout(tick, 110);
    };
    tick();
  }

  function renderBoundary(events) {
    const red = events.find(e => e.type === 'REDACTION_COMPLETED');
    const inf = events.filter(e => e.type === 'INFERENCE');
    const leak = inf.find(e => (e.data.payload_pii || []).length);
    const none = inf.find(e => !e.data.redaction_ev);
    if (none) {
      $('#boundaryLog').innerHTML =
        '<span class="chip fail">unmediated</span> The raw record reached the model with no redaction evidence.';
      return;
    }
    if (!red) { $('#boundaryLog').innerHTML = ''; return; }
    const d = red.data;
    const shown = d.pii_fields.slice(0, 3).map(esc).join(', ');
    $('#boundaryLog').innerHTML =
      `<b>${d.fields_in}</b> fields on the record · <b>${d.pii_fields.length}</b> tokenized (${shown}${d.pii_fields.length > 3 ? ', …' : ''})`
      + ` · <b>${(d.dropped_fields || []).length}</b> free-text dropped · <b>${d.fields_out}</b> crossed the boundary`
      + (leak ? `<br><span class="chip fail">leak</span> The payload still carried PII in <b>${leak.data.payload_pii.map(esc).join(', ')}</b>.`
        + ' The runtime classifier allowed it (Assumption A3); line 6 caught it at audit.' : '');
  }

  /* ============================ running ============================ */

  function runOne(applicant, faultKey, quiet) {
    const faults = faultKey ? { [faultKey]: true } : {};
    if (faults.stale) state.store = KYC.buildStore(DATA, true);
    const r = KYC.runCase({
      ledger: state.ledger, data: DATA, applicant, faults, fix: $('#fix').checked,
      paperLiteral: literal(), authorizerRef: state.authorizerRef, store: state.store,
    });
    const v = CB.reconstruct(state.ledger, r.case_id, state.authorizerRef.current, state.store,
      state.comparator, { paperLiteral: literal() });
    state.cases.push({ ...r, applicant: applicant.id, label: applicant.label, status: v.status, fault: faultKey || '' });
    if (!quiet) {
      const events = state.ledger.fetchByCase(r.case_id);
      animate(events, r.outcome);
      renderBoundary(events);
      select(r.case_id);
    }
    return r;
  }

  function run() {
    const n = Number($('#runCount').value);
    const fault = $('#fault').value;
    if (n === 1) {
      const a = DATA.applicants.find(x => x.id === $('#applicant').value);
      if (!KYC.admitted(a)) { renderFaultNote(); return; }       // Section 7.3: never enters the pipeline
      runOne(a, fault, false);
      $('.stage-head').scrollIntoView({ behavior: REDUCED ? 'auto' : 'smooth', block: 'start' });
    } else {
      const pool = DATA.applicants.slice(0, n).filter(KYC.admitted);   // Section 7.3: intake exclusion
      pool.forEach(a => runOne(a, fault, true));
      const last = state.cases[state.cases.length - 1];
      const events = state.ledger.fetchByCase(last.case_id);
      animate(events, last.outcome, { instant: true });
      renderBoundary(events);
      select(last.case_id);
      showTab('portfolio');
    }
    refresh();
  }

  function select(caseId) {
    state.selected = caseId;
    state.verdict = caseId
      ? CB.reconstruct(state.ledger, caseId, state.authorizerRef.current, state.store,
        state.comparator, { paperLiteral: literal() })
      : null;
    renderVerdictStrip();
    renderActivePanel();
  }

  /* ============================ verdict strip ============================ */

  const MEANING = {
    COMPLETE: 'Φ(c) holds. All five invariants are satisfied and the decision is reconstructable from the case id alone.',
    FAILED: 'Chain integrity is broken, or an invariant is provably violated.',
    INCOMPLETE: 'Required evidence is missing. No violation is proven.',
  };

  function renderVerdictStrip() {
    const v = state.verdict;
    const box = $('#verdict');
    if (!v) {
      box.className = 'verdict idle';
      $('#vStatus').textContent = '—';
      $('#vBody').textContent = 'Choose an applicant and press Run.';
      $('#vMeta').textContent = '';
      return;
    }
    box.className = 'verdict ' + CLS[v.status];
    $('#vStatus').textContent = v.status;
    const routed = v.events.find(e => e.type === 'ROUTED_TO_HUMAN_REVIEW');
    $('#vBody').innerHTML = esc(MEANING[v.status])
      + (routed ? ` <span class="chip warn">human review</span> ${esc(routed.data.exception
        || 'the gate refused to certify this case')}` : '');
    $('#vMeta').innerHTML = `${esc(v.case_id)}<br>read ${v.read} of ${state.ledger.total.toLocaleString()} · ${v.ms.toFixed(1)} ms`;
    $('#stRead').textContent = `${v.read} of ${state.ledger.total.toLocaleString()}`;
  }

  /* ============================ panels ============================ */

  function renderVerdictPanel() {
    const v = state.verdict;
    if (!v) return '<p class="empty">No case selected.</p>';
    const div = v.divergence ? `<div class="finding fail" style="margin-bottom:14px">
      <span class="chip fail">Proposition 1</span>
      <div><b>Recorded decision diverges from the applied policy</b>
      <div class="finding-note">The chain records <b>${esc(v.divergence.recorded.decision)}</b> on
      [${v.divergence.recorded.factors.map(esc).join(', ')}], but the policy version cited in the chain entails
      <b>${esc(v.divergence.policy_grounded.decision)}</b> on [${v.divergence.policy_grounded.factors.map(esc).join(', ')}].
      The gate still returns COMPLETE: the injection is detected at audit, not prevented.</div></div></div>` : '';

    const checks = `<div class="checks">${v.checks.map(c => `<div class="check">
      <span class="ln">line ${c.line}</span>
      <span><span class="chip ${c.passed ? 'ok' : 'fail'}">${c.passed ? 'pass' : 'fail'}</span></span>
      <span class="check-main"><span class="check-name"><b>${esc(c.invariant)}</b> ${esc(c.name)}</span>
      <span class="check-note">${esc(c.note)}</span></span></div>`).join('')}</div>`;

    const recs = CB.reconcile(state.ledger, v);
    const items = v.findings.map(f =>
      `<div class="finding ${esc(f.severity)}"><span class="chip ${f.severity === 'info' ? 'info' : f.severity === 'warn' ? 'warn' : 'fail'}">${esc(f.severity)}</span>
      <div><b>${esc(f.kind.replace(/_/g, ' '))}</b><div class="finding-note">${esc(f.note)}</div></div></div>`)
      .concat(recs.map(f =>
        `<div class="finding ${f.explains_uncovered_step ? 'fail' : 'warn'}"><span class="chip ${f.explains_uncovered_step ? 'fail' : 'warn'}">reconcile</span>
        <div><b>${esc(f.type)} ${esc(f.tool)}</b><div class="finding-note">${esc(f.note)}</div></div></div>`));
    const findings = items.length
      ? `<p class="eyebrow" style="margin:18px 0 8px">Findings · these do not change the verdict</p>
         <div class="findings">${items.join('')}</div>` : '';

    const review = v.status === 'COMPLETE' ? '' : `
      <p class="eyebrow" style="margin:18px 0 8px">Close this case</p>
      <p class="panel-intro">Recording a disposition appends a <code>REVIEW_DECISION</code> event to the chain. It does
      not make the case COMPLETE: a human decision cannot retroactively satisfy an invariant the execution violated.</p>
      <div class="bar-inner" style="padding:0;gap:10px">
        <div class="field"><label for="reviewer">Reviewer</label><input type="text" id="reviewer" placeholder="your name"></div>
        <div class="field"><label for="reviewOutcome">Disposition</label><select id="reviewOutcome">
          <option>APPROVED_AFTER_REVIEW</option><option>DECLINED_AFTER_REVIEW</option><option>ESCALATED</option></select></div>
        <div class="field"><label for="reviewNote">Rationale</label><input type="text" id="reviewNote" placeholder="what you checked"></div>
        <button id="doReview" type="button">Record</button>
      </div>`;

    return `<p class="panel-intro">Algorithm 5 line by line, for case <span class="mono-note">${esc(v.case_id)}</span>
      in <b>${esc(v.mode)}</b> mode.</p>${div}${checks}${findings}${review}`;
  }

  function renderChainPanel() {
    const v = state.verdict;
    if (!v) return '<p class="empty">No case selected.</p>';
    const rows = v.events.map(e => {
      const t = e.type, d = e.data;
      const cls = /DENIED|FAILED|VIOLATION|PENDING|NO_CURRENT/.test(t) ? 'bad'
        : t === 'ROUTED_TO_HUMAN_REVIEW' || t === 'REVIEW_DECISION' ? 'hi'
          : (t === 'INFERENCE' && (!d.redaction_ev || (d.payload_pii || []).length)) ? 'bad' : '';
      const detail =
        t === 'CASE_OPENED' ? `${d.workflow} · ${d.jurisdiction}`
          : t === 'POLICY_RETRIEVED' ? `${d.policy_ref} · effective ${d.effective_from} → ${d.effective_to || 'open'}`
            : t === 'TOOL_INVOKED' ? `${d.tool} · attempt ${d.attempt} · idem ${String(d.idempotency_key).slice(0, 8)}`
              : t === 'TOOL_COMPLETED' ? `${d.tool} → ${JSON.stringify(d.response)}`
                : t === 'INFERENCE' ? `${d.purpose} · redaction ${d.redaction_ev || 'none'}`
                  + ((d.payload_pii || []).length ? ` · LEAKED ${d.payload_pii.join(', ')}` : '')
                  + (d.plan_steps ? ` · plan [${d.plan_steps.join(', ')}]` : '')
                  : t === 'REDACTION_COMPLETED' ? `${d.pii_fields.length} field(s) tokenized · ${d.boundary_class}`
                    : t === 'DECISION_RECORDED' ? `${d.decision} · ${d.factors.join(', ')}`
                      : t === 'ROUTED_TO_HUMAN_REVIEW' ? `${d.reason}${d.exception ? ' · ' + d.exception : ''}`
                        : t === 'POLICY_PENDING_SUPERSEDED' ? `${d.incumbent} superseded by delivered ${d.successor}`
                          : t === 'TOOL_AUTHZ_DENIED' ? `${d.tool} · not in the allowed set for ${d.agent_role}`
                            : t === 'REVIEW_DECISION' ? `${d.reviewer} → ${d.outcome}${d.rationale ? ' · ' + d.rationale : ''}`
                              : t === 'DECISION_PERSISTED' ? d.decision : '';
      return `<tr class="${cls}"><td class="num">${e.seq}</td><td class="m">${esc(t)}</td>
        <td class="m">${esc(detail)}</td><td class="m">${esc(e.hash)}</td></tr>`;
    }).join('');
    const untagged = state.ledger.untagged();
    return `<p class="panel-intro">The whole basis for the decision, fetched by case id alone.
      Reconstruction read <b>${v.read}</b> events out of ${state.ledger.total.toLocaleString()} in the ledger.</p>
      <div class="tablewrap tall"><table><thead><tr><th>seq</th><th>event</th><th>detail</th><th>hash</th></tr></thead>
      <tbody>${rows}${untagged.length ? `<tr class="dim"><td>—</td><td class="m">UNTAGGED ×${untagged.length}</td>
      <td class="m">in the ledger but invisible to a case-indexed fetch; reachable only by reconciliation</td>
      <td class="m">${esc(untagged[0].hash)}</td></tr>` : ''}</tbody></table></div>`;
  }

  function renderPackPanel() {
    const v = state.verdict;
    if (!v) return '<p class="empty">No case selected.</p>';
    const sel = `<div class="field" style="max-width:280px;margin-bottom:14px">
      <label for="packView">View</label><select id="packView">
        <option value="aa"${state.packView === 'aa' ? ' selected' : ''}>Adverse-action notice</option>
        <option value="art"${state.packView === 'art' ? ' selected' : ''}>EU AI Act Article 12 record</option>
        <option value="json"${state.packView === 'json' ? ' selected' : ''}>Raw JSON</option>
      </select></div>`;
    let body = '';
    if (state.packView === 'aa') {
      const aa = CB.adverseActionStatement(v, f => KYC.reasonText(DATA, f));
      body = aa.issuable
        ? `<div class="finding info" style="border-left-color:var(--acc)"><span class="chip ok">issuable</span><div>
           <b>Statement of specific reasons</b> <span class="mono-note">Reg B §1002.9(b)(2)</span>
           <div class="finding-note">Case ${esc(v.case_id)} · ${aa.action === 'REJECT' ? 'declined' : 'referred for additional verification'} · ${DATA.meta.today}</div>
           <ol style="margin:9px 0 6px 18px;padding:0;font-size:13px">${aa.principal_reasons.map(r => `<li style="margin-bottom:4px">${esc(r)}</li>`).join('')}</ol>
           <div class="finding-note">Reasons reproduced from DECISION_RECORDED at seq ${aa.basis.decision_event};
           policy basis ${esc(aa.basis.policy_ref)}; tool evidence at seq ${aa.basis.tool_events.join(', ')}.</div></div></div>`
        : `<div class="finding warn"><span class="chip warn">withheld</span><div><b>No notice may issue</b>
           <div class="finding-note">${esc(aa.why)}</div></div></div>`;
    } else if (state.packView === 'art') {
      const a = CB.art12Record(v, 'kyc_onboarding');
      body = `<div class="tablewrap"><table><tbody>${[
        ['System', 'kyc_onboarding agent · Annex III 5(b) creditworthiness context'],
        ['Case and period', `${esc(v.case_id)}<br><span class="mono-note">${a.period ? a.period.map(p => p.replace('T', ' ').slice(0, 19)).join(' → ') : '–'}</span>`],
        ['Events logged', `${a.events_logged} · automatic, append-only, hash-chained`],
        ['Policy versions', a.policy_versions.join(', ') || 'none'],
        ['Crossing the inference boundary', a.inference_boundary.join('; ') || 'none'],
        ['Tools invoked', a.tools.join(', ') || 'none'],
        ['Human oversight · Art. 14', a.human_oversight ? 'routed to the human review queue' : 'straight through; halt path available via the gate'],
        ['Review closed', a.human_review_closed ? 'yes, recorded in the chain' : 'no'],
        ['Retention · Art. 26(6)', 'ledger retained per the policy retention period'],
        ['Verdict', a.verdict],
      ].map(([k, val]) => `<tr><td class="m" style="width:38%">${k}</td><td>${val}</td></tr>`).join('')}</tbody></table></div>`;
    } else {
      body = `<pre>${esc(JSON.stringify({
        case_id: v.case_id, verdict: v.status, mode: v.mode, invariants: v.invariants,
        checks: v.checks, findings: v.findings, divergence: v.divergence, events: v.events,
      }, null, 1))}</pre>`;
    }
    return `<p class="panel-intro">Regulator-shaped views over the same chain. Templates, not legal advice.</p>${sel}${body}`;
  }

  function renderCasesPanel() {
    const rows = state.cases.filter(c =>
      !state.caseFilter || (state.caseFilter === 'review' ? c.status !== 'COMPLETE' : c.status === state.caseFilter));
    const body = rows.length ? rows.slice().reverse().map(c => {
      const closed = state.ledger.fetchByCase(c.case_id).find(e => e.type === 'REVIEW_DECISION');
      return `<tr data-c="${esc(c.case_id)}" class="${c.case_id === state.selected ? 'sel' : ''}">
        <td class="m">${esc(c.case_id)}</td><td>${esc(c.label)}</td><td class="m">${esc(c.outcome)}</td>
        <td><span class="chip ${c.status === 'COMPLETE' ? 'ok' : c.status === 'FAILED' ? 'fail' : 'warn'}">${esc(c.status)}</span></td>
        <td class="m">${esc(c.fault || '—')}</td>
        <td class="m">${closed ? esc(closed.data.outcome) : c.status === 'COMPLETE' ? '—' : '<span class="chip warn">open</span>'}</td></tr>`;
    }).join('') : '<tr><td colspan="6" class="empty">No cases match this filter.</td></tr>';
    return `<div class="field" style="max-width:260px;margin-bottom:14px">
        <label for="caseFilter">Filter</label><select id="caseFilter">
          <option value=""${state.caseFilter === '' ? ' selected' : ''}>All cases (${state.cases.length})</option>
          <option value="review"${state.caseFilter === 'review' ? ' selected' : ''}>Needs human review</option>
          <option value="COMPLETE"${state.caseFilter === 'COMPLETE' ? ' selected' : ''}>COMPLETE</option>
          <option value="INCOMPLETE"${state.caseFilter === 'INCOMPLETE' ? ' selected' : ''}>INCOMPLETE</option>
          <option value="FAILED"${state.caseFilter === 'FAILED' ? ' selected' : ''}>FAILED</option>
        </select></div>
      <div class="tablewrap tall"><table><thead><tr><th>case</th><th>applicant</th><th>outcome</th>
        <th>verdict</th><th>fault</th><th>review</th></tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function renderPolicyPanel() {
    const today = DATA.meta.today;
    const feed = state.store.feed.filter(p => p.policy_id === KYC.POLICY).slice().sort((a, b) => a.version - b.version);
    const inIndex = v => state.store.index.some(x => x.policy_id === v.policy_id && x.version === v.version);
    const rows = feed.map(v => {
      const live = v.state === 'APPROVED' && CB.withinWindow(today, v.effective_from, v.effective_to);
      return `<tr class="${v.state === 'DELIVERED' ? 'hi' : ''}"><td class="m">v${v.version}</td>
        <td><span class="chip ${v.state === 'APPROVED' ? 'ok' : 'warn'}">${esc(v.state)}</span></td>
        <td class="m">${esc(v.effective_from)} → ${esc(v.effective_to || 'open')}</td>
        <td class="m num">${v.body.stepup_threshold}</td>
        <td class="m">${inIndex(v) ? 'served' : '—'}${live ? ' · in force' : ''}</td></tr>`;
    }).join('');

    const served = state.store.query(KYC.WORKFLOW, 'US')
      .filter(v => CB.withinWindow(today, v.effective_from, v.effective_to))
      .reduce((a, b) => (!a || b.version > a.version ? b : a), null);
    const pending = state.store.feed.find(v => v.policy_id === KYC.POLICY && v.state !== 'APPROVED'
      && served && v.version > served.version && v.effective_from <= today);
    // The index is a snapshot, so the retirement date only exists on the feed. That gap is the point.
    const feedRow = served && state.store.feed.find(v => v.policy_id === served.policy_id && v.version === served.version);
    const retiredOn = feedRow && feedRow.effective_to;
    const note = !served
      ? `<div class="finding fail"><span class="chip fail">no policy</span><div><b>Nothing approved is effective today</b>
         <div class="finding-note">Algorithm 3 raises NoCurrentPolicyError and every case routes to review.</div></div></div>`
      : pending
        ? `<div class="finding warn"><span class="chip warn">Section 7.1</span><div><b>The stale-policy window is open</b>
           <div class="finding-note">The retrieval index serves <b>v${served.version}</b>, which the compliance feed retired on
           ${esc(retiredOn || 'an earlier date')}. Delivered <b>v${pending.version}</b> is effective from ${esc(pending.effective_from)}
           but has not been signed off, so the index was never re-ingested. Turn on <b>Policy fix</b> to make Algorithm 3
           consult the feed and route these cases to review instead.</div></div></div>`
        : `<div class="finding info" style="border-left-color:var(--acc)"><span class="chip ok">in sync</span><div>
           <b>Index and feed agree</b><div class="finding-note">Algorithm 3 serves ${esc(served.policy_id)}@v${served.version},
           step-up threshold ${served.body.stepup_threshold}.</div></div></div>`;

    return `<p class="panel-intro">The retrieval index is a snapshot taken at sign-off. The compliance feed is the source of
      truth for effective dating. Section 7.1 is the window where the two disagree.</p>
      <div class="tablewrap"><table><thead><tr><th>version</th><th>state</th><th>effective</th>
        <th>step-up</th><th>index</th></tr></thead><tbody>${rows}</tbody></table></div>
      <div class="findings" style="margin-top:14px">${note}</div>
      <div class="bar-inner" style="padding:14px 0 0;gap:8px">
        <button class="ghost" id="pDeliver" type="button">Deliver v15</button>
        <button class="ghost" id="pApprove" type="button">Approve v15 and re-ingest</button>
        <button class="ghost" id="pReset" type="button">Reset corpus</button>
      </div>`;
  }

  function bars(title, rows, total, note) {
    return `<p class="eyebrow" style="margin:18px 0 9px">${esc(title)}</p>
      <div class="bars">${rows.map(([label, n, color]) => `<div class="bar-row">
        <span>${esc(label)}</span>
        <span class="bar-track"><span class="bar-fill" style="width:${total ? 100 * n / total : 0}%;background:${color}"></span></span>
        <span class="bar-num">${n} · ${pct(n, total)}%</span></div>`).join('')}</div>
      ${note ? `<p class="figcap">${note}</p>` : ''}`;
  }

  function histogram(threshold) {
    const lo = 500, hi = 860, buckets = 18, w = (hi - lo) / buckets;
    const counts = new Array(buckets).fill(0);
    DATA.applicants.forEach(a => {
      counts[Math.min(buckets - 1, Math.max(0, Math.floor((a.fixture.score - lo) / w)))]++;
    });
    const max = Math.max(...counts), H = 96, W = 560, TOP = 28, bw = W / buckets, L = 30;
    const x = v => (v - lo) / (hi - lo) * W;
    return `<figure class="figure"><p class="eyebrow" style="margin:18px 0 9px">Credit scores and the applied threshold</p>
      <svg viewBox="0 0 ${W + L + 16} ${H + TOP + 34}" role="img"
        aria-label="Histogram of synthetic credit scores. The step-up threshold is ${threshold}; applicants below it are referred.">
        ${counts.map((c, i) => {
      const h = max ? H * c / max : 0;
      const mid = lo + i * w + w / 2;
      return `<rect x="${L + i * bw + 1}" y="${TOP + H - h}" width="${bw - 2}" height="${h}" rx="2"
          fill="var(--acc)" opacity="${mid < threshold ? 0.4 : 0.88}"><title>${Math.round(lo + i * w)}–${Math.round(lo + i * w + w)}: ${c} applicant(s)</title></rect>`;
    }).join('')}
        <line x1="${L}" y1="${TOP + H}" x2="${L + W}" y2="${TOP + H}" stroke="var(--line2)"/>
        <line x1="${L + x(threshold)}" y1="${TOP - 10}" x2="${L + x(threshold)}" y2="${TOP + H}"
          stroke="var(--warn)" stroke-width="1.5" stroke-dasharray="4 3"/>
        <text x="${L + x(threshold)}" y="${TOP - 15}" text-anchor="middle" font-size="11"
          font-family="IBM Plex Mono, monospace" fill="var(--warn)">step-up ${threshold}</text>
        ${[500, 600, 700, 800].map(t => `<text x="${L + x(t)}" y="${TOP + H + 18}" text-anchor="middle" font-size="10.5"
          font-family="IBM Plex Mono, monospace" fill="var(--ink3)">${t}</text>`).join('')}
        <text x="${L}" y="${TOP + H + 32}" font-size="10.5" font-family="IBM Plex Mono, monospace" fill="var(--ink3)">applicants per 20-point band</text>
      </svg>
      <figcaption class="figcap">Faded bars fall below the threshold and are referred for step-up verification.</figcaption></figure>`;
  }

  function renderPortfolioPanel() {
    if (!state.cases.length) return '<p class="empty">Run a batch to populate portfolio metrics.</p>';
    const n = state.cases.length;
    const count = k => state.cases.filter(k).length;
    const outcomes = [
      ['Passed straight through', count(c => c.outcome === 'PASS'), 'var(--ok)'],
      ['Referred for step-up', count(c => c.outcome === 'REFER'), 'var(--warn)'],
      ['Rejected', count(c => c.outcome === 'REJECT'), 'var(--fail)'],
      ['Sent to human review', count(c => c.outcome === 'HUMAN_REVIEW'), 'var(--info)'],
      ['Crashed', count(c => c.outcome === 'CRASHED'), 'var(--ink3)'],
    ].filter(r => r[1]);
    const verdicts = [
      ['COMPLETE', count(c => c.status === 'COMPLETE'), 'var(--ok)'],
      ['INCOMPLETE', count(c => c.status === 'INCOMPLETE'), 'var(--warn)'],
      ['FAILED', count(c => c.status === 'FAILED'), 'var(--fail)'],
    ].filter(r => r[1]);
    const pol = state.store.index.filter(p => p.policy_id === KYC.POLICY)
      .reduce((a, b) => (!a || b.version > a.version ? b : a), null);
    const singles = DATA.applicants.filter(a => !KYC.admitted(a)).length;

    return `<p class="panel-intro">${n} case(s) run against
      <b>${esc(pol ? pol.policy_id + '@v' + pol.version : 'no policy')}</b>. Applicants with a single contact channel are
      excluded at intake and never become cases (Section 7.3). The population is synthetic and its parameters are
      illustrative, so these shares are not evidence for the manuscript's reported figures.</p>
      <div class="split"><div>
        ${bars('Outcome mix', outcomes, n)}
        ${bars('Gate verdicts', verdicts, n, 'Every non-COMPLETE verdict routes to human review rather than yielding a silent adverse action (Theorem 1).')}
      </div><div>
        ${histogram(pol ? pol.body.stepup_threshold : 700)}
        <p class="eyebrow" style="margin:18px 0 9px">Population</p>
        <dl class="kv">
          <dt>applicants</dt><dd>${DATA.applicants.length}, generated from seed ${DATA.meta.seed}</dd>
          <dt>excluded at intake</dt><dd>${singles} · ${pct(singles, DATA.applicants.length)}% — one contact channel (Section 7.3)</dd>
          <dt>ledger</dt><dd>${state.ledger.count().toLocaleString()} live events, ${ARCHIVE.toLocaleString()} archived</dd>
          <dt>audit cost</dt><dd>one case reads only its own events, whatever the ledger holds</dd>
        </dl></div></div>`;
  }

  const RENDER = {
    verdict: renderVerdictPanel, chain: renderChainPanel, pack: renderPackPanel,
    cases: renderCasesPanel, policy: renderPolicyPanel, portfolio: renderPortfolioPanel,
  };

  function renderActivePanel() {
    $('#p-' + state.tab).innerHTML = RENDER[state.tab]();
    wirePanel();
  }

  function wirePanel() {
    const on = (sel, ev, fn) => { const el = $(sel); if (el) el[ev] = fn; };
    on('#doReview', 'onclick', () => {
      CB.recordReviewDecision(state.ledger, state.selected,
        'reviewer:' + ($('#reviewer').value.trim() || 'unassigned'),
        $('#reviewOutcome').value, $('#reviewNote').value.trim());
      select(state.selected); refresh();
    });
    on('#packView', 'onchange', e => { state.packView = e.target.value; renderActivePanel(); });
    on('#caseFilter', 'onchange', e => { state.caseFilter = e.target.value; renderActivePanel(); });
    on('#pDeliver', 'onclick', () => { state.store = KYC.buildStore(DATA, true); refresh(); renderActivePanel(); });
    on('#pApprove', 'onclick', () => { state.store.approve(KYC.POLICY, 15); state.store.ingest(); refresh(); renderActivePanel(); });
    on('#pReset', 'onclick', () => { state.store = KYC.buildStore(DATA, false); refresh(); renderActivePanel(); });
    $$('#p-cases tbody tr[data-c]').forEach(tr => { tr.onclick = () => { select(tr.dataset.c); showTab('verdict'); }; });
  }

  /* ============================ tabs ============================ */

  const TABS = ['verdict', 'chain', 'pack', 'cases', 'policy', 'portfolio'];

  function showTab(name) {
    state.tab = name;
    TABS.forEach(t => {
      const btn = $('#tab-' + t), panel = $('#p-' + t);
      const on = t === name;
      btn.setAttribute('aria-selected', String(on));
      btn.tabIndex = on ? 0 : -1;
      panel.hidden = !on;
    });
    renderActivePanel();
  }
  $('#tabs').addEventListener('click', e => {
    const btn = e.target.closest('button[role=tab]');
    if (btn) showTab(btn.id.replace('tab-', ''));
  });
  $('#tabs').addEventListener('keydown', e => {
    const i = TABS.indexOf(state.tab);
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End') return;
    e.preventDefault();
    const next = e.key === 'Home' ? 0 : e.key === 'End' ? TABS.length - 1
      : (i + (e.key === 'ArrowRight' ? 1 : TABS.length - 1)) % TABS.length;
    showTab(TABS[next]);
    $('#tab-' + TABS[next]).focus();
  });

  /* ============================ wiring ============================ */

  function refresh() {
    $('#stTotal').textContent = state.ledger.total.toLocaleString();
    $('#stCases').textContent = state.cases.length;
    $('#stMode').textContent = literal() ? 'paper-literal' : 'extended';
  }

  $('#applicant').onchange = renderFaultNote;
  $('#fault').onchange = renderFaultNote;
  $('#run').onclick = run;
  $('#replay').onclick = () => { if (lastRun) animate(lastRun.events, lastRun.outcome); };
  $('#literal').onchange = () => { if (state.selected) select(state.selected); refresh(); };
  $('#fix').onchange = () => {};
  $('#reset').onclick = () => {
    clearTimeout(animTimer);
    state.ledger.reset(); state.cases = []; state.selected = null; state.verdict = null; lastRun = null;
    state.store = KYC.buildStore(DATA, false);
    state.authorizerRef.current = CB.makeAuthorizer(KYC.ALLOWED);
    $('#fault').value = ''; $('#runCount').value = '1';
    $('#boundaryLog').innerHTML = '';
    STAGES.forEach(([id]) => paint(id, '')); paint('model', '');
    $('#stRead').textContent = '–';
    renderFaultNote(); renderVerdictStrip(); refresh(); showTab('verdict');
  };

  /* Open in a working state: one clean case already run, so the console shows what it does
     rather than an empty shell. The animation is skipped for this one. */
  fillApplicants();
  fillFaults();
  renderFaultNote();
  refresh();
  const first = runOne(DATA.applicants.find(a => a.id === $('#applicant').value), '', true);
  const firstEvents = state.ledger.fetchByCase(first.case_id);
  animate(firstEvents, first.outcome, { instant: true });
  renderBoundary(firstEvents);
  select(first.case_id);
  refresh();
}());
