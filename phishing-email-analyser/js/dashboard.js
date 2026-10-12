/*
 * dashboard.js — personal stats plus a business/team awareness dashboard.
 *
 * How the team dashboard works without a server:
 *   1. Each person clicks "Export my summary". This creates a small JSON file containing
 *      only scores (no emails, no answers in detail).
 *   2. They send that file to their manager or security lead however they normally share files.
 *   3. The manager imports the files here. Everything is combined inside their browser.
 */
(function () {
  'use strict';
  const P = window.PEA;
  const { h } = P;
  const $ = id => document.getElementById(id);
  const LEVELS = ['Low', 'Medium', 'High', 'Critical'];
  const pct = v => v == null ? '—' : Math.round(v * 100) + '%';
  const avg = a => a.length ? a.reduce((s, x) => s + x, 0) / a.length : null;

  function bars(rows, opts) {
    // rows: [{name, value (0..1 or count), label, cls}]
    opts = opts || {};
    const max = opts.max || Math.max(1, ...rows.map(r => r.value));
    if (!rows.length) return h('p', { class: 'empty' }, opts.empty || 'No data yet.');
    return h('div', { class: 'bars', role: 'list' }, rows.map(r => {
      const fill = h('div', { class: 'bar-fill ' + (r.cls || '') });
      fill.style.width = Math.max(0, Math.min(100, (r.value / max) * 100)) + '%';
      return h('div', { class: 'bar-row', role: 'listitem', title: `${r.name}: ${r.label}` },
        h('span', { class: 'name' }, r.name), h('div', { class: 'bar-track' }, fill), h('span', { class: 'v' }, r.label));
    }));
  }

  function summaryJson() {
    const s = P.store.get();
    const aw = P.awareness();
    const hist = s.history;
    return {
      type: 'pea-summary', version: 1, exportedAt: new Date().toISOString(),
      alias: s.profile.alias || 'Anonymous', dept: s.profile.dept || 'Unassigned',
      score: aw.score, accuracy: aw.accuracy, flagAccuracy: aw.flagAcc, trainingDone: aw.done, trainingTotal: aw.total,
      skills: aw.skillPct, analyses: hist.length, highRiskShare: hist.length ? hist.filter(x => x.level === 'High' || x.level === 'Critical').length / hist.length : null
    };
  }

  const bounded = (v,min,max) => typeof v==='number' && Number.isFinite(v) && v>=min && v<=max;
  function valid(o) {
    return o && !Array.isArray(o) && o.type === 'pea-summary' && o.version === 1 &&
      typeof o.alias === 'string' && o.alias.length <= 256 &&
      (o.score === null || bounded(o.score,0,100)) &&
      o.skills && typeof o.skills === 'object' && !Array.isArray(o.skills) &&
      (!o.accuracy || bounded(o.accuracy,0,1)) &&
      (!o.flagAccuracy || bounded(o.flagAccuracy,0,1)) &&
      Object.keys(P.SKILLS).every(k => o.skills[k]==null || bounded(o.skills[k],0,1)) &&
      (!o.trainingDone || bounded(o.trainingDone,0,9)) &&
      (!o.trainingTotal || bounded(o.trainingTotal,1,9)) &&
      (!o.analyses || bounded(o.analyses,0,100000));
  }
  function addTeam(list, sample) {
    let added = 0;
    P.store.update(s => {
      for (const o of list.slice(0, 100)) {
        if (!valid(o)) continue;
        const clean = { alias: String(o.alias).slice(0, 60), dept: String(o.dept || 'Unassigned').slice(0, 60), score: o.score, accuracy: o.accuracy, flagAccuracy: o.flagAccuracy, trainingDone: +o.trainingDone || 0, trainingTotal: +o.trainingTotal || 9, skills: {}, analyses: +o.analyses || 0, sample: !!sample, exportedAt: o.exportedAt };
        for (const k of Object.keys(P.SKILLS)) clean.skills[k] = typeof o.skills[k] === 'number' ? Math.max(0, Math.min(1, o.skills[k])) : null;
        s.team = s.team.filter(t => !(t.alias === clean.alias && t.dept === clean.dept));
        s.team.push(clean); added++;
      }
    });
    return added;
  }

  function sampleTeam() {
    const people = [['A. Novak', 'Finance', 48], ['B. Osei', 'Finance', 62], ['C. Laurent', 'Finance', 55], ['D. Kim', 'Engineering', 88], ['E. Silva', 'Engineering', 79], ['F. Müller', 'Engineering', 91], ['G. Haddad', 'Sales', 58], ['H. Ivanova', 'Sales', 44], ['I. Mensah', 'Sales', 67], ['J. Rossi', 'HR', 71], ['K. Tanaka', 'HR', 63], ['L. Byrne', 'Operations', 52]];
    const keys = Object.keys(P.SKILLS);
    let seed = 7; const rnd = () => (seed = (seed * 9301 + 49297) % 233280) / 233280;
    return people.map(([alias, dept, score]) => {
      const skills = {};
      for (const k of keys) { const bias = k === 'money' && dept === 'Finance' ? -0.25 : k === 'vishing' ? -0.15 : k === 'headers' ? -0.1 : 0; skills[k] = Math.max(0.1, Math.min(1, score / 100 + bias + (rnd() - 0.5) * 0.3)); }
      return { type: 'pea-summary', version: 1, alias: alias + ' (example)', dept, score, accuracy: Math.min(1, score / 100 + 0.08), flagAccuracy: score / 110, trainingDone: Math.round((score / 100) * 9 * rnd() + 1), trainingTotal: 9, skills, analyses: Math.round(rnd() * 20) };
    });
  }

  function render() {
    const s = P.store.get();
    const hist = s.history;
    const aw = P.awareness();
    const area = $('dashboard-area');

    // ── Personal ──
    const levelCounts = LEVELS.map(l => hist.filter(x => x.level === l).length);
    const signCounts = {};
    for (const x of hist) for (const t of (x.titles || x.ids || [])) signCounts[t] = (signCounts[t] || 0) + 1;
    const topSigns = Object.entries(signCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const hr = hist.filter(x => x.level === 'High' || x.level === 'Critical').length;

    const personal = h('section', { class: 'dash' },
      h('h3', { class: 'section-title' }, 'You'),
      h('div', { class: 'kpis' },
        P.kpi('Awareness score', aw.score ?? '—', P.grade(aw.score)),
        P.kpi('Messages analysed', hist.length, hist.length ? `last on ${new Date(hist[hist.length - 1].t).toLocaleDateString()}` : 'none yet'),
        P.kpi('Average risk', hist.length ? Math.round(avg(hist.map(x => x.score))) : '—', 'out of 100'),
        P.kpi('High or critical', hist.length ? pct(hr / hist.length) : '—', `${hr} message${hr === 1 ? '' : 's'}`),
        P.kpi('Training', `${aw.done}/${aw.total}`, 'lessons complete')),
      h('div', { class: 'dash-grid' },
        h('div', { class: 'card' }, h('h3', {}, 'Risk levels of analysed messages'),
          bars(hist.length ? LEVELS.map((l, i) => ({ name: l, value: levelCounts[i], label: String(levelCounts[i]), cls: 's-' + l })) : [], { empty: 'Analyse a message (with the dashboard box ticked) to see this.' })),
        h('div', { class: 'card' }, h('h3', {}, 'Most frequent warning signs'),
          bars(topSigns.map(([n, c]) => ({ name: n, value: c, label: String(c) })), { empty: 'No warning signs recorded yet.' })),
        h('div', { class: 'card' }, h('h3', {}, 'Your proficiency by topic'),
          bars(Object.keys(P.SKILLS).filter(k => aw.skillPct[k] != null).map(k => ({ name: P.SKILLS[k].name, value: aw.skillPct[k], label: pct(aw.skillPct[k]) })).sort((a, b) => a.value - b.value), { max: 1, empty: 'Take the Challenge to measure this.' }))));

    // ── Team / business ──
    const team = s.team;
    const scored = team.filter(t => typeof t.score === 'number');
    const depts = [...new Set(team.map(t => t.dept))];
    const orgSkill = Object.keys(P.SKILLS).map(k => ({ k, v: avg(team.map(t => t.skills[k]).filter(v => typeof v === 'number')) })).filter(x => x.v != null).sort((a, b) => a.v - b.v);
    const atRisk = scored.filter(t => t.score < 50).length;
    const hasSample = team.some(t => t.sample);

    const alias = h('input', { type: 'text', id: 'profile-alias', value: s.profile.alias, placeholder: 'e.g. Nana or an employee ID', maxlength: 60 });
    const dept = h('input', { type: 'text', id: 'profile-dept', value: s.profile.dept, placeholder: 'e.g. Finance', maxlength: 60 });
    const saveProfile = () => P.store.update(st => { st.profile.alias = alias.value.trim(); st.profile.dept = dept.value.trim(); });
    alias.addEventListener('change', saveProfile); dept.addEventListener('change', saveProfile);

    const fileIn = h('input', { type: 'file', id: 'team-files', accept: '.json,application/json', multiple: true, class: 'visually-hidden' });
    fileIn.addEventListener('change', async () => {
      let added = 0, bad = 0;
      for (const f of Array.from(fileIn.files).slice(0, 100)) {
        if (f.size > 1024 * 1024) { bad++; continue; }
        try { const o = JSON.parse(await f.text()); const n = addTeam(Array.isArray(o) ? o : [o]); added += n; if (!n) bad++; } catch (e) { bad++; }
      }
      P.toast(`Imported ${added} result${added === 1 ? '' : 's'}${bad ? `, ${bad} file(s) not recognised` : ''}`);
      render();
    });
    const paste = h('textarea', { id: 'team-paste', rows: 3, placeholder: 'Or paste an exported summary here', class: 'chip', spellcheck: 'false' });
    paste.style.width = '100%';

    const teamSection = h('section', { class: 'dash' },
      h('h3', { class: 'section-title' }, 'Team & business view'),
      h('div', { class: 'card' },
        h('h3', {}, 'Share your results'),
        h('p', { class: 'sub' }, 'Exports scores only: no messages, no individual answers. Use an alias if you prefer.'),
        h('div', { class: 'form-row' },
          h('label', { for: 'profile-alias' }, 'Name or alias', alias),
          h('label', { for: 'profile-dept' }, 'Department', dept),
          h('button', { type: 'button', class: 'btn', onclick: () => { saveProfile(); P.download('awareness-summary.json', JSON.stringify(summaryJson(), null, 2)); } }, 'Export my summary'),
          h('button', { type: 'button', class: 'btn ghost', onclick: () => { saveProfile(); P.copyText(JSON.stringify(summaryJson()), 'Summary'); } }, 'Copy'))),
      h('div', { class: 'card' },
        h('h3', {}, 'Combine team results'),
        h('p', { class: 'sub' }, 'Load summary files from colleagues. They are read on this computer and never uploaded.'),
        h('div', { class: 'row' },
          fileIn, h('label', { for: 'team-files', class: 'btn' }, 'Import summary files'),
          h('button', { type: 'button', class: 'btn ghost', onclick: () => { addTeam(sampleTeam(), true); render(); } }, 'Load example team'),
          team.length ? h('button', { type: 'button', class: 'btn danger small', onclick: () => { P.store.update(st => { st.team = []; }); render(); } }, 'Clear team data') : null),
        paste,
        h('div', { class: 'row' }, h('button', { type: 'button', class: 'btn small', onclick: () => { try { if (paste.value.length > 1024 * 1024) throw new Error('Summary exceeds size limit'); const o = JSON.parse(paste.value); const n = addTeam(Array.isArray(o) ? o : [o]); P.toast(n ? `Added ${n} result${n === 1 ? '' : 's'}` : 'That does not look like an exported summary'); if (n) render(); } catch (e) { P.toast('That is not valid JSON. Paste the whole exported summary.'); } } }, 'Add pasted summary'))),
      hasSample ? h('p', { class: 'sample-banner' }, 'Showing example data for a fictional team. Clear team data to remove it.') : null,
      team.length ? h('div', { class: 'kpis' },
        P.kpi('People', team.length, `${depts.length} department${depts.length === 1 ? '' : 's'}`),
        P.kpi('Average awareness', scored.length ? Math.round(avg(scored.map(t => t.score))) : '—', 'out of 100'),
        P.kpi('At risk', atRisk, 'score below 50'),
        P.kpi('Training complete', pct(team.filter(t => t.trainingDone >= t.trainingTotal).length / team.length), 'all 9 lessons'),
        P.kpi('Weakest topic', orgSkill.length ? P.SKILLS[orgSkill[0].k].short : '—', orgSkill.length ? pct(orgSkill[0].v) + ' average' : '')) : h('p', { class: 'empty' }, 'No team results loaded yet. Import files or load the example team to see the business view.'),
      team.length ? h('div', { class: 'dash-grid' },
        h('div', { class: 'card' }, h('h3', {}, 'Average awareness by department'),
          bars(depts.map(d => { const v = avg(team.filter(t => t.dept === d && typeof t.score === 'number').map(t => t.score)); return { name: d, value: v || 0, label: v == null ? '—' : String(Math.round(v)) }; }).sort((a, b) => a.value - b.value), { max: 100 })),
        h('div', { class: 'card' }, h('h3', {}, 'Organisation proficiency by topic'),
          bars(orgSkill.map(x => ({ name: P.SKILLS[x.k].name, value: x.v, label: pct(x.v) })), { max: 1 }),
          orgSkill.length ? h('p', { class: 'hint' }, `Suggested next campaign: a focused session on ${P.SKILLS[orgSkill[0].k].name.toLowerCase()}${orgSkill[1] ? ' and ' + P.SKILLS[orgSkill[1].k].name.toLowerCase() : ''}.`) : null)) : null,
      team.length ? h('div', { class: 'card' }, h('h3', {}, 'People'),
        h('div', { class: 'table-wrap' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Department'), h('th', { class: 'num' }, 'Score'), h('th', {}, 'Level'), h('th', { class: 'num' }, 'Verdicts'), h('th', { class: 'num' }, 'Lessons'), h('th', {}, 'Weakest topic'))),
          h('tbody', {}, team.slice().sort((a, b) => (a.score ?? -1) - (b.score ?? -1)).map(t => {
            const weak = Object.entries(t.skills).filter(([, v]) => typeof v === 'number').sort((a, b) => a[1] - b[1])[0];
            return h('tr', {}, h('td', {}, t.alias), h('td', {}, t.dept), h('td', { class: 'num' }, t.score ?? '—'), h('td', {}, P.grade(t.score)), h('td', { class: 'num' }, pct(t.accuracy)), h('td', { class: 'num' }, `${t.trainingDone}/${t.trainingTotal}`), h('td', {}, weak ? P.SKILLS[weak[0]].short : '—'));
          }))))) : null);

    area.replaceChildren(personal, teamSection);
  }

  document.addEventListener('pea:view', e => { if (e.detail === 'dashboard') render(); });
  render();
})();
