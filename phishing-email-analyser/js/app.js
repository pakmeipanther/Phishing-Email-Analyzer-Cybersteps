/*
 * app.js — connects the buttons on the page to the analyser and draws the report.
 */
(function () {
  'use strict';
  const P = window.PEA;
  const { h } = P;
  const $ = id => document.getElementById(id);
  let mode = 'email';
  let lastReport = null;

  // ── Tabs ─────────────────────────────────────────────────────────────────
  const tabs = [...document.querySelectorAll('.tabs [role=tab]')];
  function showView(name, focus) {
    for (const t of tabs) {
      const on = t.dataset.view === name;
      t.setAttribute('aria-selected', on);
      t.tabIndex = on ? 0 : -1;
      $('view-' + t.dataset.view).hidden = !on;
      if (on && focus) t.focus();
    }
    document.dispatchEvent(new CustomEvent('pea:view', { detail: name }));
    try { history.replaceState(null, '', '#' + name); } catch (e) {}
  }
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => showView(t.dataset.view));
    t.addEventListener('keydown', e => {
      const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (d) showView(tabs[(i + d + tabs.length) % tabs.length].dataset.view, true);
    });
  });
  P.showView = showView;

  // ── Email / Voice mode ───────────────────────────────────────────────────
  function setMode(m) {
    mode = m;
    $('mode-email').setAttribute('aria-checked', m === 'email');
    $('mode-voice').setAttribute('aria-checked', m === 'voice');
    $('voice-tools').hidden = m !== 'voice';
    $('analyse-btn').textContent = m === 'voice' ? 'Analyse Call' : 'Analyse Email';
    $('input-label').textContent = m === 'voice'
      ? 'Paste or type what the caller said (transcript)'
      : 'Paste the suspicious email: headers, body, links and attachment names';
    $('email-input').placeholder = m === 'voice'
      ? 'e.g. "Hello, I\'m calling from your bank\'s fraud team. I need you to read me the code we just sent…"'
      : 'Tip: include the From / Reply-To lines and full headers if you have them. You can also paste HTML source.';
  }
  $('mode-email').addEventListener('click', () => setMode('email'));
  $('mode-voice').addEventListener('click', () => setMode('voice'));

  // Audio stays local: URL.createObjectURL makes a temporary in-memory address for the file.
  let audioUrl = null;
  $('audio-file').addEventListener('change', e => {
    const f = e.target.files[0];
    if (!f) return;
    if (audioUrl) URL.revokeObjectURL(audioUrl);
    audioUrl = URL.createObjectURL(f);
    const pl = $('audio-player');
    pl.src = audioUrl; pl.hidden = false;
    P.toast('Loaded ' + f.name + ' (not uploaded)');
  });

  // ── Examples ─────────────────────────────────────────────────────────────
  const sel = $('example-select');
  for (const ex of P.EXAMPLES) sel.append(h('option', { value: ex.id }, ex.label + (ex.mode === 'voice' ? ' (voice)' : '')));
  sel.addEventListener('change', () => {
    const ex = P.EXAMPLES.find(x => x.id === sel.value);
    if (!ex) return;
    setMode(ex.mode);
    generation++;analysisContext={html:'',qrResults:[]};
    $('email-input').value = ex.text;
    sel.value = '';
    run(false);
  });

  // ── .eml import ──────────────────────────────────────────────────────────
  // FileReader hands the file's bytes to this tab only; nothing is sent anywhere (the CSP would block it).
  let analysisContext = {html:'',qrResults:[]};
  let generation = 0;
  async function inspectImages(blobs, version) {
    const unique=[];
    const errors=[];
    if (!P.qrSecurity || !P.qrSecurity.supported()) {
      $('qr-status').textContent='QR decoding unavailable in this browser; static URL and email analysis remains available.';
      return;
    }
    for (const blob of blobs.slice(0,4)) {
      const result=await P.qrSecurity.inspectImage(blob);
      if (version!==generation) return;
      if (result.status==='ok') unique.push(...result.codes.filter(c=>c.url));
      else errors.push(result.status);
    }
    if (version!==generation) return;
    analysisContext.qrResults=[...new Map(unique.map(x=>[x.value,x])).values()].slice(0,12);
    $('qr-status').textContent=analysisContext.qrResults.length
      ? `${analysisContext.qrResults.length} QR URL(s) decoded locally; included in the analysis.`
      : errors.length ? `QR inspection incomplete (${[...new Set(errors)].join(', ')}). No safe verdict is possible.`
      : 'No QR URL detected in selected images. This does not prove the images are safe.';
    if ($('email-input').value.trim() || analysisContext.qrResults.length) run(false,true);
  }
  $('qr-file').addEventListener('change',e=>{
    const f=e.target.files[0];e.target.value='';if (!f)return;
    generation++; const version=generation;
    analysisContext.qrResults=[];
    inspectImages([f],version);
  });
  $('email-input').addEventListener('input',()=>{generation++; analysisContext={html:'',qrResults:[]};});
  const EML_MAX_BYTES = 25 * 1024 * 1024; // the usual mail-server size limit
  function importEml(file) {
    if (!file) return;
    const fileVersion = ++generation; // discard a stale read after edit, reset, or newer file
    if (!/\.eml$/i.test(file.name) && file.type !== 'message/rfc822') { P.toast('That is not an .eml file.'); return; }
    if (file.size > EML_MAX_BYTES) { P.toast('That file is over 25 MB. Too large to open here.'); return; }
    const reader = new FileReader();
    reader.onerror = () => P.toast('Could not read that file.');
    reader.onload = () => {
      if (fileVersion !== generation) return;
      let parsed;
      try { parsed = P.parseEml(reader.result); } catch (e) { P.toast('That file could not be read as an email.'); return; }
      if (!parsed.text.trim()) { P.toast('No readable text was found in that file.'); return; }
      setMode('email');
      generation++; const version=generation;
      analysisContext={html:parsed.html||'',qrResults:[],mimeLimited:!!parsed.limited};
      $('email-input').value = parsed.text;
      $('eml-status').replaceChildren(
        h('b', {}, file.name), ' · body from ', parsed.source === 'none' ? 'headers only' : parsed.source,
        parsed.files.length ? ` · ${parsed.files.length} attachment${parsed.files.length === 1 ? '' : 's'} listed` : null);
      run(false, true);
      if (parsed.images && parsed.images.length) {
        const images=parsed.images.map(i=>new Blob([i.bytes],{type:i.mime}));
        $('qr-status').textContent=`Checking ${images.length} embedded image(s) for QR codes locally…`;
        inspectImages(images,version);
      }
      P.toast('Loaded ' + file.name + ' (read locally, not uploaded)');
    };
    reader.readAsArrayBuffer(file);
  }
  $('eml-file').addEventListener('change', e => { importEml(e.target.files[0]); e.target.value = ''; });

  // Dropping works on the box and on the text area. Only file drags are intercepted, so dragging plain text into the area still works.
  const dropzone = $('eml-drop');
  const dragHasFiles = e => Array.from((e.dataTransfer || {}).types || []).includes('Files');
  for (const el of [dropzone, $('email-input')]) {
    el.addEventListener('dragover', e => {
      if (!dragHasFiles(e)) return;
      e.preventDefault(); // without this the browser refuses the drop and opens the file instead
      e.dataTransfer.dropEffect = 'copy';
      dropzone.classList.add('dragover');
    });
    el.addEventListener('dragleave', e => { if (!el.contains(e.relatedTarget)) dropzone.classList.remove('dragover'); });
    el.addEventListener('drop', e => {
      if (!dragHasFiles(e)) return;
      e.preventDefault();
      dropzone.classList.remove('dragover');
      importEml(e.dataTransfer.files[0]);
    });
  }

  $('clear-btn').addEventListener('click', () => {
    generation++;analysisContext={html:'',qrResults:[]};
    $('qr-status').textContent='No QR images loaded.';
    $('email-input').value = ''; $('eml-status').textContent = '';
    $('report-body').hidden = true; $('empty-state').hidden = false;
    lastReport = null;
    $('email-input').focus();
  });
  $('analyse-btn').addEventListener('click', () => run(true));
  $('email-input').addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run(true); });

  // fromFile: the text came from the user's own .eml, so don't label the report a "built-in example".
  function run(record, fromFile) {
    const text = $('email-input').value;
    if (!text.trim() && !analysisContext.qrResults.length) { P.toast('Paste a message, upload an email, or decode a QR image first.'); $('email-input').focus(); return; }
    const report = P.analyse(text, mode, analysisContext);
    if (analysisContext.mimeLimited) { report.coverage.complete = false;
      report.coverage.messages.push('MIME parsing reached a safety limit; not all email parts were inspected.'); }
    lastReport = report;
    render(report, !record && !fromFile);
    if (record && $('save-history').checked) {
      P.store.update(s => {
        s.history.push({ t: report.analysedAt, score: report.score, level: report.level, mode: report.mode, ids: report.findings.map(f => f.id), titles: report.findings.map(f => f.title), skills: report.skills });
        if (s.history.length > 500) s.history = s.history.slice(-500);
      });
    }
    if (window.matchMedia('(max-width: 900px)').matches) $('report').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // ── Report rendering ─────────────────────────────────────────────────────
  const SEV_COLOR = w => w >= 25 ? 'var(--sev-critical)' : w >= 15 ? 'var(--sev-high)' : w >= 9 ? 'var(--sev-medium)' : 'var(--sev-low)';

  function gauge(score) {
    // A half-circle meter. pathLength=100 lets us draw "score" percent of the arc.
    const arc = 'M 14 84 A 70 70 0 0 1 154 84';
    return h('svg', { class: 'gauge', viewBox: '0 0 168 100', role: 'img', 'aria-label': `Risk score ${score} out of 100` },
      h('path', { d: arc, class: 'g-track', pathLength: 100 }),
      h('path', { d: arc, class: 'g-fill', pathLength: 100, 'stroke-dasharray': `${Math.max(score, 0.5)} 100` }),
      h('text', { x: 84, y: 78, 'text-anchor': 'middle', class: 'g-num' }, String(score)),
      h('text', { x: 84, y: 96, 'text-anchor': 'middle', class: 'g-sub' }, 'RISK / 100'));
  }

  function headline(r) {
    const n = r.findings.filter(f => f.weight > 0).length;
    if (r.level === 'Critical') return 'Multiple high-severity phishing indicators';
    if (r.level === 'High') return 'Strong phishing indicators present';
    if (r.level === 'Medium') return 'Some warning signs. Verify before acting';
    return n ? 'Few warning signs found' : 'No common warning signs found';
  }

  function annotated(text, spans) {
    // Merge overlapping highlight ranges, then build text + <mark> nodes safely.
    const s = spans.filter(x => x.end > x.start).sort((a, b) => a.start - b.start);
    const merged = [];
    for (const x of s) {
      const last = merged[merged.length - 1];
      if (last && x.start <= last.end) { last.end = Math.max(last.end, x.end); if (!last.titles.includes(x.title)) last.titles.push(x.title); }
      else merged.push({ start: x.start, end: x.end, titles: [x.title] });
    }
    const out = []; let i = 0;
    for (const m of merged) {
      if (m.start > i) out.push(text.slice(i, m.start));
      out.push(h('mark', { title: m.titles.join(' · ') }, text.slice(m.start, m.end)));
      i = m.end;
    }
    out.push(text.slice(i));
    return h('div', { class: 'evidence', tabindex: 0, 'aria-label': 'Message with warning signs highlighted' }, out);
  }

  function findingsCard(r) {
    // Include future/new investigator categories. an earlier release omitted HTML and
    // QR findings from the explanatory panel despite scoring them.
    const preferred = ['Patterns', 'Language', 'Links', 'HTML source', 'QR code', 'Attachments', 'Sender'];
    const groups = [...new Set([...preferred, ...r.findings.map(f => f.group || 'Other')])];
    const card = h('section', { class: 'card' },
      h('h3', {}, 'Why it is suspicious', h('span', { class: 'count' }, `${r.findings.filter(f => f.weight > 0).length} weighted finding${r.findings.filter(f => f.weight > 0).length === 1 ? '' : 's'}`)),
      h('p', { class: 'sub' }, 'Open any item to see the evidence and an explanation. The number is how much it added to the risk.'));
    if (!r.findings.length) card.append(h('p', { class: 'empty' }, 'Nothing matched the analyser\'s rules. That does not prove the message is safe.'));
    for (const g of groups) {
      const items = r.findings.filter(f => (f.group || 'Other') === g);
      if (!items.length) continue;
      card.append(h('div', { class: 'findings' },
        h('div', { class: 'group-label' }, g === 'Patterns' ? 'Attack patterns' : g),
        items.map(f => {
          const bar = h('span', { class: 'sev-bar', 'aria-hidden': 'true' });
          bar.style.setProperty('--c', SEV_COLOR(f.weight));
          return h('details', { class: 'finding' },
            h('summary', {}, bar, h('span', { class: 'f-title' }, f.title, ' ', h('span', { class: 'tag' }, P.SKILLS[f.skill].short)), h('span', { class: 'weight' }, '+' + f.weight)),
            h('div', { class: 'finding-body' },
              h('p', {}, f.explain),
              f.evidence.length ? h('div', { class: 'chips' }, f.evidence.map(e => h('span', { class: 'chip' }, e))) : null));
        })));
    }
    for (const p of r.headers.positives) card.append(h('p', { class: 'positive' }, p));
    return card;
  }

  function linksCard(r) {
    if (!r.urls.length && !r.attachments.length) return null;
    const card = h('section', { class: 'card' }, h('h3', {}, 'Links & attachments', h('span', { class: 'count' }, `${r.urls.length} link${r.urls.length === 1 ? '' : 's'} · ${r.attachments.length} file${r.attachments.length === 1 ? '' : 's'}`)),
      h('p', { class: 'sub' }, 'Links are read as text only. The analyser never visits them.'));
    if (r.urls.length) card.append(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Link'), h('th', {}, 'Real owner'), h('th', {}, 'Verdict'))),
      h('tbody', {}, r.urls.map(u => h('tr', {},
        h('td', { class: 'mono' }, u.raw,
          u.unicodeHost && u.host !== u.unicodeHost ? h('div', { class: 'hint' }, 'Decoded IDN: ' + u.unicodeHost + ' (ASCII: ' + u.host + ')') : null,
          u.shownAs ? h('div', { class: 'hint' }, 'Shown as: "' + u.shownAs + '"') : null),
        h('td', { class: 'mono' }, u.reg || '—'),
        h('td', {}, u.issues.length ? h('span', { class: 'bad' }, u.issues.map(i => i.title).join('; ')) : h('span', { class: 'ok' }, 'No detected indicators (not a safety guarantee)'))))))));
    if (r.attachments.length) card.append(h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'File name'), h('th', {}, 'Type'), h('th', {}, 'Verdict'))),
      h('tbody', {}, r.attachments.map(a => h('tr', {},
        h('td', { class: 'mono' }, a.name), h('td', { class: 'mono' }, '.' + a.ext),
        h('td', {}, a.issues.length ? h('span', { class: 'bad' }, a.issues.map(i => i.title).join('; ')) : h('span', { class: 'ok' }, 'Common document type'))))))));
    return card;
  }

  function whatIfCard(r) {
    return h('section', { class: 'card' },
      h('h3', {}, 'What happens if you…'),
      h('p', { class: 'sub' }, 'A walk-through of the likely consequences of each action, based on what this message asks for.'),
      h('div', { class: 'whatif' }, P.whatIf(r).map(w => h('article', {},
        h('h4', {}, w.action, h('span', { class: 'sev-tag', 'data-s': w.severity }, w.severity)),
        h('ol', {}, w.steps.map(s => h('li', {}, s)))))));
  }

  function pathCard(r) {
    const stages = P.attackPath(r);
    const list = h('ol', { class: 'path' }, stages.map(s => h('li', {},
      h('div', { class: 'stage-body' },
        h('h4', {}, s.stage),
        h('p', {}, s.what),
        h('div', { class: 'chips' }, s.techniques.map(([id, name]) => h('span', { class: 'chip ttp' }, id, ' ', h('span', {}, name)))),
        h('p', { class: 'detect' }, h('b', {}, 'How defenders spot it: '), s.detect)))));
    let timer = null;
    const btn = h('button', { type: 'button', class: 'btn small', onclick: play }, '▶ Play simulation');
    function play() {
      const items = [...list.children];
      clearInterval(timer);
      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) { items.forEach(li => li.classList.add('done')); return; }
      items.forEach(li => li.classList.remove('active', 'done'));
      list.classList.add('playing');
      let i = 0;
      const step = () => {
        if (i > 0) { items[i - 1].classList.remove('active'); items[i - 1].classList.add('done'); }
        if (i >= items.length) { clearInterval(timer); list.classList.remove('playing'); btn.textContent = '↻ Replay simulation'; return; }
        items[i].classList.add('active'); i++;
      };
      step(); timer = setInterval(step, 1400);
    }
    return h('section', { class: 'card' },
      h('div', { class: 'row' }, h('h3', {}, 'Attack path simulation'), btn),
      h('p', { class: 'sub' }, 'How this attack would most likely unfold, mapped to MITRE ATT&CK technique IDs used by security teams.'),
      list);
  }

  function actionsCard(r) {
    const a = P.actions(r);
    const panes = {
      now: h('ol', { class: 'steps' }, a.now.map(s => h('li', {}, s))),
      ir: h('div', { class: 'ir-grid' }, a.ir.map(b => h('div', { class: 'ir-block' }, h('h4', {}, b.title), h('ol', { class: 'steps' }, b.steps.map(s => h('li', {}, s)))))),
      soc: h('ol', { class: 'steps' }, a.soc.map(s => h('li', {}, s)))
    };
    const labels = { now: 'What to do now', ir: 'If you already interacted', soc: 'For security analysts' };
    const body = h('div', {});
    const btns = Object.keys(panes).map(k => h('button', { type: 'button', role: 'tab', 'aria-selected': k === 'now', onclick: () => pick(k) }, labels[k]));
    function pick(k) { btns.forEach((b, i) => b.setAttribute('aria-selected', Object.keys(panes)[i] === k)); body.replaceChildren(panes[k]); }
    pick(r.level === 'Low' ? 'now' : 'now');
    return h('section', { class: 'card' }, h('h3', {}, 'Recommended actions & incident response'), h('div', { class: 'action-tabs', role: 'tablist' }, btns), body);
  }

  function iocCard(r) {
    const io = r.iocs;
    const sets = [['URLs', io.urls], ['Domains', io.domains], ['IP addresses', io.ips], ['Email addresses', io.emails], ['Files', io.files], ['Phone numbers', io.phones]].filter(x => x[1].length);
    const lines = sets.flatMap(([k, v]) => [`# ${k}`, ...v.map(x => k === 'Phone numbers' || k === 'Files' ? x : P.defang(x)), '']).join('\n');
    return h('section', { class: 'card' },
      h('h3', {}, 'Candidate indicators for investigation (IOCs)'),
      h('p', { class: 'sub' }, 'Defanged ("evil[.]com") so they cannot be clicked by accident when you share them with your security team.'),
      sets.length ? h('div', { class: 'ioc-grid' }, sets.map(([k, v]) => h('div', {}, h('h4', {}, k), h('ul', {}, v.map(x => h('li', {}, k === 'Phone numbers' || k === 'Files' ? x : P.defang(x))))))) : h('p', { class: 'empty' }, 'No suspicious indicators extracted.'),
      h('div', { class: 'row' },
        sets.length ? h('button', { type: 'button', class: 'btn small', onclick: () => P.copyText(lines, 'IOCs') }, 'Copy IOCs') : null,
        h('button', { type: 'button', class: 'btn small', onclick: () => P.download('phishing-report.txt', textReport(r), 'text/plain') }, 'Download report (.txt)'),
        h('button', { type: 'button', class: 'btn small', onclick: () => P.copyText(textReport(r), 'Report') }, 'Copy report')));
  }

  function textReport(r) {
    const L = [];
    L.push('PHISHING ANALYSIS REPORT', `Generated: ${new Date(r.analysedAt).toLocaleString()}`, `Type: ${r.mode === 'voice' ? 'Voice call transcript' : 'Email'}`, `Risk: ${r.score}/100 (${r.level})`, '');
    if (r.coverage && !r.coverage.complete) L.push('INCOMPLETE ANALYSIS: ' + r.coverage.messages.join(' '), '');
    L.push('WARNING SIGNS');
    r.findings.forEach(f => L.push(`- [+${f.weight}] ${f.title}${f.evidence.length ? ' :: ' + f.evidence.map(e => P.defang(e)).join(' | ') : ''}`));
    L.push('', 'ATTACK PATH (MITRE ATT&CK)');
    P.attackPath(r).forEach((s, i) => L.push(`${i + 1}. ${s.stage}: ${s.techniques.map(t => t.join(' ')).join(', ')}`));
    L.push('', 'IOCs (defanged)');
    Object.entries(r.iocs).forEach(([k, v]) => v.length && L.push(`${k}: ${v.map(x => (k === 'phones' || k === 'files') ? x : P.defang(x)).join(', ')}`));
    L.push('', 'Generated locally by Phishing Email Analyser. The message text is not included in this report.');
    return L.join('\n');
  }

  function render(r, isExample) {
    const body = $('report-body');
    const verdict = h('section', { class: 'card verdict', 'data-level': r.level },
      gauge(r.score),
      h('div', { class: 'verdict-text' },
        h('span', { class: 'level-pill' }, r.level + ' risk'),
        h('h2', {}, headline(r)),
        h('div', { class: 'stat-row' },
          h('span', {}, h('b', {}, r.findings.filter(f => f.weight > 0).length), ' weighted findings'),
          h('span', {}, h('b', {}, r.urls.filter(u => u.issues.length).length), ' / ', r.urls.length, ' links suspicious'),
          r.mode === 'email' ? h('span', {}, h('b', {}, r.attachments.filter(a => a.issues.length).length), ' risky files') : null,
          r.wasHtml ? h('span', {}, 'HTML source detected') : null)));
    const evidence = h('section', { class: 'card' },
      h('h3', {}, 'Evidence in the message'),
      h('p', { class: 'sub' }, 'Highlighted text triggered a rule. Hover or long-press a highlight to see which.'),
      annotated(r.text, r.spans));
    const note = isExample ? h('p', { class: 'sample-banner' }, 'This is a built-in example so you can see a full report. Clear the box and paste your own message to analyse it.') : null;
    const coverageNotice = r.coverage && !r.coverage.complete ? h('section', { class:'card', role:'alert' },
      h('h3', {}, 'Incomplete analysis — verdict is not reliable'),
      r.coverage.messages.map(message => h('p', {class:'bad'}, message))) : null;
    body.replaceChildren(...[note, coverageNotice, verdict, findingsCard(r), evidence, linksCard(r), whatIfCard(r), pathCard(r), actionsCard(r), iocCard(r)].filter(Boolean));
    $('empty-state').hidden = true;
    body.hidden = false;
  }

  // Open the tab named in the address (e.g. …/#challenge), otherwise start on Analyse.
  const start = (location.hash || '').slice(1);
  if (['analyse', 'challenge', 'training', 'dashboard', 'about'].includes(start)) setTimeout(() => showView(start), 0);

  // Show a worked example on first load so the page is never empty.
  const first = P.EXAMPLES[0];
  $('email-input').value = first.text;
  run(false);

  $('wipe-btn').addEventListener('click', () => {
    P.store.wipe();
    $('wipe-status').textContent = 'All locally stored data deleted.';
  });
})();
