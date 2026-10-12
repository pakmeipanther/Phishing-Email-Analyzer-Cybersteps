/*
 * core.js — shared helpers: safe storage, safe element building, small UI bits.
 *
 * SECURITY NOTE (worth learning!):
 *   Email text is untrusted. If we inserted it into the page with innerHTML, a malicious
 *   email containing <script> or <img onerror=...> could run code. This is called
 *   Cross-Site Scripting (XSS). The h() helper below only ever sets text with
 *   textContent, so untrusted text is always shown as plain characters.
 */
(function (root) {
  'use strict';
  const P = root.PEA;
  const KEY = 'pea:v1';

  // ── Storage (this browser only) ──────────────────────────────────────────
  const blank = () => ({ history: [], challenge: { answers: {} }, training: { done: {}, quiz: {} }, team: [], profile: { alias: '', dept: '' } });
  function load() {
    try {
      const s = JSON.parse(localStorage.getItem(KEY) || 'null');
      const state = blank();
      if (!s || typeof s !== 'object' || Array.isArray(s)) return state;
      if (Array.isArray(s.history)) state.history = s.history.slice(-500);
      if (s.challenge && s.challenge.answers && typeof s.challenge.answers === 'object') state.challenge.answers = s.challenge.answers;
      if (s.training && s.training.done && s.training.quiz && typeof s.training.done === 'object' && typeof s.training.quiz === 'object') state.training = {done:s.training.done,quiz:s.training.quiz};
      if (Array.isArray(s.team)) state.team = s.team.slice(0, 500);
      if (s.profile && typeof s.profile === 'object') state.profile = {alias:typeof s.profile.alias==='string'?s.profile.alias.slice(0,60):'',dept:typeof s.profile.dept==='string'?s.profile.dept.slice(0,60):''};
      return state;
    } catch (e) { return blank(); }
  }
  let state = load();
  function save() { try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) { /* storage blocked: app still works for this visit */ } }
  const store = {
    get: () => state,
    update(fn) { fn(state); save(); document.dispatchEvent(new CustomEvent('pea:data')); },
    wipe() { state = blank(); try { localStorage.removeItem(KEY); } catch (e) {} document.dispatchEvent(new CustomEvent('pea:data')); }
  };

  // ── Safe element builder ─────────────────────────────────────────────────
  // h('p', {class: 'x'}, 'text', childNode) → <p class="x">text…</p>
  function h(tag, attrs, ...kids) {
    const isSvg = ['svg', 'path', 'circle', 'text', 'g', 'line', 'rect'].includes(tag);
    const el = isSvg ? document.createElementNS('http://www.w3.org/2000/svg', tag) : document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'class') el.setAttribute('class', v);
      else if (k === 'text') el.textContent = v;
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  // ── Awareness score (shared by Challenge, Training, Dashboard) ───────────
  function awareness(s) {
    s = s || state;
    const ans = Object.values(s.challenge.answers);
    const total = Object.keys(P.SKILLS).length;
    const done = Object.keys(s.training.done).filter(k => s.training.done[k]).length;
    const perSkill = {};
    for (const k of Object.keys(P.SKILLS)) perSkill[k] = { seen: 0, got: 0 };
    let correct = 0, hit = 0, missed = 0, wrong = 0;
    for (const a of ans) {
      if (a.correct) correct++;
      hit += a.hit.length; missed += a.missed.length; wrong += a.wrong.length;
      const item = P.CHALLENGE.find(c => c.id === a.id);
      if (!item) continue;
      for (const sk of item.flags) { perSkill[sk].seen += 2; perSkill[sk].got += (a.correct ? 1 : 0) + (a.hit.includes(sk) ? 1 : 0); }
    }
    for (const [sk, q] of Object.entries(s.training.quiz)) if (perSkill[sk]) { perSkill[sk].seen += 1; perSkill[sk].got += q ? 1 : 0; }
    const accuracy = ans.length ? correct / ans.length : null;
    const flagAcc = hit + missed + wrong ? hit / (hit + missed + wrong) : null;
    const trainingPct = done / total;
    let score = null;
    if (accuracy !== null) score = Math.round(60 * accuracy + 20 * (flagAcc ?? 0) + 20 * trainingPct);
    else if (done) score = Math.round(20 * trainingPct);
    const skillPct = {};
    for (const [k, v] of Object.entries(perSkill)) skillPct[k] = v.seen ? v.got / v.seen : null;
    return { score, accuracy, flagAcc, trainingPct, done, total, answered: ans.length, skillPct };
  }
  function grade(score) {
    if (score == null) return 'Not rated yet';
    return score >= 85 ? 'Phishing expert' : score >= 70 ? 'Alert' : score >= 50 ? 'Developing' : 'At risk';
  }

  // ── Small UI helpers ─────────────────────────────────────────────────────
  let toastTimer;
  function toast(msg) {
    const t = document.getElementById('toast');
    if (!t) return;
    t.textContent = msg; t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { t.hidden = true; }, 2600);
  }
  async function copyText(text, label) {
    try { await navigator.clipboard.writeText(text); toast((label || 'Text') + ' copied'); }
    catch (e) { toast('Copy was blocked by the browser. Select the text and copy it manually.'); }
  }
  /** Create a file on the fly and offer it as a download. Nothing is uploaded. */
  function download(filename, text, type) {
    try {
      const url = URL.createObjectURL(new Blob([text], { type: type || 'application/json' }));
      const a = h('a', { href: url, download: filename });
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      toast('Saved ' + filename);
    } catch (e) { toast('Download blocked here. Use Copy instead.'); }
  }

  Object.assign(P, { store, h, awareness, grade, toast, copyText, download });
})(typeof window !== 'undefined' ? window : globalThis);
