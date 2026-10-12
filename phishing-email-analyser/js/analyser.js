/*
 * analyser.js — the detection engine.
 *
 * Plain-English summary:
 *   analyse(text, mode) takes the pasted email (or call transcript) and returns
 *   a "report" object: a list of findings, a 0–100 risk score, every link and
 *   attachment it found, and IOCs (indicators of compromise) for analysts.
 *
 *   Everything happens in memory, inside your browser tab. There is no fetch(),
 *   no XMLHttpRequest, nothing that talks to the internet. Links are only READ
 *   as text; they are never opened or visited.
 */
(function (root) {
  'use strict';
  const P = root.PEA;

  // ── Small helpers ───────────────────────────────────────────────────────────

  /** Turn HTML entities like &amp; back into normal characters (without using the DOM). */
  function decodeEntities(s) {
    return s.replace(/&nbsp;/gi, ' ').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
      .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Math.min(+n || 0, 0x10ffff)))
      .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(Math.min(parseInt(n, 16) || 0, 0x10ffff)))
      .replace(/&amp;/gi, '&');
  }

  /**
   * If the user pasted raw HTML (for example "view source" of an email), pull out
   * every <a href="...">text</a> pair, then strip the tags so we can read the text.
   * We use text processing rather than inserting the HTML into the page, so any
   * scripts or tracking images in the email can never run or load.
   */
  function normaliseInput(raw) {
    const anchors = [];
    let text = raw.replace(/\r\n?/g, '\n');
    const looksHtml = /<\s*(html|body|div|p|a|table|span|br|form|input|meta|img|section|main)\b/i.test(text);
    if (looksHtml) {
      // Non-rendered HTML must not create fictitious phishing language/URLs.
      text = text.replace(/<!--[\s\S]*?(?:-->|$)/g, ' ')
        .replace(/<(script|style|head|template|noscript)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' ');
      const aRe = /<a\b[^>]*?\bhref\s*=\s*(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a\s*>/gi;
      let m;
      while ((m = aRe.exec(text))) {
        anchors.push({ href: decodeEntities(m[2]).trim(), text: decodeEntities(m[3].replace(/<[^>]*>/g, '')).replace(/\s+/g, ' ').trim() });
      }
      text = text
        .replace(/<(script|style|head)\b[\s\S]*?<\/\1\s*>/gi, ' ')
        .replace(/<br\s*\/?>|<\/(p|div|tr|li|h\d)>/gi, '\n')
        .replace(/<[^>]+>/g, ' ');
      text = decodeEntities(text).replace(/[ \t]+/g, ' ').replace(/\n\s*\n\s*\n+/g, '\n\n').trim();
    }
    return { text, anchors, wasHtml: looksHtml };
  }

  /** "login.secure.paypal.co.uk" → "paypal.co.uk" (the part someone actually registered). */
  function registrableDomain(host) {
    const h = (host || '').toLowerCase().replace(/\.$/, '');
    if (isIp(h)) return h;
    if (P.publicSuffix) return P.publicSuffix.registrableDomain(h);
    const parts = h.split('.');
    if (parts.length <= 2) return h;
    const lastTwo = parts.slice(-2).join('.');
    if (P.MULTI_SUFFIXES.includes(lastTwo)) return parts.slice(-3).join('.');
    return lastTwo;
  }

  function isIp(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || /^\[?[0-9a-f:]+\]?$/i.test(host) && host.includes(':') || /^\d{8,10}$/.test(host) || /^0x[0-9a-f]{8}$/i.test(host);
  }

  /** Classic "edit distance": how many single-letter changes turn a into b. */
  function levenshtein(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++)
      for (let j = 1; j <= b.length; j++)
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return d[a.length][b.length];
  }

  /** Swap look-alike characters (paypa1 → paypal, rnicrosoft → microsoft). */
  function deHomoglyph(s) {
    return s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/1/g, 'l')
      .replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/\$/g, 's');
  }

  // Brands that are too short or too common as substrings ("purchase" contains "chase").
  const SUBSTRING_SKIP = new Set(['office', 'outlook', 'chase', 'steam', 'irs', 'hmrc', 'dhl', 'apple', 'adobe', 'google']);

  function isOfficial(brand, reg) {
    return (P.BRANDS[brand] || []).some(d => reg === d || reg.endsWith('.' + d));
  }

  /** Check one domain name for brand abuse and look-alike tricks. Returns issue list. */
  function domainIssues(host) {
    const issues = [];
    if (!host || isIp(host)) return issues;
    const reg = registrableDomain(host);
    const label = reg.split('.')[0];
    const tld = host.split('.').pop();

    for (const brand of Object.keys(P.BRANDS)) {
      if (isOfficial(brand, reg)) continue;
      // 1) look-alike registered name: paypa1.com, arnazon.com, micros0ft.com
      const deh = deHomoglyph(label);
      const dist = levenshtein(label, brand);
      const lookalike = (label !== brand && deh === brand && brand.length >= 4) ||
        (label !== brand && brand.length >= 6 && dist === 1) ||
        (label !== brand && brand.length >= 8 && dist === 2);
      if (lookalike) {
        issues.push({ type: 'lookalike', weight: 30, title: 'Look-alike (typosquatted) domain', detail: `"${reg}" imitates ${brand} but is not an official ${brand} domain.` });
        break;
      }
      // 2) brand name used somewhere else in the address: paypal.com.secure-login.xyz, microsoft-support.net
      if (!SUBSTRING_SKIP.has(brand) && host.replace(/[-.]/g, ' ').split(' ').some(w => w.includes(brand))) {
        issues.push({ type: 'brand-mismatch', weight: 25, title: 'Brand name in a domain the brand does not own', detail: `"${host}" contains "${brand}", but the real owner of this address is "${reg}".` });
        break;
      }
    }
    // The dedicated Unicode investigator only scores IDNs when impersonation
    // evidence exists; legitimate internationalized domains are not malware.
    if (P.domainSecurity) issues.push(...P.domainSecurity.issues(host, reg));
    if (P.RISKY_TLDS.includes(tld))
      issues.push({ type: 'risky-tld', weight: 10, title: 'Frequently abused domain ending', detail: `".${tld}" domains are cheap and heavily used in phishing campaigns. Not proof on its own.` });
    if (P.ABUSED_HOSTS.some(h => host === h || host.endsWith('.' + h)))
      issues.push({ type: 'abused-host', weight: 10, title: 'Free hosting service often used for phishing pages', detail: `"${host}" is on a legitimate free hosting/form platform that attackers commonly use to host fake login pages.` });
    return issues;
  }

  // ── URL extraction & analysis ───────────────────────────────────────────────

  const URL_RE = /(?:\b(?:https?|hxxps?|ftp):\/\/|\bwww\.)[^\s<>"'`)\]}]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\/[^\s<>"'`)\]}]*|[\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)*\.[\p{L}]{2,24}\/[^\s<>"'`)\]}]*/giu;
  // Bare non-ASCII domains without a /path are also valuable evidence. Exclude
  // email-address suffixes and files; leave normal ASCII naked domains alone.
  const BARE_IDN_RE = /(?<![\p{L}\p{N}@.-])(?:[\p{L}\p{N}-]+\.)+[\p{L}]{2,24}(?![\p{L}\p{N}-])/gu;

  function cleanUrlText(u) { return u.replace(/[.,;:!?]+$/, ''); }

  function toUrl(raw) {
    let s = raw.trim().replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.');
    if (/^(javascript|data|vbscript):/i.test(s)) return { scheme: s.split(':')[0].toLowerCase(), href: s };
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;
    try { return new URL(s); } catch (e) { return null; }
  }

  function analyseUrl(raw, extra) {
    const u = toUrl(raw);
    const issues = [];
    if (!u) return { raw, host: '', reg: '', issues };
    if (u.scheme) { // javascript: / data: link
      issues.push({ type: 'script-uri', weight: 30, title: 'Script or data link', detail: `This link uses "${u.scheme}:", which can run code or embed a fake page directly.` });
      return { raw, host: '', reg: '', issues };
    }
    const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const reg = registrableDomain(host);
    const unicodeHost = P.domainSecurity ? P.domainSecurity.decodeHost(host) : host;

    if (P.SHORTENERS.includes(host) || P.SHORTENERS.includes(reg))
      issues.push({ type: 'shortener', weight: 18, title: 'Shortened link hides the real destination', detail: `"${host}" is a link-shortening service. You cannot see where it really leads without clicking.` });
    if (isIp(host))
      issues.push({ type: 'ip-url', weight: 28, title: 'Link uses a raw IP address', detail: `"${host}" is a numeric address instead of a company name. Genuine organisations use their own domain names.` });
    if (u.username || /@/.test(raw.split(/[/?#]/).slice(0, 3).join('/').replace(/^[a-z]+:\/\//i, '')))
      issues.push({ type: 'userinfo', weight: 25, title: '"@" trick in link', detail: 'Everything before an "@" in a web address is ignored by the browser, so "https://paypal.com@evil.com" really goes to evil.com.' });
    if (u.protocol === 'http:' && /^(https?|hxxps?):/i.test(raw))
      issues.push({ type: 'no-https', weight: 6, title: 'Unencrypted (http) link', detail: 'The link is not encrypted. Unusual for any login or payment page.' });
    if (u.port && !['80', '443'].includes(u.port))
      issues.push({ type: 'odd-port', weight: 8, title: 'Unusual port number', detail: `The link specifies port ${u.port}, which normal websites do not need.` });
    const subLabels = host.split('.').length - reg.split('.').length;
    if (!isIp(host) && subLabels >= 3)
      issues.push({ type: 'deep-subdomain', weight: 8, title: 'Many sub-domains', detail: `"${host}" stacks several sub-domains, a common trick to push the real domain out of view.` });
    if (raw.length > 120)
      issues.push({ type: 'long-url', weight: 4, title: 'Very long link', detail: 'Very long links can hide the real destination or carry tracking IDs.' });

    issues.push(...domainIssues(host));
    if (P.urlSecurity) issues.push(...P.urlSecurity.inspect(u.href));

    const official = Object.keys(P.BRANDS).some(b => isOfficial(b, reg));
    if (!official && /(log-?in|sign-?in|verify|verification|secure|account|update|wallet|password|banking|webscr|auth)/i.test(u.pathname + u.hostname))
      issues.push({ type: 'login-words', weight: 8, title: 'Login or security words in an unknown domain', detail: 'Words like "login", "verify" or "secure" in the address are used to make a fake page look official.' });

    if (extra) issues.push(...extra);
    return { raw, host, unicodeHost, reg, issues };
  }

  /** Find every link in the text plus every <a href> from HTML input, and spot misleading link text. */
  function collectUrls(text, anchors) {
    const out = [];
    const seen = new Set();
    const add = (raw, start, end, extra, shownAs) => {
      raw = cleanUrlText(raw);
      const key = raw.toLowerCase();
      if (seen.has(key)) { const prev = out.find(o => o.raw.toLowerCase() === key); if (prev && extra) prev.issues.push(...extra); return; }
      seen.add(key);
      const a = analyseUrl(raw, extra);
      a.start = start; a.end = end; a.shownAs = shownAs || null;
      out.push(a);
    };

    // Plain-text email copies often show links as:  Display text <https://real.link>
    const misleadRe = /(\S[^\n<]{0,80}?)\s*<((?:https?|hxxps?):\/\/[^>\s]+)>/gi;
    const pairs = [];
    let m;
    while ((m = misleadRe.exec(text))) pairs.push({ text: m[1].trim(), href: m[2], start: m.index + m[0].indexOf('<') + 1 });
    const mdRe = /\[([^\]\n]{1,100})\]\(((?:https?):\/\/[^)\s]+)\)/gi;
    while ((m = mdRe.exec(text))) pairs.push({ text: m[1].trim(), href: m[2], start: m.index + m[0].indexOf('(') + 1 });
    for (const a of anchors) pairs.push({ text: a.text, href: a.href, start: -1 });

    const pairExtra = new Map();
    for (const p of pairs) {
      const extra = misleadingText(p.text, p.href);
      if (extra.length) pairExtra.set(cleanUrlText(p.href).toLowerCase(), { extra, shown: p.text });
    }

    URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(text))) {
      const raw = cleanUrlText(m[0]);
      if (/^[\w.-]+\.(png|jpe?g|gif|pdf|docx?|xlsx?)\/?$/i.test(raw)) continue;
      const pe = pairExtra.get(raw.toLowerCase());
      add(raw, m.index, m.index + raw.length, pe ? pe.extra : null, pe ? pe.shown : null);
    }
    BARE_IDN_RE.lastIndex = 0;
    while ((m = BARE_IDN_RE.exec(text))) {
      if ((/[^\x00-\x7f]/.test(m[0]) || /(?:^|\.)xn--/i.test(m[0])) &&
          !out.some(u => u.start >= 0 && u.start <= m.index && u.end >= m.index + m[0].length) &&
          !seen.has(m[0].toLowerCase()))
        add(m[0], m.index, m.index + m[0].length, null, null);
    }
    for (const a of anchors) {
      const pe = pairExtra.get(cleanUrlText(a.href).toLowerCase());
      if (/^(mailto|tel|cid):/i.test(a.href) || a.href.startsWith('#')) continue;
      add(a.href, -1, -1, pe ? pe.extra : null, a.text);
    }
    return out;
  }

  /** Does the visible text of a link promise a different destination than the real one? */
  function misleadingText(shown, href) {
    const issues = [];
    if (!shown) return issues;
    const target = toUrl(href);
    if (!target || target.scheme) return issues;
    const targetReg = registrableDomain(target.hostname);
    const shownUrlMatch = shown.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,24})/i);
    if (shownUrlMatch) {
      const shownReg = registrableDomain(shownUrlMatch[1]);
      if (shownReg && shownReg !== targetReg)
        issues.push({ type: 'misleading-text', weight: 30, title: 'Link text shows a different address than the real link', detail: `The link says "${shown}" but actually goes to "${target.hostname}".` });
      return issues;
    }
    for (const brand of Object.keys(P.BRANDS)) {
      if (new RegExp('\\b' + brand + '\\b', 'i').test(shown) && !isOfficial(brand, targetReg)) {
        issues.push({ type: 'misleading-text', weight: 22, title: 'Link text names a brand the link does not belong to', detail: `The link text mentions "${brand}" but the link goes to "${target.hostname}".` });
        break;
      }
    }
    return issues;
  }

  // ── Attachments ─────────────────────────────────────────────────────────────

  function collectAttachments(textNoUrls) {
    const allExts = Object.values(P.ATTACHMENT_TYPES).flatMap(t => t.exts);
    const safeDoc = 'pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|csv|rtf';
    const fileRe = new RegExp('(?:^|[\\s:"\'(\\[])([\\w\\u00C0-\\u024F\\u202E\\-.,()\\[\\]&+]{1,120}?(?:\\s{2,}[\\w.]*)?\\.(' + allExts.join('|') + '|' + safeDoc + '))(?=$|[\\s"\'),\\];:!?]|\\.(?:\\s|$))', 'gim');
    const found = [];
    const seen = new Set();
    let m;
    while ((m = fileRe.exec(textNoUrls))) {
      const name = m[1].trim();
      const key = name.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      const ext = m[2].toLowerCase();
      const issues = [];
      for (const [kind, t] of Object.entries(P.ATTACHMENT_TYPES)) {
        if (t.exts.includes(ext)) issues.push({ type: 'att-' + kind, weight: t.weight, title: t.title, detail: t.explain });
      }
      if (new RegExp('\\.(' + safeDoc + ')\\s*\\.(' + allExts.join('|') + ')$', 'i').test(name))
        issues.push({ type: 'att-double-ext', weight: 30, title: 'Double file extension', detail: `"${name}" pretends to be a document but its real type is ".${ext}".` });
      if (/\s{3,}/.test(name))
        issues.push({ type: 'att-padding', weight: 20, title: 'Hidden file extension (padding)', detail: 'Many spaces inside the file name push the real file type out of view.' });
      if (/‮/.test(name))
        issues.push({ type: 'att-rtlo', weight: 35, title: 'Right-to-left override character', detail: 'An invisible Unicode character reverses part of the name so "invoice‮fdp.exe" displays as "invoiceexe.pdf".' });
      found.push({ name, ext, issues });
    }
    return found;
  }

  // ── Headers / sender ───────────────────────────────────────────────────────

  function parseAddress(v) {
    if (!v) return null;
    const em = v.match(/<?([^\s<>"@]+@[^\s<>"]+?)>?\s*$/) || v.match(/([^\s<>"@]+@[^\s<>"]+)/);
    const email = em ? em[1].replace(/[>;,]+$/, '').toLowerCase() : '';
    const display = v.replace(/<[^>]*>/, '').replace(/"/g, '').trim();
    return { display: display === email ? '' : display, email, domain: email.split('@')[1] || '' };
  }

  // Header-looking lines *inside the body* are untrusted message content.
  // Only the initial RFC-style header block may influence sender/authentication
  // assessment. This still accepts header-only copies without a blank line.
  function headerBlock(text) {
    if (typeof text !== 'string' || !/^(?:From|Reply-To|Return-Path|To|Subject|Date|Authentication-Results|ARC-Authentication-Results|Received-SPF):[ \t]/i.test(text)) return '';
    const head = text.split(/\n[ \t]*\n/, 1)[0].slice(0, 65536);
    const lines = head.split('\n');
    const valid = /^[-A-Za-z0-9]+:[ \t]/;
    const continuation = /^[ \t]/;
    let end = 0;
    for (const line of lines) {
      if (!valid.test(line) && !(end && continuation.test(line))) break;
      end++;
    }
    return lines.slice(0, end).join('\n');
  }
  function getHeader(text, name) {
    const head = headerBlock(text);
    const re = new RegExp('^' + name + ':[ \t]*(.*(?:\n[ \t]+.*)*)', 'im');
    const m = head.match(re);
    return m ? m[1].replace(/\n[ \t]+/g, ' ').trim() : null;
  }

  function analyseHeaders(text) {
    const findings = [];
    const positives = [];
    const from = parseAddress(getHeader(text, 'From'));
    const replyTo = parseAddress(getHeader(text, 'Reply-To'));
    const returnPath = parseAddress(getHeader(text, 'Return-Path'));
    const auth = (getHeader(text, 'Authentication-Results') || '') + ' ' + (getHeader(text, 'ARC-Authentication-Results') || '') + ' ' + (getHeader(text, 'Received-SPF') || '');
    const add = (id, weight, title, detail, explain) => findings.push({ id, skill: 'headers', weight, title, evidence: [detail], explain, group: 'Sender' });

    if (from && from.domain) {
      const fromReg = registrableDomain(from.domain);
      if (replyTo && replyTo.domain && registrableDomain(replyTo.domain) !== fromReg)
        add('reply-to-mismatch', 20, 'Replies go to a different domain than the sender', `From: ${from.email} → Reply-To: ${replyTo.email}`,
          'If you hit "Reply", your answer goes to the attacker\'s mailbox instead of the person the email claims to be from.');
      if (returnPath && returnPath.domain && registrableDomain(returnPath.domain) !== fromReg)
        add('return-path-mismatch', 10, 'Return-Path differs from the From address', `From: ${from.email} · Return-Path: ${returnPath.email}`,
          'The technical "envelope" sender differs from the visible sender. Common for mailing services, but also for spoofed mail.');
      const lowDisp = (from.display || '').toLowerCase();
      const dispEmail = lowDisp.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/);
      if (dispEmail && dispEmail[0] !== from.email)
        add('display-email-spoof', 25, 'Display name contains a fake email address', `Shows "${from.display}" but the real address is ${from.email}`,
          'The name shown in your inbox contains an email address, but the actual sender is different. This is designed to fool you at a glance.');
      for (const brand of Object.keys(P.BRANDS)) {
        if (lowDisp.replace(/\s+/g, '').includes(brand) && !isOfficial(brand, fromReg)) {
          add('display-brand-mismatch', 25, 'Sender name claims a brand the address does not belong to', `"${from.display}" <${from.email}>`,
            `The sender's name says ${brand}, but the email address belongs to "${fromReg}".`);
          break;
        }
      }
      if (P.FREE_MAIL.includes(from.domain) && /(support|security|billing|payroll|helpdesk|help desk|service|admin|team|bank|ceo|director|hr|department|account)/i.test(lowDisp))
        add('freemail-org', 15, 'Organisation-style sender using a free email account', `"${from.display}" <${from.email}>`,
          'A company department or executive writing from a free webmail account (Gmail, Outlook.com…) is a strong sign of impersonation.');
      for (const iss of domainIssues(from.domain).filter(i => i.type !== 'abused-host'))
        add('sender-' + iss.type, iss.weight, 'Sender domain: ' + iss.title.toLowerCase(), iss.detail, 'The sender\'s own domain shows the same tricks used in fake links.');
    }
    const authRes = (k) => { const m = auth.match(new RegExp('\\b' + k + '\\s*=\\s*(\\w+)', 'i')); return m ? m[1].toLowerCase() : null; };
    const spf = authRes('spf') || (getHeader(text, 'Received-SPF') ? (getHeader(text, 'Received-SPF').match(/^(pass|fail|softfail|neutral|none)\b/i) || [])[1] : null);
    const dkim = authRes('dkim'), dmarc = authRes('dmarc');
    if (spf && /fail/.test(spf)) add('spf-fail', 18, 'SPF check failed', `spf=${spf}`, 'The supplied headers REPORT an SPF failure. Authentication-Results text can be forged; verify the result in your trusted receiving mail system.');
    if (dkim && /fail/.test(dkim)) add('dkim-fail', 15, 'DKIM signature failed', `dkim=${dkim}`, 'The supplied headers REPORT a DKIM failure. This app does not verify signatures; check trusted mail-gateway logs.');
    if (dmarc && /fail/.test(dmarc)) add('dmarc-fail', 22, 'DMARC check failed', `dmarc=${dmarc}`, 'The supplied headers REPORT a DMARC failure, not independently confirmed by this app. Inspect trusted receiver authentication results.');
    if (spf === 'pass' && dkim === 'pass' && dmarc === 'pass')
      positives.push('Supplied headers REPORT SPF, DKIM and DMARC pass; these are unverified claims, not proof of identity. Verify using your trusted mail provider and review the actual sender domain.');
    return { findings, positives, from, replyTo };
  }

  // ── Main entry point ───────────────────────────────────────────────────────

  /**
   * analyse(rawText, mode) → report
   * mode: 'email' (default) or 'voice' (a call transcript)
   */
  function analyse(rawText, mode, context) {
    mode = mode === 'voice' ? 'voice' : 'email';
    const INPUT_LIMIT = 512 * 1024;
    const supplied = typeof rawText === 'string' ? rawText : String(rawText || '');
    const truncated = supplied.length > INPUT_LIMIT;
    const limitedInput = truncated ? supplied.slice(0, INPUT_LIMIT) : supplied;
    // Long unbroken attacker-controlled tokens can cause quadratic work in
    // extraction regexes even when total input is bounded. Keep a prefix,
    // explicitly mark coverage incomplete and never pronounce a safe verdict.
    let longTokenCount = 0;
    const inspectedInput = limitedInput.replace(/\S{1025,}/g, token => {
      longTokenCount++;
      return token.slice(0, 1024) + ' ';
    });
    const { text, anchors, wasHtml } = normaliseInput(inspectedInput);
    const coverage = { complete: !truncated && !longTokenCount, inputCharacters: supplied.length,
      analysedCharacters: inspectedInput.length, messages: [] };
    if (truncated) coverage.messages.push('Only the first 512 KiB of input was inspected. Later indicators may have been missed.');
    if (longTokenCount) coverage.messages.push(longTokenCount + ' oversized unbroken token(s) shortened to protect the analyzer from resource exhaustion; hidden indicators may have been missed.');
    if (!coverage.complete) coverage.messages.push('This is a partial scan, NOT a safe verdict.');
    const findings = [];
    const spans = []; // where to highlight evidence in the text

    // 1) Language rules
    for (const rule of P.TEXT_RULES) {
      if (!rule.modes.includes(mode)) continue;
      const evidence = [];
      for (const re of rule.patterns) {
        for (const m of text.matchAll(re)) {
          if (evidence.length < 6 && !evidence.some(e => e.toLowerCase() === m[0].toLowerCase())) evidence.push(m[0].trim());
          spans.push({ start: m.index, end: m.index + m[0].length, skill: rule.skill, title: rule.title });
        }
      }
      if (evidence.length) {
        // A sign repeated many times is slightly more suspicious than one mention.
        const weight = Math.round(rule.weight * Math.min(1.4, 1 + (evidence.length - 1) * 0.1));
        findings.push({ id: rule.id, skill: rule.skill, weight, title: rule.title, evidence, explain: rule.explain, group: 'Language' });
      }
    }

    // 2) Links
    const urls = collectUrls(text, anchors);
    const linkGroups = {};
    for (const u of urls) {
      for (const iss of u.issues) {
        const g = linkGroups[iss.type] || (linkGroups[iss.type] = { id: 'url-' + iss.type, skill: 'links', weight: iss.weight, title: iss.title, evidence: [], explain: iss.detail, group: 'Links' });
        g.weight = Math.max(g.weight, iss.weight);
        if (g.evidence.length < 5 && !g.evidence.includes(u.raw)) g.evidence.push(u.raw);
      }
      if (u.issues.length && u.start >= 0) spans.push({ start: u.start, end: u.end, skill: 'links', title: 'Suspicious link' });
    }
    findings.push(...Object.values(linkGroups));

    // 3) Attachments (ignore anything inside URLs)
    let textNoUrls = text;
    for (const u of urls) if (u.start >= 0) textNoUrls = textNoUrls.slice(0, u.start) + ' '.repeat(u.end - u.start) + textNoUrls.slice(u.end);
    const attachments = mode === 'email' ? collectAttachments(textNoUrls) : [];
    const attGroups = {};
    for (const a of attachments) for (const iss of a.issues) {
      const g = attGroups[iss.type] || (attGroups[iss.type] = { id: iss.type, skill: 'attachments', weight: iss.weight, title: iss.title, evidence: [], explain: iss.detail, group: 'Attachments' });
      if (!g.evidence.includes(a.name)) g.evidence.push(a.name);
    }
    findings.push(...Object.values(attGroups));
    for (const a of attachments) if (a.issues.length) {
      const i = text.indexOf(a.name);
      if (i >= 0) spans.push({ start: i, end: i + a.name.length, skill: 'attachments', title: 'Risky attachment' });
    }

    // 4) Headers / sender
    const hdr = mode === 'email' ? analyseHeaders(text) : { findings: [], positives: [], from: null };
    findings.push(...hdr.findings);

    // 4b) Static HTML source, including MIME HTML retained by the .eml parser.
    const htmlSource = context && typeof context.html === 'string' && context.html.trim() ? context.html : (wasHtml ? inspectedInput : '');
    const htmlInvestigation = mode === 'email' && P.htmlSecurity ? P.htmlSecurity.inspect(htmlSource) : {findings:[],urls:[],truncated:false};
    for (const item of htmlInvestigation.findings) {
      findings.push({id:'html-'+item.type,skill:'links',weight:item.weight,title:item.title,
        evidence:item.url?[item.url]:[],explain:item.detail,group:'HTML source'});
    }
    // Independently evaluate URLs that HTML source contains, even if the plain
    // text representation omits them. Do not trust an anchor's displayed text.
    for (const rawUrl of [...new Set(htmlInvestigation.urls)].slice(0,50)) {
      if (urls.some(x=>x.raw===rawUrl)) continue;
      const u=analyseUrl(rawUrl);u.start=-1;u.end=-1;u.source='html'; urls.push(u);
      for (const item of u.issues) if (!findings.some(f=>f.id==='html-url-'+item.type))
        findings.push({id:'html-url-'+item.type,skill:'links',weight:item.weight,
          title:item.title,evidence:[rawUrl],explain:item.detail,group:'HTML source'});
    }
    // QR results are injected by an asynchronous, user-initiated local scan.
    const qrResults = context && Array.isArray(context.qrResults) ? context.qrResults.slice(0,12) : [];
    for (const qr of qrResults) if (qr && qr.url && typeof qr.value==='string') {
      const u=analyseUrl(qr.value);u.start=-1;u.end=-1;u.source='qr'; urls.push(u);
      findings.push({id:'qr-embedded-link',skill:'links',weight:0,title:'QR code contains a web link',
        evidence:[qr.value],explain:'The URL was decoded locally from image pixels without visiting it. A QR link alone does not prove phishing.',group:'QR code'});
      for (const item of u.issues) if (!findings.some(f=>f.id==='qr-'+item.type))
        findings.push({id:'qr-'+item.type,skill:'links',weight:item.weight,title:'QR: '+item.title,
          evidence:[qr.value],explain:item.detail,group:'QR code'});
    }


    // 5) Combinations that are much more dangerous together
    const has = id => findings.some(f => f.id === id);
    const hasSkill = s => findings.some(f => f.skill === s);
    const linkRisk = findings.some(f => f.group === 'Links' && f.weight >= 18);
    const combos = [];
    if ((has('password-request') || has('mfa-request')) && (linkRisk || hasSkill('headers')))
      combos.push({ id: 'combo-credential-harvest', title: 'Credential-harvesting pattern', weight: 15, explain: 'A request for your login or code combined with a suspicious link or sender is the textbook shape of a credential-phishing attack.' });
    if ((has('payment') || has('bank-change')) && (has('urgency') || has('secrecy') || has('authority')))
      combos.push({ id: 'combo-bec', title: 'Business Email Compromise (BEC) pattern', weight: 15, explain: 'Money requests combined with pressure, secrecy or a "boss" are the hallmark of CEO-fraud / BEC attacks.' });
    if ((has('invoice') || has('macros')) && findings.some(f => f.group === 'Attachments' && f.weight >= 20))
      combos.push({ id: 'combo-malware', title: 'Malware-delivery pattern', weight: 12, explain: 'An invoice-style lure combined with a risky attachment is a classic way to deliver malware such as ransomware loaders.' });
    if (mode === 'voice' && (has('mfa-request') || has('password-request') || has('card-details')) && (has('caller-authority') || has('brand')))
      combos.push({ id: 'combo-vishing', title: 'Impersonation + secret request', weight: 15, explain: 'A caller who claims authority and then asks for a secret (code, password, card details) is almost certainly a scammer.' });
    for (const c of combos) findings.push({ ...c, skill: 'pressure', evidence: [], group: 'Patterns' });

    // 6) Score: add up the weights, then squash into 0–100 so it never exceeds 100.
    const raw = findings.reduce((s, f) => s + f.weight, 0);
    const score = Math.round(100 * (1 - Math.exp(-raw / 55)));
    const level = score >= 70 ? 'Critical' : score >= 45 ? 'High' : score >= 20 ? 'Medium' : 'Low';
    findings.sort((a, b) => b.weight - a.weight);

    const skills = [...new Set(findings.map(f => f.skill))];
    return {
      mode, text, wasHtml, htmlInvestigation, qrResults, score, level, raw, findings, urls, attachments, coverage,
      headers: { from: hdr.from, positives: hdr.positives },
      spans, skills, iocs: extractIocs(text, urls, attachments, hdr.from), analysedAt: new Date().toISOString()
    };
  }

  // ── IOCs (for analysts) ────────────────────────────────────────────────────

  /** "Defang" makes an indicator unclickable so it can be shared safely: evil.com → evil[.]com */
  function defang(s) {
    return s.replace(/^http/i, 'hxxp').replace(/\./g, '[.]').replace(/@/g, '[@]').replace(/:\/\//, '[://]');
  }

  function extractIocs(text, urls, attachments, from) {
    const uniq = a => [...new Set(a.filter(Boolean))];
    const ips = uniq((text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).filter(ip => ip.split('.').every(n => +n <= 255)));
    const emails = uniq((text.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g) || []).map(e => e.toLowerCase()));
    const phones = uniq((text.match(/(?:\+|\b00)?\d[\d\s().-]{8,}\d\b/g) || []).map(p => p.trim()).filter(p => p.replace(/\D/g, '').length >= 9 && !/^\d{1,3}(\.\d{1,3}){3}$/.test(p)));
    const suspiciousUrls = urls.filter(u => u.issues.length).map(u => u.raw);
    return {
      urls: uniq(suspiciousUrls),
      domains: uniq(urls.filter(u => u.issues.length).map(u => u.host).concat(from && from.domain ? [from.domain] : [])),
      ips, emails, phones,
      files: uniq(attachments.filter(a => a.issues.length).map(a => a.name))
    };
  }

  Object.assign(P, { analyse, defang, registrableDomain, levenshtein, analyseUrl, normaliseInput });
})(typeof window !== 'undefined' ? window : globalThis);
