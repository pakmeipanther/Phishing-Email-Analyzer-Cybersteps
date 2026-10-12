/*
 * url-security.js — offline inspection of URLs nested inside redirect parameters.
 * Security boundary: NO fetching, navigation, DNS resolution, or link execution.
 * Analyze one redirect layer to avoid adversarial recursion / decompression.
 * A redirect parameter is a clue, not proof a server performs redirection.
 */
(function(root) {
  'use strict';
  const P = root.PEA || (root.PEA = {});
  const KEYS = new Set(['url','u','target','dest','destination','redirect','redirect_uri',
    'redirect_url','return','returnurl','return_url','next','continue','goto','to']);
  // Inspect a bounded chain of embedded links. This is static inspection, NOT
  // verification of redirects. The explicit budgets make attacker-controlled
  // deeply nested or heavily encoded links inexpensive to process.
  const MAX_URL = 4096, MAX_PARAMS = 40, MAX_CANDIDATES = 6;
  const MAX_DEPTH = 3, MAX_TOTAL_VISITS = 12, MAX_DECODE_PASSES = 2;
  const LOGIN_PATH = /(?:login|sign-?in|verify|password|mfa|reset|account)/i;

  function parseCandidate(value) {
    let candidate = value.trim();
    for (let attempt = 0; attempt <= MAX_DECODE_PASSES; attempt++) {
      if (candidate.length > MAX_URL) return null;
      // Protocol-relative references are not followed; resolving them would
      // require assumptions about which service performs the redirect.
      if (/^https?:\/\//i.test(candidate)) {
        try {
          const parsed = new URL(candidate);
          return ['https:', 'http:'].includes(parsed.protocol) ? parsed : null;
        } catch (_) { return null; }
      }
      if (!/%[a-f0-9]{2}/i.test(candidate)) return null;
      try {
        const next = decodeURIComponent(candidate);
        if (next === candidate) return null;
        candidate = next;
      } catch (_) { return null; }
    }
    return null;
  }

  function inspect(input, brands) {
    const findings = [], observed = new Set();
    if (typeof input !== 'string' || input.length > MAX_URL) return findings;
    let outer;
    try { outer = new URL(input); } catch (_) { return findings; }
    if (!['http:', 'https:'].includes(outer.protocol)) return findings;
    const queue = [{url:outer, depth:0, path:[]}];
    const visited = new Set([outer.href]);
    let totalVisits = 0;
    while (queue.length && totalVisits < MAX_TOTAL_VISITS) {
      const current = queue.shift();
      totalVisits++;
      if (current.depth >= MAX_DEPTH) continue;
      let count = 0, checked = 0;
      for (const [key, value] of current.url.searchParams) {
        if (++count > MAX_PARAMS || checked >= MAX_CANDIDATES) break;
        if (!KEYS.has(key.toLowerCase()) || value.length > MAX_URL) continue;
        const inner = parseCandidate(value);
        if (!inner) continue;
        checked++;
        if (inner.origin === current.url.origin) continue;
        const host = inner.hostname.toLowerCase();
        const chain = [...current.path, key];
        const lookalikes = P.domainSecurity && P.domainSecurity.issues(host,
          P.registrableDomain ? P.registrableDomain(host) : host, brands)
          .filter(x => ['unicode-brand-confusable', 'embedded-trusted-host',
            'hosted-tenant-lookalike', 'hosted-brand-claim', 'unicode-mixed-script'].includes(x.type));
        if (lookalikes && lookalikes.length) {
          const type = 'nested-redirect-impersonation';
          const signature = type + '|' + host;
          if (!observed.has(signature)) {
            observed.add(signature);
            findings.push({ type, weight:26,
              title:'Embedded URL chain contains a potential impersonation hostname',
              detail:`Parameter chain "${chain.join(' → ')}" embeds hostname "${host}" ` +
                `with ${lookalikes.map(x=>x.type).join(', ')} (depth ${current.depth + 1}). ` +
                `The application has NOT followed this URL or verified redirection.`,
              technique:'Nested URL laundering / brand impersonation candidate' });
          }
        } else if (LOGIN_PATH.test(inner.pathname) && !observed.has('login|' + host)) {
          observed.add('login|' + host);
          findings.push({ type:'nested-external-login', weight:9,
            title:'Embedded URL points to an external login-like page',
            detail:`Parameter chain "${chain.join(' → ')}" includes hostname "${host}" ` +
              `and a security-related path. The redirect is unconfirmed; this may be ` +
              `legitimate, including authorization and identity-provider flows.`,
            technique:'Potential redirect-based phishing' });
        }
        // Do not request, resolve, or dereference nested links.
        if (!visited.has(inner.href) && visited.size < MAX_TOTAL_VISITS) {
          visited.add(inner.href);
          queue.push({ url:inner, depth:current.depth + 1, path:chain });
        }
      }
    }
    return findings;
  }
  P.urlSecurity = Object.freeze({inspect});
})(typeof window !== 'undefined' ? window : globalThis);
