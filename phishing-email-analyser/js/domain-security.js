/*
 * domain-security.js — offline domain-impersonation investigation (Cybersteps extension).
 *
 * Threat model: visually deceptive hostnames and brand impersonation in URLs or
 * email sender addresses. Never dereferences a URL, queries DNS, or sends data.
 *
 * Standards-informed, NOT a full UTS #39 conformant implementation. A deliberately
 * audited, small confusable mapping targets common Latin-brand substitutions.
 * See ../README.md for the exact scope, test evidence and limitations.
 *
 * Public API: PEA.domainSecurity.inspect(host, registrableDomain, brands)
 *             PEA.domainSecurity.issues(host, registrableDomain, brands)
 */
(function (root) {
  'use strict';
  const P = root.PEA || (root.PEA = {});

  // Add only verified domains. Demo organisation's actual domain was not given.
  // Example after verifying ownership: { cybersteps: ['cybersteps.example'] }.
  const ADDITIONAL_TRUSTED_DOMAINS = Object.freeze({});

  // Small, explicitly non-exhaustive, reviewed map inspired by UTS #39 confusables.
  // Each entry maps a visual substitute to a Latin letter; do not use this for
  // general Unicode identifiers, and do not call it the full UTS #39 skeleton.
  const CONFUSABLE_GROUPS = Object.freeze({
    a: 'аАαΑɑᎪ',
    b: 'ЬΒВᏴ',
    c: 'сСϲϹⅽ',
    d: 'ԁⅾ',
    e: 'еЕεΕҽ℮',
    g: 'ɡԍ',
    h: 'һҺнН',
    i: 'іІιΙıӏⅠ',
    j: 'јЈϳ',
    k: 'кКκΚ',
    l: 'ӏӀⅼӀ',
    m: 'мМϻ',
    n: 'ոΝ',
    o: 'оОοΟօ',
    p: 'рРρΡ',
    q: 'ԛԚ',
    s: 'ѕЅ',
    t: 'тТτΤ',
    u: 'υՍ',
    v: 'ѵν',
    w: 'ԝԜѡ',
    x: 'хХχΧ',
    y: 'уУγΥү',
    z: 'ᴢ'
  });
  const confusables = new Map();
  for (const [latin, characters] of Object.entries(CONFUSABLE_GROUPS)) {
    for (const ch of characters) confusables.set(ch, latin);
  }

  // Only significant scripts in the *same label* should be compared. TLD script
  // and brand script need not match. Japanese multi-script labels are common.
  const SCRIPTS = [
    'Latin', 'Cyrillic', 'Greek', 'Armenian', 'Hebrew', 'Arabic',
    'Han', 'Hiragana', 'Katakana', 'Hangul', 'Devanagari', 'Thai', 'Georgian'
  ].map(name => ({ name, re: new RegExp('\\p{Script=' + name + '}', 'u') }));
  const IGNORABLE = /[\p{Script=Common}\p{Script=Inherited}]/u;
  const NONASCII = /[^\x00-\x7f]/;
  const MAX_HOST_LENGTH = 253;

  // RFC 3492 decoder. Strict limits protect interactive analysis from hostile
  // oversized/malformed input. URL() handles URL/IDNA validation separately.
  function adapt(delta, points, first) {
    delta = first ? Math.floor(delta / 700) : Math.floor(delta / 2);
    delta += Math.floor(delta / points);
    let k = 0;
    while (delta > 455) { delta = Math.floor(delta / 35); k += 36; }
    return k + Math.floor(36 * delta / (delta + 38));
  }
  function digit(ch) {
    const x = ch.charCodeAt(0);
    if (x >= 48 && x <= 57) return x - 22;
    if (x >= 65 && x <= 90) return x - 65;
    if (x >= 97 && x <= 122) return x - 97;
    return -1;
  }
  function decodeLabel(label) {
    if (!/^xn--/i.test(label)) return label;
    const payload = label.slice(4).toLowerCase();
    if (!payload || label.length > 63 || !/^[a-z0-9-]+$/.test(payload)) return null;
    const lastDash = payload.lastIndexOf('-');
    const basic = lastDash >= 0 ? payload.slice(0, lastDash) : '';
    if (/[^\x00-\x7f]/.test(basic)) return null;
    const out = Array.from(basic);
    let n = 128, i = 0, bias = 72, index = lastDash >= 0 ? lastDash + 1 : 0;
    if (index >= payload.length) return null;
    while (index < payload.length) {
      const old = i;
      let weight = 1;
      for (let k = 36; ; k += 36) {
        if (index >= payload.length) return null;
        const d = digit(payload[index++]);
        if (d < 0 || weight > Number.MAX_SAFE_INTEGER / 36) return null;
        i += d * weight;
        if (!Number.isSafeInteger(i)) return null;
        const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
        if (d < t) break;
        weight *= (36 - t);
        if (!Number.isSafeInteger(weight)) return null;
      }
      const length = out.length + 1;
      bias = adapt(i - old, length, old === 0);
      n += Math.floor(i / length);
      i %= length;
      if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff)) return null;
      out.splice(i, 0, String.fromCodePoint(n));
      i++;
      if (out.length > 63) return null;
    }
    return out.join('');
  }

  function decodeHost(host) {
    if (typeof host !== 'string' || host.length > MAX_HOST_LENGTH || !host) return null;
    const labels = host.toLowerCase().replace(/\.$/, '').split('.');
    if (labels.some(x => !x || x.length > 63)) return null;
    const decoded = labels.map(decodeLabel);
    if (decoded.some(x => x === null)) return null;
    return decoded.join('.');
  }

  function scripts(label) {
    const detected = new Set();
    for (const ch of label) {
      if (IGNORABLE.test(ch)) continue;
      for (const s of SCRIPTS) {
        if (s.re.test(ch)) { detected.add(s.name); break; }
      }
    }
    return [...detected];
  }

  function visualSkeleton(label) {
    // NFD also makes Latin diacritic lookalikes comparable to ASCII. This is
    // only used for comparisons against explicitly configured protected brands.
    // Data-driven ICU/UTS #39 mapping snapshot. Full UTS #39 conformance
    // additionally needs version-aligned case folding and restriction rules.
    const mapping = P.confusableMappings || {};
    return Array.from(label.toLowerCase().normalize('NFD'))
      .map(ch => confusables.get(ch) || (Object.prototype.hasOwnProperty.call(mapping, ch) ? mapping[ch] : ch))
      .join('').normalize('NFD').replace(/\p{Mark}/gu, '');
  }

  function unicodeEvidence(label) {
    const chars = [];
    for (const ch of label) {
      if (!NONASCII.test(ch)) continue;
      const script = SCRIPTS.find(s => s.re.test(ch));
      chars.push(`${ch} (U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}, ${script ? script.name : 'Other'})`);
      if (chars.length === 8) break;
    }
    return chars.join('; ');
  }

  function trustedCatalog(brands) {
    const merged = Object.assign({}, brands || P.BRANDS || {}, ADDITIONAL_TRUSTED_DOMAINS);
    return Object.entries(merged).filter(([name, domains]) =>
      /^[a-z0-9-]{3,32}$/.test(name) && Array.isArray(domains))
      .map(([name, domains]) => ({ name, domains: domains.map(d => String(d).toLowerCase().replace(/\.$/, '')) }));
  }

  function officialHost(host, domains) {
    return domains.some(d => host === d || host.endsWith('.' + d));
  }

  // When websites provide tenant subdomains (paypa1.github.io), the attacker's
  // registered identity is the label directly left of the hosting platform.
  function candidateLabels(host, reg) {
    const entries = [];
    const normal = reg.split('.')[0];
    if (normal) entries.push(normal);
    const providers = (P.ABUSED_HOSTS || []).slice().sort((a, b) => b.length - a.length);
    for (const provider of providers) {
      if (host.endsWith('.' + provider)) {
        const prefix = host.slice(0, -provider.length - 1).split('.');
        const tenant = prefix[prefix.length - 1];
        if (tenant && tenant !== normal) entries.push(tenant);
        break;
      }
    }
    return [...new Set(entries)];
  }

  function inspect(inputHost, registrable, brands) {
    const asciiHost = String(inputHost || '').toLowerCase().replace(/\.$/, '');
    const unicodeHost = decodeHost(asciiHost);
    const result = { asciiHost, unicodeHost, issues: [], labels: [], standard: 'ICU confusable skeleton snapshot + UTS #39-inspired checks; not full conformance' };
    if (!unicodeHost || asciiHost.length > MAX_HOST_LENGTH || !registrable) return result;
    const catalog = trustedCatalog(brands);
    const reg = String(registrable).toLowerCase();
    const hostLabels = unicodeHost.split('.');
    const asciiLabels = asciiHost.split('.');
    const candidates = candidateLabels(asciiHost, reg).map(label => {
      const position = asciiLabels.lastIndexOf(label);
      return { ascii: label, unicode: position >= 0 ? hostLabels[position] : decodeLabel(label) };
    }).filter(c => c.unicode);
    // Inspect all non-TLD labels as well: a confusable *subdomain* such as
    // miсrosoft.com.evil.example must not evade detection merely because the
    // registrable label (evil) contains no brand. Keep tenant information
    // separately because its ownership semantics depend on hosting providers.
    const allLabels = asciiLabels.slice(0, -1).map((ascii, i) => ({ ascii, unicode: hostLabels[i] }));
    const candidateSet = new Set(candidates.map(c => c.ascii + '/' + c.unicode));
    for (const c of allLabels) {
      if (!candidateSet.has(c.ascii + '/' + c.unicode)) {
        candidates.push(c);
        candidateSet.add(c.ascii + '/' + c.unicode);
      }
    }
    const seen = new Set();
    function add(type, weight, title, detail, technique) {
      if (seen.has(type)) return;
      seen.add(type);
      result.issues.push({ type, weight, title, detail, technique });
    }

    const safeOfficial = catalog.some(b => officialHost(asciiHost, b.domains));
    for (const candidate of candidates) {
      const label = candidate.unicode;
      const usedScripts = scripts(label);
      result.labels.push({ label, scripts: usedScripts });
      const mixture = usedScripts.includes('Latin') &&
        (usedScripts.includes('Cyrillic') || usedScripts.includes('Greek')) ||
        usedScripts.includes('Cyrillic') && usedScripts.includes('Greek');
      if (mixture && !safeOfficial) {
        add('unicode-mixed-script', 20, 'Mixed-script hostname label',
          `The label "${label}" mixes ${usedScripts.join(', ')} characters. ${unicodeEvidence(label)}. A script mixture can hide substitutions, but is not proof of phishing.`,
          'Unicode mixed-script spoofing');
      }
      if (safeOfficial) continue;
      const skeleton = visualSkeleton(label);
      for (const brand of catalog) {
        if (officialHost(asciiHost, brand.domains)) continue;
        if (label.toLowerCase() !== brand.name && skeleton === visualSkeleton(brand.name) &&
            // Protect against falsely suggesting that an all-ASCII typo is Unicode.
            (NONASCII.test(label) || /^xn--/.test(candidate.ascii))) {
          const whole = usedScripts.length === 1 && !usedScripts.includes('Latin');
          const technique = whole ? 'Whole-script Unicode homograph' : 'Unicode confusable / IDN homograph';
          add('unicode-brand-confusable', 35, 'Unicode domain impersonates ' + brand.name,
            `"${unicodeHost}" contains label "${label}" visually resembling "${brand.name}". ` +
            `The actual hostname is "${asciiHost}" and it is not in the trusted-domain list for ${brand.name}. ` +
            `Characters: ${unicodeEvidence(label)}. Verify using a known trusted address; visual similarity is not proof of ownership.`, technique);
          break;
        }
      }
    }
    // Typosquatted *tenant names* are otherwise missed because a private
    // hosting suffix (e.g. github.io) makes the normal registered-domain
    // heuristic see "github", not the attacker-controlled "paypa1".
    // Reuse a bounded edit-distance test only for the special tenant label;
    // normal registered-domain typo detection remains in analyser.js.
    function distanceAtMost(a, b, limit) {
      if (Math.abs(a.length - b.length) > limit) return false;
      let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
      for (let i = 1; i <= a.length; i++) {
        const current = [i];
        let minimum = current[0];
        for (let j = 1; j <= b.length; j++) {
          current[j] = Math.min(previous[j] + 1, current[j - 1] + 1,
            previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
          minimum = Math.min(minimum, current[j]);
        }
        if (minimum > limit) return false;
        previous = current;
      }
      return previous[b.length] <= limit;
    }
    const hosted = (P.ABUSED_HOSTS || []).filter(p => asciiHost.endsWith('.' + p))
      .sort((a, b) => b.length - a.length)[0];
    if (!safeOfficial && hosted) {
      const tenant = asciiHost.slice(0, -hosted.length - 1).split('.').pop();
      for (const brand of catalog) {
        if (tenant === brand.name) {
          add('hosted-brand-claim', 18, 'Protected brand used as hosted tenant name',
            `"${asciiHost}" uses "${brand.name}" as a tenant on a third-party service. This alone does not establish who controls that tenant; verify independently.`,
            'Hosted-page brand impersonation');
          break;
        }
        if (brand.name.length >= 6 && tenant.length >= 4 && tenant !== brand.name &&
            distanceAtMost(tenant, brand.name, brand.name.length >= 8 ? 2 : 1)) {
          add('hosted-tenant-lookalike', 27, 'Look-alike brand on a hosted subdomain',
            `The tenant label "${tenant}" on "${asciiHost}" closely resembles "${brand.name}", ` +
            `but the site is hosted under a third-party domain, not an official ${brand.name} domain.`,
            'Hosted-service typosquatting');
          break;
        }
      }
    }
    // A domain containing a fully trusted host as its *prefix* may mislead
    // users: paypal.com.attacker.example is controlled by attacker.example.
    if (!safeOfficial) {
      outer: for (const brand of catalog) {
        for (const domain of brand.domains) {
          if (asciiHost.startsWith(domain + '.') || asciiHost.includes('.' + domain + '.')) {
            add('embedded-trusted-host', 28, 'Trusted domain embedded inside another hostname',
              `"${asciiHost}" includes "${domain}", but the effective hostname is still "${asciiHost}" ` +
              `and the estimated registered domain is "${reg}". This is not a subdomain of ${domain}.`,
              'Domain shadowing / deceptive subdomain');
            break outer;
          }
        }
      }
    }
    // An IDN only gets a Punycode-specific *scoring* signal in the context of
    // a demonstrated unicode impersonation, not simply for being international.
    if (asciiLabels.some(l => l.startsWith('xn--')) && result.issues.some(i => i.type === 'unicode-brand-confusable')) {
      add('punycode', 9, 'Punycode encodes a brand lookalike',
        `The ASCII hostname "${asciiHost}" decodes to "${unicodeHost}". Punycode itself is normal for internationalized domains; the visual similarity to a protected brand is the concern.`,
        'IDN / Punycode homograph');
    }
    return result;
  }

  Object.freeze(ADDITIONAL_TRUSTED_DOMAINS);
  P.domainSecurity = Object.freeze({ inspect, issues: (host, reg, brands) => inspect(host, reg, brands).issues,
    decodeHost, decodeLabel, scripts, visualSkeleton });
})(typeof window !== 'undefined' ? window : globalThis);
