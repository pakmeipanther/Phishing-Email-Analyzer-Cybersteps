/*
 * eml.js — a small, hand-written reader for .eml files (MIME email messages).
 *
 * What it does, in plain English:
 *   An .eml file is just text: a block of headers, a blank line, then the body.
 *   Real emails are often "multipart": the body is split into labelled parts
 *   (plain text, HTML, attachments) separated by a boundary string, and each part
 *   may be encoded (base64 or quoted-printable) so it survives old mail systems.
 *   parseEml() unwraps all of that and returns ONE block of plain text, laid out like
 *   a pasted email ("From: …", "Subject: …", blank line, body), which is exactly
 *   what P.analyse() already knows how to read. No detection logic lives here.
 *
 * No libraries, no network. It only handles text it is given, so it never opens,
 * runs or renders anything inside the email.
 *
 * Not handled on purpose (keeps it small): RFC 2231 multi-line parameter
 * continuations, S/MIME and PGP, TNEF (winmail.dat) and decoding attachment contents.
 */
(function (root) {
  'use strict';
  const P = root.PEA;

  // Only the headers the analyser can use are copied into the text box.
  // Received: and X- headers are long and noisy, so they are left out.
  const KEEP = {
    'from': 'From', 'reply-to': 'Reply-To', 'return-path': 'Return-Path', 'to': 'To',
    'subject': 'Subject', 'date': 'Date', 'authentication-results': 'Authentication-Results',
    'arc-authentication-results': 'ARC-Authentication-Results', 'received-spf': 'Received-SPF'
  };
  const MAX_DEPTH = 8;
  const MAX_INPUT_BYTES = 25 * 1024 * 1024;
  const MAX_MIME_PARTS = 250;
  const MAX_BODY_CHARS = 512 * 1024; // a hostile file could nest parts forever; stop after this many levels
  const HEADER_NAME = '[\\x21-\\x39\\x3b-\\x7e]+'; // printable ASCII except ":" (RFC 5322)

  // ── Bytes → text ───────────────────────────────────────────────────────────
  // The file is read as raw bytes and held in a "binary string" (one character per
  // byte, 0–255). That keeps every byte intact until we know the right character set
  // (UTF-8, ISO-8859-1, …) for each part, which the part's own headers tell us.

  function decodeBytes(binary, charset) {
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) & 255;
    try { return new TextDecoder(charset || 'utf-8').decode(bytes); }
    catch (e) { return new TextDecoder('utf-8').decode(bytes); } // unknown charset name
  }

  function toBinary(input) {
    if (typeof input === 'string') return input;
    const bytes = new Uint8Array(input);
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return s;
  }

  // ── Content-Transfer-Encodings ─────────────────────────────────────────────

  function fromBase64(s) {
    try { return atob(s.replace(/[^A-Za-z0-9+/]/g, '')); } catch (e) { return s; }
  }

  /** "caf=C3=A9" → bytes C3 A9. */
  const unescapeEquals = s => s.replace(/=([0-9a-f]{2})/gi, (_, x) => String.fromCharCode(parseInt(x, 16)));

  /** Body version: a "=" at the end of a line is a soft line break, and trailing spaces on a line are not content. */
  const fromQuotedPrintable = s => unescapeEquals(s.replace(/[ \t]+$/gm, '').replace(/=\n/g, ''));

  function decodeBody(body, cte, charset) {
    cte = (cte || '').toLowerCase().trim();
    const bin = cte === 'base64' ? fromBase64(body) : cte === 'quoted-printable' ? fromQuotedPrintable(body) : body;
    return decodeBytes(bin, charset);
  }

  // ── Headers ────────────────────────────────────────────────────────────────

  /** Header values may contain =?UTF-8?B?...?= "encoded words" (RFC 2047). Turn them back into text. */
  function headerText(v) {
    return decodeBytes(v, 'utf-8')
      .replace(/(\?=)\s+(?==\?)/g, '$1') // whitespace between two encoded words is not shown
      .replace(/=\?([^?\s]+)\?([bq])\?([^?\s]*)\?=/gi, (all, cs, enc, data) =>
        decodeBytes(enc.toLowerCase() === 'b' ? fromBase64(data) : unescapeEquals(data.replace(/_/g, ' ')), cs.split('*')[0]));
  }

  /** Header block → [[lowercase-name, raw value], …]. A line starting with space/tab continues the previous one. */
  function parseHeaders(head) {
    const out = [];
    for (const line of head.replace(/\n[ \t]+/g, ' ').split('\n')) {
      const m = line.match(new RegExp('^(' + HEADER_NAME + '):[ \\t]*(.*)$'));
      if (m) out.push([m[1].toLowerCase(), m[2].trim()]);
    }
    return out;
  }

  const getHeader = (hs, name) => (hs.find(x => x[0] === name) || [])[1];

  /** 'multipart/mixed; boundary="abc"; charset=utf-8' → { type: 'multipart/mixed', params: { boundary: 'abc', … } } */
  function parseValue(v) {
    v = v || '';
    const type = ((v.match(/^\s*([^;\s]*)/) || [])[1] || '').toLowerCase();
    const params = {};
    const re = /;\s*([^=\s;]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;\s]*))/g;
    let m;
    while ((m = re.exec(v))) params[m[1].toLowerCase()] = m[2] != null ? m[2].replace(/\\(.)/g, '$1') : m[3];
    return { type, params };
  }

  /** A file name can be plain, RFC 2047 encoded, or RFC 2231 (filename*=utf-8''%E2%82%AC.pdf). */
  function paramText(params, key) {
    const star = params[key + '*'];
    if (star) {
      const m = star.match(/^([^']*)'[^']*'(.*)$/);
      if (m) return decodeBytes(m[2].replace(/%([0-9a-f]{2})/gi, (_, x) => String.fromCharCode(parseInt(x, 16))), m[1]);
    }
    return params[key] != null ? headerText(params[key]) : '';
  }

  /** Headers and body are separated by the first blank line. No header-looking first line = all body. */
  function splitHead(s) {
    if (!new RegExp('^' + HEADER_NAME + ':').test(s)) return ['', s.startsWith('\n') ? s.slice(1) : s];
    const i = s.indexOf('\n\n');
    return i < 0 ? [s, ''] : [s.slice(0, i), s.slice(i + 2)];
  }

  // ── Multipart ──────────────────────────────────────────────────────────────

  /** Cut a multipart body at its "--boundary" lines. Text before the first / after the closing one is ignored. */
  function splitMultipart(body, boundary) {
    const parts = [];
    let cur = null;
    for (const line of body.split('\n')) {
      const t = line.replace(/[ \t]+$/, '');
      if (t === '--' + boundary + '--') break;
      if (t === '--' + boundary) { if (cur) parts.push(cur.join('\n')); cur = []; }
      else if (cur) cur.push(line);
    }
    if (cur) parts.push(cur.join('\n')); // forgive a missing closing boundary
    return parts;
  }

  const newBag = () => ({ headers: null, plain: [], html: [], files: [], images: [], inner: [], budget: {parts:0, limited:false, chars:0} });

  /** Walk one MIME entity (a whole message, or one part of it), filling `bag` with what it finds. */
  function walk(raw, depth, bag) {
    if (++bag.budget.parts > MAX_MIME_PARTS) { bag.budget.limited = true; return; }
    const [head, body] = splitHead(raw);
    const hs = parseHeaders(head);
    if (!bag.headers) bag.headers = hs;
    const ct = parseValue(getHeader(hs, 'content-type') || 'text/plain');
    const cd = parseValue(getHeader(hs, 'content-disposition'));

    if (ct.type.startsWith('multipart/')) {
      if (depth < MAX_DEPTH && ct.params.boundary)
        for (const part of splitMultipart(body, ct.params.boundary)) walk(part, depth + 1, bag);
      return;
    }
    if (ct.type === 'message/rfc822') { // a forwarded-as-attachment email: read it as its own message
      if (depth < MAX_DEPTH) { const sub = newBag(); walk(body, depth + 1, sub); bag.inner.push(sub); }
      return;
    }
    // Local QR inspection can optionally use small supported inline/attached
    // images. Never execute attachments or load external image resources.
    if (/^image\/(png|jpeg|webp|gif)$/.test(ct.type) && bag.images.length < 4) {
      const encoded = getHeader(hs, 'content-transfer-encoding');
      if ((encoded||'').toLowerCase().trim() === 'base64' && body.length <= 4*1024*1024) {
        const bytes = fromBase64(body);
        if (bytes.length > 0 && bytes.length <= 3*1024*1024) {
          const data = new Uint8Array(bytes.length);
          for (let i=0; i<bytes.length; i++) data[i] = bytes.charCodeAt(i)&255;
          bag.images.push({mime:ct.type, filename:paramText(cd.params,'filename')||paramText(ct.params,'name')||'inline image', bytes:data});
        }
      }
    }
    if (/^text\/(plain|html)$/.test(ct.type) && cd.type !== 'attachment') {
      const text = decodeBody(body, getHeader(hs, 'content-transfer-encoding'), ct.params.charset);
      const remaining = Math.max(0, MAX_BODY_CHARS - bag.budget.chars);
      if (text.length > remaining) bag.budget.limited = true;
      if (remaining) (ct.type === 'text/html' ? bag.html : bag.plain).push(text.slice(0, remaining));
      bag.budget.chars += Math.min(text.length, remaining);
      return;
    }
    const name = paramText(cd.params, 'filename') || paramText(ct.params, 'name');
    if (name) bag.files.push(name);
  }

  // ── HTML → text ────────────────────────────────────────────────────────────

  function decodeEntities(s) {
    const cp = n => (n > 0x10ffff ? '' : String.fromCodePoint(n));
    return s.replace(/&nbsp;/gi, ' ').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
      .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
      .replace(/&#(\d+);/g, (_, n) => cp(+n))
      .replace(/&#x([0-9a-f]+);/gi, (_, n) => cp(parseInt(n, 16)))
      .replace(/&amp;/gi, '&');
  }

  /**
   * Strip tags from an HTML-only email. Links are kept as "shown text <real address>",
   * because deleting the href would hide the very thing phishing relies on: where a link
   * really goes. The analyser already understands that plain-text form.
   * (\u0001 and \u0002 stand in for "<" and ">" until the other tags are gone.)
   */
  function htmlToText(html) {
    const text = html
      .replace(/<(script|style|head)\b[\s\S]*?<\/\1\s*>/gi, ' ')
      .replace(/<a\b[^>]*?\bhref\s*=\s*(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a\s*>/gi, (all, q, href, inner) => {
        const shown = decodeEntities(inner.replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
        href = decodeEntities(href).trim();
        if (!/^https?:\/\//i.test(href) || shown === href) return ' ' + (shown || '') + ' ';
        return ' ' + shown + ' \u0001' + href + '\u0002 ';
      })
      .replace(/<br\s*\/?>|<\/(p|div|tr|li|h\d)>/gi, '\n')
      .replace(/<[^>]+>/g, ' ');
    return decodeEntities(text).replace(/[ \t]+/g, ' ').replace(/ ?\n ?/g, '\n').replace(/\n{3,}/g, '\n\n')
      .replace(/\u0001/g, '<').replace(/\u0002/g, '>').trim();
  }

  // ── Main entry point ───────────────────────────────────────────────────────

  /**
   * parseEml(input) → { text, source, files }
   *   input  : an ArrayBuffer (from FileReader) or a binary string
   *   text   : headers + blank line + body (+ "Attachment: name" lines), ready for P.analyse()
   *   source : which body was used: 'text/plain', 'text/html' or 'none'
   *   files  : attachment names found
   */
  function parseEml(input) {
    if (input && (input.byteLength || input.length || 0) > MAX_INPUT_BYTES) throw new RangeError('Email exceeds 25 MiB safety limit');
    const raw = toBinary(input).replace(/\r\n?/g, '\n').replace(/^From \S+ +\w{3} \w{3} +\d[^\n]*\n/, ''); // drop an mbox "From " line

    let bag = newBag();
    walk(raw, 0, bag);
    const files = bag.files.slice();
    // "Forward as attachment" wraps the real email inside the one you received. Use the inner one.
    while (!bag.plain.some(t => t.trim()) && !bag.html.some(t => t.trim()) && bag.inner.length) {
      bag = bag.inner[0];
      files.push(...bag.files);
    }

    const plain = bag.plain.map(t => t.trim()).filter(Boolean);
    const html = bag.html.map(htmlToText).filter(Boolean);
    const body = (plain.length ? plain : html).join('\n\n');
    const htmlSource = bag.html.join('\n\n');
    const source = plain.length ? 'text/plain' : html.length ? 'text/html' : 'none';

    // Headers are untrusted too: an encoded word could decode to "x\nReply-To: …" and fake a
    // second header line, so every value is flattened to a single line.
    const oneLine = s => s.replace(/[\r\n]+/g, ' ').trim();
    const lines = [];
    for (const [k, v] of bag.headers || []) if (KEEP[k]) lines.push(KEEP[k] + ': ' + oneLine(headerText(v)));
    const names = [...new Set(files.map(oneLine).filter(Boolean))];

    const text = [lines.join('\n'), body, names.map(n => 'Attachment: ' + n).join('\n')].filter(Boolean).join('\n\n');
    return { text, source, files: names, html: htmlSource, images: bag.images, limited: bag.budget.limited }; 
  }

  Object.assign(P, { parseEml });
})(typeof window !== 'undefined' ? window : globalThis);
