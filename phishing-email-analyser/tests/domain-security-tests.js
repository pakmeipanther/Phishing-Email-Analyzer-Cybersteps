'use strict';
/*
 * Cybersteps security regression suite — offline, synthetic threat cases.
 * These are not representative population samples and MUST NOT be published as
 * measured real-world phishing detection rates. Every URL remains plain text.
 */
const assert = require('node:assert/strict');
require('../js/rules.js');
require('../js/psl-data.js');
require('../js/public-suffix.js');
require('../js/confusables-data.js');
require('../js/domain-security.js');
require('../js/analyser.js');
const P = globalThis.PEA;
let passed = 0;
let failed = 0;
function test(name, fn) {
  try { fn(); passed++; process.stdout.write('  ✓ ' + name + '\n'); }
  catch (e) { failed++; process.stderr.write('  ✗ ' + name + ': ' + e.message + '\n'); }
}
const has = (url, id) => P.analyseUrl(url).issues.some(i => i.type === id);
const ids = report => report.findings.map(f => f.id);

console.log('\nUnicode / IDN brand impersonation');
const adversarial = [
  ['Cyrillic c in microsoft', 'https://miсrosoft.com/login', 'unicode-brand-confusable'],
  ['Cyrillic o in microsoft', 'https://microsоft.com/login', 'unicode-brand-confusable'],
  ['Cyrillic a in paypal', 'https://pаypal.com', 'unicode-brand-confusable'],
  ['Cyrillic a in amazon', 'https://аmazon.com', 'unicode-brand-confusable'],
  ['Greek o in google', 'https://gοogle.com', 'unicode-brand-confusable'],
  ['Cyrillic Apple whole-script', 'https://аррӏе.com', 'unicode-brand-confusable'],
  ['Cyrillic PayPal whole-script', 'https://раураӏ.com', 'unicode-brand-confusable'],
  ['Unicode lookalike hidden in subdomain', 'https://miсrosoft.com.evil.example', 'unicode-brand-confusable'],
  ['Unicode lookalike two labels deep', 'https://login.miсrosoft.evil.example', 'unicode-brand-confusable'],
  ['punycode Apple', 'https://xn--pple-43d.com', 'unicode-brand-confusable'],
  ['Latin accented Google', 'https://góogle.com', 'unicode-brand-confusable'],
  ['mixed-script brand on unusual suffix', 'https://miсrosoft.example', 'unicode-brand-confusable'],
  ['lookalike under hosted domain', 'https://paypa1.github.io/login', 'hosted-tenant-lookalike'],
  ['hosted Google brand claim', 'https://google.pages.dev', 'hosted-brand-claim'],
  ['official domain embedded as prefix', 'https://paypal.com.evil.example/login', 'embedded-trusted-host'],
  ['official domain embedded after a subdomain', 'https://login.microsoft.com.evil.example', 'embedded-trusted-host'],
  ['lookalike Microsoft ASCII (existing)', 'https://microsott.com', 'lookalike'],
  ['rn for m (existing)', 'https://rnicrosoft.com', 'lookalike'],
  ['digit substitution (existing)', 'https://paypa1.com', 'lookalike'],
];
for (const [name, url, id] of adversarial) test(name, () => assert.equal(has(url, id), true, JSON.stringify(P.analyseUrl(url).issues)));

console.log('\nLow false-positive controls');
const benign = [
  ['real Microsoft', 'https://login.microsoft.com/'],
  ['real Google', 'https://accounts.google.com/'],
  ['real PayPal', 'https://www.paypal.com/'],
  ['real Apple', 'https://apple.com/'],
  ['real Amazon', 'https://amazon.co.uk/'],
  ['German umlaut IDN', 'https://xn--bcher-kva.de/shop'],
  ['German umlaut Unicode', 'https://bücher.de/shop'],
  ['Spanish café', 'https://café.example/menu'],
  ['Greek-language IDN', 'https://παράδειγμα.δοκιμή/'],
  ['Cyrillic-language IDN', 'https://пример.рф/'],
  ['Japanese-language IDN', 'https://例え.テスト/'],
  ['multi-script Japanese', 'https://日本語かな.日本/'],
  ['normal hosted website', 'https://project.github.io/'],
  ['normal business website', 'https://example.com/'],
  ['normal multi-part domain', 'https://shop.example.co.uk/']
];
const dangerousIds = new Set(['unicode-brand-confusable','unicode-mixed-script','punycode',
  'embedded-trusted-host','hosted-brand-claim','hosted-tenant-lookalike']);
for (const [name, url] of benign) test(name, () => {
  const issues = P.analyseUrl(url).issues.filter(i => dangerousIds.has(i.type));
  assert.equal(issues.length, 0, JSON.stringify(issues));
});

console.log('\nContext / protocol / visible explanations');
test('IDN without brand match is not automatically high risk', () => {
  const issues = P.analyseUrl('https://bücher.de/').issues;
  assert.equal(issues.some(i => i.type === 'punycode' || i.type === 'unicode-brand-confusable'), false);
});
test('mixed Cyrillic + Latin detected without a brand match', () =>
  assert.equal(has('https://tеst.example/info', 'unicode-mixed-script'), true));
test('mixed Latin/Greek detected without known brand', () =>
  assert.equal(has('https://bοok.example/info', 'unicode-mixed-script'), true));
test('Greek URL is not flagged only for using Greek script', () =>
  assert.equal(has('https://παράδειγμα.δοκιμή', 'unicode-mixed-script'), false));
test('whole-script confusable does not depend on mixed scripts', () => {
  const issues = P.analyseUrl('https://аррӏе.com').issues;
  assert(issues.some(i => i.type === 'unicode-brand-confusable'));
  assert(!issues.some(i => i.type === 'unicode-mixed-script'));
  assert(issues.find(i => i.type === 'unicode-brand-confusable').technique.includes('Whole-script'));
});
test('decoding is correct for a known ACE label', () =>
  assert.equal(P.domainSecurity.decodeHost('xn--bcher-kva.de'), 'bücher.de'));
test('confusable details identify actual Unicode code point', () => {
  const issue = P.analyseUrl('https://miсrosoft.example').issues.find(i => i.type === 'unicode-brand-confusable');
  assert(issue.detail.includes('U+0441') && issue.detail.includes('Cyrillic'));
  assert(issue.detail.includes('xn--'));
});
test('visible IDN and ACE both yield matching signals', () => {
  const ace = new URL('https://miсrosoft.com').hostname;
  assert.equal(P.domainSecurity.decodeHost(ace), 'miсrosoft.com');
  assert.deepEqual(P.analyseUrl('https://' + ace).issues.map(i => i.type),
    P.analyseUrl('https://miсrosoft.com').issues.map(i => i.type));
});
test('real subdomain boundaries are respected', () => {
  const x = P.analyseUrl('https://login.paypal.com');
  assert(!x.issues.some(i => i.type === 'embedded-trusted-host'));
});
test('fake subdomain of an official site is flagged', () => {
  assert(has('https://signin.paypal.com.evil.example/', 'embedded-trusted-host'));
});
test('Unicode sender address is checked using same detector', () => {
  const r = P.analyse('From: Microsoft IT <security@miсrosoft.com>\nSubject: Update\n\nHello');
  assert(ids(r).includes('sender-unicode-brand-confusable'));
});
test('URL without scheme supports a Unicode bare hostname', () => {
  const r = P.analyse('Please check раураӏ.com before replying.');
  assert(r.urls.length === 1);
  assert(ids(r).includes('url-unicode-brand-confusable'));
});
test('URL without scheme supports bare ACE hostname', () => {
  const r = P.analyse('Please check xn--pple-43d.com before replying.');
  assert(r.urls.some(u => u.issues.some(i => i.type === 'unicode-brand-confusable')));
});
test('no duplicate link extracted from unicode URL with path', () => {
  assert.equal(P.analyse('https://аррӏе.com/signin').urls.length, 1);
});
test('header address is not incorrectly extracted as a URL', () => {
  assert.equal(P.analyse('From: info@miсrosoft.com\nSubject: hello\n\nHello').urls.length, 0);
});
test('HTML href is analysed without executing embedded content', () => {
  const r = P.analyse('<html><body><a href="https://miсrosoft.com">View document</a><script>alert(1)</script></body></html>');
  assert(ids(r).includes('url-unicode-brand-confusable'));
  assert(!r.text.includes('alert(1)'));
});
test('two domains inside one message keep separate URL evidence', () => {
  const r = P.analyse('https://paypal.com https://раураӏ.com');
  assert.equal(r.urls.length, 2);
  assert(r.urls.find(u => u.host === 'paypal.com').issues.every(i => i.type !== 'unicode-brand-confusable'));
});
test('finder returns structured data without contacting network', () => {
  const report = P.domainSecurity.inspect('xn--pple-43d.com', 'xn--pple-43d.com');
  assert.equal(report.unicodeHost, 'аpple.com');
  assert(report.issues.every(i => typeof i.type === 'string' && typeof i.detail === 'string' && i.weight >= 0));
});
test('plain text is never marked as phishing merely because it contains Unicode', () => {
  const r = P.analyse('Hello, I will bring café and tea tomorrow.');
  assert(!ids(r).includes('url-unicode-brand-confusable'));
});
test('dangerous match remains justified in complete analysis report', () => {
  const r = P.analyse('Please sign in at https://miсrosoft.com/login');
  const finding = r.findings.find(f => f.id === 'url-unicode-brand-confusable');
  assert(finding && finding.explain.includes('U+0441') && finding.evidence.length === 1);
  assert(r.score >= 45);
});

console.log('\nResilience to malformed / adversarial input');
for (const bad of ['', 'xn--', 'xn--a-', 'xn--!!!!', 'xn--' + 'a'.repeat(500),
  'xn--zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz', 'a'.repeat(10000)]) {
  test('malformed ACE ' + JSON.stringify(bad.slice(0, 20)), () =>
    assert.doesNotThrow(() => P.domainSecurity.inspect(bad, bad)));
}
test('URL parser handles invalid Unicode percent escapes', () => {
  assert.doesNotThrow(() => P.analyseUrl('https://xn--!!!!.example/%ZZ'));
});
test('fuzz fixed-seed short hostnames do not throw', () => {
  let seed = 0x7f432194;
  const chars = ['a','x','-','0','9','р','а','Ꭺ','ο','ʕ','\u200d','👀','.'];
  for (let i = 0; i < 350; i++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    let value = '';
    for (let n = 0; n < 12; n++) { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; value += chars[seed % chars.length]; }
    assert.doesNotThrow(() => P.domainSecurity.inspect(value, 'example.com'));
  }
});
test('protected Cybersteps demo domain can be passed without modifying global brands', () => {
  const additional = { cybersteps: ['cybersteps.example'] };
  const issues = P.domainSecurity.issues('cybersteps.example.evil.example', 'evil.example', additional);
  assert(issues.some(i => i.type === 'embedded-trusted-host'));
});
test('custom brand domain is accepted as legitimate', () => {
  const additional = { cybersteps: ['cybersteps.example'] };
  const issues = P.domainSecurity.issues('login.cybersteps.example', 'cybersteps.example', additional);
  assert(!issues.some(i => i.type === 'embedded-trusted-host' || i.type === 'unicode-brand-confusable'));
});
test('scripts are label-local and tolerate Japanese writing system', () => {
  const r = P.domainSecurity.inspect(new URL('https://日本語かな.日本').hostname, 'xn--wgv71a309e.xn--wgv71a');
  assert(!r.issues.some(i => i.type === 'unicode-mixed-script'));
});

console.log(`\nDomain security: ${passed} passed, ${failed} failed\n`);
process.exitCode = failed ? 1 : 0;
