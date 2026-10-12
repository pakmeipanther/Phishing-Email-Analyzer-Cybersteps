/* Tests use synthetic, inert URLs. */
'use strict';
const assert = require('node:assert/strict');
require('../js/rules.js');
require('../js/psl-data.js');
require('../js/public-suffix.js');
require('../js/confusables-data.js');
require('../js/domain-security.js');
require('../js/url-security.js');
require('../js/analyser.js');
const P = globalThis.PEA;
const tests = [
  ['nested unicode spoof', 'https://example.com/r?next='+encodeURIComponent('https://miсrosoft.com/login'), 'nested-redirect-impersonation'],
  ['nested brand embedded', 'https://example.com/r?url='+encodeURIComponent('https://paypal.com.evil.example/'), 'nested-redirect-impersonation'],
  ['hosted tenant lookalike', 'https://example.com/r?target='+encodeURIComponent('https://paypa1.github.io/'), 'nested-redirect-impersonation'],
  ['external login', 'https://example.com/r?continue='+encodeURIComponent('https://unknown.example/login'), 'nested-external-login'],
];
let count=0;
for (const [name,url,kind] of tests) {
  assert(P.analyseUrl(url).issues.some(x=>x.type===kind), name);count++;
}
const benign = [
 'https://example.com/?url=https%3A%2F%2Fexample.com%2Flogin',
 'https://example.com/?url=https%3A%2F%2Fwww.paypal.com%2Fhome',
 'https://example.com/?next=%2Fdashboard',
 'https://example.com/?search=paypal.com',
 'https://example.com/?redirect=not-a-link',
 'https://example.com/?redirect=javascript%3Aalert(1)',
 'https://example.com/?redirect='+encodeURIComponent('https://bücher.de/menu'),
 'https://example.com/?url='+encodeURIComponent('https://пример.рф/info'),
];
for (const url of benign) {
  assert.equal(P.analyseUrl(url).issues.some(x=>x.type.startsWith('nested-redirect')||x.type==='nested-external-login'),false,url);count++;
}
for (const input of ['',null,undefined,'not a URL','https://example.com/?url=%ZZ',
 'https://example.com/?url='+ 'a'.repeat(5000)]) {
  assert.doesNotThrow(()=>P.urlSecurity.inspect(input));count++;
}
const attack = P.analyseUrl(tests[0][1]).issues.find(x=>x.type==='nested-redirect-impersonation');
assert(attack.detail.includes('NOT followed'));count++;
assert(P.urlSecurity.inspect('https://example.com/?target='+encodeURIComponent('https://miсrosoft.com')).length>0);count++;
const nested = 'https://example.com/start?next=' + encodeURIComponent(
  'https://portal.example/forward?destination=' + encodeURIComponent(
    'https://login.example/continue?url=' + encodeURIComponent('https://miсrosoft.com/signin')));
assert(P.analyseUrl(nested).issues.some(x => x.type === 'nested-redirect-impersonation' && x.detail.includes('depth 3')));count++;
const encodedTwice = 'https://example.com/?next=' + encodeURIComponent(encodeURIComponent('https://аррӏе.com/'));
assert(P.analyseUrl(encodedTwice).issues.some(x => x.type === 'nested-redirect-impersonation'));count++;
const oauth = 'https://accounts.example/?redirect_uri=' + encodeURIComponent('https://client.example/callback');
assert(!P.urlSecurity.inspect(oauth).some(x => x.type === 'nested-redirect-impersonation'));count++;
const loop = 'https://a.example/?next=' + encodeURIComponent('https://b.example/?next=https%3A%2F%2Fa.example');
assert.doesNotThrow(() => P.urlSecurity.inspect(loop));count++;
const huge = 'https://example.com/?next=' + encodeURIComponent('https://example.org/?next='.repeat(1500));
assert.deepEqual(P.urlSecurity.inspect(huge), []);count++;
const invalidEncoded = 'https://example.com/?next=%25ZZ';
assert.doesNotThrow(() => P.urlSecurity.inspect(invalidEncoded));count++;
console.log(`URL security: ${count} passed, 0 failed`);
