'use strict';
/* Independent regression coverage for security hardening and measurement.
 * These are deterministic engineering tests, NOT real-world detection metrics.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const cp = require('node:child_process');
require('../js/rules.js');
require('../js/psl-data.js');
require('../js/public-suffix.js');
require('../js/confusables-data.js');
require('../js/domain-security.js');
require('../js/url-security.js');
require('../js/analyser.js');
require('../js/html-security.js');
require('../js/qr-security.js');
const P=globalThis.PEA;
let tests=0;
function check(name,fn) { try { fn(); tests++; console.log(' ✓ '+name); } catch(e) { console.error(' ✗ '+name); throw e; } }
check('PSL registrable domain co.uk',()=>assert.equal(P.publicSuffix.resolve('login.example.co.uk').registrable,'example.co.uk'));
check('PSL private service github.io tenant',()=>assert.equal(P.publicSuffix.resolve('paypa1.github.io').registrable,'paypa1.github.io'));
check('PSL private hosting suffix itself is not registrable',()=>assert.equal(P.publicSuffix.resolve('github.io').registrable,''));
check('PSL wildcard handles multiple labels',()=>assert.equal(P.publicSuffix.resolve('a.b.ck').publicSuffix,'b.ck'));
check('PSL exception overrides wildcard',()=>assert.equal(P.publicSuffix.resolve('test.www.ck').registrable,'www.ck'));
check('PSL IDNA Unicode and ASCII canonicalize identically',()=>assert.deepEqual(P.publicSuffix.resolve('bücher.de'),P.publicSuffix.resolve('xn--bcher-kva.de')));
check('PSL rejects URL instead of hostname',()=>assert.equal(P.publicSuffix.resolve('https://example.com').rule,'invalid'));
check('PSL rejects credentials/ports',()=>assert.equal(P.publicSuffix.resolve('paypal.com@evil.example').rule,'invalid'));
check('PSL rejects overly long host',()=>assert.equal(P.publicSuffix.resolve('x'.repeat(300)).rule,'invalid'));
check('Legitimate IDN not branded as malicious',()=>assert(!P.analyseUrl('https://bücher.de').issues.some(i=>i.type==='unicode-brand-confusable')));
check('Unicode lookalike identified with character codepoints',()=>{const hits=P.analyseUrl('https://pаypаl.com/login').issues;assert(hits.some(i=>i.type==='unicode-brand-confusable'&&/U\+0430/.test(i.detail)));});
check('Pasted bare form identified as HTML',()=>assert(P.analyse('<form action="https://bad.example/"><input type="password"></form>','email').findings.some(f=>f.id==='html-html-credential-form')));
check('Pasted bare meta refresh identified as HTML',()=>assert(P.analyse('<meta http-equiv="refresh" content="0;url=https://example.com/">','email').findings.some(f=>f.id==='html-html-meta-refresh')));
check('Numeric HTML entity too large does not crash',()=>assert.doesNotThrow(()=>P.analyse('<a href="https://example.com">&#9999999999999999999999999999;</a>','email')));
check('HTML comment does not become phishing evidence',()=>{
  const r=P.htmlSecurity.inspect('<!-- <a href="https://evil.example">https://paypal.com</a> -->');
  assert.equal(r.findings.length,0);assert.equal(r.urls.length,0);
});
check('HTML script string does not become hyperlink evidence',()=>{
  const r=P.htmlSecurity.inspect('<script>const example = `<a href="https://evil.example">https://paypal.com</a>`;</script>');
  assert.equal(r.findings.length,0);assert.equal(r.urls.length,0);
});
check('HTML quoted greater-than in href does not mask true destination',()=>{
  const r=P.htmlSecurity.inspect('<a href="https://evil.example/q?q=>42">https://paypal.com</a>');
  assert(r.findings.some(f=>f.type==='html-link-target-mismatch'));
});
check('Benchmark does not mislabel spam as phishing',()=>{
 const work=fs.mkdtempSync(path.join(os.tmpdir(),'cybersteps-label-'));
 try {const input=path.join(work,'data.csv');fs.writeFileSync(input,'label,url\nspam,https://test.example\nlegitimate,https://safe.example\n');
  const r=JSON.parse(cp.execFileSync(process.execPath,[path.join(__dirname,'../tools/benchmark.js'),'--input',input,'--dataset-kind','external-labelled'],{encoding:'utf8'}));
  assert.equal(r.invalid,1);assert.equal(r.count,1);
 }finally{fs.rmSync(work,{recursive:true,force:true});}
});
check('HTML source is not evaluated as JavaScript',()=>{globalThis.__cybersteps_trap=0;P.htmlSecurity.inspect('<script>globalThis.__cybersteps_trap=1</script>');assert.equal(globalThis.__cybersteps_trap,0);});
check('QR plain text not treated as URL',()=>assert.equal(P.qrSecurity.inspectDecoded('please login').url,false));
check('QR typo correctly forwarded to domain detector',()=>assert(P.qrSecurity.inspectDecoded('https://miсrosoft.com').issues.some(i=>i.type==='unicode-brand-confusable')));
check('QR available support never assumed in Node',()=>assert.equal(typeof P.qrSecurity.supported(),'boolean'));
check('Benchmark excludes both conflicting records, not only second',()=>{
 const work=fs.mkdtempSync(path.join(os.tmpdir(),'cybersteps-eval-'));
 try{
  const source=path.join(work,'tiny.csv');fs.writeFileSync(source,'label,url\nphishing,https://miсrosoft.com\nlegitimate,https://miсrosoft.com\nlegitimate,https://example.com\n');
  const result=cp.execFileSync(process.execPath,[path.join(__dirname,'../tools/benchmark.js'),'--input',source,'--dataset-kind','synthetic'],{encoding:'utf8'});
  const m=JSON.parse(result);assert.equal(m.conflicting_duplicate_labels,1);assert.equal(m.count,1);assert.equal(m.confusion.tp+m.confusion.fp+m.confusion.tn+m.confusion.fn,1);
 } finally {fs.rmSync(work,{recursive:true,force:true});}
});
check('Benchmark synthetic smoke provenance explicit',()=>{const r=JSON.parse(fs.readFileSync(path.join(__dirname,'../docs/synthetic-benchmark-result.json'),'utf8'));assert.equal(r.dataset_kind,'synthetic');assert.equal(r.count,20);assert(r.wilson_95_percent_intervals.recall.low<r.recall);});
console.log(`Release hardening: ${tests} passed`);
