'use strict';
/* Reproducible adversarial tests of defensive behavior, not phishing-detection accuracy. */
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
for(const name of ['rules','psl-data','public-suffix','confusables-data','domain-security','url-security','analyser','html-security','qr-security','eml']) require('../js/'+name+'.js');
const P=globalThis.PEA;
let passes=0;
function check(name,test){try {test(); passes++;}catch(e){console.error('FAILED '+name);throw e;}}
const mock='https://pаypаl.com/login';
check('Pasted spoofed header in body is not considered From',()=>{
 const r=P.analyse('Hello!\n\nFrom: Security <x@paypa1.example>\nReply-To: attacker@example.net\nAuthentication-Results: evil.example; spf=fail; dkim=fail; dmarc=fail\n\nSigned by IT.','email');
 assert(!r.findings.some(f=>f.group==='Sender'));
});
check('Body authentication does not supply forged PASS results',()=>{
 const r=P.analyse('Normal update\n\nAuthentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass');
 assert.equal(r.headers.positives.length,0);
});
check('Only real header block contributes sender findings',()=>{
 const r=P.analyse('From: Employee <x@example.org>\nSubject: Test\n\nReply-To: attacker@paypa1.example\nAuthentication-Results: forged; spf=fail; dmarc=fail');
 assert(!r.findings.some(f=>f.group==='Sender' && /mismatch|SPF|DMARC/i.test(f.title)));
});
check('Sender header and reply-to parsed when in initial block',()=>{
 const r=P.analyse('From: Employee <x@example.org>\nReply-To: attacker@example.net\nSubject: Test\n\nHello');
 assert(r.findings.some(f=>f.id==='reply-to-mismatch'));
});
check('Header-only input still recognized',()=>{
 const r=P.analyse('From: Employee <x@example.org>\nReply-To: attacker@example.net');
 assert(r.findings.some(f=>f.id==='reply-to-mismatch'));
});
check('Claimed SPF DKIM DMARC pass is explicitly unverified',()=>{
 const r=P.analyse('From: Example <x@example.com>\nAuthentication-Results: example.com; spf=pass dkim=pass dmarc=pass\n\nHi');
 assert(r.headers.positives.some(s=>/unverified/i.test(s) && !/really came/i.test(s)));
});
check('Reported SPF failure is not presented as cryptographically verified',()=>{
 const r=P.analyse('From: Person <test@example.com>\nAuthentication-Results: mx; spf=fail dkim=fail dmarc=fail\n\nText');
 assert(r.findings.some(f=>f.id==='spf-fail'&&/REPORT/.test(f.explain)));
});
check('Received-SPF marker in body does not spoof header',()=>{
 const r=P.analyse('Hello\n\nReceived-SPF: fail (bogus)');
 assert(!r.findings.some(f=>f.id==='spf-fail'));
});
check('Pasted HTML is inspected even with empty analysisContext.html',()=>{
 const r=P.analyse('<form action="https://example.org/login"><input type="password"></form>','email',{html:'',qrResults:[]});
 assert(r.findings.some(f=>f.id==='html-html-credential-form'));
});
check('HTML extracted URI is inspected with empty context',()=>{
 const r=P.analyse('<html><a href="https://pаypаl.com/login">Login</a></html>','email',{html:'',qrResults:[]});
 assert(r.findings.some(f=>f.id==='url-unicode-brand-confusable'||f.id==='html-url-unicode-brand-confusable'));
});
check('Benign QR link is informational only',()=>{
 const r=P.analyse('Hello','email',{qrResults:[{url:true,value:'https://example.org'}]});
 assert(r.findings.some(f=>f.id==='qr-embedded-link' && f.weight===0));
});
check('HTML duplicate href honors first attribute',()=>{
 const s=P.htmlSecurity.inspect('<a href="https://evil.example/login" href="https://paypal.com">https://paypal.com</a>');
 assert(s.findings.some(f=>f.type==='html-link-target-mismatch'));
 assert(s.urls.includes('https://evil.example/login'));
});
check('HTML duplicate safe first href is not replaced by malicious second',()=>{
 const s=P.htmlSecurity.inspect('<a href="https://paypal.com" href="https://evil.example">https://paypal.com</a>');
 assert(!s.findings.some(f=>f.type==='html-link-target-mismatch'));
});
check('HTML duplicate attributes case insensitive',()=>{
 const s=P.htmlSecurity.inspect('<a HREF="https://evil.example" href="https://paypal.com">https://paypal.com</a>');
 assert(s.findings.some(f=>f.type==='html-link-target-mismatch'));
});
check('HTML escaped attribute URL considered',()=>{
 const s=P.htmlSecurity.inspect('<a href="https://evil.example/?x=1&amp;y=2">https://paypal.com</a>');
 assert(s.urls.some(u=>u.includes('x=1&y=2')));
});
check('HTML button formaction override is surfaced',()=>{
 const r=P.htmlSecurity.inspect('<form action="https://paypal.com"><button formaction="https://paypa1.example/login">Login</button></form>');
 assert(r.findings.some(f=>f.type==='html-formaction-override'));
 assert(r.urls.includes('https://paypa1.example/login'));
});
check('HTML input formaction override is surfaced',()=>{
 const r=P.htmlSecurity.inspect('<form action="https://paypal.com"><input type=submit formaction=https://paypa1.example/login></form>');
 assert(r.urls.includes('https://paypa1.example/login'));
});
check('HTML image map links are investigated',()=>{
 const r=P.htmlSecurity.inspect('<map><area href="https://paypa1.example/login"></map>');
 assert(r.urls.includes('https://paypa1.example/login'));
});
check('HTML iframe resource is extracted but never executed',()=>{
 const r=P.htmlSecurity.inspect('<iframe src="https://paypa1.example/login"></iframe>');
 assert(r.findings.some(f=>f.type==='html-embedded-content'));
});
check('HTML active image-map scheme is flagged',()=>{
 const r=P.htmlSecurity.inspect('<area href="javascript:alert(1)">');
 assert(r.findings.some(f=>f.type==='html-active-area'));
});
check('HTML form action included even without credential fields',()=>{
 const r=P.htmlSecurity.inspect('<form action="https://paypa1.example/login"><button>Continue</button></form>');
 assert(r.urls.includes('https://paypa1.example/login'));
});
check('Script comments not used as evidence in pasted HTML',()=>{
 const r=P.analyse('<html><body><script>password verify account now</script><p>Have a nice day</p></body></html>');
 assert(!r.findings.some(f=>f.group==='Language'));
});
check('HTML comments not used as evidence in pasted HTML',()=>{
 const r=P.analyse('<html><body><!-- <a href="https://paypa1.example"> -->Hello</body></html>');
 assert(!r.urls.some(u=>u.host==='paypa1.example'));
});
check('Mixed Unicode link remains detected',()=>assert(P.analyseUrl(mock).issues.some(i=>i.type==='unicode-brand-confusable')));
check('Traditional ASCII typosquatting remains detected',()=>assert(P.analyseUrl('https://microsott.com').issues.some(i=>i.type==='lookalike')));
check('Legitimate IDN remains neutral to brand impersonation',()=>assert(!P.analyseUrl('https://bücher.de').issues.some(i=>i.type==='unicode-brand-confusable')));
check('Redirects to suspicious IDN are still detected',()=>{
 const r=P.analyseUrl('https://example.com/continue?url='+encodeURIComponent(mock));
 assert(r.issues.some(i=>i.type==='nested-redirect-impersonation'));
});
check('Incomplete oversized input clearly marked not complete',()=>{
 const s='A'.repeat(512*1024+22)+mock;
 const r=P.analyse(s);assert.equal(r.coverage.complete,false);
 assert(r.coverage.messages.some(m=>/may have been missed/.test(m)));
 assert(r.coverage.analysedCharacters <= 512*1024);assert(r.coverage.messages.some(m=>/oversized unbroken token/.test(m)));
});
check('Normal input records complete coverage',()=>{
 const r=P.analyse('Thank you.');assert.equal(r.coverage.complete,true);
});
check('Oversized .eml rejected before parsing',()=>{
 assert.throws(()=>P.parseEml('x'.repeat(25*1024*1024+1)),/25 MiB/);
});
check('Large MIME messages only extract bounded body text',()=>{
 const s='From: a@b.test\nContent-Type: text/plain\n\n'+'A'.repeat(700000);
 const parsed=P.parseEml(s);assert(parsed.limited);assert(parsed.text.length<530000);
});
check('MIME parser counts thousands of parts without unlimited traversal',()=>{
 const lines=['From: a@b.test','Content-Type: multipart/mixed; boundary="B"',''];
 for(let j=0;j<300;j++) lines.push('--B','Content-Type: text/plain','','Hi');
 lines.push('--B--');const r=P.parseEml(lines.join('\n'));assert(r.limited);
});
check('Malformed .eml is non executable text',()=>{
 globalThis.__maliciousCode=false;
 P.parseEml('From: attacker@example.com\n\n<script>globalThis.__maliciousCode=true</script>');
 assert.equal(globalThis.__maliciousCode,false);
});
check('QR decoding of text is not reported as web link',()=>assert.equal(P.qrSecurity.inspectDecoded('bitcoin:1example').url,false));
check('QR encoded malicious link uses domain engine',()=>assert(P.qrSecurity.inspectDecoded(mock).issues.some(i=>i.type==='unicode-brand-confusable')));
check('Nonmatching ordinary link gives no impersonation',()=>assert(!P.analyseUrl('https://example.com/home').issues.some(i=>i.type==='unicode-brand-confusable')));
check('Malformed URL parser remains non throwing',()=>assert.doesNotThrow(()=>P.analyseUrl('https://%')));
check('Long dangerous link is processed within a safety limit',()=>{
 const link='https://example.com/?next='+encodeURIComponent('https://example.org/?target='.repeat(300));
 assert.doesNotThrow(()=>P.urlSecurity.inspect(link));
});
check('Data is never fetched by static detectors',()=>{
 globalThis.fetch=()=>{throw new Error('Network request detected');};
 assert.doesNotThrow(()=>P.analyse('Visit https://example.com/continue?url='+encodeURIComponent(mock)));
 delete globalThis.fetch;
});
check('Missing optional QR browser capabilities are honestly reported',()=>assert.equal(P.qrSecurity.supported(),false));
// Deterministic input mutation: parsers should not crash on invalid URI escapes,
// URL separators, homoglyph injections or truncated structured inputs.
let seed=0xFA17BEEF;const rand=()=>((seed=Math.imul(seed,1664525)+1013904223>>>0)/4294967296);
const pieces=['%','\\u200b','\\u202e','&amp;','%25','<a href="','xn--','https://','</a>','?next=','\\0', 'р','а','()'];
for(let i=0;i<320;i++){
 const mutation=Array.from({length:1+Math.floor(rand()*11)},()=>pieces[Math.floor(rand()*pieces.length)]).join('');
 check('mutation '+i,()=>{
  assert.doesNotThrow(()=>P.analyseUrl('https://example.com/'+mutation));
  assert.doesNotThrow(()=>P.htmlSecurity.inspect('<a href="'+mutation+'">https://example.com</a>'));
  assert.doesNotThrow(()=>P.domainSecurity.inspect('xn--'+mutation, 'example.com'));
 });
}
console.log(`Adversarial security suite: ${passes} passed (including 320 deterministic mutations)`);
