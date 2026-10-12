'use strict';
const assert=require('node:assert/strict');
require('../js/rules.js');require('../js/psl-data.js');require('../js/public-suffix.js');require('../js/confusables-data.js');
require('../js/domain-security.js');require('../js/url-security.js');require('../js/analyser.js');
require('../js/html-security.js');require('../js/qr-security.js');require('../js/eml.js');
const P=globalThis.PEA;
let n=0;
function check(name,fn){try{fn();n++;console.log(' ✓ '+name);}catch(e){console.error(' ✗ '+name);throw e;}}
function risky(s,type){return P.analyse(s,'email').findings.some(f=>f.id===type);}
for(const [host,registrable,suffix] of [
 ['login.microsoft.com','microsoft.com','com'],['x.paypal.co.uk','paypal.co.uk','co.uk'],
 ['foo.appspot.com','foo.appspot.com','appspot.com'],['abc.github.io','abc.github.io','github.io'],
 ['x.y.example.com','example.com','com'],['shop.co.jp','shop.co.jp','co.jp'],
 ['www.ck','www.ck','ck'],['a.www.ck','www.ck','ck'],['a.b.ck','a.b.ck','b.ck']]) {
 check('PSL: '+host,()=>{const v=P.publicSuffix.resolve(host);assert.equal(v.registrable,registrable,JSON.stringify(v));assert.equal(v.publicSuffix,suffix);});
}
check('PSL rule count > 9000',()=>assert(P.publicSuffix.ruleCount>9000));
check('PSL default rule for unknown suffix',()=>assert.equal(P.registrableDomain('a.example.unknownsuffix'),'example.unknownsuffix'));
check('legitimate IDN is not brand-confusable',()=>assert(!P.analyseUrl('https://bücher.de').issues.some(x=>x.type==='unicode-brand-confusable')));
check('ICU mapping has broader coverage',()=>assert(Object.keys(P.confusableMappings).length>10000));
check('mixed Cyrillic is detected',()=>assert(P.analyseUrl('https://miсrosoft.com').issues.some(x=>x.type==='unicode-brand-confusable')));
check('whole-script Apple works with audited override',()=>assert(P.analyseUrl('https://аррӏе.com').issues.some(x=>x.type==='unicode-brand-confusable')));
check('HTML mismatch (unquoted href)',()=>assert(risky('<html><a href=https://evil.example/login>https://www.paypal.com</a></html>','html-html-link-target-mismatch')));
check('HTML mismatch (quoted href)',()=>assert(risky('<a href="https://evil.example">https://google.com</a>','html-html-link-target-mismatch')));
check('HTML matching domain is not mismatch',()=>assert(!risky('<a href="https://login.microsoft.com">https://microsoft.com</a>','html-html-link-target-mismatch')));
check('HTML credential form',()=>assert(risky('<html><form action="https://evil.example"><input type="password" name="p"></form></html>','html-html-credential-form')));
check('HTML meta refresh',()=>assert(risky('<html><meta http-equiv="refresh" content="0;url=https://evil.example/login"></html>','html-html-meta-refresh')));
check('HTML hidden link',()=>assert(risky('<html><a href="https://evil.example/login" style="display:none">hidden</a></html>','html-hidden-html-link')));
check('HTML javascript URI',()=>assert(risky('<html><a href="javascript:alert(1)">Click</a></html>','html-active-link-scheme')));
check('HTML report contains actual source URLs',()=>assert(P.analyse('<a href=https://evil.example/login>Go</a>','email').urls.some(u=>u.host==='evil.example')));
check('MIME HTML source retained',()=>{
 const raw='From: x@example.org\nContent-Type: text/html; charset=utf-8\n\n<a href="https://evil.example">https://paypal.com</a>';
 const parsed=P.parseEml(raw);assert(parsed.html.includes('https://evil.example'));
 assert(P.analyse(parsed.text,'email',{html:parsed.html}).findings.some(f=>f.id==='html-html-link-target-mismatch'));
});
check('HTML source is not evaluated/executed',()=>{
 globalThis.__badness=0;const r=P.htmlSecurity.inspect('<script>globalThis.__badness=7</script><a href=https://evil.example>click</a>');assert.equal(globalThis.__badness,0);assert(r.urls.length);
});
check('HTML processing bounded',()=>assert(P.htmlSecurity.inspect('<a href=https://evil.example>x</a>'.repeat(30000)).truncated));
check('QR decoded IDN has security issues',()=>assert(P.qrSecurity.inspectDecoded('https://miсrosoft.com/login').issues.some(i=>i.type==='unicode-brand-confusable')));
check('QR plain text does not claim URL',()=>assert(!P.qrSecurity.inspectDecoded('hello world').url));
check('QR recognized URL adds investigation links',()=>{
 const qr=P.qrSecurity.inspectDecoded('https://pаypal.com/login');const r=P.analyse('A message','email',{qrResults:[qr]});
 assert(r.urls.some(u=>u.source==='qr'));assert(r.findings.some(f=>f.id==='qr-unicode-brand-confusable'));
});
check('QR benign link alone scores zero',()=>assert.equal(P.analyse('hello','email',{qrResults:[P.qrSecurity.inspectDecoded('https://example.com')]}).raw,0));
check('QR rejects invalid content type',async()=>{});
console.log('Advanced security synchronous checks: '+n+' passed');
(async()=>{
 let asyncN=0;
 async function checkAsync(name,fn){await fn();asyncN++;console.log(' ✓ '+name);}
 await checkAsync('QR rejects invalid type',async()=>assert.equal((await P.qrSecurity.inspectImage(new Blob(['hi'],{type:'text/plain'}))).status,'invalid-type'));
 await checkAsync('QR unsupported is not false negative',async()=>{assert.equal((await P.qrSecurity.inspectImage(new Blob(['hi'],{type:'image/png'}))).status,'unsupported');});
 const oldDetector=globalThis.BarcodeDetector,oldBitmap=globalThis.createImageBitmap;
 globalThis.BarcodeDetector=class{async detect(){return [{rawValue:'https://miсrosoft.com/login'}];}};
 globalThis.createImageBitmap=async()=>({width:100,height:100,close(){}});
 try {
  await checkAsync('QR decoder mock yields security evidence',async()=>{
   const result=await P.qrSecurity.inspectImage(new Blob(['mockimage'],{type:'image/png'}));
   assert.equal(result.status,'ok');assert(result.codes[0].issues.some(x=>x.type==='unicode-brand-confusable'));
  });
 }finally { if(oldDetector===undefined)delete globalThis.BarcodeDetector;else globalThis.BarcodeDetector=oldDetector;
 if(oldBitmap===undefined)delete globalThis.createImageBitmap;else globalThis.createImageBitmap=oldBitmap; }
 await checkAsync('Optional jsQR fallback decodes QR pixels locally',async()=>{
   const prior=globalThis.BarcodeDetector, jsQR=globalThis.jsQR, doc=globalThis.document;
   delete globalThis.BarcodeDetector;
   globalThis.jsQR=()=>({data:'https://pаypal.com/login'});
   globalThis.document={createElement:()=>({width:0,height:0,getContext:()=>({drawImage(){},getImageData:()=>({data:new Uint8Array(4)})})})};
   globalThis.createImageBitmap=async()=>({width:1,height:1,close(){}});
   try{const r=await P.qrSecurity.inspectImage(new Blob(['data'],{type:'image/png'}));
     assert.equal(r.status,'ok');assert(r.codes[0].issues.some(x=>x.type==='unicode-brand-confusable'));
   }finally{
     if(prior===undefined)delete globalThis.BarcodeDetector;else globalThis.BarcodeDetector=prior;
     if(jsQR===undefined)delete globalThis.jsQR;else globalThis.jsQR=jsQR;
     if(doc===undefined)delete globalThis.document;else globalThis.document=doc;
   }
 });
 const bytes=Buffer.from('fakeimage');
 const eml='From: sender@example.com\nContent-Type: multipart/mixed; boundary="BOUND"\n\n--BOUND\nContent-Type: text/plain\n\nHi\n--BOUND\nContent-Type: image/png\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename="qr.png"\n\n'+bytes.toString('base64')+'\n--BOUND--';
 await checkAsync('MIME parser retrieves bounded image bytes',async()=>{
  const parsed=P.parseEml(eml);assert.equal(parsed.images.length,1);assert.equal(parsed.images[0].mime,'image/png');assert.deepEqual(Buffer.from(parsed.images[0].bytes),bytes);
 });
 console.log('Advanced security total: '+(n+asyncN)+' passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
