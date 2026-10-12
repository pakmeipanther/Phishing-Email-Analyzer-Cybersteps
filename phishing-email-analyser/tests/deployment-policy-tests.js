'use strict';
/* Static deployment-policy invariants. Run alongside dynamic security tests.
 * These checks do not replace a third-party application penetration test.
 */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.join(__dirname,'..');
const html=fs.readFileSync(path.join(root,'index.html'),'utf8');
const headers=fs.readFileSync(path.join(root,'_headers'),'utf8');
const csp=(html.match(/<meta[^>]+http-equiv="Content-Security-Policy"[^>]*content="([^"]+)"/i)||[])[1]||'';
const scripts=Array.from(html.matchAll(/<script\s+src="([^"]+)"\s*><\/script>/g),m=>m[1]);
let passed=0;
function check(name,fn){try{fn();passed++;}catch(e){console.error('FAILED '+name);throw e;}}
check('browser CSP default deny',()=>assert.match(csp,/default-src 'none'/));
check('browser CSP forbids outbound connections',()=>assert.match(csp,/connect-src 'none'/));
check('browser CSP forbids form submission',()=>assert.match(csp,/form-action 'none'/));
check('browser CSP only allows local scripts',()=>assert.match(csp,/script-src 'self'/));
check('browser CSP forbids base element',()=>assert.match(csp,/base-uri 'none'/));
check('deploy headers forbid frames',()=>assert.match(headers,/frame-ancestors 'none'/));
check('deploy headers disable content sniffing',()=>assert.match(headers,/X-Content-Type-Options:\s*nosniff/));
check('deploy headers deny referrers',()=>assert.match(headers,/Referrer-Policy:\s*no-referrer/));
check('runtime scripts use relative paths only',()=>assert(scripts.every(s=>/^js\/[\w\-/.]+\.js$/.test(s)&&!s.includes('..'))));
check('all runtime script files exist',()=>assert(scripts.every(s=>fs.existsSync(path.join(root,s)))));
check('no remote runtime script URLs',()=>assert(!scripts.some(s=>/https?:|^\/\//i.test(s))));
check('no inline JavaScript in page',()=>{
 const filtered=html.replace(/<!--[\s\S]*?-->/g,'');
 for (const m of filtered.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
   assert(/\bsrc\s*=/.test(m[1])); assert.equal(m[2].trim(), '');
 }
 assert(!/\son(?:click|error|load)\s*=/i.test(filtered));
});
check('all scripts are loaded after DOM content',()=>assert(html.indexOf('<script src=')>html.indexOf('</main>')));
check('no plaintext email data included in stored summaries',()=>{
 const source=fs.readFileSync(path.join(root,'js/app.js'),'utf8');
 assert.match(source,/s\.history\.push\(\{ t: report\.analysedAt, score: report\.score/);
});
check('CI checks adversarial tests',()=>{
 const workflow=fs.readFileSync(path.join(root,'../.github/workflows/security-tests.yml'),'utf8');
 assert.match(workflow,/node tests\/adversarial-tests\.js/);
});
check('CI checks deployment policy tests',()=>{
 const workflow=fs.readFileSync(path.join(root,'../.github/workflows/security-tests.yml'),'utf8');
 assert.match(workflow,/node tests\/deployment-policy-tests\.js/);
});
check('required data snapshots exist',()=>{
 for(const file of ['js/psl-data.js','js/confusables-data.js','../README.md']) assert(fs.statSync(path.join(root,file)).size>500);
});
console.log(`Deployment policy: ${passed} passed`);
