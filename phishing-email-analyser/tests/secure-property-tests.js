'use strict';
/* Deterministic property-style fuzz corpus: budgeted hostile inputs. Never network. */
const assert=require('node:assert/strict');
require('../js/rules.js');require('../js/psl-data.js');require('../js/public-suffix.js');require('../js/confusables-data.js');
require('../js/domain-security.js');require('../js/url-security.js');require('../js/analyser.js');require('../js/html-security.js');
const P=globalThis.PEA;
let state=0x59F3A;const rand=()=>{state=(Math.imul(state,1664525)+1013904223)>>>0;return state/2**32;};
const chars='aBc1234-_%#?=&:;!/\\\u0430\u0441\u039f\u200b\ud800';const next=(n)=>Math.floor(rand()*n);
let cases=0;const start=Date.now();
for(let i=0;i<600;i++){
 const host=Array.from({length:next(140)+1},()=>chars[next(chars.length)]).join('');
 const url='https://'+host+'.example/redirect?url='+encodeURIComponent('https://'+host.replace(/\uD800/g,'x')+'.example/login');
 const text='<html><a href="'+url+'">https://paypal.com</a><form action="https://'+host+'.example"><input type="password"></form></html>';
 const r=P.analyse(text,'email');
 assert(Number.isInteger(r.score)&&r.score>=0&&r.score<=100);
 assert(r.findings.length<180);
 assert(P.htmlSecurity.inspect(text).findings.length<=30);
 assert(P.urlSecurity.inspect(url).length<=25);
 assert(P.publicSuffix.resolve(host+'.example').registrable.length<=253);
 cases++;
}
for(const size of [1000,10000,100000,600000]){
 const r=P.htmlSecurity.inspect('<a href=https://evil.example>'+('a'.repeat(size))+'</a>');
 assert(r.findings.length<=30);if(size>512*1024)assert(r.truncated);
 cases++;
}
console.log('Property/fuzz checks: '+cases+' passed; elapsed '+(Date.now()-start)+'ms; seed 0x59F3A');
