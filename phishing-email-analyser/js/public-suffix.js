/* PSL registrar boundary resolver. Offline; no DNS lookup or ownership claim.
 * Supports ICANN/PRIVATE exact, wildcard, exception rules from the bundled list.
 * Canonicalizes all host/rule labels through WHATWG URL IDNA processing so
 * UTF-8 rules and ASCII xn-- input can be matched consistently.
 */
(function(root){
 'use strict';
 const P=root.PEA||(root.PEA={});
 const raw=Array.isArray(P.pslRules)?P.pslRules:[];
 function asciiDomain(input){
   if(typeof input!=='string'||!input||input.length>1024||/[\s\/#?@:]/.test(input)) return '';
   try {
     const h=new URL('http://'+input.replace(/\.$/,'')).hostname.toLowerCase();
     if(!h||h.length>253||h.startsWith('.')||h.endsWith('.')||h.includes('..'))return '';
     if(h.split('.').some(s=>!s||s.length>63||!/^[a-z0-9_-]+$/.test(s)))return '';
     return h;
   }catch(_){return '';}
 }
 function canonicalRule(s){
   if(typeof s!=='string')return '';
   let prefix='';
   if(s.startsWith('!')){prefix='!';s=s.slice(1);}
   else if(s.startsWith('*.')){prefix='*.';s=s.slice(2);}
   const h=asciiDomain(s);return h?prefix+h:'';
 }
 const rules=new Set(raw.map(canonicalRule).filter(Boolean));
 function resolve(input){
   const h=asciiDomain(input);
   if(!h)return {host:'',registrable:'',publicSuffix:'',rule:'invalid',source:'unavailable'};
   if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(h))return {host:h,registrable:h,publicSuffix:'',rule:'ip',source:'n/a'};
   const labels=h.split('.');
   let best={len:1,rule:'*',exception:false};
   for(let i=0;i<labels.length;i++){
     const joined=labels.slice(i).join('.'),len=labels.length-i;
     if(rules.has('!'+joined)){
       if(!best.exception||len>best.len)best={len,rule:'!'+joined,exception:true};
     }
     if(!best.exception&&rules.has(joined)&&len>best.len)best={len,rule:joined,exception:false};
     if(i+1<labels.length&&!best.exception&&rules.has('*.'+labels.slice(i+1).join('.'))&&len>best.len)
       best={len,rule:'*.'+labels.slice(i+1).join('.'),exception:false};
   }
   const suffixLen=best.exception?best.len-1:best.len;
   const registrable=labels.length>suffixLen?labels.slice(-suffixLen-1).join('.'):'';
   return {host:h,registrable,publicSuffix:labels.slice(-suffixLen).join('.'),rule:best.rule,
     source:raw.length?'bundled-psl-snapshot':'default-rule-only'};
 }
 P.publicSuffix=Object.freeze({resolve,asciiDomain,registrableDomain:host=>resolve(host).registrable||asciiDomain(host),ruleCount:rules.size});
})(typeof window!=='undefined'?window:globalThis);
