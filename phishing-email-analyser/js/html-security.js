/* Offline inspection of HTML email source. Never inserts untrusted HTML into
 * document/DOM; does not load external resources. Static evidence ONLY.
 * Deliberately bounded; not a complete HTML5 parser (browser quirks can differ).
 */
(function(root) {
 'use strict';
 const P = root.PEA || (root.PEA={});
 const MAX_HTML=512*1024, MAX_TAGS=700, MAX_FINDINGS=30;
 const entity = s=>String(s||'').replace(/&amp;/gi,'&').replace(/&quot;/gi,'"').replace(/&apos;|&#39;/gi,"'")
   .replace(/&lt;/gi,'<').replace(/&gt;/gi,'>').replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(Math.min(+n,0x10ffff)))
   .replace(/&#x([\da-f]+);/gi,(_,n)=>String.fromCodePoint(Math.min(parseInt(n,16),0x10ffff)));
 function attributes(raw) {
   const attrs = Object.create(null);
   const re=/([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
   let m, count=0;
   while ((m=re.exec(raw)) && ++count<=45) if (!Object.prototype.hasOwnProperty.call(attrs, m[1].toLowerCase()))
     attrs[m[1].toLowerCase()] = entity(m[2]??m[3]??m[4]??''); // first attribute wins in HTML
   return attrs;
 }
 const http = s => /^https?:\/\//i.test(s);
 function inspect(html) {
   const report={findings:[], urls:[], truncated:false};
   if (typeof html!=='string' || !html.trim()) return report;
   report.truncated=html.length>MAX_HTML;
   // Suppress non-rendered source; links inside JavaScript strings, comments,
   // CSS or <template> are not user-facing HTML links. Retain all other HTML
   // as inert source text and do not create DOM nodes from the input.
   const src=html.slice(0,MAX_HTML).replace(/<!--[\s\S]*?(?:-->|$)/g,' ')
     .replace(/<(script|style|template|noscript)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,' ');
   // Scan opening tags without stopping at '>' inside a quoted attribute.
   // A regex such as /<a ...[^>]*>/ fails on common quoted URLs containing >.
   function* tags() {
     const starts=/<(a|area|form|meta|img|input|button|iframe|object)\b/gi;
     let m;
     while ((m=starts.exec(src))) {
       const start=m.index, from=starts.lastIndex, tag=m[1].toLowerCase();
       let quote='', j=from;
       for (;j<src.length && j-from<=8192;j++) {
         const c=src[j];
         if (quote) {if (c===quote)quote='';}
         else if (c==='\"'||c==="'")quote=c;
         else if (c==='>')break;
       }
       if (j>=src.length || src[j]!=='>')continue;
       const after=j+1;
       starts.lastIndex=after;
       yield {tag,raw:src.slice(from,j),after};
     }
   }
   let tagsCount=0;
   const pending=[];
   for (const t of tags()) {
     if (++tagsCount>MAX_TAGS)break;
     const tag=t.tag, attrs=attributes(t.raw);
     const add=(type,weight,title,detail,url)=>{
       if (report.findings.length>=MAX_FINDINGS)return;
       report.findings.push({type,weight,title,detail,url:url||''});
     };
     // Secondary submit destinations override <form action> and are easy to
     // overlook in manual email-source reviews. Inspect without submitting.
     if ((tag==='input' || tag==='button') && attrs.formaction) {
       if (http(attrs.formaction)) report.urls.push(attrs.formaction);
       add('html-formaction-override', 23, 'HTML submit control overrides form destination',
         'A submit control specifies its own destination. Verify the actual destination; no form was submitted.',attrs.formaction);
     }
     if (tag==='area' && attrs.href) {
       if (http(attrs.href)) report.urls.push(attrs.href);
       else if (/^(?:javascript|data|vbscript):/i.test(attrs.href))
         add('html-active-area', 25, 'Image-map hotspot has active URL scheme',
           'A clickable image-map area uses an active URL scheme.',attrs.href);
     }
     if ((tag==='iframe' && attrs.src) || (tag==='object' && attrs.data)) {
       const source=tag==='iframe'?attrs.src:attrs.data;
       if (http(source)) report.urls.push(source);
       add('html-embedded-content', 12, 'HTML embeds an external or active resource',
         'An embedded object/iframe destination appears in the email source. The app did not load it.',source);
     }
     if (tag==='form' && attrs.action) {
       if (http(attrs.action)) report.urls.push(attrs.action);
       const body=src.slice(t.after).split(/<\/form\s*>/i,1)[0].slice(0,8192);
       const credential=/<input\b[^>]*\btype\s*=\s*['"]?(?:password|email)(?:['"\s>])/i.test(body);
       pending.push({action:attrs.action,credential});
     }
     if (tag==='a') {
       const href=attrs.href||'';
       if (!http(href)) {
         if (/^(javascript|data|vbscript):/i.test(href)) add('active-link-scheme',25,'Executable or embedded-data HTML link','The anchor uses an active or data URL scheme.',href);
         continue;
       }
       report.urls.push(href);
       const closing=src.slice(t.after).match(/^([\s\S]{0,2048}?)<\/a\s*>/i);
       const shown=entity((closing?closing[1]:'').replace(/<[^>]*>/g,' ').trim());
       const visible=shown.match(/https?:\/\/[^\s<>"']+/i);
       if (visible) {
         try {
           const actual=new URL(href), depicted=new URL(visible[0]);
           const owner=P.registrableDomain?P.registrableDomain(actual.hostname):actual.hostname;
           const label=P.registrableDomain?P.registrableDomain(depicted.hostname):depicted.hostname;
           if (owner!==label) add('html-link-target-mismatch',31,'Visible link misrepresents destination',
             `Displayed link is for "${depicted.hostname}", but the href points to "${actual.hostname}" (registrable domain: "${owner}").`,href);
         } catch(_){}
       }
       const style=(attrs.style||'').toLowerCase();
       if (/display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px)?\b/.test(style) || attrs.hidden!==undefined)
         add('hidden-html-link',9,'Hidden HTML hyperlink',`A URL appears inside an element marked hidden. This is not proof of phishing; some email layouts contain hidden preheaders.`,href);
     }
     if (tag==='meta' && /refresh/i.test(attrs['http-equiv']||'')) {
       const match=(attrs.content||'').match(/(?:^|;)\s*\d+\s*;\s*url\s*=\s*['"]?([^'"\s;]+)/i);
       if (match && http(match[1])) { report.urls.push(match[1]); add('html-meta-refresh',15,'HTML meta refresh contains destination',`HTML declares a refresh target "${match[1]}"; this is static source evidence, not proof of navigation.`,match[1]); }
     }
     if (tag==='img' && (attrs.width==='1' || attrs.height==='1') && http(attrs.src||''))
       add('tracking-pixel',3,'Remote single-pixel image',`A 1-pixel remote image is present. It may track opens, including in legitimate marketing emails.`,attrs.src);
   }
   for (const item of pending.slice(0,10)) if (http(item.action)) {
     const action=item.action; report.urls.push(action);
     if (item.credential) addFinding(report,'html-credential-form',24,'HTML credential form with external action',
       `A form containing credential-like input submits to "${action}". The form's purpose and server behavior are unverified.`,action);
   }
   if (tagsCount>MAX_TAGS || report.truncated) report.truncated=true;
   return report;
 }
 function addFinding(r,type,weight,title,detail,url) { if (r.findings.length<MAX_FINDINGS) r.findings.push({type,weight,title,detail,url}); }
 P.htmlSecurity=Object.freeze({inspect,attributes});
})(typeof window!=='undefined'?window:globalThis);
