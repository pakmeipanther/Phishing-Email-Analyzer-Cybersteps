/* QR phishing inspection — no decoding links via navigation, no upload.
 * Browser BarcodeDetector support varies; do not claim support when unavailable.
 * Optional locally-installed jsQR can provide an offline fallback where native QR scanning is unavailable.
 */
(function(root){
 'use strict';
 const P=root.PEA||(root.PEA={});
 const MAX_BYTES=3*1024*1024, MAX_CODES=8;
 function supported(){return typeof root.createImageBitmap==='function' && (typeof root.BarcodeDetector==='function' || typeof root.jsQR==='function');}
 function inspectDecoded(text){
   const value=String(text||'').trim().slice(0,4096);
   if (!/^https?:\/\//i.test(value)) return {value,url:false,issues:[]};
   const analysed = typeof P.analyseUrl==='function' ? P.analyseUrl(value) : {issues:[]};
   const issues=analysed.issues||[];
   return {value,url:true,host:analysed.host,issues};
 }
 async function inspectImage(blob) {
   if (!blob || !/^image\/(png|jpeg|webp|gif)$/i.test(blob.type||'')) return {status:'invalid-type',codes:[]};
   if (blob.size>MAX_BYTES || !blob.size) return {status:'size-limit',codes:[]};
   if (!supported()) return {status:'unsupported',codes:[]};
   let bitmap;
   try {
     bitmap=await root.createImageBitmap(blob);
     if (bitmap.width>4096 || bitmap.height>4096) return {status:'size-limit',codes:[]};
     let found=[];
     if (typeof root.BarcodeDetector==='function') {
       try { found=await new root.BarcodeDetector({formats:['qr_code']}).detect(bitmap); }
       catch(error) { if (typeof root.jsQR!=='function') throw error; }
     }
     if (!found.length && typeof root.jsQR==='function' && root.document) {
       // Optional locally vendored Apache-2.0-licensed jsQR decoder; no network request.
       const canvas=root.document.createElement('canvas');
       canvas.width=bitmap.width;canvas.height=bitmap.height;
       const ctx=canvas.getContext('2d',{willReadFrequently:true});
       if(ctx) {
         ctx.drawImage(bitmap,0,0);
         const pixels=ctx.getImageData(0,0,canvas.width,canvas.height);
         const decoded=root.jsQR(pixels.data,canvas.width,canvas.height,{inversionAttempts:'attemptBoth'});
         if (decoded && decoded.data) found=[{rawValue:decoded.data}];
       }
       canvas.width=0;canvas.height=0;
     }
     return {status:'ok',codes:(found||[]).slice(0,MAX_CODES).map(f=>inspectDecoded(f.rawValue))};
   } catch(_){return {status:'decoder-error',codes:[]};}
   finally {if (bitmap && typeof bitmap.close==='function') bitmap.close();}
 }
 P.qrSecurity=Object.freeze({supported,inspectDecoded,inspectImage,MAX_BYTES});
})(typeof window!=='undefined'?window:globalThis);
