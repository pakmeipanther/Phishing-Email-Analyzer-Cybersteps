#!/usr/bin/env node
/* Measurable, reproducible evaluation using a user-supplied LABELLED CSV.
 * No dataset is shipped and no unverified accuracy claims are made.
 * Input: label,url/text  / labels: phishing|legitimate,1|0,malicious|benign.
 * Deduplication is SHA-256 based, avoiding duplicate-inflated metrics.
 * Avoid storing raw emails or full URLs in report JSON.
 */
'use strict';
const fs=require('node:fs'),crypto=require('node:crypto'),path=require('node:path');
const args=process.argv.slice(2);const opt=n=>args[args.indexOf(n)+1];
if (!args.includes('--input')) {console.error('Usage: node tools/benchmark.js --input labelled.csv [--output metrics.json] [--threshold 45]');process.exit(2);}
const src=opt('--input');const dest=args.includes('--output')?opt('--output'):'';
const threshold=args.includes('--threshold')?Number(opt('--threshold')):45;
const kind=args.includes('--dataset-kind')?String(opt('--dataset-kind')):'unspecified';
if(!['unspecified','synthetic','external-labelled'].includes(kind))throw new Error('Invalid --dataset-kind');
if (!Number.isInteger(threshold)||threshold<0||threshold>100)throw new Error('Invalid threshold');
function parseCsv(data) {
 let rows=[],row=[],cell='',quoted=false;
 for(let i=0;i<data.length;i++) {
  const c=data[i];
  if(quoted){if(c==='"' && data[i+1]==='"'){cell+='"';i++;}else if(c==='"')quoted=false;else cell+=c;}
  else if(c==='"')quoted=true;
  else if(c===','){row.push(cell);cell='';}
  else if(c==='\n'){row.push(cell.replace(/\r$/,''));rows.push(row);row=[];cell='';}
  else cell+=c;
 }
 if(quoted)throw new Error('Unterminated CSV quote');
 if(row.length || cell){row.push(cell.replace(/\r$/,''));rows.push(row);}
 return rows;
}
const size=fs.statSync(src).size;if(size>100*1024*1024)throw Error('Dataset exceeds 100MB cap');
const csv=fs.readFileSync(src,'utf8').replace(/^\ufeff/,'');
const rows=parseCsv(csv),headers=rows.shift().map(x=>x.trim().toLowerCase());
const idx=n=>headers.indexOf(n);
const labelIndex=['label','is_phishing','class','target'].map(idx).find(n=>n>=0);
const textIndex=['url','text','email','message','body'].map(idx).find(n=>n>=0);
if(labelIndex===undefined || textIndex===undefined) throw Error('CSV requires label + url/text/email/message/body columns');
require('../js/rules.js');require('../js/psl-data.js');require('../js/public-suffix.js');require('../js/confusables-data.js');
require('../js/domain-security.js');require('../js/url-security.js');require('../js/html-security.js');require('../js/analyser.js');
const P=globalThis.PEA;
const classes={phishing:1,malicious:1,'1':1,'true':1,legitimate:0,benign:0,'0':0,'false':0,safe:0};
let confusion={tp:0,tn:0,fp:0,fn:0},duplicates=0,invalid=0,count=0,disagreements=0;
const seen=new Map(),hash=crypto.createHash('sha256').update(csv).digest('hex');
for(const row of rows){
 const label=classes[String(row[labelIndex]||'').toLowerCase().trim()];
 const input=String(row[textIndex]||'').trim();
 if(label===undefined || !input || input.length>100_000){invalid++;continue;}
 const digest=crypto.createHash('sha256').update(input).digest('hex');
 if(seen.has(digest)){duplicates++;if(seen.get(digest).label!==label){seen.get(digest).conflict=true;disagreements++;}continue;}
 seen.set(digest,{label,input,conflict:false});
}
const samples=[...seen.values()].filter(v=>!v.conflict);
let groups={};
for(const item of samples){
 count++;const score=P.analyse(item.input,'email').score;const predicted=score>=threshold;
 if(predicted && item.label===1)confusion.tp++;else if(predicted)confusion.fp++;
 else if(item.label===1)confusion.fn++;else confusion.tn++;
 const g=groups[item.label?'phishing':'legitimate']||(groups[item.label?'phishing':'legitimate']={count:0,score_min:101,score_max:-1,score_total:0});
 g.count++;g.score_min=Math.min(g.score_min,score);g.score_max=Math.max(g.score_max,score);g.score_total+=score;
}
for(const g of Object.values(groups)){g.score_mean=Number((g.score_total/g.count).toFixed(2));delete g.score_total;}

const {tp,tn,fp,fn}=confusion;
const ratio=(a,b)=>b?Number((a/b).toFixed(6)):null;
const accuracy=ratio(tp+tn,count),precision=ratio(tp,tp+fp),recall=ratio(tp,tp+fn);
// Wilson binomial confidence bounds describe sampling uncertainty; they do NOT
// fix biased/contaminated labels or temporal distribution shift.
function wilson(success,n){if(!n)return null;const z=1.96,z2=z*z,p=success/n;
 const mid=(p+z2/(2*n))/(1+z2/n);
 const half=z*Math.sqrt(p*(1-p)/n+z2/(4*n*n))/(1+z2/n);
 return {low:Number(Math.max(0,mid-half).toFixed(6)),high:Number(Math.min(1,mid+half).toFixed(6)),n};
}
const report={source:'user-supplied labelled CSV',dataset_kind:kind,dataset_sha256:hash,threshold,method:'Static rule-score classification, exact deduplication; all conflicting-label values excluded',count,duplicates,invalid,conflicting_duplicate_labels:disagreements,label_distribution:groups,
 wilson_95_percent_intervals:{accuracy:wilson(tp+tn,count),precision:wilson(tp,tp+fp),recall:wilson(tp,tp+fn),specificity:wilson(tn,tn+fp)},
 confusion,accuracy,precision,recall,specificity:ratio(tn,tn+fp),false_positive_rate:ratio(fp,fp+tn),
 f1:(precision===null||recall===null||precision+recall===0)?null:ratio(2*precision*recall,precision+recall),
 warnings:[...count<100?['Fewer than 100 unique samples; results have high statistical uncertainty.']:[],
 ...disagreements?['Conflicting labels on duplicate inputs were excluded ENTIRELY from evaluation.']:[],
 ...kind==='unspecified'?['Dataset provenance is unspecified. Specify --dataset-kind and document source, license, labels and collection dates.']:[],
 ...kind==='synthetic'?['This result is from synthetic examples, not real-world accuracy.']:[],
 'Performance depends strongly on dataset representativeness, time, and label quality.',
 'A synthetic fixture is not a real-world benchmark. Report its origin accurately.',
 'Spam vs ham is not synonymous with phishing vs legitimate; non-phishing spam labels are rejected.',
 'False positives and false negatives must be reviewed by a human.']};
if(dest)fs.writeFileSync(dest,JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report,null,2));
