/*
 * Automated checks for the detection engine.
 * Run with:  node tests/run-tests.js
 * (Only needed for development. Visitors never run this.)
 */
require('../js/rules.js');
require('../js/psl-data.js');
require('../js/public-suffix.js');
require('../js/confusables-data.js');
require('../js/domain-security.js');
require('../js/analyser.js');
require('../js/guidance.js');
require('../js/content.js');
require('../js/eml.js');
const P = globalThis.PEA;

let pass = 0, fail = 0;
function check(name, cond, info) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (info ? '  → ' + info : '')); }
}
const ids = r => r.findings.map(f => f.id);

console.log('\nCredential phish with look-alike domain');
let r = P.analyse(`From: "PayPal Security" <service@paypa1-secure.xyz>
Reply-To: help@mail-collector.ru
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-secure.xyz; dkim=none; dmarc=fail
Subject: Your account has been suspended

Dear Customer,
We detected unusual sign-in activity. Your account will be suspended within 24 hours.
Please verify your account and confirm your password here: http://paypal.com.account-verify.xyz/login
Or use https://bit.ly/3xYz12
Failure to comply will result in permanent closure.`);
check('score is Critical', r.level === 'Critical', r.score);
['urgency', 'threat', 'password-request', 'generic-greeting', 'url-brand-mismatch', 'url-shortener', 'reply-to-mismatch', 'spf-fail', 'dmarc-fail', 'display-brand-mismatch', 'combo-credential-harvest']
  .forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));
check('sender lookalike', ids(r).some(i => i.startsWith('sender-')), ids(r).join(','));

console.log('\nBEC / bank change');
r = P.analyse(`Hi Sarah, are you at your desk? I need you to process an urgent wire transfer today.
Our supplier's bank details have changed, please use the new IBAN below. Keep this confidential, I'm in a meeting and can't talk.
Regards, John (CEO)`);
['bank-change', 'payment', 'secrecy', 'authority', 'combo-bec'].forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));
check('High or Critical', ['High', 'Critical'].includes(r.level), r.score);

console.log('\nMalware attachment');
r = P.analyse(`Please find attached the overdue invoice. Attachment: Invoice_4471.pdf.exe and report.docm, plus scan.iso
If you see a yellow bar, click Enable Content to view the document.`);
['att-double-ext', 'att-executable', 'att-macro', 'att-container', 'macros', 'invoice', 'combo-malware'].forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));

console.log('\nURL tricks');
r = P.analyse(`Visit http://192.168.10.5/login.php or https://www.microsoft.com@evil.example/auth or https://xn--pple-43d.com/id
Track: https://arnazon.com/orders  and https://login-portal.web.app/`);
['url-ip-url', 'url-userinfo', 'url-punycode', 'url-lookalike', 'url-abused-host'].forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));

console.log('\nMisleading link text (HTML and plain text)');
r = P.analyse(`<html><body><p>Dear user, sign in to <a href="http://secure-update.top/x">https://www.paypal.com/signin</a></p></body></html>`);
check('HTML misleading', ids(r).includes('url-misleading-text'), ids(r).join(','));
r = P.analyse(`Sign in at https://login.microsoftonline.com <http://evil-login.click/ms>`);
check('plain-text misleading', ids(r).includes('url-misleading-text'), ids(r).join(','));
check('official MS link not flagged', !r.urls.find(u => u.host === 'login.microsoftonline.com').issues.length);

console.log('\nVoice transcript');
r = P.analyse(`Hello, I'm calling from your bank's fraud department. We've seen an unauthorised transaction. To stop it I need you to read me the code we just sent to your phone. Please stay on the line. To protect your savings we will move your money to a safe account. Please install AnyDesk so I can help.`, 'voice');
['caller-authority', 'mfa-request', 'stay-on-line', 'safe-account', 'remote-access', 'combo-vishing'].forEach(id => check('finds ' + id, ids(r).includes(id), ids(r).join(',')));
check('Critical', r.level === 'Critical', r.score);

console.log('\nBenign messages stay low');
r = P.analyse(`Hi team, the agenda for Thursday's planning meeting is attached as agenda.pdf. Lunch will be provided. See https://www.google.com/maps for directions. Thanks, Maria`);
check('benign Low', r.level === 'Low', r.score + ' ' + ids(r).join(','));
r = P.analyse(`Your Amazon order #112-555 has shipped. Track it at https://www.amazon.de/gp/your-account/order-history. Thanks for shopping with us.`);
check('legit amazon Low', r.level === 'Low', r.score + ' ' + ids(r).join(','));
r = P.analyse(`I made a purchase at the officedepot store yesterday, see https://www.officedepot.com/receipt`);
check('no false brand hit on "purchase"/officedepot', !ids(r).some(i => i.includes('brand-mismatch')), ids(r).join(','));

console.log('\nIOCs & defang');
r = P.analyse(`Go to http://203.0.113.9/pay and email billing@evil-pay.top or call +44 20 7946 0958`);
check('IP ioc', r.iocs.ips.includes('203.0.113.9'));
check('email ioc', r.iocs.emails.includes('billing@evil-pay.top'));
check('phone ioc', r.iocs.phones.length === 1, JSON.stringify(r.iocs.phones));
check('defang', P.defang('http://evil.com/a') === 'hxxp[://]evil[.]com/a', P.defang('http://evil.com/a'));

console.log('\nBuilt-in examples & challenge items');
for (const ex of P.EXAMPLES) {
  const rr = P.analyse(ex.text, ex.mode);
  check(`example "${ex.label}" → ${rr.level} (${rr.score})`, ex.id === 'legit' ? rr.level === 'Low' : ['High', 'Critical'].includes(rr.level), ids(rr).join(','));
  check('guidance renders for ' + ex.id, P.whatIf(rr).length && P.attackPath(rr).length >= 4 && P.actions(rr).now.length);
}
for (const c of P.CHALLENGE) {
  const rr = P.analyse('From: ' + c.from + '\n\n' + c.body, c.kind === 'Voice' ? 'voice' : 'email');
  check(`challenge ${c.id} (${c.phish ? 'phish' : 'legit'}) → ${rr.level} ${rr.score}`, c.phish ? rr.score >= 45 : rr.score < 20, ids(rr).join(','));
}

console.log('\n.eml import (parser only)');
const b64 = t => Buffer.from(t, 'utf8').toString('base64').replace(/(.{60})/g, '$1\r\n');
const eml = lines => lines.join('\r\n');   // real .eml files use CRLF
const bin = t => Buffer.from(t, 'utf8').toString('binary'); // what FileReader gives us: one char per byte

// multipart/alternative: quoted-printable plain text wins over HTML; encoded subject; attachment name
let e = P.parseEml(bin(eml([
  'From: =?UTF-8?B?UGF5UGFsIFNlY3VyaXR5?= <service@paypa1-secure.xyz>',
  'Reply-To: help@mail-collector.ru',
  'Subject: =?UTF-8?Q?Your_account_has_been_suspended_=E2=80=93_?=',
  ' =?UTF-8?Q?act_now?=',
  'Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-secure.xyz; dkim=none; dmarc=fail',
  'X-Noise: should not be copied',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="OUTER"',
  '',
  '--OUTER',
  'Content-Type: multipart/alternative; boundary="INNER"',
  '',
  '--INNER',
  'Content-Type: text/plain; charset=utf-8',
  'Content-Transfer-Encoding: quoted-printable',
  '',
  'Dear Customer, please verify your account and confirm your pass=',
  'word at http://paypal.com.account-verify.xyz/login within 24 hours =E2=80=94 or it will be suspended.',
  '--INNER',
  'Content-Type: text/html; charset=utf-8',
  '',
  '<html><body><p>HTML copy that must be ignored</p></body></html>',
  '--INNER--',
  '--OUTER',
  'Content-Type: application/octet-stream; name="Invoice_4471.pdf.exe"',
  'Content-Disposition: attachment; filename="Invoice_4471.pdf.exe"',
  'Content-Transfer-Encoding: base64',
  '',
  'TVqQAAMAAAAEAAAA',
  '--OUTER--', ''])));
check('uses the text/plain part', e.source === 'text/plain' && !/HTML copy/.test(e.text), e.source);
check('soft line break joined ("password")', /confirm your password at/.test(e.text), e.text);
check('QP UTF-8 bytes decoded (em dash)', e.text.includes('hours — or'));
check('RFC 2047 base64 display name decoded', e.text.includes('From: PayPal Security <service@paypa1-secure.xyz>'));
check('RFC 2047 folded Q subject decoded', e.text.includes('Subject: Your account has been suspended – act now'), e.text.split('\n')[2]);
check('noisy headers are not copied', !/X-Noise|MIME-Version/.test(e.text));
check('attachment name listed', e.files.length === 1 && e.files[0] === 'Invoice_4471.pdf.exe', JSON.stringify(e.files));
r = P.analyse(e.text, 'email');
['reply-to-mismatch', 'spf-fail', 'dmarc-fail', 'display-brand-mismatch', 'password-request', 'att-double-ext', 'url-brand-mismatch']
  .forEach(id => check('analyser sees ' + id + ' via .eml', ids(r).includes(id), ids(r).join(',')));

// HTML-only, base64: tags stripped but the real link address survives so link checks still work
e = P.parseEml(bin(eml([
  'From: Security <noreply@example.com>', 'Subject: Sign in',
  'Content-Type: text/html; charset=utf-8', 'Content-Transfer-Encoding: base64', '',
  b64('<html><head><style>p{color:red}</style></head><body><p>Dear user,&nbsp;sign in to <a href="http://secure-update.top/x">https://www.paypal.com/signin</a></p><script>alert(1)</script></body></html>')])));
check('HTML-only falls back to text/html', e.source === 'text/html', e.source);
check('no tags / script / style left', !/<\/?(p|body|script|style|html)\b|alert\(1\)|color:red/.test(e.text), e.text);
check('entity decoded', e.text.includes('Dear user, sign in'), e.text);
r = P.analyse(e.text, 'email');
check('misleading link text still detected from stripped HTML', ids(r).includes('url-misleading-text'), ids(r).join(','));

// Latin-1 8-bit body is decoded with its declared charset
e = P.parseEml(new Uint8Array(Buffer.from('From: a@b.com\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\nCaf\xe9 menu', 'latin1')).buffer);
check('ISO-8859-1 body (ArrayBuffer input)', e.text.includes('Café menu'), e.text);

// Forwarded-as-attachment: the inner email is the one analysed
e = P.parseEml(bin(eml([
  'From: employee@corp.example', 'Subject: Fwd: suspicious', 'Content-Type: multipart/mixed; boundary="B"', '',
  '--B', 'Content-Type: message/rfc822', '', 'From: "Bank" <alerts@bank-secure.top>', 'Subject: Urgent', 'Content-Type: text/plain', '',
  'Verify your account immediately.', '--B--', ''])));
check('forwarded message: inner headers used', e.text.includes('alerts@bank-secure.top') && !e.text.includes('employee@corp.example'), e.text);

// Hostile / odd input must never throw or inject headers
e = P.parseEml(bin(eml(['From: a@b.com', 'Subject: =?UTF-8?Q?hi=0AReply-To:_evil@x.ru?=', '', 'body'])));
check('encoded newline cannot fake a header line', !/^Reply-To:/m.test(e.text), e.text);
check('plain text with no headers is used as-is', P.parseEml('just some pasted words').text === 'just some pasted words');
check('empty file → empty text', P.parseEml('').text === '' && P.parseEml(new ArrayBuffer(0)).source === 'none');
let threw = false;
try { P.parseEml(bin('Content-Type: multipart/mixed; boundary=X\n\n--X\nContent-Type: multipart/mixed; boundary=X\n\n--X\nContent-Transfer-Encoding: base64\n\n!!!\n')); P.parseEml('Content-Type: text/plain; charset=nope\n\n=ZZ =\n'); } catch (err) { threw = true; }
check('malformed MIME does not throw', !threw);

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
