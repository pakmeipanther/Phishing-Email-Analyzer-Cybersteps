#!/usr/bin/env python3
"""Install optional Apache-2.0-licensed jsQR 1.4.0 as a LOCAL offline asset.
Run manually when connected to the Internet, review diff, commit both assets.
No remote scripts are ever loaded by the browser.
"""
from pathlib import Path
import hashlib
import urllib.request

root=Path(__file__).resolve().parents[1]
js=root/'js'/'vendor'/'jsQR.js'
lic=root/'js'/'vendor'/'jsQR.LICENSE'
html=root/'index.html'
files=[(js,'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js'),
       (lic,'https://raw.githubusercontent.com/cozmo/jsQR/master/LICENSE')]
pending=[]
for path,url in files:
    req=urllib.request.Request(url,headers={'User-Agent':'CyberstepsSourceVendor/1.0'})
    with urllib.request.urlopen(req,timeout=30) as r: b=r.read(500_001)
    if len(b)>=500_001 or not b:raise ValueError('Size limit or empty asset: '+url)
    if path==js and b'jsQR' not in b:raise ValueError('Unexpected decoder content')
    if path==lic and b'Apache License' not in b:raise ValueError('Unexpected license')
    pending.append((path,b))
for path,b in pending:
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(b)
    print(path.relative_to(root),'SHA256',hashlib.sha256(b).hexdigest())
s=html.read_text()
anchor='<!-- Optional offline jsQR decoder may be installed by tools/vendor-qr-decoder.py. -->'
if '<script src="js/vendor/jsQR.js"></script>' not in s:
    s=s.replace(anchor,anchor+'\n<script src="js/vendor/jsQR.js"></script>')
    html.write_text(s)
print('Offline QR decoder vendored. Review downloaded assets, then rerun tests.')
