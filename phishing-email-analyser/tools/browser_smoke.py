#!/usr/bin/env python3
"""Optional offline UI smoke test. Requires Playwright and a local Chromium.
The harness inlines LOCAL assets and omits the meta CSP because set_content
uses an about:blank document; it does NOT test deployed CSP response headers.
"""
import asyncio, json, re
from pathlib import Path
from playwright.async_api import async_playwright
ROOT=Path(__file__).resolve().parents[1]
async def main():
    html=(ROOT/'index.html').read_text(encoding='utf8')
    html=re.sub(r'<meta[^>]+http-equiv="Content-Security-Policy"[^>]*>', '', html)
    html=re.sub(r'<script\s+src="([^"]+)"\s*></script>', '', html)
    html=re.sub(r'<link[^>]+href="css/styles.css"[^>]*>', '', html)
    html=html.replace('</head>', '<style>'+ (ROOT/'css/styles.css').read_text() + '</style></head>')
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox','--disable-dev-shm-usage'])
        page=await browser.new_page(viewport={'width':1360,'height':900})
        errors=[]
        page.on('pageerror',lambda err:errors.append(str(err)))
        await page.set_content(html)
        for src in re.findall(r'<script\s+src="([^"]+)"\s*></script>',(ROOT/'index.html').read_text()):
            await page.add_script_tag(content=(ROOT/src).read_text(encoding='utf8'))
        assert await page.locator('.g-num').count()==1, 'Initial report failed'
        await page.locator('#email-input').fill('From: PayPal Support <help@pаypаl.com>\nSubject: Review account\n\nPlease sign in: https://pаypаl.com/login')
        await page.locator('#analyse-btn').click()
        evidence=await page.locator('#report-body').inner_text()
        assert 'Unicode domain impersonates paypal' in evidence,evidence[:450]
        assert 'U+0430' in await page.locator('#report-body').text_content()
        await page.wait_for_timeout(900)
        await page.screenshot(path=str(ROOT/'docs/browser-preview.png'),full_page=True)
        await page.locator('#email-input').fill('a'*1300)
        await page.locator('#analyse-btn').click()
        assert 'Incomplete analysis' in await page.locator('#report-body').inner_text()
        assert 'oversized unbroken' in await page.locator('#report-body').inner_text()
        await page.locator('#email-input').fill('Hello\n\nFrom: Security <x@paypa1.example>\nAuthentication-Results: forged; spf=fail')
        await page.locator('#analyse-btn').click()
        assert not await page.get_by_text('SPF check failed').count()
        # HTML investigations must actually appear in the evidence card, not
        # merely inflate the score (a previous presentation defect).
        await page.locator('#email-input').fill('<html><body><a href="https://evil.example">https://paypal.com</a></body></html>')
        await page.locator('#analyse-btn').click()
        assert await page.get_by_text('Visible link misrepresents destination').count() > 0
        assert 'HTML source' in await page.locator('#report-body').inner_text()
        await page.locator('#tab-dashboard').click()
        assert await page.locator('#view-dashboard').is_visible()
        await page.locator('#tab-training').click()
        assert await page.locator('#view-training').is_visible()
        assert not errors,errors
        report={'status':'passed','checks':['initial report','IDN impersonation evidence','coverage banner','body-header spoof rejection','dashboard navigation','training navigation','no page exceptions'],
                'qr_native_available':await page.evaluate('typeof BarcodeDetector === "function"'),
                'qr_decoder_included':await page.evaluate('typeof jsQR === "function"'),
                'context':'local-asset controlled browser harness; not a deployed-CSP or full penetration test'}
        (ROOT/'docs/browser-verification.json').write_text(json.dumps(report,indent=2))
        print(json.dumps(report,indent=2))
        await browser.close()
if __name__=='__main__':asyncio.run(main())
