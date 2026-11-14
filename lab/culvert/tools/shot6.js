const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1700, height: 1000 }, deviceScaleFactor: 2,
    storageState: '/home/user/culvert-lab/run/ui-state-v2.json' });
  const p = await ctx.newPage();
  await p.goto('https://127.0.0.1:19093/app/policies/access-rules', { waitUntil: 'networkidle' });
  await p.waitForTimeout(1200);
  const row = p.locator('tbody tr', { hasText: 'lab-secure-tls-only' }).first();
  console.log('row buttons:', await row.locator('button').allInnerTexts());
  await row.getByRole('button', { name: /Edit/ }).first().click();
  await p.waitForTimeout(1000);
  const legend = p.getByText('Protocol restriction (lab)');
  await legend.scrollIntoViewIfNeeded();
  await p.waitForTimeout(300);
  await p.screenshot({ path: '/home/user/culvert-lab/shots/14-app-rule-editor.png' });
  await b.close();
})().catch(e => { console.error(String(e).slice(0, 700)); process.exit(1); });
