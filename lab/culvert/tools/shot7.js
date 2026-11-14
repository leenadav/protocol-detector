const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1600, height: 1250 }, deviceScaleFactor: 2 });
  const p = await ctx.newPage();
  const errors = []; p.on('pageerror', e => errors.push(String(e)));
  await p.goto('file:///home/user/culvert-lab/results/observatory.html');
  await p.waitForTimeout(500);
  await p.screenshot({ path: '/home/user/culvert-lab/shots/20-observatory.png' });
  await p.locator('[data-filter="policy"]').click();
  await p.locator('#session-rows tr', { hasText: 'SSH client to the TLS-only host' }).first().click();
  await p.waitForTimeout(400);
  await p.screenshot({ path: '/home/user/culvert-lab/shots/21-observatory-drawer.png' });
  console.log('page errors:', errors.length, errors.slice(0, 2));
  await b.close();
})().catch(e => { console.error(String(e).slice(0, 600)); process.exit(1); });
