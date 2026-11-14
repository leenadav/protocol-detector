// New frontend: Traffic (with the detector column and an opened row) and Access Rules (list + editor).
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1700, height: 1100 }, deviceScaleFactor: 2,
    storageState: '/home/user/culvert-lab/run/ui-state-v2.json' });
  const p = await ctx.newPage();
  const base = 'https://127.0.0.1:19093/app';
  await p.goto(base + '/monitor/traffic', { waitUntil: 'networkidle' });
  await p.waitForTimeout(1500);
  console.log('traffic url', p.url());
  const mem = p.getByRole('button', { name: /Query recent memory instead/ });
  if (await mem.count() > 0) { await mem.click(); await p.waitForTimeout(1500); }
  await p.screenshot({ path: '/home/user/culvert-lab/shots/11-app-traffic.png' });
  console.log('rows', await p.locator('tbody tr').count());
  await b.close();
})().catch(e => { console.error(String(e).slice(0, 600)); process.exit(1); });
