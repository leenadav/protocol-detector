// Results matrix page and the TLS row detail in Culvert's new Traffic page (after work item #4).
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1700, height: 1250 }, deviceScaleFactor: 2,
    storageState: '/home/user/culvert-lab/run/ui-state-v2.json' });
  const p = await ctx.newPage();
  await p.goto('file:///home/user/culvert-lab/results/index.html');
  await p.screenshot({ path: '/home/user/culvert-lab/shots/30-matrix.png' });
  await p.goto('https://127.0.0.1:19093/app/monitor/traffic?filter=origin.lab.test%3A443', { waitUntil: 'networkidle' });
  await p.waitForTimeout(1000);
  const mem = p.getByRole('button', { name: /Query recent memory instead/ });
  if (await mem.count() > 0) { await mem.click(); await p.waitForTimeout(1500); }
  await p.locator('tbody tr', { hasText: 'TUNNEL_CLOSED' }).first().locator('button').first().click();
  await p.waitForTimeout(500);
  await p.screenshot({ path: '/home/user/culvert-lab/shots/31-app-tls-detail.png' });
  await b.close();
})().catch(e => { console.error(String(e).slice(0, 500)); process.exit(1); });
