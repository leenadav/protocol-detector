const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1700, height: 1500 }, deviceScaleFactor: 2,
    storageState: '/home/user/culvert-lab/run/ui-state-v2.json' });
  const p = await ctx.newPage();
  const base = 'https://127.0.0.1:19093/app';
  // Traffic filtered to the TLS-only host, with the blocked SSH row opened.
  await p.goto(base + '/monitor/traffic?filter=secure.lab.test', { waitUntil: 'networkidle' });
  await p.waitForTimeout(1200);
  const mem = p.getByRole('button', { name: /Query recent memory instead/ });
  if (await mem.count() > 0) { await mem.click(); await p.waitForTimeout(1500); }
  const row = p.locator('tbody tr', { hasText: 'secure.lab.test:22' }).filter({ hasText: 'APP_BLOCKED' }).first();
  console.log('blocked ssh rows', await p.locator('tbody tr', { hasText: 'APP_BLOCKED' }).count());
  await row.locator('button').first().click();
  await p.waitForTimeout(500);
  await p.screenshot({ path: '/home/user/culvert-lab/shots/12-app-traffic-blocked.png' });
  // Access rules.
  await p.goto(base + '/policies/access-rules', { waitUntil: 'networkidle' });
  await p.waitForTimeout(1500);
  await p.setViewportSize({ width: 1700, height: 900 });
  await p.screenshot({ path: '/home/user/culvert-lab/shots/13-app-access-rules.png' });
  console.log((await p.locator('main').innerText()).slice(0, 900));
  await b.close();
})().catch(e => { console.error(String(e).slice(0, 700)); process.exit(1); });
