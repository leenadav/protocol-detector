// Check that the preview instance (G, plain-HTTP UI) accepts a login and shows data.
const { chromium } = require('playwright');
const fs = require('fs');
(async () => {
  const pw = fs.readFileSync('/home/user/culvert-lab/run/admin-G.secret', 'utf8');
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1500, height: 950 }, deviceScaleFactor: 1 });
  const p = await ctx.newPage();
  await p.goto('http://127.0.0.1:19096/app/', { waitUntil: 'networkidle' });
  await p.waitForTimeout(800);
  if (await p.locator('input[type=password]:visible').count() > 0) {
    await p.locator('input:visible').first().fill('admin');
    await p.locator('input[type=password]:visible').first().fill(pw);
    await p.locator('button[type=submit]:visible').first().click();
    await p.waitForTimeout(2000);
  }
  await p.goto('http://127.0.0.1:19096/app/monitor/traffic', { waitUntil: 'networkidle' });
  await p.waitForTimeout(1000);
  const mem = p.getByRole('button', { name: /Query recent memory instead/ });
  if (await mem.count() > 0) { await mem.click(); await p.waitForTimeout(1500); }
  console.log('url', p.url(), '| rows', await p.locator('tbody tr').count(), '| signed in as', (await p.locator('header').innerText()).replace(/\s+/g, ' ').slice(0, 80));
  await b.close();
})().catch(e => { console.error(String(e).slice(0, 500)); process.exit(1); });
