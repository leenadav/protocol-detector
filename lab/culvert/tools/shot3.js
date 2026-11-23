// New frontend (/app) on the real-detector build: log in with the lab admin and capture pages.
const { chromium } = require('playwright');
const fs = require('fs');
(async () => {
  const pw = fs.readFileSync('/home/user/culvert-lab/run/admin-D.secret', 'utf8');
  const b = await chromium.launch();
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 2 });
  const p = await ctx.newPage();
  await p.goto('https://127.0.0.1:19093/app/', { waitUntil: 'networkidle' });
  await p.waitForTimeout(800);
  if (await p.locator('input[type=password]:visible').count() > 0) {
    await p.locator('input:visible').first().fill('admin');
    await p.locator('input[type=password]:visible').first().fill(pw);
    await p.locator('button[type=submit]:visible').first().click();
    await p.waitForTimeout(2000);
  }
  await ctx.storageState({ path: '/home/user/culvert-lab/run/ui-state-v2.json' });
  await p.screenshot({ path: '/home/user/culvert-lab/shots/10-app-home.png' });
  console.log('url:', p.url());
  console.log((await p.locator('body').innerText()).slice(0, 700));
  await b.close();
})().catch(e => { console.error(String(e).slice(0, 400)); process.exit(1); });
