// Dependency mapping (method v2, item 2): load a public web-client or login page without signing in and
// record the host name of every request the page makes, including requests the egress proxy refuses.
// Only host names, request counts and the final page host are written; no content, cookies or URLs paths.
// usage: node observe_web.js OUT.json URL [URL ...]   or   node observe_web.js OUT.json --urls URLS.txt
// Without HTTPS_PROXY it connects directly (the pass-2 run on the Hermes server).
const { chromium } = require('playwright');
const fs = require('fs');
(async () => {
  const [, , out, ...rest] = process.argv;
  const urls = rest[0] === '--urls'
    ? fs.readFileSync(rest[1], 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    : rest;
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  const browser = await chromium.launch({ proxy: proxy ? { server: proxy } : undefined });
  const results = [];
  for (const url of urls) {
    const ctx = await browser.newContext();           // fresh profile per page: no stored sign-in
    const page = await ctx.newPage();
    const hosts = {};
    const note = (u, k) => { try { const h = new URL(u).hostname; if (!h) return; hosts[h] = hosts[h] || { requested: 0, failed: 0 }; hosts[h][k]++; } catch (e) {} };
    page.on('request', r => note(r.url(), 'requested'));
    page.on('requestfailed', r => note(r.url(), 'failed'));
    let status = null, error = null;
    try { const resp = await page.goto(url, { waitUntil: 'networkidle', timeout: 45000 }); status = resp ? resp.status() : null; }
    catch (e) { error = e.message.split('\n')[0].slice(0, 120); }
    await page.waitForTimeout(4000);
    let finalHost = null; try { finalHost = new URL(page.url()).hostname; } catch (e) {}
    results.push({ url, date: new Date().toISOString().slice(0, 10), status, error, final_host: finalHost, hosts });
    console.log(url, status, error || '', Object.keys(hosts).length, 'hosts');
    await ctx.close();
  }
  await browser.close();
  fs.writeFileSync(out, JSON.stringify(results, null, 1) + '\n');
})();
