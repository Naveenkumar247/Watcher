const express = require('express');
const { chromium } = require('playwright');
const { spawn } = require('child_process');
const dns = require('dns').promises;
const net = require('net');

const app = express();
app.use(express.json({ limit: '1mb' }));
const PORT = Number(process.env.PORT || 4000);
const TOKEN = process.env.INTERNAL_API_TOKEN || 'replace-with-a-long-random-secret';
const packets = [];
const MAX_PACKETS = 500;
let browser, context, page;
let browserState = { status: 'starting', url: '', title: '', error: null, updatedAt: new Date().toISOString() };

function auth(req, res, next) {
  if (req.get('x-internal-token') !== TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
function isPrivateIPv4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  return p[0] === 0 || p[0] === 10 || p[0] === 127 || p[0] >= 224 ||
    (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
    (p[0] === 198 && (p[1] === 18 || p[1] === 19));
}
function isPrivateIPv6(ip) {
  const s = ip.toLowerCase();
  return s === '::' || s === '::1' || s.startsWith('fc') || s.startsWith('fd') || s.startsWith('fe80:') || s.startsWith('ff') || s.startsWith('::ffff:127.') || s.startsWith('::ffff:10.') || s.startsWith('::ffff:192.168.');
}
async function validatePublicUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('Enter a valid full URL, e.g. https://example.com'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http:// and https:// URLs are allowed.');
  if (u.username || u.password) throw new Error('URLs containing credentials are not allowed.');
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) throw new Error('Local and internal hostnames are blocked.');
  if (net.isIP(host)) {
    if ((net.isIPv4(host) && isPrivateIPv4(host)) || (net.isIPv6(host) && isPrivateIPv6(host))) throw new Error('Private or reserved IP destinations are blocked.');
  } else {
    let records;
    try { records = await dns.lookup(host, { all: true, verbatim: true }); }
    catch { throw new Error('Hostname could not be resolved.'); }
    if (!records.length || records.some(r => net.isIPv4(r.address) ? isPrivateIPv4(r.address) : isPrivateIPv6(r.address))) throw new Error('The hostname resolves to a private or reserved IP address and is blocked.');
  }
  return u.toString();
}

// Start a bounded TShark capture. Only packet metadata is retained; payloads are not saved.
function startCapture() {
  const args = ['-l', '-i', 'any', '-n', '-T', 'fields', '-E', 'separator=|', '-E', 'occurrence=f',
    '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'ipv6.src', '-e', 'tcp.srcport', '-e', 'udp.srcport',
    '-e', 'ip.dst', '-e', 'ipv6.dst', '-e', 'tcp.dstport', '-e', 'udp.dstport', '-e', 'frame.protocols', '-e', 'frame.len', '-e', '_ws.col.Protocol'];
  const child = spawn('tshark', args, { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.setEncoding('utf8');
  let carry = '';
  child.stdout.on('data', chunk => {
    carry += chunk;
    const lines = carry.split(/\r?\n/); carry = lines.pop() || '';
    for (const line of lines) {
      const f = line.split('|'); if (f.length < 12) continue;
      const src = f[1] || f[2] || '—'; const dst = f[5] || f[6] || '—';
      const packet = {
        id: `${Date.now()}-${Math.random().toString(16).slice(2, 7)}`,
        timestamp: f[0] ? new Date(Number(f[0]) * 1000).toISOString() : new Date().toISOString(),
        source: src, sourcePort: f[3] || f[4] || '—', destination: dst,
        destinationPort: f[7] || f[8] || '—', protocols: f[9] || f[11] || 'Unknown',
        protocol: f[11] || f[9]?.split(':').pop() || 'Unknown', size: Number(f[10]) || 0,
        status: 'OBSERVED'
      };
      packets.push(packet); if (packets.length > MAX_PACKETS) packets.shift();
    }
  });
  child.stderr.on('data', d => { const msg = d.toString().trim(); if (msg && /error|permission|failed/i.test(msg)) console.error('[tshark]', msg.slice(0, 300)); });
  child.on('error', e => console.error('[tshark spawn error]', e.message));
  child.on('exit', code => { console.error('[tshark exited]', code); setTimeout(() => startCapture(), 3000); });
}

async function ensureBrowser() {
  if (browser && browser.isConnected()) return;
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] });
  context = await browser.newContext({ viewport: { width: 1280, height: 800 }, ignoreHTTPSErrors: false });
  page = await context.newPage();
  // Validate every browser request, including redirects, subresources and pop-ups.
  await context.route('**/*', async route => {
    try {
      const target = await validatePublicUrl(route.request().url());
      await route.continue({ url: target });
    } catch (e) {
      await route.abort('blockedbyclient').catch(() => {});
    }
  });
  page.on('pageerror', e => { browserState.error = `Page error: ${String(e.message).slice(0, 180)}`; });
  page.on('requestfailed', req => {
    const failure = req.failure()?.errorText || 'request failed';
    if (!/blockedbyclient/i.test(failure)) browserState.error = `${req.url().slice(0, 100)} — ${failure}`;
  });
  browserState.status = 'ready';
}

app.get('/health', (req, res) => res.json({ ok: true, service: 'browser-worker' }));
app.use(auth);
app.post('/navigate', async (req, res) => {
  try {
    const url = await validatePublicUrl(String(req.body?.url || ''));
    await ensureBrowser();
    browserState = { status: 'loading', url, title: '', error: null, updatedAt: new Date().toISOString() };
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 25000 });
    await page.waitForTimeout(900);
    browserState.title = await page.title().catch(() => '');
    browserState.status = 'loaded'; browserState.updatedAt = new Date().toISOString();
    res.json({ ok: true, state: browserState, screenshot: `/screenshot?ts=${Date.now()}` });
  } catch (e) {
    browserState.status = 'error'; browserState.error = String(e.message || e).slice(0, 350); browserState.updatedAt = new Date().toISOString();
    res.status(400).json({ ok: false, error: browserState.error, state: browserState });
  }
});
app.get('/screenshot', async (req, res) => {
  try {
    await ensureBrowser();
    const image = await page.screenshot({ type: 'jpeg', quality: 65, timeout: 8000 });
    res.set('Content-Type', 'image/jpeg').set('Cache-Control', 'no-store').send(image);
  } catch (e) { res.status(503).json({ error: 'Browser preview is not ready.' }); }
});
app.get('/state', (req, res) => res.json(browserState));
app.get('/packets', (req, res) => {
  const since = Number(req.query.since || 0);
  res.json({ packets: since ? packets.filter(p => Number(p.id.split('-')[0]) > since) : packets.slice(-150), count: packets.length, capture: 'TShark metadata capture' });
});
app.post('/action', async (req, res) => {
  try {
    await ensureBrowser();
    const action = String(req.body?.action || '');
    if (action === 'back') await page.goBack({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});
    else if (action === 'forward') await page.goForward({ waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});
    else if (action === 'reload') await page.reload({ waitUntil: 'domcontentloaded', timeout: 15000 });
    else return res.status(400).json({ error: 'Unsupported browser action.' });
    browserState.url = page.url(); browserState.title = await page.title().catch(() => ''); browserState.updatedAt = new Date().toISOString();
    res.json({ ok: true, state: browserState });
  } catch (e) { res.status(500).json({ error: String(e.message || e).slice(0, 200) }); }
});

app.listen(PORT, '0.0.0.0', async () => {
  console.log(`Browser worker listening on ${PORT}`);
  startCapture();
  try { await ensureBrowser(); } catch (e) { console.error('Browser startup:', e.message); }
});
