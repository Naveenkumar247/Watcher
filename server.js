require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = Number(process.env.PORT || 3000);
const WORKER = process.env.BROWSER_WORKER_URL || 'http://browser-worker:4000';
const TOKEN = process.env.INTERNAL_API_TOKEN || 'replace-with-a-long-random-secret';
const VT_KEY = process.env.VIRUSTOTAL_API_KEY || '';
app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

async function workerFetch(path, options = {}) {
  const response = await fetch(`${WORKER}${path}`, {
    ...options,
    headers: { 'content-type': 'application/json', 'x-internal-token': TOKEN, ...(options.headers || {}) },
    signal: AbortSignal.timeout(options.timeout || 30000)
  });
  const type = response.headers.get('content-type') || '';
  if (type.includes('image/')) return { response };
  const body = await response.json().catch(() => ({}));
  if (!response.ok) { const err = new Error(body.error || `Browser worker returned ${response.status}`); err.status = response.status; throw err; }
  return { body, response };
}
app.get('/api/health', async (req, res) => {
  try { const r = await fetch(`${WORKER}/health`, { signal: AbortSignal.timeout(2500) }); res.json({ app: 'online', browserWorker: r.ok ? 'online' : 'degraded', packetCapture: 'configured', virusTotal: VT_KEY ? 'configured' : 'not configured' }); }
  catch { res.status(503).json({ app: 'online', browserWorker: 'offline', packetCapture: 'unknown', virusTotal: VT_KEY ? 'configured' : 'not configured' }); }
});
app.post('/api/navigate', async (req, res) => {
  try {
    const url = String(req.body?.url || '').trim();
    if (!url || url.length > 2048) return res.status(400).json({ error: 'Enter a URL up to 2048 characters.' });
    const result = await workerFetch('/navigate', { method: 'POST', body: JSON.stringify({ url }), timeout: 32000 });
    io.emit('browser-state', result.body.state);
    res.json(result.body);
  } catch (e) { res.status(e.status || 502).json({ error: e.message || 'Browser worker unavailable.' }); }
});
app.get('/api/state', async (req, res) => { try { res.json((await workerFetch('/state')).body); } catch (e) { res.status(502).json({ error: e.message }); } });
app.get('/api/packets', async (req, res) => { try { res.json((await workerFetch(`/packets?since=${encodeURIComponent(req.query.since || '0')}`)).body); } catch (e) { res.status(502).json({ error: e.message, packets: [] }); } });
app.post('/api/action', async (req, res) => { try { const r = await workerFetch('/action', { method: 'POST', body: JSON.stringify({ action: req.body?.action }) }); io.emit('browser-state', r.body.state); res.json(r.body); } catch (e) { res.status(e.status || 502).json({ error: e.message }); } });
app.get('/api/screenshot', async (req, res) => {
  try { const r = await workerFetch('/screenshot'); const imageResponse = r.response; res.set('Content-Type', imageResponse.headers.get('content-type') || 'image/jpeg'); res.set('Cache-Control', 'no-store'); res.status(imageResponse.status); res.send(Buffer.from(await imageResponse.arrayBuffer())); }
  catch (e) { res.status(503).json({ error: e.message || 'Screenshot unavailable' }); }
});
app.post('/api/virustotal/url', async (req, res) => {
  if (!VT_KEY) return res.status(503).json({ error: 'VirusTotal is not configured. Add VIRUSTOTAL_API_KEY to .env and restart.' });
  let u; try { u = new URL(String(req.body?.url || '')); } catch { return res.status(400).json({ error: 'Enter a valid URL.' }); }
  if (!['http:', 'https:'].includes(u.protocol)) return res.status(400).json({ error: 'Only HTTP and HTTPS URLs are supported.' });
  try {
    // VirusTotal URL report lookup (does not submit a new scan).
    const id = Buffer.from(u.toString()).toString('base64').replace(/=/g, '');
    const vt = await fetch(`https://www.virustotal.com/api/v3/urls/${id}`, { headers: { 'x-apikey': VT_KEY }, signal: AbortSignal.timeout(12000) });
    const data = await vt.json().catch(() => ({}));
    if (vt.status === 404) return res.json({ found: false, message: 'No existing VirusTotal report was found for this URL.', note: 'This lookup did not submit the URL for scanning.' });
    if (!vt.ok) return res.status(vt.status === 429 ? 429 : 502).json({ error: data.error?.message || `VirusTotal returned ${vt.status}` });
    const stats = data.data?.attributes?.last_analysis_stats || {};
    res.json({ found: true, url: u.toString(), stats, reputation: data.data?.attributes?.reputation ?? null, lastAnalysisDate: data.data?.attributes?.last_analysis_date ? new Date(data.data.attributes.last_analysis_date * 1000).toISOString() : null });
  } catch (e) { res.status(502).json({ error: `VirusTotal lookup failed: ${e.message}` }); }
});

let lastPacketTimestamp = 0;
setInterval(async () => {
  try {
    const { body } = await workerFetch('/packets?since=0', { timeout: 4000 });
    const latest = (body.packets || []).filter(p => Date.parse(p.timestamp) > lastPacketTimestamp);
    for (const packet of latest) { io.emit('packet', packet); lastPacketTimestamp = Math.max(lastPacketTimestamp, Date.parse(packet.timestamp) || 0); }
    io.emit('metrics', { totalPacketsSeen: body.count || 0, updatedAt: new Date().toISOString() });
  } catch { io.emit('system-warning', { message: 'Packet worker is temporarily unavailable.' }); }
}, 1000);

io.on('connection', socket => { socket.emit('connected', { ok: true, time: new Date().toISOString() }); });
server.listen(PORT, '0.0.0.0', () => console.log(`AI Firewall dashboard listening on http://localhost:${PORT}`));
