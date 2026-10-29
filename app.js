const socket = io();
const $ = id => document.getElementById(id);
let packetList = [], protocolSet = new Set(), alerts = 0, errors = 0, newestTimestamp = 0;
const MAX_ROWS = 120;
function timeNow() { return new Date().toLocaleTimeString('en-GB', { hour12: false }); }
$('clock').textContent = timeNow(); setInterval(() => $('clock').textContent = timeNow(), 1000);
function showNotice(message, type = 'info') { const n = $('notice'); n.textContent = message; n.className = `notice ${type === 'error' ? 'error' : ''}`; n.classList.remove('hidden'); }
function clearNotice() { $('notice').classList.add('hidden'); }
function eventLog(title, detail, type = '') {
  const row = document.createElement('div'); row.className = `event ${type}`;
  const dot = document.createElement('span'); dot.className = 'event-dot';
  const body = document.createElement('div'); const strong = document.createElement('strong'); strong.textContent = title;
  const p = document.createElement('p'); p.textContent = detail; body.append(strong, p);
  const time = document.createElement('time'); time.textContent = timeNow(); row.append(dot, body, time);
  $('events').prepend(row); while ($('events').children.length > 35) $('events').lastElementChild.remove();
}
function escapeText(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function renderPacket(p) {
  packetList.unshift(p); if (packetList.length > MAX_ROWS) packetList.pop();
  protocolSet.add(p.protocol || 'Unknown');
  const protocol = String(p.protocols || p.protocol || 'Unknown').split(':').pop().toUpperCase();
  const likelyFlag = /malware|exploit|telnet|smb|rdp/i.test(p.protocols || '') || Number(p.destinationPort) === 23;
  if (likelyFlag) { alerts++; $('alertCount').textContent = alerts; eventLog('Heuristic packet flag', `${protocol} traffic observed to ${p.destination}:${p.destinationPort}. This is a heuristic, not a malware verdict.`, 'warning'); }
  const tr = document.createElement('tr');
  const t = p.timestamp ? new Date(p.timestamp).toLocaleTimeString('en-GB', { hour12: false }) : timeNow();
  tr.innerHTML = `<td>${escapeText(t)}</td><td title="${escapeText(p.source)} → ${escapeText(p.destination)}">${escapeText(shortAddress(p.source))} → ${escapeText(shortAddress(p.destination))}<br><span style="color:#61798c;font-size:9px">${escapeText(p.sourcePort)} → ${escapeText(p.destinationPort)}</span></td><td><span class="proto">${escapeText(protocol)}</span></td><td>${Number(p.size) || 0} B</td><td><span class="state-pill">OBSERVED</span></td>`;
  const tbody = $('packetRows'); if (tbody.querySelector('.empty-row')) tbody.innerHTML = ''; tbody.prepend(tr); while (tbody.children.length > MAX_ROWS) tbody.lastElementChild.remove();
  $('packetCountLabel').textContent = `${packetList.length} packets shown`; $('protocolCount').textContent = protocolSet.size;
}
function shortAddress(s) { s = String(s || '—'); return s.length > 20 ? `${s.slice(0, 9)}…${s.slice(-8)}` : s; }
async function navigate(url) {
  clearNotice(); $('openBtn').disabled = true; $('openBtn').textContent = 'OPENING…';
  $('browserBadge').textContent = 'LOADING'; $('browserBadge').className = 'badge neutral';
  eventLog('Navigation requested', `Opening ${url} in the isolated browser.`);
  try {
    const r = await fetch('/api/navigate', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url }) });
    const data = await r.json(); if (!r.ok) throw new Error(data.error || 'Navigation failed');
    updateBrowserState(data.state); await refreshScreenshot();
    showNotice('Website opened in the isolated browser. Packet capture displays network metadata; encrypted HTTPS payloads are not readable.', 'info');
    eventLog('Browser navigation complete', `${data.state.title || data.state.url || url}`);
  } catch (e) { errors++; $('errorCount').textContent = errors; $('browserBadge').textContent = 'ERROR'; $('browserBadge').className = 'badge neutral'; showNotice(e.message, 'error'); eventLog('Navigation failed', e.message, 'error'); }
  finally { $('openBtn').disabled = false; $('openBtn').innerHTML = 'OPEN IN SANDBOX <span>→</span>'; }
}
function updateBrowserState(s) {
  if (!s) return;
  $('sandboxStatus').textContent = `SANDBOX ${String(s.status || 'UNKNOWN').toUpperCase()}`;
  $('browserBadge').textContent = String(s.status || 'unknown').toUpperCase();
  $('currentUrl').textContent = s.url || 'Waiting for navigation'; $('pageTitle').textContent = s.title || 'No page title';
  if (s.status === 'loaded') $('browserBadge').className = 'badge live';
  if (s.error) { eventLog('Browser / request error', s.error, 'warning'); }
}
async function refreshScreenshot() {
  const img = $('preview'); img.onload = () => { img.classList.remove('hidden'); $('previewPlaceholder').classList.add('hidden'); };
  img.onerror = () => { img.classList.add('hidden'); $('previewPlaceholder').classList.remove('hidden'); };
  img.src = `/api/screenshot?ts=${Date.now()}`;
}
$('navigateForm').addEventListener('submit', e => { e.preventDefault(); navigate($('urlInput').value.trim()); });
document.querySelectorAll('[data-action]').forEach(b => b.addEventListener('click', async () => {
  try { const r = await fetch('/api/action', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: b.dataset.action }) }); const d = await r.json(); if (!r.ok) throw new Error(d.error); updateBrowserState(d.state); await refreshScreenshot(); }
  catch (e) { showNotice(e.message, 'error'); }
}));
async function lookupVirusTotal() {
  const url = $('urlInput').value.trim(); if (!url) return showNotice('Enter a URL first.', 'error');
  $('vtBadge').textContent = 'LOOKING UP'; $('vtResult').innerHTML = '<p class="sub">Checking for an existing VirusTotal report…</p>';
  try {
    const r = await fetch('/api/virustotal/url', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url }) });
    const d = await r.json(); if (!r.ok) throw new Error(d.error || 'Lookup failed');
    if (!d.found) { $('vtBadge').textContent = 'NO REPORT'; $('vtResult').innerHTML = `<div class="empty-state"><strong>No existing report found</strong><p>${escapeText(d.message)}</p><p>${escapeText(d.note)}</p></div>`; eventLog('VirusTotal lookup', 'No existing report was found; URL was not submitted.'); return; }
    const s = d.stats || {}; const malicious = Number(s.malicious || 0), suspicious = Number(s.suspicious || 0);
    $('vtBadge').textContent = malicious ? 'DETECTIONS FOUND' : suspicious ? 'SUSPICIOUS' : 'REPORT FOUND';
    $('vtResult').innerHTML = `<div class="vt-stats"><div class="vt-stat"><b style="color:var(--red)">${malicious}</b><span>MALICIOUS</span></div><div class="vt-stat"><b style="color:var(--amber)">${Number(s.suspicious||0)}</b><span>SUSPICIOUS</span></div><div class="vt-stat"><b>${Number(s.harmless||0)}</b><span>HARMLESS</span></div><div class="vt-stat"><b>${Number(s.undetected||0)}</b><span>UNDETECTED</span></div></div><div class="vt-url">${escapeText(d.url)}</div><p class="sub">Last analysis: ${escapeText(d.lastAnalysisDate || 'Not available')}. Results are from VirusTotal and are not a guarantee of safety.</p>`;
    eventLog('VirusTotal report retrieved', `${malicious} malicious, ${suspicious} suspicious detections reported.`, malicious ? 'warning' : '');
  } catch (e) { $('vtBadge').textContent = 'UNAVAILABLE'; $('vtResult').innerHTML = `<div class="empty-state"><strong>Lookup unavailable</strong><p>${escapeText(e.message)}</p></div>`; eventLog('VirusTotal lookup failed', e.message, 'warning'); }
}
$('vtBtn').addEventListener('click', lookupVirusTotal); $('vtBtn2').addEventListener('click', lookupVirusTotal);
$('clearEvents').addEventListener('click', () => { $('events').innerHTML = ''; eventLog('Event list cleared', 'Visible session events were cleared.'); });
socket.on('connected', () => eventLog('Live dashboard connected', 'Socket.IO telemetry channel is active.'));
socket.on('packet', p => { const ts = Date.parse(p.timestamp) || 0; if (ts > newestTimestamp) newestTimestamp = ts; renderPacket(p); });
socket.on('browser-state', updateBrowserState);
socket.on('metrics', m => { $('totalPackets').textContent = Number(m.totalPacketsSeen || 0).toLocaleString(); });
socket.on('system-warning', d => eventLog('Monitoring service warning', d.message, 'warning'));
async function init() {
  try { const r = await fetch('/api/health'); const h = await r.json(); $('sandboxStatus').textContent = h.browserWorker === 'online' ? 'SANDBOX READY' : 'WORKER OFFLINE'; if (h.browserWorker !== 'online') eventLog('Browser worker unavailable', 'Check Docker logs and restart the project.', 'error'); }
  catch { eventLog('Health check failed', 'Dashboard could not reach the browser worker.', 'error'); }
  try { const r = await fetch('/api/packets'); const d = await r.json(); (d.packets || []).slice(-MAX_ROWS).reverse().forEach(renderPacket); $('totalPackets').textContent = Number(d.count || 0).toLocaleString(); }
  catch {}
  try { const r = await fetch('/api/state'); if (r.ok) { const s = await r.json(); updateBrowserState(s); if (s.url) await refreshScreenshot(); } } catch {}
  setInterval(() => { if (!$('preview').classList.contains('hidden')) refreshScreenshot(); }, 3000);
}
init();
