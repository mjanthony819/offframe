import { analyze, strip, buildReceipt, defaultFileName, sha256Hex, OffframeError, VERSION, LIMITS } from './engine.js';
import { makeZip } from './zip.js';

const $ = (id) => document.getElementById(id);
const MAX_FILES = 20;
const MIME = { jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp' };
const SAMPLES = ['trail-photo.jpg', 'screen-capture.png', 'trailer.jpg', 'already-clean.jpg', 'hostile-comment.jpg', 'trail-photo.webp', 'alpha-sticker.webp', 'animated-clean.webp'];
const state = { items: [], selected: -1, urls: [] };

$('ver').textContent = VERSION;

// ----- helpers -----
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`);
const say = (t) => { $('status').textContent = t; };
const CAT = { location: 'Where you were', identity: 'Who you are', device: 'What took it', time: 'When it was taken', content: 'Notes and embedded images', hidden: 'Hidden data', software: 'Software', technical: 'Technical' };
const CAT_ORDER = ['location', 'identity', 'device', 'time', 'content', 'hidden', 'software', 'technical'];
const SEV = { high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

async function inflate(data, max) {
  const ds = new DecompressionStream('deflate');
  const w = ds.writable.getWriter();
  w.write(data).catch(() => {}); w.close().catch(() => {});
  const reader = ds.readable.getReader();
  const out = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) { reader.cancel().catch(() => {}); throw new Error('decompressed text is over the safety limit, not read'); }
    out.push(value);
  }
  const res = new Uint8Array(total);
  let o = 0;
  for (const c of out) { res.set(c, o); o += c.length; }
  return res;
}

function options() { return { keepOrientation: $('keepOri').checked, keepColorProfile: $('keepIcc').checked, inflate }; }

function download(name, bytes, type) {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

// Decode both files with the browser's own decoder and compare what it draws. If the rotation flag was deliberately dropped the two will differ by design, so the check is skipped then.
async function pixelsMatch(origBlob, cleanBlob, w, h, skip) {
  if (skip || typeof createImageBitmap !== 'function' || w * h > 40e6) return null;
  const grab = async (blob) => {
    const bmp = await createImageBitmap(blob, { imageOrientation: 'from-image', colorSpaceConversion: 'none', premultiplyAlpha: 'none' });
    const c = document.createElement('canvas'); c.width = bmp.width; c.height = bmp.height;
    const ctx = c.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(bmp, 0, 0);
    const px = ctx.getImageData(0, 0, c.width, c.height).data;
    bmp.close();
    return sha256Hex(new Uint8Array(px.buffer, px.byteOffset, px.byteLength));
  };
  try { const [a, b] = await Promise.all([grab(origBlob), grab(cleanBlob)]); return a === b; } catch { return null; }
}

// ----- intake -----
async function addFiles(fileList) {
  const files = [...fileList].slice(0, MAX_FILES - state.items.length);
  if (fileList.length > files.length) say(`Only ${MAX_FILES} files at a time. Extra files were skipped.`);
  for (const f of files) {
    const item = { name: f.name, size: f.size, status: 'working', error: null };
    state.items.push(item);
    renderQueue();
    try {
      if (f.size > LIMITS.maxFileBytes) throw new OffframeError('too-large', `Files over ${LIMITS.maxFileBytes / 1048576} MB are not accepted.`);
      const bytes = new Uint8Array(await f.arrayBuffer());
      item.origBytes = bytes;
      item.result = await strip(bytes, options());
      item.analysis = item.result.before;
      item.origUrl = URL.createObjectURL(new Blob([bytes], { type: MIME[item.analysis.format] }));
      const cleanBlob = new Blob([item.result.bytes], { type: MIME[item.analysis.format] });
      item.cleanUrl = URL.createObjectURL(cleanBlob);
      // Browsers honour the rotation flag in JPEG and PNG but ignore it in WebP (verified in Chrome 158),
      // so only JPEG/PNG get the rotation warning and skip the visual-equality check when it is dropped.
      const droppedFlag = !$('keepOri').checked && item.analysis.orientation > 1 && item.analysis.format !== 'webp';
      item.droppedRotation = droppedFlag;
      item.result.checks.decodedPixelsIdentical = await pixelsMatch(new Blob([bytes]), cleanBlob, item.analysis.width, item.analysis.height, droppedFlag);
      item.opts = { keepOrientation: $('keepOri').checked, keepColorProfile: $('keepIcc').checked };
      item.status = 'done';
    } catch (e) {
      item.status = 'error';
      item.error = e instanceof OffframeError ? e.message : 'This file could not be read safely.';
    }
    renderQueue();
    if (state.selected < 0 || item.status === 'done' && state.items[state.selected] && state.items[state.selected].status !== 'done') select(state.items.indexOf(item));
  }
  say(`${state.items.filter((i) => i.status === 'done').length} file(s) ready.`);
  $('batch').hidden = !state.items.some((i) => i.status === 'done');
}

async function loadSamples() {
  const files = [];
  for (const n of SAMPLES) {
    const r = await fetch(`fixtures/${n}`);
    const b = await r.blob();
    files.push(new File([b], n, { type: b.type }));
  }
  state.items.splice(0).forEach(freeItem); state.selected = -1;
  await addFiles(files);
}
function freeItem(i) { if (i.origUrl) URL.revokeObjectURL(i.origUrl); if (i.cleanUrl) URL.revokeObjectURL(i.cleanUrl); }

// ----- render -----
function renderQueue() {
  const q = $('queue'); q.textContent = '';
  $('count').textContent = state.items.length ? `(${state.items.length})` : '';
  state.items.forEach((it, i) => {
    const li = el('li');
    const b = el('button', 'qitem' + (i === state.selected ? ' on' : ''));
    b.type = 'button';
    b.setAttribute('aria-current', i === state.selected ? 'true' : 'false');
    const dot = el('span', `dot ${it.status === 'error' ? 'bad' : it.status === 'working' ? 'wait' : it.analysis && it.analysis.counts.high ? 'hi' : it.analysis && it.analysis.counts.medium + it.analysis.counts.low ? 'mid' : 'ok'}`);
    dot.setAttribute('aria-hidden', 'true');
    const name = el('span', 'qname', it.name);
    const sub = el('span', 'qsub', it.status === 'error' ? it.error : it.status === 'working' ? 'Reading...' : `${it.analysis.counts.high} high, ${it.analysis.counts.medium} medium, ${it.analysis.counts.low} low`);
    const col = el('span', 'qcol'); col.append(name, sub);
    b.append(dot, col);
    b.addEventListener('click', () => { select(i); if (matchMedia('(max-width:900px)').matches) $('main').scrollIntoView(); });
    li.append(b); q.append(li);
  });
}

function select(i) {
  state.selected = i; renderQueue();
  const it = state.items[i];
  const detail = $('detail');
  $('empty').hidden = true; detail.hidden = false; detail.textContent = '';
  if (!it) { detail.hidden = true; $('empty').hidden = false; return; }
  if (it.status === 'error') { detail.append(errorCard(it)); return; }
  if (it.status !== 'done') return;
  detail.append(header(it), verdict(it), el('div', 'cols'));
  const cols = detail.querySelector('.cols');
  cols.append(findingsCol(it), afterCol(it));
  detail.append(segmentsCard(it));
}

function errorCard(it) {
  const c = el('div', 'card err');
  c.append(el('h2', null, it.name), el('p', null, it.error), el('p', 'muted', 'Nothing was changed and nothing leaves your device. Only JPEG, PNG and WebP files are supported, and damaged files are refused rather than repaired.'));
  return c;
}

function header(it) {
  const a = it.analysis;
  const h = el('div', 'head');
  const t = el('div'); t.append(el('h2', 'fname', it.name), el('p', 'muted', `${a.details} - ${a.width} x ${a.height} px - ${fmtBytes(it.size)}`));
  const act = el('div', 'acts');
  const dl = el('button', 'primary', 'Download clean file'); dl.type = 'button';
  dl.addEventListener('click', () => download(defaultFileName(it.name, a.format), it.result.bytes, MIME[a.format]));
  const rc = el('button', 'soft', 'Receipt (JSON)'); rc.type = 'button';
  rc.addEventListener('click', () => download(`${it.name}.receipt.json`, new TextEncoder().encode(JSON.stringify(buildReceipt(it.name, it.result, it.opts), null, 2)), 'application/json'));
  const sc = el('button', 'soft', 'Summary card (PNG)'); sc.type = 'button';
  sc.title = 'A human-readable picture of what was removed, made to send along with the clean photo.';
  sc.addEventListener('click', () => {
    try {
      summaryCardCanvas(it).toBlob((b) => { if (b) download(`${it.name.replace(/\.[A-Za-z0-9]+$/, '')}.offframe-summary.png`, b, 'image/png'); }, 'image/png');
    } catch (e) { say('The summary card could not be drawn in this browser.'); }
  });
  act.append(dl, rc, sc); h.append(t, act); return h;
}

// A shareable, human-readable summary of one cleaned file, drawn locally on a canvas.
function summaryCardCanvas(it) {
  const W = 1080, pad = 72;
  const ink = '#14213d', accent = '#d9481f', muted = '#5a5548', paper = '#f7f4ee';
  const wrap = (x, text, yy, font, color, lh) => {
    x.font = font; x.fillStyle = color;
    const maxW = W - 2 * pad;
    for (const line of text.split('\n')) {
      let words = line.split(' '), cur = '';
      for (let w of words) {
        // A single word wider than the line (a long filename, say) is broken by character.
        while (x.measureText(w).width > maxW && w.length > 1) {
          let k = w.length;
          while (k > 1 && x.measureText(w.slice(0, k)).width > maxW) k--;
          if (cur) { x.fillText(cur, pad, yy); yy += lh; cur = ''; }
          x.fillText(w.slice(0, k), pad, yy); yy += lh;
          w = w.slice(k);
        }
        const t = cur ? cur + ' ' + w : w;
        if (x.measureText(t).width > maxW && cur) { x.fillText(cur, pad, yy); yy += lh; cur = w; } else cur = t;
      }
      if (cur) { x.fillText(cur, pad, yy); yy += lh; }
    }
    return yy;
  };
  // One layout routine, run twice: once on a scratch context to measure the wrapped
  // content height, then for real on a canvas sized to fit, so the footer and border
  // can never collide however long the filename or field list.
  const body = (x) => {
    let y = pad + 44;
    y = wrap(x, 'Offframe removal summary', y, '700 54px Georgia, serif', ink, 60) + 6;
    y = wrap(x, new Date().toLocaleString(undefined, { dateStyle: 'long', timeStyle: 'short' }), y, '400 26px system-ui, sans-serif', muted, 32) + 26;
    y = wrap(x, it.name, y, '600 36px system-ui, sans-serif', ink, 44);
    y = wrap(x, `${it.analysis.details} - ${it.analysis.width} x ${it.analysis.height} px`, y, '400 26px system-ui, sans-serif', muted, 32) + 26;
    const groups = new Map();
    for (const f of it.result.before.findings) {
      if (f.severity === 'info') continue;
      const k = CAT[f.category] || f.category;
      if (!groups.has(k)) groups.set(k, new Set());
      groups.get(k).add(f.label);
    }
    y = wrap(x, 'Removed', y, '700 34px system-ui, sans-serif', accent, 40) + 4;
    if (!groups.size) y = wrap(x, 'Nothing personal was stored in the file data.', y, '400 28px system-ui, sans-serif', ink, 36) + 6;
    else for (const [cat, labels] of groups) {
      y = wrap(x, `${cat}: ${[...labels].slice(0, 6).join('; ')}`, y, '400 28px system-ui, sans-serif', ink, 38) + 8;
    }
    y += 8;
    if (it.result.kept.length) y = wrap(x, `Kept on purpose: ${it.result.kept.join('; ')}`, y, '400 26px system-ui, sans-serif', muted, 34) + 18;
    y = wrap(x, 'Checked', y, '700 34px system-ui, sans-serif', accent, 40) + 4;
    const ch = it.result.checks;
    const lines = [
      ch.imageDataIdentical ? 'Image data is byte-identical before and after (SHA-256 match).' : 'Image data changed - do not use this output.',
      ch.dimensionsIdentical ? 'Dimensions unchanged.' : 'Dimensions changed - do not use this output.',
      ch.noMetadataFindingsLeft ? 'The cleaned file was re-scanned: none of the targeted identifying metadata is left (kept fields are listed above).' : 'Re-scan still finds metadata - do not use this output.',
      ch.decodedPixelsIdentical === true ? 'The browser decoded both files: pixels match.' : ch.decodedPixelsIdentical === false ? 'Decoded pixels differ - do not use this output.' : 'Pixel decode check not run for this file.',
    ];
    for (const l of lines) y = wrap(x, '- ' + l, y, '400 28px system-ui, sans-serif', ink, 38) + 2;
    y += 16;
    x.strokeStyle = muted; x.lineWidth = 2; x.beginPath(); x.moveTo(pad, y); x.lineTo(W - pad, y); x.stroke(); y += 42;
    y = wrap(x, 'Pixels were not changed: faces, signs, screens and other visible content stay in the picture. This card lists labels only, never the removed values.', y, '400 25px system-ui, sans-serif', muted, 33) + 10;
    return wrap(x, 'Made by Offframe v' + VERSION + ' - runs fully in the browser, nothing is uploaded.', y, '400 25px system-ui, sans-serif', muted, 33);
  };
  const yEnd = body(document.createElement('canvas').getContext('2d'));
  const H = Math.max(1350, Math.ceil(yEnd) + 72);
  const c = document.createElement('canvas'); c.width = W; c.height = H;
  const x = c.getContext('2d');
  x.fillStyle = paper; x.fillRect(0, 0, W, H);
  x.strokeStyle = ink; x.lineWidth = 6; x.strokeRect(28, 28, W - 56, H - 56);
  body(x);
  return c;
}

function verdict(it) {
  const c = it.analysis.counts;
  const total = c.high + c.medium + c.low;
  const v = el('div', 'verdict ' + (c.high ? 'hi' : total ? 'mid' : 'ok'));
  const big = el('p', 'vbig');
  if (!total) big.textContent = 'Nothing personal found in the file data.';
  else big.textContent = c.high ? `${c.high} high-risk ${c.high === 1 ? 'item' : 'items'} found, ${total} in total.` : `${total} ${total === 1 ? 'item' : 'items'} found, none high-risk.`;
  const sm = el('p', 'vsub', total ? 'Everything listed below is removed from the clean copy. A few display settings are kept on purpose, listed further down. The original file on your device is untouched.' : 'The clean copy is the same picture with the same data. Check the limits below: this does not look inside the pixels.');
  v.append(big, sm);
  const g = it.analysis.gps;
  if (g) {
    const gp = el('div', 'gps');
    gp.append(el('b', null, 'Location in this file: '), el('span', 'mono', `${g.lat.toFixed(5)}, ${g.lon.toFixed(5)}`), el('span', 'muted', ' - enough to find the spot on any map app.'));
    v.append(gp);
  }
  return v;
}

function findingsCol(it) {
  const col = el('section', 'card');
  col.append(el('h3', null, 'What this file says'));
  if (!it.analysis.findings.length) { col.append(el('p', 'muted', 'No metadata findings.')); return col; }
  for (const cat of CAT_ORDER) {
    const list = it.analysis.findings.filter((f) => f.category === cat && f.severity !== 'info');
    if (!list.length) continue;
    col.append(el('h4', null, CAT[cat]));
    const ul = el('ul', 'flist');
    for (const f of list) {
      const li = el('li');
      li.append(el('span', `chip ${f.severity}`, SEV[f.severity]));
      const body = el('span', 'fbody');
      body.append(el('span', 'flabel', f.label), el('span', 'fval mono', f.value || '(empty)'));
      if (f.note) body.append(el('span', 'fnote', f.note));
      li.append(body); ul.append(li);
    }
    col.append(ul);
  }
  const info = it.analysis.findings.filter((f) => f.severity === 'info');
  if (info.length) col.append(el('p', 'muted', `Also present: ${info.map((f) => `${f.label} ${f.value}`).join('; ')}.`));
  if (it.analysis.issues.length) col.append(el('p', 'muted', `Parser notes: ${it.analysis.issues.join('; ')}.`));
  return col;
}

function checkRow(ok, text, detail) {
  const li = el('li', ok === true ? 'pass' : ok === false ? 'fail' : 'skip');
  li.append(el('span', 'tick', ok === true ? 'Pass' : ok === false ? 'Fail' : 'Skipped'), el('span', null, text));
  if (detail) li.append(el('span', 'muted mono', detail));
  return li;
}

function afterCol(it) {
  const col = el('section', 'card');
  col.append(el('h3', null, 'Before and after'));
  const pair = el('div', 'pair');
  for (const [label, url] of [['Original', it.origUrl], ['Clean copy', it.cleanUrl]]) {
    const f = el('figure');
    const img = document.createElement('img'); img.src = url; img.alt = `${label} of ${it.name}`;
    f.append(img, el('figcaption', null, `${label} - ${fmtBytes(label === 'Original' ? it.size : it.result.bytes.length)}`));
    pair.append(f);
  }
  col.append(pair);
  const c = it.result.checks;
  col.append(el('h4', null, 'Checked after removal'));
  const ul = el('ul', 'checks');
  ul.append(
    checkRow(c.imageDataIdentical, 'Image data is byte-identical to the original', c.imageDataSha256.slice(0, 16) + '...'),
    checkRow(c.dimensionsIdentical, 'Width and height are unchanged', `${it.analysis.width} x ${it.analysis.height}`),
    checkRow(c.decodedPixelsIdentical, 'Your browser draws both files as the same picture', c.decodedPixelsIdentical === null ? (it.droppedRotation ? 'skipped: you chose to drop the rotation flag' : 'not available for this size') : ''),
    checkRow(c.noMetadataFindingsLeft, 'Re-reading the clean copy finds none of the supported identifying fields', c.leftovers.join(', ')),
  );
  col.append(ul);
  const kept = it.result.kept;
  col.append(el('h4', null, 'Kept on purpose'));
  col.append(el('p', 'muted', kept.length ? `${kept.join('; ')}. These affect how the picture displays. Rotation is itself metadata, and a colour profile can carry a vendor or software name; untick the matching option on the left to remove them.` : 'Nothing beyond the image itself.'));
  if (it.droppedRotation) col.append(el('p', 'warn', `Heads up: this file was stored sideways and relied on a rotation flag (${it.analysis.orientation}). With the flag removed, most viewers will show the clean copy rotated differently from the original, as the previews above show. Turn the first option back on to keep it upright.`));
  return col;
}

function segmentsCard(it) {
  const card = el('section', 'card');
  card.append(el('h3', null, 'What was cut and what stayed'));
  const t = el('table', 'seg');
  const th = el('tr'); for (const h of ['Part of the file', 'Size', 'Result']) th.append(el('th', null, h));
  t.append(th);
  const optsNow = it.opts;
  const rows = it.analysis.items;
  if (!rows.length) { card.append(el('p', 'muted', 'The file has no optional segments. Only the image itself.')); return card; }
  for (const r of rows) {
    const tr = el('tr');
    const removed = !r.keep || (r.optional && !optsNow.keepColorProfile);
    tr.append(el('td', null, r.label), el('td', 'mono', fmtBytes(r.bytes)), el('td', removed ? 'cut' : 'kept', removed ? 'Removed' : 'Kept'));
    t.append(tr);
  }
  card.append(t);
  const note = [];
  if (it.result.kept.some((k) => k.startsWith('Orientation'))) note.push('The rotation flag was rewritten as the only tag in a fresh, minimal EXIF block so the picture still opens upright.');
  if (it.result.kept.some((k) => k.includes('rebuilt'))) note.push('The JFIF header was rebuilt without its embedded thumbnail.');
  if (note.length) card.append(el('p', 'muted', note.join(' ')));
  return card;
}

// ----- wiring -----
const drop = $('drop'), input = $('file');
drop.addEventListener('click', () => input.click());
drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
input.addEventListener('change', () => { addFiles(input.files); input.value = ''; });
for (const ev of ['dragenter', 'dragover']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); });
for (const ev of ['dragleave', 'drop']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); });
drop.addEventListener('drop', (e) => addFiles(e.dataTransfer.files));
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => { e.preventDefault(); });
$('samples').addEventListener('click', () => loadSamples().catch(() => say('Samples could not be loaded.')));
$('folderBtn').addEventListener('click', () => $('folderFile').click());
$('folderFile').addEventListener('change', async () => {
  const all = [...$('folderFile').files];
  $('folderFile').value = '';
  const ok = all.filter((f) => /\.(jpe?g|png|webp)$/i.test(f.name));
  const skipped = all.length - ok.length;
  await addFiles(ok);
  if (skipped) say(`${state.items.filter((i) => i.status === 'done').length} file(s) ready. ${skipped} unsupported file(s) in that folder were skipped - only JPEG, PNG and WebP are read.`);
});
$('zipAll').addEventListener('click', () => {
  const used = new Set(); const files = [];
  for (const it of state.items.filter((i) => i.status === 'done')) {
    let n = defaultFileName(it.name, it.analysis.format); let k = 1;
    while (used.has(n)) n = n.replace(/\.offframe\./, `.offframe-${++k}.`);
    used.add(n);
    files.push({ name: n, data: it.result.bytes });
    files.push({ name: `receipts/${n}.receipt.json`, data: new TextEncoder().encode(JSON.stringify(buildReceipt(it.name, it.result, it.opts), null, 2)) });
  }
  download('offframe-clean-files.zip', makeZip(files), 'application/zip');
});
// changing options reprocesses what is loaded
for (const id of ['keepOri', 'keepIcc']) $(id).addEventListener('change', async () => {
  const keep = state.items.filter((i) => i.origBytes);
  if (!keep.length) return;
  const sel = state.selected;
  const rebuilt = keep.map((i) => new File([i.origBytes], i.name));
  state.items.splice(0).forEach(freeItem); state.selected = -1;
  await addFiles(rebuilt);
  if (sel >= 0 && sel < state.items.length) select(sel);
});
const themeBtn = $('theme');
const saved = (() => { try { return localStorage.getItem('offframe-theme'); } catch { return null; } })();
if (saved) document.documentElement.dataset.theme = saved;
themeBtn.addEventListener('click', () => {
  const dark = (document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')) === 'dark';
  const next = dark ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('offframe-theme', next); } catch { /* storage may be blocked */ }
});
