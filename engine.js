// Offframe engine: parse, report and strip metadata from JPEG, PNG and WebP bytes.
// Pure functions over Uint8Array. No DOM, no network. Runs in browsers and Node.
// Scope: JPEG (baseline, extended, progressive), PNG (including APNG) and WebP
// (lossy, lossless and animated). Nothing else.

export const VERSION = '1.1.0';
export const LIMITS = Object.freeze({
  maxFileBytes: 50 * 1024 * 1024,
  maxIfdEntries: 512,
  maxIfdDepth: 4,
  maxTextInflate: 1024 * 1024,
  maxXmpScan: 512 * 1024,
});

export class OffframeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'OffframeError';
    this.code = code;
  }
}

const dec = new TextDecoder('utf-8', { fatal: false });
const latin1 = (b, s = 0, e = b.length) => {
  let out = '';
  for (let i = s; i < e; i++) out += String.fromCharCode(b[i]);
  return out;
};
const startsWith = (b, off, str) => {
  if (off + str.length > b.length) return false;
  for (let i = 0; i < str.length; i++) if (b[off + i] !== str.charCodeAt(i)) return false;
  return true;
};

// ---------- file type ----------
export function sniff(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'jpeg';
  if (bytes.length >= 8 && bytes[0] === 0x89 && startsWith(bytes, 1, 'PNG') && bytes[4] === 0x0d && bytes[5] === 0x0a && bytes[6] === 0x1a && bytes[7] === 0x0a) return 'png';
  if (bytes.length >= 12 && startsWith(bytes, 0, 'RIFF') && startsWith(bytes, 8, 'WEBP')) return 'webp';
  return null;
}

// ---------- CRC32 and SHA-256 ----------
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
export function crc32(bytes, start = 0, end = bytes.length, seed = 0) {
  let c = (seed ^ 0xffffffff) >>> 0;
  for (let i = start; i < end; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
export async function sha256Hex(bytes) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new OffframeError('no-crypto', 'SHA-256 is not available in this environment.');
  const d = new Uint8Array(await subtle.digest('SHA-256', bytes));
  return [...d].map((x) => x.toString(16).padStart(2, '0')).join('');
}

// ---------- findings ----------
// severity: high | medium | low | info.  category: location | identity | device | time | content | hidden | software | technical
function finding(category, severity, label, value, source, extra = {}) {
  return { category, severity, label, value, source, ...extra };
}

// ---------- TIFF / EXIF ----------
const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 };

const IFD0_TAGS = {
  0x010e: ['ImageDescription', 'content', 'medium'],
  0x010f: ['Camera make', 'device', 'medium'],
  0x0110: ['Camera model', 'device', 'medium'],
  0x0112: ['Orientation', 'technical', 'info'],
  0x0131: ['Software', 'software', 'low'],
  0x0132: ['File modified time', 'time', 'medium'],
  0x013b: ['Artist', 'identity', 'high'],
  0x013c: ['Host computer', 'device', 'medium'],
  0x8298: ['Copyright', 'identity', 'medium'],
  0x9c9b: ['Windows title', 'content', 'medium'],
  0x9c9c: ['Windows comment', 'content', 'medium'],
  0x9c9d: ['Windows author', 'identity', 'high'],
  0x9c9e: ['Windows keywords', 'content', 'medium'],
  0x9c9f: ['Windows subject', 'content', 'medium'],
};
const EXIF_TAGS = {
  0x9003: ['Date taken', 'time', 'medium'],
  0x9004: ['Date digitized', 'time', 'medium'],
  0x9010: ['Time zone offset', 'time', 'low'],
  0x9011: ['Time zone offset (original)', 'time', 'low'],
  0x9012: ['Time zone offset (digitized)', 'time', 'low'],
  0x9286: ['User comment', 'content', 'medium'],
  0x927c: ['Maker note (opaque camera data)', 'device', 'medium'],
  0xa420: ['Image unique ID', 'identity', 'medium'],
  0xa430: ['Camera owner name', 'identity', 'high'],
  0xa431: ['Camera body serial number', 'identity', 'high'],
  0xa433: ['Lens make', 'device', 'low'],
  0xa434: ['Lens model', 'device', 'low'],
  0xa435: ['Lens serial number', 'identity', 'high'],
};
const GPS_TAGS = {
  0x0001: 'GPSLatitudeRef', 0x0002: 'GPSLatitude', 0x0003: 'GPSLongitudeRef', 0x0004: 'GPSLongitude',
  0x0005: 'GPSAltitudeRef', 0x0006: 'GPSAltitude', 0x0007: 'GPSTimeStamp', 0x0010: 'GPSImgDirectionRef',
  0x0011: 'GPSImgDirection', 0x0012: 'GPSMapDatum', 0x001b: 'GPSProcessingMethod', 0x001c: 'GPSAreaInformation',
  0x001d: 'GPSDateStamp',
};

function makeReader(b, base, len, le) {
  const end = base + len;
  const ok = (o, n) => o >= 0 && n >= 0 && base + o + n <= end;
  return {
    ok,
    u8: (o) => b[base + o],
    u16: (o) => (le ? b[base + o] | (b[base + o + 1] << 8) : (b[base + o] << 8) | b[base + o + 1]),
    u32: (o) =>
      le
        ? (b[base + o] | (b[base + o + 1] << 8) | (b[base + o + 2] << 16) | (b[base + o + 3] << 24)) >>> 0
        : ((b[base + o] << 24) | (b[base + o + 1] << 16) | (b[base + o + 2] << 8) | b[base + o + 3]) >>> 0,
    i32(o) { return this.u32(o) | 0; },
    bytes: (o, n) => b.subarray(base + o, base + o + n),
  };
}

function readValue(r, type, count, valueOff) {
  const size = TYPE_SIZE[type];
  if (!size) return { unsupported: true };
  const total = size * count;
  let off = valueOff;
  if (total <= 4) off = valueOff; // inline in entry
  else {
    off = r.u32(valueOff);
    if (!r.ok(off, total)) return { outOfBounds: true };
  }
  if (count > 4096 && type !== 2 && type !== 7 && type !== 1) return { tooLong: true };
  switch (type) {
    case 2: {
      const raw = r.bytes(off, total);
      let e = raw.length;
      while (e > 0 && raw[e - 1] === 0) e--;
      return { text: latin1(raw, 0, e) };
    }
    case 1: case 7: return { raw: r.bytes(off, total), nums: Array.from(r.bytes(off, Math.min(total, 64))) };
    case 3: { const a = []; for (let i = 0; i < Math.min(count, 64); i++) a.push(r.u16(off + i * 2)); return { nums: a, raw: r.bytes(off, total) }; }
    case 4: { const a = []; for (let i = 0; i < Math.min(count, 64); i++) a.push(r.u32(off + i * 4)); return { nums: a }; }
    case 5: { const a = []; for (let i = 0; i < Math.min(count, 16); i++) { const n = r.u32(off + i * 8), d = r.u32(off + i * 8 + 4); a.push(d ? n / d : 0); } return { nums: a }; }
    case 10: { const a = []; for (let i = 0; i < Math.min(count, 16); i++) { const n = r.i32(off + i * 8), d = r.i32(off + i * 8 + 4); a.push(d ? n / d : 0); } return { nums: a }; }
    case 8: { const a = []; for (let i = 0; i < Math.min(count, 64); i++) a.push((r.u16(off + i * 2) << 16) >> 16); return { nums: a }; }
    case 9: { const a = []; for (let i = 0; i < Math.min(count, 64); i++) a.push(r.i32(off + i * 4)); return { nums: a }; }
    default: return { nums: [] };
  }
}

function ucs2(raw) {
  let s = '';
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const c = raw[i] | (raw[i + 1] << 8);
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

/**
 * Parse a TIFF/EXIF block. Returns { findings, orientation, hasThumbnail, gps, issues }.
 * Never throws on malformed data: problems are recorded in issues.
 */
export function parseTiff(b, base = 0, len = b.length - base, sourceLabel = 'EXIF') {
  const out = { findings: [], orientation: null, hasThumbnail: false, gps: null, issues: [] };
  if (len < 8) { out.issues.push('EXIF block too short'); return out; }
  const bo = latin1(b, base, base + 2);
  if (bo !== 'II' && bo !== 'MM') { out.issues.push('EXIF byte order marker invalid'); return out; }
  const le = bo === 'II';
  const r = makeReader(b, base, len, le);
  if (r.u16(2) !== 42) { out.issues.push('EXIF magic number invalid'); return out; }
  const visited = new Set();
  const gpsVals = {};

  function readIfd(off, kind, depth) {
    if (depth > LIMITS.maxIfdDepth) { out.issues.push('EXIF IFD nesting too deep'); return 0; }
    if (visited.has(off)) { out.issues.push('EXIF IFD loop detected'); return 0; }
    visited.add(off);
    if (!r.ok(off, 2)) { out.issues.push(`${kind} offset out of range`); return 0; }
    const n = r.u16(off);
    if (n > LIMITS.maxIfdEntries) { out.issues.push(`${kind} has too many entries`); return 0; }
    if (!r.ok(off + 2, n * 12)) { out.issues.push(`${kind} entries run past the block`); return 0; }
    let thumbOff = null, thumbLen = null;
    for (let i = 0; i < n; i++) {
      const e = off + 2 + i * 12;
      const tag = r.u16(e), type = r.u16(e + 2), count = r.u32(e + 4);
      if (count > 0x1000000) continue;
      if (kind === 'IFD0' || kind === 'Exif') {
        if (tag === 0x8769 && kind === 'IFD0') { readIfd(r.u32(e + 8), 'Exif', depth + 1); continue; }
        if (tag === 0x8825 && kind === 'IFD0') { readIfd(r.u32(e + 8), 'GPS', depth + 1); continue; }
        if (tag === 0xa005 && kind === 'Exif') { readIfd(r.u32(e + 8), 'Interop', depth + 1); continue; }
      }
      if (kind === 'IFD1') {
        if (tag === 0x0201) thumbOff = r.u32(e + 8);
        if (tag === 0x0202) thumbLen = r.u32(e + 8);
        continue;
      }
      const v = readValue(r, type, count, e + 8);
      if (v.outOfBounds) { out.issues.push(`${kind} tag 0x${tag.toString(16)} points outside the block`); continue; }
      if (kind === 'GPS') { gpsVals[tag] = v; continue; }
      const table = kind === 'IFD0' ? IFD0_TAGS : kind === 'Exif' ? EXIF_TAGS : null;
      const meta = table && table[tag];
      if (!meta) continue;
      const [label, category, severity] = meta;
      let value;
      if (tag === 0x0112) { out.orientation = v.nums ? v.nums[0] : null; value = describeOrientation(out.orientation); }
      else if (tag >= 0x9c9b && tag <= 0x9f9f && tag >= 0x9c9b && tag <= 0x9c9f) value = ucs2(v.raw || new Uint8Array());
      else if (tag === 0x927c) value = `${count} bytes`;
      else if (tag === 0x9286) {
        const raw = v.raw || new Uint8Array();
        const pre = latin1(raw, 0, Math.min(8, raw.length));
        value = latin1(raw, pre.startsWith('ASCII') || pre.startsWith('UNICODE') || pre.startsWith('JIS') ? 8 : 0, raw.length).replace(/\0/g, '').slice(0, 200);
      } else if (v.text !== undefined) value = v.text.slice(0, 200);
      else if (v.nums) value = v.nums.slice(0, 8).join(', ');
      else value = '(binary)';
      if (tag === 0x0112 && (out.orientation === 1 || out.orientation == null)) {
        out.findings.push(finding(category, 'info', label, value, `${sourceLabel} ${kind}`, { tag: '0x0112' }));
      } else out.findings.push(finding(category, severity, label, value, `${sourceLabel} ${kind}`, { tag: '0x' + tag.toString(16).padStart(4, '0') }));
    }
    if (r.ok(off + 2 + n * 12, 4)) return r.u32(off + 2 + n * 12);
    if (thumbOff != null && thumbLen) out.hasThumbnail = true;
    return 0;
  }

  const ifd0 = r.u32(4);
  const next = readIfd(ifd0, 'IFD0', 0);
  if (next) {
    // IFD1 describes an embedded thumbnail.
    const before = visited.size;
    const saveFindings = out.findings.length;
    const nIfd1 = (() => {
      if (visited.has(next) || !r.ok(next, 2)) return 0;
      visited.add(next);
      const n = r.u16(next);
      if (n > LIMITS.maxIfdEntries || !r.ok(next + 2, n * 12)) return 0;
      let o = null, l = null;
      for (let i = 0; i < n; i++) {
        const e = next + 2 + i * 12;
        const tag = r.u16(e);
        if (tag === 0x0201) o = r.u32(e + 8);
        if (tag === 0x0202) l = r.u32(e + 8);
      }
      return o != null && l ? l : 0;
    })();
    void before; void saveFindings;
    if (nIfd1) {
      out.hasThumbnail = true;
      out.findings.push(finding('content', 'medium', 'Embedded thumbnail image', `${nIfd1} bytes`, `${sourceLabel} IFD1`, { note: 'A thumbnail can still show the original picture after the main image was cropped or edited.' }));
    }
  }

  if (gpsVals[0x0002] && gpsVals[0x0004] && gpsVals[0x0002].nums && gpsVals[0x0004].nums) {
    const toDeg = (a) => (a.length >= 3 ? a[0] + a[1] / 60 + a[2] / 3600 : a[0] || 0);
    let lat = toDeg(gpsVals[0x0002].nums), lon = toDeg(gpsVals[0x0004].nums);
    const latRef = gpsVals[0x0001] && gpsVals[0x0001].text, lonRef = gpsVals[0x0003] && gpsVals[0x0003].text;
    if (latRef === 'S') lat = -lat;
    if (lonRef === 'W') lon = -lon;
    if (Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180) {
      out.gps = { lat, lon };
      out.findings.push(finding('location', 'high', 'GPS coordinates', `${lat.toFixed(6)}, ${lon.toFixed(6)}`, `${sourceLabel} GPS`, { gps: { lat, lon }, note: 'Anyone holding this file can paste these numbers into a map app.' }));
    } else out.issues.push('GPS values present but out of range');
  }
  for (const [tag, name] of Object.entries(GPS_TAGS)) {
    const t = Number(tag);
    if (!gpsVals[t] || t === 0x0001 || t === 0x0002 || t === 0x0003 || t === 0x0004) continue;
    const v = gpsVals[t];
    const val = v.text !== undefined ? v.text : v.raw && (t === 0x001b || t === 0x001c) ? latin1(v.raw).replace(/\0/g, '').slice(0, 120) : v.nums ? v.nums.slice(0, 4).map((x) => (typeof x === 'number' ? +x.toFixed(3) : x)).join(', ') : '';
    const sev = t === 0x0006 || t === 0x0011 ? 'medium' : t === 0x0007 || t === 0x001d ? 'medium' : 'low';
    out.findings.push(finding(t === 0x0007 || t === 0x001d ? 'time' : 'location', sev, name.replace('GPS', 'GPS '), val, `${sourceLabel} GPS`, { tag: '0x' + t.toString(16).padStart(4, '0') }));
  }
  return out;
}

function describeOrientation(o) {
  const names = { 1: 'normal', 2: 'mirrored', 3: 'rotated 180 degrees', 4: 'flipped vertically', 5: 'transposed', 6: 'rotated 90 degrees clockwise', 7: 'transverse', 8: 'rotated 90 degrees counter-clockwise' };
  return o ? `${o} (${names[o] || 'unknown'})` : 'not set';
}

/** Minimal EXIF TIFF block holding only the Orientation tag. */
export function buildOrientationTiff(orientation) {
  const t = new Uint8Array(8 + 2 + 12 + 4);
  const dv = new DataView(t.buffer);
  t[0] = 0x4d; t[1] = 0x4d; dv.setUint16(2, 42); dv.setUint32(4, 8);
  dv.setUint16(8, 1);
  dv.setUint16(10, 0x0112); dv.setUint16(12, 3); dv.setUint32(14, 1); dv.setUint16(18, orientation);
  dv.setUint32(22, 0);
  return t;
}

// ---------- XMP and IPTC ----------
const NOTABLE_XMP = /^(dc:creator|dc:rights|dc:title|dc:description|dc:subject|photoshop:Credit|photoshop:City|photoshop:Country|photoshop:AuthorsPosition|xmp:CreatorTool|xmp:CreateDate|xmp:ModifyDate|xmpRights:.*|exif:GPS.*|exif:DateTimeOriginal|tiff:Make|tiff:Model|aux:SerialNumber|aux:Lens|Iptc4xmpCore:.*|xmpMM:DocumentID|xmpMM:InstanceID|xmpMM:History|crs:.*|MicrosoftPhoto:.*|mwg-rs:.*|lr:.*)$/;
export function parseXmp(text, source = 'XMP') {
  const findings = [];
  const scan = text.slice(0, LIMITS.maxXmpScan);
  const seen = new Set();
  const add = (k, v) => {
    const val = v.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    if (!val || seen.has(k + val) || !NOTABLE_XMP.test(k)) return;
    seen.add(k + val);
    if (findings.length >= 24) return;
    const isLoc = /GPS|City|Country|Location/i.test(k);
    const isId = /creator|rights|Credit|Author|SerialNumber|DocumentID|InstanceID/i.test(k);
    findings.push(finding(isLoc ? 'location' : isId ? 'identity' : /Date/i.test(k) ? 'time' : /Tool|crs:/i.test(k) ? 'software' : 'content', isLoc ? 'high' : isId ? 'medium' : 'low', k, val.slice(0, 160), source));
  };
  for (const m of scan.matchAll(/<([A-Za-z0-9_-]+:[A-Za-z0-9_-]+)(?:\s[^>]*)?>/g)) {
    if (!NOTABLE_XMP.test(m[1])) continue;
    const from = m.index + m[0].length;
    const close = scan.indexOf(`</${m[1]}>`, from);
    if (close > from) add(m[1], scan.slice(from, Math.min(close, from + 2000)));
  }
  for (const m of scan.matchAll(/\s([A-Za-z0-9_-]+:[A-Za-z0-9_-]+)="([^"]*)"/g)) add(m[1], m[2]);
  return findings;
}

const IPTC_NAMES = { 5: 'Title', 25: 'Keywords', 55: 'Date created', 80: 'By-line (author)', 90: 'City', 92: 'Sub-location', 95: 'State or province', 101: 'Country', 110: 'Credit', 115: 'Source', 116: 'Copyright notice', 120: 'Caption' };
export function parseIptc(b, s, e) {
  const findings = [];
  let p = s;
  while (p + 12 <= e) {
    if (!startsWith(b, p, '8BIM')) break;
    const id = (b[p + 4] << 8) | b[p + 5];
    let q = p + 6;
    const nameLen = b[q];
    q += 1 + nameLen;
    if (q % 2 === 1 && ((q - s) % 2 === 1)) q += 0; // pascal string padding handled below
    if ((1 + nameLen) % 2 === 1) q += 1;
    if (q + 4 > e) break;
    const size = ((b[q] << 24) | (b[q + 1] << 16) | (b[q + 2] << 8) | b[q + 3]) >>> 0;
    q += 4;
    if (q + size > e) break;
    if (id === 0x0404) {
      let r = q;
      const end = q + size;
      while (r + 5 <= end && b[r] === 0x1c) {
        const rec = b[r + 1], ds = b[r + 2];
        const l = (b[r + 3] << 8) | b[r + 4];
        if (r + 5 + l > end) break;
        if (rec === 2 && IPTC_NAMES[ds]) {
          const label = IPTC_NAMES[ds];
          const isLoc = ds === 90 || ds === 92 || ds === 95 || ds === 101;
          const isId = ds === 80 || ds === 110 || ds === 115 || ds === 116;
          findings.push(finding(isLoc ? 'location' : isId ? 'identity' : ds === 55 ? 'time' : 'content', isLoc ? 'high' : isId ? 'high' : 'medium', `IPTC ${label}`, dec.decode(b.subarray(r + 5, r + 5 + l)).slice(0, 160), 'IPTC (Photoshop block)'));
        }
        r += 5 + l;
      }
    }
    p = q + size + (size % 2);
  }
  return findings;
}

// ---------- JPEG ----------
const SOF_MARKERS = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);

/** Walk the JPEG into segments. Throws OffframeError for structurally broken files. */
export function walkJpeg(b) {
  if (b.length < 4 || b[0] !== 0xff || b[1] !== 0xd8) throw new OffframeError('not-jpeg', 'This does not start with a JPEG header.');
  const segments = [];
  let p = 2;
  let sawSof = false, sawScan = false, eoi = -1;
  let info = null;
  while (p < b.length) {
    if (b[p] !== 0xff) throw new OffframeError('jpeg-corrupt', `Unexpected byte at offset ${p}; the JPEG structure is damaged.`);
    while (p < b.length && b[p] === 0xff) p++; // fill bytes
    if (p >= b.length) break;
    const m = b[p++];
    if (m === 0x00) throw new OffframeError('jpeg-corrupt', 'Stray 0xFF00 outside image data.');
    if (m === 0xd9) { eoi = p; segments.push({ marker: m, start: p - 2, end: p, kind: 'EOI' }); break; }
    if (m >= 0xd0 && m <= 0xd7 || m === 0x01) { segments.push({ marker: m, start: p - 2, end: p, kind: 'MARK' }); continue; }
    if (p + 2 > b.length) throw new OffframeError('jpeg-truncated', 'The file ends in the middle of a segment header.');
    const len = (b[p] << 8) | b[p + 1];
    if (len < 2) throw new OffframeError('jpeg-corrupt', `Bad segment length at offset ${p}.`);
    const segStart = p - 2;
    const dataStart = p + 2;
    const segEnd = p + len;
    if (segEnd > b.length) throw new OffframeError('jpeg-truncated', 'A segment runs past the end of the file.');
    if (SOF_MARKERS.has(m)) {
      if (len < 8) throw new OffframeError('jpeg-corrupt', 'Frame header too short.');
      sawSof = true;
      info = { precision: b[dataStart], height: (b[dataStart + 1] << 8) | b[dataStart + 2], width: (b[dataStart + 3] << 8) | b[dataStart + 4], components: b[dataStart + 5], progressive: m === 0xc2 || m === 0xc6 || m === 0xca || m === 0xce };
      if (!info.width || !info.height) throw new OffframeError('jpeg-corrupt', 'Frame header reports a zero-sized image.');
    }
    segments.push({ marker: m, start: segStart, end: segEnd, dataStart, kind: m === 0xda ? 'SOS' : 'SEG' });
    p = segEnd;
    if (m === 0xda) {
      if (!sawSof) throw new OffframeError('jpeg-corrupt', 'Scan data before any frame header.');
      sawScan = true;
      // entropy coded data: until a marker that is not RSTn or stuffed 0xFF00
      const scanStart = p;
      while (p < b.length) {
        if (b[p] === 0xff) {
          const n = b[p + 1];
          if (n === 0x00 || (n >= 0xd0 && n <= 0xd7)) { p += 2; continue; }
          if (n === 0xff) { p += 1; continue; }
          break;
        }
        p++;
      }
      segments[segments.length - 1].scanEnd = p;
      segments[segments.length - 1].scanStart = scanStart;
      if (p >= b.length) throw new OffframeError('jpeg-truncated', 'The image data stops before the end-of-image marker.');
    }
  }
  if (!sawSof || !sawScan) throw new OffframeError('jpeg-corrupt', 'No image data found.');
  if (eoi < 0) throw new OffframeError('jpeg-truncated', 'No end-of-image marker; the file looks cut off.');
  return { segments, info, eoi, trailer: b.length - eoi };
}

function classifyApp(b, seg) {
  const m = seg.marker, d = seg.dataStart, e = seg.end;
  if (m === 0xfe) return { id: 'COM', keep: false, label: 'JPEG comment' };
  if (m < 0xe0 || m > 0xef) return { id: 'core', keep: true };
  if (m === 0xe0) {
    if (startsWith(b, d, 'JFIF\0')) return { id: 'JFIF', keep: true, rebuild: true, label: 'JFIF header' };
    if (startsWith(b, d, 'JFXX\0')) return { id: 'JFXX', keep: false, label: 'JFIF extension thumbnail' };
    return { id: 'APP0?', keep: false, label: 'Unknown APP0 data' };
  }
  if (m === 0xe1) {
    if (startsWith(b, d, 'Exif\0\0')) return { id: 'EXIF', keep: false, label: 'EXIF block' };
    if (startsWith(b, d, 'http://ns.adobe.com/xap/1.0/\0')) return { id: 'XMP', keep: false, label: 'XMP block' };
    if (startsWith(b, d, 'http://ns.adobe.com/xmp/extension/\0')) return { id: 'XMPX', keep: false, label: 'Extended XMP block' };
    return { id: 'APP1?', keep: false, label: 'Unknown APP1 data' };
  }
  if (m === 0xe2) {
    if (startsWith(b, d, 'ICC_PROFILE\0')) return { id: 'ICC', keep: true, optional: true, label: 'Colour profile (ICC)' };
    if (startsWith(b, d, 'MPF\0')) return { id: 'MPF', keep: false, label: 'Multi-picture data' };
    return { id: 'APP2?', keep: false, label: 'Unknown APP2 data' };
  }
  if (m === 0xed && startsWith(b, d, 'Photoshop 3.0\0')) return { id: 'IPTC', keep: false, label: 'Photoshop / IPTC block' };
  if (m === 0xee && startsWith(b, d, 'Adobe')) return { id: 'ADOBE', keep: true, label: 'Adobe colour-transform marker' };
  void e;
  return { id: `APP${m - 0xe0}?`, keep: false, label: `Application data (APP${m - 0xe0})` };
}

function analyzeJpeg(b) {
  const walk = walkJpeg(b);
  const findings = [];
  const issues = [];
  const items = [];
  let orientation = null, gps = null, hasThumbnail = false;
  let iccPresent = false;
  for (const seg of walk.segments) {
    if (seg.kind === 'SEG' || seg.kind === 'SOS') {
      const c = classifyApp(b, seg);
      if (c.id === 'core') continue;
      const size = seg.end - seg.start;
      items.push({ id: c.id, label: c.label, bytes: size, keep: c.keep, optional: !!c.optional });
      if (c.id === 'EXIF') {
        const t = parseTiff(b, seg.dataStart + 6, seg.end - seg.dataStart - 6, 'EXIF');
        findings.push(...t.findings);
        issues.push(...t.issues);
        if (t.orientation) orientation = t.orientation;
        if (t.gps) gps = t.gps;
        if (t.hasThumbnail) hasThumbnail = true;
      } else if (c.id === 'XMP') {
        findings.push(...parseXmp(latin1(b, seg.dataStart + 29, Math.min(seg.end, seg.dataStart + 29 + LIMITS.maxXmpScan)), 'XMP'));
        findings.push(finding('hidden', 'medium', 'XMP metadata block', `${size} bytes`, 'XMP'));
      } else if (c.id === 'XMPX') {
        findings.push(finding('hidden', 'medium', 'Extended XMP block', `${size} bytes`, 'XMP'));
      } else if (c.id === 'IPTC') {
        const f = parseIptc(b, seg.dataStart + 14, seg.end);
        findings.push(...f);
        if (!f.length) findings.push(finding('hidden', 'medium', 'Photoshop / IPTC block', `${size} bytes`, 'APP13'));
      } else if (c.id === 'COM') {
        findings.push(finding('content', 'medium', 'JPEG comment', latin1(b, seg.dataStart, Math.min(seg.end, seg.dataStart + 200)).replace(/[^\x20-\x7e]/g, ' '), 'COM'));
      } else if (c.id === 'MPF') {
        findings.push(finding('hidden', 'medium', 'Multi-picture data (may point at extra embedded images)', `${size} bytes`, 'APP2 MPF'));
      } else if (c.id === 'JFXX') {
        findings.push(finding('content', 'medium', 'Extension thumbnail image', `${size} bytes`, 'JFXX'));
      } else if (c.id === 'JFIF') {
        const tw = b[seg.dataStart + 12], th = b[seg.dataStart + 13];
        if (tw && th) findings.push(finding('content', 'medium', 'JFIF thumbnail image', `${tw} x ${th} px`, 'JFIF'));
      } else if (c.id === 'ICC') {
        iccPresent = true;
      } else if (!c.keep) {
        findings.push(finding('hidden', 'low', c.label, `${size} bytes`, `APP marker 0x${seg.marker.toString(16)}`));
      }
    }
  }
  if (walk.trailer > 0) {
    findings.push(finding('hidden', 'high', 'Extra bytes after the end of the image', `${walk.trailer} bytes`, 'Trailer', { note: 'Viewers ignore data after the JPEG end marker, so files can carry hidden content here.' }));
    items.push({ id: 'TRAILER', label: 'Bytes after end-of-image', bytes: walk.trailer, keep: false });
  }
  return { format: 'jpeg', width: walk.info.width, height: walk.info.height, details: `${walk.info.progressive ? 'progressive' : 'baseline'} JPEG, ${walk.info.components} channel(s), ${walk.info.precision}-bit`, findings, issues, items, orientation, gps, hasThumbnail, iccPresent, walk };
}

function buildJfif(b, seg) {
  const d = seg.dataStart;
  const out = new Uint8Array(2 + 2 + 14);
  out[0] = 0xff; out[1] = 0xe0; out[2] = 0; out[3] = 16;
  for (let i = 0; i < 5; i++) out[4 + i] = b[d + i];
  out[9] = b[d + 5]; out[10] = b[d + 6]; out[11] = b[d + 7];
  out[12] = b[d + 8]; out[13] = b[d + 9]; out[14] = b[d + 10]; out[15] = b[d + 11];
  out[16] = 0; out[17] = 0; // no thumbnail
  return out;
}

function concat(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function stripJpeg(b, a, opts) {
  const parts = [b.subarray(0, 2)];
  const kept = [], removed = [];
  const keepOrientation = opts.keepOrientation && a.orientation && a.orientation > 1;
  let orientationWritten = false;
  const walk = a.walk;
  for (const seg of walk.segments) {
    if (seg.kind === 'EOI') { parts.push(b.subarray(seg.start, seg.end)); break; }
    if (seg.kind === 'MARK') { parts.push(b.subarray(seg.start, seg.end)); continue; }
    if (seg.kind === 'SOS') { parts.push(b.subarray(seg.start, seg.scanEnd)); continue; }
    const c = classifyApp(b, seg);
    if (c.id === 'core') { parts.push(b.subarray(seg.start, seg.end)); continue; }
    if (c.id === 'JFIF') {
      parts.push(buildJfif(b, seg));
      kept.push(c.label + ' (rebuilt without thumbnail)');
      continue;
    }
    if (c.id === 'ICC' && !opts.keepColorProfile) { removed.push(c.label); continue; }
    if (c.keep) { parts.push(b.subarray(seg.start, seg.end)); kept.push(c.label); continue; }
    removed.push(c.label);
    if (c.id === 'EXIF' && keepOrientation && !orientationWritten) {
      const tiff = buildOrientationTiff(a.orientation);
      const payload = concat([new Uint8Array([0x45, 0x78, 0x69, 0x66, 0, 0]), tiff]);
      const hdr = new Uint8Array([0xff, 0xe1, ((payload.length + 2) >> 8) & 0xff, (payload.length + 2) & 0xff]);
      parts.push(hdr, payload);
      orientationWritten = true;
      kept.push('Orientation tag only (rewritten EXIF)');
    }
  }
  return { bytes: concat(parts), kept, removed };
}

function jpegImageHash(b, a) {
  const parts = [];
  for (const seg of a.walk.segments) {
    if (seg.kind === 'SOS') parts.push(b.subarray(seg.start, seg.scanEnd));
    else if (seg.kind === 'SEG' && (SOF_MARKERS.has(seg.marker) || seg.marker === 0xc4 || seg.marker === 0xdb || seg.marker === 0xdd)) parts.push(b.subarray(seg.start, seg.end));
  }
  return concat(parts);
}

// ---------- PNG ----------
const PNG_KEEP = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'gAMA', 'cHRM', 'sRGB', 'sBIT', 'bKGD', 'pHYs', 'acTL', 'fcTL', 'fdAT', 'cICP', 'mDCV', 'cLLI', 'hIST']);

export function walkPng(b) {
  if (sniff(b) !== 'png') throw new OffframeError('not-png', 'This does not start with a PNG header.');
  const chunks = [];
  let p = 8;
  let sawIhdr = false, sawIdat = false, iend = -1;
  while (p < b.length) {
    if (p + 12 > b.length) throw new OffframeError('png-truncated', 'The file ends in the middle of a chunk.');
    const len = ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
    if (len > 0x7fffffff) throw new OffframeError('png-corrupt', 'A chunk reports an impossible length.');
    const type = latin1(b, p + 4, p + 8);
    if (!/^[A-Za-z]{4}$/.test(type)) throw new OffframeError('png-corrupt', 'A chunk has an invalid name.');
    const dataStart = p + 8, dataEnd = dataStart + len;
    if (dataEnd + 4 > b.length) throw new OffframeError('png-truncated', `Chunk ${type} runs past the end of the file.`);
    const stored = ((b[dataEnd] << 24) | (b[dataEnd + 1] << 16) | (b[dataEnd + 2] << 8) | b[dataEnd + 3]) >>> 0;
    const actual = crc32(b, p + 4, dataEnd);
    if (stored !== actual) throw new OffframeError('png-crc', `Chunk ${type} fails its checksum, so the file is damaged.`);
    if (!sawIhdr && type !== 'IHDR') throw new OffframeError('png-corrupt', 'IHDR must be the first chunk.');
    if (type === 'IHDR') { if (sawIhdr) throw new OffframeError('png-corrupt', 'Duplicate IHDR.'); if (len !== 13) throw new OffframeError('png-corrupt', 'IHDR has the wrong size.'); sawIhdr = true; }
    if (type === 'IDAT') sawIdat = true;
    chunks.push({ type, start: p, end: dataEnd + 4, dataStart, dataEnd });
    p = dataEnd + 4;
    if (type === 'IEND') { iend = p; break; }
  }
  if (!sawIhdr || !sawIdat) throw new OffframeError('png-corrupt', 'No image data found.');
  if (iend < 0) throw new OffframeError('png-truncated', 'No IEND chunk; the file looks cut off.');
  const ih = chunks[0];
  const width = ((b[ih.dataStart] << 24) | (b[ih.dataStart + 1] << 16) | (b[ih.dataStart + 2] << 8) | b[ih.dataStart + 3]) >>> 0;
  const height = ((b[ih.dataStart + 4] << 24) | (b[ih.dataStart + 5] << 16) | (b[ih.dataStart + 6] << 8) | b[ih.dataStart + 7]) >>> 0;
  if (!width || !height) throw new OffframeError('png-corrupt', 'IHDR reports a zero-sized image.');
  return { chunks, width, height, bitDepth: b[ih.dataStart + 8], colorType: b[ih.dataStart + 9], trailer: b.length - iend };
}

function pngIsAncillary(type) { return (type.charCodeAt(0) & 0x20) !== 0; }

async function readPngText(b, ch, inflate) {
  const d = ch.dataStart, e = ch.dataEnd;
  const readKey = () => { let i = d; while (i < e && b[i] !== 0) i++; return { key: latin1(b, d, i), next: i + 1 }; };
  const { key, next } = readKey();
  if (ch.type === 'tEXt') return { key, text: latin1(b, next, e) };
  if (ch.type === 'zTXt') {
    if (!inflate) return { key, text: '(compressed)' };
    try { const raw = await inflate(b.subarray(next + 1, e), LIMITS.maxTextInflate); return { key, text: dec.decode(raw) }; } catch (err) { return { key, text: '(compressed text not readable)', note: String(err.message || err) }; }
  }
  // iTXt: key\0 compFlag compMethod lang\0 translated\0 text
  let i = next;
  const comp = b[i], i0 = i;
  i += 2;
  while (i < e && b[i] !== 0) i++;
  i++;
  while (i < e && b[i] !== 0) i++;
  i++;
  void i0;
  if (i > e) return { key, text: '' };
  if (comp === 1) {
    if (!inflate) return { key, text: '(compressed)' };
    try { const raw = await inflate(b.subarray(i, e), LIMITS.maxTextInflate); return { key, text: dec.decode(raw) }; } catch (err) { return { key, text: '(compressed text not readable)' }; }
  }
  return { key, text: dec.decode(b.subarray(i, e)) };
}

const PNG_TEXT_META = (key) => {
  const k = key.toLowerCase();
  if (k === 'software') return ['software', 'low', 'Software'];
  if (k === 'author' || k === 'artist' || k === 'copyright') return ['identity', 'high', key];
  if (k === 'creation time' || k === 'date:create' || k === 'date:modify') return ['time', 'medium', key];
  if (k === 'parameters' || k === 'prompt' || k === 'workflow') return ['content', 'high', `${key} (generator settings or prompt)`];
  if (k === 'xml:com.adobe.xmp') return ['hidden', 'medium', 'XMP metadata'];
  if (k.startsWith('raw profile type')) return ['hidden', 'medium', `${key} (embedded metadata dump)`];
  if (k === 'comment' || k === 'description' || k === 'title' || k === 'source' || k === 'warning' || k === 'disclaimer') return ['content', 'medium', key];
  return ['content', 'low', key];
};

async function analyzePng(b, opts) {
  const walk = walkPng(b);
  const findings = [], issues = [], items = [];
  let orientation = null, gps = null, hasThumbnail = false, iccPresent = false;
  for (const ch of walk.chunks) {
    if (ch.type === 'IHDR' || ch.type === 'IDAT' || ch.type === 'IEND') continue;
    const size = ch.end - ch.start;
    const keepByDefault = PNG_KEEP.has(ch.type) || ch.type === 'iCCP';
    if (!PNG_KEEP.has(ch.type) && ch.type !== 'iCCP' && !pngIsAncillary(ch.type)) throw new OffframeError('png-unknown-critical', `Unknown critical chunk ${ch.type}; Offframe will not guess how to rewrite it.`);
    if (ch.type === 'iCCP') { iccPresent = true; items.push({ id: 'iCCP', label: 'Colour profile (ICC)', bytes: size, keep: true, optional: true }); continue; }
    if (keepByDefault) { if (ch.type !== 'PLTE' && ch.type !== 'fdAT') items.push({ id: ch.type, label: `${ch.type} chunk`, bytes: size, keep: true }); continue; }
    items.push({ id: ch.type, label: `${ch.type} chunk`, bytes: size, keep: false });
    if (ch.type === 'tEXt' || ch.type === 'zTXt' || ch.type === 'iTXt') {
      const t = await readPngText(b, ch, opts.inflate);
      const [cat, sev, label] = PNG_TEXT_META(t.key);
      findings.push(finding(cat, sev, label, (t.text || '').replace(/\s+/g, ' ').slice(0, 200), `PNG ${ch.type}`));
      if (t.key === 'XML:com.adobe.xmp') findings.push(...parseXmp(t.text || '', 'XMP in PNG'));
    } else if (ch.type === 'eXIf') {
      const t = parseTiff(b, ch.dataStart, ch.dataEnd - ch.dataStart, 'PNG eXIf');
      findings.push(...t.findings);
      issues.push(...t.issues);
      if (t.orientation) orientation = t.orientation;
      if (t.gps) gps = t.gps;
      if (t.hasThumbnail) hasThumbnail = true;
    } else if (ch.type === 'tIME') {
      const y = (b[ch.dataStart] << 8) | b[ch.dataStart + 1];
      const p2 = (n) => String(n).padStart(2, '0');
      findings.push(finding('time', 'medium', 'Last-modified time (tIME)', `${y}-${p2(b[ch.dataStart + 2])}-${p2(b[ch.dataStart + 3])} ${p2(b[ch.dataStart + 4])}:${p2(b[ch.dataStart + 5])}:${p2(b[ch.dataStart + 6])} UTC`, 'PNG tIME'));
    } else if (ch.type === 'sPLT') {
      findings.push(finding('hidden', 'low', 'Suggested palette (sPLT)', `${size} bytes`, 'PNG'));
    } else {
      findings.push(finding('hidden', 'low', `Private chunk ${ch.type}`, `${size} bytes`, 'PNG'));
    }
  }
  if (walk.trailer > 0) {
    findings.push(finding('hidden', 'high', 'Extra bytes after the end of the image', `${walk.trailer} bytes`, 'Trailer', { note: 'Viewers ignore data after IEND, so files can carry hidden content here.' }));
    items.push({ id: 'TRAILER', label: 'Bytes after IEND', bytes: walk.trailer, keep: false });
  }
  const hasApng = walk.chunks.some((c) => c.type === 'acTL');
  return { format: 'png', width: walk.width, height: walk.height, details: `PNG${hasApng ? ' (animated)' : ''}, ${walk.bitDepth}-bit, colour type ${walk.colorType}`, findings, issues, items, orientation, gps, hasThumbnail, iccPresent, walk };
}

function crcChunk(type, data) {
  const out = new Uint8Array(12 + data.length);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, data.length);
  for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
  out.set(data, 8);
  dv.setUint32(8 + data.length, crc32(out, 4, 8 + data.length));
  return out;
}

function stripPng(b, a, opts) {
  const parts = [b.subarray(0, 8)];
  const kept = [], removed = [];
  const wantOri = opts.keepOrientation && a.orientation && a.orientation > 1;
  let wrote = false;
  for (const ch of a.walk.chunks) {
    const t = ch.type;
    if (t === 'IHDR' || t === 'IDAT' || t === 'IEND') { parts.push(b.subarray(ch.start, ch.end)); continue; }
    if (t === 'iCCP') {
      if (opts.keepColorProfile) { parts.push(b.subarray(ch.start, ch.end)); kept.push('Colour profile (ICC)'); } else removed.push('Colour profile (ICC)');
      continue;
    }
    if (PNG_KEEP.has(t)) { parts.push(b.subarray(ch.start, ch.end)); if (t !== 'PLTE' && t !== 'fdAT') kept.push(`${t} chunk`); continue; }
    removed.push(`${t} chunk`);
    if (t === 'eXIf' && wantOri && !wrote) {
      parts.push(crcChunk('eXIf', buildOrientationTiff(a.orientation)));
      wrote = true;
      kept.push('Orientation tag only (rewritten eXIf)');
    }
  }
  return { bytes: concat(parts), kept: dedupe(kept), removed: dedupe(removed) };
}
const dedupe = (a) => [...new Set(a)];

function pngImageData(b, a) {
  const parts = [];
  for (const ch of a.walk.chunks) {
    if (ch.type === 'IHDR' || ch.type === 'PLTE' || ch.type === 'IDAT' || ch.type === 'tRNS' || ch.type === 'fdAT' || ch.type === 'fcTL' || ch.type === 'acTL') parts.push(b.subarray(ch.start, ch.end));
  }
  return concat(parts);
}

// ---------- WebP ----------
const u32leAt = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;

// Walk the RIFF container. Strict about structure: anything malformed is refused, not guessed at.
export function walkWebp(b) {
  if (sniff(b) !== 'webp') throw new OffframeError('not-webp', 'This does not start with a WebP (RIFF) header.');
  const declared = u32leAt(b, 4) + 8;
  if (declared > b.length) throw new OffframeError('webp-truncated', 'The RIFF header says the file holds more data than is present; it looks cut off.');
  const chunks = [];
  let p = 12;
  while (p < declared) {
    if (p + 8 > declared) throw new OffframeError('webp-corrupt', 'A chunk header does not fit inside the RIFF payload.');
    const type = latin1(b, p, p + 4);
    if (!/^[\x20-\x7e]{4}$/.test(type)) throw new OffframeError('webp-corrupt', 'A chunk has an invalid name.');
    const size = u32leAt(b, p + 4);
    const dataStart = p + 8, dataEnd = dataStart + size;
    if (dataEnd > declared) throw new OffframeError('webp-truncated', `Chunk ${type} runs past the end of the file.`);
    const end = dataEnd + (size & 1); // chunks are padded to even sizes
    chunks.push({ type, start: p, end, dataStart, dataEnd, size });
    p = end;
  }
  if (!chunks.length) throw new OffframeError('webp-corrupt', 'No chunks inside the RIFF container.');
  return { chunks, trailer: b.length - declared };
}

const WEBP_KEEP = { 'VP8 ': 'Image data (lossy WebP)', 'VP8L': 'Image data (lossless WebP)', 'VP8X': 'WebP feature flags', 'ALPH': 'Transparency data', 'ANIM': 'Animation settings', 'ANMF': 'Animation frame data' };

function webpDimensions(b, chunks) {
  const x = chunks.find((c) => c.type === 'VP8X');
  if (x && x.size >= 10) {
    return {
      width: 1 + (b[x.dataStart + 4] | (b[x.dataStart + 5] << 8) | (b[x.dataStart + 6] << 16)),
      height: 1 + (b[x.dataStart + 7] | (b[x.dataStart + 8] << 8) | (b[x.dataStart + 9] << 16)),
    };
  }
  const v8 = chunks.find((c) => c.type === 'VP8 ');
  if (v8 && v8.size >= 10 && b[v8.dataStart + 3] === 0x9d && b[v8.dataStart + 4] === 0x01 && b[v8.dataStart + 5] === 0x2a) {
    return { width: (b[v8.dataStart + 6] | (b[v8.dataStart + 7] << 8)) & 0x3fff, height: (b[v8.dataStart + 8] | (b[v8.dataStart + 9] << 8)) & 0x3fff };
  }
  const vl = chunks.find((c) => c.type === 'VP8L');
  if (vl && vl.size >= 5 && b[vl.dataStart] === 0x2f) {
    const b1 = b[vl.dataStart + 1], b2 = b[vl.dataStart + 2], b3 = b[vl.dataStart + 3], b4 = b[vl.dataStart + 4];
    return { width: 1 + (((b2 & 0x3f) << 8) | b1), height: 1 + (((b4 & 0x0f) << 10) | (b3 << 2) | ((b2 & 0xc0) >> 6)) };
  }
  throw new OffframeError('webp-corrupt', 'No readable image dimensions found.');
}

function analyzeWebp(b) {
  const walk = walkWebp(b);
  const dim = webpDimensions(b, walk.chunks);
  if (!dim.width || !dim.height) throw new OffframeError('webp-corrupt', 'The WebP header reports a zero-sized image.');
  const findings = [], issues = [], items = [];
  let orientation = null, gps = null, iccPresent = false, hasThumbnail = false;
  let lossless = false, animated = false, alpha = false;
  for (const ch of walk.chunks) {
    const size = ch.end - ch.start;
    if (ch.type === 'EXIF') {
      items.push({ id: 'EXIF', label: 'EXIF block', bytes: size, keep: false });
      const t = parseTiff(b, ch.dataStart, ch.size, 'EXIF');
      findings.push(...t.findings);
      issues.push(...t.issues);
      if (t.orientation) orientation = t.orientation;
      if (t.gps) gps = t.gps;
      if (t.hasThumbnail) hasThumbnail = true;
    } else if (ch.type === 'XMP ') {
      items.push({ id: 'XMP', label: 'XMP block', bytes: size, keep: false });
      findings.push(...parseXmp(latin1(b, ch.dataStart, Math.min(ch.dataEnd, ch.dataStart + LIMITS.maxXmpScan)), 'XMP'));
      findings.push(finding('hidden', 'medium', 'XMP metadata block', `${size} bytes`, 'XMP'));
    } else if (ch.type === 'ICCP') {
      items.push({ id: 'ICCP', label: 'Colour profile (ICC)', bytes: size, keep: true, optional: true });
      iccPresent = true;
    } else if (WEBP_KEEP[ch.type]) {
      items.push({ id: ch.type === 'VP8 ' ? 'VP8' : ch.type, label: WEBP_KEEP[ch.type], bytes: size, keep: true });
      if (ch.type === 'VP8L') lossless = true;
      if (ch.type === 'ANIM' || ch.type === 'ANMF') animated = true;
      if (ch.type === 'ALPH') alpha = true;
    } else {
      const shown = ch.type.replace(/[^\x20-\x7e]/g, '?');
      items.push({ id: 'UNK:' + shown, label: `Unknown WebP chunk (${shown})`, bytes: size, keep: false });
      findings.push(finding('hidden', 'low', `Unknown WebP chunk (${shown})`, `${size} bytes`, 'RIFF'));
    }
  }
  if (walk.trailer > 0) {
    findings.push(finding('hidden', 'high', 'Extra bytes after the end of the image', `${walk.trailer} bytes`, 'Trailer', { note: 'Viewers ignore data after the RIFF payload, so files can carry hidden content here.' }));
    items.push({ id: 'TRAILER', label: 'Bytes after end of image', bytes: walk.trailer, keep: false });
  }
  const details = `${animated ? 'animated ' : ''}${lossless ? 'lossless' : 'lossy'} WebP${alpha ? ', with transparency' : ''}`;
  return { format: 'webp', width: dim.width, height: dim.height, details, findings, issues, items, orientation, gps, hasThumbnail, iccPresent, walk };
}

function webpChunk(type, data) {
  const out = new Uint8Array(8 + data.length + (data.length & 1));
  for (let i = 0; i < 4; i++) out[i] = type.charCodeAt(i);
  const dv = new DataView(out.buffer);
  dv.setUint32(4, data.length, true);
  out.set(data, 8);
  return out;
}

const WEBP_FLAG_ICC = 0x20, WEBP_FLAG_EXIF = 0x08, WEBP_FLAG_XMP = 0x04;

function stripWebp(b, a, opts) {
  const kept = [], removed = [];
  const keepOrientation = opts.keepOrientation && a.orientation && a.orientation > 1;
  const willWriteOrientation = !!keepOrientation; // the source EXIF chunk exists whenever orientation was read
  let orientationWritten = false;
  const body = [];
  for (const ch of a.walk.chunks) {
    if (ch.type === 'EXIF') {
      removed.push('EXIF block');
      if (keepOrientation && !orientationWritten) {
        body.push(webpChunk('EXIF', buildOrientationTiff(a.orientation)));
        orientationWritten = true;
        kept.push('Orientation tag only (rewritten EXIF)');
      }
      continue;
    }
    if (ch.type === 'XMP ') { removed.push('XMP block'); continue; }
    if (ch.type === 'ICCP') {
      if (opts.keepColorProfile) { body.push(b.subarray(ch.start, ch.end)); kept.push('Colour profile (ICC)'); }
      else removed.push('Colour profile (ICC)');
      continue;
    }
    if (ch.type === 'VP8X') {
      if (ch.size !== 10) throw new OffframeError('webp-corrupt', 'VP8X chunk has the wrong size.');
      const d = b.slice(ch.dataStart, ch.dataEnd);
      let flags = d[0];
      flags &= ~WEBP_FLAG_XMP;
      if (!willWriteOrientation) flags &= ~WEBP_FLAG_EXIF;
      if (!(opts.keepColorProfile && a.iccPresent)) flags &= ~WEBP_FLAG_ICC;
      d[0] = flags;
      body.push(webpChunk('VP8X', d));
      kept.push('WebP feature flags (updated)');
      continue;
    }
    if (WEBP_KEEP[ch.type]) { body.push(b.subarray(ch.start, ch.end)); kept.push(WEBP_KEEP[ch.type]); continue; }
    removed.push(`Unknown WebP chunk (${ch.type.replace(/[^\x20-\x7e]/g, '?')})`);
  }
  if (a.walk.trailer > 0) removed.push('Bytes after end of image');
  const payload = concat(body);
  const head = new Uint8Array(12);
  head.set([0x52, 0x49, 0x46, 0x46]); // RIFF
  new DataView(head.buffer).setUint32(4, payload.length + 4, true);
  head.set([0x57, 0x45, 0x42, 0x50], 8); // WEBP
  return { bytes: concat([head, payload]), kept, removed };
}

function webpImageData(b, a) {
  const parts = [];
  for (const ch of a.walk.chunks) {
    if (ch.type === 'VP8 ' || ch.type === 'VP8L' || ch.type === 'ALPH' || ch.type === 'ANIM' || ch.type === 'ANMF') parts.push(b.subarray(ch.start, ch.end));
  }
  return concat(parts);
}

// ---------- public API ----------
const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

/** Analyze bytes. Throws OffframeError when the file is unsupported or damaged. */
export async function analyze(bytes, opts = {}) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('analyze expects a Uint8Array');
  if (bytes.length > LIMITS.maxFileBytes) throw new OffframeError('too-large', `Files over ${LIMITS.maxFileBytes / 1048576} MB are not accepted.`);
  const kind = sniff(bytes);
  if (!kind) throw new OffframeError('unsupported', 'Only JPEG, PNG and WebP files are supported. This file is something else.');
  const a = kind === 'jpeg' ? analyzeJpeg(bytes) : kind === 'png' ? await analyzePng(bytes, opts) : analyzeWebp(bytes);
  a.findings.sort((x, y) => SEVERITY_ORDER[x.severity] - SEVERITY_ORDER[y.severity]);
  a.counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of a.findings) a.counts[f.severity]++;
  a.byteLength = bytes.length;
  return a;
}

/**
 * Strip metadata. Returns { bytes, kept, removed, before, after, checks }.
 * checks.imageDataIdentical compares SHA-256 of the entropy-coded image data and frame headers before and after.
 */
export async function strip(bytes, opts = {}) {
  const o = { keepOrientation: true, keepColorProfile: true, inflate: opts.inflate, ...opts };
  const before = await analyze(bytes, o);
  const strippers = { jpeg: stripJpeg, png: stripPng, webp: stripWebp };
  const imageData = { jpeg: jpegImageHash, png: pngImageData, webp: webpImageData };
  const r = strippers[before.format](bytes, before, o);
  const after = await analyze(r.bytes, o);
  const dataBefore = imageData[before.format](bytes, before);
  const dataAfter = imageData[after.format](r.bytes, after);
  const [hb, ha, hIn, hOut] = await Promise.all([sha256Hex(dataBefore), sha256Hex(dataAfter), sha256Hex(bytes), sha256Hex(r.bytes)]);
  const allowed = new Set(['Orientation', 'JFIF header']);
  const leftovers = after.findings.filter((f) => f.severity !== 'info' && !allowed.has(f.label));
  return {
    bytes: r.bytes, kept: r.kept, removed: r.removed, before, after,
    checks: {
      imageDataIdentical: hb === ha,
      imageDataSha256: hb,
      dimensionsIdentical: before.width === after.width && before.height === after.height,
      noMetadataFindingsLeft: leftovers.length === 0,
      leftovers: leftovers.map((f) => f.label),
      inputSha256: hIn,
      outputSha256: hOut,
    },
  };
}

export function defaultFileName(name, format) {
  const ext = format === 'jpeg' ? 'jpg' : format === 'webp' ? 'webp' : 'png';
  const base = name.replace(/\.[A-Za-z0-9]+$/, '') || 'image';
  return `${base}.offframe.${ext}`;
}

/** Receipt: labels and sizes only. It never copies metadata values (coordinates, names, serials). */
export function buildReceipt(fileName, result, options) {
  const groups = {};
  for (const f of result.before.findings) {
    const k = `${f.category}|${f.label}`;
    groups[k] = groups[k] || { category: f.category, severity: f.severity, label: f.label, count: 0 };
    groups[k].count++;
  }
  return {
    tool: 'Offframe',
    version: VERSION,
    createdAt: new Date().toISOString(),
    input: { name: fileName, format: result.before.format, bytes: result.before.byteLength, sha256: result.checks.inputSha256, width: result.before.width, height: result.before.height },
    output: { bytes: result.bytes.length, sha256: result.checks.outputSha256 },
    options: { keepOrientation: !!options.keepOrientation, keepColorProfile: !!options.keepColorProfile },
    removed: result.removed,
    kept: result.kept,
    findingsBefore: Object.values(groups),
    checks: {
      imageDataIdentical: result.checks.imageDataIdentical,
      imageDataSha256: result.checks.imageDataSha256,
      dimensionsIdentical: result.checks.dimensionsIdentical,
      noMetadataFindingsLeft: result.checks.noMetadataFindingsLeft,
      decodedPixelsIdentical: result.checks.decodedPixelsIdentical ?? null,
    },
    limits: [
      'Pixels are not changed. Faces, signs, screens and other visible content stay in the picture.',
      'Not a forensic guarantee. Only the file format metadata Offframe recognises was removed.',
      'This receipt lists labels and sizes only, never the removed values.',
    ],
  };
                            }
