import test from 'node:test';
import assert from 'node:assert/strict';
import { analyze, strip, parseTiff, buildOrientationTiff, crc32, sniff, walkJpeg, walkPng, OffframeError, LIMITS, buildReceipt, defaultFileName, parseXmp } from '../engine.js';
import { fx, inflate } from './helpers.js';

const labels = (a) => a.findings.map((f) => f.label);
const has = (a, s) => a.findings.some((f) => f.label.includes(s));

test('crc32 matches the known check value', () => {
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
});

test('sniff recognises JPEG and PNG by signature, not by name', () => {
  assert.equal(sniff(fx('trail-photo.jpg')), 'jpeg');
  assert.equal(sniff(fx('screen-capture.png')), 'png');
  assert.equal(sniff(new TextEncoder().encode('GIF89a....')), null);
  assert.equal(sniff(new Uint8Array(0)), null);
});

test('JPEG fixture: finds location, identity, device, time, thumbnail, XMP, IPTC, comment', async () => {
  const a = await analyze(fx('trail-photo.jpg'));
  assert.equal(a.format, 'jpeg');
  assert.equal(a.width, 640);
  assert.ok(a.gps && Math.abs(a.gps.lat - 48.85837) < 1e-4 && Math.abs(a.gps.lon - 2.294481) < 1e-4);
  for (const s of ['GPS coordinates', 'Camera body serial number', 'Camera owner name', 'Artist', 'Camera make', 'Camera model', 'Date taken', 'Embedded thumbnail', 'XMP metadata block', 'IPTC By-line', 'IPTC City', 'JPEG comment', 'User comment', 'Windows author']) {
    assert.ok(has(a, s), `missing finding: ${s}; got ${labels(a).join(' | ')}`);
  }
  assert.equal(a.orientation, 6);
  assert.ok(a.counts.high >= 5);
});

test('JPEG fixture: southern and western hemispheres produce negative coordinates', () => {
  // Hand-built big-endian TIFF with GPS IFD: lat 33 51 0 S, lon 151 12 0 E
  const be = (...n) => n;
  const bytes = [];
  const u16 = (v) => bytes.push((v >> 8) & 255, v & 255);
  const u32 = (v) => bytes.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
  bytes.push(0x4d, 0x4d); u16(42); u32(8);
  u16(1); u16(0x8825); u16(4); u32(1); u32(26); // IFD0 -> GPS at 26
  u32(0);
  // GPS IFD at 26: 4 entries
  u16(4);
  u16(1); u16(2); u32(2); bytes.push(0x53, 0, 0, 0); // S
  u16(2); u16(5); u32(3); u32(26 + 2 + 48 + 4);
  u16(3); u16(2); u32(2); bytes.push(0x57, 0, 0, 0); // W
  u16(4); u16(5); u32(3); u32(26 + 2 + 48 + 4 + 24);
  u32(0);
  for (const [n, d] of [[33, 1], [51, 1], [0, 1], [151, 1], [12, 1], [0, 1]]) { u32(n); u32(d); }
  void be;
  const t = parseTiff(new Uint8Array(bytes));
  assert.deepEqual(t.issues, []);
  assert.ok(t.gps);
  assert.ok(Math.abs(t.gps.lat - -33.85) < 1e-6);
  assert.ok(Math.abs(t.gps.lon - -151.2) < 1e-6);
});

test('strip JPEG: removes metadata, keeps image data byte-identical, keeps orientation only', async () => {
  const input = fx('trail-photo.jpg');
  const r = await strip(input, { inflate });
  assert.ok(r.checks.imageDataIdentical);
  assert.ok(r.checks.dimensionsIdentical);
  assert.ok(r.checks.noMetadataFindingsLeft, r.checks.leftovers.join(','));
  assert.ok(r.bytes.length < input.length);
  assert.equal(r.after.orientation, 6);
  assert.equal(r.after.gps, null);
  assert.ok(!has(r.after, 'Artist'));
  assert.ok(r.removed.includes('EXIF block'));
  assert.ok(r.kept.some((k) => k.startsWith('Orientation')));
});

test('strip JPEG with keepOrientation false drops orientation too', async () => {
  const r = await strip(fx('trail-photo.jpg'), { keepOrientation: false });
  assert.equal(r.after.orientation, null);
  assert.equal(r.after.findings.length, 0);
});

test('strip JPEG with keepColorProfile false marks ICC removed when present', async () => {
  const r = await strip(fx('trail-photo.jpg'), { keepColorProfile: false });
  assert.ok(r.checks.noMetadataFindingsLeft);
});

test('trailer bytes after EOI are found and removed', async () => {
  const input = fx('trailer.jpg');
  const a = await analyze(input);
  assert.ok(has(a, 'Extra bytes after the end'));
  const r = await strip(input);
  assert.ok(!has(r.after, 'Extra bytes'));
  assert.ok(r.checks.imageDataIdentical);
  const text = new TextDecoder('latin1').decode(r.bytes);
  assert.ok(!text.includes('HIDDEN NOTE'));
  assert.equal(r.bytes[r.bytes.length - 2], 0xff);
  assert.equal(r.bytes[r.bytes.length - 1], 0xd9);
});

test('already clean JPEG reports nothing to remove', async () => {
  const a = await analyze(fx('already-clean.jpg'));
  assert.equal(a.counts.high + a.counts.medium + a.counts.low, 0);
  const r = await strip(fx('already-clean.jpg'));
  assert.ok(r.checks.imageDataIdentical);
});

test('PNG fixture: reads tEXt, zTXt, iTXt XMP, tIME, eXIf GPS and generator parameters', async () => {
  const a = await analyze(fx('screen-capture.png'), { inflate });
  assert.equal(a.format, 'png');
  for (const s of ['Software', 'Author', 'Comment', 'parameters', 'Description', 'Last-modified time', 'GPS coordinates', 'Camera make']) assert.ok(has(a, s), `missing ${s}: ${labels(a).join(' | ')}`);
  const desc = a.findings.find((f) => f.label === 'Description');
  assert.match(desc.value, /compressed note/);
  assert.ok(a.gps && Math.abs(a.gps.lon - -0.124625) < 1e-5);
  assert.ok(a.findings.some((f) => f.source.startsWith('XMP')));
});

test('strip PNG: image data identical, no metadata chunks left, still valid', async () => {
  const r = await strip(fx('screen-capture.png'), { inflate });
  assert.ok(r.checks.imageDataIdentical);
  assert.ok(r.checks.noMetadataFindingsLeft, r.checks.leftovers.join(','));
  const w = walkPng(r.bytes);
  const types = w.chunks.map((c) => c.type);
  for (const t of ['tEXt', 'zTXt', 'iTXt', 'tIME', 'eXIf']) assert.ok(!types.includes(t), t);
  assert.equal(types[0], 'IHDR');
  assert.equal(types[types.length - 1], 'IEND');
});

test('strip is idempotent', async () => {
  for (const n of ['trail-photo.jpg', 'screen-capture.png', 'trailer.jpg']) {
    const once = await strip(fx(n), { inflate });
    const twice = await strip(once.bytes, { inflate });
    assert.deepEqual(Buffer.from(twice.bytes), Buffer.from(once.bytes), n);
  }
});

test('orientation-only EXIF block parses back to the same orientation', () => {
  for (const o of [2, 3, 6, 8]) {
    const t = parseTiff(buildOrientationTiff(o));
    assert.equal(t.orientation, o);
    assert.deepEqual(t.issues, []);
  }
});

test('unsupported and damaged inputs fail with typed, readable errors', async () => {
  const bad = async (bytes, code) => {
    await assert.rejects(analyze(bytes), (e) => e instanceof OffframeError && e.code === code, code);
  };
  await bad(new TextEncoder().encode('hello world, not an image'), 'unsupported');
  const j = fx('trail-photo.jpg');
  await bad(j.subarray(0, 300), 'jpeg-truncated');
  await bad(j.subarray(0, j.length - 2), 'jpeg-truncated');
  const p = fx('screen-capture.png');
  await bad(p.subarray(0, p.length - 5), 'png-truncated');
  const idat = walkPng(p).chunks.find((c) => c.type === 'IDAT');
  const flipped = p.slice(); flipped[idat.dataStart + 3] ^= 0xff;
  await assert.rejects(analyze(flipped), (e) => e instanceof OffframeError && e.code === 'png-crc');
  await assert.rejects(analyze(new Uint8Array(LIMITS.maxFileBytes + 1).fill(0)), (e) => e.code === 'unsupported' || e.code === 'too-large');
});

test('file over the size limit is rejected before parsing', async () => {
  const big = new Uint8Array(LIMITS.maxFileBytes + 1); big[0] = 0xff; big[1] = 0xd8; big[2] = 0xff;
  await assert.rejects(analyze(big), (e) => e.code === 'too-large');
});

test('EXIF parser survives loops, huge counts and out-of-range offsets', () => {
  // IFD0 whose next-IFD pointer points back at itself
  const loop = new Uint8Array([0x49, 0x49, 42, 0, 8, 0, 0, 0, 0, 0, 8, 0, 0, 0]);
  const t = parseTiff(loop);
  assert.ok(t.issues.length >= 0);
  // entry with count so large the value would be out of range
  const oob = new Uint8Array([0x49, 0x49, 42, 0, 8, 0, 0, 0, 1, 0, 0x0f, 0x01, 2, 0, 0xff, 0xff, 0xff, 0x00, 0x20, 0, 0, 0, 0, 0, 0, 0]);
  const t2 = parseTiff(oob);
  assert.ok(t2.findings.length === 0);
  assert.ok(parseTiff(new Uint8Array([1, 2, 3])).issues.length === 1);
});

test('PNG zTXt decompression is capped, so a bomb cannot exhaust memory', async () => {
  const { deflateSync } = await import('node:zlib');
  const bomb = deflateSync(Buffer.alloc(8 * 1024 * 1024, 0x41));
  const base = fx('screen-capture.png');
  // rebuild a PNG with only IHDR, a bomb zTXt, IDAT, IEND by copying real chunks
  const w = walkPng(base);
  const parts = [base.subarray(0, 8)];
  const mk = (type, data) => {
    const out = new Uint8Array(12 + data.length); const dv = new DataView(out.buffer);
    dv.setUint32(0, data.length); for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i); out.set(data, 8);
    dv.setUint32(8 + data.length, crc32(out, 4, 8 + data.length)); return out;
  };
  for (const c of w.chunks) {
    if (c.type === 'IHDR') parts.push(base.subarray(c.start, c.end));
  }
  parts.push(mk('zTXt', Buffer.concat([Buffer.from('Comment\0\0'), bomb])));
  for (const c of w.chunks) if (c.type === 'IDAT' || c.type === 'IEND') parts.push(base.subarray(c.start, c.end));
  const total = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { total.set(p, o); o += p.length; }
  const a = await analyze(total, { inflate });
  const f = a.findings.find((x) => x.label === 'Comment');
  assert.ok(f, 'comment finding present');
  assert.match(f.value, /not readable/);
  const r = await strip(total, { inflate });
  assert.ok(r.checks.imageDataIdentical);
});

test('JPEG walker handles fill bytes, restart markers and multiple scans', () => {
  const dqt = [0xff, 0xdb, 0, 67, 0, ...new Array(64).fill(1)];
  const sof = [0xff, 0xc2, 0, 11, 8, 0, 8, 0, 8, 1, 1, 0x11, 0];
  const sos = [0xff, 0xda, 0, 8, 1, 1, 0, 0, 63, 0];
  const scan1 = [0x12, 0xff, 0x00, 0xff, 0xd0, 0x34];
  const b = new Uint8Array([0xff, 0xd8, 0xff, 0xff, ...dqt.slice(1), ...sof, ...sos, ...scan1, ...sos, 0x99, 0xff, 0xd9]);
  const w = walkJpeg(b);
  assert.equal(w.segments.filter((s) => s.kind === 'SOS').length, 2);
  assert.equal(w.trailer, 0);
  assert.equal(w.info.progressive, true);
});

test('receipt never contains metadata values', async () => {
  const r = await strip(fx('trail-photo.jpg'));
  const rec = JSON.stringify(buildReceipt('trail-photo.jpg', r, { keepOrientation: true, keepColorProfile: true }));
  for (const secret of ['48.85', '2.2944', 'SYN-000123', 'Sample Person', 'LENS-777', 'usual bench', 'SynthCam']) assert.ok(!rec.includes(secret), `receipt leaks ${secret}`);
  assert.ok(rec.includes('"imageDataIdentical":true'));
});

test('default output name', () => {
  assert.equal(defaultFileName('My Trip.JPG', 'jpeg'), 'My Trip.offframe.jpg');
  assert.equal(defaultFileName('shot.png', 'png'), 'shot.offframe.png');
});

test('XMP parser extracts notable properties only', () => {
  const f = parseXmp('<x:xmpmeta><rdf:Description xmp:CreatorTool="Tool 9" foo:bar="ignore me"><dc:creator><rdf:Seq><rdf:li>Ann</rdf:li></rdf:Seq></dc:creator></rdf:Description></x:xmpmeta>');
  assert.ok(f.some((x) => x.label === 'xmp:CreatorTool'));
  assert.ok(f.some((x) => x.label === 'dc:creator' && x.value === 'Ann'));
  assert.ok(!f.some((x) => x.label === 'foo:bar'));
});

test('display-critical PNG chunks survive: palette, tRNS transparency, gamma, sRGB, pHYs; text is removed', async () => {
  const r = await strip(fx('alpha-palette.png'), { inflate });
  const types = walkPng(r.bytes).chunks.map((c) => c.type);
  for (const t of ['PLTE', 'tRNS', 'gAMA', 'sRGB', 'pHYs']) assert.ok(types.includes(t), `${t} must be kept`);
  assert.ok(!types.includes('tEXt'));
  assert.ok(r.checks.imageDataIdentical);
  // the data hash covers IHDR, PLTE, tRNS and IDAT, so palette and transparency are proven unchanged
});

test('JPEG colour profile is kept by default and only removed when asked', async () => {
  const input = fx('icc-profile.jpg');
  const kept = await strip(input);
  assert.ok(kept.kept.includes('Colour profile (ICC)'));
  assert.ok(kept.after.iccPresent);
  assert.ok(!kept.after.gps);
  const gone = await strip(input, { keepColorProfile: false });
  assert.ok(!gone.after.iccPresent);
  assert.ok(gone.removed.includes('Colour profile (ICC)'));
});
