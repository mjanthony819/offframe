// Independent verification: ExifTool (separate codebase) lists what is left, Pillow decodes the pixels.
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { strip } from '../engine.js';
import { fx, inflate, root } from './helpers.js';

const have = (cmd, args) => spawnSync(cmd, args).status === 0;
const hasExif = have('exiftool', ['-ver']);
const hasPil = have('python3', ['-c', 'import PIL']);

const OK_GROUPS = new Set(['ExifTool', 'System', 'File', 'JFIF', 'Composite']);
const OK_PNG = new Set(['ImageWidth', 'ImageHeight', 'BitDepth', 'ColorType', 'Compression', 'Filter', 'Interlace', 'PixelsPerUnitX', 'PixelsPerUnitY', 'PixelUnits', 'SRGBRendering', 'Gamma', 'WhitePointX', 'WhitePointY', 'RedX', 'RedY', 'GreenX', 'GreenY', 'BlueX', 'BlueY']);

for (const name of ['trail-photo.jpg', 'screen-capture.png', 'trailer.jpg', 'already-clean.jpg', 'alpha-palette.png', 'icc-profile.jpg']) {
  test(`ExifTool sees no metadata left in stripped ${name}`, { skip: !hasExif && 'exiftool not installed' }, async () => {
    const r = await strip(fx(name), { inflate });
    const dir = mkdtempSync(join(tmpdir(), 'offframe-'));
    const out = join(dir, 'out' + (name.endsWith('png') ? '.png' : '.jpg'));
    writeFileSync(out, r.bytes);
    const txt = execFileSync('exiftool', ['-a', '-G1', '-s', '-api', 'largefilesupport=1', out]).toString();
    const warn = execFileSync('exiftool', ['-validate', '-warning', '-error', '-s3', out]).toString().trim();
    const rows = txt.split('\n').filter(Boolean).map((l) => { const m = l.match(/^\[(.+?)\]\s+(\S+)\s*:\s*(.*)$/); return m && { g: m[1], k: m[2], v: m[3] }; }).filter(Boolean);
    const extra = rows.filter((x) => !OK_GROUPS.has(x.g) && !/^(ICC|PNG-pHYs)/.test(x.g) && !(x.g === 'PNG' && (OK_PNG.has(x.k) || /Palette|Transparency|Gamma|SRGB|PixelsPer|PixelUnits/.test(x.k))) && !(x.g === 'IFD0' && x.k === 'Orientation') && !(x.g === 'IFD0' && /Resolution|YCbCr/.test(x.k)) && !(x.g === 'File' ));
    const tolerated = extra.filter((x) => !(x.g === 'JFIF'));
    assert.deepEqual(tolerated, [], `leftover tags: ${JSON.stringify(tolerated)}`);
    assert.ok(!/error/i.test(warn), `exiftool validate: ${warn}`);
    const fileGroup = rows.filter((x) => x.g === 'File' && /Comment|Trailer|Warning/i.test(x.k));
    assert.deepEqual(fileGroup, [], 'no comment or trailer reported');
  });

  test(`Pillow decodes identical pixels before and after ${name}`, { skip: !hasPil && 'Pillow not installed' }, async () => {
    const r = await strip(fx(name), { inflate });
    const dir = mkdtempSync(join(tmpdir(), 'offframe-'));
    const a = join(dir, 'a' + (name.endsWith('png') ? '.png' : '.jpg'));
    const b = join(dir, 'b' + (name.endsWith('png') ? '.png' : '.jpg'));
    writeFileSync(a, fx(name));
    writeFileSync(b, r.bytes);
    const py = `import sys,hashlib\nfrom PIL import Image\nA=Image.open(sys.argv[1]);B=Image.open(sys.argv[2])\nA.load();B.load()\nassert A.size==B.size,(A.size,B.size)\nassert A.mode==B.mode\nassert hashlib.sha256(A.tobytes()).digest()==hashlib.sha256(B.tobytes()).digest(),'pixels differ'\nprint('same',A.size,A.mode)`;
    const out = execFileSync('python3', ['-c', py, a, b]).toString();
    assert.match(out, /^same/);
  });
}

test('orientation tag survives for the rotated fixture, as ExifTool reads it', { skip: !hasExif && 'exiftool not installed' }, async () => {
  const r = await strip(fx('trail-photo.jpg'));
  const dir = mkdtempSync(join(tmpdir(), 'offframe-'));
  const out = join(dir, 'o.jpg');
  writeFileSync(out, r.bytes);
  const o = execFileSync('exiftool', ['-Orientation', '-n', '-s3', out]).toString().trim();
  assert.equal(o, '6');
  const gps = execFileSync('exiftool', ['-GPS:all', out]).toString().trim();
  assert.equal(gps, '');
});

const extOf = (n) => n.endsWith('png') ? '.png' : n.endsWith('webp') ? '.webp' : '.jpg';
const OK_WEBP_GROUPS = new Set(['ExifTool', 'System', 'File', 'RIFF', 'Composite']);
for (const name of ['trail-photo.webp', 'alpha-sticker.webp', 'animated-clean.webp', 'already-clean.webp']) {
  test(`ExifTool sees no metadata left in stripped ${name}`, { skip: !hasExif && 'exiftool not installed' }, async () => {
    const r = await strip(fx(name), { inflate });
    const dir = mkdtempSync(join(tmpdir(), 'offframe-'));
    const out = join(dir, 'out' + extOf(name));
    writeFileSync(out, r.bytes);
    const txt = execFileSync('exiftool', ['-a', '-G1', '-s', '-api', 'largefilesupport=1', out]).toString();
    const warn = execFileSync('exiftool', ['-validate', '-warning', '-error', '-s3', out]).toString().trim();
    const rows = txt.split('\n').filter(Boolean).map((l) => { const m = l.match(/^\[(.+?)\]\s+(\S+)\s*:\s*(.*)$/); return m && { g: m[1], k: m[2], v: m[3] }; }).filter(Boolean);
    const extra = rows.filter((x) => !OK_WEBP_GROUPS.has(x.g) && !(x.g === 'IFD0' && (x.k === 'Orientation' || /Resolution|YCbCr/.test(x.k))));
    assert.deepEqual(extra, [], `leftover tags: ${JSON.stringify(extra)}`);
    assert.ok(!/error/i.test(warn), `exiftool validate: ${warn}`);
  });

  test(`Pillow decodes identical pixels before and after ${name}`, { skip: !hasPil && 'Pillow not installed' }, async () => {
    const r = await strip(fx(name), { inflate });
    const dir = mkdtempSync(join(tmpdir(), 'offframe-'));
    const a = join(dir, 'a' + extOf(name));
    const b = join(dir, 'b' + extOf(name));
    writeFileSync(a, fx(name));
    writeFileSync(b, r.bytes);
    const py = `import sys,hashlib\nfrom PIL import Image\nA=Image.open(sys.argv[1]);B=Image.open(sys.argv[2])\nA.load();B.load()\nassert A.size==B.size,(A.size,B.size)\nassert A.mode==B.mode,(A.mode,B.mode)\nassert hashlib.sha256(A.tobytes()).digest()==hashlib.sha256(B.tobytes()).digest(),'pixels differ'\nprint('same',A.size,A.mode)`;
    const out = execFileSync('python3', ['-c', py, a, b]).toString();
    assert.match(out, /^same/);
  });
}

test('orientation tag survives for the WebP fixture, as ExifTool reads it', { skip: !hasExif && 'exiftool not installed' }, async () => {
  const r = await strip(fx('trail-photo.webp'), { inflate });
  const dir = mkdtempSync(join(tmpdir(), 'offframe-'));
  const out = join(dir, 'o.webp');
  writeFileSync(out, r.bytes);
  assert.equal(execFileSync('exiftool', ['-Orientation', '-n', '-s3', out]).toString().trim(), '6');
  assert.equal(execFileSync('exiftool', ['-GPS:all', '-XMP:all', out]).toString().trim(), '');
});

void root;

test('colour profile is really gone when the user unticks keep-colour-profile', { skip: !hasExif && 'exiftool not installed' }, async () => {
  const r = await strip(fx('icc-profile.jpg'), { keepColorProfile: false });
  const dir = mkdtempSync(join(tmpdir(), 'offframe-'));
  const out = join(dir, 'n.jpg');
  writeFileSync(out, r.bytes);
  assert.equal(execFileSync('exiftool', ['-ICC_Profile:all', '-GPS:all', out]).toString().trim(), '');
});
