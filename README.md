# Offframe

**Send the picture, not the place it was taken.**

Offframe is a browser-only tool that audits JPEG and PNG files for hidden data, removes it, and then checks its own work. Nothing is uploaded. There is no server, no account and no network call while you use it. A content security policy in the page blocks outbound requests, and a browser test proves it.

Live app: https://mjanthony819.github.io/offframe/
Built for [SafeSpace Hacks 2026](https://safespace-hacks.devpost.com/) with AI assistance (see "How this was built").

## The situation

You send a photo to a seller, a landlord, a school or a stranger online. The picture shows a living room. The file can also say where it was taken (GPS to a few metres), which phone took it, that phone's serial number, the exact time, the owner's name, the software that edited it, and a small thumbnail of the picture before you cropped it. PNG screenshots and AI-generated images can carry the prompt or settings used to make them.

Offframe makes that visible in plain words, ranked by how much it gives away, and removes it.

## One safer outcome, one limitation

- **Safer outcome.** `fixtures/trail-photo.jpg` carries GPS coordinates, an owner name, a camera serial number, a timestamp, XMP, IPTC, a comment and an embedded thumbnail. After Offframe, ExifTool finds none of it, and the image data hashes identically before and after.
- **Limitation.** The pixels are not touched. A face, a street sign, a house number or a screenshot of a private page stays in the picture. Offframe does not blur anything and does not make a photo anonymous.

## What it does

1. **Reads** the file with its own parsers: JPEG segments, TIFF/EXIF (both byte orders, IFD loop guards, bounds checks), XMP, IPTC/Photoshop blocks, PNG chunks with CRC validation (tEXt, zTXt, iTXt, eXIf, tIME and unknown chunks).
2. **Reports** each finding with a severity (high, medium, low) and a plain-language group: where you were, who you are, what took it, when it was taken, notes and embedded images, hidden data.
3. **Removes** metadata at the byte-structure level. Entropy-coded image data (JPEG) and IDAT chunks (PNG) are copied, never re-encoded, so there is no quality loss.
4. **Keeps** only what is needed to display correctly: image data, colour profile (optional), and a rewritten EXIF block holding only the rotation flag (optional).
5. **Checks itself** after removal: re-reads the clean file and confirms none of the supported identifying fields remain; compares SHA-256 of image data before and after; compares dimensions; asks the browser to decode both and compares what it draws.
6. **Receipt.** A JSON receipt with file hashes, what was removed and kept, and the check results. It never contains the removed values.

Also removes bytes hidden **after** the end of the image, which viewers ignore. Batch mode downloads a ZIP of clean files and receipts.

## Scope and limits

- JPEG (baseline, extended, progressive) and PNG (including animated PNG) only. Anything else is rejected with a reason.
- Files up to 50 MB, up to 20 at a time. Compressed PNG text is read up to 1 MB decompressed, so a decompression bomb cannot exhaust memory.
- Damaged files are refused, not repaired. An unknown critical PNG chunk is refused rather than guessed at.
- If you untick "keep the rotation flag" on a file that needs it, the clean copy shows rotated differently. The page warns about this and skips the visual-equality check.
- Some metadata is kept on purpose: the rotation flag, the colour profile (it can carry a vendor or software name), and PNG display chunks (transparency, gamma, pixel density). Both options can be turned off.
- Not a forensic guarantee. Watermarks hidden in the pixels and anything the parsers do not recognise are out of reach.
- The sample GPS points are public landmarks. All people and notes in the samples are invented.

## Run it

```
python3 -m http.server 8000     # then open http://localhost:8000
```

No build step. Open `index.html` through any static server (ES modules need http, not file://).

## Tests

```
npm test                 # 26 engine and fuzz tests, no dependencies
npm run test:external    # 14 ExifTool and Pillow checks (needs both installed)
python3 tests/ui_test.py # drives the real page in Chrome (needs Playwright and Chrome)
```

What the tests cover:

- Known-value checks (CRC-32, GPS hemisphere signs, orientation round trip, name handling).
- Every fixture: expected findings found, metadata gone, image data hash identical, output idempotent.
- Hostile and broken input: truncated files, flipped checksums, IFD loops, out-of-range offsets, a zlib bomb, oversize files, non-images.
- 4,500 seeded random mutations of the fixtures: nothing crashes or hangs, and every accepted output re-parses.
- ExifTool lists no leftover tags in the cleaned files and `-validate` reports no errors; Pillow decodes identical pixels before and after.
- UI: findings shown, downloads verified with ExifTool, receipt has no values, hostile HTML in metadata is shown as text and never runs, the page makes no off-origin requests, outbound `fetch` is blocked by the CSP, no horizontal overflow at 390 and 320 px, keyboard access to the drop zone.

## How this was built

Designed and directed by M J Anthony. Implementation, tests and the demo were produced with AI assistance (an AI agent wrote the code and ran the tests), and that is disclosed on the Devpost page. Work started on 13 November 2026, inside the SafeSpace Hacks build window. No pre-existing code was reused. Libraries: none at runtime.

## Related tools

Metadata strippers already exist (ExifTool, many web apps). Offframe's angle is the verification: it shows what was found, proves the pixels are byte-identical, re-reads its own output, and hands back a receipt.

## Licence

MIT. See `LICENSE` and `THIRD_PARTY.md`.
