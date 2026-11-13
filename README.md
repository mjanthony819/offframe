# Offframe

**Send the picture, not the place it was taken.**

Offframe is a browser-only tool that audits JPEG, PNG and WebP files for hidden data, removes it, and then checks its own work. Nothing is uploaded. There is no server, no account and no network call while you use it. A content security policy in the page blocks outbound requests, and a browser test proves it.

Live app: https://mjanthony819.github.io/offframe/
Built for [SafeSpace Hacks 2026](https://safespace-hacks.devpost.com/) with AI assistance (see "How this was built").

## The situation

You send a photo to a seller, a landlord, a school or a stranger online. The picture shows a living room. The file can also say where it was taken (GPS to a few metres), which phone took it, that phone's serial number, the exact time, the owner's name, the software that edited it, and a small thumbnail of the picture before you cropped it. PNG screenshots and AI-generated images can carry the prompt or settings used to make them.

Offframe makes that visible in plain words, ranked by how much it gives away, and removes it.

## One safer outcome, one limitation

- **Safer outcome.** `fixtures/trail-photo.jpg` carries GPS coordinates, an owner name, a camera serial number, a timestamp, XMP, IPTC, a comment and an embedded thumbnail. After Offframe, ExifTool finds none of it, and the image data hashes identically before and after.
- **Limitation.** The pixels are not touched. A face, a street sign, a house number or a screenshot of a private page stays in the picture. Offframe does not blur anything and does not make a photo anonymous.

## What it does

1. **Reads** the file with its own parsers: JPEG segments, TIFF/EXIF (both byte orders, IFD loop guards, bounds checks), XMP, IPTC/Photoshop blocks, PNG chunks with CRC validation (tEXt, zTXt, iTXt, eXIf, tIME and unknown chunks), and WebP RIFF chunks (VP8/VP8L/VP8X/EXIF/XMP/ICCP/ALPH/ANIM/ANMF and unknown chunks).
2. **Reports** each finding with a severity (high, medium, low) and a plain-language group: where you were, who you are, what took it, when it was taken, notes and embedded images, hidden data.
3. **Removes** metadata at the byte-structure level. Entropy-coded image data (JPEG), IDAT chunks (PNG) and VP8/VP8L/ALPH/ANIM/ANMF chunks (WebP) are copied, never re-encoded, so there is no quality loss. WebP feature flags in VP8X are rewritten to match what remains.
4. **Keeps** only what is needed to display correctly: image data, colour profile (optional), and a rewritten EXIF block holding only the rotation flag (optional).
5. **Checks itself** after removal: re-reads the clean file and confirms none of the supported identifying fields remain; compares SHA-256 of image data before and after; compares dimensions; asks the browser to decode both and compares what it draws.
6. **Receipt.** A JSON receipt with file hashes, what was removed and kept, and the check results. It never contains the removed values.
7. **Summary card.** A shareable PNG card per file: what was removed in plain grouped words, what was kept on purpose, and that file's own check results. Drawn locally on a canvas; no upload.

Also removes bytes hidden **after** the end of the image, which viewers ignore. Batch mode handles up to 20 files at once - picked individually or as a whole folder (unsupported files inside are skipped, not uploaded) - and downloads a ZIP of clean files and receipts.

## Scope and limits

- JPEG (baseline, extended, progressive), PNG (including animated PNG) and WebP (lossy, lossless, animated, with transparency) only. Anything else is rejected with a reason. HEIC needs a full decoder, so it is refused rather than converted.
- Files up to 50 MB, up to 20 at a time. Compressed PNG text is read up to 1 MB decompressed, so a decompression bomb cannot exhaust memory.
- Damaged files are refused, not repaired. An unknown critical PNG chunk is refused rather than guessed at.
- If you untick "keep the rotation flag" on a JPEG or PNG that needs it, the clean copy shows rotated differently in the browser. The page warns about this and skips the visual-equality check. Browsers ignore rotation flags inside WebP files (verified in Chrome 158), so for WebP the flag is kept for desktop viewers that honour it, and dropping it changes nothing you see in the browser.
- Some metadata is kept on purpose: the rotation flag, the colour profile (it can carry a vendor or software name), and display chunks (PNG transparency, gamma, pixel density; WebP transparency and animation). Both options can be turned off. After a clean, the targeted identifying metadata is gone and the retained fields are exactly the ones the page enumerates under "kept on purpose".
- Not a forensic guarantee. Watermarks hidden in the pixels and anything the parsers do not recognise are out of reach.
- The sample GPS points are public landmarks. All people and notes in the samples are invented.

## Run it

```
python3 -m http.server 8000     # then open http://localhost:8000
```

No build step. Open `index.html` through any static server (ES modules need http, not file://).

## Tests

```
npm test                 # 37 engine and fuzz tests, no dependencies
npm run test:external    # 23 ExifTool and Pillow checks (needs both installed)
python3 tests/ui_test.py # drives the real page in Chrome (needs Playwright and Chrome)
```

What the tests cover:

- Known-value checks (CRC-32, GPS hemisphere signs, orientation round trip, name handling).
- Every fixture: expected findings found, metadata gone, image data hash identical, output idempotent.
- Hostile and broken input: truncated files, flipped checksums, IFD loops, out-of-range offsets, a zlib bomb, oversize files, non-images.
- 6,000 seeded random mutations of the fixtures (including WebP): nothing crashes or hangs, and every accepted output re-parses.
- ExifTool lists no leftover targeted tags in the cleaned files (retained fields are enumerated per file) and `-validate` reports no errors; Pillow decodes identical pixels before and after; Chrome 158 renders the stripped animated WebP identically and applies rotation flags to JPEG/PNG but not WebP (all three verified).
- UI: findings shown, downloads verified with ExifTool, receipt has no values, hostile HTML in metadata is shown as text and never runs, the page makes no off-origin requests, outbound `fetch` is blocked by the CSP, no horizontal overflow at 390 and 320 px, keyboard access to the drop zone.

## How this was built

Designed and directed by M J Anthony. Implementation, tests and the demo were produced with AI assistance (an AI agent wrote the code and ran the tests), and that is disclosed on the Devpost page. Work started on 13 November 2026, inside the SafeSpace Hacks build window. The app's own source was written during the build window; no earlier project code was reused. Runtime libraries: none. Tools used for fixtures, tests and the demo: Pillow and ExifTool (fixture generation and independent checks), Playwright with Chrome (UI test), ffmpeg (video). The demo narration is AI text-to-speech.

## Related tools

Metadata strippers already exist (ExifTool, many web apps). Offframe's angle is the verification: it shows what was found, proves the pixels are byte-identical, re-reads its own output, and hands back a receipt.

## Licence

MIT. See `LICENSE` and `THIRD_PARTY.md`.
