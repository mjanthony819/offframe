# Third-party material

Offframe ships no third-party code. The app is plain HTML, CSS and JavaScript with no dependencies and no build step.

Development-only tools, not distributed with the app:

- ExifTool (Phil Harvey, Perl Artistic / GPL) - used by `make_fixtures.py` to write synthetic metadata and by `tests/external.test.js` as an independent reader.
- Pillow (HPND) - used by `make_fixtures.py` to draw the sample scenes and by the external tests to compare decoded pixels.
- Playwright for Python (Apache-2.0) and Google Chrome - used by `tests/ui_test.py`.

All sample images in `fixtures/` were drawn by `make_fixtures.py`. Every person, serial number, comment and prompt inside them is invented. The GPS points are public landmarks (the Eiffel Tower and the Palace of Westminster area) used as stand-ins.
