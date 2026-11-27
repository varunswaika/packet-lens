# Status

**27 November 2026.** Works on the test captures, from the CLI and in the web page.

- 43 Rust tests and 3 node tests pass. rustfmt, clippy, Biome and ruff are clean.
- The page was checked by hand in Chromium, light and dark, with the sample capture.
- CI runs lint and tests on every push; it first ran green on 27 November 2026.
- Agrees with tshark 4.2.2 on every flow, TLS name and DNS reply in the 10 test captures (`tests/tshark_diff.py`, run in CI).
- Not yet tried on large real-world captures.

Next:

1. Run it on a few large public captures and time it, CLI and page.
2. Read the file in chunks in the page, so very large captures do not need one big copy.
