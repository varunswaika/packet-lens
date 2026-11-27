# Status

**27 November 2026.** Works on the test captures, from the CLI and in the web page.

- 42 Rust tests and 3 node tests pass. rustfmt and clippy are clean.
- The page was checked by hand in Chromium, light and dark, with the sample capture.
- Not yet tried on large real-world captures. CI is written but has not run.

Next:

1. Run it on a few large public captures and time it, CLI and page.
2. Read the file in chunks in the page, so very large captures do not need one big copy.
