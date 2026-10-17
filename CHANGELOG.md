# Changelog

## 3.2.0 — Unreleased

- Add 14 source-linked parser probes: six JSON, four XML and four repeated-parameter inputs.
- Add `--pack research` and three individual research packs; include all 26 reviewed inputs in the default core.
- Send repeated query/form fields as ordered pairs, and retain their shape in neutral controls.
- Preserve raw JSON bytes for duplicate members, Unicode escapes and deliberately malformed inputs.
- Add bounded local parser fixtures, a reproducible 26-request research demo and 12 regression tests (49 total).
- Document primary research sources, fixture policies and attribution limits; refresh console recordings.


## 3.1.0 — Unreleased

- Add a console ASCII wordmark, coordinated colors, live request progress,
  phase-aware response ledger, summary counters and a terminal SVG recording.
- Add neutral controls per delivery profile; expose status/body-sample comparison
  while keeping every observation unconfirmed. Controls share the request budget.
- Add 12 reviewed probes with purpose, side effects and controlled local scenarios:
  reflection markers, Unicode/encoding normalization and bounded JSON/input checks.
- Make reviewed essentials the default; retain the 767-input source corpus behind
  an explicit `--pack legacy` selection with one exact duplicate removed at load.
- Preserve completed observations on cancellation and keep controls in CSV exports.
- Add original terminal recordings, actual console screenshots in README and tests
  for baseline uncertainty, cancellation, NFC/NFD, encoding layers and application
  validation. No web UI is shipped.

Breaking: the default corpus is now the reviewed core pack; controls consume
requests by default. CSV adds phase, baseline and sample-comparison fields. Use
`--pack legacy --no-baseline` only when intentionally reproducing older lab behavior.

## 3.0.0 — Unreleased

- Replace blocked/passed verdicts and strong/moderate/weak scores with explicit,
  unconfirmed HTTP observations. Preserve server errors and rate-limit evidence.
- Fix custom status handling; keep redirects, 429 and 5xx distinct from signals.
- Preserve each delivery's status and reason instead of mixing methods.
- Add loopback target defaults, explicit remote-lab opt-in, request budget,
  pacing, timeout and bounded body reading. Stop immediately after 429.
- Disable redirects, ambient proxies, netrc, retries and cookie carryover.
- Constrain probes to the configured endpoint; skip raw/framing overrides.
- Remove unreliable vendor fingerprinting and unrequested trigger probes.
- Separate legacy payload data and input helpers from the request/report code.
- Preserve JSON delivery metadata and neutralize spreadsheet formula prefixes.
- Minimize exported response data; add confirmation and truncation metadata.
- Add controlled local fixture, regression/end-to-end tests, reproducible terminal
  demo, CI and dependency/secret checks. Update Requests to 2.33.0.
- Rewrite README around measured scope; remove stale screenshot, nonexistent
  launcher/license links and unsupported coverage claims.

Breaking: CLI options, result labels, CSV schema, path delivery and defaults have
changed. No exploit confirmation or WAF effectiveness measurement is performed.
