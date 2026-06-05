# Contributing to polin-guard

Thanks for helping make supply-chain attacks harder to pull off. 🛡️

polin-guard is intentionally **tiny and zero-dependency**. Please keep it that
way — no runtime dependencies should be added.

## Getting started

```bash
git clone https://github.com/Valentin-Shyaka/polin-guard.git
cd polin-guard
npm test        # runs the zero-dependency test suite
```

There is nothing to build — it is plain CommonJS that runs on Node ≥ 14.

## Project layout

| Path | What it is |
|------|------------|
| `src/patterns.js` | Detection rules and default thresholds |
| `src/scan.js` | The scanning engine (line analysis, git integration) |
| `bin/cli.js` | The `polin-guard` command-line interface |
| `scan-injection.sh` | Standalone POSIX scanner (no Node) — keep it in sync with the rules |
| `test/` | Zero-dependency tests + fixtures |

## Adding or changing a detection rule

1. Add the pattern to `src/patterns.js`. Prefer **high precision**: a `critical`
   finding must be safe to block a commit on. If a rule can reasonably fire on
   legitimate code, make it a `warning`, not `critical`.
2. Add a matching check to `scan-injection.sh` so the no-Node path stays equivalent.
3. Add a test in `test/run.js`:
   - a **true-positive** case (the rule fires), and
   - a **false-positive guard** (similar-but-legit code does *not* fire).
4. Run `npm test` — it must stay green.

### A note on test fixtures

`test/fixtures/malicious.config.js` contains the detection *signatures* but is
**inert** — it performs no real decode or execution. Never add a working payload
to this repository. If you need to extend it, keep it inert.

## Reporting false positives / false negatives

Open an issue with a **minimal code snippet** that reproduces it. For a missed
detection (false negative), describe the technique, not a live payload.

## Pull requests

- Keep PRs focused and small.
- Update the README if behavior or flags change.
- By contributing you agree your work is licensed under the project's MIT license.

## Security issues

Please do **not** open a public issue for a vulnerability in polin-guard itself.
See [SECURITY.md](SECURITY.md) for private disclosure.
