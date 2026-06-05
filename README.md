# polin-guard

**Block obfuscated build/commit-time code-injection payloads before they ever enter your repo.**

`polin-guard` is a tiny, **zero-dependency** scanner that catches the family of
malicious JavaScript "stagers" that hide a payload on a single, space-padded line
inside an otherwise normal config or entry file — e.g. `tailwind.config.js`,
`ecosystem.config.js`, `.eslintrc.js`, `postcss.config.js`, or `src/index.ts`.

These payloads typically:

- decode strings at runtime with a character-shuffle cipher,
- re-expose Node's `require`/`module` as globals, and
- execute a second stage through a `Function()` constructor —

…all of which runs **automatically at build/dev/CI time** with full Node.js
access to your environment variables, SSH keys, and tokens. Because the malicious
code sits hundreds of spaces to the right of legitimate code, it is trivially
missed in review. `polin-guard` makes it impossible to miss.

> Built after a real incident in which this exact payload was committed across
> multiple repositories. The detection rules are tuned for **high precision** —
> a `CRITICAL` finding should be safe to block a commit on.

## What it detects

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `global-bang-key` | critical | `global['!']=…` stager marker |
| `global-underscore-handle` | critical | `global[_$_…]=…` obfuscated handle |
| `require-reexposed` | critical | `…]=require; … typeof module` capability escalation |
| `char-shuffle-cipher` | critical | `String.fromCharCode(127)` cipher delimiter |
| `escape-density` | critical | a line with ≥25 `\xNN`/`\uNNNN` escapes (obfuscated blob) |
| `iife-constructor` | critical | immediately-invoked `Function()` on a long line |
| `oversized-line` | critical* | a source line > 1000 chars **with** exec/require tokens (the concealment trick) |
| `oversized-line` | warning | a long line with no exec tokens (review) |
| `eval` / `atob` / `child_process` | warning | weaker indicators |

\* A long line **without** exec tokens is only a warning, to keep false positives near zero.

Lockfiles, minified bundles, source maps, and `node_modules` are excluded automatically.

## Install

```bash
npm install --save-dev polin-guard
```

Or run it without installing:

```bash
npx polin-guard --all
```

No Node? Use the standalone script — copy `scan-injection.sh` into your repo.

## Usage

```bash
polin-guard --staged    # scan staged content (use in pre-commit; also covers `git commit --amend`)
polin-guard --all       # scan every tracked file
polin-guard --ci        # same as --all, for CI
polin-guard path/to/file.js ...   # scan specific files (no git required)
polin-guard --strict    # treat warnings as blocking too
```

Exit code `1` means a blocking finding was detected.

### As a pre-commit hook (husky)

```bash
npm install --save-dev polin-guard husky
npx husky init
# add the scan to the hook (runs on commit AND amend):
echo 'npx --no-install polin-guard --staged' > .husky/pre-commit
```

A ready-made hook is included at `.husky/pre-commit` in this package.

### As a pre-commit hook (pre-commit.com framework)

See `examples/pre-commit-config.yaml`. It calls the standalone `scan-injection.sh`,
so it needs no Node.

### In CI (the bypass-proof backstop)

A local hook can be skipped with `git commit --no-verify` or sidestepped by a
force-push from a compromised machine. Add the server-side scan so history is
always re-checked:

Copy `examples/github-action.yml` to `.github/workflows/polin-guard.yml`.

## Configuration

Optional `.polinguardrc.json` in your repo root:

```json
{
  "maxLineLength": 1000,
  "maxEscapes": 25,
  "excludeDirs": ["node_modules", "dist", "build", "vendor"],
  "includeExtensions": [".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".vue", ".json", ".bat", ".cmd", ".ps1", ".sh"]
}
```

### Acknowledging a verified false positive

If a line is genuinely legitimate (a real minified-in-source blob, say):

- put `// polinguard-allow-line` on the same line, **or**
- put `// polinguard-allow-next-line` on the line above it, **or**
- raise `maxLineLength` / exclude the path in `.polinguardrc.json`.

Never use `git commit --no-verify` to push past a finding you haven't understood.

## Audit an existing repo / whole org

One-off scan of a checked-out repo:

```bash
npx polin-guard --all
# or, without Node:
git grep -nI '.\{1000,\}'   # flag any suspiciously long line
```

Scan every branch of every repo in a GitHub org:

```bash
for r in $(gh repo list YOUR_ORG --limit 200 --json name --jq '.[].name'); do
  git clone --quiet "https://github.com/YOUR_ORG/$r.git" "/tmp/scan/$r" || continue
  ( cd "/tmp/scan/$r"
    for b in $(git branch -r | grep -v HEAD | sed 's# *origin/##'); do
      git checkout -q "$b" 2>/dev/null || continue
      npx --yes polin-guard --all || echo "FOUND in $r @ $b"
    done )
done
```

## How it works

Pure Node, no dependencies (so the security tool itself adds no supply-chain risk).
For each candidate file it reads the staged blob (`git show :file`) or the working
copy, then analyzes every line for the signatures and concealment patterns above.
It exits non-zero on any `critical` finding so a hook or CI step fails the build.

## Development

```bash
npm test   # runs the zero-dependency test suite (clean + inert-malicious fixtures)
```

The `test/fixtures/malicious.config.js` fixture contains the detection *signatures*
but performs no real decode/exec — it exists only to prove the detector fires.

## License

MIT
