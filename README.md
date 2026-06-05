<h1 align="center">🛡️ polin-guard</h1>

<p align="center">
  <strong>Stop obfuscated malware from being committed to your repo — automatically, on every commit.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/polin-guard"><img alt="npm version" src="https://img.shields.io/npm/v/polin-guard?color=cb3837&logo=npm"></a>
  <a href="https://www.npmjs.com/package/polin-guard"><img alt="npm downloads" src="https://img.shields.io/npm/dm/polin-guard?color=cb3837&logo=npm"></a>
  <a href="https://github.com/Valentin-Shyaka/polin-guard/blob/main/LICENSE"><img alt="license" src="https://img.shields.io/npm/l/polin-guard?color=blue"></a>
  <img alt="dependencies" src="https://img.shields.io/badge/dependencies-0-brightgreen">
  <img alt="node" src="https://img.shields.io/node/v/polin-guard">
</p>

<p align="center">
  <code>npm install --save-dev polin-guard</code>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Valentin-Shyaka/polin-guard/main/assets/demo.svg" alt="polin-guard blocking a commit that contains an obfuscated injected payload" width="760">
</p>

---

## The problem it solves

Modern supply-chain attacks hide a malicious payload on a **single, space-padded
line** inside an ordinary-looking config or entry file — `tailwind.config.js`,
`ecosystem.config.js`, `.eslintrc.js`, `postcss.config.js`, `src/index.ts`, etc.
The line is hundreds of spaces wide, so the payload scrolls **off-screen** in your
editor and sails through code review:

```js
plugins: [tailwindcssAnimate];
};                                          global['!']='…';var d=String.fromCharCode(127);…require;…Function(…)(…)
//        ^ legitimate code                 ^ hundreds of spaces hide this →→→  obfuscated payload
```

When the project is built, that line runs with **full Node.js access** — reading
your environment variables, `.env`, SSH keys, and tokens, and pulling a second
stage. Because it sits in a file that's `require`d during `dev`/`build`/`test`, it
executes silently and automatically.

**polin-guard catches it before it can ever be committed.**

> Built after a real incident in which this exact payload was committed across
> multiple repositories and reached production branches.

## What it detects

| Rule | Severity | Catches |
|------|----------|---------|
| `global-bang-key` | 🔴 critical | `global['!']=…` stager marker |
| `global-underscore-handle` | 🔴 critical | `global[_$_…]=…` obfuscated handle |
| `require-reexposed` | 🔴 critical | `…]=require; … typeof module` capability escalation |
| `char-shuffle-cipher` | 🔴 critical | `String.fromCharCode(127)` cipher delimiter |
| `escape-density` | 🔴 critical | a line with ≥25 `\xNN`/`\uNNNN` escapes (obfuscated blob) |
| `iife-constructor` | 🔴 critical | immediately-invoked `Function()` on a long line |
| `oversized-line` | 🔴 critical\* | a source line > 1000 chars **with** exec/require tokens |
| `oversized-line` | 🟡 warning | a long line *without* exec tokens (review) |
| `eval` / `atob` / `child_process` | 🟡 warning | weaker indicators |

\* Tuned for **high precision**: a lone long line is only a *warning*. It takes a
unique signature or exec tokens to **block** a commit, so it won't cry wolf.
Lockfiles, minified bundles, source maps, and `node_modules` are skipped automatically.

## Quick start

```bash
npm install --save-dev polin-guard
```

Scan right now:

```bash
npx polin-guard --all      # scan every tracked file in the repo
```

### Block it on every commit (husky)

```bash
npm install --save-dev polin-guard husky
npx husky init
echo 'npx --no-install polin-guard --staged' > .husky/pre-commit
```

That's it. The hook runs on **every commit and every `git commit --amend`**, and
scans the exact content being committed. A malicious payload makes the commit fail.

### Add the CI backstop (recommended)

A local hook can be skipped (`git commit --no-verify`) or sidestepped by a
force-push from a compromised machine. Re-scan on the server, where it can't be
skipped — copy [`examples/github-action.yml`](examples/github-action.yml) to
`.github/workflows/polin-guard.yml`.

### No Node? Use the standalone script

Drop [`scan-injection.sh`](scan-injection.sh) into your repo (works with the
[pre-commit framework](examples/pre-commit-config.yaml) too):

```bash
./scan-injection.sh --staged
```

## Usage

```text
polin-guard [options] [paths...]

  --staged     Scan staged content (default; for pre-commit hooks; covers --amend)
  --all        Scan all git-tracked files
  --ci         Alias for --all (use in CI)
  [paths...]   Scan specific files (no git required)
  --strict     Treat warnings as blocking too
  --quiet      Only print on findings
  -h, --help   Show help
  -v, --version

Exit 0 = clean · 1 = blocking finding · 2 = usage error
```

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

**Acknowledging a verified false positive** (e.g. a legitimate inline blob):

- add `// polinguard-allow-line` on the same line, **or**
- add `// polinguard-allow-next-line` on the line above it, **or**
- raise `maxLineLength` / exclude the path in `.polinguardrc.json`.

> Never use `git commit --no-verify` to push past a finding you don't understand.

## Audit an existing repo or whole org

```bash
# one repo
npx polin-guard --all

# every branch of every repo in a GitHub org
for r in $(gh repo list YOUR_ORG --limit 200 --json name --jq '.[].name'); do
  git clone -q "https://github.com/YOUR_ORG/$r.git" "/tmp/scan/$r" || continue
  ( cd "/tmp/scan/$r"
    for b in $(git branch -r | grep -v HEAD | sed 's# *origin/##'); do
      git checkout -q "$b" 2>/dev/null && { npx --yes polin-guard --all || echo "FOUND in $r @ $b"; }
    done )
done
```

## How it works

Pure Node, **zero dependencies** (so the security tool adds no supply-chain risk
of its own). For each candidate file it reads the staged blob (`git show :file`)
or the working copy, analyzes every line against the rules above, and exits
non-zero on any `critical` finding so your hook or CI step fails.

## Links

- 📦 **npm:** https://www.npmjs.com/package/polin-guard
- 🐙 **GitHub:** https://github.com/Valentin-Shyaka/polin-guard
- 🐛 **Issues:** https://github.com/Valentin-Shyaka/polin-guard/issues
- 🔒 **Security policy:** [SECURITY.md](SECURITY.md)
- 🤝 **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)

## License

[MIT](LICENSE) © Valentin Shyaka
