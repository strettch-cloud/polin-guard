#!/usr/bin/env node
'use strict';

const { run } = require('../src/scan');

const HELP = `polin-guard — block obfuscated code-injection payloads before they are committed

Usage:
  polin-guard [options] [paths...]

Modes:
  --staged        Scan files staged for commit (default; use in pre-commit hooks).
  --all           Scan all git-tracked files.
  --ci            Alias for --all (use in CI).
  [paths...]      Scan specific files/globs (no git required).

Options:
  --strict        Treat warnings as blocking (exit non-zero on warnings too).
  --quiet         Only print on findings.
  --no-color      Disable ANSI colors.
  -h, --help      Show this help.
  -v, --version   Show version.

Exit codes:
  0  clean (or only warnings without --strict)
  1  blocking finding(s) detected
  2  usage / runtime error

Docs & allowlisting: see README. Add a config via .polinguardrc.json.`;

function parseArgs(argv) {
  const o = { mode: 'staged', paths: [], strict: false, quiet: false, color: true };
  for (const a of argv) {
    if (a === '--staged') o.mode = 'staged';
    else if (a === '--all' || a === '--ci') o.mode = 'all';
    else if (a === '--strict') o.strict = true;
    else if (a === '--quiet') o.quiet = true;
    else if (a === '--no-color') o.color = false;
    else if (a === '-h' || a === '--help') o.help = true;
    else if (a === '-v' || a === '--version') o.version = true;
    else if (a.startsWith('-')) { o.unknown = a; }
    else { o.paths.push(a); o.mode = 'paths'; }
  }
  return o;
}

function paint(s, code, enabled) {
  const ESC = String.fromCharCode(27);
  return enabled ? ESC + "[" + code + "m" + s + ESC + "[0m" : s;
}

function main() {
  const o = parseArgs(process.argv.slice(2));
  const c = o.color && process.stdout.isTTY;

  if (o.help) { process.stdout.write(HELP + '\n'); return 0; }
  if (o.version) {
    try { process.stdout.write(require('../package.json').version + '\n'); } catch { process.stdout.write('0.0.0\n'); }
    return 0;
  }
  if (o.unknown) { process.stderr.write(`polin-guard: unknown option ${o.unknown}\n`); return 2; }

  let res;
  try {
    res = run({ mode: o.mode, paths: o.paths, strict: o.strict });
  } catch (e) {
    process.stderr.write(`polin-guard: ${e.message}\n`);
    return 2;
  }

  if (res.findings.length === 0) {
    if (!o.quiet) {
      process.stdout.write(paint('✓ polin-guard: no injection indicators found', '32', c) +
        ` (${res.filesScanned} file${res.filesScanned === 1 ? '' : 's'} scanned)\n`);
    }
    return 0;
  }

  const header = res.blocking
    ? paint('✖ polin-guard: potential code injection detected', '1;31', c)
    : paint('⚠ polin-guard: review-worthy findings', '33', c);
  process.stderr.write(`\n${header}\n\n`);

  // Group findings by file.
  const byFile = new Map();
  for (const f of res.findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }
  for (const [file, items] of byFile) {
    process.stderr.write(paint(file, '36', c) + '\n');
    for (const it of items) {
      const tag = it.severity === 'critical'
        ? paint('CRITICAL', '1;31', c)
        : paint('warning ', '33', c);
      const loc = it.line === 0 ? `${file} (file-level)` : `${file}:${it.line}`;
      process.stderr.write(`  ${tag} ${loc}  [${it.ruleId}]\n            ${it.message}\n`);
    }
    process.stderr.write('\n');
  }

  if (res.blocking) {
    process.stderr.write(
      'Commit blocked. If this is a genuine attack, do NOT commit — investigate the file.\n' +
      'If this is a verified false positive, acknowledge the line with a\n' +
      `"// polinguard-allow-line" comment, an "polinguard-allow-next-line" comment above it,\n` +
      'or adjust .polinguardrc.json. (Bypass for one commit: git commit --no-verify.)\n'
    );
    return 1;
  }
  process.stderr.write('Warnings only — not blocking. Use --strict to block on warnings.\n');
  return 0;
}

process.exit(main());
