#!/usr/bin/env node
'use strict';

const { run } = require('../src/scan');
const { auditInstall, harden } = require('../src/supplychain');

const HELP = `polin-guard — stop obfuscated injection & malicious dependencies

Usage:
  polin-guard [scan] [options] [paths...]   Scan files for injected payloads (default)
  polin-guard install-audit [options]       Audit dependencies for supply-chain risk
  polin-guard harden [--fix]                Check/enable install-time hardening

Scan modes:
  --staged        Scan files staged for commit (default; for pre-commit hooks).
  --all           Scan all git-tracked files.
  --ci            Alias for --all (use in CI).
  [paths...]      Scan specific files (no git required).

Options:
  --strict        Treat warnings as blocking (exit non-zero on warnings too).
  --quiet         Only print on findings.
  --no-color      Disable ANSI colors.
  -h, --help      Show this help.
  -v, --version   Show version.

Exit codes:  0 clean · 1 blocking finding(s) · 2 usage/runtime error

Docs & allowlisting: see README. Scan config via .polinguardrc.json.`;

function paint(s, code, enabled) {
  const ESC = String.fromCharCode(27);
  return enabled ? ESC + '[' + code + 'm' + s + ESC + '[0m' : s;
}
const useColor = (argv) => !argv.includes('--no-color') && process.stdout.isTTY;

/** Shared pretty-printer for a list of {severity, ruleId, message, where|file,line}. */
function printFindings(title, findings, blocking, c) {
  const header = blocking
    ? paint(`✖ ${title}`, '1;31', c)
    : paint(`⚠ ${title}`, '33', c);
  process.stderr.write(`\n${header}\n\n`);
  for (const f of findings) {
    const tag = f.severity === 'critical' ? paint('CRITICAL', '1;31', c)
      : f.severity === 'warning' ? paint('warning ', '33', c)
      : paint('info    ', '36', c);
    const loc = f.where || (f.line === 0 ? `${f.file} (file-level)` : `${f.file}:${f.line}`);
    process.stderr.write(`  ${tag} ${paint(loc, '36', c)}  [${f.ruleId}]\n            ${f.message}\n`);
  }
  process.stderr.write('\n');
}

function cmdScan(argv) {
  const o = { mode: 'staged', paths: [], strict: false, quiet: false };
  for (const a of argv) {
    if (a === '--staged') o.mode = 'staged';
    else if (a === '--all' || a === '--ci') o.mode = 'all';
    else if (a === '--strict') o.strict = true;
    else if (a === '--quiet') o.quiet = true;
    else if (a === '--no-color') { /* handled globally */ }
    else if (a.startsWith('-')) { process.stderr.write(`polin-guard: unknown option ${a}\n`); return 2; }
    else { o.paths.push(a); o.mode = 'paths'; }
  }
  const c = useColor(argv);

  let res;
  try { res = run({ mode: o.mode, paths: o.paths, strict: o.strict }); }
  catch (e) { process.stderr.write(`polin-guard: ${e.message}\n`); return 2; }

  if (res.findings.length === 0) {
    if (!o.quiet) process.stdout.write(paint('✓ polin-guard: no injection indicators found', '32', c) +
      ` (${res.filesScanned} file${res.filesScanned === 1 ? '' : 's'} scanned)\n`);
    return 0;
  }
  printFindings('polin-guard: potential code injection detected', res.findings, res.blocking, c);
  if (res.blocking) {
    process.stderr.write(
      'Commit blocked. If this is a genuine attack, do NOT commit — investigate the file.\n' +
      'Verified false positive? Use a "// polinguard-allow-line" comment or .polinguardrc.json.\n' +
      '(Bypass for one commit: git commit --no-verify.)\n');
    return 1;
  }
  process.stderr.write('Warnings only — not blocking. Use --strict to block on warnings.\n');
  return 0;
}

function cmdAudit(argv) {
  const strict = argv.includes('--strict');
  const quiet = argv.includes('--quiet');
  const c = useColor(argv);
  let res;
  try { res = auditInstall(process.cwd()); }
  catch (e) { process.stderr.write(`polin-guard: ${e.message}\n`); return 2; }

  const blocking = strict ? (res.critical.length + res.warnings.length) > 0 : res.critical.length > 0;
  if (res.findings.length === 0) {
    if (!quiet) process.stdout.write(paint('✓ polin-guard: no supply-chain risks found', '32', c) + '\n');
    return 0;
  }
  printFindings('polin-guard: supply-chain risks detected', res.findings, blocking, c);
  process.stderr.write(`${res.critical.length} critical, ${res.warnings.length} warning(s). ` +
    `Run \`polin-guard harden --fix\` to block install scripts.\n`);
  return blocking ? 1 : 0;
}

function cmdHarden(argv) {
  const fix = argv.includes('--fix');
  const c = useColor(argv);
  let r;
  try { r = harden(process.cwd(), { fix }); }
  catch (e) { process.stderr.write(`polin-guard: ${e.message}\n`); return 2; }

  if (r.hasIgnore) process.stdout.write(paint('✓ ignore-scripts is already enabled', '32', c) + ` (${r.npmrc})\n`);
  else if (r.applied) process.stdout.write(paint('✓ enabled ignore-scripts=true', '32', c) + ` in ${r.npmrc}\n`);
  else process.stdout.write(paint('⚠ ignore-scripts is NOT enabled', '33', c) + ` — run \`polin-guard harden --fix\` to set it.\n`);

  process.stdout.write('\nRecommendations:\n');
  for (const rec of r.recommendations) process.stdout.write(`  • ${rec}\n`);
  return 0;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('-h') || argv.includes('--help')) { process.stdout.write(HELP + '\n'); return 0; }
  if (argv.includes('-v') || argv.includes('--version')) {
    try { process.stdout.write(require('../package.json').version + '\n'); } catch { process.stdout.write('0.0.0\n'); }
    return 0;
  }
  const sub = argv[0];
  if (sub === 'install-audit' || sub === 'audit') return cmdAudit(argv.slice(1));
  if (sub === 'harden') return cmdHarden(argv.slice(1));
  if (sub === 'scan') return cmdScan(argv.slice(1));
  return cmdScan(argv); // default: scan
}

process.exit(main());
