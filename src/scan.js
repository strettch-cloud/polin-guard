'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { DEFAULTS, WEIGHTS, SIGNATURES, RE } = require('./patterns');

const ALLOW_LINE_MARKER = 'polinguard-allow-next-line';
const ALLOW_INLINE_MARKER = 'polinguard-allow-line';

/** Load optional config file from the repo root or cwd. */
function loadConfig(cwd) {
  for (const name of ['.polinguardrc.json', '.polinguard.json']) {
    const p = path.join(cwd, name);
    try {
      if (fs.existsSync(p)) return { ...DEFAULTS, ...JSON.parse(fs.readFileSync(p, 'utf8')) };
    } catch (e) {
      process.stderr.write(`polin-guard: ignoring invalid ${name}: ${e.message}\n`);
    }
  }
  return { ...DEFAULTS };
}

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 1024 * 1024 * 64 });
}
function getStagedFiles(cwd) {
  return git(['diff', '--cached', '--name-only', '--diff-filter=ACMR'], cwd).split('\n').filter(Boolean);
}
function getTrackedFiles(cwd) {
  return git(['ls-files'], cwd).split('\n').filter(Boolean);
}
function readStaged(file, cwd) {
  try { return git(['show', `:${file}`], cwd); } catch { return null; }
}

function isExcluded(file, cfg) {
  const parts = file.split(/[\\/]/);
  if (parts.some((p) => cfg.excludeDirs.includes(p))) return true;
  if (cfg.excludeFilePatterns.some((re) => re.test(file))) return true;
  return !cfg.includeExtensions.includes(path.extname(file).toLowerCase());
}

/** Files that a build/test tool loads automatically — exec here is high-risk. */
function isAutoLoaded(file) {
  const base = (file.split(/[\\/]/).pop() || '').toLowerCase();
  return (
    /\.config\.(js|cjs|mjs|ts)$/.test(base) ||
    /^\.?eslintrc(\.(js|cjs|json|yml|yaml))?$/.test(base) ||
    /^(index|main|server|app)\.(js|cjs|mjs|ts)$/.test(base) ||
    /^\.(babelrc|prettierrc|stylelintrc)/.test(base) ||
    base === 'ecosystem.config.js'
  );
}

function countEscapes(line) {
  const m = line.match(/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g);
  return m ? m.length : 0;
}

/** Shannon entropy (bits/char). Obfuscated/encoded blobs run high. */
function entropy(s) {
  if (!s.length) return 0;
  const freq = Object.create(null);
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const k in freq) { const p = freq[k] / s.length; h -= p * Math.log2(p); }
  return h;
}

function longestToken(line) {
  let max = 0;
  for (const t of line.split(/\s+/)) if (t.length > max) max = t.length;
  return max;
}

/**
 * Score a single line. Returns { score, signals: [{id, weight, message}], flags }.
 * `flags` exposes booleans the file-level pass aggregates.
 */
function analyzeLine(line, cfg, ctx = {}) {
  const signals = [];
  const add = (id, weight, message) => signals.push({ id, weight, message });

  for (const sig of SIGNATURES) if (sig.re.test(line)) add(sig.id, WEIGHTS.signature, sig.message);

  // Concealment: code after a long mid-line whitespace gap (off-screen trick).
  const body = line.replace(/^[ \t]+/, '');
  if (new RegExp(`\\S[ \\t]{${cfg.minGapWhitespace},}\\S`).test(body)) {
    add('concealment', WEIGHTS.concealment, `code hidden after ${cfg.minGapWhitespace}+ spaces (off-screen concealment)`);
  }

  const tok = longestToken(body);
  if (tok >= cfg.maxTokenLength) add('long-token', WEIGHTS.longToken, `unbroken ${tok}-char token (encoded blob)`);

  const esc = countEscapes(line);
  if (esc >= cfg.maxEscapes) add('escape-density', WEIGHTS.escapeDense, `${esc} \\x/\\u escapes (obfuscated blob)`);

  if (line.length >= cfg.entropyMinLen) {
    const h = entropy(line);
    if (h >= cfg.entropyThreshold) add('entropy', WEIGHTS.entropy, `high entropy ${h.toFixed(2)} over ${line.length} chars`);
  }

  if (line.length > cfg.maxLineLength) {
    const exec = RE.execTokens.test(line);
    add('oversized-line', WEIGHTS.oversized + (exec ? WEIGHTS.oversizedExecBonus : 0),
      `line length ${line.length}${exec ? ' with exec/require tokens' : ''}`);
  }

  const execSink = RE.execSink.test(line);
  if (execSink) add('exec-sink', WEIGHTS.execSink, 'dynamic code-exec sink (Function/eval)');
  if (RE.indirectRequire.test(line)) add('indirect-require', WEIGHTS.indirectRequire, 'require() with a non-literal argument');
  if (RE.ctorChain.test(line)) add('ctor-chain', WEIGHTS.ctorChain, 'constructor.constructor access (reaches Function)');
  if (RE.dynTimer.test(line)) add('dyn-timer', WEIGHTS.dynTimer, 'setTimeout/Interval with a string body');
  if (RE.vmModule.test(line)) add('vm-module', WEIGHTS.vmModule, 'loads the vm module');

  const net = RE.network.test(line);
  if (net) add('network', WEIGHTS.network, 'network access');
  const cap = RE.capability.test(line);
  if (cap) add('capability', WEIGHTS.capability, 'env/fs/child_process capability');
  const fsWrite = RE.fsWrite.test(line);
  const child = RE.childProc.test(line);

  if (net && (execSink || RE.indirectRequire.test(line) || fsWrite || child)) {
    add('net-exec-combo', WEIGHTS.netExecCombo, 'network + code-exec/file-write on one line (runtime-fetched payload)');
  }
  if (ctx.autoLoaded && (execSink || cap || net || child)) {
    add('autoloaded-context', WEIGHTS.autoloadBonus, 'in an auto-loaded config/entry file');
  }

  const score = signals.reduce((a, s) => a + s.weight, 0);
  return { score, signals, flags: { execSink, net, cap, fsWrite, child, esc, longTok: tok >= cfg.maxTokenLength } };
}

function severityFor(score, cfg) {
  if (score >= cfg.criticalScore) return 'critical';
  if (score >= cfg.warningScore) return 'warning';
  return null;
}

/** Scan one file's content (string) -> findings[]. */
function scanContent(file, content, cfg) {
  const ctx = { autoLoaded: isAutoLoaded(file) };
  const lines = content.split(/\r?\n/);
  const findings = [];

  let fileEsc = 0, anyExec = false, anyNet = false, anyChild = false, anyFsWrite = false, anyLongTok = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes(ALLOW_INLINE_MARKER)) continue;
    if (i > 0 && lines[i - 1].includes(ALLOW_LINE_MARKER)) continue;

    const { score, signals, flags } = analyzeLine(line, cfg, ctx);
    fileEsc += flags.esc;
    anyExec = anyExec || flags.execSink;
    anyNet = anyNet || flags.net;
    anyChild = anyChild || flags.child;
    anyFsWrite = anyFsWrite || flags.fsWrite;
    anyLongTok = anyLongTok || flags.longTok;

    const sev = severityFor(score, cfg);
    if (sev) {
      const top = signals.slice().sort((a, b) => b.weight - a.weight);
      findings.push({
        file, line: i + 1, score, severity: sev,
        ruleId: top[0].id,
        message: `risk ${score} [${top.map((s) => s.id).join(', ')}] — ${top[0].message}`,
      });
    }
  }

  // File-level pass: catches payloads split across many lines or fetched at runtime.
  const region = [];
  if (fileEsc >= cfg.fileEscapeTotal && (anyExec || anyChild)) {
    region.push({ s: 80, m: `${fileEsc} escape sequences across the file + a dynamic-exec sink (split/obfuscated payload)` });
  }
  if (anyLongTok && (anyExec || anyChild)) {
    region.push({ s: 55, m: 'long encoded token(s) + a dynamic-exec sink' });
  }
  if (anyNet && (anyExec || anyChild || anyFsWrite)) {
    region.push({ s: 55 + (ctx.autoLoaded ? WEIGHTS.autoloadBonus : 0), m: 'network access + code-exec/file-write across the file (runtime-fetched payload)' });
  }
  if (region.length) {
    const best = region.sort((a, b) => b.s - a.s)[0];
    const sev = severityFor(best.s, cfg);
    if (sev) findings.push({ file, line: 0, score: best.s, severity: sev, ruleId: 'file-region', message: `file-level risk ${best.s} — ${best.m}` });
  }

  return findings;
}

function run(opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const cfg = loadConfig(cwd);
  const mode = opts.mode || 'staged';

  let files, readFile;
  if (mode === 'paths') {
    files = opts.paths || [];
    readFile = (f) => { try { return fs.readFileSync(path.resolve(cwd, f), 'utf8'); } catch { return null; } };
  } else if (mode === 'all') {
    files = getTrackedFiles(cwd);
    readFile = (f) => { try { return fs.readFileSync(path.resolve(cwd, f), 'utf8'); } catch { return null; } };
  } else {
    files = getStagedFiles(cwd);
    readFile = (f) => readStaged(f, cwd);
  }

  const scanned = [];
  const findings = [];
  for (const file of files) {
    if (isExcluded(file, cfg)) continue;
    const content = readFile(file);
    if (content == null) continue;
    scanned.push(file);
    findings.push(...scanContent(file, content, cfg));
  }

  const critical = findings.filter((f) => f.severity === 'critical');
  const warnings = findings.filter((f) => f.severity === 'warning');
  const blocking = opts.strict ? findings.length > 0 : critical.length > 0;
  return { filesScanned: scanned.length, findings, critical, warnings, blocking };
}

module.exports = { run, scanContent, analyzeLine, loadConfig, entropy, isAutoLoaded };
