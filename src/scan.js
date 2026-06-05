'use strict';

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const {
  DEFAULTS,
  SIGNATURES,
  IIFE_CONSTRUCTOR,
  EXEC_TOKENS,
  SOFT_INDICATORS,
} = require('./patterns');

const ALLOW_LINE_MARKER = 'polinguard-allow-next-line';
const ALLOW_INLINE_MARKER = 'polinguard-allow-line';

/** Load optional config file from the repo root or cwd. */
function loadConfig(cwd) {
  const candidates = ['.polinguardrc.json', '.polinguard.json'];
  for (const name of candidates) {
    const p = path.join(cwd, name);
    try {
      if (fs.existsSync(p)) {
        const user = JSON.parse(fs.readFileSync(p, 'utf8'));
        return { ...DEFAULTS, ...user };
      }
    } catch (e) {
      process.stderr.write(`polin-guard: ignoring invalid ${name}: ${e.message}\n`);
    }
  }
  return { ...DEFAULTS };
}

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 1024 * 1024 * 64 });
}

/** Files staged for commit (added/copied/modified/renamed). */
function getStagedFiles(cwd) {
  const out = git(['diff', '--cached', '--name-only', '--diff-filter=ACMR'], cwd);
  return out.split('\n').filter(Boolean);
}

/** All tracked files (for --all / --ci). */
function getTrackedFiles(cwd) {
  return git(['ls-files'], cwd).split('\n').filter(Boolean);
}

/** Read the *staged* blob content (what will actually be committed). */
function readStaged(file, cwd) {
  try {
    return git(['show', `:${file}`], cwd);
  } catch (e) {
    return null; // deleted or unreadable
  }
}

function isExcluded(file, cfg) {
  const parts = file.split(/[\\/]/);
  if (parts.some((p) => cfg.excludeDirs.includes(p))) return true;
  if (cfg.excludeFilePatterns.some((re) => re.test(file))) return true;
  const ext = path.extname(file).toLowerCase();
  if (!cfg.includeExtensions.includes(ext)) return true;
  return false;
}

function countEscapes(line) {
  const m = line.match(/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/g);
  return m ? m.length : 0;
}

/** Analyze a single line. Returns array of findings for that line. */
function analyzeLine(line, cfg) {
  const out = [];

  // 1) Near-unique stager signatures -> always critical.
  for (const sig of SIGNATURES) {
    if (sig.re.test(line)) {
      out.push({ ruleId: sig.id, severity: 'critical', message: sig.message });
    }
  }

  // 2) Dense escape-sequence blob -> obfuscated payload.
  const esc = countEscapes(line);
  if (esc >= cfg.maxEscapes) {
    out.push({
      ruleId: 'escape-density',
      severity: 'critical',
      message: `High escape-sequence density (${esc} \\x/\\u escapes) — obfuscated blob.`,
    });
  }

  // 3) Immediately-invoked Function() constructor on a long line -> exec sink.
  if (IIFE_CONSTRUCTOR.test(line) && line.length > 200) {
    out.push({
      ruleId: 'iife-constructor',
      severity: 'critical',
      message: 'Immediately-invoked Function()/dynamic constructor on a long line — second-stage exec sink.',
    });
  }

  // 4) Oversized line: critical if it also carries exec/require tokens, else a warning.
  if (line.length > cfg.maxLineLength) {
    const exec = EXEC_TOKENS.test(line);
    out.push({
      ruleId: 'oversized-line',
      severity: exec ? 'critical' : 'warning',
      message: `Line length ${line.length} exceeds limit (${cfg.maxLineLength})` +
        (exec ? ' and contains exec/require tokens — classic hidden-payload concealment.' : ' — review for hidden content.'),
    });
  }

  // 5) Soft indicators (warnings only).
  for (const ind of SOFT_INDICATORS) {
    if (ind.re.test(line)) {
      out.push({ ruleId: ind.id, severity: 'warning', message: ind.message });
    }
  }

  return out;
}

/** Scan one file's content (string). */
function scanContent(file, content, cfg) {
  const findings = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Inline allow markers let a maintainer acknowledge a known-good long line.
    if (line.includes(ALLOW_INLINE_MARKER)) continue;
    if (i > 0 && lines[i - 1].includes(ALLOW_LINE_MARKER)) continue;

    const lineFindings = analyzeLine(line, cfg);
    for (const f of lineFindings) {
      findings.push({ ...f, file, line: i + 1 });
    }
  }
  return findings;
}

/**
 * Run a scan.
 * @param {object} opts
 * @param {'staged'|'all'|'paths'} opts.mode
 * @param {string[]} [opts.paths] explicit paths when mode === 'paths'
 * @param {string} [opts.cwd]
 * @param {boolean} [opts.strict] treat warnings as blocking too
 */
function run(opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const cfg = loadConfig(cwd);
  const mode = opts.mode || 'staged';

  let files = [];
  let readFile;

  if (mode === 'paths') {
    files = opts.paths || [];
    readFile = (f) => {
      try { return fs.readFileSync(path.resolve(cwd, f), 'utf8'); } catch { return null; }
    };
  } else if (mode === 'all') {
    files = getTrackedFiles(cwd);
    readFile = (f) => {
      try { return fs.readFileSync(path.resolve(cwd, f), 'utf8'); } catch { return null; }
    };
  } else {
    // staged (default): scan the exact content that will be committed.
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

module.exports = { run, scanContent, analyzeLine, loadConfig };
