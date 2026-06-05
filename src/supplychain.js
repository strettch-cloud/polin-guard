'use strict';

/**
 * Supply-chain layer for polin-guard.
 *
 * The scanner (scan.js) catches a payload that is already in your tree. This
 * module attacks the *root cause*: a malicious dependency that executes code at
 * `npm install` / build time. It reads manifests and lockfiles WITHOUT installing
 * anything, and flags the vectors that actually deliver these attacks:
 *
 *   - lifecycle install scripts (pre/post-install, prepare, …) — how install-time
 *     code runs at all — and especially scripts that pipe the network to a shell
 *   - dependencies pulled from non-registry sources (git/http/tarball/file)
 *   - packages resolved from a non-default registry (registry hijack)
 *   - transitive packages that declare an install/build script (the real surface)
 *   - typosquatted / homoglyph package names
 *
 * `harden()` flips on the defenses (ignore-scripts) so install scripts can't run.
 */

const fs = require('fs');
const path = require('path');

const LIFECYCLE = [
  'preinstall', 'install', 'postinstall',
  'preuninstall', 'postuninstall',
  'prepare', 'prepublish', 'prepublishOnly', 'prepack', 'postpack',
];

// Commands inside a script that strongly indicate malicious install-time code.
const SUSPICIOUS_SCRIPT = new RegExp(
  [
    '(?:curl|wget)\\s+[^|&;]*\\|\\s*(?:sh|bash|node|python)', // curl … | sh
    '\\bnode\\s+(?:-e|--eval)\\b', // node -e "…"
    '\\bbash\\s+-c\\b',
    'base64\\s+(?:-d|--decode|-D)',
    '\\beval\\b',
    '\\b(?:powershell|iwr|Invoke-WebRequest|certutil)\\b',
    '\\bchild_process\\b',
    'https?:\\/\\/\\d{1,3}(?:\\.\\d{1,3}){3}', // raw IP URL
    '\\b(?:atob|fromCharCode)\\b',
    '\\/dev\\/tcp\\/',
  ].join('|'),
  'i'
);

// A small set of very popular packages, for typosquat distance checks.
const POPULAR = [
  'react', 'react-dom', 'lodash', 'express', 'chalk', 'axios', 'commander',
  'webpack', 'vue', 'next', 'nuxt', 'vite', 'eslint', 'prettier', 'typescript',
  'tailwindcss', 'dotenv', 'jest', 'babel', 'rollup', 'moment', 'dayjs',
  'request', 'debug', 'colors', 'cross-env', 'node-fetch', 'uuid',
];

const DEFAULT_REGISTRY_HOSTS = new Set(['registry.npmjs.org']);

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const d = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
    }
  }
  return d[m][n];
}

function readJson(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}

function allowedRegistryHosts(cwd) {
  const hosts = new Set(DEFAULT_REGISTRY_HOSTS);
  for (const p of [path.join(cwd, '.npmrc'), path.join(require('os').homedir(), '.npmrc')]) {
    try {
      const txt = fs.readFileSync(p, 'utf8');
      const m = txt.match(/^\s*registry\s*=\s*(\S+)/m);
      if (m) { try { hosts.add(new URL(m[1]).host); } catch { /* ignore */ } }
    } catch { /* no .npmrc */ }
  }
  return hosts;
}

function hostOf(url) {
  try { return new URL(url.replace(/^git\+/, '')).host; } catch { return null; }
}

function isNonRegistrySpec(spec) {
  return /^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:|file:|link:|portal:)/.test(spec) ||
    /^[\w.-]+\/[\w.-]+(?:#.*)?$/.test(spec); // github user/repo shorthand
}

/** Audit package.json scripts + dependency sources. */
function auditManifest(cwd, findings) {
  const pkgPath = path.join(cwd, 'package.json');
  const pkg = readJson(pkgPath);
  if (!pkg) { findings.push({ severity: 'info', ruleId: 'no-manifest', where: 'package.json', message: 'No readable package.json found.' }); return null; }

  const scripts = pkg.scripts || {};
  for (const [name, body] of Object.entries(scripts)) {
    const isLifecycle = LIFECYCLE.includes(name);
    if (SUSPICIOUS_SCRIPT.test(String(body))) {
      findings.push({ severity: 'critical', ruleId: 'malicious-script', where: `package.json scripts.${name}`,
        message: `Script "${name}" runs a suspicious command (network-to-shell / eval / encoded): ${String(body).slice(0, 120)}` });
    } else if (isLifecycle) {
      findings.push({ severity: 'warning', ruleId: 'install-script', where: `package.json scripts.${name}`,
        message: `This package defines a lifecycle install script "${name}" — it will run on install.` });
    }
  }

  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const deps = pkg[field] || {};
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec === 'string' && isNonRegistrySpec(spec)) {
        findings.push({ severity: 'warning', ruleId: 'non-registry-source', where: `package.json ${field}.${name}`,
          message: `Dependency "${name}" is installed from a non-registry source: ${spec}` });
      }
      // typosquat / homoglyph
      if (/[^\x00-\x7f]/.test(name)) {
        findings.push({ severity: 'critical', ruleId: 'homoglyph-name', where: `package.json ${field}.${name}`,
          message: `Dependency name "${name}" contains non-ASCII characters (possible homoglyph squat).` });
      } else {
        const base = name.replace(/^@[^/]+\//, '');
        for (const pop of POPULAR) {
          if (base !== pop && Math.abs(base.length - pop.length) <= 1 && levenshtein(base, pop) === 1) {
            findings.push({ severity: 'critical', ruleId: 'typosquat', where: `package.json ${field}.${name}`,
              message: `Dependency "${name}" is one character away from popular package "${pop}" (possible typosquat).` });
            break;
          }
        }
      }
    }
  }
  return pkg;
}

/** Audit lockfiles for non-registry resolutions and install-script packages. */
function auditLockfiles(cwd, findings) {
  const allowed = allowedRegistryHosts(cwd);
  let installScriptPkgs = 0;

  // npm: package-lock.json (v2/v3)
  const lock = readJson(path.join(cwd, 'package-lock.json'));
  if (lock && lock.packages) {
    for (const [loc, info] of Object.entries(lock.packages)) {
      if (!loc) continue;
      if (info.hasInstallScript) installScriptPkgs++;
      const resolved = info.resolved;
      if (resolved && /^https?:/.test(resolved)) {
        const h = hostOf(resolved);
        if (h && !allowed.has(h)) {
          findings.push({ severity: 'critical', ruleId: 'foreign-registry', where: `package-lock.json ${loc}`,
            message: `Package resolved from a non-default registry/host "${h}": ${resolved}` });
        }
      } else if (resolved && /^git\+|^git:/.test(resolved)) {
        findings.push({ severity: 'warning', ruleId: 'git-source', where: `package-lock.json ${loc}`,
          message: `Package installed from a git source: ${resolved}` });
      }
    }
  }

  // pnpm: pnpm-lock.yaml (line scan — no YAML dependency)
  try {
    const txt = fs.readFileSync(path.join(cwd, 'pnpm-lock.yaml'), 'utf8');
    const lines = txt.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (/^\s*requiresBuild:\s*true/.test(l)) installScriptPkgs++;
      const tb = l.match(/tarball:\s*(\S+)/);
      if (tb) {
        const h = hostOf(tb[1]);
        if (h && !allowed.has(h)) {
          findings.push({ severity: 'critical', ruleId: 'foreign-registry', where: 'pnpm-lock.yaml',
            message: `Package tarball from a non-default host "${h}": ${tb[1]}` });
        }
      }
      if (/resolution:\s*\{[^}]*\b(repo|commit)\b/.test(l)) {
        findings.push({ severity: 'warning', ruleId: 'git-source', where: 'pnpm-lock.yaml',
          message: `Package resolved from a git source: ${l.trim().slice(0, 100)}` });
      }
    }
  } catch { /* no pnpm-lock */ }

  // yarn: yarn.lock
  try {
    const txt = fs.readFileSync(path.join(cwd, 'yarn.lock'), 'utf8');
    for (const m of txt.matchAll(/resolved\s+"([^"]+)"/g)) {
      const h = hostOf(m[1]);
      if (h && /^https?:/.test(m[1]) && !allowed.has(h)) {
        findings.push({ severity: 'critical', ruleId: 'foreign-registry', where: 'yarn.lock',
          message: `Package resolved from a non-default host "${h}": ${m[1]}` });
      }
    }
  } catch { /* no yarn.lock */ }

  if (installScriptPkgs > 0) {
    findings.push({ severity: 'info', ruleId: 'install-script-count', where: 'lockfile',
      message: `${installScriptPkgs} installed package(s) declare an install/build script. Run \`polin-guard harden\` to block them with ignore-scripts.` });
  }
}

/** Run the full supply-chain audit. */
function auditInstall(cwd) {
  const findings = [];
  auditManifest(cwd, findings);
  auditLockfiles(cwd, findings);
  const critical = findings.filter((f) => f.severity === 'critical');
  const warnings = findings.filter((f) => f.severity === 'warning');
  return { findings, critical, warnings, blocking: critical.length > 0 };
}

/** Check (and optionally apply) install-time hardening for this project. */
function harden(cwd, { fix = false } = {}) {
  const npmrc = path.join(cwd, '.npmrc');
  let current = '';
  try { current = fs.readFileSync(npmrc, 'utf8'); } catch { /* none */ }
  const hasIgnore = /^\s*ignore-scripts\s*=\s*true\s*$/m.test(current);

  const result = { hasIgnore, applied: false, npmrc, recommendations: [] };
  if (!hasIgnore) {
    result.recommendations.push('Set `ignore-scripts=true` in .npmrc to stop dependency install scripts from executing.');
    if (fix) {
      const next = (current.replace(/\s*$/, '') + '\nignore-scripts=true\n').replace(/^\n/, '');
      fs.writeFileSync(npmrc, next);
      result.applied = true;
    }
  }
  result.recommendations.push('Install with a frozen lockfile: `npm ci` / `pnpm install --frozen-lockfile`.');
  result.recommendations.push('Pin the registry and review lockfile diffs in code review.');
  return result;
}

module.exports = { auditInstall, harden, levenshtein, isNonRegistrySpec, SUSPICIOUS_SCRIPT, LIFECYCLE };
