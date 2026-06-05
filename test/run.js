'use strict';

// Minimal zero-dependency test runner.
const path = require('path');
const { run, scanContent, loadConfig } = require('../src/scan');

let passed = 0;
let failed = 0;
function check(name, cond) {
  if (cond) { passed++; process.stdout.write(`  ok  ${name}\n`); }
  else { failed++; process.stdout.write(`  FAIL ${name}\n`); }
}

const cwd = path.join(__dirname, '..');
const cfg = loadConfig(cwd);
const fs = require('fs');

// 1) Clean fixture must produce zero findings.
const clean = fs.readFileSync(path.join(__dirname, 'fixtures/clean.config.js'), 'utf8');
const cleanFindings = scanContent('clean.config.js', clean, cfg);
check('clean fixture has no findings', cleanFindings.length === 0);

// 2) Malicious fixture must produce at least one CRITICAL finding.
const mal = fs.readFileSync(path.join(__dirname, 'fixtures/malicious.config.js'), 'utf8');
const malFindings = scanContent('malicious.config.js', mal, cfg);
const malCritical = malFindings.filter((f) => f.severity === 'critical');
check('malicious fixture flagged critical', malCritical.length >= 1);
check('detects global-bang signature', malFindings.some((f) => f.ruleId === 'global-bang-key'));
check('detects oversized-line', malFindings.some((f) => f.ruleId === 'oversized-line'));
check('detects escape-density', malFindings.some((f) => f.ruleId === 'escape-density'));
check('detects iife-constructor', malFindings.some((f) => f.ruleId === 'iife-constructor'));

// 3) Allow markers suppress findings.
const allowed =
  '// injectguard-allow-next-line\n' +
  'module.exports={};' + ' '.repeat(1100) + 'var x=require("fs");\n';
check('allow-next-line suppresses finding', scanContent('a.js', allowed, cfg).length === 0);

const allowedInline =
  'module.exports={};' + ' '.repeat(1100) + 'var x=require("fs"); // injectguard-allow-line\n';
check('allow-line inline suppresses finding', scanContent('b.js', allowedInline, cfg).length === 0);

// 4) A short, ordinary require() must NOT trip the scanner.
check('ordinary require not flagged', scanContent('c.js', 'const fs = require("fs");\n', cfg).length === 0);

// 5) End-to-end run() over the fixtures dir in paths mode blocks.
const e2e = run({
  mode: 'paths',
  cwd,
  paths: ['test/fixtures/clean.config.js', 'test/fixtures/malicious.config.js'],
});
check('run() blocks on fixtures', e2e.blocking === true);
check('run() scanned 2 files', e2e.filesScanned === 2);

process.stdout.write(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
