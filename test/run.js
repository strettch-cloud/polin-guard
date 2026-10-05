'use strict';

// Zero-dependency test runner for polin-guard v0.2 (scoring engine + evasion).
const fs = require('fs');
const path = require('path');
const { scanContent, analyzeLine, loadConfig, entropy } = require('../src/scan');

let passed = 0, failed = 0;
function check(name, cond) {
  if (cond) { passed++; process.stdout.write(`  ok   ${name}\n`); }
  else { failed++; process.stdout.write(`  FAIL ${name}\n`); }
}

const cwd = path.join(__dirname, '..');
const cfg = loadConfig(cwd);
const FX = path.join(__dirname, 'fixtures');
const read = (f) => fs.readFileSync(path.join(FX, f), 'utf8');
const scan = (f) => scanContent(f, read(f), cfg);
const hasCritical = (findings) => findings.some((x) => x.severity === 'critical');

// --- Clean / true-positive baseline ---------------------------------------
check('clean fixture: no findings', scan('clean.config.js').length === 0);
check('known payload: blocked (critical)', hasCritical(scan('malicious.config.js')));

// --- Evasion resistance (the v0.2 point) ----------------------------------
const renamed = scan('evade-renamed.config.js');
check('EVASION renamed payload: still blocked', hasCritical(renamed));
check('  ...caught WITHOUT a known signature (structural)',
  renamed.every((f) => !/global-bang-key|char-shuffle-cipher|global-underscore/.test(f.ruleId)) &&
  renamed.some((f) => /concealment/.test(f.message)));

const split = scan('evade-split.config.js');
check('EVASION split-across-lines payload: still blocked', hasCritical(split));
check('  ...caught by the file-level pass', split.some((f) => f.ruleId === 'file-region' && f.severity === 'critical'));

const rf = scan('evade-runtime-fetch.config.js');
check('EVASION runtime-fetched payload: still blocked', hasCritical(rf));
check('  ...caught by network+exec combo', rf.some((f) => /network access \+ code-exec/.test(f.message)));

// --- False-positive guards -------------------------------------------------
check('FP guard: long data line is NOT critical', !hasCritical(scan('legit-bigdata.js')));
check('FP guard: ordinary dynamic require is NOT critical', !hasCritical(scan('legit-dynamic-require.js')));
check('FP guard: ordinary literal require not flagged at all',
  scanContent('c.js', 'const fs = require("fs");\nmodule.exports = {};\n', cfg).length === 0);

// --- Scoring engine internals ---------------------------------------------
const conceal = analyzeLine('x;' + ' '.repeat(100) + 'var y=Function("return 1")();', cfg, {});
check('concealment is a heavy signal', conceal.signals.some((s) => s.id === 'concealment'));
check('concealment line scores critical', conceal.score >= cfg.criticalScore);

const plain = analyzeLine('const a = 1 + 2;', cfg, {});
check('plain code scores 0', plain.score === 0);

check('entropy: random string > structured text', entropy('a8F!x2@qZ9#wL5') > entropy('aaaaaaaaaaaaaa'));

// --- Allow markers ---------------------------------------------------------
check('allow-next-line suppresses',
  scanContent('a.js', '// polinguard-allow-next-line\nx;' + ' '.repeat(100) + 'y;\n', cfg).length === 0);
check('allow-line inline suppresses',
  scanContent('b.js', 'x;' + ' '.repeat(100) + 'y; // polinguard-allow-line\n', cfg).length === 0);

// --- Delivery artifacts (fake fonts, folder-open tasks, push tooling) -----
// Synthetic, inert samples shaped like the Oct-2026 PolinRider wave, scanned through run() so file selection
// (non-code extensions) is covered too.
const { run } = require('../src/scan');
const os2 = require('os');
const art = fs.mkdtempSync(path.join(os2.tmpdir(), 'pg-art-'));
const put = (rel, data, enc = 'utf8') => {
  fs.mkdirSync(path.dirname(path.join(art, rel)), { recursive: true });
  fs.writeFileSync(path.join(art, rel), data, enc);
  return rel;
};
const tabbed = "\t".repeat(421) + "global['!'] = '8-J';var _0x1=function(){return 0};_0x1();\n";
const files = {
  llf: put('public/fonts/fa-solid-300.llf', tabbed),
  fakeWoff2: put('public/fonts/fa-solid-500.woff2', 'var inert = 0;\n'),
  realWoff2: put('public/fonts/real.woff2', Buffer.from([0x77, 0x4f, 0x46, 0x32, 0x00, 0x01, 0xff, 0x80]), null),
  realTtf: put('public/fonts/real.ttf', Buffer.from([0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00]), null),
  tasksEvil: put('evil/.vscode/tasks.json', '{ "version": "2.0.0", "tasks": [ { "label": "eslint-check", "type": "shell",\n' +
    '  "command": "node ./public/fonts/fa-solid-300.llf",\n  "presentation": { "reveal": "never", "echo": false },\n' +
    '  "runOptions": { "\\u0072unOn": "folderOpen" } }, ] }\n'),
  tasksPlainOpen: put('dev/.vscode/tasks.json', '{ "tasks": [ { "label": "dev", "type": "npm", "script": "dev", "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  tasksBuild: put('ok/.vscode/tasks.json', '{ "tasks": [ { "label": "build", "type": "shell", "command": "npm run build" } ] }\n'),
  settingsAuto: put('evil/.vscode/settings.json', '{ "task.allowAutomaticTasks": "on" }\n'),
  settingsOk: put('ok/.vscode/settings.json', '{ "editor.tabSize": 2 }\n'),
  ignoreEvil: put('evil/.gitignore', 'node_modules\ntemp_auto_push.bat\nbranch_structure.json\n'),
  ignoreOk: put('ok/.gitignore', 'node_modules\n.env\n'),
  pushTool: put('tools/branch_structure.json', '{"branches":[]}\n'),
  tabConfig: put('web/postcss.config.js', 'module.exports = {};' + tabbed),
};
const res = run({ mode: 'paths', cwd: art, paths: Object.values(files) });
const at = (rel) => res.findings.filter((f) => f.file === rel);
const crit = (rel, rule) => at(rel).some((f) => f.severity === 'critical' && (!rule || f.ruleId === rule));
check('ART: .llf loader is read and blocked as a fake font', crit(files.llf, 'fake-font'));
check('ART: .llf content also line-scored (tab-padded stamp)', at(files.llf).some((f) => f.ruleId !== 'fake-font'));
check('ART: text .woff2 is a fake font', crit(files.fakeWoff2, 'fake-font'));
check('ART: real woff2 / ttf headers are not flagged', at(files.realWoff2).length === 0 && at(files.realTtf).length === 0);
check('ART: hidden folder-open task running a font-named file blocks (escaped key too)', crit(files.tasksEvil, 'vscode-autorun'));
check('ART: plain folder-open npm task only warns', at(files.tasksPlainOpen).some((f) => f.severity === 'warning') && !crit(files.tasksPlainOpen));
check('ART: ordinary build task not flagged', at(files.tasksBuild).length === 0);
check('ART: committed task.allowAutomaticTasks blocks', crit(files.settingsAuto, 'vscode-auto-tasks'));
check('ART: ordinary settings.json not flagged', at(files.settingsOk).length === 0);
check('ART: .gitignore hiding the push tool blocks', crit(files.ignoreEvil, 'push-tool-ignored'));
check('ART: ordinary .gitignore not flagged', at(files.ignoreOk).length === 0);
check('ART: branch_structure.json push-tool file blocks', crit(files.pushTool, 'push-tool'));
check('ART: tab-padded loader in a config blocks', crit(files.tabConfig));
check('ART: run() reports blocking', res.blocking === true);
fs.rmSync(art, { recursive: true, force: true });

// --- Supply-chain layer ----------------------------------------------------
const { auditInstall, harden, levenshtein } = require('../src/supplychain');
const os = require('os');
const SC = path.join(FX, 'sc');
const audit = (d) => auditInstall(path.join(SC, d));

check('SC: clean project has no critical/warning', (() => { const r = audit('clean'); return r.critical.length === 0 && r.warnings.length === 0; })());
check('SC: malicious postinstall (curl|bash) blocks', audit('malicious').findings.some((f) => f.ruleId === 'malicious-script' && f.severity === 'critical'));
check('SC: typosquat dependency blocks', audit('typosquat').findings.some((f) => f.ruleId === 'typosquat' && f.severity === 'critical'));
check('SC: git-source dependency warns', audit('gitdep').findings.some((f) => f.ruleId === 'non-registry-source'));
check('SC: foreign-registry lock entry blocks', audit('foreignlock').findings.some((f) => f.ruleId === 'foreign-registry' && f.severity === 'critical'));
check('SC: counts install-script packages', audit('foreignlock').findings.some((f) => f.ruleId === 'install-script-count'));
check('SC: official-registry package (sharp) NOT flagged as foreign',
  !audit('foreignlock').findings.some((f) => f.ruleId === 'foreign-registry' && /sharp/.test(f.message)));
check('SC: levenshtein basic', levenshtein('expres', 'express') === 1 && levenshtein('abc', 'abc') === 0);

// harden in a throwaway dir (don't touch the project)
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-harden-'));
const h1 = harden(tmp, { fix: false });
check('SC harden: reports ignore-scripts not set', h1.hasIgnore === false && h1.applied === false);
const h2 = harden(tmp, { fix: true });
check('SC harden: --fix writes ignore-scripts', h2.applied === true && /ignore-scripts=true/.test(fs.readFileSync(path.join(tmp, '.npmrc'), 'utf8')));
const h3 = harden(tmp, { fix: false });
check('SC harden: detects it is now enabled', h3.hasIgnore === true);
fs.rmSync(tmp, { recursive: true, force: true });

process.stdout.write(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed === 0 ? 0 : 1);
