'use strict';

// Delivery and propagation artifacts that line scoring cannot see: a loader stored as a "font", a VS Code
// task that runs it when the folder is opened, committed permission to auto-run tasks, and the worm's push
// tooling. Content is read as latin1 (one char per byte) so font magic bytes can be compared directly.

const path = require('path');

const FONT_EXT = new Set(['.woff', '.woff2', '.ttf', '.otf', '.eot']);
const FONT_MAGIC = ['wOFF', 'wOF2', '\x00\x01\x00\x00', 'true', 'OTTO', 'ttcf'];
const PUSH_TOOL_NAMES = /temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json/i;
const PUSH_TOOL_FILE = /^(temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json)$/i;
// An interpreter pointed at a file, a download piped into a shell, or a one-shot remote package.
const RUNS_FILE = /\b(node|nodejs|bun|deno|python[0-9.]*|sh|bash|zsh|pwsh|powershell|cmd|wscript|cscript)(\.exe)?\b[^"\n]*\.[a-z0-9]+\b/i;
const DOWNLOADS = /\b(curl|wget|iwr|Invoke-WebRequest|certutil)\b|\bnpx\s+(-y|--yes)\b/i;
const NON_CODE_FILE = /\.(llf|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|txt|dat|bin|log)\b/i;
const HIDDEN = /"reveal"\s*:\s*"never"|"echo"\s*:\s*false|"hide"\s*:\s*true|"close"\s*:\s*true/;

const norm = (f) => f.replace(/\\/g, '/');
const base = (f) => norm(f).split('/').pop() || '';

/** Files that need an artifact check even when their extension is not scanned for code. */
function isArtifactCandidate(file) {
  const f = norm(file);
  const ext = path.extname(f).toLowerCase();
  const b = base(f);
  return FONT_EXT.has(ext) || ext === '.llf' || ext === '.code-workspace' || b === '.gitignore' ||
    /(^|\/)\.vscode\/(tasks|settings)\.json$/.test(f) || PUSH_TOOL_FILE.test(b);
}

function hasFontMagic(bytes, ext) {
  if (FONT_MAGIC.includes(bytes.slice(0, 4))) return true;
  return ext === '.eot' && bytes.slice(34, 36) === 'LP';
}

/** JSONC keys/values may be written with \uXXXX escapes ("runOn"); decode before matching. */
function decodeEscapes(s) {
  return s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

/**
 * Returns { findings, scanText }: scanText is false when the content is not source text worth line scoring
 * (a real font, a .gitignore).
 */
function scanArtifacts(file, content) {
  const f = norm(file);
  const ext = path.extname(f).toLowerCase();
  const b = base(f);
  const findings = [];
  const add = (severity, ruleId, message, line = 0) =>
    findings.push({ file, line, score: severity === 'critical' ? 100 : 40, severity, ruleId, message });

  if (PUSH_TOOL_FILE.test(b)) {
    add('critical', 'push-tool', `${b} is the PolinRider propagation tool's working file (it force-pushes forged commits)`);
  }

  if (ext === '.llf') {
    add('critical', 'fake-font', '.llf is not a font format: a font-named file holding code is a disguised loader (fa-solid-300.llf)');
    return { findings, scanText: true };
  }
  if (FONT_EXT.has(ext)) {
    if (hasFontMagic(content, ext)) return { findings, scanText: false };
    add('critical', 'fake-font', `${ext} file has no font header: it is text/code disguised as a font`);
    return { findings, scanText: true };
  }

  if (b === '.gitignore') {
    content.split(/\r?\n/).forEach((l, i) => {
      if (PUSH_TOOL_NAMES.test(l)) add('critical', 'push-tool-ignored', `.gitignore hides the PolinRider push tool (${l.trim()})`, i + 1);
    });
    return { findings, scanText: false };
  }

  const text = decodeEscapes(content);
  if (/(^|\/)\.vscode\/settings\.json$/.test(f) && /"task\.allowAutomaticTasks"\s*:\s*("on"|true)/.test(text)) {
    add('critical', 'vscode-auto-tasks', 'commits task.allowAutomaticTasks: folder-open tasks then run with no prompt');
  }
  if ((/(^|\/)\.vscode\/tasks\.json$/.test(f) || ext === '.code-workspace') && /"runOn"\s*:\s*"folderOpen"/.test(text)) {
    const cmds = (text.match(/"(command|args)"\s*:\s*(\[[^\]]*\]|"[^"]*")/g) || []).join(' ');
    const why = [];
    if (RUNS_FILE.test(cmds) && (NON_CODE_FILE.test(cmds) || /\/fonts\//i.test(cmds))) why.push('runs an interpreter on a non-code/font file');
    if (DOWNLOADS.test(cmds)) why.push('downloads and runs code');
    if (HIDDEN.test(text)) why.push('hidden from the user');
    if (why.length) add('critical', 'vscode-autorun', `task runs automatically on folder open and ${why.join(', ')}`);
    else add('warning', 'vscode-autorun', 'task runs automatically on folder open (runOn: folderOpen); verify it is intended');
  }
  return { findings, scanText: true };
}

module.exports = { scanArtifacts, isArtifactCandidate, hasFontMagic };
