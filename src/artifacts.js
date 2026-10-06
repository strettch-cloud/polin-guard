'use strict';

// Delivery and propagation artifacts that line scoring cannot see: a loader stored as a "font", a VS Code
// task that runs it when the folder is opened, committed permission to auto-run tasks, and the worm's push
// tooling. Content is read as latin1 (one char per byte) so font headers can be compared byte for byte.

const path = require('path');

// Header bytes a real font of each type starts with (EOT keeps its magic at offset 34 instead).
const FONT_MAGIC = {
  '.woff': ['wOFF'],
  '.woff2': ['wOF2'],
  '.ttf': ['\x00\x01\x00\x00', 'true', 'ttcf'],
  '.otf': ['OTTO', '\x00\x01\x00\x00', 'ttcf'],
  '.eot': [],
};
const PUSH_TOOLS = ['temp_auto_push.bat', 'temp_interactive_push.bat', 'branch_structure.json'];
const PUSH_TOOL_FILE = /^(temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json)$/i;
// An interpreter pointed at a file, a download piped into a shell, or a one-shot remote package.
const RUNS_FILE = /\b(node|nodejs|bun|deno|python[0-9.]*|sh|bash|zsh|pwsh|powershell|cmd|wscript|cscript)(\.exe)?\b.*\.[a-z0-9]+\b/i;
const DOWNLOADS = /\b(curl|wget|iwr|Invoke-WebRequest|certutil)\b|\bnpx\s+(-y|--yes)\b/i;
const NON_CODE_FILE = /\.(llf|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|txt|dat|bin|log)\b/i;

const norm = (f) => f.replace(/\\/g, '/');
const base = (f) => norm(f).split('/').pop() || '';

/** Files that need an artifact check even when their extension is not scanned for code. */
function isArtifactCandidate(file) {
  const f = norm(file);
  const ext = path.extname(f).toLowerCase();
  const b = base(f);
  return ext in FONT_MAGIC || ext === '.llf' || ext === '.code-workspace' || b === '.gitignore' ||
    /(^|\/)\.vscode\/(tasks|settings)\.json$/.test(f) || PUSH_TOOL_FILE.test(b);
}

/** Real fonts are binary; a loader can copy a valid header and still be plain text after it. */
function looksBinary(bytes) {
  const s = bytes.slice(0, 4096);
  if (!s.length) return false;
  let odd = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 9 || (c > 13 && c < 32) || c > 126) odd++;
  }
  return odd / s.length >= 0.1;
}

const u16 = (s, o) => (s.charCodeAt(o) << 8) + s.charCodeAt(o + 1);
const u32 = (s, o) => s.charCodeAt(o) * 0x1000000 + (s.charCodeAt(o + 1) << 16) + (s.charCodeAt(o + 2) << 8) + s.charCodeAt(o + 3);
const u32le = (s, o) => s.charCodeAt(o) + (s.charCodeAt(o + 1) << 8) + (s.charCodeAt(o + 2) << 16) + s.charCodeAt(o + 3) * 0x1000000;

/** Header fields a real font of this type must have; a copied 4-byte magic alone does not pass. */
function fontHeaderOk(s, ext) {
  const magic = s.slice(0, 4);
  if (ext === '.eot') return s.length > 36 && s.slice(34, 36) === 'LP' && u32le(s, 0) === s.length;
  if (!(FONT_MAGIC[ext] || []).includes(magic)) return false;
  if (magic === 'wOFF' || magic === 'wOF2') {
    // total length == file size, at least one table, reserved field zero
    return s.length >= 48 && u32(s, 8) === s.length && u16(s, 12) > 0 && u16(s, 14) === 0;
  }
  if (magic === 'ttcf') return s.length >= 16 && [0x10000, 0x20000].includes(u32(s, 4)) && u32(s, 8) > 0 && u32(s, 8) < 256;
  // sfnt: searchRange is fixed by numTables, and the table directory must fit in the file
  const n = u16(s, 4);
  if (n < 1 || n > 200 || s.length < 12 + 16 * n) return false;
  return u16(s, 6) === 16 * 2 ** Math.floor(Math.log2(n));
}

/** True only for a well-formed header of this extension's own type, on content that is actually binary. */
function isRealFont(bytes, ext) {
  return fontHeaderOk(bytes, ext) && looksBinary(bytes);
}

/** JSONC (comments, trailing commas, BOM) to JSON; strings are copied untouched. */
function stripJsonc(s) {
  let out = '';
  let inStr = false;
  let comma = -1; // index in `out` of a comma followed so far only by whitespace/comments
  const start = s.charCodeAt(0) === 0xfeff ? 1 : s.startsWith('\xef\xbb\xbf') ? 3 : 0; // BOM, decoded or as latin1
  for (let i = start; i < s.length; i++) {
    const c = s[i];
    if (inStr) {
      out += c;
      if (c === '\\') out += s[++i] || '';
      else if (c === '"') inStr = false;
      continue;
    }
    if (c === '/' && s[i + 1] === '/') {
      while (i < s.length && s[i] !== '\n') i++;
      out += '\n';
    } else if (c === '/' && s[i + 1] === '*') {
      const end = s.indexOf('*/', i + 2);
      i = end < 0 ? s.length : end + 1;
      out += ' ';
    } else if ((c === '}' || c === ']') && comma >= 0) {
      out = out.slice(0, comma) + out.slice(comma + 1) + c; // trailing comma: dropped
      comma = -1;
    } else {
      if (c === ',') comma = out.length;
      else if (!/\s/.test(c)) comma = -1;
      if (c === '"') inStr = true;
      out += c;
    }
  }
  return out;
}
function parseJsonc(s) {
  try { return JSON.parse(stripJsonc(s)); } catch { return null; }
}

/** Every string under a command/args value, including { value } objects. */
const strings = (v) => (v == null ? [] : Array.isArray(v) ? v.flatMap(strings)
  : typeof v === 'object' ? strings(v.value) : [String(v)]);

/**
 * The command line and visibility VS Code would use on each OS: windows/osx/linux properties override the
 * task's own, which override the file's top-level ones. Each variant is judged on its own.
 */
function taskVariants(t, top) {
  const out = [];
  for (const os of [null, 'windows', 'osx', 'linux']) {
    const o = os ? t[os] : null;
    if (os && (!o || typeof o !== 'object')) continue;
    const pick = (k) => (o && o[k] !== undefined ? o[k] : t[k] !== undefined ? t[k] : top[k]);
    const cmd = [...strings(pick('command')), ...strings(pick('args'))].join(' ');
    const p = { ...(top.presentation || {}), ...(t.presentation || {}), ...((o && o.presentation) || {}) };
    const hidden = p.reveal === 'never' || p.echo === false || p.close === true || pick('hide') === true;
    out.push({ os: os || 'all', cmd, hidden });
  }
  return out;
}

/** Reasons a folder-open command line is dangerous (empty = an ordinary auto-start task). */
function dangers(cmd, hidden) {
  const why = [];
  if (RUNS_FILE.test(cmd) && (NON_CODE_FILE.test(cmd) || /(^|[\s/\\])fonts[/\\]/i.test(cmd))) why.push('runs an interpreter on a non-code/font file');
  if (DOWNLOADS.test(cmd)) why.push('downloads and runs code');
  if (hidden) why.push('hidden from the user');
  return why;
}

/** gitignore glob for one path segment -> RegExp; the literal part must be long enough to name a tool. */
function ignoreSegmentRe(seg) {
  const literal = seg.replace(/\\(.)/g, '$1').replace(/[*?]|\[[^\]]*\]/g, '');
  if (literal.length < 6) return null; // "*.bat", "*.json", "*" hide far more than the push tool
  let re = '';
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    if (c === '\\') re += (seg[i + 1] || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), i++;
    else if (c === '*') re += '[^/]*';
    else if (c === '?') re += '[^/]';
    else if (c === '[') { const end = seg.indexOf(']', i + 1); if (end < 0) { re += '\\['; continue; } re += '[' + seg.slice(i + 1, end).replace(/^!/, '^') + ']'; i = end; }
    else re += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + re + '$', 'i');
}
function ignoredTools(line) {
  let l = line.replace(/\r$/, '').replace(/(^|[^\\])\s+$/, '$1');
  if (!l || l.startsWith('#') || l.startsWith('!') || l.endsWith('/')) return [];
  if (l.startsWith('\\')) l = l.slice(1);
  const seg = (l.split('/').filter(Boolean).pop() || '').replace(/\*\*/g, '*');
  const re = seg ? ignoreSegmentRe(seg) : null;
  return re ? PUSH_TOOLS.filter((t) => re.test(t)) : [];
}

/**
 * Returns { findings, scanText }: true = line-score as source, 'binary' = a real font, scored with the signals
 * that random binary cannot trip, false = nothing to score (a .gitignore).
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
  if (ext in FONT_MAGIC) {
    // A real font is still scanned, with the binary-safe signals only: a header can be forged inside a comment.
    if (isRealFont(content, ext)) return { findings, scanText: 'binary' };
    add('critical', 'fake-font', `${ext} file is not a real ${ext.slice(1)} font (wrong header or plain text): code disguised as a font`);
    return { findings, scanText: true };
  }

  if (b === '.gitignore') {
    content.split('\n').forEach((l, i) => {
      const hit = ignoredTools(l);
      if (hit.length) add('critical', 'push-tool-ignored', `.gitignore hides the PolinRider push tool (${l.trim()} matches ${hit.join(', ')})`, i + 1);
    });
    return { findings, scanText: false };
  }

  const isSettings = /(^|\/)\.vscode\/settings\.json$/.test(f);
  const isTasks = /(^|\/)\.vscode\/tasks\.json$/.test(f) || ext === '.code-workspace';
  if (!isSettings && !isTasks) return { findings, scanText: true };

  const doc = parseJsonc(content);
  const flat = stripJsonc(content).replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

  if (isSettings) {
    const v = doc && typeof doc === 'object' ? doc['task.allowAutomaticTasks'] : undefined;
    if (v === 'on' || v === true || (doc == null && /"task\.allowAutomaticTasks"\s*:\s*("on"|true)/.test(flat))) {
      add('critical', 'vscode-auto-tasks', 'commits task.allowAutomaticTasks: folder-open tasks then run with no prompt');
    }
  }

  if (isTasks) {
    const root = doc && (ext === '.code-workspace' ? doc.tasks : doc);
    if (root && typeof root === 'object') {
      for (const t of Array.isArray(root.tasks) ? root.tasks : []) {
        if (!t || typeof t !== 'object' || !t.runOptions || t.runOptions.runOn !== 'folderOpen') continue;
        const label = t.label || t.taskName || t.script || '(unnamed)';
        const bad = taskVariants(t, root).map((v) => ({ v, why: dangers(v.cmd, v.hidden) })).filter((x) => x.why.length);
        if (bad.length) {
          const { v, why } = bad[0];
          add('critical', 'vscode-autorun', `task "${label}" runs automatically on folder open and ${why.join(', ')}` +
            (v.os === 'all' ? '' : ` (on ${v.os})`));
        } else add('warning', 'vscode-autorun', `task "${label}" runs automatically on folder open (runOn: folderOpen); verify it is intended`);
      }
    } else if (/"runOn"\s*:\s*"folderOpen"/.test(flat)) {
      // Unparseable file: judge it as a whole rather than miss it.
      const cmds = (flat.match(/"(?:command|args)"\s*:\s*(?:\[(?:[^\]"]|"(?:[^"\\]|\\.)*")*\]|"(?:[^"\\]|\\.)*")/g) || [])
        .join(' ').replace(/\\?"/g, ' ');
      const why = dangers(cmds, /"reveal"\s*:\s*"never"|"echo"\s*:\s*false|"hide"\s*:\s*true|"close"\s*:\s*true/.test(flat));
      add(why.length ? 'critical' : 'warning', 'vscode-autorun',
        `task file does not parse as JSONC and has a folder-open task${why.length ? ' that ' + why.join(', ') : ''}`);
    }
  }
  return { findings, scanText: true };
}

module.exports = { scanArtifacts, isArtifactCandidate, isRealFont, stripJsonc, ignoredTools };
