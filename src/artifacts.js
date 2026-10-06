'use strict';

// Delivery and propagation artifacts that line scoring cannot see: a loader stored as a "font", a VS Code
// task that runs it when the folder is opened, committed permission to auto-run tasks, and the worm's push
// tooling. Content is read as latin1 (one char per byte) so font headers can be compared byte for byte.

const path = require('path');

// Font extensions, and the header bytes a real font starts with (EOT keeps its magic at offset 34 instead).
const FONT_MAGIC = {
  '.woff': ['wOFF'],
  '.woff2': ['wOF2'],
  '.ttf': ['\x00\x01\x00\x00', 'true', 'ttcf'],
  '.otf': ['OTTO'],
  '.eot': [],
};
const PUSH_TOOLS = ['temp_auto_push.bat', 'temp_interactive_push.bat', 'branch_structure.json'];
const PUSH_TOOL_FILE = /^(temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json)$/i;
// An interpreter pointed at a file, a download piped into a shell, or a one-shot remote package.
const RUNS_FILE = /\b(node|nodejs|bun|deno|python[0-9.]*|sh|bash|zsh|pwsh|powershell|cmd|wscript|cscript)(\.exe)?\b.*\.[a-z0-9]+\b/i;
const DOWNLOADS = /\b(curl|wget|iwr|Invoke-WebRequest|certutil)\b|\bnpx\s+(-y|--yes)\b/i;
const NON_CODE_FILE = /\.(llf|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|txt|dat|bin|log)\b/i;
// runOn values VS Code acts on without being asked; it lowercases the value before matching.
const AUTO_RUN = new Map([['folderopen', 'folder open'], ['worktreecreated', 'worktree creation']]);

// Paths are matched lowercased: on macOS/Windows a committed .VSCode/Tasks.json is what VS Code opens.
const norm = (f) => f.replace(/\\/g, '/');
const base = (f) => norm(f).split('/').pop() || '';
const lower = (v) => (typeof v === 'string' ? v.toLowerCase() : v);

/** Files that need an artifact check even when their extension is not scanned for code. */
function isArtifactCandidate(file) {
  const f = norm(file).toLowerCase();
  const ext = path.extname(f);
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

/**
 * Header fields a real font must have; a copied 4-byte magic alone does not pass. Any font format is accepted
 * under any font extension (vendors ship WOFF2 named .woff, and browsers sniff the content); the structure
 * checks are what keep text out, since none of them can be met by printable bytes.
 */
function fontHeaderOk(s) {
  const magic = s.slice(0, 4);
  // EOT: magic at 34, known version, and a total size that some writers pad by a few bytes but never undercount
  // (data appended after a real font would make the file larger than the header says).
  if (s.length > 36 && s.slice(34, 36) === 'LP') {
    const over = u32le(s, 0) - s.length;
    return over >= 0 && over <= 4 && [0x10000, 0x20001, 0x20002].includes(u32le(s, 8)) && u32le(s, 4) <= s.length;
  }
  if (!Object.values(FONT_MAGIC).some((m) => m.includes(magic))) return false;
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

/** True only for a well-formed font header on content that is actually binary. */
function isRealFont(bytes) {
  return fontHeaderOk(bytes) && looksBinary(bytes);
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

const PLATFORMS = ['windows', 'osx', 'linux'];
// Past these a crafted task file is reported for review instead of analysed, so the scan stays fast.
const MAX_TASKS = 1000;
const MAX_REFS = 5000;

const objs = (...ls) => ls.filter((l) => l && typeof l === 'object' && !Array.isArray(l));
const taskList = (scope) => (objs(scope).length && Array.isArray(scope.tasks) ? objs(...scope.tasks) : []);
const depRefs = (t) => (t.dependsOn == null ? [] : [].concat(t.dependsOn));
const labelOf = (t) => (typeof t.label === 'string' ? t.label : typeof t.taskName === 'string' ? t.taskName : undefined);
const autoTrigger = (t) => {
  const r = objs(t.runOptions).length ? t.runOptions.runOn : undefined;
  return typeof r === 'string' ? AUTO_RUN.get(r.toLowerCase()) : undefined;
};
const firstDefined = (layers, get) => {
  for (const l of layers) { const v = get(l); if (v !== undefined) return v; }
  return undefined;
};
/** A command value as text, or undefined where VS Code ignores it (null, numbers, ...). */
const commandText = (v) => (typeof v === 'string' ? v : Array.isArray(v) ? strings(v).join(' ')
  : objs(v).length && (typeof v.value === 'string' || Array.isArray(v.value)) ? strings(v.value).join(' ') : undefined);
const argsText = (layers) => firstDefined(layers, (l) => (Array.isArray(l.args) ? strings(l.args).join(' ') : undefined));
const presentationOf = (l) => objs(l.presentation || l.terminal)[0] || {};

/**
 * What a task runs on one platform and whether that is hidden, merged the way VS Code merges it: the task's
 * windows/osx/linux block over the task, then the file's (platform block over file) only to fill what the task
 * leaves unset. A task with no command takes the file's command with the file's args before its own; a
 * dependsOn-only task takes nothing. Values of the wrong type are skipped, as VS Code skips them.
 */
function taskOn(t, root, os) {
  const task = objs(t[os], t);
  const file = objs(root[os], root);
  let line = [];
  const own = firstDefined(task, (l) => commandText(l.command));
  const inherits = own === undefined && t.dependsOn == null;
  if (own !== undefined) line = [own, argsText(task)];
  else if (inherits) {
    const cmd = firstDefined(file, (l) => commandText(l.command));
    if (cmd !== undefined) line = [cmd, argsText(file), argsText(task)];
  }
  // Per layer, presentation (or legacy `terminal`) wins over legacy showOutput/echoCommand; enum values are case-insensitive.
  const layers = own !== undefined || inherits ? [...task, ...file] : task;
  const reveal = firstDefined(layers, (l) => { const p = presentationOf(l);
    return typeof p.reveal === 'string' ? p.reveal : typeof l.showOutput === 'string' ? l.showOutput : undefined; });
  const echo = firstDefined(layers, (l) => { const p = presentationOf(l);
    return typeof p.echo === 'boolean' ? p.echo : typeof l.echoCommand === 'boolean' ? l.echoCommand : undefined; });
  const close = firstDefined(layers, (l) => (typeof presentationOf(l).close === 'boolean' ? presentationOf(l).close : undefined));
  // A task runs something itself if it has a command line or is a contributed type (npm, gulp, ...).
  const runs = line.length > 0 || (typeof t.type === 'string' && !/^(shell|process)$/i.test(t.type));
  const hidden = runs && (lower(reveal) === 'never' || echo === false || close === true);
  return { cmd: line.filter(Boolean).join(' '), hidden };
}

/** The tasks VS Code loads on one platform: the top-level list, with same-named tasks replaced by the platform's list (2.0.0 flags that list as an error but still runs it). */
function tasksOn(root, os) {
  const local = taskList(root[os]);
  const names = new Set(local.map(labelOf).filter((n) => n !== undefined));
  return [...taskList(root).filter((t) => labelOf(t) === undefined || !names.has(labelOf(t))), ...local];
}

/** An object dependsOn reference ({ type, script, ... }) names every task whose fields all match it. */
function refersTo(ref, t) {
  let any = false;
  for (const k in ref) { if (t[k] !== ref[k]) return false; any = true; }
  return any;
}

/** Each distinct object reference in the file -> the tasks it names (any list), resolved once per file. */
function objectRefTargets(all) {
  const out = new Map();
  for (const t of all) {
    for (const ref of depRefs(t)) {
      const key = objs(ref).length ? JSON.stringify(ref) : null;
      if (key !== null && !out.has(key)) out.set(key, all.filter((d) => refersTo(ref, d)));
    }
  }
  return out;
}

/**
 * On one platform, every task that runs something dangerous itself or through dependsOn (VS Code runs those
 * first): Map(task -> { culprit, why }). Dangerous tasks are walked back along dependsOn edges once.
 */
function dangerousOn(root, os, objTargets) {
  const tasks = tasksOn(root, os);
  const here = new Set(tasks);
  const add = (map, k, t) => map.set(k, (map.get(k) || new Set()).add(t));
  // Dependents of a name (label or identifier), and of a task named by an object reference.
  const byName = new Map();
  const byTask = new Map();
  for (const t of tasks) {
    for (const ref of depRefs(t)) {
      if (typeof ref === 'string') add(byName, ref, t);
      else if (objs(ref).length) for (const d of objTargets.get(JSON.stringify(ref))) if (here.has(d)) add(byTask, d, t);
    }
  }
  const hit = new Map();
  const queue = [];
  for (const t of tasks) {
    const { cmd, hidden } = taskOn(t, root, os);
    const why = dangers(cmd, hidden);
    if (why.length) { hit.set(t, { culprit: t, why }); queue.push(t); }
  }
  const walked = new Set(); // names already walked back: their dependents are all marked
  for (let i = 0; i < queue.length; i++) {
    const d = queue[i];
    const names = [labelOf(d), d.identifier].filter((k) => typeof k === 'string' && !walked.has(k));
    names.forEach((k) => walked.add(k));
    for (const from of [...names.map((k) => byName.get(k)), byTask.get(d)]) {
      for (const p of from || []) if (!hit.has(p)) { hit.set(p, hit.get(d)); queue.push(p); }
    }
  }
  return { tasks, hit };
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
  const f = norm(file).toLowerCase();
  const ext = path.extname(f);
  const b = base(file);
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
    if (isRealFont(content)) return { findings, scanText: 'binary' };
    add('critical', 'fake-font', `${ext} file is not a real font (malformed header or plain text): code disguised as a font`);
    return { findings, scanText: true };
  }

  if (b.toLowerCase() === '.gitignore') {
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
    if (doc == null) {
      if (/"runOn"\s*:\s*"(?:folderOpen|worktreeCreated)"/i.test(flat)) {
        // Unparseable file: judge it as a whole rather than miss it.
        const cmds = (flat.match(/"(?:command|args)"\s*:\s*(?:\[(?:[^\]"]|"(?:[^"\\]|\\.)*")*\]|"(?:[^"\\]|\\.)*")/g) || [])
          .join(' ').replace(/\\?"/g, ' ');
        const why = dangers(cmds, /"(?:reveal|showOutput)"\s*:\s*"never"|"(?:echo|echoCommand)"\s*:\s*false|"close"\s*:\s*true/i.test(flat));
        add(why.length ? 'critical' : 'warning', 'vscode-autorun',
          `task file does not parse as JSONC and has an auto-run task${why.length ? ' that ' + why.join(', ') : ''}`);
      }
    } else if (objs(root).length) {
      const all = [root, ...PLATFORMS.map((os) => root[os])].flatMap(taskList);
      const refs = all.reduce((n, t) => n + depRefs(t).length, 0);
      if (all.length > MAX_TASKS || refs > MAX_REFS) {
        add('critical', 'vscode-autorun', `task file has ${all.length} tasks and ${refs} dependsOn references, more than ` +
          `polin-guard analyses (${MAX_TASKS} / ${MAX_REFS}); review it by hand`);
      } else {
        // Judge every unattended task on each platform, with what it depends on; report each task once.
        const results = new Map();
        const objTargets = objectRefTargets(all);
        for (const os of PLATFORMS) {
          const { tasks, hit } = dangerousOn(root, os, objTargets);
          for (const t of tasks) {
            const trigger = autoTrigger(t);
            if (!trigger) continue;
            if (!results.has(t)) results.set(t, { trigger, hits: [] });
            if (hit.has(t)) results.get(t).hits.push({ os, ...hit.get(t) });
          }
        }
        for (const [t, { trigger, hits }] of results) {
          const label = labelOf(t) || (typeof t.script === 'string' ? t.script : '(unnamed)');
          if (!hits.length) {
            add('warning', 'vscode-autorun', `task "${label}" runs automatically on ${trigger}; verify it is intended`);
            continue;
          }
          const { culprit, why } = hits[0];
          const via = culprit === t ? '' : `, through dependsOn task "${labelOf(culprit) || '(unnamed)'}",`;
          const where = hits.length === PLATFORMS.length ? '' : ` (on ${hits.map((h) => h.os).join(', ')})`;
          add('critical', 'vscode-autorun', `task "${label}" runs automatically on ${trigger} and${via} ${why.join(', ')}${where}`);
        }
      }
    }
  }
  return { findings, scanText: true };
}

module.exports = { scanArtifacts, isArtifactCandidate, isRealFont, stripJsonc, ignoredTools };
