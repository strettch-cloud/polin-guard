'use strict';

/**
 * Detection model for polin-guard (v0.2).
 *
 * v0.1 was signature-only and therefore evadable. v0.2 detects the *necessary
 * conditions* of the attack class and combines independent signals into a
 * weighted RISK SCORE. To stay hidden yet execute at build time, the payload is
 * forced to do several things at once — and each is a detector here:
 *
 *   - HIDE visually        -> concealment (code after a long whitespace gap),
 *                             long unbroken tokens, dense escapes, high entropy
 *   - EXECUTE implicitly   -> dynamic exec sinks (Function/eval/indirect require/
 *                             constructor.constructor/vm/string-timer) in
 *                             auto-loaded config/entry files
 *   - OBFUSCATE            -> entropy / escape / long-token signals (token-agnostic)
 *   - REACH SECRETS        -> env/fs/child_process + network capability
 *
 * Defeating one detector by renaming/splitting/runtime-fetching still trips the
 * others, so evasion becomes self-defeating (visible, inert, readable, or
 * capability-less). The known-family signatures remain as fast, high-weight hits.
 */

const DEFAULTS = {
  // Scoring thresholds.
  criticalScore: 70, // >= this blocks the commit
  warningScore: 35, // >= this is reported (non-blocking unless --strict)

  // Detector thresholds.
  maxLineLength: 1000, // oversized source line
  maxEscapes: 25, // \xNN / \uNNNN escapes on one line => obfuscated blob
  maxTokenLength: 120, // unbroken non-whitespace run => encoded blob
  minGapWhitespace: 80, // code hidden after this many mid-line spaces/tabs
  entropyMinLen: 200, // only entropy-score lines at least this long
  entropyThreshold: 4.3, // bits/char; obfuscated/encoded content runs high
  fileEscapeTotal: 100, // total escapes across a file (catches split payloads)

  excludeDirs: [
    'node_modules', '.git', 'dist', 'build', 'out', 'coverage',
    '.next', '.nuxt', '.output', '.turbo', '.cache', 'vendor', '__snapshots__',
  ],
  excludeFilePatterns: [
    /\.min\.(js|css|mjs|cjs)$/i,
    /\.map$/i,
    /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/i,
    /\.snap$/i,
  ],
  includeExtensions: [
    '.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx', '.vue',
    '.json', '.bat', '.cmd', '.ps1', '.sh',
  ],
};

// Per-signal weights (points added to a line's / file's risk score).
const WEIGHTS = {
  signature: 60, // a known-family signature
  concealment: 80, // code after a long mid-line whitespace gap (off-screen trick)
  longToken: 35, // unbroken token >= maxTokenLength
  escapeDense: 50, // >= maxEscapes on one line
  entropy: 25, // long, high-entropy line
  oversized: 25, // line longer than maxLineLength
  oversizedExecBonus: 30, // ...and it also carries exec/require tokens
  execSink: 40, // Function()/eval dynamic execution
  indirectRequire: 25, // require(<non-literal>)
  ctorChain: 35, // constructor.constructor / ['constructor']
  dynTimer: 25, // setTimeout/Interval("string")
  vmModule: 25, // require('vm')
  network: 15, // fetch / http(s)/net/dns/tls
  capability: 10, // process.env / fs / child_process
  netExecCombo: 30, // network + exec/file-write on the same line
  autoloadBonus: 20, // exec/capability/network inside an auto-loaded file
};

// Known-family signatures (fast, high-confidence). Each adds WEIGHTS.signature.
const SIGNATURES = [
  { id: 'global-bang-key', re: /global\s*\[\s*['"`]!['"`]\s*\]/, message: "global['!'] stager marker" },
  { id: 'global-underscore-handle', re: /global\s*\[\s*_\$_/, message: 'global[_$_…] obfuscated handle' },
  { id: 'require-reexposed', re: /\]\s*=\s*require\s*;[\s\S]{0,60}typeof\s+module/, message: 'require/module re-exposed as globals' },
  { id: 'char-shuffle-cipher', re: /String\.fromCharCode\(\s*127\s*\)/, message: 'fromCharCode(127) cipher delimiter' },
];

// Behavioral / structural regexes (token-agnostic where possible).
const RE = {
  execSink: /\b(?:new\s+)?Function\s*\(|\beval\s*\(/,
  indirectRequire: /\brequire\s*\(\s*(?!['"`)])/, // require( not immediately a string
  ctorChain: /\bconstructor\b\s*(?:\.\s*constructor|\[\s*['"`]\s*constructor)|\[\s*['"`]constructor['"`]\s*\]/,
  dynTimer: /\bset(?:Timeout|Interval)\s*\(\s*['"`]/,
  vmModule: /\brequire\s*\(\s*['"`]vm['"`]\s*\)/,
  network: /\bfetch\s*\(|\bXMLHttpRequest\b|require\s*\(\s*['"`](?:https?|net|dns|tls|dgram)['"`]\s*\)|\bhttps?\s*\.\s*(?:get|request)\b/,
  capability: /\bprocess\s*\.\s*env\b|require\s*\(\s*['"`](?:fs|os|child_process)['"`]\s*\)|\bchild_process\b/,
  fsWrite: /\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream)\b/,
  childProc: /\bchild_process\b|\b(?:execSync|spawnSync|spawn|fork)\s*\(|\bexec\s*\(/,
  // tokens that upgrade an oversized line to critical
  execTokens: /\b(?:require|eval|atob|unescape|child_process|Function)\b|process\s*\.\s*env|global\s*\[|String\.fromCharCode/,
};

module.exports = { DEFAULTS, WEIGHTS, SIGNATURES, RE };
