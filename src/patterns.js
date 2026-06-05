'use strict';

/**
 * Detection rules for polin-guard.
 *
 * These target the family of obfuscated build/commit-time JavaScript "stagers"
 * that hide a payload on a single, heavily space-padded line inside an otherwise
 * legitimate config or entry file (e.g. tailwind.config.js, ecosystem.config.js,
 * .eslintrc.js, postcss.config.js, src/index.ts). The payload typically:
 *   - decodes strings at runtime via a character-shuffle cipher,
 *   - re-exposes Node's `require`/`module` as globals, and
 *   - runs a second stage through a Function() constructor.
 *
 * The goal is HIGH precision: a "critical" finding should almost never be a
 * false positive, so it is safe to BLOCK a commit on it.
 */

// Default thresholds (override via .polinguardrc.json).
const DEFAULTS = {
  maxLineLength: 1000, // a single source line longer than this is suspicious
  maxEscapes: 25, // count of \xNN / \uNNNN escapes on one line => obfuscated blob
  // Files / directories that legitimately contain long or generated lines.
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
  // Only these extensions are scanned. Covers JS/TS, Vue, configs, and the
  // Windows batch / shell droppers seen alongside the JS stager.
  includeExtensions: [
    '.js', '.cjs', '.mjs', '.jsx', '.ts', '.tsx', '.vue',
    '.json', '.bat', '.cmd', '.ps1', '.sh',
  ],
};

// Near-unique signatures of the known stager. Each match is CRITICAL on its own.
const SIGNATURES = [
  {
    id: 'global-bang-key',
    re: /global\s*\[\s*['"`]!['"`]\s*\]/,
    message: "Assigns to global['!'] — a known obfuscated-stager marker.",
  },
  {
    id: 'global-underscore-handle',
    re: /global\s*\[\s*_\$_/,
    message: 'Assigns to global[_$_…] — obfuscated stager variable handle.',
  },
  {
    id: 'require-reexposed',
    re: /\]\s*=\s*require\s*;[\s\S]{0,60}typeof\s+module/,
    message: 'Re-exposes require()/module as globals — capability-escalation pattern.',
  },
  {
    id: 'char-shuffle-cipher',
    // String.fromCharCode(127) used as a sentinel/delimiter in the shuffle cipher.
    // Legitimate uses are virtually always inside excluded node_modules (e.g. websocket).
    re: /String\.fromCharCode\(\s*127\s*\)/,
    message: 'Uses fromCharCode(127) cipher delimiter — stager string-decoder pattern.',
  },
];

// Immediately-invoked Function() / this[...] constructor: a second-stage exec sink.
const IIFE_CONSTRUCTOR =
  /(?:\bFunction\b|this\s*\[[^\]]+\]|global\s*\[[^\]]+\])\s*\([^)]*\)\s*\(/;

// Tokens that turn an over-long line from "suspicious" into "critical".
const EXEC_TOKENS =
  /\b(require|eval|atob|unescape|child_process|execSync|spawnSync|Function)\b|process\s*\.\s*env|global\s*\[|String\.fromCharCode/;

// Standalone weaker indicators (reported as warnings, never block on their own).
const SOFT_INDICATORS = [
  { id: 'eval-call', re: /\beval\s*\(/, message: 'Contains eval().' },
  { id: 'atob-call', re: /\batob\s*\(/, message: 'Contains atob() (base64 decode).' },
  {
    id: 'child-process-in-config',
    re: /require\(\s*['"`]child_process['"`]\s*\)/,
    message: "Loads child_process.",
  },
];

module.exports = {
  DEFAULTS,
  SIGNATURES,
  IIFE_CONSTRUCTOR,
  EXEC_TOKENS,
  SOFT_INDICATORS,
};
