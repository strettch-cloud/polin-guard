#!/usr/bin/env bash
#
# inject-guard standalone scanner (no Node required).
# Detects obfuscated hidden-line code-injection payloads in source/config files.
#
# Usage:
#   ./scan-injection.sh --staged   # scan staged content (pre-commit; covers --amend)
#   ./scan-injection.sh --all      # scan all tracked files
#   ./scan-injection.sh PATH...    # scan specific files
#
# Exit 0 = clean, 1 = blocking finding, 2 = usage error.
#
# Mirrors the Node detector: near-unique signatures + oversized-line concealment
# + dense escape blobs. Lockfiles, minified output and node_modules are excluded.

set -u

MAX_LINE_LENGTH="${INJECTGUARD_MAX_LINE:-1000}"
MAX_ESCAPES="${INJECTGUARD_MAX_ESCAPES:-25}"
MODE="staged"
FILES=()

case "${1:-}" in
  --staged) MODE="staged" ;;
  --all|--ci) MODE="all" ;;
  -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  "" ) MODE="staged" ;;
  -* ) echo "inject-guard: unknown option $1" >&2; exit 2 ;;
  * ) MODE="paths"; FILES=("$@") ;;
esac

INCLUDE_RE='\.(js|cjs|mjs|jsx|ts|tsx|vue|json|bat|cmd|ps1|sh)$'
EXCLUDE_RE='(^|/)(node_modules|\.git|dist|build|out|coverage|\.next|\.nuxt|\.output|vendor|__snapshots__)/|\.min\.(js|css|mjs|cjs)$|\.map$|(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$|\.snap$'

list_files() {
  case "$MODE" in
    staged) git diff --cached --name-only --diff-filter=ACMR 2>/dev/null ;;
    all)    git ls-files 2>/dev/null ;;
    paths)  printf '%s\n' "${FILES[@]}" ;;
  esac
}

# Read the content to scan for a given file (staged blob vs working tree).
read_content() {
  f="$1"
  if [ "$MODE" = "staged" ]; then
    git show ":$f" 2>/dev/null
  else
    cat "$f" 2>/dev/null
  fi
}

FOUND=0

scan_one() {
  f="$1"
  echo "$f" | grep -Eq "$INCLUDE_RE" || return 0
  echo "$f" | grep -Eq "$EXCLUDE_RE" && return 0

  # awk does all per-line analysis in one pass.
  read_content "$f" | awk -v file="$f" -v maxlen="$MAX_LINE_LENGTH" -v maxesc="$MAX_ESCAPES" '
    {
      crit="";
      line=$0;
      if (index(line, "injectguard-allow-line") > 0) next;
      if (prev_allow == 1) { prev_allow=0; next; }
      prev_allow = (index(line, "injectguard-allow-next-line") > 0) ? 1 : 0;
      if (prev_allow == 1) next;

      # near-unique signatures
      if (line ~ /global[ \t]*\[[ \t]*['"'"'"`]![ \t]*['"'"'"`]?\]/ || line ~ /global\[.?!.?\]/) crit=crit "global-bang ";
      if (line ~ /global[ \t]*\[[ \t]*_\$_/) crit=crit "global-underscore ";
      if (line ~ /\][ \t]*=[ \t]*require[ \t]*;/ && line ~ /typeof[ \t]+module/) crit=crit "require-reexposed ";
      if (line ~ /String\.fromCharCode\([ \t]*127[ \t]*\)/) crit=crit "fromCharCode127 ";

      # dense escape blob
      tmp=line; n=gsub(/\\x[0-9a-fA-F][0-9a-fA-F]|\\u[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]/, "", tmp);
      if (n >= maxesc) crit=crit "escape-density(" n ") ";

      # immediately-invoked Function ctor on a long line
      if (length(line) > 200 && line ~ /Function[ \t]*\([^)]*\)[ \t]*\(/) crit=crit "iife-ctor ";

      # oversized line, critical if it also has exec/require tokens
      if (length(line) > maxlen) {
        if (line ~ /require|eval|atob|child_process|Function|process\.env|global[ \t]*\[|String\.fromCharCode/)
          crit=crit "oversized-exec(" length(line) ") ";
        else
          crit=crit "oversized(" length(line) ") ";
      }

      if (crit != "") {
        printf("  CRITICAL %s:%d  [%s]\n", file, NR, crit);
        hits++;
      }
    }
    END { exit (hits>0 ? 3 : 0) }
  '
  if [ "${PIPESTATUS[1]:-0}" -eq 3 ] || [ "$?" -eq 3 ]; then FOUND=1; fi
}

HEADER_PRINTED=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  out="$(scan_one "$f")"
  if [ -n "$out" ]; then
    if [ "$HEADER_PRINTED" -eq 0 ]; then
      echo "" >&2
      echo "X inject-guard: potential code injection detected" >&2
      echo "" >&2
      HEADER_PRINTED=1
    fi
    echo "$out" >&2
    FOUND=1
  fi
done < <(list_files)

if [ "$FOUND" -eq 1 ]; then
  echo "" >&2
  echo "Commit blocked. Investigate the file(s) above before committing." >&2
  echo "Acknowledge a verified false positive with an 'injectguard-allow-line' comment." >&2
  exit 1
fi

echo "v inject-guard: no injection indicators found"
exit 0
