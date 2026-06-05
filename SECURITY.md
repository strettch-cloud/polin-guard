# Security Policy

## Scope

polin-guard is a **defensive** static scanner. It detects obfuscated, hidden-line
code-injection payloads ("stagers") in source and config files before they are
committed. It is a high-precision early-warning tool — **not** a complete malware
scanner or a guarantee of safety. Treat a clean result as "no *known* indicators
found," and keep your other defenses (lockfile review, 2FA, least-privilege
tokens, CI scanning) in place.

## Reporting a vulnerability

If you find a way to **bypass** polin-guard's detection, or a vulnerability in
polin-guard itself, please report it privately:

- Use **GitHub Security Advisories**: open a draft advisory at
  https://github.com/Valentin-Shyaka/polin-guard/security/advisories/new
- Or email the maintainer (see the npm package author field).

Please include:
- a **minimal, inert** reproduction (describe the evasion technique — do **not**
  send a live, weaponized payload),
- the polin-guard version (`polin-guard --version`),
- expected vs. actual behavior.

We aim to acknowledge reports within a few days and to ship a fix or mitigation
promptly. Coordinated disclosure is appreciated — please give us a reasonable
window before publicizing.

## If you found injected malware in YOUR repository

polin-guard exists because this happens. If a scan flags a real payload:

1. **Do not commit, merge, or build** the affected branch.
2. Assume any secret reachable from a build/dev/CI run is **compromised** and
   rotate it: `.env` values, cloud tokens, SSH keys, npm/CI tokens.
3. Check whether CI/CD already built the affected branch — those runners and
   their secrets may be compromised too.
4. Remove the injected line(s), restore any tampered `.gitignore`, and scan every
   branch (`npx polin-guard --all` on each).
5. Identify the entry point (often a malicious dependency executed during
   install/build, or a rogue editor extension).

## Supported versions

The latest published version on npm receives fixes. Pin a version (or commit SHA)
in CI for reproducibility.
