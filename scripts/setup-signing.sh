#!/usr/bin/env bash
#
# setup-signing.sh — configure git to sign EVERY commit with an SSH key held in
# the macOS Secure Enclave via Secretive (https://github.com/maxgoedjen/secretive),
# requiring Touch ID on every commit.
#
# Security goal: no session caching, no exportable key, no third-party account.
# The private key lives in the Secure Enclave and cannot leave the machine;
# each commit triggers a fresh Touch ID prompt. This defeats malware that would
# otherwise sign commits silently during a cached agent window (threat T6 in
# SECURE-PUBLISHING-DESIGN.md).
#
# Usage:
#   ./scripts/setup-signing.sh "ssh-ed25519 AAAA... your-comment"
#
# The argument is the PUBLIC key, copied from Secretive ("Copy Public Key").

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Secretive is macOS-only. On other OSes use a passphrase-protected SSH" >&2
  echo "key (kept out of ssh-agent) or a YubiKey, then set the same git config." >&2
  exit 1
fi

PUBKEY="${1:-}"
if [[ -z "$PUBKEY" ]]; then
  echo "Usage: $0 \"ssh-ed25519 AAAA... your-comment\"" >&2
  echo "Copy the public key from Secretive: select your key → Copy Public Key." >&2
  exit 1
fi

EMAIL="$(git config --get user.email || true)"
if [[ -z "$EMAIL" ]]; then
  echo "ERROR: git user.email is not set. Run:" >&2
  echo "  git config --global user.email \"you@strettch.cloud\"" >&2
  exit 1
fi

# Secretive's sandboxed SSH agent socket
SOCK="$HOME/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh"

# --- allowed-signers file (enables local 'Good signature' verification) ------
SIGNERS_DIR="$HOME/.config/git"
SIGNERS_FILE="$SIGNERS_DIR/allowed_signers"
mkdir -p "$SIGNERS_DIR"
if [[ ! -f "$SIGNERS_FILE" ]] || ! grep -qF "$PUBKEY" "$SIGNERS_FILE"; then
  printf '%s %s\n' "$EMAIL" "$PUBKEY" >> "$SIGNERS_FILE"
  echo "Added your key to $SIGNERS_FILE"
fi

# --- write the public key to a file --------------------------------------------
# git's SSH signer needs a FILE path (or a "key::" prefix); a bare literal key
# string is misread as a filename ("Couldn't load public key ...").
PUBKEY_FILE="$HOME/.ssh/polin-guard-signing.pub"
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
printf '%s\n' "$PUBKEY" > "$PUBKEY_FILE"
chmod 644 "$PUBKEY_FILE"

# --- configure git -----------------------------------------------------------
git config --global gpg.format ssh
git config --global user.signingkey "$PUBKEY_FILE"
git config --global gpg.ssh.allowedSignersFile "$SIGNERS_FILE"
git config --global commit.gpgsign true
git config --global tag.gpgsign true
# remove any stale helper from a previous (e.g. 1Password) setup so git uses
# the default ssh-keygen signer, which talks to Secretive's agent
git config --global --unset gpg.ssh.program 2>/dev/null || true

# --- agent / SSH_AUTH_SOCK checks --------------------------------------------
echo
if [[ -S "$SOCK" ]]; then
  echo "✓ Secretive agent socket found."
else
  echo "⚠ Secretive agent socket NOT found at:"
  echo "    $SOCK"
  echo "  Open Secretive and confirm the agent is running (its setup tab shows the path)."
fi

if [[ "${SSH_AUTH_SOCK:-}" != "$SOCK" ]]; then
  cat <<EOF

ACTION: point SSH at Secretive's agent. Add this line to ~/.zshrc, then restart your shell:

  export SSH_AUTH_SOCK="$SOCK"
EOF
fi

cat <<'DONE'

✓ Git is configured to sign every commit and tag via Secretive (Secure Enclave + Touch ID).

REMAINING MANUAL STEPS (cannot be scripted):

  1. In Secretive, the key MUST be created with "Authenticate before use"
     (Touch ID required on every use). Do NOT disable it — that toggle is the
     no-caching guarantee.

  2. Add the SAME public key to GitHub as a SIGNING KEY (not an auth key):
       GitHub → Settings → SSH and GPG keys → New SSH key
       → Key type: "Signing Key"  → paste the public key.

  3. Verify it works:
       git commit --allow-empty -m "test: signing"     # expect a Touch ID prompt
       git log --show-signature -1                      # expect "Good signature"
     Push to a branch and confirm the commit shows "Verified" on GitHub.
DONE
