#!/usr/bin/env bash
#
# Produce the checksum and SSH signature that accompany a GitHub release.
#
# The signing key is the same SSH key that signs the commits of this repo, so a
# release can be cross-checked against the "Verified" badge on its commits. The
# matching public key lives in ./allowed_signers and must be registered on
# GitHub as a *signing* key (Settings -> SSH and GPG keys -> New SSH key ->
# key type "Signing Key").
#
# Overridable:
#   PSSO_SIGN_KEY       private key to sign with (default: git config user.signingkey)
#   PSSO_SIGN_IDENTITY  identity to verify against (default: git config user.email)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

JAR="keycloak-psso.jar"
SUM="$JAR.sha256"
SIG="$SUM.sig"
NAMESPACE="file"
ALLOWED_SIGNERS="$ROOT/allowed_signers"

KEY="${PSSO_SIGN_KEY:-$(git -C "$ROOT" config user.signingkey || true)}"
KEY="${KEY:-$HOME/.ssh/id_rsa}"
KEY="${KEY%.pub}"   # ssh-keygen -Y sign wants the private key

IDENTITY="${PSSO_SIGN_IDENTITY:-$(git -C "$ROOT" config user.email || true)}"

die() { echo "error: $*" >&2; exit 1; }

[ -f "$ROOT/target/$JAR" ] || die "target/$JAR not found - run 'mvn clean install' first"
[ -f "$KEY" ] || die "signing key $KEY not found (set PSSO_SIGN_KEY)"
[ -n "$IDENTITY" ] || die "no identity (set PSSO_SIGN_IDENTITY or git config user.email)"
[ -f "$ALLOWED_SIGNERS" ] || die "allowed_signers not found at $ALLOWED_SIGNERS"

cd "$ROOT/target"
rm -f "$SUM" "$SIG"

# Sign the checksum file rather than the jar: one small signed manifest, and
# 'shasum -c' chains the signature through to the binary. Paths stay bare so
# the files verify in whatever directory a user downloads them into.
shasum -a 256 "$JAR" > "$SUM"
ssh-keygen -Y sign -f "$KEY" -n "$NAMESPACE" "$SUM" < /dev/null

# Verify what we just produced against the published key, so a key missing from
# allowed_signers fails here rather than in a user's hands.
shasum -a 256 -c "$SUM"
ssh-keygen -Y verify -f "$ALLOWED_SIGNERS" -I "$IDENTITY" \
    -n "$NAMESPACE" -s "$SIG" < "$SUM"

echo
echo "Version $(cat "$ROOT/VERSION") - upload these three files to the GitHub release:"
echo "  target/$JAR"
echo "  target/$SUM"
echo "  target/$SIG"
