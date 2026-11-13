#!/bin/sh
# Signs dist/manifest.json with the Ed25519 private key (Ed25519 signs the raw bytes).
# Key source: $BASTION_SIGNING_KEY (PEM text, set as a GitHub secret) or ~/.bastion/definitions-signing.pem.
set -eu
cd "$(dirname "$0")"
KEYFILE=$(mktemp)
trap 'rm -f "$KEYFILE"' EXIT
if [ -n "${BASTION_SIGNING_KEY:-}" ]; then
  printf '%s\n' "$BASTION_SIGNING_KEY" > "$KEYFILE"
else
  cp "$HOME/.bastion/definitions-signing.pem" "$KEYFILE"
fi
openssl pkeyutl -sign -inkey "$KEYFILE" -rawin -in dist/manifest.json -out dist/manifest.sig
# Self-check before publishing.
openssl pkey -in "$KEYFILE" -pubout -out "$KEYFILE.pub"
openssl pkeyutl -verify -pubin -inkey "$KEYFILE.pub" -rawin -in dist/manifest.json -sigfile dist/manifest.sig
rm -f "$KEYFILE.pub"
