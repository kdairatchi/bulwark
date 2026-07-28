#!/usr/bin/env bash
# Encode an Android upload keystore for the BULWARK_TV_KEYSTORE_BASE64 secret.
# Usage: ./apps/android-tv/scripts/encode-keystore.sh path/to/upload.jks
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <keystore.jks|keystore.keystore>" >&2
  exit 1
fi

KS="$1"
if [[ ! -f "$KS" ]]; then
  echo "File not found: $KS" >&2
  exit 1
fi

if base64 --help 2>&1 | grep -q -- '-w'; then
  ENCODED="$(base64 -w0 "$KS")"
else
  ENCODED="$(base64 "$KS" | tr -d '\n')"
fi

echo "Paste this into GitHub Actions secret BULWARK_TV_KEYSTORE_BASE64:"
echo
echo "$ENCODED"
echo
echo "(${#ENCODED} chars; source file: $KS)"
