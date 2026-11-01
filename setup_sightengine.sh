#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

printf '\nTRACEWEAVE — Sightengine setup\n'
printf 'Use credentials from your Sightengine dashboard.\n'
printf 'Security note: if a secret was shared in chat or screenshots, rotate it first.\n\n'
read -r -p 'Sightengine API User: ' API_USER
read -r -s -p 'Sightengine API Secret: ' API_SECRET
printf '\n'
if [[ -z "$API_USER" || -z "$API_SECRET" ]]; then
  echo 'Both values are required. No .env file was changed.' >&2
  exit 1
fi

umask 077
TMP_FILE="$(mktemp .env.XXXXXX)"
{
  printf 'SIGHTENGINE_API_USER=%s\n' "$API_USER"
  printf 'SIGHTENGINE_API_SECRET=%s\n' "$API_SECRET"
} > "$TMP_FILE"
mv "$TMP_FILE" .env
chmod 600 .env
unset API_USER API_SECRET
printf '\nSaved credentials to .env with restricted file permissions.\n'
printf 'They are not printed to the terminal and should not be uploaded to GitHub.\n'
