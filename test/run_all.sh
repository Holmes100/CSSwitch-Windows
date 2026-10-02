#!/bin/bash
# Compatibility name only: authority remains the fixed source-gate CLI.
set -u
if [ "$#" -ne 2 ] || [ "$1" != "--output-root" ]; then
  exit 64
fi
case "$2" in
  --require-release-ready) exit 64 ;;
esac
ROOT="$(cd "$(dirname "$0")/.." && pwd)" || exit 12
cd "$ROOT" || exit 12
exec /usr/bin/python3 -I test/quality/source_gate/cli.py run \
  --output-root "$2"
