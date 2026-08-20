#!/usr/bin/env bash
set -euo pipefail

make -C /lab build >/dev/null 2>&1 || true

exec "$@"
