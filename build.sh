#!/usr/bin/env bash
set -euo pipefail

current="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
img="${IMG:-heaplab}"

exec env DOCKER_BUILDKIT=1 docker build -t "$img" "$current"
