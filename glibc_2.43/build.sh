#!/usr/bin/env bash
set -euo pipefail

current="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
img="${IMG:-heaplab-2.43}"

exec env DOCKER_BUILDKIT=1 docker build -t "$img" "$current"
