#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
linux_target_dir="${GALEIKAN_LINUX_TARGET_DIR:-${CARGO_TARGET_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/galeikan-script-target}}"
cd "$project_root"
CARGO_TARGET_DIR="$linux_target_dir" cargo test --quiet
GALEIKAN_TEST_BINARY="$linux_target_dir/debug/galeikan" \
  PYTHONPATH="$project_root/python" python3 -m unittest discover -s python/tests -q
