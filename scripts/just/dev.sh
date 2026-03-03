#!/usr/bin/env bash
set -euo pipefail

log_dir="${1:?missing log dir}"

RADROOTS_LOG_DIR="${log_dir}" cargo run -- --config config.dev.toml --identity identity.json --allow-generate-identity
