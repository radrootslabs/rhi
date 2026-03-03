#!/usr/bin/env bash
set -euo pipefail

log_dir="${1:?missing log dir}"
rm -rf "${log_dir}"/*
