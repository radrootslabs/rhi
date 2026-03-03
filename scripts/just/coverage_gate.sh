#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
summary_path="${repo_root}/target/coverage/summary.json"
lcov_path="${repo_root}/target/coverage/lcov.info"
thresholds_path="${repo_root}/contract/coverage/thresholds.toml"

"${script_dir}/coverage_report.sh"

python3 "${repo_root}/scripts/ci/verify_coverage.py" \
    --thresholds "${thresholds_path}" \
    --summary "${summary_path}" \
    --lcov "${lcov_path}"
