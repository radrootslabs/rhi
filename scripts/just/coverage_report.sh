#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
output_dir="${repo_root}/target/coverage"
summary_path="${output_dir}/summary.json"
lcov_path="${output_dir}/lcov.info"

mkdir -p "${output_dir}"
cd "${repo_root}"

cargo +nightly llvm-cov clean --workspace
cargo +nightly llvm-cov --workspace --all-features --branch --no-report
cargo +nightly llvm-cov report --json --summary-only --output-path "${summary_path}"
cargo +nightly llvm-cov report --lcov --output-path "${lcov_path}"
cargo +nightly llvm-cov report --summary-only

echo "coverage summary: ${summary_path}"
echo "coverage lcov: ${lcov_path}"
