#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIRECT_DIR="$(cd "$SCRIPT_DIR/../direct" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"

export TDXTEST_MLDSA_ALGS="${TDXTEST_MLDSA_ALGS:-44 65 87}"
export TDXTEST_RUN_ECDSA="${TDXTEST_RUN_ECDSA:-1}"
export TDXTEST_MLDSA_SGX_MODE="${TDXTEST_MLDSA_SGX_MODE:-HW}"
export TDXTEST_ECDSA_SGX_MODE="${TDXTEST_ECDSA_SGX_MODE:-HW}"
export TDXTEST_MLDSA_USE_HOST_REPO_QGS="${TDXTEST_MLDSA_USE_HOST_REPO_QGS:-1}"
export TDXTEST_MLDSA_REQUIRE_FULL_DCAP="${TDXTEST_MLDSA_REQUIRE_FULL_DCAP:-1}"
export TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY="${TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY:-1}"
export TDXTEST_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST="${TDXTEST_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST:-0}"
export TDXTEST_LOG_DIR="${TDXTEST_LOG_DIR:-$SCRIPT_DIR/logs}"
export TDX_BENCH_ITERATIONS="${TDX_BENCH_ITERATIONS:-8}"
export TDX_BENCH_WARMUP="${TDX_BENCH_WARMUP:-1}"
export TDX_BENCH_INCLUDE_DIRECT="${TDX_BENCH_INCLUDE_DIRECT:-0}"

BENCH_HOST_OUTPUT_JSON="${TDX_BENCH_HOST_OUTPUT_JSON:-$REPO_ROOT/tdx_tests/results/attestation_benchmarks.json}"
BENCH_LOG_PATH="${TDX_BENCH_LOG_PATH:-$TDXTEST_LOG_DIR/attestation_benchmarks.log}"
BENCH_HOST_RESULT_ROOT="${TDX_BENCH_HOST_RESULT_ROOT:-$REPO_ROOT/tdx_tests/results/attestation_benchmarks}"
BENCH_HOST_RAW_DIR="$BENCH_HOST_RESULT_ROOT/raw"
HOST_PREQUOTE_SCRIPT="$SCRIPT_DIR/run_host_wrapper_prequote_benchmarks.sh"
AGGREGATE_SCRIPT="$SCRIPT_DIR/aggregate_attestation_benchmarks.py"

source "$DIRECT_DIR/run_host_tdx_guest_repo_tests.sh"

BENCH_GUEST_SCRIPT="$GUEST_REPO_ROOT/tdx_tests/experiments/run_attestation_benchmarks.sh"
BENCH_GUEST_OUTPUT_JSON="${TDX_BENCH_GUEST_OUTPUT_JSON:-$GUEST_REPO_ROOT/tdx_tests/results/attestation_benchmarks.json}"
BENCH_GUEST_RAW_DIR="${TDX_BENCH_GUEST_RAW_DIR:-$GUEST_REPO_ROOT/tdx_tests/results/attestation_benchmarks/raw}"
BENCH_GUEST_RESULT_ROOT="$(dirname "$BENCH_GUEST_RAW_DIR")"

run_host_prequote_benchmarks() {
  info "Running host-side SGX wrapper prequote benchmarks ..."
  mkdir -p "$BENCH_HOST_RAW_DIR"
  TDX_BENCH_RESULT_ROOT="$BENCH_HOST_RESULT_ROOT" \
  TDX_BENCH_ITERATIONS="$TDX_BENCH_ITERATIONS" \
  TDX_BENCH_WARMUP="$TDX_BENCH_WARMUP" \
    "$HOST_PREQUOTE_SCRIPT"
}

copy_guest_raw_results_to_host() {
  mkdir -p "$BENCH_HOST_RAW_DIR"
  info "Copying guest raw benchmark JSONs to host: $BENCH_HOST_RAW_DIR"
  local direct_patterns=(ecdsa_direct.json 44_direct.json 65_direct.json 87_direct.json)
  local pattern

  for pattern in "${direct_patterns[@]}"; do
    sshpass -p "$GUEST_ROOT_PASSWORD" \
      scp "${SCP_OPTS[@]}" "root@$GUEST_HOST:$BENCH_GUEST_RAW_DIR/$pattern" "$BENCH_HOST_RAW_DIR/"
  done
}

aggregate_host_results() {
  local -a raw_files=()
  while IFS= read -r -d '' path; do
    raw_files+=("$path")
  done < <(find "$BENCH_HOST_RAW_DIR" -maxdepth 1 -type f -name '*.json' -print0 | sort -z)

  (( ${#raw_files[@]} != 0 )) || fail "No raw benchmark JSON files found in $BENCH_HOST_RAW_DIR"

  info "Aggregating raw benchmark JSONs into: $BENCH_HOST_OUTPUT_JSON"
  BENCH_ENV_SGX_MODE="HW" \
  BENCH_ENV_TDX_GUEST_DEVICE="/dev/tdx_guest" \
  BENCH_ENV_ECDSA_PORT="$HOST_SYSTEM_QGS_PORT" \
  BENCH_ENV_MLDSA_PORT="$HOST_REPO_QGS_PORT" \
  BENCH_ENV_MLDSA_VERIFIER_MODE="local_pcs_tdqe_identity" \
  BENCH_ENV_ECDSA_VERIFIER_MODE="stock_dcap" \
  BENCH_ENV_ITERATIONS="$TDX_BENCH_ITERATIONS" \
  BENCH_ENV_WARMUP="$TDX_BENCH_WARMUP" \
    python3 "$AGGREGATE_SCRIPT" "$BENCH_HOST_OUTPUT_JSON" "${raw_files[@]}"
}

run_guest_benchmarks() {
  local cmd
  local status=0

  mkdir -p "$TDXTEST_LOG_DIR" "$(dirname "$BENCH_HOST_OUTPUT_JSON")"

  if [[ "$TDXTEST_MLDSA_SGX_MODE" != "SIM" ]]; then
    if host_repo_qgs_requested; then
      configure_guest_quote_transport_port "$HOST_REPO_QGS_PORT"
    else
      configure_guest_quote_transport_port "$HOST_SYSTEM_QGS_PORT"
    fi
  fi

  cmd="
    cd '$GUEST_REPO_ROOT'
    rm -rf '$BENCH_GUEST_RESULT_ROOT'
    timeout '$((TDXTEST_MLDSA_TIMEOUT_SECONDS + TDXTEST_ECDSA_TIMEOUT_SECONDS + 7200))' \
      env \
        TDXTEST_HOST_SYSTEM_QGS_PORT='${HOST_SYSTEM_QGS_PORT}' \
        TDXTEST_MLDSA_HOST_REPO_QGS_PORT='${HOST_REPO_QGS_PORT}' \
        TDXTEST_MLDSA_LOCAL_PCS_PORT='${TDXTEST_MLDSA_LOCAL_PCS_PORT:-18081}' \
        TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN='${TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN:-https://api.trustedservices.intel.com}' \
        TDX_BENCH_ITERATIONS='${TDX_BENCH_ITERATIONS}' \
        TDX_BENCH_WARMUP='${TDX_BENCH_WARMUP}' \
        TDX_BENCH_INCLUDE_DIRECT='${TDX_BENCH_INCLUDE_DIRECT}' \
        TDX_BENCH_OUTPUT_JSON='${BENCH_GUEST_OUTPUT_JSON}' \
        '$BENCH_GUEST_SCRIPT'
  "

  info "Running guest-side attestation benchmarks ..."
  set +e
  ssh_guest_cmd "$cmd" 2>&1 | tee "$BENCH_LOG_PATH"
  status=${PIPESTATUS[0]}
  set -e

  if (( status != 0 )); then
    FAILURES+=("attestation_benchmarks")
    error "attestation_benchmarks failed with status $status"
    return 0
  fi

  info "attestation_benchmarks passed"
  return 0
}

main_bench() {
  need_cmd bash
  need_cmd ssh
  need_cmd tar
  need_cmd tee
  need_cmd timeout
  need_cmd python3
  ensure_sshpass
  ensure_host_tdx_ready
  ensure_host_qgsd_ready
  ensure_host_registration_ready
  populate_host_pccs_from_pckid
  ensure_guest_tools
  ensure_guest_image
  start_guest
  wait_for_guest_ssh
  ensure_guest_is_not_local_machine
  ensure_guest_tdx_device_if_required
  install_guest_dependencies
  configure_guest_quote_transport
  copy_repo_to_guest
  sanitize_guest_repo_build_artifacts
  run_host_prequote_benchmarks
  start_host_repo_qgs
  run_guest_benchmarks
  copy_guest_raw_results_to_host
  aggregate_host_results
  print_summary_and_exit
}

trap cleanup_exit EXIT
main_bench "$@"
