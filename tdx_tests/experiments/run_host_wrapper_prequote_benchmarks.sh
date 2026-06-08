#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
RUN_AS_USER="${SUDO_USER:-$(id -un)}"
RUN_AS_HOME="${HOME}"
if [[ -n "${SUDO_USER:-}" ]]; then
  RUN_AS_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
fi

TDX_ATTEST_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux"
TDX_QUOTE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux"
PCE_WRAPPER_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux"
QCNL_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/qcnl/linux"
QPL_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/qpl/linux"
QV_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/dcap_quoteverify/linux"
QG_BUILD_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/build/linux"
TDQE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe/linux"
ID_ENCLAVE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/id_enclave/linux"
LOCAL_SGX_SDK="$TESTS_DIR/sgxsdk"
QVL_INCLUDE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc"
QV_INCLUDE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/dcap_quoteverify/inc"
ECDSA_WRAPPER_QCNL_CONF="$TESTS_DIR/sgx_default_qcnl_wrapper_ecdsa_test.conf"
HOST_PCKID_RETRIEVAL_CSV="${TDXTEST_HOST_PCKID_RETRIEVAL_CSV:-$RUN_AS_HOME/pckid_retrieval.csv}"
HOST_PCKCERT_QEID_OVERRIDE="${TDXTEST_HOST_PCKCERT_QEID_OVERRIDE:-}"

BIN_DIR="$TESTS_DIR/bin"
RESULT_ROOT="${TDX_BENCH_RESULT_ROOT:-$TESTS_DIR/results/attestation_benchmarks}"
RAW_DIR="$RESULT_ROOT/raw"
BENCH_BIN="$BIN_DIR/attestation_benchmark"

ITERATIONS="${TDX_BENCH_ITERATIONS:-8}"
WARMUP="${TDX_BENCH_WARMUP:-1}"

SYSTEM_URTS_DIR="/lib/x86_64-linux-gnu"
URTS_LIB_DIR="$LOCAL_SGX_SDK/lib64"
URTS_LINK_LIB="-lsgx_urts"

ensure_major_link() {
  local real_path="$1"
  local major_path="$2"

  if [[ -f "$real_path" && ! -e "$major_path" ]]; then
    ln -sf "$(basename "$real_path")" "$major_path"
  fi
}

discover_host_pckcert_qeid_override() {
  local csv_path="${1:-$HOST_PCKID_RETRIEVAL_CSV}"
  local csv_line=""
  local qeid=""
  local tmp_out=""

  if [[ -n "$HOST_PCKCERT_QEID_OVERRIDE" ]]; then
    HOST_PCKCERT_QEID_OVERRIDE="${HOST_PCKCERT_QEID_OVERRIDE^^}"
    [[ "$HOST_PCKCERT_QEID_OVERRIDE" =~ ^[0-9A-F]{32}$ ]] || {
      echo "[ERROR] TDXTEST_HOST_PCKCERT_QEID_OVERRIDE must be 32 hex chars" >&2
      exit 1
    }
    return 0
  fi

  if command -v PCKIDRetrievalTool >/dev/null 2>&1; then
    echo "[INFO] Refreshing host PCK ID data to discover the PCCS lookup QEID ..."
    tmp_out="$(mktemp /tmp/tdx_host_qeid_discovery.XXXXXX.out)"
    /usr/bin/PCKIDRetrievalTool -f "$csv_path" >"$tmp_out" 2>&1 || {
      sed -n '1,120p' "$tmp_out" >&2 || true
      rm -f "$tmp_out"
      echo "[ERROR] PCKIDRetrievalTool failed while discovering the host PCCS lookup QEID" >&2
      exit 1
    }
    rm -f "$tmp_out"
  fi

  [[ -f "$csv_path" ]] || {
    echo "[ERROR] Missing host PCK ID CSV: $csv_path" >&2
    exit 1
  }

  csv_line="$(head -n 1 "$csv_path" | tr -d '\r\n')"
  qeid="$(awk -F',' 'NF >= 5 {print toupper($5)}' <<<"$csv_line")"
  [[ "$qeid" =~ ^[0-9A-F]{32}$ ]] || {
    echo "[ERROR] Unable to extract a valid QEID override from $csv_path" >&2
    exit 1
  }

  HOST_PCKCERT_QEID_OVERRIDE="$qeid"
  echo "[INFO] Using host PCCS lookup QEID override: $HOST_PCKCERT_QEID_OVERRIDE"
}

mkdir -p "$BIN_DIR" "$RAW_DIR"

if [[ -d "$LOCAL_SGX_SDK" ]]; then
  export SGX_SDK="$LOCAL_SGX_SDK"
fi

if [[ -f "$SYSTEM_URTS_DIR/libsgx_urts.so" ]]; then
  URTS_LIB_DIR="$SYSTEM_URTS_DIR"
fi

echo "[INFO] Building repo-local TDQE..."
make -C "$TDQE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE=HW
ensure_major_link \
  "$TDQE_LINUX_DIR/libsgx_tdqe.signed.so" \
  "$TDQE_LINUX_DIR/libsgx_tdqe.signed.so.1"

echo "[INFO] Building repo-local ID enclave..."
make -C "$ID_ENCLAVE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE=HW
ensure_major_link \
  "$ID_ENCLAVE_LINUX_DIR/libsgx_id_enclave.signed.so" \
  "$ID_ENCLAVE_LINUX_DIR/libsgx_id_enclave.signed.so.1"

echo "[INFO] Building repo-local PCE wrapper..."
make -C "$PCE_WRAPPER_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE=HW
ensure_major_link \
  "$PCE_WRAPPER_LINUX_DIR/libsgx_pce_logic.so" \
  "$PCE_WRAPPER_LINUX_DIR/libsgx_pce_logic.so.1"

echo "[INFO] Building repo-local TDX quote wrapper..."
make -C "$TDX_QUOTE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE=HW
ensure_major_link \
  "$TDX_QUOTE_LINUX_DIR/libsgx_tdx_logic.so" \
  "$TDX_QUOTE_LINUX_DIR/libsgx_tdx_logic.so.1"

echo "[INFO] Building repo-local libtdx_attest..."
make -C "$TDX_ATTEST_LINUX_DIR"
ensure_major_link \
  "$TDX_ATTEST_LINUX_DIR/libtdx_attest.so" \
  "$TDX_ATTEST_LINUX_DIR/libtdx_attest.so.1"

echo "[INFO] Building repo-local QCNL/QPL/QuoteVerification libraries..."
make -C "$QCNL_LINUX_DIR"
make -C "$QPL_LINUX_DIR"
make -C "$QV_LINUX_DIR"
ensure_major_link \
  "$(readlink -f "$QG_BUILD_LINUX_DIR/libdcap_quoteprov.so")" \
  "$QG_BUILD_LINUX_DIR/libdcap_quoteprov.so.1"
ensure_major_link \
  "$(readlink -f "$QG_BUILD_LINUX_DIR/libsgx_default_qcnl_wrapper.so")" \
  "$QG_BUILD_LINUX_DIR/libsgx_default_qcnl_wrapper.so.1"

discover_host_pckcert_qeid_override

echo "[INFO] Compiling attestation benchmark binary..."
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/inc" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe" \
  -I"$QVL_INCLUDE_DIR" \
  -I"$QV_INCLUDE_DIR" \
  -I"$LOCAL_SGX_SDK/include" \
  "$SCRIPT_DIR/attestation_benchmark.cpp" \
  -L"$TDX_QUOTE_LINUX_DIR" \
  -L"$TDX_ATTEST_LINUX_DIR" \
  -L"$PCE_WRAPPER_LINUX_DIR" \
  -L"$QV_LINUX_DIR" \
  -L"$QG_BUILD_LINUX_DIR" \
  -L"$URTS_LIB_DIR" \
  -Wl,-rpath,"$TDX_QUOTE_LINUX_DIR" \
  -Wl,-rpath,"$TDX_ATTEST_LINUX_DIR" \
  -Wl,-rpath,"$PCE_WRAPPER_LINUX_DIR" \
  -Wl,-rpath,"$QV_LINUX_DIR" \
  -Wl,-rpath,"$QG_BUILD_LINUX_DIR" \
  -Wl,-rpath,"$URTS_LIB_DIR" \
  -lsgx_tdx_logic -lsgx_pce_logic -ltdx_attest \
  -l:libsgx_dcap_quoteverify.so -l:libdcap_quoteprov.so -l:libsgx_default_qcnl_wrapper.so \
  "$URTS_LINK_LIB" -lpthread -ldl \
  -o "$BENCH_BIN"

run_host_wrapper_bench() {
  local alg="$1"
  local raw_json="$RAW_DIR/${alg}_wrapper.json"
  local env_args=(
    TEST_BENCH_ALG="$alg"
    TEST_BENCH_PATH_MODE="wrapper"
    TEST_BENCH_EXECUTION_CONTEXT="host_sgx_wrapper_prequote"
    TEST_BENCH_STOP_AFTER_QUOTE_SIZE="1"
    TEST_BENCH_ITERATIONS="$ITERATIONS"
    TEST_BENCH_WARMUP="$WARMUP"
    TEST_BENCH_OUTPUT_JSON="$raw_json"
    TEST_BENCH_VERIFIER_MODE="not_applicable_prequote"
    TEST_BENCH_QUOTE_TRANSPORT="local host SGX quote-wrapper prequote"
    TEST_TDQE_PATH="$TDQE_LINUX_DIR/libsgx_tdqe.signed.so.1"
  )

  if [[ "$alg" == "ecdsa" ]]; then
    env_args+=(
      QCNL_CONF_PATH="$ECDSA_WRAPPER_QCNL_CONF"
      TDX_MLDSA_PCKCERT_QEID_OVERRIDE="$HOST_PCKCERT_QEID_OVERRIDE"
    )
  fi

  echo "[INFO] Running host wrapper prequote benchmark: alg=$alg"
  env \
    "${env_args[@]}" \
    LD_LIBRARY_PATH="$QG_BUILD_LINUX_DIR:$QV_LINUX_DIR:$TDX_ATTEST_LINUX_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
      "$BENCH_BIN"
}

run_host_wrapper_bench "ecdsa"
run_host_wrapper_bench "44"
run_host_wrapper_bench "65"
run_host_wrapper_bench "87"

echo "[INFO] Host wrapper prequote raw JSONs written under: $RAW_DIR"
