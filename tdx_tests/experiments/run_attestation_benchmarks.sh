#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"

TDX_ATTEST_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux"
TDX_QUOTE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux"
PCE_WRAPPER_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux"
QCNL_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/qcnl/linux"
QPL_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/qpl/linux"
QV_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/dcap_quoteverify/linux"
QG_BUILD_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/build/linux"
QV_BUILD_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/build/linux"
TDQE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe/linux"
ID_ENCLAVE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/id_enclave/linux"
LOCAL_SGX_SDK="$TESTS_DIR/sgxsdk"
LOCAL_PREBUILT_OPENSSL_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/prebuilt/openssl"
LOCAL_SGXSSL_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/sgxssl/Linux"
LOCAL_SGXSSL_PACKAGE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/sgxssl/Linux/package"
QVL_INCLUDE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc"
QV_INCLUDE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/dcap_quoteverify/inc"
PRIVATE_PCS_SCRIPT="$TESTS_DIR/private_pcs/local_tdx_pcs_proxy.py"
ECDSA_QCNL_CONF="$TESTS_DIR/sgx_default_qcnl_ecdsa_test.conf"

BIN_DIR="$TESTS_DIR/bin"
RESULT_ROOT="${TDX_BENCH_RESULT_ROOT:-$TESTS_DIR/results/attestation_benchmarks}"
RAW_DIR="$RESULT_ROOT/raw"
BENCH_BIN="$BIN_DIR/attestation_benchmark"
AGGREGATE_JSON="${TDX_BENCH_OUTPUT_JSON:-$TESTS_DIR/results/attestation_benchmarks.json}"
AGGREGATE_SCRIPT="$SCRIPT_DIR/aggregate_attestation_benchmarks.py"
PRIVATE_PCS_QCNL_CONF="$RESULT_ROOT/sgx_default_qcnl_private_pcs_bench.conf"
PRIVATE_PCS_IDENTITY_FILE="$RESULT_ROOT/local_tdqe_identity.json"
PRIVATE_PCS_LOG="$RESULT_ROOT/local_tdx_pcs_proxy.log"
PRIVATE_PCS_HOST="${TDXTEST_MLDSA_LOCAL_PCS_HOST:-127.0.0.1}"
PRIVATE_PCS_PORT="${TDXTEST_MLDSA_LOCAL_PCS_PORT:-18081}"
PRIVATE_PCS_UPSTREAM_ORIGIN="${TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN:-https://api.trustedservices.intel.com}"
PRIVATE_PCS_PID=""

SYSTEM_URTS_DIR="/lib/x86_64-linux-gnu"
URTS_LIB_DIR="$LOCAL_SGX_SDK/lib64"
URTS_LINK_LIB="-lsgx_urts"

ITERATIONS="${TDX_BENCH_ITERATIONS:-8}"
WARMUP="${TDX_BENCH_WARMUP:-1}"

HOST_SYSTEM_QGS_PORT="${TDXTEST_HOST_SYSTEM_QGS_PORT:-4050}"
HOST_REPO_QGS_PORT="${TDXTEST_MLDSA_HOST_REPO_QGS_PORT:-4051}"

TDX_GUEST_DEV=""
for dev in /dev/tdx_guest /dev/tdx-guest /dev/tdx*; do
  if [[ -e "$dev" ]]; then
    TDX_GUEST_DEV="$dev"
    break
  fi
done

ensure_repo_local_sgxssl_untrusted_lib() {
  local header_path="$LOCAL_SGXSSL_PACKAGE_DIR/include/openssl/opensslconf.h"
  local untrusted_lib_path="$LOCAL_SGXSSL_PACKAGE_DIR/lib64/libsgx_usgxssl.a"

  if [[ ! -f "$header_path" ]]; then
    return 1
  fi

  if [[ -f "$untrusted_lib_path" ]]; then
    return 0
  fi

  echo "[INFO] Building missing repo-local SGXSSL untrusted wrapper..."
  make -C "$LOCAL_SGXSSL_LINUX_DIR/sgx/libsgx_usgxssl" SGX_SDK="$LOCAL_SGX_SDK"

  [[ -f "$untrusted_lib_path" ]]
}

ensure_major_link() {
  local real_path="$1"
  local major_path="$2"

  if [[ -f "$real_path" && ! -e "$major_path" ]]; then
    ln -sf "$(basename "$real_path")" "$major_path"
  fi
}

configure_quote_transport_port() {
  local port="$1"
  cat >/etc/tdx-attest.conf <<EOF
port = $port
EOF
}

write_private_pcs_qcnl_conf() {
  mkdir -p "$(dirname "$PRIVATE_PCS_QCNL_CONF")"
  cat >"$PRIVATE_PCS_QCNL_CONF" <<EOF
{
  "collateral_service": "http://$PRIVATE_PCS_HOST:$PRIVATE_PCS_PORT/sgx/certification/v4/",
  "pccs_api_version": "3.1",
  "retry_times": 0,
  "verify_collateral_cache_expire_hours": 0,
  "local_cache_only": false,
  "use_secure_cert": false
}
EOF
}

start_private_pcs() {
  rm -f "$PRIVATE_PCS_LOG" "$PRIVATE_PCS_IDENTITY_FILE"
  echo "[INFO] Starting private local PCS proxy on http://$PRIVATE_PCS_HOST:$PRIVATE_PCS_PORT ..."
  python3 "$PRIVATE_PCS_SCRIPT" \
    --host "$PRIVATE_PCS_HOST" \
    --port "$PRIVATE_PCS_PORT" \
    --identity-file "$PRIVATE_PCS_IDENTITY_FILE" \
    --upstream-origin "$PRIVATE_PCS_UPSTREAM_ORIGIN" \
    >"$PRIVATE_PCS_LOG" 2>&1 &
  PRIVATE_PCS_PID=$!

  for _ in $(seq 1 30); do
    if curl -fsS "http://$PRIVATE_PCS_HOST:$PRIVATE_PCS_PORT/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "[ERROR] Private PCS proxy failed to start."
  sed -n '1,200p' "$PRIVATE_PCS_LOG" || true
  return 1
}

cleanup() {
  if [[ -n "$PRIVATE_PCS_PID" ]] && kill -0 "$PRIVATE_PCS_PID" 2>/dev/null; then
    kill "$PRIVATE_PCS_PID" 2>/dev/null || true
    wait "$PRIVATE_PCS_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT

mkdir -p "$BIN_DIR" "$RAW_DIR"

if [[ -z "$TDX_GUEST_DEV" ]]; then
  echo "[ERROR] No TDX guest device available inside the guest."
  exit 1
fi

if [[ ! -r "$TDX_GUEST_DEV" || ! -w "$TDX_GUEST_DEV" ]]; then
  echo "[ERROR] Insufficient permissions on $TDX_GUEST_DEV"
  exit 1
fi

if [[ -d "$LOCAL_SGX_SDK" ]]; then
  export SGX_SDK="$LOCAL_SGX_SDK"
fi

if [[ -f "$SYSTEM_URTS_DIR/libsgx_urts.so" ]]; then
  URTS_LIB_DIR="$SYSTEM_URTS_DIR"
fi

if [[ ! -d "$LOCAL_PREBUILT_OPENSSL_DIR/inc" || ! -d "$LOCAL_PREBUILT_OPENSSL_DIR/lib/linux64" ]]; then
  echo "[INFO] Preparing repo-local OpenSSL compatibility paths for DCAP builds..."
  mkdir -p "$LOCAL_PREBUILT_OPENSSL_DIR/lib"
  ln -sfn /usr/include "$LOCAL_PREBUILT_OPENSSL_DIR/inc"
  ln -sfn /usr/lib/x86_64-linux-gnu "$LOCAL_PREBUILT_OPENSSL_DIR/lib/linux64"
fi

if ! ensure_repo_local_sgxssl_untrusted_lib; then
  echo "[ERROR] Missing repo-local SGXSSL package required by DCAP quote verification."
  exit 1
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
  -L"$URTS_LIB_DIR" \
  -L"$QV_BUILD_LINUX_DIR" \
  -L"$QG_BUILD_LINUX_DIR" \
  -Wl,-rpath,"$TDX_QUOTE_LINUX_DIR" \
  -Wl,-rpath,"$TDX_ATTEST_LINUX_DIR" \
  -Wl,-rpath,"$PCE_WRAPPER_LINUX_DIR" \
  -Wl,-rpath,"$URTS_LIB_DIR" \
  -Wl,-rpath,"$QV_BUILD_LINUX_DIR" \
  -Wl,-rpath,"$QG_BUILD_LINUX_DIR" \
  -lsgx_tdx_logic -lsgx_pce_logic -ltdx_attest \
  -l:libsgx_dcap_quoteverify.so -l:libdcap_quoteprov.so -l:libsgx_default_qcnl_wrapper.so \
  "$URTS_LINK_LIB" -lpthread -ldl \
  -o "$BENCH_BIN"

write_private_pcs_qcnl_conf
start_private_pcs

RAW_FILES=()

scenario_has_success() {
  local path="$1"
  python3 - "$path" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as f:
    payload = json.load(f)
samples = [s for s in payload["samples"] if not s["warmup"]]
print("1" if any(s["success"] for s in samples) else "0")
PY
}

run_direct_bench() {
  local alg="$1"
  local verifier_mode="$2"
  local qcnl_conf="$3"
  local transport_port="$4"
  local transport_label="$5"
  local raw_json="$RAW_DIR/${alg}_direct.json"
  local local_identity_env=()

  configure_quote_transport_port "$transport_port"
  RAW_FILES+=("$raw_json")

  if [[ "$alg" != "ecdsa" ]]; then
    local_identity_env=(
      TDX_MLDSA_ALLOW_LOCAL_TDQE_IDENTITY=1
      TEST_LOCAL_TDQE_IDENTITY_FILE="$PRIVATE_PCS_IDENTITY_FILE"
    )
  fi

  echo "[INFO] Running benchmark: alg=$alg path=direct verifier=$verifier_mode transport=$transport_label"
  env \
    QCNL_CONF_PATH="$qcnl_conf" \
    TEST_BENCH_ALG="$alg" \
    TEST_BENCH_PATH_MODE="direct" \
    TEST_BENCH_EXECUTION_CONTEXT="guest_tdx_direct_full" \
    TEST_BENCH_ITERATIONS="$ITERATIONS" \
    TEST_BENCH_WARMUP="$WARMUP" \
    TEST_BENCH_OUTPUT_JSON="$raw_json" \
    TEST_BENCH_VERIFIER_MODE="$verifier_mode" \
    TEST_BENCH_QUOTE_TRANSPORT="$transport_label" \
    LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR:$QV_BUILD_LINUX_DIR:$QG_BUILD_LINUX_DIR:${LD_LIBRARY_PATH:-}" \
    "${local_identity_env[@]}" \
      "$BENCH_BIN"
}

run_direct_bench "ecdsa" "stock_dcap" "$ECDSA_QCNL_CONF" "$HOST_SYSTEM_QGS_PORT" "vsock:$HOST_SYSTEM_QGS_PORT -> host qgsd"
run_direct_bench "44" "local_pcs_tdqe_identity" "$PRIVATE_PCS_QCNL_CONF" "$HOST_REPO_QGS_PORT" "vsock:$HOST_REPO_QGS_PORT -> host repo-local QGS"
run_direct_bench "65" "local_pcs_tdqe_identity" "$PRIVATE_PCS_QCNL_CONF" "$HOST_REPO_QGS_PORT" "vsock:$HOST_REPO_QGS_PORT -> host repo-local QGS"
run_direct_bench "87" "local_pcs_tdqe_identity" "$PRIVATE_PCS_QCNL_CONF" "$HOST_REPO_QGS_PORT" "vsock:$HOST_REPO_QGS_PORT -> host repo-local QGS"

BENCH_ENV_SGX_MODE="HW" \
BENCH_ENV_TDX_GUEST_DEVICE="$TDX_GUEST_DEV" \
BENCH_ENV_ECDSA_PORT="$HOST_SYSTEM_QGS_PORT" \
BENCH_ENV_MLDSA_PORT="$HOST_REPO_QGS_PORT" \
BENCH_ENV_MLDSA_VERIFIER_MODE="local_pcs_tdqe_identity" \
BENCH_ENV_ECDSA_VERIFIER_MODE="stock_dcap" \
BENCH_ENV_ITERATIONS="$ITERATIONS" \
BENCH_ENV_WARMUP="$WARMUP" \
python3 "$AGGREGATE_SCRIPT" "$AGGREGATE_JSON" "${RAW_FILES[@]}"

echo "[INFO] Benchmark JSON written to: $AGGREGATE_JSON"
