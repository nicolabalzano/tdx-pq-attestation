#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"

TDX_ATTEST_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux"
TDX_QUOTE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux"
PCE_WRAPPER_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux"
TDQE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe/linux"
TDQE_SIGNED="$TDQE_LINUX_DIR/libsgx_tdqe.signed.so"
LOCAL_SGX_SDK="$TESTS_DIR/sgxsdk"
BIN_DIR="$TESTS_DIR/bin"
OUT_BIN="$BIN_DIR/test_tdx_wrapper_mldsa_e2e"
SYSTEM_PCE_DIR="/lib/x86_64-linux-gnu"
SYSTEM_URTS_DIR="/lib/x86_64-linux-gnu"
PCE_RUNTIME_LIB_DIR="$SYSTEM_PCE_DIR"
URTS_LIB_DIR="$LOCAL_SGX_SDK/lib64"

if [[ -f "$SYSTEM_URTS_DIR/libsgx_urts.so" ]]; then
  URTS_LIB_DIR="$SYSTEM_URTS_DIR"
fi

if [[ -f "$PCE_WRAPPER_LINUX_DIR/libsgx_pce.signed.so.1" || -f "$PCE_WRAPPER_LINUX_DIR/libsgx_pce.signed.so" ]]; then
  PCE_RUNTIME_LIB_DIR="$PCE_WRAPPER_LINUX_DIR"
fi

has_sgx_device() {
  [[ -e /dev/sgx_enclave || -e /dev/sgx/enclave || -e /dev/isgx ]]
}

mkdir -p "$BIN_DIR"

echo "[INFO] Building repo-local TDQE..."
make -C "$TDQE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK"

echo "[INFO] Building repo-local TDX quote wrapper..."
make -C "$TDX_QUOTE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK"

echo "[INFO] Building repo-local libtdx_attest..."
make -C "$TDX_ATTEST_LINUX_DIR"

echo "[INFO] Compiling ML-DSA wrapper end-to-end test..."
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/inc" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe" \
  -I"$LOCAL_SGX_SDK/include" \
  "$SCRIPT_DIR/test_tdx_wrapper_mldsa_e2e.cpp" \
  -L"$TDX_QUOTE_LINUX_DIR" \
  -L"$TDX_ATTEST_LINUX_DIR" \
  -L"$PCE_WRAPPER_LINUX_DIR" \
  -L"$URTS_LIB_DIR" \
  -Wl,-rpath,"$TDX_QUOTE_LINUX_DIR" \
  -Wl,-rpath,"$TDX_ATTEST_LINUX_DIR" \
  -Wl,-rpath,"$URTS_LIB_DIR" \
  -lsgx_tdx_logic -ltdx_attest -lsgx_urts -lpthread -ldl \
  -o "$OUT_BIN"

if ! has_sgx_device; then
  echo "[SKIP] No SGX enclave device found (/dev/sgx_enclave, /dev/sgx/enclave, or /dev/isgx)."
  echo "[SKIP] The public wrapper ML-DSA end-to-end test requires the SGX PCE path used by tee_att_init_quote()."
  echo "[SKIP] Repo-local TDQE/wrapper build succeeded; run this script on a machine with both TDX guest support and SGX PSW device support."
  exit 0
fi

echo "[INFO] Running ML-DSA wrapper end-to-end test..."
echo "[INFO] Using PCE runtime library directory: $PCE_RUNTIME_LIB_DIR"
TEST_TDQE_PATH="$TDQE_SIGNED" \
LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_RUNTIME_LIB_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
  "$OUT_BIN"
