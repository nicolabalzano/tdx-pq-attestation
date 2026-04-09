#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"

TDX_ATTEST_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux"
TDX_QUOTE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux"
QGS_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs"
PCE_WRAPPER_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux"
TDQE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe/linux"
LOCAL_SGX_SDK="$TESTS_DIR/sgxsdk"
BIN_DIR="$TESTS_DIR/bin"

TDQE_MLDSA_ADAPTER_BIN="$BIN_DIR/test_tdqe_mldsa_adapter"
QUOTE_HEADERS_BIN="$BIN_DIR/test_quote_headers_mldsa"
TDQE_LAYOUT_BIN="$BIN_DIR/test_tdqe_quote_layout_mldsa"
WRAPPER_ALGORITHMS_BIN="$BIN_DIR/test_tdx_wrapper_algorithms"
TDX_DIRECT_PROBE_BIN="$BIN_DIR/test_tdx_direct_mldsa_probe"
QGS_SOCKET_PATH="${QGS_SOCKET_PATH:-$BIN_DIR/qgs.socket}"
QGS_LOG_PATH="${QGS_LOG_PATH:-$BIN_DIR/qgs.log}"
DIRECT_PROBE_TIMEOUT_SECONDS="${DIRECT_PROBE_TIMEOUT_SECONDS:-20}"
QGS_NUM_THREADS="${QGS_NUM_THREADS:-1}"
QGS_PID=""

print_qgs_unavailable_hint() {
  if [[ -f "$QGS_LOG_PATH" ]] && \
     grep -Eq 'tee_att_init_quote bootstrap ret=0x1100d|Please use the correct uRTS library from PSW package\.' "$QGS_LOG_PATH"; then
    echo "[UNAVAILABLE] The forced local QGS / tee_att path is unavailable in this environment."
    echo "[UNAVAILABLE] This machine exposes TDX guest attestation, but the wrapper/QGS bootstrap still requires the SGX PCE/PSW interface."
    echo "[UNAVAILABLE] On a tdx_guest-only system, this ML-DSA direct-wrapper path cannot complete end-to-end."
  fi
}

SYSTEM_URTS_DIR="/lib/x86_64-linux-gnu"
URTS_LIB_DIR="$LOCAL_SGX_SDK/lib64"
TDX_GUEST_DEV=""
QGS_LD_LIBRARY_PATH="$QGS_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR"

if [[ -f "$SYSTEM_URTS_DIR/libsgx_urts.so" ]]; then
  URTS_LIB_DIR="$SYSTEM_URTS_DIR"
fi

for dev in /dev/tdx_guest /dev/tdx-guest /dev/tdx*; do
  if [[ -e "$dev" ]]; then
    TDX_GUEST_DEV="$dev"
    break
  fi
done

mkdir -p "$BIN_DIR"

cleanup() {
  if [[ -n "$QGS_PID" ]] && kill -0 "$QGS_PID" 2>/dev/null; then
    kill "$QGS_PID" 2>/dev/null || true
    wait "$QGS_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT

echo "[INFO] Building repo-local TDQE..."
make -C "$TDQE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK"

echo "[INFO] Building repo-local TDX quote wrapper..."
make -C "$TDX_QUOTE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK"

echo "[INFO] Building repo-local libtdx_attest..."
make -C "$TDX_ATTEST_LINUX_DIR"

echo "[INFO] Building repo-local QGS..."
make -C "$QGS_DIR" SGX_SDK="$LOCAL_SGX_SDK"

echo "[INFO] Compiling TDQE ML-DSA adapter test..."
gcc -std=c11 \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/src" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc" \
  -I"$LOCAL_SGX_SDK/include" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux" \
  "$TESTS_DIR/tdqe/test_tdqe_mldsa_adapter.c" \
  "$TESTS_DIR/tdqe/test_randombytes_stub.c" \
  "$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe/tdqe_mldsa_adapter.c" \
  "$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/mldsa_native.c" \
  -o "$TDQE_MLDSA_ADAPTER_BIN"

echo "[INFO] Compiling quote header ML-DSA layout test..."
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc" \
  -I"$LOCAL_SGX_SDK/include" \
  "$TESTS_DIR/format/test_quote_headers_mldsa.cpp" \
  -o "$QUOTE_HEADERS_BIN"

echo "[INFO] Compiling TDQE ML-DSA quote layout test..."
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe" \
  -I"$LOCAL_SGX_SDK/include" \
  "$TESTS_DIR/tdqe/test_tdqe_quote_layout_mldsa.cpp" \
  -o "$TDQE_LAYOUT_BIN"

echo "[INFO] Compiling wrapper ML-DSA algorithm-selection test..."
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/inc" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe" \
  -I"$LOCAL_SGX_SDK/include" \
  "$TESTS_DIR/wrapper/test_tdx_wrapper_algorithms.cpp" \
  -L"$TDX_QUOTE_LINUX_DIR" \
  -L"$PCE_WRAPPER_LINUX_DIR" \
  -L"$URTS_LIB_DIR" \
  -Wl,-rpath,"$TDX_QUOTE_LINUX_DIR" \
  -Wl,-rpath,"$PCE_WRAPPER_LINUX_DIR" \
  -Wl,-rpath,"$URTS_LIB_DIR" \
  -lsgx_tdx_logic -lsgx_urts -lpthread -ldl \
  -o "$WRAPPER_ALGORITHMS_BIN"

echo "[INFO] Compiling direct TDX ML-DSA capability probe..."
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc" \
  -I"$LOCAL_SGX_SDK/include" \
  "$SCRIPT_DIR/test_tdx_direct_mldsa_probe.cpp" \
  -L"$TDX_ATTEST_LINUX_DIR" \
  -Wl,-rpath,"$TDX_ATTEST_LINUX_DIR" \
  -ltdx_attest -lpthread -ldl \
  -o "$TDX_DIRECT_PROBE_BIN"

echo "[INFO] Running TDQE ML-DSA adapter test..."
"$TDQE_MLDSA_ADAPTER_BIN"

echo "[INFO] Running quote header ML-DSA layout test..."
"$QUOTE_HEADERS_BIN"

echo "[INFO] Running TDQE ML-DSA quote layout test..."
"$TDQE_LAYOUT_BIN"

echo "[INFO] Running wrapper ML-DSA algorithm-selection test..."
LD_LIBRARY_PATH="$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
  "$WRAPPER_ALGORITHMS_BIN"

if [[ -z "$TDX_GUEST_DEV" ]]; then
  echo "[SKIP] No TDX guest device found; skipping the direct TDX ML-DSA capability probe."
  exit 0
fi

if [[ ! -r "$TDX_GUEST_DEV" || ! -w "$TDX_GUEST_DEV" ]]; then
  echo "[SKIP] Insufficient permissions on $TDX_GUEST_DEV; skipping the direct TDX ML-DSA capability probe."
  echo "[SKIP] Run this script with elevated privileges to exercise the direct TDX path."
  exit 0
fi

rm -f "$QGS_SOCKET_PATH" "$QGS_LOG_PATH"

echo "[INFO] Starting repo-local QGS on $QGS_SOCKET_PATH ..."
QGS_SOCKET_PATH="$QGS_SOCKET_PATH" \
LD_LIBRARY_PATH="$QGS_LD_LIBRARY_PATH:${LD_LIBRARY_PATH:-}" \
  "$QGS_DIR/qgs" --no-daemon --debug "-n=$QGS_NUM_THREADS" >"$QGS_LOG_PATH" 2>&1 &
QGS_PID=$!
sleep 1

if ! kill -0 "$QGS_PID" 2>/dev/null; then
  echo "[ERROR] Local QGS failed to start. Log follows:"
  cat "$QGS_LOG_PATH"
  exit 1
fi

echo "[INFO] Running direct TDX ML-DSA capability probe..."
TDX_ATTEST_FORCE_LOCAL_QGS=1 \
TDX_ATTEST_LOCAL_QGS_SOCKET="$QGS_SOCKET_PATH" \
LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:${LD_LIBRARY_PATH:-}" \
  timeout "$DIRECT_PROBE_TIMEOUT_SECONDS" "$TDX_DIRECT_PROBE_BIN" || {
    probe_status=$?
    echo "[ERROR] Direct TDX ML-DSA capability probe failed with status $probe_status"
    print_qgs_unavailable_hint
    echo "[ERROR] Recent QGS log:"
    tail -n 200 "$QGS_LOG_PATH" || true
    exit "$probe_status"
  }
