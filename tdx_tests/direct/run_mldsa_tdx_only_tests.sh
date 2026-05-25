#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"

TDX_ATTEST_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux"
TDX_QUOTE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux"
QGS_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs"
PCE_WRAPPER_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux"
QVL_INCLUDE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc"
QV_INCLUDE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/dcap_quoteverify/inc"
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
SIM_QCNL_CONF="${TDXTEST_MLDSA_SIM_QCNL_CONF:-$TESTS_DIR/sgx_default_qcnl_local_test.conf}"
HW_QCNL_CONF="${TDXTEST_MLDSA_HW_QCNL_CONF:-$TESTS_DIR/sgx_default_qcnl_ecdsa_test.conf}"
SELECTED_QCNL_CONF="$SIM_QCNL_CONF"
BIN_DIR="$TESTS_DIR/bin"
PCCS_SERVICE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/pccs/service"
MODE_STAMP_PATH="$BIN_DIR/.run_mldsa_tdx_only_tests_sgx_mode"
TDX_GUEST_DEV=""

for dev in /dev/tdx_guest /dev/tdx-guest /dev/tdx*; do
  if [[ -e "$dev" ]]; then
    TDX_GUEST_DEV="$dev"
    break
  fi
done

DEFAULT_SGX_MODE="SIM"
if [[ -n "$TDX_GUEST_DEV" ]]; then
  DEFAULT_SGX_MODE="HW"
fi

SGX_MODE_VALUE="${SGX_MODE:-$DEFAULT_SGX_MODE}"
MLDSA_FLOW_MODE="SIM"
if [[ "$SGX_MODE_VALUE" != "SIM" ]]; then
  MLDSA_FLOW_MODE="HW"
fi
if [[ "$MLDSA_FLOW_MODE" == "HW" ]]; then
  SELECTED_QCNL_CONF="$HW_QCNL_CONF"
fi
if [[ -z "${TDX_MLDSA_REQUIRE_FULL_DCAP+x}" ]]; then
  if [[ "$MLDSA_FLOW_MODE" == "HW" ]]; then
    TDX_MLDSA_REQUIRE_FULL_DCAP="1"
  else
    TDX_MLDSA_REQUIRE_FULL_DCAP="0"
  fi
fi
if [[ -z "${TDX_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST+x}" ]]; then
  if [[ "$MLDSA_FLOW_MODE" == "HW" ]]; then
    TDX_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST="1"
  else
    TDX_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST="0"
  fi
fi
TDXTEST_MLDSA_FORCE_LOCAL_QGS="${TDXTEST_MLDSA_FORCE_LOCAL_QGS:-}"
TDXTEST_MLDSA_REMOTE_QGS_LABEL="${TDXTEST_MLDSA_REMOTE_QGS_LABEL:-host qgsd}"
TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY="${TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY:-0}"
if [[ -z "${TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY+x}" ]]; then
  if [[ "$MLDSA_FLOW_MODE" == "HW" && "$TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY" != "1" ]]; then
    TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY="1"
  else
    TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY="0"
  fi
fi
if [[ "$TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY" == "1" && "$TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY" == "1" ]]; then
  echo "[ERROR] TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY=1 conflicts with TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY=1."
  echo "[ERROR] Disable one of them: local PCS is a private trust-domain path, not stock Intel DCAP."
  exit 1
fi
USE_LOCAL_QGS="0"
if [[ "$MLDSA_FLOW_MODE" == "SIM" ]]; then
  USE_LOCAL_QGS="1"
fi
if [[ -n "$TDXTEST_MLDSA_FORCE_LOCAL_QGS" ]]; then
  if [[ "$TDXTEST_MLDSA_FORCE_LOCAL_QGS" == "1" ]]; then
    USE_LOCAL_QGS="1"
  else
    USE_LOCAL_QGS="0"
  fi
fi

TDQE_MLDSA_ADAPTER_BIN="$BIN_DIR/test_tdqe_mldsa_adapter"
QUOTE_HEADERS_BIN="$BIN_DIR/test_quote_headers_mldsa"
TDQE_LAYOUT_BIN="$BIN_DIR/test_tdqe_quote_layout_mldsa"
TDQE_SIM_LOADER_BIN="$BIN_DIR/test_tdqe_sim_loader"
WRAPPER_ALGORITHMS_BIN="$BIN_DIR/test_tdx_wrapper_algorithms"
WRAPPER_INIT_QUOTE_PROBE_BIN="$BIN_DIR/test_tdx_mldsa_init_quote_probe"
MLDSA_VERIFY_PROBE_BIN="$BIN_DIR/test_tdx_mldsa_quote_verify_probe"
TDX_DIRECT_PROBE_BIN="$BIN_DIR/test_tdx_direct_mldsa_probe"
RANDOMBYTES_STUB_OBJ="$BIN_DIR/test_randombytes_stub.o"
QGS_SOCKET_PATH="${QGS_SOCKET_PATH:-$BIN_DIR/qgs.socket}"
QGS_LOG_PATH="${QGS_LOG_PATH:-$BIN_DIR/qgs.log}"
DIRECT_PROBE_TIMEOUT_SECONDS="${DIRECT_PROBE_TIMEOUT_SECONDS:-20}"
QGS_NUM_THREADS="${QGS_NUM_THREADS:-1}"
QGS_TDQE_PATH="${QGS_TDQE_PATH:-$TDQE_LINUX_DIR/libsgx_tdqe.signed.so.1}"
QGS_PID=""
PCCS_PID=""
PCCS_LOG_PATH="${PCCS_LOG_PATH:-$BIN_DIR/pccs.log}"
PRIVATE_PCS_SCRIPT="$TESTS_DIR/private_pcs/local_tdx_pcs_proxy.py"
PRIVATE_PCS_PID=""
PRIVATE_PCS_HOST="${TDXTEST_MLDSA_LOCAL_PCS_HOST:-127.0.0.1}"
PRIVATE_PCS_PORT="${TDXTEST_MLDSA_LOCAL_PCS_PORT:-18081}"
PRIVATE_PCS_UPSTREAM_ORIGIN="${TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN:-https://api.trustedservices.intel.com}"
PRIVATE_PCS_LOG_PATH="${TDXTEST_MLDSA_LOCAL_PCS_LOG_PATH:-$BIN_DIR/local_tdx_pcs_proxy.log}"
PRIVATE_PCS_IDENTITY_FILE="${TDXTEST_MLDSA_LOCAL_PCS_IDENTITY_FILE:-$BIN_DIR/local_tdqe_identity.json}"
PRIVATE_PCS_QCNL_CONF="${TDXTEST_MLDSA_LOCAL_PCS_QCNL_CONF:-$BIN_DIR/sgx_default_qcnl_private_pcs_test.conf}"
PRIVATE_PCS_IDENTITY_FILE_FOR_ENV=""
if [[ "$TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY" == "1" ]]; then
  PRIVATE_PCS_IDENTITY_FILE_FOR_ENV="$PRIVATE_PCS_IDENTITY_FILE"
fi
LOCAL_PCCS_ENABLE="${LOCAL_PCCS_ENABLE:-1}"
LOCAL_PCCS_PORT="${LOCAL_PCCS_PORT:-8081}"
LOCAL_PCCS_ADMIN_TOKEN="${LOCAL_PCCS_ADMIN_TOKEN:-mldsa-local-admin-token}"
LOCAL_PCCS_USER_TOKEN="${LOCAL_PCCS_USER_TOKEN:-mldsa-local-user-token}"
LOCAL_PCCS_PLATFORM_COLLATERAL_JSON="${LOCAL_PCCS_PLATFORM_COLLATERAL_JSON:-}"

ensure_major_link() {
  local signed_path="$1"
  local major_path="$2"
  if [[ -f "$signed_path" && ! -e "$major_path" ]]; then
    ln -sf "$(basename "$signed_path")" "$major_path"
  fi
}

print_qgs_unavailable_hint() {
  if [[ -f "$QGS_LOG_PATH" ]] && \
     grep -Eq 'tee_att_init_quote bootstrap ret=0x1100d|Please use the correct uRTS library from PSW package\.' "$QGS_LOG_PATH"; then
    echo "[UNAVAILABLE] The forced local QGS / tee_att path is unavailable in this environment."
    echo "[UNAVAILABLE] This machine exposes TDX guest attestation, but the wrapper/QGS bootstrap still requires the SGX PCE/PSW interface."
    echo "[UNAVAILABLE] On a tdx_guest-only system, this ML-DSA direct-wrapper path cannot complete end-to-end."
  fi
}

print_host_qgsd_hint() {
  echo "[UNAVAILABLE] The hardware ML-DSA path is using the default guest transport to $TDXTEST_MLDSA_REMOTE_QGS_LABEL."
  echo "[UNAVAILABLE] Inspect the host-side QGS and PCCS logs for the quote-generation failure details."
}

print_missing_tdx_guest_hint() {
  local virt_type=""

  if command -v systemd-detect-virt >/dev/null 2>&1; then
    virt_type="$(systemd-detect-virt 2>/dev/null || true)"
  fi

  if [[ -z "$virt_type" || "$virt_type" == "none" ]]; then
    echo "[ERROR] This machine does not look like a TDX guest. It is likely the bare-metal host."
  else
    echo "[ERROR] This guest does not expose a usable TDX attestation device."
  fi

  echo "[ERROR] Run the hardware ML-DSA flow inside the TDX guest, or use run_host_tdx_guest_repo_tests.sh from the host."
}

print_machine_security_summary() {
  local verifier_mode="$1"
  local quoting_path="$2"
  echo "[INFO] Machine/attestation summary:"
  echo "       - SGX mode: $SGX_MODE_VALUE"
  if [[ -n "$TDX_GUEST_DEV" ]]; then
    echo "       - TDX device: $TDX_GUEST_DEV"
  else
    echo "       - TDX device: not present"
  fi
  echo "       - Verifier mode: $verifier_mode"
  echo "       - Trusted quoting path: $quoting_path"
  echo "[INFO] For a higher-confidence hardware-backed run, you should see:"
  echo "       - SGX mode: HW (not SIM)"
  echo "       - no 'SE_SIM bypass -> true' lines"
  echo "       - a real TDX guest device (/dev/tdx_guest or equivalent)"
  echo "       - standard DCAP/collateral verification, not local fallback"
}

sha512_hex() {
  printf '%s' "$1" | sha512sum | awk '{print $1}'
}

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

ensure_local_pccs_tls() {
  local ssl_dir="$PCCS_SERVICE_DIR/ssl_key"
  mkdir -p "$ssl_dir"
  if [[ -f "$ssl_dir/private.pem" && -f "$ssl_dir/file.crt" ]]; then
    return 0
  fi

  echo "[INFO] Generating self-signed PCCS TLS keypair..."
  openssl genrsa -out "$ssl_dir/private.pem" 2048 >/dev/null 2>&1
  openssl req -new -key "$ssl_dir/private.pem" -out "$ssl_dir/csr.pem" \
    -subj "/CN=localhost" >/dev/null 2>&1
  openssl x509 -req -days 365 -in "$ssl_dir/csr.pem" \
    -signkey "$ssl_dir/private.pem" -out "$ssl_dir/file.crt" >/dev/null 2>&1
}

start_local_pccs() {
  if [[ "$LOCAL_PCCS_ENABLE" != "1" ]]; then
    echo "[INFO] Local PCCS bootstrap disabled."
    return 0
  fi

  if [[ ! -d "$PCCS_SERVICE_DIR/node_modules" ]]; then
    if [[ "${TDX_MLDSA_LOCAL_PCCS_EMPTY_FALLBACK:-0}" == "1" ]]; then
      echo "[INFO] PCCS dependencies are missing: $PCCS_SERVICE_DIR/node_modules"
      echo "[INFO] Continuing without local PCCS because ML-DSA local fallback is enabled."
      return 0
    fi

    echo "[ERROR] PCCS dependencies are missing: $PCCS_SERVICE_DIR/node_modules"
    echo "[ERROR] Run 'npm ci' in $PCCS_SERVICE_DIR or disable local PCCS bootstrap."
    return 1
  fi

  ensure_local_pccs_tls

  local admin_hash
  local user_hash
  admin_hash="$(sha512_hex "$LOCAL_PCCS_ADMIN_TOKEN")"
  user_hash="$(sha512_hex "$LOCAL_PCCS_USER_TOKEN")"

  rm -f "$PCCS_LOG_PATH"
  echo "[INFO] Starting local PCCS on https://localhost:$LOCAL_PCCS_PORT ..."
  (
    cd "$PCCS_SERVICE_DIR"
    NODE_ENV=production \
    NODE_CONFIG="{\"HTTPS_PORT\":$LOCAL_PCCS_PORT,\"hosts\":\"127.0.0.1\",\"CachingFillMode\":\"OFFLINE\",\"AdminTokenHash\":\"$admin_hash\",\"UserTokenHash\":\"$user_hash\",\"LogLevel\":\"debug\"}" \
      node pccs_server.js
  ) >"$PCCS_LOG_PATH" 2>&1 &
  PCCS_PID=$!

  for _ in $(seq 1 30); do
    if curl -ks "https://localhost:$LOCAL_PCCS_PORT/" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  if ! kill -0 "$PCCS_PID" 2>/dev/null; then
    echo "[ERROR] Local PCCS failed to start. Log follows:"
    sed -n '1,200p' "$PCCS_LOG_PATH" || true
    return 1
  fi

  if ! curl -ks "https://localhost:$LOCAL_PCCS_PORT/" >/dev/null 2>&1; then
    echo "[ERROR] Local PCCS did not become reachable on https://localhost:$LOCAL_PCCS_PORT"
    sed -n '1,200p' "$PCCS_LOG_PATH" || true
    return 1
  fi

  if [[ -n "$LOCAL_PCCS_PLATFORM_COLLATERAL_JSON" ]]; then
    if [[ ! -f "$LOCAL_PCCS_PLATFORM_COLLATERAL_JSON" ]]; then
      echo "[ERROR] LOCAL_PCCS_PLATFORM_COLLATERAL_JSON does not exist:"
      echo "        $LOCAL_PCCS_PLATFORM_COLLATERAL_JSON"
      return 1
    fi

    echo "[INFO] Importing local PCCS platform collateral from:"
    echo "       $LOCAL_PCCS_PLATFORM_COLLATERAL_JSON"
    curl -ksS \
      -X PUT \
      -H "admin-token: $LOCAL_PCCS_ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      --data @"$LOCAL_PCCS_PLATFORM_COLLATERAL_JSON" \
      "https://localhost:$LOCAL_PCCS_PORT/sgx/certification/v4/platformcollateral" >/dev/null
  else
    echo "[INFO] No LOCAL_PCCS_PLATFORM_COLLATERAL_JSON provided; PCCS will stay empty."
  fi
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
  if [[ "$TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY" != "1" ]]; then
    return 0
  fi

  if [[ ! -f "$PRIVATE_PCS_SCRIPT" ]]; then
    echo "[ERROR] Missing private PCS proxy: $PRIVATE_PCS_SCRIPT"
    return 1
  fi

  rm -f "$PRIVATE_PCS_LOG_PATH" "$PRIVATE_PCS_IDENTITY_FILE"
  echo "[INFO] Starting private local PCS proxy on http://$PRIVATE_PCS_HOST:$PRIVATE_PCS_PORT ..."
  python3 "$PRIVATE_PCS_SCRIPT" \
    --host "$PRIVATE_PCS_HOST" \
    --port "$PRIVATE_PCS_PORT" \
    --identity-file "$PRIVATE_PCS_IDENTITY_FILE" \
    --upstream-origin "$PRIVATE_PCS_UPSTREAM_ORIGIN" \
    >"$PRIVATE_PCS_LOG_PATH" 2>&1 &
  PRIVATE_PCS_PID=$!

  for _ in $(seq 1 30); do
    if curl -fsS "http://$PRIVATE_PCS_HOST:$PRIVATE_PCS_PORT/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  if ! kill -0 "$PRIVATE_PCS_PID" 2>/dev/null; then
    echo "[ERROR] Private local PCS proxy failed to start. Log follows:"
    sed -n '1,200p' "$PRIVATE_PCS_LOG_PATH" || true
    return 1
  fi

  if ! curl -fsS "http://$PRIVATE_PCS_HOST:$PRIVATE_PCS_PORT/healthz" >/dev/null 2>&1; then
    echo "[ERROR] Private local PCS proxy did not become reachable."
    sed -n '1,200p' "$PRIVATE_PCS_LOG_PATH" || true
    return 1
  fi
}

SYSTEM_URTS_DIR="/lib/x86_64-linux-gnu"
URTS_LIB_DIR="$LOCAL_SGX_SDK/lib64"
URTS_LINK_LIB="-lsgx_urts"

if [[ "$SGX_MODE_VALUE" == "SIM" ]]; then
  URTS_LIB_DIR="$LOCAL_SGX_SDK/lib64"
  URTS_LINK_LIB="-lsgx_urts_sim"
elif [[ -f "$SYSTEM_URTS_DIR/libsgx_urts.so" ]]; then
  URTS_LIB_DIR="$SYSTEM_URTS_DIR"
fi

QGS_LD_LIBRARY_PATH="$QGS_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$QG_BUILD_LINUX_DIR:$URTS_LIB_DIR"

mkdir -p "$BIN_DIR"
if [[ "$USE_LOCAL_QGS" != "1" ]]; then
  rm -f "$QGS_SOCKET_PATH" "$QGS_LOG_PATH"
fi

start_local_qgs() {
  if [[ -n "$QGS_PID" ]] && kill -0 "$QGS_PID" 2>/dev/null; then
    kill "$QGS_PID" 2>/dev/null || true
    wait "$QGS_PID" 2>/dev/null || true
  fi

  rm -f "$QGS_SOCKET_PATH" "$QGS_LOG_PATH"

  echo "[INFO] Building repo-local QGS for the direct TDX probe..."
  make -C "$QGS_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"

  echo "[INFO] Starting repo-local QGS on $QGS_SOCKET_PATH ..."
  QGS_SOCKET_PATH="$QGS_SOCKET_PATH" \
  QGS_TDQE_PATH="$QGS_TDQE_PATH" \
  TDX_MLDSA_REQUIRE_FULL_DCAP="$TDX_MLDSA_REQUIRE_FULL_DCAP" \
  TDX_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST="$TDX_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST" \
  LD_LIBRARY_PATH="$QGS_LD_LIBRARY_PATH:${LD_LIBRARY_PATH:-}" \
    "$QGS_DIR/qgs" --no-daemon --debug "-n=$QGS_NUM_THREADS" >"$QGS_LOG_PATH" 2>&1 &
  QGS_PID=$!
  sleep 1

  if ! kill -0 "$QGS_PID" 2>/dev/null; then
    echo "[ERROR] Local QGS failed to start. Log follows:"
    cat "$QGS_LOG_PATH"
    exit 1
  fi
}

cleanup() {
  if [[ -n "$QGS_PID" ]] && kill -0 "$QGS_PID" 2>/dev/null; then
    kill "$QGS_PID" 2>/dev/null || true
    wait "$QGS_PID" 2>/dev/null || true
  fi
  if [[ -n "$PCCS_PID" ]] && kill -0 "$PCCS_PID" 2>/dev/null; then
    kill "$PCCS_PID" 2>/dev/null || true
    wait "$PCCS_PID" 2>/dev/null || true
  fi
  if [[ -n "$PRIVATE_PCS_PID" ]] && kill -0 "$PRIVATE_PCS_PID" 2>/dev/null; then
    kill "$PRIVATE_PCS_PID" 2>/dev/null || true
    wait "$PRIVATE_PCS_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT

should_clean_for_mode() {
  if [[ "$SGX_MODE_VALUE" == "SIM" ]]; then
    return 0
  fi

  if [[ ! -f "$MODE_STAMP_PATH" ]]; then
    return 1
  fi

  [[ "$(cat "$MODE_STAMP_PATH")" != "$SGX_MODE_VALUE" ]]
}

if [[ -z "${SGX_MODE:-}" ]]; then
  echo "[INFO] SGX_MODE not set; defaulting to $SGX_MODE_VALUE for the ML-DSA flow."
fi

if should_clean_for_mode; then
  echo "[INFO] Cleaning repo-local TDQE for a deterministic rebuild (SGX_MODE=$SGX_MODE_VALUE)..."
  make -C "$TDQE_LINUX_DIR" clean SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
  echo "[INFO] Cleaning repo-local ID enclave for a deterministic rebuild (SGX_MODE=$SGX_MODE_VALUE)..."
  make -C "$ID_ENCLAVE_LINUX_DIR" clean SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
  echo "[INFO] Cleaning repo-local PCE wrapper for a deterministic rebuild (SGX_MODE=$SGX_MODE_VALUE)..."
  make -C "$PCE_WRAPPER_LINUX_DIR" clean SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
  echo "[INFO] Cleaning repo-local TDX quote wrapper for a deterministic rebuild (SGX_MODE=$SGX_MODE_VALUE)..."
  make -C "$TDX_QUOTE_LINUX_DIR" clean SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
  echo "[INFO] Cleaning repo-local QGS for a deterministic rebuild (SGX_MODE=$SGX_MODE_VALUE)..."
  make -C "$QGS_DIR" clean SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
fi

echo "[INFO] Building repo-local TDQE..."
make -C "$TDQE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
ensure_major_link \
  "$TDQE_LINUX_DIR/libsgx_tdqe.signed.so" \
  "$TDQE_LINUX_DIR/libsgx_tdqe.signed.so.1"

echo "[INFO] Building repo-local ID enclave..."
make -C "$ID_ENCLAVE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
ensure_major_link \
  "$ID_ENCLAVE_LINUX_DIR/libsgx_id_enclave.signed.so" \
  "$ID_ENCLAVE_LINUX_DIR/libsgx_id_enclave.signed.so.1"

echo "[INFO] Building repo-local PCE wrapper..."
make -C "$PCE_WRAPPER_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
ensure_major_link \
  "$PCE_WRAPPER_LINUX_DIR/libsgx_pce_logic.so" \
  "$PCE_WRAPPER_LINUX_DIR/libsgx_pce_logic.so.1"

echo "[INFO] Building repo-local TDX quote wrapper..."
make -C "$TDX_QUOTE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
ensure_major_link \
  "$TDX_QUOTE_LINUX_DIR/libsgx_tdx_logic.so" \
  "$TDX_QUOTE_LINUX_DIR/libsgx_tdx_logic.so.1"

echo "[INFO] Building repo-local libtdx_attest..."
make -C "$TDX_ATTEST_LINUX_DIR"
ensure_major_link \
  "$TDX_ATTEST_LINUX_DIR/libtdx_attest.so" \
  "$TDX_ATTEST_LINUX_DIR/libtdx_attest.so.1"

printf '%s\n' "$SGX_MODE_VALUE" > "$MODE_STAMP_PATH"

if [[ -d "$LOCAL_SGX_SDK" ]]; then
  export SGX_SDK="$LOCAL_SGX_SDK"
fi

if [[ "$TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY" == "1" ]]; then
  write_private_pcs_qcnl_conf
  SELECTED_QCNL_CONF="$PRIVATE_PCS_QCNL_CONF"
fi

export QCNL_CONF_PATH="${QCNL_CONF_PATH:-$SELECTED_QCNL_CONF}"
echo "[INFO] Using QCNL config: $QCNL_CONF_PATH"
if [[ "$TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY" == "1" ]]; then
  echo "[INFO] Using private local PCS TDQE identity authority for ML-DSA verification."
fi
if [[ "$SGX_MODE_VALUE" == "SIM" ]]; then
  export TDX_MLDSA_LOCAL_PCCS_EMPTY_FALLBACK="${TDX_MLDSA_LOCAL_PCCS_EMPTY_FALLBACK:-1}"
fi

if [[ ! -d "$LOCAL_PREBUILT_OPENSSL_DIR/inc" || ! -d "$LOCAL_PREBUILT_OPENSSL_DIR/lib/linux64" ]]; then
  echo "[INFO] Preparing repo-local OpenSSL compatibility paths for DCAP builds..."
  mkdir -p "$LOCAL_PREBUILT_OPENSSL_DIR/lib"
  ln -sfn /usr/include "$LOCAL_PREBUILT_OPENSSL_DIR/inc"
  ln -sfn /usr/lib/x86_64-linux-gnu "$LOCAL_PREBUILT_OPENSSL_DIR/lib/linux64"
fi

if ! ensure_repo_local_sgxssl_untrusted_lib; then
  echo "[SKIP] Missing repo-local SGXSSL package at:"
  echo "       $LOCAL_SGXSSL_PACKAGE_DIR"
  echo "[SKIP] Expected SGXSSL header/lib pair:"
  echo "       - include/openssl/opensslconf.h"
  echo "       - lib64/libsgx_usgxssl.a"
  echo "[SKIP] ML-DSA quote verification probe will be skipped."
  SKIP_MLDSA_VERIFY_PROBE=1
else
  SKIP_MLDSA_VERIFY_PROBE=0
  echo "[INFO] Building repo-local QCNL/QPL/QuoteVerification libraries..."
  make -C "$QCNL_LINUX_DIR"
  make -C "$QPL_LINUX_DIR"
  make -C "$QV_LINUX_DIR"
fi

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
  "$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/pq/mldsa_native_44.c" \
  "$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/pq/mldsa_native_65.c" \
  "$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/pq/mldsa_native_87.c" \
  -o "$TDQE_MLDSA_ADAPTER_BIN"

echo "[INFO] Compiling host-side randombytes stub..."
gcc -std=c11 -O2 -Wall -Wextra -Werror \
  -c "$TESTS_DIR/tdqe/test_randombytes_stub.c" \
  -o "$RANDOMBYTES_STUB_OBJ"

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

echo "[INFO] Compiling TDQE simulation loader probe..."
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  -I"$LOCAL_SGX_SDK/include" \
  "$TESTS_DIR/tdqe/test_tdqe_sim_loader.cpp" \
  -L"$URTS_LIB_DIR" \
  -Wl,-rpath,"$URTS_LIB_DIR" \
  "$URTS_LINK_LIB" -lpthread -ldl \
  -o "$TDQE_SIM_LOADER_BIN"

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
  -lsgx_tdx_logic -lsgx_pce_logic "$URTS_LINK_LIB" -lpthread -ldl \
  -o "$WRAPPER_ALGORITHMS_BIN"

echo "[INFO] Compiling wrapper ML-DSA init_quote probe..."
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/inc" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper" \
  -I"$LOCAL_SGX_SDK/include" \
  "$TESTS_DIR/wrapper/test_tdx_mldsa_init_quote_probe.cpp" \
  -L"$TDX_QUOTE_LINUX_DIR" \
  -L"$PCE_WRAPPER_LINUX_DIR" \
  -L"$URTS_LIB_DIR" \
  -Wl,-rpath,"$TDX_QUOTE_LINUX_DIR" \
  -Wl,-rpath,"$PCE_WRAPPER_LINUX_DIR" \
  -Wl,-rpath,"$URTS_LIB_DIR" \
  -lsgx_tdx_logic -lsgx_pce_logic "$URTS_LINK_LIB" -lpthread -ldl \
  -o "$WRAPPER_INIT_QUOTE_PROBE_BIN"

if [[ "$SKIP_MLDSA_VERIFY_PROBE" != "1" ]]; then
  echo "[INFO] Compiling ML-DSA quote verification support probe..."
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
    "$TESTS_DIR/verifier/test_tdx_mldsa_quote_verify_probe.cpp" \
    "$RANDOMBYTES_STUB_OBJ" \
    "$TDQE_LINUX_DIR/tdqe_mldsa_adapter.o" \
    "$TDQE_LINUX_DIR/mldsa_native_44.o" \
    "$TDQE_LINUX_DIR/mldsa_native_65.o" \
    "$TDQE_LINUX_DIR/mldsa_native_87.o" \
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
    -lsgx_tdx_logic -lsgx_pce_logic -ltdx_attest -l:libsgx_dcap_quoteverify.so -l:libdcap_quoteprov.so -l:libsgx_default_qcnl_wrapper.so \
    "$URTS_LINK_LIB" -lcrypto -lcurl -lpthread -ldl \
    -o "$MLDSA_VERIFY_PROBE_BIN"
fi

echo "[INFO] Compiling direct TDX ML-DSA capability probe..."
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest" \
  -I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc" \
  -I"$TESTS_DIR/common" \
  -I"$LOCAL_SGX_SDK/include" \
  "$SCRIPT_DIR/test_tdx_direct_mldsa_probe.cpp" \
  "$TESTS_DIR/common/utils.cpp" \
  -L"$TDX_ATTEST_LINUX_DIR" \
  -L"$TDX_QUOTE_LINUX_DIR" \
  -L"$PCE_WRAPPER_LINUX_DIR" \
  -Wl,-rpath,"$TDX_ATTEST_LINUX_DIR" \
  -Wl,-rpath,"$TDX_QUOTE_LINUX_DIR" \
  -Wl,-rpath,"$PCE_WRAPPER_LINUX_DIR" \
  -ltdx_attest -lsgx_tdx_logic -lsgx_pce_logic -lcurl -lpthread -ldl \
  -o "$TDX_DIRECT_PROBE_BIN"

echo "[INFO] Running TDQE ML-DSA adapter test..."
"$TDQE_MLDSA_ADAPTER_BIN"

echo "[INFO] Running quote header ML-DSA layout test..."
"$QUOTE_HEADERS_BIN"

echo "[INFO] Running TDQE ML-DSA quote layout test..."
"$TDQE_LAYOUT_BIN"

if [[ "$MLDSA_FLOW_MODE" == "SIM" ]]; then
  echo "[INFO] Running TDQE simulation loader probe..."
  LD_LIBRARY_PATH="$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
    "$TDQE_SIM_LOADER_BIN" "$QGS_TDQE_PATH"

  echo "[INFO] Running wrapper ML-DSA init_quote probe..."
  LD_LIBRARY_PATH="$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$QG_BUILD_LINUX_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
    "$WRAPPER_INIT_QUOTE_PROBE_BIN" "$QGS_TDQE_PATH"
fi

if [[ "$MLDSA_FLOW_MODE" == "SIM" ]]; then
  echo "[INFO] Running wrapper ML-DSA algorithm-selection test..."
  if [[ "$SKIP_MLDSA_VERIFY_PROBE" != "1" ]]; then
    start_local_pccs
  fi

  TEST_TDQE_PATH="$QGS_TDQE_PATH" \
  LD_LIBRARY_PATH="$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$QG_BUILD_LINUX_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
    "$WRAPPER_ALGORITHMS_BIN"
else
  echo "[INFO] Skipping the repo-local wrapper ML-DSA algorithm-selection test in hardware mode."
fi

if [[ "$SKIP_MLDSA_VERIFY_PROBE" != "1" && "$MLDSA_FLOW_MODE" == "SIM" ]]; then
  if [[ -z "$TDX_GUEST_DEV" ]]; then
    echo "[SKIP] No TDX guest device found; skipping the ML-DSA quote verification probe."
    echo "[SKIP] In this repo-local setup, the probe still needs tdx_att_get_report() to obtain a TD report even in SGX SIM mode."
  else
    echo "[INFO] Running ML-DSA quote verification support probe..."
    set +e
    TEST_TDQE_PATH="$QGS_TDQE_PATH" \
    LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR:$QV_BUILD_LINUX_DIR:$QG_BUILD_LINUX_DIR:${LD_LIBRARY_PATH:-}" \
      "$MLDSA_VERIFY_PROBE_BIN"
    verify_probe_status=$?
    set -e

    case "$verify_probe_status" in
      0)
        echo "[INFO] ML-DSA quote verification probe succeeded in the current setup."
        ;;
      2)
        echo "[UNSUPPORTED] The current verifier stack does not support ML-DSA quote format/certification data yet."
        ;;
      3)
        echo "[PARTIAL] The verifier stack accepted the ML-DSA quote format but could not complete verification due to collateral/runtime limits."
        ;;
      *)
        echo "[ERROR] ML-DSA quote verification probe failed with status $verify_probe_status"
        exit "$verify_probe_status"
        ;;
    esac
  fi
elif [[ "$SKIP_MLDSA_VERIFY_PROBE" != "1" && "$MLDSA_FLOW_MODE" != "SIM" ]]; then
  echo "[INFO] Deferring the ML-DSA verifier probe to the direct hardware quote path."
fi

if [[ -z "$TDX_GUEST_DEV" ]]; then
  if [[ "$MLDSA_FLOW_MODE" == "SIM" ]]; then
    echo "[SKIP] No TDX guest device found; skipping the direct TDX ML-DSA capability probe."
    print_machine_security_summary "local ML-DSA verification fallback" "simulated SGX TDQE"
  else
    echo "[ERROR] SGX_MODE=$SGX_MODE_VALUE selected the hardware ML-DSA flow, but no TDX guest device is present."
    print_missing_tdx_guest_hint
    print_machine_security_summary "hardware ML-DSA path unavailable" "direct TDX device required"
    exit 1
  fi
  exit 0
fi

if [[ ! -r "$TDX_GUEST_DEV" || ! -w "$TDX_GUEST_DEV" ]]; then
  if [[ "$MLDSA_FLOW_MODE" == "SIM" ]]; then
    echo "[SKIP] Insufficient permissions on $TDX_GUEST_DEV; skipping the direct TDX ML-DSA capability probe."
    echo "[SKIP] Run this script with elevated privileges to exercise the direct TDX path."
    print_machine_security_summary "local ML-DSA verification fallback" "simulated SGX TDQE"
  else
    echo "[ERROR] SGX_MODE=$SGX_MODE_VALUE selected the hardware ML-DSA flow, but permissions on $TDX_GUEST_DEV are insufficient."
    print_machine_security_summary "hardware ML-DSA path unavailable" "direct TDX device permissions missing"
    exit 1
  fi
  exit 0
fi

if [[ "$USE_LOCAL_QGS" == "1" ]]; then
  start_local_qgs
else
  echo "[INFO] Using the default guest transport to $TDXTEST_MLDSA_REMOTE_QGS_LABEL for hardware ML-DSA quotes."
fi

HARDWARE_MLDSA_VERIFIER_MODE="hardware quote generation only"
if [[ "$MLDSA_FLOW_MODE" == "HW" && "$SKIP_MLDSA_VERIFY_PROBE" != "1" ]]; then
  echo "[INFO] Running ML-DSA quote verification support probe on the direct hardware path..."
  start_private_pcs
  VERIFY_PROBE_LOG="$(mktemp)"
  set +e
  if [[ "$USE_LOCAL_QGS" == "1" ]]; then
    TEST_MLDSA_USE_DIRECT_TDX=1 \
    TEST_MLDSA_ALLOW_LOCAL_FALLBACK=0 \
    TEST_MLDSA_ALLOW_LOCAL_TDQE_IDENTITY=1 \
    TEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY="$TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY" \
    TEST_MLDSA_LOCAL_PCS_IDENTITY_FILE="$PRIVATE_PCS_IDENTITY_FILE_FOR_ENV" \
    TDX_MLDSA_ALLOW_LOCAL_TDQE_IDENTITY=1 \
    TEST_TDQE_PATH="$QGS_TDQE_PATH" \
    TDX_ATTEST_FORCE_LOCAL_QGS=1 \
    TDX_ATTEST_LOCAL_QGS_SOCKET="$QGS_SOCKET_PATH" \
    LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR:$QV_BUILD_LINUX_DIR:$QG_BUILD_LINUX_DIR:${LD_LIBRARY_PATH:-}" \
      "$MLDSA_VERIFY_PROBE_BIN" 2>&1 | tee "$VERIFY_PROBE_LOG"
  else
    TEST_MLDSA_USE_DIRECT_TDX=1 \
    TEST_MLDSA_ALLOW_LOCAL_FALLBACK=0 \
    TEST_MLDSA_ALLOW_LOCAL_TDQE_IDENTITY=1 \
    TEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY="$TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY" \
    TEST_MLDSA_LOCAL_PCS_IDENTITY_FILE="$PRIVATE_PCS_IDENTITY_FILE_FOR_ENV" \
    TDX_MLDSA_ALLOW_LOCAL_TDQE_IDENTITY=1 \
    LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR:$QV_BUILD_LINUX_DIR:$QG_BUILD_LINUX_DIR:${LD_LIBRARY_PATH:-}" \
      "$MLDSA_VERIFY_PROBE_BIN" 2>&1 | tee "$VERIFY_PROBE_LOG"
  fi
  verify_probe_status=${PIPESTATUS[0]}
  set -e

  case "$verify_probe_status" in
    0)
      echo "[INFO] ML-DSA hardware quote verification probe succeeded in the current setup."
      if grep -q 'verifier mode: stock_dcap' "$VERIFY_PROBE_LOG"; then
        HARDWARE_MLDSA_VERIFIER_MODE="stock Intel DCAP verification on hardware quote"
      elif grep -q 'verifier mode: local_pcs_tdqe_identity' "$VERIFY_PROBE_LOG"; then
        HARDWARE_MLDSA_VERIFIER_MODE="private local PCS TDQE identity verification"
      elif grep -q 'verifier mode: local_tdqe_identity_override' "$VERIFY_PROBE_LOG"; then
        HARDWARE_MLDSA_VERIFIER_MODE="DCAP verification with local TDQE identity override"
      else
        HARDWARE_MLDSA_VERIFIER_MODE="DCAP verification on hardware quote"
      fi
      ;;
    5)
      echo "[ERROR] Stock Intel DCAP verification was required, but the quote mismatched the PCCS TD_QE identity."
      echo "[ERROR] The repo-local TDQE is still not accepted by the stock Intel TD_QE identity collateral."
      rm -f "$VERIFY_PROBE_LOG"
      exit 5
      ;;
    2)
      echo "[UNSUPPORTED] The current verifier stack still does not support standard DCAP verification for this ML-DSA quote format."
      rm -f "$VERIFY_PROBE_LOG"
      exit 2
      ;;
    3)
      echo "[PARTIAL] The verifier stack recognized the ML-DSA quote but could not complete standard verification due to collateral/runtime limits."
      rm -f "$VERIFY_PROBE_LOG"
      exit 3
      ;;
    *)
      echo "[ERROR] ML-DSA hardware quote verification probe failed with status $verify_probe_status"
      if [[ "$USE_LOCAL_QGS" == "1" ]]; then
        print_qgs_unavailable_hint
        echo "[ERROR] Recent QGS log:"
        tail -n 200 "$QGS_LOG_PATH" || true
      else
        print_host_qgsd_hint
      fi
      rm -f "$VERIFY_PROBE_LOG"
      exit "$verify_probe_status"
      ;;
  esac
  rm -f "$VERIFY_PROBE_LOG"
fi

echo "[INFO] Running direct TDX ML-DSA capability probe..."
if [[ "$USE_LOCAL_QGS" == "1" ]]; then
  TDX_ATTEST_FORCE_LOCAL_QGS=1 \
  TDX_ATTEST_LOCAL_QGS_SOCKET="$QGS_SOCKET_PATH" \
  LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
    timeout "$DIRECT_PROBE_TIMEOUT_SECONDS" "$TDX_DIRECT_PROBE_BIN" || {
      probe_status=$?
      echo "[ERROR] Direct TDX ML-DSA capability probe failed with status $probe_status"
      print_qgs_unavailable_hint
      echo "[ERROR] Recent QGS log:"
      tail -n 200 "$QGS_LOG_PATH" || true
      exit "$probe_status"
    }
else
  LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
    timeout "$DIRECT_PROBE_TIMEOUT_SECONDS" "$TDX_DIRECT_PROBE_BIN" || {
      probe_status=$?
      echo "[ERROR] Direct TDX ML-DSA capability probe failed with status $probe_status"
      print_host_qgsd_hint
      exit "$probe_status"
    }
fi

if [[ "$MLDSA_FLOW_MODE" == "SIM" ]]; then
  print_machine_security_summary "local ML-DSA verification fallback" "simulated SGX TDQE"
else
  if [[ "$SKIP_MLDSA_VERIFY_PROBE" == "1" ]]; then
    HARDWARE_MLDSA_VERIFIER_MODE="hardware quote generation only"
  fi
  if [[ "$USE_LOCAL_QGS" == "1" ]]; then
    print_machine_security_summary "$HARDWARE_MLDSA_VERIFIER_MODE" "direct TDX device via repo-local QGS"
  else
    print_machine_security_summary "$HARDWARE_MLDSA_VERIFIER_MODE" "direct TDX device via $TDXTEST_MLDSA_REMOTE_QGS_LABEL"
  fi
fi
