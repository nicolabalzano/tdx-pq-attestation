#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"

RUN_AS_USER="${SUDO_USER:-$(id -un)}"
RUN_AS_HOME="${HOME}"
if [[ -n "${SUDO_USER:-}" ]]; then
  RUN_AS_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
fi

TDX_TOOLS_DIR="${TDX_TOOLS_DIR:-$RUN_AS_HOME/tdx/guest-tools}"
CREATE_TD_IMAGE_SH="$TDX_TOOLS_DIR/image/create-td-image.sh"
RUN_TD_SH="$TDX_TOOLS_DIR/run_td"

GUEST_UBUNTU_VERSION="${TDX_GUEST_UBUNTU_VERSION:-24.04}"
DEFAULT_GUEST_IMAGE_PATH="$TDX_TOOLS_DIR/image/tdx-guest-ubuntu-${GUEST_UBUNTU_VERSION}-generic.qcow2"
GUEST_IMAGE_PATH="${TDX_GUEST_IMAGE_PATH:-$DEFAULT_GUEST_IMAGE_PATH}"

GUEST_HOST="${TDX_GUEST_HOST:-127.0.0.1}"
GUEST_SSH_PORT="${TDX_GUEST_SSH_PORT:-10022}"
GUEST_ROOT_PASSWORD="${TDX_GUEST_ROOT_PASSWORD:-123456}"
GUEST_VCPUS="${TDX_GUEST_VCPUS:-16}"
GUEST_MEM="${TDX_GUEST_MEM:-16G}"
GUEST_REPO_ROOT="${TDX_GUEST_REPO_ROOT:-/root/tdx-pq-attestation}"
GUEST_TEST_DIR="$GUEST_REPO_ROOT/tdx_tests/direct"
GUEST_SGX_SDK_LIB64="$GUEST_REPO_ROOT/tdx_tests/sgxsdk/lib64"
GUEST_SGX_SDK_ROOT="$GUEST_REPO_ROOT/tdx_tests/sgxsdk"

HOST_SGX_SDK_ROOT="${TDXTEST_HOST_SGX_SDK_ROOT:-$REPO_ROOT/tdx_tests/sgxsdk}"
HOST_SYSTEM_QGS_PORT="${TDXTEST_HOST_SYSTEM_QGS_PORT:-4050}"
HOST_REPO_QGS_PORT="${TDXTEST_MLDSA_HOST_REPO_QGS_PORT:-4051}"
HOST_REPO_QGS_THREADS="${TDXTEST_MLDSA_HOST_REPO_QGS_THREADS:-1}"
HOST_REPO_QGS_BOOTSTRAP_MODE="${TDXTEST_MLDSA_HOST_BOOTSTRAP_MODE:-legacy_pce}"
HOST_REPO_QGS_REQUIRE_FULL_DCAP="${TDXTEST_MLDSA_REQUIRE_FULL_DCAP:-1}"
HOST_REPO_QGS_FORCE_REFRESH="${TDXTEST_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST:-1}"
TDXTEST_MLDSA_USE_HOST_REPO_QGS="${TDXTEST_MLDSA_USE_HOST_REPO_QGS:-1}"
HOST_TDQE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe/linux"
HOST_ID_ENCLAVE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/id_enclave/linux"
HOST_PCE_WRAPPER_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux"
HOST_QCNL_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/qcnl/linux"
HOST_QPL_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/qpl/linux"
HOST_TDX_QUOTE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux"
HOST_QGS_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs"
HOST_QG_BUILD_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/build/linux"
HOST_URTS_LIB_DIR="${TDXTEST_HOST_URTS_LIB_DIR:-/lib/x86_64-linux-gnu}"
HOST_PCKID_RETRIEVAL_CSV="${TDXTEST_HOST_PCKID_RETRIEVAL_CSV:-$RUN_AS_HOME/pckid_retrieval.csv}"
HOST_PCKCERT_QEID_OVERRIDE="${TDXTEST_HOST_PCKCERT_QEID_OVERRIDE:-}"
HOST_REPO_QGS_LOG_PATH="${TDXTEST_HOST_REPO_QGS_LOG_PATH:-}"
HOST_REPO_QGS_PID=""
TDXTEST_EXEC_MODE="${TDXTEST_EXEC_MODE:-}"

TDXTEST_CREATE_IMAGE="${TDXTEST_CREATE_IMAGE:-1}"
TDXTEST_START_GUEST="${TDXTEST_START_GUEST:-1}"
TDXTEST_INSTALL_GUEST_DEPS="${TDXTEST_INSTALL_GUEST_DEPS:-1}"
TDXTEST_COPY_REPO="${TDXTEST_COPY_REPO:-1}"
TDXTEST_CLEAN_GUEST_BUILD="${TDXTEST_CLEAN_GUEST_BUILD:-1}"
TDXTEST_REQUIRE_HOST_QGSD="${TDXTEST_REQUIRE_HOST_QGSD:-1}"
TDXTEST_REQUIRE_HOST_REGISTRATION="${TDXTEST_REQUIRE_HOST_REGISTRATION:-0}"
TDXTEST_POPULATE_HOST_PCCS_FROM_PCKID="${TDXTEST_POPULATE_HOST_PCCS_FROM_PCKID:-0}"
TDXTEST_PCCS_URL="${TDXTEST_PCCS_URL:-https://localhost:8081}"
TDXTEST_PCCS_USER_TOKEN="${TDXTEST_PCCS_USER_TOKEN:-}"
TDXTEST_CONFIGURE_GUEST_VSOCK_ATTEST="${TDXTEST_CONFIGURE_GUEST_VSOCK_ATTEST:-1}"
TDXTEST_RUN_ECDSA="${TDXTEST_RUN_ECDSA:-1}"
TDXTEST_STOP_GUEST_ON_EXIT="${TDXTEST_STOP_GUEST_ON_EXIT:-0}"
TDXTEST_MLDSA_ALGS="${TDXTEST_MLDSA_ALGS-"44 65 87"}"
TDXTEST_MLDSA_SGX_MODE="${TDXTEST_MLDSA_SGX_MODE:-HW}"
TDXTEST_MLDSA_FORCE_LOCAL_QGS="${TDXTEST_MLDSA_FORCE_LOCAL_QGS:-}"
TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY="${TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY:-}"
TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY="${TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY:-}"
TDXTEST_MLDSA_LOCAL_PCS_PORT="${TDXTEST_MLDSA_LOCAL_PCS_PORT:-}"
TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN="${TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN:-}"
TDXTEST_ECDSA_SGX_MODE="${TDXTEST_ECDSA_SGX_MODE:-HW}"
TDXTEST_ECDSA_VERIFIER_MODE="${TDXTEST_ECDSA_VERIFIER_MODE:-binding-only}"
TDXTEST_SSH_WAIT_SECONDS="${TDXTEST_SSH_WAIT_SECONDS:-300}"
TDXTEST_MLDSA_TIMEOUT_SECONDS="${TDXTEST_MLDSA_TIMEOUT_SECONDS:-5400}"
TDXTEST_ECDSA_TIMEOUT_SECONDS="${TDXTEST_ECDSA_TIMEOUT_SECONDS:-3600}"
TDXTEST_LOG_DIR="${TDXTEST_LOG_DIR:-$SCRIPT_DIR/logs}"
if [[ -z "$HOST_REPO_QGS_LOG_PATH" ]]; then
  HOST_REPO_QGS_LOG_PATH="$TDXTEST_LOG_DIR/host_repo_qgs.log"
fi

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ConnectTimeout=5
  -p "$GUEST_SSH_PORT"
)
SCP_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -P "$GUEST_SSH_PORT"
)

declare -a FAILURES=()

usage() {
  cat <<EOF
Usage: $(basename "$0")

Host-side orchestrator for the Canonical TDX 24.04 guest tools and this repo's
direct TDX test runners.

What it does:
  1. verifies that the host TDX stack is active
  2. creates the default TDX guest image if missing
  3. starts the guest through ~/tdx/guest-tools/run_td
  4. waits for SSH on localhost:${GUEST_SSH_PORT}
  5. installs guest build/runtime dependencies
  6. copies the current repo snapshot into the guest
  7. runs:
     - ML-DSA direct flow with TEST_MLDSA_ALG=44
     - ML-DSA direct flow with TEST_MLDSA_ALG=65
     - ML-DSA direct flow with TEST_MLDSA_ALG=87
     - ECDSA direct flow

Environment overrides:
  TDX_TOOLS_DIR                     default: $RUN_AS_HOME/tdx/guest-tools
  TDX_GUEST_UBUNTU_VERSION          default: $GUEST_UBUNTU_VERSION
  TDX_GUEST_IMAGE_PATH              default: $GUEST_IMAGE_PATH
  TDX_GUEST_HOST                    default: $GUEST_HOST
  TDX_GUEST_SSH_PORT                default: $GUEST_SSH_PORT
  TDX_GUEST_ROOT_PASSWORD           default: $GUEST_ROOT_PASSWORD
  TDX_GUEST_VCPUS                   default: $GUEST_VCPUS
  TDX_GUEST_MEM                     default: $GUEST_MEM
  TDX_GUEST_REPO_ROOT               default: $GUEST_REPO_ROOT
  TDXTEST_HOST_SGX_SDK_ROOT         default: $HOST_SGX_SDK_ROOT
  TDXTEST_HOST_SYSTEM_QGS_PORT      default: $HOST_SYSTEM_QGS_PORT
  TDXTEST_MLDSA_HOST_REPO_QGS_PORT  default: $HOST_REPO_QGS_PORT
  TDXTEST_MLDSA_HOST_REPO_QGS_THREADS default: $HOST_REPO_QGS_THREADS
  TDXTEST_MLDSA_HOST_BOOTSTRAP_MODE default: $HOST_REPO_QGS_BOOTSTRAP_MODE
  TDXTEST_MLDSA_REQUIRE_FULL_DCAP   1=fail ML-DSA HW when platform cert data/DCAP collateral are unavailable
  TDXTEST_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST 1=refresh ML-DSA attestation key before each host repo-local QGS quote request
  TDXTEST_MLDSA_USE_HOST_REPO_QGS   1=run host repo-local QGS for ML-DSA HW, 0=use host qgsd
  TDXTEST_CREATE_IMAGE              1=create if missing, 0=fail if missing
  TDXTEST_START_GUEST               1=start guest, 0=assume guest already running
  TDXTEST_INSTALL_GUEST_DEPS        1=apt install guest deps, 0=skip
  TDXTEST_COPY_REPO                 1=copy current repo snapshot, 0=reuse guest repo
  TDXTEST_CLEAN_GUEST_BUILD         1=remove stale guest build artifacts, 0=skip
  TDXTEST_REQUIRE_HOST_QGSD         1=fail early if qgsd is missing on the host
  TDXTEST_REQUIRE_HOST_REGISTRATION 1=fail early if Canonical MPA registration is not completed
  TDXTEST_POPULATE_HOST_PCCS_FROM_PCKID 1=run PCKIDRetrievalTool against PCCS before booting the guest
  TDXTEST_PCCS_URL                  default: $TDXTEST_PCCS_URL
  TDXTEST_PCCS_USER_TOKEN           plain PCCS user token/password for PCKIDRetrievalTool upload
  TDXTEST_CONFIGURE_GUEST_VSOCK_ATTEST 1=write /etc/tdx-attest.conf with the selected QGS port
  TDXTEST_RUN_ECDSA                 1=run ECDSA flow, 0=skip it
  TDXTEST_STOP_GUEST_ON_EXIT        1=stop guest at end, 0=leave it running
  TDXTEST_MLDSA_ALGS                default: "44 65 87"
  TDXTEST_MLDSA_SGX_MODE            default: $TDXTEST_MLDSA_SGX_MODE
  TDXTEST_MLDSA_FORCE_LOCAL_QGS     empty=use remote host QGS in HW, 1=force guest repo-local QGS
  TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY 1=require Intel TD_QE identity and fail local TDQE
  TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY 1=serve a private local TD_QE identity through a PCS-compatible proxy
  TDXTEST_MLDSA_LOCAL_PCS_PORT      default: 18081 inside the guest
  TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN default: https://api.trustedservices.intel.com
  TDXTEST_ECDSA_SGX_MODE            default: $TDXTEST_ECDSA_SGX_MODE
  TDXTEST_ECDSA_VERIFIER_MODE       default: $TDXTEST_ECDSA_VERIFIER_MODE
  TDXTEST_SSH_WAIT_SECONDS          default: 300
  TDXTEST_MLDSA_TIMEOUT_SECONDS     default: 5400
  TDXTEST_ECDSA_TIMEOUT_SECONDS     default: 3600
  TDXTEST_LOG_DIR                   default: $TDXTEST_LOG_DIR
  TDXTEST_EXEC_MODE                 internal: host (default) or guest
EOF
}

info() {
  echo "[INFO] $*"
}

error() {
  echo "[ERROR] $*" >&2
}

fail() {
  error "$@"
  exit 1
}

ensure_major_link() {
  local signed_path="$1"
  local major_path="$2"

  if [[ -f "$signed_path" && ! -e "$major_path" ]]; then
    ln -sf "$(basename "$signed_path")" "$major_path"
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing host command: $1"
}

discover_host_pckcert_qeid_override() {
  local csv_path="${1:-$HOST_PCKID_RETRIEVAL_CSV}"
  local csv_line=""
  local qeid=""
  local tmp_out=""

  if [[ -n "$HOST_PCKCERT_QEID_OVERRIDE" ]]; then
    HOST_PCKCERT_QEID_OVERRIDE="${HOST_PCKCERT_QEID_OVERRIDE^^}"
    [[ "$HOST_PCKCERT_QEID_OVERRIDE" =~ ^[0-9A-F]{32}$ ]] || fail "TDXTEST_HOST_PCKCERT_QEID_OVERRIDE must be 32 hex chars"
    return 0
  fi

  if command -v PCKIDRetrievalTool >/dev/null 2>&1; then
    info "Refreshing host PCK ID data to discover the PCCS lookup QEID ..."
    tmp_out="$(mktemp /tmp/tdx_host_qeid_discovery.XXXXXX.out)"
    sudo /usr/bin/PCKIDRetrievalTool -f "$csv_path" >"$tmp_out" 2>&1 || {
      sed -n '1,120p' "$tmp_out" >&2 || true
      fail "PCKIDRetrievalTool failed while discovering the host PCCS lookup QEID"
    }
    rm -f "$tmp_out"
  fi

  [[ -f "$csv_path" ]] || return 1
  csv_line="$(head -n 1 "$csv_path" | tr -d '\r\n')"
  qeid="$(awk -F',' 'NF >= 5 {print toupper($5)}' <<<"$csv_line")"
  if [[ "$qeid" =~ ^[0-9A-F]{32}$ ]]; then
    HOST_PCKCERT_QEID_OVERRIDE="$qeid"
    info "Using host PCCS lookup QEID override: $HOST_PCKCERT_QEID_OVERRIDE"
    return 0
  fi

  return 1
}

ensure_sshpass() {
  if command -v sshpass >/dev/null 2>&1; then
    return 0
  fi

  info "Installing missing host dependency: sshpass"
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y sshpass
  command -v sshpass >/dev/null 2>&1 || fail "sshpass install failed"
}

ensure_host_tdx_ready() {
  local tdx_param="/sys/module/kvm_intel/parameters/tdx"

  [[ -r "$tdx_param" ]] || fail "Host TDX parameter not found at $tdx_param"

  if [[ "$(cat "$tdx_param")" != "Y" ]]; then
    fail "Host TDX is not active: $tdx_param is not Y"
  fi

  info "Host TDX is active."
}

ensure_host_qgsd_ready() {
  [[ "$TDXTEST_REQUIRE_HOST_QGSD" == "1" ]] || return 0

  if ! dpkg -s tdx-qgs >/dev/null 2>&1; then
    fail "Host package 'tdx-qgs' is not installed. Run: sudo ~/tdx/attestation/setup-attestation-host.sh"
  fi

  if ! systemctl is-enabled qgsd >/dev/null 2>&1 && ! systemctl is-active qgsd >/dev/null 2>&1; then
    fail "Host service 'qgsd' is not enabled or active. Install/setup host attestation first."
  fi

  if ! systemctl is-active qgsd >/dev/null 2>&1; then
    fail "Host service 'qgsd' is not active. Start it with: sudo systemctl start qgsd"
  fi

  info "Host qgsd is active."
}

ensure_host_registration_ready() {
  local reg_script

  [[ "$TDXTEST_REQUIRE_HOST_REGISTRATION" == "1" ]] || return 0

  reg_script="$(cd "$TDX_TOOLS_DIR/.." && pwd)/attestation/check-registration.sh"
  [[ -x "$reg_script" ]] || fail "Missing host registration checker: $reg_script"

  if ! sudo "$reg_script" >/tmp/tdx_host_registration_check.out 2>&1; then
    if [[ "$TDXTEST_REQUIRE_HOST_REGISTRATION" == "1" ]]; then
      error "Host platform registration is not complete."
      sed -n '1,120p' /tmp/tdx_host_registration_check.out >&2 || true
      error "qgsd is reachable, but host PCCS/registration is still broken."
      error "Typical fix path:"
      error "  1. sudo /usr/bin/pccs-configure"
      error "  2. sudo systemctl restart pccs"
      error "  3. sudo systemctl restart mpa_registration_tool"
      error "  4. sudo $(printf '%q' "$reg_script")"
      exit 1
    fi

    info "Canonical MPA registration check is not complete."
    sed -n '1,120p' /tmp/tdx_host_registration_check.out || true
    info "Continuing because some setups rely on PCKIDRetrievalTool/PCCS instead of MPA completion."
    return 0
  fi

  info "Host platform registration is complete."
}

populate_host_pccs_from_pckid() {
  [[ "$TDXTEST_POPULATE_HOST_PCCS_FROM_PCKID" == "1" ]] || return 0

  if [[ -z "$TDXTEST_PCCS_USER_TOKEN" ]]; then
    fail "TDXTEST_POPULATE_HOST_PCCS_FROM_PCKID=1 requires TDXTEST_PCCS_USER_TOKEN to be set"
  fi

  command -v PCKIDRetrievalTool >/dev/null 2>&1 || fail "PCKIDRetrievalTool is not installed on the host"

  info "Uploading host PCK ID data to PCCS via PCKIDRetrievalTool ..."
  sudo /usr/bin/PCKIDRetrievalTool \
    -url "$TDXTEST_PCCS_URL" \
    -user_token "$TDXTEST_PCCS_USER_TOKEN" \
    -use_secure_cert false >/tmp/tdx_pckid_upload.out 2>&1 || {
      sed -n '1,200p' /tmp/tdx_pckid_upload.out >&2 || true
      fail "PCKIDRetrievalTool upload to PCCS failed"
    }

  info "PCKIDRetrievalTool upload completed."
}

host_repo_qgs_requested() {
  [[ "$TDXTEST_MLDSA_USE_HOST_REPO_QGS" == "1" ]] || return 1
  [[ "$TDXTEST_MLDSA_SGX_MODE" != "SIM" ]] || return 1
  [[ -n "${TDXTEST_MLDSA_ALGS// }" ]] || return 1
  [[ "$TDXTEST_MLDSA_FORCE_LOCAL_QGS" != "1" ]] || return 1
}

ensure_host_signed_tdqe() {
  local tdqe_unsigned="$HOST_TDQE_LINUX_DIR/tdqe.so"
  local tdqe_signed="$HOST_TDQE_LINUX_DIR/libsgx_tdqe.signed.so"
  local tdqe_signed_major="$HOST_TDQE_LINUX_DIR/libsgx_tdqe.signed.so.1"
  local tdqe_config="$HOST_TDQE_LINUX_DIR/config.xml"
  local tdqe_key="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/dep/dcap_ae_test_key.pem"
  local sgx_sign="$HOST_SGX_SDK_ROOT/bin/x64/sgx_sign"

  make -C "$HOST_TDQE_LINUX_DIR" SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW tdqe.so

  if [[ ! -f "$tdqe_signed" || "$tdqe_unsigned" -nt "$tdqe_signed" ]]; then
    "$sgx_sign" sign -key "$tdqe_key" -enclave "$tdqe_unsigned" -out "$tdqe_signed" -config "$tdqe_config"
  fi

  ensure_major_link "$tdqe_signed" "$tdqe_signed_major"
}

build_host_repo_qgs_stack() {
  host_repo_qgs_requested || return 0

  [[ -d "$HOST_SGX_SDK_ROOT" ]] || fail "Missing host SGX SDK root: $HOST_SGX_SDK_ROOT"
  if [[ ! -f "$HOST_URTS_LIB_DIR/libsgx_urts.so" && -d "$HOST_SGX_SDK_ROOT/lib64" ]]; then
    HOST_URTS_LIB_DIR="$HOST_SGX_SDK_ROOT/lib64"
  fi

  info "Building host repo-local ML-DSA quote stack ..."
  make -C "$HOST_QGS_DIR" clean SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW >/dev/null 2>&1 || true
  make -C "$HOST_TDX_QUOTE_LINUX_DIR" clean SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW >/dev/null 2>&1 || true
  make -C "$HOST_PCE_WRAPPER_LINUX_DIR" clean SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW >/dev/null 2>&1 || true
  make -C "$HOST_TDQE_LINUX_DIR" clean SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW >/dev/null 2>&1 || true
  rm -f \
    "$HOST_QG_BUILD_LINUX_DIR"/libsgx_tdx_logic.so* \
    "$HOST_QG_BUILD_LINUX_DIR"/libsgx_pce_logic.so*

  ensure_host_signed_tdqe

  if [[ ! -f "$HOST_ID_ENCLAVE_LINUX_DIR/libsgx_id_enclave.signed.so" ]]; then
    make -C "$HOST_ID_ENCLAVE_LINUX_DIR" SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW
  fi
  ensure_major_link \
    "$HOST_ID_ENCLAVE_LINUX_DIR/libsgx_id_enclave.signed.so" \
    "$HOST_ID_ENCLAVE_LINUX_DIR/libsgx_id_enclave.signed.so.1"

  make -C "$HOST_PCE_WRAPPER_LINUX_DIR" SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW
  ensure_major_link \
    "$HOST_PCE_WRAPPER_LINUX_DIR/libsgx_pce_logic.so" \
    "$HOST_PCE_WRAPPER_LINUX_DIR/libsgx_pce_logic.so.1"

  make -C "$HOST_QCNL_LINUX_DIR" SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW
  make -C "$HOST_QPL_LINUX_DIR" SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW

  make -C "$HOST_TDX_QUOTE_LINUX_DIR" SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW
  ensure_major_link \
    "$HOST_TDX_QUOTE_LINUX_DIR/libsgx_tdx_logic.so" \
    "$HOST_TDX_QUOTE_LINUX_DIR/libsgx_tdx_logic.so.1"

  make -C "$HOST_QGS_DIR" SGX_SDK="$HOST_SGX_SDK_ROOT" SGX_MODE=HW
}

start_host_repo_qgs() {
  local qgs_ld_library_path

  host_repo_qgs_requested || return 0

  if [[ ! -f /usr/include/boost/asio.hpp ]]; then
    info "Installing missing host dependency for repo-local QGS: libboost-all-dev"
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libboost-all-dev
  fi

  build_host_repo_qgs_stack
  discover_host_pckcert_qeid_override || info "No host PCCS lookup QEID override discovered; repo-local QGS will use its native QEID"
  mkdir -p "$TDXTEST_LOG_DIR"
  rm -f "$HOST_REPO_QGS_LOG_PATH"

  if [[ -n "$HOST_REPO_QGS_PID" ]] && kill -0 "$HOST_REPO_QGS_PID" 2>/dev/null; then
    kill "$HOST_REPO_QGS_PID" 2>/dev/null || true
    wait "$HOST_REPO_QGS_PID" 2>/dev/null || true
  fi

  qgs_ld_library_path="$HOST_QGS_DIR:$HOST_TDX_QUOTE_LINUX_DIR:$HOST_PCE_WRAPPER_LINUX_DIR:$HOST_QG_BUILD_LINUX_DIR:$HOST_URTS_LIB_DIR"

  info "Starting host repo-local QGS on vsock port $HOST_REPO_QGS_PORT ..."
  QGS_TDQE_PATH="$HOST_TDQE_LINUX_DIR/libsgx_tdqe.signed.so.1" \
  TDX_MLDSA_PCKCERT_QEID_OVERRIDE="${HOST_PCKCERT_QEID_OVERRIDE:-}" \
  TDX_MLDSA_BOOTSTRAP_MODE="$HOST_REPO_QGS_BOOTSTRAP_MODE" \
  TDX_MLDSA_REQUIRE_FULL_DCAP="$HOST_REPO_QGS_REQUIRE_FULL_DCAP" \
  TDX_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST="$HOST_REPO_QGS_FORCE_REFRESH" \
  LD_LIBRARY_PATH="$qgs_ld_library_path:${LD_LIBRARY_PATH:-}" \
    "$HOST_QGS_DIR/qgs" --no-daemon "-p=$HOST_REPO_QGS_PORT" "-n=$HOST_REPO_QGS_THREADS" \
    >"$HOST_REPO_QGS_LOG_PATH" 2>&1 &
  HOST_REPO_QGS_PID=$!
  sleep 1

  if ! kill -0 "$HOST_REPO_QGS_PID" 2>/dev/null; then
    sed -n '1,200p' "$HOST_REPO_QGS_LOG_PATH" >&2 || true
    fail "Host repo-local QGS failed to start on vsock port $HOST_REPO_QGS_PORT"
  fi
}

stop_host_repo_qgs() {
  if [[ -n "$HOST_REPO_QGS_PID" ]] && kill -0 "$HOST_REPO_QGS_PID" 2>/dev/null; then
    kill "$HOST_REPO_QGS_PID" 2>/dev/null || true
    wait "$HOST_REPO_QGS_PID" 2>/dev/null || true
  fi
}

ensure_guest_tools() {
  [[ -x "$RUN_TD_SH" ]] || fail "Missing run_td helper: $RUN_TD_SH"
  [[ -x "$CREATE_TD_IMAGE_SH" ]] || fail "Missing create-td-image helper: $CREATE_TD_IMAGE_SH"
}

ensure_guest_image() {
  if [[ -f "$GUEST_IMAGE_PATH" ]]; then
    info "Using guest image: $GUEST_IMAGE_PATH"
    return 0
  fi

  [[ "$TDXTEST_CREATE_IMAGE" == "1" ]] || fail "Guest image missing and TDXTEST_CREATE_IMAGE=0: $GUEST_IMAGE_PATH"

  info "Creating TDX guest image for Ubuntu $GUEST_UBUNTU_VERSION ..."
  (
    cd "$TDX_TOOLS_DIR/image"
    sudo ./create-td-image.sh -v "$GUEST_UBUNTU_VERSION"
  )

  [[ -f "$DEFAULT_GUEST_IMAGE_PATH" ]] || fail "Guest image was not created at $DEFAULT_GUEST_IMAGE_PATH"

  if [[ "$GUEST_IMAGE_PATH" != "$DEFAULT_GUEST_IMAGE_PATH" ]]; then
    info "Copying default image to custom path: $GUEST_IMAGE_PATH"
    cp -f "$DEFAULT_GUEST_IMAGE_PATH" "$GUEST_IMAGE_PATH"
  fi
}

start_guest() {
  [[ "$TDXTEST_START_GUEST" == "1" ]] || return 0

  info "Stopping any previous guest started by run_td ..."
  "$RUN_TD_SH" --clean >/dev/null 2>&1 || true

  info "Starting TDX guest with image $GUEST_IMAGE_PATH ..."
  "$RUN_TD_SH" --image "$GUEST_IMAGE_PATH" --vcpus "$GUEST_VCPUS" --mem "$GUEST_MEM"
}

stop_guest() {
  [[ "$TDXTEST_STOP_GUEST_ON_EXIT" == "1" ]] || return 0
  info "Stopping guest on exit ..."
  "$RUN_TD_SH" --clean >/dev/null 2>&1 || true
}

ssh_guest() {
  sshpass -p "$GUEST_ROOT_PASSWORD" \
    ssh "${SSH_OPTS[@]}" "root@$GUEST_HOST" "$@"
}

ssh_guest_cmd() {
  local cmd="$1"
  ssh_guest "bash -lc $(printf '%q' "$cmd")"
}

is_local_tdx_guest_context() {
  for dev in /dev/tdx_guest /dev/tdx-guest /dev/tdx*; do
    if [[ -e "$dev" ]]; then
      return 0
    fi
  done
  return 1
}

ensure_guest_is_not_local_machine() {
  local local_machine_id=""
  local guest_machine_id=""

  [[ "$TDXTEST_COPY_REPO" == "1" ]] || return 0

  if [[ -r /etc/machine-id ]]; then
    local_machine_id="$(tr -d '\n' </etc/machine-id)"
  fi

  guest_machine_id="$(ssh_guest_cmd 'if [[ -r /etc/machine-id ]]; then tr -d "\\n" </etc/machine-id; fi' 2>/dev/null || true)"

  if [[ -n "$local_machine_id" && -n "$guest_machine_id" && "$local_machine_id" == "$guest_machine_id" ]]; then
    fail "Guest SSH endpoint resolves to this same machine. Refusing to copy the repo onto itself. Run this script from the host, or use TDXTEST_COPY_REPO=0 if the repo is already in the guest."
  fi
}

wait_for_guest_ssh() {
  local elapsed=0

  info "Waiting for guest SSH on ${GUEST_HOST}:${GUEST_SSH_PORT} ..."
  until ssh_guest "true" >/dev/null 2>&1; do
    sleep 5
    elapsed=$((elapsed + 5))
    if (( elapsed >= TDXTEST_SSH_WAIT_SECONDS )); then
      fail "Timed out waiting for guest SSH after ${TDXTEST_SSH_WAIT_SECONDS}s"
    fi
  done

  info "Guest SSH is reachable."
}

ensure_guest_tdx_device_if_required() {
  local require_guest_tdx=0

  if [[ "$TDXTEST_MLDSA_SGX_MODE" != "SIM" ]]; then
    require_guest_tdx=1
  fi

  if [[ "$TDXTEST_RUN_ECDSA" == "1" && "$TDXTEST_ECDSA_SGX_MODE" != "SIM" ]]; then
    require_guest_tdx=1
  fi

  (( require_guest_tdx == 1 )) || return 0

  info "Checking guest TDX device availability ..."
  if ! ssh_guest_cmd '
    for dev in /dev/tdx_guest /dev/tdx-guest /dev/tdx*; do
      if [[ -e "$dev" ]]; then
        exit 0
      fi
    done
    exit 1
  '; then
    fail "Guest is reachable over SSH but does not expose /dev/tdx_guest; refusing to run hardware attestation flows."
  fi

  info "Guest exposes a TDX attestation device."
}

install_guest_dependencies() {
  [[ "$TDXTEST_INSTALL_GUEST_DEPS" == "1" ]] || return 0

  info "Installing guest dependencies ..."
  ssh_guest_cmd "
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y \
      build-essential \
      cmake \
      curl \
      git \
      jq \
      libboost-all-dev \
      libcurl4-openssl-dev \
      libssl-dev \
      netcat-openbsd \
      nodejs \
      npm \
      pkg-config \
      python3 \
      python3-pip \
      zlib1g-dev
  "
}

configure_guest_quote_transport_port() {
  local port="$1"

  [[ "$TDXTEST_CONFIGURE_GUEST_VSOCK_ATTEST" == "1" ]] || return 0

  info "Configuring guest vsock quote transport on port $port ..."
  ssh_guest_cmd "
    cat >/etc/tdx-attest.conf <<'EOF'
port = $port
EOF
  "
}

configure_guest_quote_transport() {
  configure_guest_quote_transport_port "$HOST_SYSTEM_QGS_PORT"
}

configure_local_quote_transport_port() {
  local port="$1"

  [[ "$TDXTEST_CONFIGURE_GUEST_VSOCK_ATTEST" == "1" ]] || return 0

  info "Configuring local guest vsock quote transport on port $port ..."
  cat >/etc/tdx-attest.conf <<EOF
port = $port
EOF
}

copy_repo_to_guest() {
  [[ "$TDXTEST_COPY_REPO" == "1" ]] || return 0

  local archive_path
  local guest_archive_path="/tmp/tdx-pq-attestation-repo.tgz"

  info "Copying repo snapshot to guest: $GUEST_REPO_ROOT"
  archive_path="$(mktemp /tmp/tdx-pq-attestation-repo.XXXXXX.tgz)"
  (
    cd "$REPO_ROOT"
    tar \
      --exclude-vcs \
      --exclude='./tdx_tests/bin' \
      --exclude='./tdx_tests/direct/logs' \
      --exclude='./confidential-computing.tee.dcap-pq/QuoteGeneration/build' \
      --exclude='./confidential-computing.tee.dcap-pq/QuoteVerification/build' \
      --exclude='./confidential-computing.tee.dcap-pq/external/wasm-micro-runtime/product-mini/platforms/linux/build' \
      --exclude='./ssl_key' \
      --exclude='./confidential-computing.tee.dcap-pq/QuoteGeneration/pccs/service/ssl_key' \
      --exclude='./confidential-computing.tee.dcap-pq/QuoteGeneration/pccs/service/pckcache.db' \
      -czf "$archive_path" .
  )

  sshpass -p "$GUEST_ROOT_PASSWORD" \
    scp "${SCP_OPTS[@]}" "$archive_path" "root@$GUEST_HOST:$guest_archive_path"

  ssh_guest_cmd "
    rm -rf '$GUEST_REPO_ROOT'
    mkdir -p '$GUEST_REPO_ROOT'
    tar -xzf '$guest_archive_path' -C '$GUEST_REPO_ROOT'
    rm -f '$guest_archive_path'
  "

  rm -f "$archive_path"
}

sanitize_guest_repo_build_artifacts() {
  [[ "$TDXTEST_CLEAN_GUEST_BUILD" == "1" ]] || return 0

  info "Cleaning stale guest-side build artifacts ..."
  ssh_guest_cmd "
    set -e
    export SGX_SDK='$GUEST_SGX_SDK_ROOT'
    export SGX_MODE=HW

    rm -rf '$GUEST_REPO_ROOT/tdx_tests/bin'
    rm -rf '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/build/linux'
    rm -rf '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/build/linux'
    rm -rf '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/external/wasm-micro-runtime/product-mini/platforms/linux/build'

    for dir in \
      '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe/linux' \
      '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/ae/id_enclave/linux' \
      '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux' \
      '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/qcnl/linux' \
      '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/qpl/linux' \
      '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs' \
      '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux' \
      '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux' \
      '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/dcap_quoteverify/linux'; do
      if [[ -d \"\$dir\" ]]; then
        make -C \"\$dir\" clean SGX_SDK=\"\$SGX_SDK\" SGX_MODE=\"\$SGX_MODE\" >/dev/null 2>&1 || true
      fi
    done

    find '$GUEST_REPO_ROOT/confidential-computing.tee.dcap-pq' \
      \\( -path '*/linux/*' -o -path '*/build/*' -o -path '*/product-mini/platforms/linux/build/*' \\) \
      -type f \
      \\( -name '*.o' -o -name '*.d' -o -name '*.a' -o -name '*.so' -o -name '*.so.*' -o -name '*.map' -o -name '*.token' -o -name 'qgs' \\) \
      -delete

    if [[ -f '$GUEST_SGX_SDK_ROOT/lib64/libsgx_urts.so' ]]; then
      ln -sfn libsgx_urts.so '$GUEST_SGX_SDK_ROOT/lib64/libsgx_urts.so.2'
    fi
  "
}

run_remote_logged() {
  local name="$1"
  local cmd="$2"
  local log_path="$TDXTEST_LOG_DIR/$name.log"
  local status=0

  info "Running $name ..."
  set +e
  ssh_guest_cmd "$cmd" 2>&1 | tee "$log_path"
  status=${PIPESTATUS[0]}
  set -e

  if (( status != 0 )); then
    FAILURES+=("$name")
    error "$name failed with status $status"
  else
    info "$name passed"
  fi

  return 0
}

run_local_logged() {
  local name="$1"
  local cmd="$2"
  local log_path="$TDXTEST_LOG_DIR/$name.log"
  local status=0

  mkdir -p "$TDXTEST_LOG_DIR"

  info "Running $name ..."
  set +e
  bash -lc "$cmd" 2>&1 | tee "$log_path"
  status=${PIPESTATUS[0]}
  set -e

  if (( status != 0 )); then
    FAILURES+=("$name")
    error "$name failed with status $status"
  else
    info "$name passed"
  fi

  return 0
}

print_host_attestation_diagnostics() {
  info "Host attestation diagnostics:"

  if host_repo_qgs_requested; then
    if [[ -f "$HOST_REPO_QGS_LOG_PATH" ]]; then
      echo "[INFO] Host repo-local QGS log tail:"
      tail -n 120 "$HOST_REPO_QGS_LOG_PATH" || true
    else
      echo "[INFO] Host repo-local QGS log is not available."
    fi
  fi

  if systemctl is-active qgsd >/dev/null 2>&1; then
    echo "[INFO] Host qgsd journal tail:"
    journalctl -u qgsd -b 0 --no-pager | tail -n 60 || true
  else
    echo "[INFO] Host qgsd is not active."
  fi

  if systemctl is-active pccs >/dev/null 2>&1; then
    echo "[INFO] Host pccs journal tail:"
    journalctl -u pccs -b 0 --no-pager | tail -n 60 || true
  else
    echo "[INFO] Host pccs is not active."
  fi
}

run_guest_tests_locally() {
  local alg
  local cmd
  local local_mldsa_transport_port="$HOST_SYSTEM_QGS_PORT"

  mkdir -p "$TDXTEST_LOG_DIR"

  if [[ "$TDXTEST_MLDSA_SGX_MODE" != "SIM" && "${TDXTEST_MLDSA_FORCE_LOCAL_QGS:-}" != "1" && "$TDXTEST_MLDSA_USE_HOST_REPO_QGS" == "1" ]]; then
    local_mldsa_transport_port="$HOST_REPO_QGS_PORT"
  fi

  if [[ "$TDXTEST_MLDSA_SGX_MODE" != "SIM" && "${TDXTEST_MLDSA_FORCE_LOCAL_QGS:-}" != "1" ]]; then
    configure_local_quote_transport_port "$local_mldsa_transport_port"
  fi

  for alg in $TDXTEST_MLDSA_ALGS; do
    cmd="
      cd '$SCRIPT_DIR'
      timeout '$TDXTEST_MLDSA_TIMEOUT_SECONDS' \
        env SGX_MODE='$TDXTEST_MLDSA_SGX_MODE' TEST_MLDSA_ALG='$alg' \
        TDX_MLDSA_REQUIRE_FULL_DCAP='${TDXTEST_MLDSA_REQUIRE_FULL_DCAP:-1}' \
        TDX_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST='${TDXTEST_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST:-1}' \
        TDXTEST_MLDSA_FORCE_LOCAL_QGS='${TDXTEST_MLDSA_FORCE_LOCAL_QGS:-}' \
        TDXTEST_MLDSA_REMOTE_QGS_LABEL='${TDXTEST_MLDSA_REMOTE_QGS_LABEL:-host qgsd}' \
        ./run_mldsa_tdx_only_tests.sh
    "
    run_local_logged "mldsa_${alg}" "$cmd"
  done

  if [[ "$TDXTEST_RUN_ECDSA" == "1" ]]; then
    if [[ "$TDXTEST_ECDSA_SGX_MODE" != "SIM" ]]; then
      configure_local_quote_transport_port "$HOST_SYSTEM_QGS_PORT"
    fi

    cmd="
      cd '$SCRIPT_DIR'
      timeout '$TDXTEST_ECDSA_TIMEOUT_SECONDS' \
        env SGX_MODE='$TDXTEST_ECDSA_SGX_MODE' \
        TDXTEST_ECDSA_VERIFIER_MODE='${TDXTEST_ECDSA_VERIFIER_MODE}' \
        ./run_tdx_ecdsa_tests.sh
    "
    run_local_logged "ecdsa" "$cmd"
  fi
}

run_guest_phase_over_ssh() {
  local log_path="$TDXTEST_LOG_DIR/guest_self.log"
  local guest_remote_qgs_label="host qgsd"
  local guest_force_local_qgs="${TDXTEST_MLDSA_FORCE_LOCAL_QGS:-}"
  local mldsa_require_stock_env=""
  local mldsa_use_local_pcs_env=""
  local mldsa_local_pcs_port_env=""
  local mldsa_local_pcs_upstream_env=""
  local cmd
  local status=0

  mkdir -p "$TDXTEST_LOG_DIR"

  if [[ -n "$TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY" ]]; then
    mldsa_require_stock_env="TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY='${TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY}'"
  fi
  if [[ -n "$TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY" ]]; then
    mldsa_use_local_pcs_env="TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY='${TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY}'"
  fi
  if [[ -n "$TDXTEST_MLDSA_LOCAL_PCS_PORT" ]]; then
    mldsa_local_pcs_port_env="TDXTEST_MLDSA_LOCAL_PCS_PORT='${TDXTEST_MLDSA_LOCAL_PCS_PORT}'"
  fi
  if [[ -n "$TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN" ]]; then
    mldsa_local_pcs_upstream_env="TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN='${TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN}'"
  fi

  if [[ "$TDXTEST_MLDSA_SGX_MODE" != "SIM" && -z "$guest_force_local_qgs" ]]; then
    if host_repo_qgs_requested; then
      guest_remote_qgs_label="host repo-local QGS"
    fi
  fi

  cmd="
    cd '$GUEST_TEST_DIR'
    timeout '$((TDXTEST_MLDSA_TIMEOUT_SECONDS + TDXTEST_ECDSA_TIMEOUT_SECONDS + 600))' \
      env \
        TDXTEST_EXEC_MODE='guest' \
        TDXTEST_RUN_ECDSA='$TDXTEST_RUN_ECDSA' \
        TDXTEST_MLDSA_ALGS='${TDXTEST_MLDSA_ALGS}' \
        TDXTEST_MLDSA_SGX_MODE='${TDXTEST_MLDSA_SGX_MODE}' \
        TDXTEST_MLDSA_FORCE_LOCAL_QGS='${guest_force_local_qgs}' \
        TDXTEST_MLDSA_REMOTE_QGS_LABEL='${guest_remote_qgs_label}' \
        TDXTEST_MLDSA_USE_HOST_REPO_QGS='${TDXTEST_MLDSA_USE_HOST_REPO_QGS}' \
        TDXTEST_MLDSA_REQUIRE_FULL_DCAP='${TDXTEST_MLDSA_REQUIRE_FULL_DCAP:-1}' \
        TDXTEST_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST='${TDXTEST_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST:-1}' \
        $mldsa_require_stock_env $mldsa_use_local_pcs_env \
        $mldsa_local_pcs_port_env $mldsa_local_pcs_upstream_env \
        TDXTEST_HOST_SYSTEM_QGS_PORT='${HOST_SYSTEM_QGS_PORT}' \
        TDXTEST_MLDSA_HOST_REPO_QGS_PORT='${HOST_REPO_QGS_PORT}' \
        TDXTEST_CONFIGURE_GUEST_VSOCK_ATTEST='${TDXTEST_CONFIGURE_GUEST_VSOCK_ATTEST}' \
        TDXTEST_ECDSA_SGX_MODE='${TDXTEST_ECDSA_SGX_MODE}' \
        TDXTEST_ECDSA_VERIFIER_MODE='${TDXTEST_ECDSA_VERIFIER_MODE}' \
        TDXTEST_MLDSA_TIMEOUT_SECONDS='${TDXTEST_MLDSA_TIMEOUT_SECONDS}' \
        TDXTEST_ECDSA_TIMEOUT_SECONDS='${TDXTEST_ECDSA_TIMEOUT_SECONDS}' \
        TDXTEST_LOG_DIR='${GUEST_TEST_DIR}/logs' \
        ./run_host_tdx_guest_repo_tests.sh
  "

  info "Running guest-side self orchestration ..."
  set +e
  ssh_guest_cmd "$cmd" 2>&1 | tee "$log_path"
  status=${PIPESTATUS[0]}
  set -e

  if (( status != 0 )); then
    FAILURES+=("guest_self")
    error "guest_self failed with status $status"
  else
    info "guest_self passed"
  fi

  return 0
}

run_guest_tests() {
  local alg
  local cmd
  local mldsa_force_local_qgs_env=""
  local mldsa_remote_qgs_label_env=""
  local mldsa_require_stock_env=""
  local mldsa_use_local_pcs_env=""
  local mldsa_local_pcs_port_env=""
  local mldsa_local_pcs_upstream_env=""

  mkdir -p "$TDXTEST_LOG_DIR"

  if [[ -n "$TDXTEST_MLDSA_FORCE_LOCAL_QGS" ]]; then
    mldsa_force_local_qgs_env="TDXTEST_MLDSA_FORCE_LOCAL_QGS='$TDXTEST_MLDSA_FORCE_LOCAL_QGS'"
  fi
  if [[ -n "$TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY" ]]; then
    mldsa_require_stock_env="TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY='$TDXTEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY'"
  fi
  if [[ -n "$TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY" ]]; then
    mldsa_use_local_pcs_env="TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY='$TDXTEST_MLDSA_USE_LOCAL_PCS_IDENTITY'"
  fi
  if [[ -n "$TDXTEST_MLDSA_LOCAL_PCS_PORT" ]]; then
    mldsa_local_pcs_port_env="TDXTEST_MLDSA_LOCAL_PCS_PORT='$TDXTEST_MLDSA_LOCAL_PCS_PORT'"
  fi
  if [[ -n "$TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN" ]]; then
    mldsa_local_pcs_upstream_env="TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN='$TDXTEST_MLDSA_LOCAL_PCS_UPSTREAM_ORIGIN'"
  fi

  if [[ "$TDXTEST_MLDSA_SGX_MODE" != "SIM" && -z "$TDXTEST_MLDSA_FORCE_LOCAL_QGS" ]]; then
    if host_repo_qgs_requested; then
      configure_guest_quote_transport_port "$HOST_REPO_QGS_PORT"
      mldsa_remote_qgs_label_env="TDXTEST_MLDSA_REMOTE_QGS_LABEL='host repo-local QGS'"
    else
      configure_guest_quote_transport_port "$HOST_SYSTEM_QGS_PORT"
      mldsa_remote_qgs_label_env="TDXTEST_MLDSA_REMOTE_QGS_LABEL='host qgsd'"
    fi
  fi

  for alg in $TDXTEST_MLDSA_ALGS; do
    cmd="
      cd '$GUEST_TEST_DIR'
      timeout '$TDXTEST_MLDSA_TIMEOUT_SECONDS' \
        env SGX_MODE='$TDXTEST_MLDSA_SGX_MODE' TEST_MLDSA_ALG='$alg' \
        TDX_MLDSA_REQUIRE_FULL_DCAP='${TDXTEST_MLDSA_REQUIRE_FULL_DCAP:-1}' \
        TDX_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST='${TDXTEST_MLDSA_FORCE_REFRESH_ON_QGS_REQUEST:-1}' \
        $mldsa_force_local_qgs_env $mldsa_remote_qgs_label_env \
        $mldsa_require_stock_env $mldsa_use_local_pcs_env \
        $mldsa_local_pcs_port_env $mldsa_local_pcs_upstream_env \
        ./run_mldsa_tdx_only_tests.sh
    "
    run_remote_logged "mldsa_${alg}" "$cmd"
  done

  if [[ "$TDXTEST_RUN_ECDSA" == "1" ]]; then
    if [[ "$TDXTEST_ECDSA_SGX_MODE" != "SIM" ]]; then
      configure_guest_quote_transport_port "$HOST_SYSTEM_QGS_PORT"
    fi

    cmd="
      cd '$GUEST_TEST_DIR'
      timeout '$TDXTEST_ECDSA_TIMEOUT_SECONDS' \
        env SGX_MODE='$TDXTEST_ECDSA_SGX_MODE' \
        TDXTEST_ECDSA_VERIFIER_MODE='${TDXTEST_ECDSA_VERIFIER_MODE}' \
        ./run_tdx_ecdsa_tests.sh
    "
    run_remote_logged "ecdsa" "$cmd"
  fi
}

print_summary_and_exit() {
  if (( ${#FAILURES[@]} == 0 )); then
    info "All requested guest-side test flows completed successfully."
    info "Logs: $TDXTEST_LOG_DIR"
    exit 0
  fi

  error "One or more guest-side test flows failed:"
  printf '  - %s\n' "${FAILURES[@]}" >&2
  print_host_attestation_diagnostics
  error "Logs: $TDXTEST_LOG_DIR"
  exit 1
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  if [[ "$TDXTEST_EXEC_MODE" == "guest" ]] || { [[ -z "$TDXTEST_EXEC_MODE" ]] && is_local_tdx_guest_context; }; then
    if [[ "$TDXTEST_EXEC_MODE" != "guest" ]]; then
      info "Detected local TDX guest context; running the guest-side phase locally."
    fi
    run_guest_tests_locally
    print_summary_and_exit
  fi

  need_cmd bash
  need_cmd ssh
  need_cmd tar
  need_cmd tee
  need_cmd timeout
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
  start_host_repo_qgs
  run_guest_phase_over_ssh
  print_summary_and_exit
}

cleanup_exit() {
  stop_host_repo_qgs
  stop_guest
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  trap cleanup_exit EXIT
  main "$@"
fi
