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
TDXTEST_MLDSA_ALGS="${TDXTEST_MLDSA_ALGS:-65 87}"
TDXTEST_MLDSA_SGX_MODE="${TDXTEST_MLDSA_SGX_MODE:-SIM}"
TDXTEST_ECDSA_SGX_MODE="${TDXTEST_ECDSA_SGX_MODE:-HW}"
TDXTEST_SSH_WAIT_SECONDS="${TDXTEST_SSH_WAIT_SECONDS:-300}"
TDXTEST_MLDSA_TIMEOUT_SECONDS="${TDXTEST_MLDSA_TIMEOUT_SECONDS:-5400}"
TDXTEST_ECDSA_TIMEOUT_SECONDS="${TDXTEST_ECDSA_TIMEOUT_SECONDS:-3600}"
TDXTEST_LOG_DIR="${TDXTEST_LOG_DIR:-$SCRIPT_DIR/logs}"

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
  TDXTEST_CONFIGURE_GUEST_VSOCK_ATTEST 1=write /etc/tdx-attest.conf with port 4050
  TDXTEST_RUN_ECDSA                 1=run ECDSA flow, 0=skip it
  TDXTEST_STOP_GUEST_ON_EXIT        1=stop guest at end, 0=leave it running
  TDXTEST_MLDSA_ALGS                default: "65 87"
  TDXTEST_MLDSA_SGX_MODE            default: $TDXTEST_MLDSA_SGX_MODE
  TDXTEST_ECDSA_SGX_MODE            default: $TDXTEST_ECDSA_SGX_MODE
  TDXTEST_SSH_WAIT_SECONDS          default: 300
  TDXTEST_MLDSA_TIMEOUT_SECONDS     default: 5400
  TDXTEST_ECDSA_TIMEOUT_SECONDS     default: 3600
  TDXTEST_LOG_DIR                   default: $TDXTEST_LOG_DIR
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

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing host command: $1"
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

configure_guest_quote_transport() {
  [[ "$TDXTEST_CONFIGURE_GUEST_VSOCK_ATTEST" == "1" ]] || return 0

  info "Configuring guest vsock quote transport ..."
  ssh_guest_cmd "
    cat >/etc/tdx-attest.conf <<'EOF'
port = 4050
EOF
  "
}

copy_repo_to_guest() {
  [[ "$TDXTEST_COPY_REPO" == "1" ]] || return 0

  info "Copying repo snapshot to guest: $GUEST_REPO_ROOT"
  (
    cd "$REPO_ROOT"
    tar \
      --exclude-vcs \
      --exclude='./tdx_tests/bin' \
      --exclude='./tdx_tests/direct/logs' \
      --exclude='./confidential-computing.tee.dcap-pq/QuoteGeneration/build' \
      --exclude='./confidential-computing.tee.dcap-pq/QuoteVerification/build' \
      --exclude='./confidential-computing.tee.dcap-pq/external/wasm-micro-runtime/product-mini/platforms/linux/build' \
      --exclude='./confidential-computing.tee.dcap-pq/QuoteGeneration/pccs/service/ssl_key' \
      --exclude='./confidential-computing.tee.dcap-pq/QuoteGeneration/pccs/service/pckcache.db' \
      -czf - .
  ) | ssh_guest_cmd "
    rm -rf '$GUEST_REPO_ROOT'
    mkdir -p '$GUEST_REPO_ROOT'
    tar -xzf - -C '$GUEST_REPO_ROOT'
  "
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

print_host_attestation_diagnostics() {
  info "Host attestation diagnostics:"

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

run_guest_tests() {
  local alg
  local cmd

  mkdir -p "$TDXTEST_LOG_DIR"

  for alg in $TDXTEST_MLDSA_ALGS; do
    cmd="
      cd '$GUEST_TEST_DIR'
      timeout '$TDXTEST_MLDSA_TIMEOUT_SECONDS' \
        env SGX_MODE='$TDXTEST_MLDSA_SGX_MODE' TEST_MLDSA_ALG='$alg' \
        ./run_mldsa_tdx_only_tests.sh
    "
    run_remote_logged "mldsa_${alg}" "$cmd"
  done

  if [[ "$TDXTEST_RUN_ECDSA" == "1" ]]; then
    cmd="
      cd '$GUEST_TEST_DIR'
      timeout '$TDXTEST_ECDSA_TIMEOUT_SECONDS' \
        env SGX_MODE='$TDXTEST_ECDSA_SGX_MODE' \
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
  install_guest_dependencies
  configure_guest_quote_transport
  copy_repo_to_guest
  sanitize_guest_repo_build_artifacts
  run_guest_tests
  print_summary_and_exit
}

trap stop_guest EXIT

main "$@"
