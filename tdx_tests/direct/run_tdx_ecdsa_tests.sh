#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
TDX_ATTEST_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux"
QGS_MSG_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs_msg_lib/linux"
QVL_INCLUDE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc"
QV_INCLUDE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/dcap_quoteverify/inc"
QCNL_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/qcnl/linux"
QPL_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/qpl/linux"
QV_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/dcap_quoteverify/linux"
QG_BUILD_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/build/linux"
QV_BUILD_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/build/linux"
LOCAL_SGX_SDK="$TESTS_DIR/sgxsdk"
LOCAL_PREBUILT_OPENSSL_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/prebuilt/openssl"
LOCAL_SGXSSL_PACKAGE_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteVerification/sgxssl/Linux/package"
LOCAL_QCNL_CONF="$TESTS_DIR/sgx_default_qcnl_local_test.conf"
LOCAL_VERIFIER_PORT="${TDX_LOCAL_VERIFIER_PORT:-8123}"
LOCAL_VERIFIER_PID=""
BIN_DIR="$TESTS_DIR/bin"
VERIFIER_BIN="$BIN_DIR/local_tdx_verifier"
VERIFIER_LOG="$BIN_DIR/local_tdx_verifier.log"
TEST_APP_BIN="$BIN_DIR/test_app_direct"

mkdir -p "$BIN_DIR"

TDX_GUEST_DEV=""
for dev in /dev/tdx_guest /dev/tdx-guest /dev/tdx*; do
	if [[ -e "$dev" ]]; then
		TDX_GUEST_DEV="$dev"
		break
	fi
done

if [[ -z "$TDX_GUEST_DEV" ]]; then
	echo "[ERROR] Nessun device TDX trovato (/dev/tdx*)."
	exit 1
fi

if [[ ! -r "$TDX_GUEST_DEV" || ! -w "$TDX_GUEST_DEV" ]]; then
	echo "[ERROR] Permessi insufficienti su $TDX_GUEST_DEV ($(ls -l "$TDX_GUEST_DEV"))"
	echo "[ERROR] Esegui con privilegi elevati (es. sudo -E ./run_tdx_tests.sh)"
	exit 1
fi

if [[ "$TDX_GUEST_DEV" != "/dev/tdx_guest" ]]; then
	echo "[INFO] Userò device TDX: $TDX_GUEST_DEV"
fi

echo "[INFO] Uso solo TDX (/dev/tdx*), senza flow SGX/quote-wrapper."
echo "[INFO] Building libtdx_attest..."
make -C "$TDX_ATTEST_LINUX_DIR"

if [[ -d "$LOCAL_SGX_SDK" ]]; then
	export SGX_SDK="$LOCAL_SGX_SDK"
fi

# Force repo-local DCAP/QV consumers to use a test-oriented QCNL config instead
# of the default localhost PCCS template, which can stall quote verification.
export QCNL_CONF_PATH="$LOCAL_QCNL_CONF"

if [[ ! -d "$LOCAL_PREBUILT_OPENSSL_DIR/inc" || ! -d "$LOCAL_PREBUILT_OPENSSL_DIR/lib/linux64" ]]; then
	echo "[INFO] Preparing repo-local OpenSSL compatibility paths for DCAP builds..."
	mkdir -p "$LOCAL_PREBUILT_OPENSSL_DIR/lib"
	ln -sfn /usr/include "$LOCAL_PREBUILT_OPENSSL_DIR/inc"
	ln -sfn /usr/lib/x86_64-linux-gnu "$LOCAL_PREBUILT_OPENSSL_DIR/lib/linux64"
fi

if [[ ! -f "$LOCAL_SGXSSL_PACKAGE_DIR/include/openssl/opensslconf.h" ]]; then
	echo "[ERROR] Missing repo-local SGXSSL package at:"
	echo "        $LOCAL_SGXSSL_PACKAGE_DIR"
	echo "[ERROR] QuoteVerification/dcap_quoteverify cannot be built from your checkout without SGXSSL."
	echo "[ERROR] Build or populate QuoteVerification/sgxssl first, then rerun ./run_tdx_tests.sh."
	exit 1
fi

echo "[INFO] Building repo-local QCNL/QPL/QuoteVerification libraries..."
make -C "$QCNL_LINUX_DIR"
make -C "$QPL_LINUX_DIR"
make -C "$QV_LINUX_DIR"
echo "[INFO] Using QCNL config: $QCNL_CONF_PATH"

echo "[INFO] Verifier env support:"
echo "       - TDX_VERIFIER_CHALLENGE_URL / TDX_VERIFIER_CHALLENGE_METHOD / TDX_VERIFIER_CHALLENGE_BODY"
echo "       - TDX_VERIFIER_CHALLENGE_HEX"
echo "       - TDX_VERIFIER_SUBMIT_URL / TDX_VERIFIER_SUBMIT_METHOD"
echo "       - TDX_VERIFIER_AUTH_HEADER / TDX_VERIFIER_EXTRA_HEADER"

cleanup() {
	if [[ -n "$LOCAL_VERIFIER_PID" ]]; then
		kill "$LOCAL_VERIFIER_PID" 2>/dev/null || true
		wait "$LOCAL_VERIFIER_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT

if [[ -z "${TDX_VERIFIER_CHALLENGE_URL:-}" && -z "${TDX_VERIFIER_SUBMIT_URL:-}" && -z "${TDX_VERIFIER_CHALLENGE_HEX:-}" ]]; then
	# Bring up a repo-local verifier automatically when no external verifier is configured.
	echo "[INFO] Building local TDX verifier..."
	g++ -std=c++14 -O2 -Wall -Wextra -Werror \
		-I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper" \
		-I"$QVL_INCLUDE_DIR" \
		-I"$QV_INCLUDE_DIR" \
		-I"$TESTS_DIR/common" \
		-I"$TESTS_DIR/sgxsdk/include" \
		"$TESTS_DIR/verifier/local_tdx_verifier.cpp" \
		"$TESTS_DIR/common/utils.cpp" \
		-L"$QV_BUILD_LINUX_DIR" \
		-L"$QG_BUILD_LINUX_DIR" \
		-l:libsgx_dcap_quoteverify.so -l:libdcap_quoteprov.so -l:libsgx_default_qcnl_wrapper.so \
		-lcurl -lpthread -ldl \
		-o "$VERIFIER_BIN"

	echo "[INFO] Starting local TDX verifier on 127.0.0.1:$LOCAL_VERIFIER_PORT ..."
	LD_LIBRARY_PATH="$QV_BUILD_LINUX_DIR:$QG_BUILD_LINUX_DIR:${LD_LIBRARY_PATH:-}" \
		"$VERIFIER_BIN" "$LOCAL_VERIFIER_PORT" >"$VERIFIER_LOG" 2>&1 &
	LOCAL_VERIFIER_PID=$!

	# Wait until the local verifier is reachable before starting the guest-side test.
	for _ in $(seq 1 30); do
		if curl -fsS "http://127.0.0.1:$LOCAL_VERIFIER_PORT/challenge" >/dev/null 2>&1; then
			break
		fi
		sleep 1
	done

	if ! curl -fsS "http://127.0.0.1:$LOCAL_VERIFIER_PORT/challenge" >/dev/null 2>&1; then
		echo "[ERROR] Local verifier failed to start. Log:"
		sed -n '1,200p' "$VERIFIER_LOG"
		exit 1
	fi

	export TDX_VERIFIER_CHALLENGE_URL="http://127.0.0.1:$LOCAL_VERIFIER_PORT/challenge"
	export TDX_VERIFIER_SUBMIT_URL="http://127.0.0.1:$LOCAL_VERIFIER_PORT/submit"
	echo "[INFO] Using local verifier endpoints:"
	echo "       - $TDX_VERIFIER_CHALLENGE_URL"
	echo "       - $TDX_VERIFIER_SUBMIT_URL"
fi

echo "[INFO] Building direct test_app..."
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
	-I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper" \
	-I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest" \
	-I"$TESTS_DIR/common" \
	-I/usr/include/x86_64-linux-gnu \
	"$TESTS_DIR/direct/test_tdx_quote_wrapper.cpp" \
	"$TESTS_DIR/common/utils.cpp" \
	-L"$TDX_ATTEST_LINUX_DIR" -ltdx_attest \
	-lcurl -lpthread -ldl \
	-o "$TEST_APP_BIN"

echo "[INFO] Running test_app_direct (TDX-only)..."
LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$QGS_MSG_LINUX_DIR:$QV_BUILD_LINUX_DIR:$QG_BUILD_LINUX_DIR:${LD_LIBRARY_PATH:-}" \
	"$TEST_APP_BIN"

echo "[INFO] Done (TDX-only)."
