#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TDX_QUOTE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux"
TDX_ATTEST_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux"
PCE_WRAPPER_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux"
TDQE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/tdqe/linux"
ID_ENCLAVE_LINUX_DIR="$REPO_ROOT/confidential-computing.tee.dcap-pq/ae/id_enclave/linux"

if [[ -z "${SGX_SDK:-}" ]]; then
	if [[ -x "$REPO_ROOT/tdx_tests/sgxsdk/bin/x64/sgx_edger8r" ]]; then
		export SGX_SDK="$REPO_ROOT/tdx_tests/sgxsdk"
	elif [[ -x "/opt/intel/sgxsdk/bin/x64/sgx_edger8r" ]]; then
		export SGX_SDK="/opt/intel/sgxsdk"
	fi
fi

if [[ -n "${SGX_SDK:-}" && -f "$SGX_SDK/environment" ]]; then
	# shellcheck source=/dev/null
	source "$SGX_SDK/environment"
fi

if [[ -z "${SGX_SDK:-}" || ! -x "$SGX_SDK/bin/x64/sgx_edger8r" ]]; then
	echo "[ERROR] SGX SDK non trovato o incompleto."
	echo "[ERROR] Imposta SGX_SDK oppure esegui: source /opt/intel/sgxsdk/environment"
	exit 1
fi

if [[ ! -e "/dev/tdx_guest" ]]; then
	echo "[ERROR] /dev/tdx_guest non esiste: il guest non espone l'interfaccia TDX attestation."
	exit 1
fi

if [[ ! -r "/dev/tdx_guest" || ! -w "/dev/tdx_guest" ]]; then
	echo "[ERROR] Permessi insufficienti su /dev/tdx_guest ($(ls -l /dev/tdx_guest))"
	echo "[ERROR] Esegui con privilegi elevati (es. sudo -E ./run_tdx_tests.sh)"
	exit 1
fi

URTS_SO2_PATH="$(ldconfig -p 2>/dev/null | awk '/libsgx_urts\.so\.2/{print $NF; exit}')"
if [[ -z "$URTS_SO2_PATH" ]]; then
	echo "[ERROR] Runtime PSW SGX non trovato: manca libsgx_urts.so.2 nel linker di sistema."
	echo "[ERROR] Installa PSW/runtime SGX (non solo SDK) e riprova."
	exit 1
fi

echo "[INFO] Build+run REAL TDX quote test..."

echo "[INFO] Building TDQE and ID Enclave artifacts..."
make -C "$TDQE_LINUX_DIR"
make -C "$ID_ENCLAVE_LINUX_DIR"

pushd "$TDX_QUOTE_LINUX_DIR" >/dev/null

echo "[INFO] Building quote wrapper test_app (real flow)..."
make test_app

if [[ -f "$TDX_QUOTE_LINUX_DIR/libsgx_tdx_logic.so" && ! -e "$TDX_QUOTE_LINUX_DIR/libsgx_tdx_logic.so.1" ]]; then
	ln -s libsgx_tdx_logic.so "$TDX_QUOTE_LINUX_DIR/libsgx_tdx_logic.so.1"
fi
if [[ -f "$PCE_WRAPPER_LINUX_DIR/libsgx_pce_logic.so" && ! -e "$PCE_WRAPPER_LINUX_DIR/libsgx_pce_logic.so.1" ]]; then
	ln -s libsgx_pce_logic.so "$PCE_WRAPPER_LINUX_DIR/libsgx_pce_logic.so.1"
fi
if [[ -f "$TDX_ATTEST_LINUX_DIR/libtdx_attest.so" && ! -e "$TDX_ATTEST_LINUX_DIR/libtdx_attest.so.1" ]]; then
	ln -s libtdx_attest.so "$TDX_ATTEST_LINUX_DIR/libtdx_attest.so.1"
fi

echo "[INFO] Running test_app (real TDX attestation path)..."
# Nota: non anteporre $SGX_SDK/lib64 per evitare di caricare una uRTS non-PSW.
LD_LIBRARY_PATH=".:$TDX_ATTEST_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:${LD_LIBRARY_PATH:-}" ./test_app

popd >/dev/null

echo "[INFO] Done."