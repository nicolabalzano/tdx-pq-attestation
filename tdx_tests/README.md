# TDX Test Layout

This directory is organized by test role instead of mixing runners, sources,
helpers, verifier code, and generated binaries at the top level.

## Layout

- `bin/`
  - generated test binaries and runtime logs
- `common/`
  - shared helpers used by multiple test flows
  - example: verifier/quote submission utilities
- `direct/`
  - TDX direct-path tests and runner scripts
  - intended for environments that have `tdx_guest` but not necessarily the SGX PCE device path
- `format/`
  - quote/header static layout checks
- `tdqe/`
  - TDQE-local ML-DSA backend and layout tests
- `verifier/`
  - repo-local verifier implementation used by the ECDSA direct flow
- `wrapper/`
  - wrapper-facing ML-DSA and algorithm-selection test sources
  - helper runner scripts for wrapper tests
- `sgxsdk/`
  - repo-local SDK copy used by the local test/build scripts
- top-level compatibility entry points
  - kept only for convenience and backward-compatible commands
  - example: `./tdx_tests/run_tdx_ecdsa_tests.sh`

## Recommended entry points

- General TDX smoke flow:
  - `./tdx_tests/run_tdx_ecdsa_tests.sh`
- TDX-only ML-DSA component and capability flow:
  - `./tdx_tests/direct/run_mldsa_tdx_only_tests.sh`
  - this runner now starts the repo-local `qgs` on a repo-local Unix socket and forces `libtdx_attest` to use it instead of `configfs`
- ML-DSA wrapper end-to-end flow:
  - `./tdx_tests/wrapper/run_mldsa_e2e.sh`
