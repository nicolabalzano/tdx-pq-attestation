# ML-DSA TDX Work TODO

This file tracks the current state of the ML-DSA TDX work in a practical format.
It is not a historical changelog. It is a working document for what is done, what is still open, and what should happen next.

## Scope

The goal is to support ML-DSA in the TDX quote flow while keeping the trust boundary intact.

That means:
- keep quote signing inside the trusted TDQE path
- do not export the ML-DSA private key outside TDQE
- preserve the existing ECDSA path
- distinguish clearly between:
  - the standard verifier path
  - the repo-local trusted test path

## Current Status

### Working today

- The repo-local trusted ML-DSA quote generation path works in `SGX_MODE=SIM`.
- The direct ML-DSA capability probe generates a real ML-DSA quote.
- The direct probe confirms:
  - ML-DSA attestation key selection
  - `att_key_type = 5`
  - quote size `7102`
- The QVL parser accepts ML-DSA quote v4 structure.
- The QVL verifier branch for ML-DSA exists and has unit-test coverage.
- In `SIM`, when standard DCAP collateral is not available, the local ML-DSA verifier fallback succeeds.
- Outside `SIM`, the runner does not force the local verifier path.

### Not fully working yet

- Standard DCAP end-to-end verification for ML-DSA is not complete in the current local setup.
- The blocker is not quote parsing anymore.
- The blocker is standard certification data / collateral availability for the generated ML-DSA quote.
- In the local setup, the quote still falls back to local-only certification data when platform collateral is unavailable.

## Security Constraints

- [x] Do not move ML-DSA signing outside TDQE.
- [x] Do not export the ML-DSA private key outside TDQE.
- [x] Keep local-only verification behavior limited to simulation/testing.
- [x] Do not relax real-platform behavior implicitly.
- [x] Keep the `PLATFORM_UNKNOWN` fallback opt-in and limited to the local SIM runner.

## Completed Work

### 1. Quote format and public wrapper plumbing

- [x] Added `SGX_QL_ALG_MLDSA_65`.
- [x] Added ML-DSA quote signature/public-key layout types.
- [x] Updated the TDX wrapper to accept ML-DSA contexts.
- [x] Propagated `algorithm_id` through the wrapper into TDQE ECALLs.

### 2. Trusted ML-DSA generation path

- [x] Introduced the trusted TDX-only bootstrap path.
- [x] Kept the legacy PCE bootstrap path separate.
- [x] Implemented ML-DSA blob handling in the trusted path.
- [x] Implemented ML-DSA quote-size and quote-generation logic.
- [x] Fixed the ID enclave path resolution for the repo-local flow.
- [x] Brought the repo-local TDQE/ID enclave/QGS build up in `SIM`.

### 3. Local test harness and probes

- [x] Added the TDQE simulation loader probe.
- [x] Added the wrapper ML-DSA init-quote probe.
- [x] Added the wrapper ML-DSA algorithm-selection test.
- [x] Added the direct TDX ML-DSA capability probe.
- [x] Added the ML-DSA quote verification probe.

### 4. Verifier-side ML-DSA support

- [x] Extended QVL quote parsing for ML-DSA quote v4 layout.
- [x] Extended QVL quote structures/constants for ML-DSA.
- [x] Added the ML-DSA verifier branch using `tdqe_mldsa65_verify(...)`.
- [x] Added unit tests for:
  - ML-DSA quote parsing
  - QE certification-data extraction from ML-DSA quotes
  - ML-DSA verifier branch execution
- [x] Integrated ML-DSA helper sources into the QVL CMake build.

### 5. Local PCCS / collateral test setup

- [x] Added local PCCS startup to the ML-DSA runner for `SIM`.
- [x] Added self-signed TLS bootstrap for local PCCS.
- [x] Wired the QCNL test config to the local PCCS.
- [x] Added optional offline collateral preload support.

### 6. Local ML-DSA verification fallback

- [x] Added a local verification fallback for `SIM` when standard DCAP collateral is unavailable.
- [x] The local fallback verifies:
  - `SHA256(attest_pub_key || qe_auth_data)` against QE report data
  - the ML-DSA quote signature using `tdqe_mldsa65_verify(...)`
- [x] Limited this fallback to the local simulation path.

### 7. Log cleanup

- [x] Reduced noisy debug output in normal runs.
- [x] Kept detailed QCNL/QPL/TDX/QV debug available behind:
  - `TDX_MLDSA_VERBOSE_DEBUG=1`
- [x] Updated probe messages to describe the real limitation precisely:
  - standard collateral path unavailable in local setup
  - local ML-DSA verification succeeded

## Open Issues

### A. Standard collateral path for ML-DSA

Status:
- Open

Problem:
- The generated ML-DSA quote is structurally valid.
- The standard verifier path still depends on certification data/collateral that is not available in the current local setup.
- As a result, the quote falls back to local-only certification data and the standard collateral flow cannot complete.

What this is not:
- not a quote-format parsing problem
- not a local ML-DSA signature-verification problem
- not a trust-boundary problem

What is needed:
- generate verifier-compatible certification data on a real platform path

### B. Real-platform validation

Status:
- Open

Problem:
- The current repo-local `SIM` setup proves generation and local verification.
- It does not by itself prove standard DCAP end-to-end behavior on real SGX/TDX hardware.

What is needed:
- run the same ML-DSA quote flow on a real SGX/TDX system
- confirm that:
  - no local-only fallback is used
  - platform collateral retrieval succeeds
  - standard verifier path completes

### C. Remaining test coverage gaps

Status:
- Open

Missing or incomplete tests:
- separate ECDSA/ML-DSA blob coexistence coverage
- malformed ML-DSA quote negative tests
- blob corruption / wrong-size negative tests
- unknown algorithm / unsupported algorithm negative tests

## Test Matrix

### Repo-local SIM path

- [x] TDQE ML-DSA adapter test
- [x] Quote header ML-DSA layout test
- [x] TDQE ML-DSA quote layout test
- [x] TDQE simulation loader probe
- [x] Wrapper ML-DSA init-quote probe
- [x] Wrapper ML-DSA algorithm-selection test
- [x] ML-DSA quote verification probe
- [x] Direct TDX ML-DSA capability probe

### Standard verifier path

- [x] QVL parse/validate support for ML-DSA v4
- [x] QVL QE certification-data extraction support for ML-DSA v4
- [x] QVL ML-DSA verifier branch unit test
- [ ] Full standard DCAP collateral-based verification on a real compatible platform

### Regression coverage

- [ ] ECDSA and ML-DSA blob coexistence
- [ ] Blob label separation checks
- [ ] Blob-type mismatch rejection
- [ ] Blob-size mismatch rejection
- [ ] Malformed ML-DSA quote negative tests

## Next Steps

### Priority 1

- [ ] Validate the standard ML-DSA verifier path on a real SGX/TDX platform with proper platform collateral.

### Priority 2

- [ ] Add coexistence and corruption tests for ECDSA/ML-DSA blobs.
- [ ] Add more negative tests for malformed ML-DSA quote inputs.

### Priority 3

- [ ] Keep the local SIM runner and probe messages aligned with the actual platform behavior.
- [ ] Update documentation once real-platform standard verification is confirmed.

## Practical Interpretation

If you run the current repo-local ML-DSA flow in `SGX_MODE=SIM`, the expected result is:
- ML-DSA quote generation succeeds
- the standard collateral path may still be unavailable
- the local ML-DSA quote verification fallback succeeds

If you run outside `SIM`, the local verifier is not forced.
In that case, success depends on the real standard platform collateral path being available.
