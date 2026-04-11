# Next Step For ML-DSA Verifier Support

## Current State

- The repo-local `SIM` path can now generate ML-DSA TDX quotes successfully.
- The generated quote exposes:
  - ML-DSA attestation key selection
  - quote header `att_key_type = 5`
  - ML-DSA signature/public-key layout
- The verifier-side parser also gets past quote parsing and validation:
  - `Quote::parse()` succeeds
  - `Quote::validate()` succeeds

## Current Blocker

The remaining verifier failure is not in quote parsing.

The remaining verifier failure is in quote certification data handling:

- `tee_qv_get_collateral(...)` reaches certification-data extraction
- the generated ML-DSA quote currently carries certification data:
  - `type = 3`
  - `size = 404`
- the verifier returns:
  - `SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED (0xe01c)`

This means:

- the verifier understands the ML-DSA quote structure
- but it does not accept the certification-data type currently emitted by the local ML-DSA generation path

## Correct Next Step

The next step is to make the ML-DSA quote generation path emit verifier-compatible certification data, not local-only certification data.

Concretely:

1. Update the ML-DSA quote generation path so it prefers `PCK_CERT_CHAIN` certification data when available.
2. Keep the current local-only certification-data path only as a fallback for generation tests.
3. Re-run the ML-DSA verifier probe and confirm:
   - `tee_qv_get_collateral(...)` no longer returns `SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED`
   - `tdx_qv_verify_quote(...)` is reached
   - verifier behavior becomes either:
     - fully supported
     - or blocked by collateral/runtime availability rather than certification-data format

## Files To Focus On

- [td_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp)
  - `mldsa_get_quote_size(...)`
  - `mldsa_get_quote(...)`
- [quoting_enclave_tdqe.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp)
  - only if quote assembly must be adjusted for the final certification-data payload
- [sgx_dcap_quoteverify.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteVerification/dcap_quoteverify/sgx_dcap_quoteverify.cpp)
  - only for rerun/debug once generation emits compatible certification data

## What Not To Do

- Do not treat `type = 3` local-only certification data as the final verifier target.
- Do not patch the verifier to accept the local-only certification-data path as if it were standard DCAP collateral.
- Do not move key material or signing outside the trusted generation path.

## Success Condition

The next milestone is reached when:

- the ML-DSA quote is generated with verifier-compatible certification data
- `tee_qv_get_collateral(...)` succeeds or at least fails for collateral availability reasons rather than unsupported certification-data type
- `tdx_qv_verify_quote(...)` can be exercised on the ML-DSA quote path
