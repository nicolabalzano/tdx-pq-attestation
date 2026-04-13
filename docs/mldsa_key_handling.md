# ML-DSA Key Handling

This note summarizes how ML-DSA key material is handled in the repo-local TDX quote flow.

| Item | Where generated | Where stored | Where used | Leaves TDQE? |
|---|---|---|---|---|
| ML-DSA private key | TDQE, via `tdqe_mldsa65_keygen(...)` in [quoting_enclave_tdqe.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp) | Sealed blob ciphertext: `mldsa_private_key[...]` in [quoting_enclave_tdqe.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.h) | Quote signing in `gen_quote(...)` via `tdqe_mldsa65_sign(...)` | No |
| ML-DSA public key | TDQE, same keygen call | Blob plaintext: `mldsa_att_public_key[...]` in [quoting_enclave_tdqe.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.h) | Included in quote signature area, used for local verify check | Yes |
| ML-DSA seed | TDQE, derived from seal key in `get_att_key_seed_from_seal_key(...)` called by `get_att_key_based_from_seal_key_mldsa(...)` in [quoting_enclave_tdqe.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp) | Not persisted as a standalone artifact | Only to derive the keypair | No |
| Key ID (`mldsa_id`) | TDQE, as `SHA256(public_key + authentication_data)` in [quoting_enclave_tdqe.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp) | Blob plaintext | Returned as pub key id / used to bind quote state | Yes |
| Blob file | Wrapper side, label selected in [td_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp) | Persistent storage as `tdqe_data_mldsa_65.blob` | Reloaded before quote generation / init paths | Yes, but still sealed |
| Unsealed private key material | TDQE only, after `sgx_unseal_data(...)` in [quoting_enclave_tdqe.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp) | Enclave memory only | Used by `tdqe_mldsa65_sign(...)` | No |

## Practical Summary

- The ML-DSA private key is generated inside TDQE.
- The private key is persisted only inside the sealed blob.
- The public key and the derived key identifier can leave TDQE.
- Quote signing always happens inside TDQE after unsealing the blob.
- The wrapper persists and reloads the sealed ML-DSA blob using a dedicated label:
  - `tdqe_data_mldsa_65.blob`
