# Sealed Blob In The Current TDQE Flow

This note explains what the sealed blob is in the current TDX quote-generation path and how it is used by the TDQE.

## High-level idea

A sealed blob is an enclave-protected binary container.

It is used to:
- keep secret material outside the enclave without exposing it in plaintext
- bind that material to enclave/platform trust properties
- reload it later and recover the original secret only from the trusted enclave path

In this project, the sealed blob is the mechanism used to persist the attestation key material across runs.

## Current ECDSA flow

The current implementation is ECDSA-based.

Relevant files:
- `confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`
- `confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.h`
- `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/ecdsa_quote.h`
- `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

## Main structures

Plaintext metadata stored together with the attestation-key state:

```c
typedef struct _ref_plaintext_ecdsa_data_sdk_t {
    ...
    sgx_ec256_public_t     ecdsa_att_public_key;
    sgx_sha256_hash_t      ecdsa_id;
    uint32_t               authentication_data_size;
    uint8_t                authentication_data[REF_ECDSDA_AUTHENTICATION_DATA_SIZE];
} ref_plaintext_ecdsa_data_sdk_t;
```

Secret material protected inside the sealed payload:

```c
typedef struct _ref_ciphertext_ecdsa_data_sdk_t {
    sgx_ec256_private_t  ecdsa_private_key;
    ...
} ref_ciphertext_ecdsa_data_sdk_t;
```

Final sealed container written outside the enclave:

```c
(sgx_sealed_data_t*)p_blob
```

## Visual flow

### 1. Generate attestation key inside TDQE

Function:
- `gen_att_key(...)`

Key step:

```c
ret = random_stack_advance(get_att_key_based_from_seal_key,
    &pciphertext_data->ecdsa_private_key,
    &plaintext_data.ecdsa_att_public_key,
    &req_key_id);
```

Meaning:
- the TDQE derives/generates the ECDSA private key
- the private key goes into `ref_ciphertext_ecdsa_data_sdk_t`
- the public key goes into `ref_plaintext_ecdsa_data_sdk_t`

### 2. Build report data for certification

Still in `gen_att_key(...)`:

```c
sgx_status = sgx_sha256_update((uint8_t*)&plaintext_data.ecdsa_att_public_key,
    sizeof(plaintext_data.ecdsa_att_public_key),
    sha_handle);

sgx_status = sgx_sha256_update((uint8_t*)plaintext_data.authentication_data,
    sizeof(plaintext_data.authentication_data),
    sha_handle);
```

Then:

```c
sgx_status = sgx_sha256_get_hash(sha_handle,
    reinterpret_cast<sgx_sha256_hash_t *>(&plaintext_data.ecdsa_id));
```

Meaning:
- the TDQE computes a digest of public key plus authentication data
- that digest is used in the QE report sent toward the PCE/certification flow

### 3. Seal everything into the blob

Still in `gen_att_key(...)`:

```c
sgx_status = sgx_seal_data(sizeof(plaintext_data),
    reinterpret_cast<uint8_t*>(&plaintext_data),
    sizeof(*pciphertext_data),
    reinterpret_cast<uint8_t*>(pciphertext_data),
    blob_size,
    (sgx_sealed_data_t*)p_blob);
```

Meaning:
- `plaintext_data` is stored as authenticated associated data
- `pciphertext_data` contains the real secret, especially the ECDSA private key
- output is the sealed blob in `p_blob`

## Where the blob lives after sealing

On the wrapper side, the blob is cached in memory and optionally persisted.

Example in `td_ql_logic.cpp`:

```c
refqt_ret = write_persistent_data((uint8_t *)m_ecdsa_blob,
                                  sizeof(m_ecdsa_blob),
                                  get_blob_label_for_algorithm(m_att_key_algorithm_id));
```

Meaning:
- the blob is stored in a buffer such as `m_ecdsa_blob`
- then written to persistent storage
- later it can be reloaded and reused

## Reload path

Before generating a quote, the wrapper/TDQE reloads and verifies the blob.

Wrapper side:

```c
refqt_ret = read_persistent_data((uint8_t*)m_ecdsa_blob,
                                 &blob_size_read,
                                 get_blob_label_for_algorithm(m_att_key_algorithm_id));
```

TDQE side verification:

```c
sgx_status = verify_blob(m_eid,
                         (uint32_t*)&tdqe_error,
                         (uint8_t*)m_ecdsa_blob,
                         sizeof(m_ecdsa_blob),
                         &resealed,
                         NULL,
                         sizeof(blob_ecdsa_id),
                         (uint8_t*)&blob_ecdsa_id);
```

Meaning:
- the blob is read back
- the TDQE checks whether it can still be trusted/opened
- if valid, the TDQE recovers the key state needed to sign quotes

## Quote generation using the blob

During quote generation, the TDQE verifies the blob again and recovers the secret key state:

```c
ret = random_stack_advance(verify_blob_internal, p_blob,
    blob_size,
    &is_resealed,
    &plaintext,
    (sgx_report_body_t*) NULL,
    (uint8_t*) NULL,
    0,
    pciphertext);
```

Then it uses the recovered private key to sign:

```c
sgx_status = sgx_ecdsa_sign(p_quote_buf,
    sign_buf_size,
    &pciphertext->ecdsa_private_key,
    reinterpret_cast<sgx_ec256_signature_t *>(p_quote_sig),
    handle);
```

Meaning:
- the sealed blob is the source of the attestation private key during quote signing
- without a valid blob, the TDQE cannot produce the quote with the same persistent attestation identity

## Simple mental model

Think of the sealed blob as:

```text
sealed_blob =
    protect_for_enclave(
        public_metadata,
        secret_attestation_key_material
    )
```

In the current ECDSA implementation:

```text
public_metadata:
  - ECDSA public key
  - ECDSA key id hash
  - authentication data
  - certification-related metadata
  - QE report / QE id / platform info

secret_attestation_key_material:
  - ECDSA private key
  - encrypted PPID related secret state
```

## What this means for ML-DSA

If you add ML-DSA support, you need an ML-DSA version of the same concept:

- plaintext struct for ML-DSA public metadata
- ciphertext struct for the ML-DSA private key
- sealing/unsealing logic for that new structure
- quote generation that loads the ML-DSA private key from the sealed blob and uses it to sign

So when we say "add the ML-DSA blob", what we really mean is:
- define how the ML-DSA private key and its metadata are stored in sealed form
- make the TDQE able to seal it, reload it, verify it, and use it later
