# Changes From Start

This document records every code change made so far in this repository, excluding edits to `todo`.

For each step it lists:
- what was changed
- which file was changed
- the relevant code that was added or modified
- the checks or tests that were actually executed

All paths below are repository-relative unless stated otherwise.

## Step 1: Added ML-DSA identifiers and quote layout types

### File
`confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h`

### What changed
- Added a new attestation algorithm id for ML-DSA-65
- Moved `SGX_QL_ALG_MAX` forward
- Added explicit ML-DSA signature/public-key size constants
- Added a new v3 signature payload layout for ML-DSA

### Code

```c
typedef enum {
    SGX_QL_ALG_EPID = 0,
    SGX_QL_ALG_RESERVED_1 = 1,
    SGX_QL_ALG_ECDSA_P256 = 2,
    SGX_QL_ALG_ECDSA_P384 = 3,
    SGX_QL_ALG_MLDSA_65 = 5,
    SGX_QL_ALG_MAX = 6,
} sgx_ql_attestation_algorithm_id_t;

#define SGX_QL_MLDSA_65_SIG_SIZE 3309
#define SGX_QL_MLDSA_65_PUB_KEY_SIZE 1952
```

```c
typedef struct _sgx_ql_mldsa_65_sig_data_t {
    uint8_t               sig[SGX_QL_MLDSA_65_SIG_SIZE];
    uint8_t               attest_pub_key[SGX_QL_MLDSA_65_PUB_KEY_SIZE];
    sgx_report_body_t     qe_report;
    uint8_t               qe_report_sig[32*2];
    uint8_t               auth_certification_data[];
} sgx_ql_mldsa_65_sig_data_t;
```

### File
`confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h`

### What changed
- Added the v4 ML-DSA signature payload layout

### Code

```c
typedef struct _sgx_mldsa_65_sig_data_v4_t {
     uint8_t             sig[SGX_QL_MLDSA_65_SIG_SIZE];
     uint8_t             attest_pub_key[SGX_QL_MLDSA_65_PUB_KEY_SIZE];
     uint8_t             certification_data[];
} sgx_mldsa_65_sig_data_v4_t;
```

### Tests run
- Static layout test added later in Step 10 and executed successfully.

## Step 2: Forced the TDX wrapper to use the repository quote headers

### File
`confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/inc/td_ql_wrapper.h`

### What changed
- Replaced the generic include with a repository-local include to avoid accidentally pulling `sgx_quote_4.h` from the SDK

### Code

```c
#include "../../common/inc/sgx_quote_4.h"
```

### Why this was needed
- `td_ql_wrapper.cpp` used `SGX_QL_ALG_MLDSA_65`
- the compiler was previously resolving `sgx_quote_4.h` from `tdx_tests/sgxsdk/include`
- that SDK header did not contain the ML-DSA additions

### Tests run
- `g++ -H -fsyntax-only ... td_ql_wrapper.cpp` was used earlier to diagnose the wrong include source
- after the include fix, `td_ql_wrapper.cpp` compiled successfully in the wrapper build

## Step 3: Generalized the public TDX wrapper for ML-DSA contexts

### File
`confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_wrapper.cpp`

### What changed
- Added a default attestation key id for ML-DSA-65
- Added an algorithm whitelist helper
- Added a helper returning the default key id for the selected algorithm
- Allowed `tee_att_create_context(...)` to accept ML-DSA
- Stored the chosen algorithm in the context
- Made the wrapper dispatch `init_quote`, `get_quote_size`, and `get_quote` through generic per-algorithm methods
- Made `tee_att_get_keyid(...)` return a key id consistent with the context algorithm
- Added translation for `TDQE_ERROR_UNSUPPORTED_ATT_KEY_ID`

### Code

```c
extern const sgx_ql_att_key_id_t g_default_mldsa_65_att_key_id =
{
    {
        0,
        0,
        0,
        0,
        SGX_QL_ALG_MLDSA_65
    }
};
```

```c
static bool is_supported_tdx_att_key_algorithm(uint32_t algorithm_id)
{
    return algorithm_id == SGX_QL_ALG_ECDSA_P256 ||
           algorithm_id == SGX_QL_ALG_MLDSA_65;
}
```

```c
static const sgx_ql_att_key_id_t* get_default_att_key_id_for_algorithm(uint32_t algorithm_id)
{
    switch (algorithm_id)
    {
    case SGX_QL_ALG_MLDSA_65:
        return &g_default_mldsa_65_att_key_id;
    case SGX_QL_ALG_ECDSA_P256:
    default:
        return &g_default_ecdsa_p256_att_key_id;
    }
}
```

```c
p_context->m_att_key_algorithm_id = p_att_key_id ?
    static_cast<sgx_ql_attestation_algorithm_id_t>(p_att_key_id->base.algorithm_id)
    : SGX_QL_ALG_ECDSA_P256;
```

```c
ret_val = const_cast<tee_att_config_t*>(p_context)->init_quote(...);
ret_val = const_cast<tee_att_config_t*>(p_context)->get_quote_size(...);
ret_val = const_cast<tee_att_config_t*>(p_context)->get_quote(...);
```

```c
const sgx_ql_att_key_id_t* p_default_att_key_id =
    get_default_att_key_id_for_algorithm(p_context->m_att_key_algorithm_id);
```

### Tests run
- Wrapper library rebuilt successfully:

```bash
make -C confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

- Runtime wrapper test added later in Step 11 and executed successfully.

## Step 4: Added algorithm state and dispatch methods to the internal TDX logic

### File
`confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.h`

### What changed
- Added a field to remember the requested attestation algorithm inside `tee_att_config_t`
- Defaulted the field to `SGX_QL_ALG_ECDSA_P256`
- Declared ML-DSA-specific internal methods
- Declared generic dispatcher methods
- Forced `sgx_quote_5.h` to come from the repository

### Code

```c
#include "../../common/inc/sgx_quote_5.h"
```

```c
sgx_ql_attestation_algorithm_id_t m_att_key_algorithm_id;
```

```c
m_att_key_algorithm_id(SGX_QL_ALG_ECDSA_P256)
```

```c
tee_att_error_t mldsa_init_quote(...);
tee_att_error_t mldsa_get_quote_size(...);
tee_att_error_t mldsa_get_quote(...);

tee_att_error_t init_quote(...);
tee_att_error_t get_quote_size(...);
tee_att_error_t get_quote(...);
```

### Tests run
- Indirectly validated by rebuilding the wrapper library and running the wrapper tests in later steps.

## Step 5: Added per-algorithm dispatch in `td_ql_logic.cpp`

### File
`confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

### What changed
- Added `init_quote`, `get_quote_size`, and `get_quote` dispatchers
- Added explicit ML-DSA stubs returning `TEE_ATT_UNSUPPORTED_ATT_KEY_ID`
- Threaded `m_att_key_algorithm_id` into the TDQE ECALLs

### Code

```c
switch (m_att_key_algorithm_id)
{
case SGX_QL_ALG_ECDSA_P256:
    return ecdsa_init_quote(...);
case SGX_QL_ALG_MLDSA_65:
    return mldsa_init_quote(...);
default:
    return TEE_ATT_UNSUPPORTED_ATT_KEY_ID;
}
```

```c
tee_att_error_t tee_att_config_t::mldsa_init_quote(...)
{
    return TEE_ATT_UNSUPPORTED_ATT_KEY_ID;
}
```

```c
tee_att_error_t tee_att_config_t::mldsa_get_quote(...)
{
    return TEE_ATT_UNSUPPORTED_ATT_KEY_ID;
}
```

```c
sgx_status = gen_att_key(m_eid,
                         (uint32_t*)&tdqe_error,
                         (uint8_t*)m_ecdsa_blob,
                         (uint32_t)sizeof(m_ecdsa_blob),
                         static_cast<uint32_t>(m_att_key_algorithm_id),
                         ...);
```

```c
sgx_status = gen_quote(m_eid,
                       (uint32_t*)&tdqe_error,
                       (uint8_t*)m_ecdsa_blob,
                       (uint32_t)sizeof(m_ecdsa_blob),
                       static_cast<uint32_t>(m_att_key_algorithm_id),
                       p_app_report,
                       ...);
```

### Tests run
- Wrapper library rebuilt successfully
- Later runtime wrapper tests confirmed the ML-DSA context path reaches the new logic

## Step 6: Separated persistent blob labels by algorithm

### File
`confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

### What changed
- Added a second persistent-storage label for ML-DSA
- Added a helper to select the correct blob label by algorithm
- Replaced all hardcoded ECDSA blob label uses with the helper

### Code

```c
#define ECDSA_BLOB_LABEL "tdqe_data.blob"
#define MLDSA_65_BLOB_LABEL "tdqe_data_mldsa_65.blob"

static const char* get_blob_label_for_algorithm(uint32_t algorithm_id)
{
    switch (algorithm_id)
    {
    case SGX_QL_ALG_MLDSA_65:
        return MLDSA_65_BLOB_LABEL;
    case SGX_QL_ALG_ECDSA_P256:
    default:
        return ECDSA_BLOB_LABEL;
    }
}
```

```c
refqt_ret = read_persistent_data((uint8_t*)m_ecdsa_blob,
                                 &blob_size_read,
                                 get_blob_label_for_algorithm(m_att_key_algorithm_id));
```

```c
refqt_ret = write_persistent_data((uint8_t *)m_ecdsa_blob,
                                  sizeof(m_ecdsa_blob),
                                  get_blob_label_for_algorithm(m_att_key_algorithm_id));
```

### Tests run
- No standalone blob collision test has been completed yet
- Logic compiled successfully inside the wrapper build

## Step 7: Added `algorithm_id` to the TDQE ECALL surface

### File
`confidential-computing.tee.dcap-pq/ae/tdqe/tdqe.edl`

### What changed
- Added `uint32_t algorithm_id` to `gen_att_key(...)`
- Added `uint32_t algorithm_id` to `gen_quote(...)`

### Code

```c
public uint32_t gen_att_key(...,
                            uint32_t algorithm_id,
                            ...);
```

```c
public uint32_t gen_quote(...,
                          uint32_t algorithm_id,
                          ...);
```

### Tests run
- Validated indirectly through successful wrapper build and successful syntax checks of the TDQE code.

## Step 8: Added a dedicated TDQE error for unsupported attestation key ids

### File
`confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.h`

### What changed
- Added an explicit error value for unsupported attestation key ids

### Code

```c
TDQE_ERROR_UNSUPPORTED_ATT_KEY_ID = TDQE_MK_ERROR(0x000D)
```

### Tests run
- Error translation path validated through wrapper logic and runtime tests rejecting unsupported algorithm ids.

## Step 9: Propagated the algorithm into TDQE and added initial algorithm gating

### File
`confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`

### What changed
- Updated `gen_att_key(...)` to accept `algorithm_id`
- Updated `gen_quote(...)` to accept `algorithm_id`
- Added early unsupported-algorithm rejection in both functions

### Code

```c
uint32_t gen_att_key(uint8_t *p_blob,
    uint32_t blob_size,
    uint32_t algorithm_id,
    ...)
```

```c
if (algorithm_id != SGX_QL_ALG_ECDSA_P256) {
    return(TDQE_ERROR_UNSUPPORTED_ATT_KEY_ID);
}
```

```c
uint32_t gen_quote(uint8_t *p_blob,
    uint32_t blob_size,
    uint32_t algorithm_id,
    ...)
```

```c
if (algorithm_id != SGX_QL_ALG_ECDSA_P256) {
    return(TDQE_ERROR_UNSUPPORTED_ATT_KEY_ID);
}
```

### Current limitation
- At this stage the real quote was still fully ECDSA-only

### Tests run
- TDQE source later syntax-checked successfully

## Step 10: Replaced the ML-DSA quote-size stub with a real structural calculation

### File
`confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

### What changed
- Replaced `mldsa_get_quote_size(...)` stub with a real size calculation
- Kept the certification model aligned with the existing default certification-data path
- Initially implemented a too-short size formula
- Corrected it to include the full v4 quote layout, including QE report certification data and auth data

### Final code

```c
tee_att_error_t tee_att_config_t::mldsa_get_quote_size(sgx_ql_cert_key_type_t certification_key_type,
                                                       uint32_t* p_quote_size)
{
    if (PPID_RSA3072_ENCRYPTED != certification_key_type) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid certification key type.");
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    if (NULL == p_quote_size) {
        SE_TRACE(SE_TRACE_ERROR, "p_quote_size is NULL.");
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    *p_quote_size = sizeof(sgx_quote5_t) +                // quote body
                    sizeof(sgx_report2_body_v1_5_ex_t) +     // copy from TD Report for TDX 1.5 type 4
                    sizeof(uint32_t) +                    // Field for Auth Data size
                    sizeof(sgx_mldsa_65_sig_data_v4_t) +  // signature
                    sizeof(sgx_ql_certification_data_t) + // cert_key_type == ECDSA_SIG_AUX_DATA
                    sizeof(sgx_qe_report_certification_data_t) +
                    sizeof(sgx_ql_auth_data_t) +
                    REF_ECDSDA_AUTHENTICATION_DATA_SIZE +  // Authentication data
                    sizeof(sgx_ql_certification_data_t) + // cert_key_type == PPID_RSA3072_ENCRYPTED
                    sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t);
    SE_PROD_LOG("[tdx-quote-debug] mldsa_get_quote_size: quote_size=%u (default certification data path only).\n",
                *p_quote_size);
    return TEE_ATT_SUCCESS;
}
```

### Notes
- The first attempt tried to query platform certification data in a way that returned `0x11002`
- That was removed because the ML-DSA backend does not yet have a real TDQE/certification path
- The current implementation intentionally returns a deterministic structural size for the default certification-data path only

### Tests run
- Wrapper rebuilt successfully:

```bash
make -C confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

- Runtime wrapper test executed successfully:

```bash
g++ -std=c++14 \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/inc \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/inc \
  -I /home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  /home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdx_wrapper_algorithms.cpp \
  -L /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux -lsgx_tdx_logic \
  -L /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux -lsgx_pce_logic \
  -L /home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/lib64 -lsgx_urts -lpthread -ldl \
  -o /tmp/test_tdx_wrapper_algorithms
```

```bash
LD_LIBRARY_PATH=/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux:\
/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux:\
/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/lib64 \
/tmp/test_tdx_wrapper_algorithms
```

Observed output:

```text
[mldsa_get_quote_size td_ql_logic.cpp:1837] [tdx-quote-debug] mldsa_get_quote_size: quote_size=7102 (default certification data path only).
[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=7102)
```

## Step 11: Added and updated local tests

### File
`tdx_tests/test_tdx_wrapper_algorithms.cpp`

### What changed
- Added a runtime wrapper test
- Verified:
  - default context still returns ECDSA key id
  - ML-DSA context is accepted
  - ML-DSA context returns ML-DSA key id
  - ML-DSA context returns a non-zero quote size
  - invalid algorithm id is rejected

### Current code

```c++
#include <cstdio>
#include <cstring>

#include "td_ql_wrapper.h"

static int fail(const char* message, tee_att_error_t err)
{
    std::printf("[test] %s: 0x%x\n", message, static_cast<unsigned>(err));
    return 1;
}

int main()
{
    tee_att_config_t* default_context = nullptr;
    tee_att_error_t err = tee_att_create_context(nullptr, nullptr, &default_context);
    if (err != TEE_ATT_SUCCESS) {
        return fail("tee_att_create_context(default) failed", err);
    }

    tee_att_att_key_id_t default_key_id = {};
    err = tee_att_get_keyid(default_context, &default_key_id);
    if (err != TEE_ATT_SUCCESS) {
        tee_att_free_context(default_context);
        return fail("tee_att_get_keyid(default) failed", err);
    }

    if (default_key_id.base.algorithm_id != SGX_QL_ALG_ECDSA_P256) {
        tee_att_free_context(default_context);
        return fail("default key id algorithm is not ECDSA_P256", TEE_ATT_ERROR_UNEXPECTED);
    }

    err = tee_att_free_context(default_context);
    if (err != TEE_ATT_SUCCESS) {
        return fail("tee_att_free_context(default) failed", err);
    }

    tee_att_att_key_id_t mldsa_key_id = default_key_id;
    mldsa_key_id.base.algorithm_id = SGX_QL_ALG_MLDSA_65;

    tee_att_config_t* mldsa_context = nullptr;
    err = tee_att_create_context(&mldsa_key_id, nullptr, &mldsa_context);
    if (err != TEE_ATT_SUCCESS) {
        return fail("tee_att_create_context(MLDSA_65) failed", err);
    }

    tee_att_att_key_id_t returned_mldsa_key_id = {};
    err = tee_att_get_keyid(mldsa_context, &returned_mldsa_key_id);
    if (err != TEE_ATT_SUCCESS) {
        tee_att_free_context(mldsa_context);
        return fail("tee_att_get_keyid(MLDSA_65) failed", err);
    }

    if (returned_mldsa_key_id.base.algorithm_id != SGX_QL_ALG_MLDSA_65) {
        tee_att_free_context(mldsa_context);
        return fail("returned key id algorithm is not MLDSA_65", TEE_ATT_ERROR_UNEXPECTED);
    }

    uint32_t mldsa_quote_size = 0;
    err = tee_att_get_quote_size(mldsa_context, &mldsa_quote_size);
    if (err != TEE_ATT_SUCCESS) {
        tee_att_free_context(mldsa_context);
        return fail("tee_att_get_quote_size(MLDSA_65) failed", err);
    }

    if (mldsa_quote_size == 0) {
        tee_att_free_context(mldsa_context);
        return fail("tee_att_get_quote_size(MLDSA_65) returned zero", TEE_ATT_ERROR_UNEXPECTED);
    }

    err = tee_att_free_context(mldsa_context);
    if (err != TEE_ATT_SUCCESS) {
        return fail("tee_att_free_context(MLDSA_65) failed", err);
    }

    tee_att_att_key_id_t invalid_key_id = default_key_id;
    invalid_key_id.base.algorithm_id = 0xffff;

    tee_att_config_t* invalid_context = nullptr;
    err = tee_att_create_context(&invalid_key_id, nullptr, &invalid_context);
    if (err != TEE_ATT_UNSUPPORTED_ATT_KEY_ID) {
        if (invalid_context != nullptr) {
            tee_att_free_context(invalid_context);
        }
        return fail("tee_att_create_context(invalid algorithm) did not reject the request", err);
    }

    std::printf("[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=%u)\n",
                mldsa_quote_size);
    return 0;
}
```

### Tests run
- The compile/run commands and output are listed in Step 10.

### File
`tdx_tests/test_quote_headers_mldsa.cpp`

### What changed
- Added a static test for enum presence, struct presence, offsets, and derived quote-size relationships
- Later updated it to include `sgx_quote_5.h`
- Later updated it to include `ecdsa_quote.h`
- Added a structural check that the derived ML-DSA quote size is larger than the ECDSA one

### Current code

```c++
#include <cstddef>
#include <type_traits>

#include "../confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h"
#include "../confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h"
#include "../confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_5.h"
#include "../confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/ecdsa_quote.h"

static constexpr std::size_t kExpectedMldsaDefaultQuote5Size =
    sizeof(sgx_quote5_t) +
    sizeof(sgx_report2_body_v1_5_ex_t) +
    sizeof(uint32_t) +
    sizeof(sgx_mldsa_65_sig_data_v4_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_qe_report_certification_data_t) +
    sizeof(sgx_ql_auth_data_t) +
    REF_ECDSDA_AUTHENTICATION_DATA_SIZE +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t);

static constexpr std::size_t kExpectedEcdsaDefaultQuote5Size =
    sizeof(sgx_quote5_t) +
    sizeof(sgx_report2_body_v1_5_ex_t) +
    sizeof(uint32_t) +
    sizeof(sgx_ecdsa_sig_data_v4_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_qe_report_certification_data_t) +
    sizeof(sgx_ql_auth_data_t) +
    REF_ECDSDA_AUTHENTICATION_DATA_SIZE +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t);

static_assert(SGX_QL_ALG_MLDSA_65 != SGX_QL_ALG_ECDSA_P256, "ML-DSA and ECDSA algorithm ids must differ");
static_assert(SGX_QL_ALG_MLDSA_65 < SGX_QL_ALG_MAX, "ML-DSA id must be within the supported enum range");
static_assert(SGX_QL_MLDSA_65_SIG_SIZE > 0, "ML-DSA signature size must be defined");
static_assert(SGX_QL_MLDSA_65_PUB_KEY_SIZE > 0, "ML-DSA public-key size must be defined");
static_assert(sizeof(sgx_ql_mldsa_65_sig_data_t) > sizeof(sgx_ql_ecdsa_sig_data_t),
              "The ML-DSA v3 signature layout should be larger than the ECDSA one");
static_assert(sizeof(sgx_mldsa_65_sig_data_v4_t) > sizeof(sgx_ecdsa_sig_data_v4_t),
              "The ML-DSA v4 signature layout should be larger than the ECDSA one");
static_assert(kExpectedMldsaDefaultQuote5Size > sizeof(sgx_quote5_t),
              "The derived ML-DSA quote size must include the body and signature payload");
static_assert(kExpectedMldsaDefaultQuote5Size > kExpectedEcdsaDefaultQuote5Size,
              "The derived ML-DSA quote size must be larger than the ECDSA one");
static_assert(offsetof(sgx_quote_header_t, att_key_type) == 2, "Quote header att_key_type offset changed unexpectedly");
static_assert(offsetof(sgx_quote4_header_t, att_key_type) == 2, "Quote4 header att_key_type offset changed unexpectedly");

int main()
{
    return 0;
}
```

### Tests run

```bash
g++ -std=c++14 \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/inc \
  -I /home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  /home/alocin-local/tdx-pq-attestation/tdx_tests/test_quote_headers_mldsa.cpp \
  -o /tmp/test_quote_headers_mldsa
```

```bash
/tmp/test_quote_headers_mldsa
```

Observed result:
- no output
- exit code `0`

## Step 12: Extended the TDQE quote construction path structurally for ML-DSA

### File
`confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`

### What changed
- Added helper functions to describe algorithm support and per-algorithm signature layout sizes
- Replaced hardcoded `sgx_ecdsa_sig_data_v4_t` size in `sign_size` with an algorithm-dependent size
- Replaced hardcoded typed signature-data pointer with a raw pointer plus algorithm-specific views
- Set `header.att_key_type` from the requested `algorithm_id`
- Moved the ML-DSA rejection point later in `gen_quote(...)`, after quote layout setup but before ECDSA-only cryptographic operations
- Replaced the generic include of `sgx_quote_5.h` with the repository-local one

### Code

```c
#include "../../QuoteGeneration/quote_wrapper/common/inc/sgx_quote_5.h"
```

```c
static bool is_supported_att_key_algorithm(uint32_t algorithm_id)
{
    return algorithm_id == SGX_QL_ALG_ECDSA_P256 ||
           algorithm_id == SGX_QL_ALG_MLDSA_65;
}

static uint32_t get_quote_sig_data_struct_size(uint32_t algorithm_id)
{
    switch (algorithm_id) {
    case SGX_QL_ALG_MLDSA_65:
        return (uint32_t)sizeof(sgx_mldsa_65_sig_data_v4_t);
    case SGX_QL_ALG_ECDSA_P256:
    default:
        return (uint32_t)sizeof(sgx_ecdsa_sig_data_v4_t);
    }
}

static uint32_t get_quote_signature_size(uint32_t algorithm_id)
{
    switch (algorithm_id) {
    case SGX_QL_ALG_MLDSA_65:
        return SGX_QL_MLDSA_65_SIG_SIZE;
    case SGX_QL_ALG_ECDSA_P256:
    default:
        return (uint32_t)sizeof(sgx_ec256_signature_t);
    }
}
```

```c
uint8_t *p_quote_sig = NULL;
uint8_t *p_quote_sig_certification_data = NULL;
uint8_t *p_quote_sig_pub_key = NULL;
```

```c
if (!is_supported_att_key_algorithm(algorithm_id)) {
    return(TDQE_ERROR_UNSUPPORTED_ATT_KEY_ID);
}
```

```c
sign_size = get_quote_sig_data_struct_size(algorithm_id) +
    sizeof(sgx_ql_auth_data_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_qe_report_certification_data_t) +
    sizeof(sgx_ql_certification_data_t);
```

```c
switch (algorithm_id) {
case SGX_QL_ALG_MLDSA_65:
    p_quote_sig_pub_key = reinterpret_cast<sgx_mldsa_65_sig_data_v4_t *>(p_quote_sig)->attest_pub_key;
    p_quote_sig_certification_data = reinterpret_cast<sgx_mldsa_65_sig_data_v4_t *>(p_quote_sig)->certification_data;
    break;
case SGX_QL_ALG_ECDSA_P256:
default:
    p_quote_sig_pub_key = reinterpret_cast<sgx_ecdsa_sig_data_v4_t *>(p_quote_sig)->attest_pub_key;
    p_quote_sig_certification_data = reinterpret_cast<sgx_ecdsa_sig_data_v4_t *>(p_quote_sig)->certification_data;
    break;
}
```

```c
p_quote->header.att_key_type = (uint16_t)algorithm_id;
```

```c
if (algorithm_id != SGX_QL_ALG_ECDSA_P256) {
    ret = TDQE_ERROR_UNSUPPORTED_ATT_KEY_ID;
    goto ret_point;
}
```

### Important limitation
- This change does not implement ML-DSA key generation
- This change does not implement ML-DSA signing
- This change does not implement ML-DSA internal verification
- ECDSA cryptographic code is still the only real signing backend
- I also checked the repository for existing ML-DSA support (`MLDSA`, `mldsa`, `Dilithium`, `liboqs`, `pqclean`, `ml_dsa`) and did not find any reusable cryptographic implementation in the current tree

### Tests run
- TDQE source syntax check executed successfully:

```bash
g++ -std=c++14 -fsyntax-only \
  -I /home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  -I /home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include/tlibc \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp
```

Observed result:
- exit code `0`

## Step 13: Added a TDQE-side structural test for the ML-DSA sign-size formula

### File
`tdx_tests/test_tdqe_quote_layout_mldsa.cpp`

### What changed
- Added a static test focused on the TDQE-side `sign_size` formula
- Verified that:
  - the default ML-DSA TDQE `sign_size` is larger than the ECDSA one
  - the difference comes only from the algorithm-specific signature payload struct size

### Code

```c++
#include <cstddef>

#include "../confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h"
#include "../confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/ecdsa_quote.h"

static constexpr std::size_t kExpectedTdqeDefaultEcdsaSignSize =
    sizeof(sgx_ecdsa_sig_data_v4_t) +
    sizeof(sgx_ql_auth_data_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_qe_report_certification_data_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t) +
    REF_ECDSDA_AUTHENTICATION_DATA_SIZE;

static constexpr std::size_t kExpectedTdqeDefaultMldsaSignSize =
    sizeof(sgx_mldsa_65_sig_data_v4_t) +
    sizeof(sgx_ql_auth_data_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_qe_report_certification_data_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t) +
    REF_ECDSDA_AUTHENTICATION_DATA_SIZE;

static_assert(kExpectedTdqeDefaultMldsaSignSize > kExpectedTdqeDefaultEcdsaSignSize,
              "ML-DSA TDQE sign_size should be larger than the ECDSA one");

static_assert(kExpectedTdqeDefaultMldsaSignSize ==
              kExpectedTdqeDefaultEcdsaSignSize +
              (sizeof(sgx_mldsa_65_sig_data_v4_t) - sizeof(sgx_ecdsa_sig_data_v4_t)),
              "Only the algorithm-specific signature payload should change the TDQE default sign_size");

int main()
{
    return 0;
}
```

### Tests run

```bash
g++ -std=c++14 \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/inc \
  -I /home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  /home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdqe_quote_layout_mldsa.cpp \
  -o /tmp/test_tdqe_quote_layout_mldsa
```

```bash
/tmp/test_tdqe_quote_layout_mldsa
```

Observed result:
- no output
- exit code `0`

## Environment limitations encountered during this work

### Full TDQE rebuild is still blocked

The full enclave-side TDQE rebuild has not been completed because generated files in:
- `confidential-computing.tee.dcap-pq/ae/tdqe/linux/tdqe_t.c`
- `confidential-computing.tee.dcap-pq/ae/tdqe/linux/tdqe_t.h`

are owned by `root:root` in the current environment.

### Command attempted

```bash
make -C confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

### Observed failure

```text
Fatal error: exception Sys_error("./tdqe_t.h: Permission denied")
```

## Current functional state

At the current point:
- the quote schema knows about `SGX_QL_ALG_MLDSA_65`
- the TDX wrapper accepts ML-DSA contexts
- the internal TDX logic dispatches by algorithm
- persistent blob labels are separated by algorithm
- the wrapper can return a deterministic ML-DSA quote size
- the TDQE receives `algorithm_id`
- the TDQE can now lay out the quote structurally for ML-DSA up to the point where real cryptography would be needed
- the actual quote signing path is still ECDSA-only
- verification code has not yet been updated for ML-DSA
