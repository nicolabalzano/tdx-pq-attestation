# Changes From Start

This document records every code change made so far in this repository, excluding edits to `todo`.

For each step it lists:
- what was changed
- which file was changed
- the relevant code that was added or modified
- the checks or tests that were actually executed

All paths below are repository-relative unless stated otherwise.

## Latest update: Added QVL unit-test coverage for ML-DSA v4 quotes

### Files
`confidential-computing.tee.dcap-pq/QuoteVerification/QVL/Src/AttestationLibrary/test/CommonTestUtils/QuoteV4Generator.h`

`confidential-computing.tee.dcap-pq/QuoteVerification/QVL/Src/AttestationLibrary/test/CommonTestUtils/QuoteV4Generator.cpp`

`confidential-computing.tee.dcap-pq/QuoteVerification/QVL/Src/AttestationLibrary/test/UnitTests/QuoteV4ParsingUT.cpp`

`confidential-computing.tee.dcap-pq/QuoteVerification/QVL/Src/AttestationLibrary/test/UnitTests/GetQECertificationDataSizeUT.cpp`

`confidential-computing.tee.dcap-pq/QuoteVerification/QVL/Src/AttestationLibrary/test/UnitTests/GetQECertificationDataUT.cpp`

### What changed
- Extended the QVL v4 quote test generator so it can emit either ECDSA or ML-DSA auth-data layouts
- Added ML-DSA signature/public-key test structs using the repository quote constants
- Made the generator switch the serialized v4 auth-data layout from the selected `attestationKeyType`
- Added a positive parser/validator test for a TDX v4 ML-DSA quote
- Added positive extraction tests proving `sgxAttestationGetQECertificationDataSize()` and `sgxAttestationGetQECertificationData()` accept a v4 ML-DSA quote
- Added a verifier unit test proving the `QuoteVerifier` ML-DSA branch is reached and returns `STATUS_INVALID_QUOTE_SIGNATURE` for an invalid ML-DSA quote signature

### Why this matters
- The runtime probe had already shown that the repo-local path generates real ML-DSA quotes
- The remaining end-to-end verifier blocker is the local-only certification data `type=3`
- These unit tests lock in the part that already works in the QVL:
  - v4 ML-DSA quote parsing
  - ML-DSA auth-data layout handling
  - QE certification-data extraction from ML-DSA quotes

### Tests run
- Syntax-checked generator update:

```bash
g++ -std=c++14 -fsyntax-only .../QuoteV4Generator.cpp
```

- Syntax-checked new/updated unit tests:

```bash
g++ -std=c++14 -fsyntax-only .../QuoteV4ParsingUT.cpp
g++ -std=c++14 -fsyntax-only .../GetQECertificationDataSizeUT.cpp
g++ -std=c++14 -fsyntax-only .../GetQECertificationDataUT.cpp
g++ -std=c++14 -fsyntax-only .../QuoteV4VerifierUT.cpp
```

- All five syntax checks completed successfully.

## Latest update: Fixed the wrapper ML-DSA algorithm-selection test in SIM mode

### File
`tdx_tests/wrapper/test_tdx_wrapper_algorithms.cpp`

`tdx_tests/direct/run_mldsa_tdx_only_tests.sh`

### What changed
- The test now reads `TEST_TDQE_PATH` from the environment
- The ML-DSA context is created with that `tdqe_path` instead of `nullptr`
- The runner now exports `TEST_TDQE_PATH="$QGS_TDQE_PATH"` when launching `test_tdx_wrapper_algorithms`
- The wrapper algorithm-selection test now performs `tee_att_init_quote(..., nullptr, false, &pub_key_id_size, nullptr)` before calling `tee_att_get_quote_size()`
- The wrapper algorithm-selection test now also performs the real bootstrap call:

```c++
tee_att_init_quote(mldsa_context,
                   &qe_target_info,
                   false,
                   &pub_key_id_size,
                   reinterpret_cast<uint8_t*>(&pub_key_id));
```

### Why this was needed
- The runner already exported `TEST_TDQE_PATH="$QGS_TDQE_PATH"` for this test
- But the test ignored it and created the ML-DSA context with a null path
- In `SGX_MODE=SIM`, that made `tee_att_get_quote_size()` hit `load_qe()` with the wrong default lookup path and fail with `SGXError:200f`
- After fixing the path, the test still called `tee_att_get_quote_size()` on an uninitialized ML-DSA context
- That left `m_raw_pce_isvsvn` at the sentinel value and made the trusted ML-DSA quote-size path fail with `TEE_ATT_ATT_KEY_NOT_INITIALIZED`
- A size-only `tee_att_init_quote(..., nullptr, ...)` was still not enough for this path
- The trusted ML-DSA context is fully initialized only after the bootstrap call that materializes `qe_target_info` and `pub_key_id`

### Tests run
- Syntax-checked the updated test:

```bash
g++ -std=c++14 -O2 -Wall -Wextra -Werror -fsyntax-only .../test_tdx_wrapper_algorithms.cpp
```

- Syntax-checked the updated runner:

```bash
bash -n .../run_mldsa_tdx_only_tests.sh
```

- Syntax-checked the updated wrapper test again after adding the `init_quote` step:

```bash
g++ -std=c++14 -O2 -Wall -Wextra -Werror -fsyntax-only .../test_tdx_wrapper_algorithms.cpp
```

- All syntax checks completed successfully.

## Latest update: Integrated ML-DSA sources into the QVL CMake build

### File
`confidential-computing.tee.dcap-pq/QuoteVerification/QVL/Src/AttestationLibrary/CMakeLists.txt`

### What changed
- Enabled C in the `AttestationLibrary` CMake project
- Added:
  - `ae/tdqe/tdqe_mldsa_adapter.c`
  - `ae/pq/mldsa-native/mldsa/mldsa_native.c`
  to the `AttestationLibrary` source list
- Added include paths for:
  - `ae/tdqe`
  - `ae/pq/mldsa-native/mldsa`
  - `ae/pq/mldsa-native/mldsa/src`

### Why this was needed
- The Makefile-based `dcap_quoteverify` build already compiled the ML-DSA verifier helper sources
- The QVL `AttestationLibrary` CMake build did not
- That left the ML-DSA `QuoteVerifier.cpp` branch under-integrated for the CMake/unit-test path
- With this change, the QVL test/build path has the same ML-DSA helper sources available as the Makefile verifier path

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

## Step 14: Routed ML-DSA init/get_quote through the backend-facing path

### File
`confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

### What changed
- Replaced the immediate `TEE_ATT_UNSUPPORTED_ATT_KEY_ID` stubs in `mldsa_init_quote(...)` and `mldsa_get_quote(...)`
- Reused the common TDQE-facing flow instead
- This means ML-DSA requests now reach the actual backend boundary before failing, instead of stopping immediately inside the wrapper logic

### Code

```c
tee_att_error_t tee_att_config_t::mldsa_init_quote(sgx_ql_cert_key_type_t certification_key_type,
                                                   sgx_target_info_t *p_qe_target_info,
                                                   bool refresh_att_key,
                                                   ref_sha256_hash_t *p_pub_key_id)
{
    // Reuse the common TDQE-facing path so ML-DSA reaches the backend boundary.
    // The TDQE still rejects ML-DSA cryptographic operations explicitly.
    return ecdsa_init_quote(certification_key_type,
                            p_qe_target_info,
                            refresh_att_key,
                            p_pub_key_id);
}
```

```c
tee_att_error_t tee_att_config_t::mldsa_get_quote(const sgx_report2_t *p_app_report,
                                                  uint8_t *p_quote,
                                                  uint32_t quote_size)
{
    // Reuse the common TDQE-facing path so ML-DSA quote requests fail at the
    // actual backend boundary until a real ML-DSA attestation key exists.
    return ecdsa_get_quote(p_app_report, p_quote, quote_size);
}
```

### Why this change matters
- Before this change, ML-DSA `init_quote` and `get_quote` stopped inside the wrapper logic with an immediate unsupported error
- After this change, the unsupported result is deferred to the TDQE/backend side
- This is a better integration point for the future ML-DSA implementation because the public wrapper and internal logic now follow the real end-to-end control flow

### Important limitation
- This still does not generate an ML-DSA key
- This still does not sign an ML-DSA quote
- In the current repository state, the request still fails at the TDQE boundary because only the ECDSA cryptographic backend exists

### Tests run
- Wrapper library rebuilt successfully:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

## Step 18: Integrated the imported `mldsa-native` backend into the TDQE build and verified a full enclave build

### Files
- `confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/mldsa_native_config.h`
- `confidential-computing.tee.dcap-pq/ae/tdqe/tdqe_mldsa_adapter.h`
- `confidential-computing.tee.dcap-pq/ae/tdqe/tdqe_mldsa_adapter.c`
- `confidential-computing.tee.dcap-pq/ae/tdqe/linux/Makefile`

### What changed
- Reconfigured the imported ML-DSA library from parameter set `44` to `65`
- Disabled the randomized API in the imported library so the TDQE can rely on deterministic internal APIs without adding a `randombytes()` implementation
- Added a local TDQE adapter exposing the three enclave-local functions already declared in `quoting_enclave_tdqe.h`
- Bound the adapter to the internal ML-DSA APIs:
  - key generation uses `keypair_internal(seed)`
  - signing uses `signature_internal(...)` with a zeroed deterministic randomness buffer
  - verification uses `verify_internal(...)`
- Added the imported ML-DSA source and adapter source to the Linux TDQE enclave build
- Added the imported `mldsa` and `mldsa/src` include paths to the TDQE Makefile
- Disabled the unsupported `__CET__` path for `mldsa_native.o` only, because the enclave toolchain in this environment does not provide `<cet.h>`

### Code

```c
#define MLD_CONFIG_PARAMETER_SET \
  65 /* TDQE integration uses ML-DSA-65 */
```

```c
#define MLD_CONFIG_NO_RANDOMIZED_API
```

```c
int tdqe_mldsa65_keygen(uint8_t *public_key, uint8_t *private_key, uint8_t *seed)
{
    if ((NULL == public_key) || (NULL == private_key) || (NULL == seed)) {
        return -1;
    }

    return MLD_API_NAMESPACE(keypair_internal)(public_key, private_key, seed);
}
```

```c
int tdqe_mldsa65_sign(uint8_t *signature,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *private_key)
{
    size_t signature_len = 0;
    uint8_t deterministic_rnd[MLDSA65_RNDBYTES] = {0};
    int ret = -1;

    ret = MLD_API_NAMESPACE(signature_internal)(signature,
        &signature_len,
        message,
        message_len,
        NULL,
        0,
        deterministic_rnd,
        private_key,
        0);
    if ((0 != ret) || (signature_len != SGX_QL_MLDSA_65_SIG_SIZE)) {
        return -1;
    }

    return 0;
}
```

```c
int tdqe_mldsa65_verify(const uint8_t *signature,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *public_key)
{
    return MLD_API_NAMESPACE(verify_internal)(signature,
        SGX_QL_MLDSA_65_SIG_SIZE,
        message,
        message_len,
        NULL,
        0,
        public_key,
        0);
}
```

```make
           -I$(TOP_DIR)/../ae/pq/mldsa-native/mldsa        \
           -I$(TOP_DIR)/../ae/pq/mldsa-native/mldsa/src    \
```

```make
tdqe_mldsa_adapter.o: ../tdqe_mldsa_adapter.c
	$(CC) $(CFLAGS) $(INCLUDE) $(DEFINES) -c $< -o $@

mldsa_native.o: $(TOP_DIR)/../ae/pq/mldsa-native/mldsa/mldsa_native.c
	$(CC) $(CFLAGS) $(INCLUDE) $(DEFINES) -U__CET__ -c $< -o $@
```

### Tests run
- Imported ML-DSA source syntax check passed:

```bash
gcc -std=c11 -fsyntax-only \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/src \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/mldsa_native.c
```

- TDQE adapter syntax check passed:

```bash
gcc -std=c11 -fsyntax-only \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/src \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include/tlibc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/tdqe_mldsa_adapter.c
```

- TDQE source syntax check still passed after wiring in the adapter/import paths:

```bash
g++ -std=c++14 -fsyntax-only \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include/tlibc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/src \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp
```

- Full TDQE build passed after fixing stale build-artifact permissions:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Relevant tail of the build output:

```text
handle_compatible_metadata: Overwrite with metadata version 0x100000005
Succeed.
SIGN =>  libsgx_tdqe.signed.so
```

### Important limitation
- The backend library is now compiled into the TDQE and the enclave builds successfully
- But the ML-DSA sealed blob is still not consumed end to end:
  - `verify_blob_internal(...)` is still ECDSA-only
  - wrapper-side plaintext blob parsing in `td_ql_logic.cpp` is still ECDSA-only
  - `store_cert_data(...)` still accepts `ref_plaintext_ecdsa_data_sdk_t *`
  - `gen_quote(...)` still only signs/verifies the final quote through the ECDSA path

## Step 19: Generalized external blob verification and wrapper-side blob parsing for ECDSA and ML-DSA

### Files
- `confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`
- `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

### What changed
- Kept the original `verify_blob_internal(...)` in the TDQE for the existing ECDSA-only internal callers
- Added a new algorithm-aware `verify_blob_any_internal(...)` for the external `verify_blob(...)` ECALL path
- The new external verifier can now:
  - accept either the ECDSA blob size or the ML-DSA blob size
  - unseal either blob type
  - validate the matching plaintext/ciphertext lengths and blob version
  - return the correct public-key hash (`ecdsa_id` or `mldsa_id`)
  - reseal the blob on TCB change without caring whether it is ECDSA or ML-DSA
- In the wrapper, replaced direct sealed-blob casts to `ref_plaintext_ecdsa_data_sdk_t` with a common `tdqe_blob_plaintext_view_t`
- The wrapper common view extracts only the fields needed by the caller and maps them for both ECDSA and ML-DSA blobs:
  - certification key type
  - certification/raw TCB fields
  - PCE target info
  - QE report
  - QE ID
  - signature scheme
- Updated the wrapper code paths in:
  - `ecdsa_init_quote(...)`
  - `ecdsa_get_quote_size(...)`
  - `ecdsa_get_quote(...)`
  so they read common blob metadata through the view rather than assuming an ECDSA plaintext layout

### Code

```c
static tdqe_error_t verify_blob_any_internal(uint8_t *p_blob,
    uint32_t blob_size,
    uint8_t *p_is_resealed,
    sgx_report_body_t *p_report_body,
    uint8_t *p_pub_key_id,
    uint32_t pub_key_id_size)
{
    ...
    if (plaintext_length >= sizeof(ref_plaintext_ecdsa_data_sdk_t) &&
        p_plaintext_common->seal_blob_type == SGX_QL_SEAL_ECDSA_KEY_BLOB) {
        ...
        memcpy(p_pub_key_id, &p_plaintext_ecdsa->ecdsa_id, sizeof(p_plaintext_ecdsa->ecdsa_id));
    } else if (plaintext_length >= sizeof(ref_plaintext_mldsa_65_data_sdk_t) &&
               p_plaintext_common->seal_blob_type == SGX_QL_SEAL_MLDSA_65_KEY_BLOB) {
        ...
        memcpy(p_pub_key_id, &p_plaintext_mldsa->mldsa_id, sizeof(p_plaintext_mldsa->mldsa_id));
    } else {
        ret = TDQE_ECDSABLOB_ERROR;
    }
    ...
}
```

```c
struct tdqe_blob_plaintext_view_t {
    uint8_t seal_blob_type;
    const sgx_ql_cert_key_type_t *certification_key_type;
    const sgx_isv_svn_t *cert_qe_isv_svn;
    const sgx_cpu_svn_t *cert_cpu_svn;
    const sgx_pce_info_t *cert_pce_info;
    const sgx_cpu_svn_t *raw_cpu_svn;
    const sgx_pce_info_t *raw_pce_info;
    const uint8_t *signature_scheme;
    const sgx_target_info_t *pce_target_info;
    const sgx_report_t *qe_report;
    const sgx_key_128bit_t *qe_id;
};
```

```c
static bool get_tdqe_blob_plaintext_view(const uint8_t *p_blob,
                                         uint32_t blob_size,
                                         tdqe_blob_plaintext_view_t *p_view)
{
    ...
    if (p_view->seal_blob_type == SGX_QL_SEAL_ECDSA_KEY_BLOB) {
        const ref_plaintext_ecdsa_data_sdk_t *p_ecdsa = ...;
        ...
        return true;
    }

    if (p_view->seal_blob_type == SGX_QL_SEAL_MLDSA_65_KEY_BLOB) {
        const ref_plaintext_mldsa_65_data_sdk_t *p_mldsa = ...;
        ...
        return true;
    }

    return false;
}
```

```c
if (!get_tdqe_blob_plaintext_view(m_ecdsa_blob, tdqe_blob_size, &blob_view)) {
    SE_TRACE(SE_TRACE_ERROR, "Unsupported TDQE blob format.\n");
    refqt_ret = TEE_ATT_ATT_KEY_NOT_INITIALIZED;
    goto CLEANUP;
}
```

### Tests run
- TDX wrapper rebuilt successfully:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

- TDQE enclave rebuilt and signed successfully:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Relevant tail of the TDQE build output:

```text
handle_compatible_metadata: Overwrite with metadata version 0x100000005
Succeed.
SIGN =>  libsgx_tdqe.signed.so
```

### Important limitation
- This step makes the external blob-verification path and wrapper-side common metadata parsing understand both ECDSA and ML-DSA blob shapes
- The internal TDQE consumers that still operate on concrete ECDSA plaintext/ciphertext types are not generalized yet:
  - `store_cert_data(...)`
  - the ECDSA-only `verify_blob_internal(...)` call sites used by `store_cert_data(...)` and `gen_quote(...)`
  - the final quote signing/verification logic in `gen_quote(...)`

## Step 18: Wired the imported `mldsa-native` backend into the TDQE build

### Files
- `confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/mldsa_native_config.h`
- `confidential-computing.tee.dcap-pq/ae/tdqe/tdqe_mldsa_adapter.h`
- `confidential-computing.tee.dcap-pq/ae/tdqe/tdqe_mldsa_adapter.c`
- `confidential-computing.tee.dcap-pq/ae/tdqe/linux/Makefile`

### What changed
- Reconfigured the imported ML-DSA library from its default parameter set `44` to `65`
- Disabled the randomized API in the imported library so the TDQE can use the deterministic internal APIs without adding a `randombytes()` implementation
- Added a local TDQE adapter exposing the three enclave-local functions already declared in `quoting_enclave_tdqe.h`
- Bound the adapter to the internal ML-DSA APIs:
  - key generation uses `keypair_internal(seed)`
  - signing uses `signature_internal(...)` with a zeroed deterministic randomness buffer
  - verification uses `verify_internal(...)`
- Added the imported ML-DSA source and adapter source to the Linux TDQE enclave build
- Added the imported `mldsa` and `mldsa/src` include paths to the TDQE Makefile
- Disabled the unsupported `__CET__` path for `mldsa_native.o` only, because the SGX enclave toolchain in this environment does not provide `<cet.h>`

### Code

```c
#define MLD_CONFIG_PARAMETER_SET \
  65 /* TDQE integration uses ML-DSA-65 */
```

```c
#define MLD_CONFIG_NO_RANDOMIZED_API
```

```c
int tdqe_mldsa65_keygen(uint8_t *public_key, uint8_t *private_key, uint8_t *seed)
{
    if ((NULL == public_key) || (NULL == private_key) || (NULL == seed)) {
        return -1;
    }

    return MLD_API_NAMESPACE(keypair_internal)(public_key, private_key, seed);
}
```

```c
int tdqe_mldsa65_sign(uint8_t *signature,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *private_key)
{
    size_t signature_len = 0;
    uint8_t deterministic_rnd[MLDSA65_RNDBYTES] = {0};
    int ret = -1;

    ret = MLD_API_NAMESPACE(signature_internal)(signature,
        &signature_len,
        message,
        message_len,
        NULL,
        0,
        deterministic_rnd,
        private_key,
        0);
    if ((0 != ret) || (signature_len != SGX_QL_MLDSA_65_SIG_SIZE)) {
        return -1;
    }

    return 0;
}
```

```c
int tdqe_mldsa65_verify(const uint8_t *signature,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *public_key)
{
    return MLD_API_NAMESPACE(verify_internal)(signature,
        SGX_QL_MLDSA_65_SIG_SIZE,
        message,
        message_len,
        NULL,
        0,
        public_key,
        0);
}
```

```make
           -I$(TOP_DIR)/../ae/pq/mldsa-native/mldsa        \
           -I$(TOP_DIR)/../ae/pq/mldsa-native/mldsa/src    \
```

```make
tdqe_mldsa_adapter.o: ../tdqe_mldsa_adapter.c
	$(CC) $(CFLAGS) $(INCLUDE) $(DEFINES) -c $< -o $@

mldsa_native.o: $(TOP_DIR)/../ae/pq/mldsa-native/mldsa/mldsa_native.c
	$(CC) $(CFLAGS) $(INCLUDE) $(DEFINES) -U__CET__ -c $< -o $@
```

### Tests run
- Imported ML-DSA source syntax check passed:

```bash
gcc -std=c11 -fsyntax-only \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/src \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/mldsa_native.c
```

- TDQE adapter syntax check passed:

```bash
gcc -std=c11 -fsyntax-only \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/src \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include/tlibc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/tdqe_mldsa_adapter.c
```

- TDQE source syntax check still passed after wiring in the adapter/import paths:

```bash
g++ -std=c++14 -fsyntax-only \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include/tlibc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/src \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp
```

- Full TDQE build now enters the imported ML-DSA backend but is still blocked later by the existing generated-file permission problem:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Observed result:
- `mldsa_native.c` is now compiled by the TDQE build
- the build then fails on the pre-existing generated-file issue:

```text
Fatal error: exception Sys_error("./tdqe_t.h: Permission denied")
```

### Follow-up verification after fixing `tdqe_t.c` / `tdqe_t.h` ownership

After ownership of:
- `confidential-computing.tee.dcap-pq/ae/tdqe/linux/tdqe_t.c`
- `confidential-computing.tee.dcap-pq/ae/tdqe/linux/tdqe_t.h`

was corrected, the full TDQE build was rerun.

### Command run

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

### Observed result
- `quoting_enclave_tdqe.cpp` compiled successfully
- `tdqe_mldsa_adapter.c` compiled successfully
- the final enclave link started successfully
- the next build blocker is another stale root-owned artifact from the old build:

```text
/usr/bin/ld: cannot open map file out.map: Permission denied
```

This means the imported ML-DSA backend and the new TDQE adapter are now far enough integrated to reach the final enclave link stage.

- Existing runtime wrapper test rerun successfully:

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
[mldsa_get_quote_size td_ql_logic.cpp:1838] [tdx-quote-debug] mldsa_get_quote_size: quote_size=7102 (default certification data path only).
[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=7102)
```

## Step 15: Added TDQE-local ML-DSA blob structures and seed/keygen helpers

### File
`confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.h`

### What changed
- Added ML-DSA TDQE constants for:
  - seed size
  - private-key size
  - seal blob type
  - blob version
- Added an ML-DSA ciphertext blob struct for the private key and PPID state
- Added an ML-DSA plaintext blob struct for public metadata
- Added the new ML-DSA function declarations provided for integration:
  - `tdqe_mldsa65_keygen(...)`
  - `tdqe_mldsa65_sign(...)`
  - `tdqe_mldsa65_verify(...)`
- Added a dedicated ML-DSA sealed-blob size macro

### Code

```c
#define TDQE_MLDSA_65_SEED_SIZE 32
#define TDQE_MLDSA_65_PRIVATE_KEY_SIZE 4032

#define SGX_QL_SEAL_MLDSA_65_KEY_BLOB 1
#define SGX_QL_MLDSA_65_KEY_BLOB_VERSION_0 0
```

```c
typedef struct _ref_ciphertext_mldsa_65_data_sdk_t {
    uint8_t              mldsa_private_key[TDQE_MLDSA_65_PRIVATE_KEY_SIZE];
    uint8_t              is_clear_ppid;
    union {
        uint8_t              ppid[16];
        ref_encrypted_ppid_t encrypted_ppid_data;
    };
} ref_ciphertext_mldsa_65_data_sdk_t;
```

```c
typedef struct _ref_plaintext_mldsa_65_data_sdk_t {
    uint8_t                seal_blob_type;
    uint8_t                mldsa_key_version;
    sgx_cpu_svn_t          cert_cpu_svn;
    sgx_isv_svn_t          cert_qe_isv_svn;
    sgx_pce_info_t         cert_pce_info;
    sgx_ql_cert_key_type_t certification_key_type;
    sgx_cpu_svn_t          raw_cpu_svn;
    sgx_pce_info_t         raw_pce_info;
    uint8_t                signature_scheme;
    sgx_target_info_t      pce_target_info;
    sgx_report_t           qe_report;
    sgx_ec256_signature_t  qe_report_cert_key_sig;
    uint8_t                mldsa_att_public_key[SGX_QL_MLDSA_65_PUB_KEY_SIZE];
    sgx_sha256_hash_t      mldsa_id;
    sgx_cpu_svn_t          seal_cpu_svn;
    sgx_isv_svn_t          seal_qe_isv_svn;
    uint32_t               authentication_data_size;
    uint8_t                authentication_data[REF_ECDSDA_AUTHENTICATION_DATA_SIZE];
    sgx_key_128bit_t       qe_id;
} ref_plaintext_mldsa_65_data_sdk_t;
```

```c
int tdqe_mldsa65_keygen(uint8_t *public_key, uint8_t *private_key, uint8_t *seed);

int tdqe_mldsa65_sign(uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *private_key);

int tdqe_mldsa65_verify(const uint8_t *signature, const uint8_t *message, size_t message_len, const uint8_t *public_key);
```

```c
#define SGX_QL_TRUSTED_MLDSA_65_BLOB_SIZE_SDK ((uint32_t)(sizeof(sgx_sealed_data_t) + \
                                                          sizeof(ref_ciphertext_mldsa_65_data_sdk_t) + \
                                                          sizeof(ref_plaintext_mldsa_65_data_sdk_t)))
```

### File
`confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`

### What changed
- Added a new helper that derives deterministic seed bytes from the TDQE sealing key using the same CMAC-based derivation flow already used by ECDSA
- Added a new ML-DSA attestation-key helper that:
  - derives the seed
  - calls `tdqe_mldsa65_keygen(...)`
- These helpers are not yet wired into the full runtime blob path
- This is the first concrete TDQE-side code that can support real ML-DSA key generation once the blob path is generalized

### Code

```c
static tdqe_error_t get_att_key_seed_from_seal_key(uint8_t *p_att_seed,
    uint32_t att_seed_size,
    const sgx_key_id_t *p_req_key_id)
{
    ...
    memcpy(p_att_seed, hash_drg_output, att_seed_size);
    ret = TDQE_SUCCESS;
    ...
}
```

```c
static tdqe_error_t get_att_key_based_from_seal_key_mldsa(uint8_t *p_att_pub_key,
    uint8_t *p_att_priv_key,
    const sgx_key_id_t *p_req_key_id)
{
    uint8_t att_seed[TDQE_MLDSA_65_SEED_SIZE] = {0};
    tdqe_error_t ret = get_att_key_seed_from_seal_key(att_seed, sizeof(att_seed), p_req_key_id);
    if (TDQE_SUCCESS != ret) {
        return ret;
    }

    if (0 != tdqe_mldsa65_keygen(p_att_pub_key, p_att_priv_key, att_seed)) {
        (void)memset_s(att_seed, sizeof(att_seed), 0, sizeof(att_seed));
        return TDQE_ERROR_ATT_KEY_GEN;
    }

    (void)memset_s(att_seed, sizeof(att_seed), 0, sizeof(att_seed));
    return TDQE_SUCCESS;
}
```

### Important limitation
- The new ML-DSA blob structures are defined, but they are not yet fully used by:
  - `verify_blob_internal(...)`
  - `gen_att_key(...)`
  - `gen_quote(...)`
  - wrapper-side blob-size management
- So this step prepares the TDQE-local representation and key-derivation entry point, but it does not yet produce a usable ML-DSA sealed blob end to end

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
- the wrapper/internal logic now route ML-DSA `init_quote` and `get_quote` up to the backend boundary
- the TDQE receives `algorithm_id`
- the TDQE can now lay out the quote structurally for ML-DSA up to the point where real cryptography would be needed
- the TDQE now also has explicit ML-DSA blob structs and a seed/keygen helper entry point
- the actual quote signing path is still ECDSA-only
- verification code has not yet been updated for ML-DSA

## Step 16: Generalized the wrapper-side sealed-blob size handling

### Files
- `confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.h`
- `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.h`
- `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

### What changed
- Added a max-size TDQE blob macro so the wrapper cache can hold either an ECDSA blob or an ML-DSA blob
- Enlarged the cached wrapper blob buffer from the fixed ECDSA size to the new max-size macro
- Added a helper that maps `algorithm_id` to the expected TDQE blob size
- Replaced wrapper-side hardcoded ECDSA blob-size uses in read/verify/reseal/store/gen paths with the per-algorithm size

### Code

```c
#define SGX_QL_TRUSTED_MAX_BLOB_SIZE_SDK \
    ((SGX_QL_TRUSTED_MLDSA_65_BLOB_SIZE_SDK > SGX_QL_TRUSTED_ECDSA_BLOB_SIZE_SDK) ? \
        SGX_QL_TRUSTED_MLDSA_65_BLOB_SIZE_SDK : SGX_QL_TRUSTED_ECDSA_BLOB_SIZE_SDK)
```

```c
uint8_t m_ecdsa_blob[SGX_QL_TRUSTED_MAX_BLOB_SIZE_SDK];
```

```c
static uint32_t get_tdqe_blob_size_for_algorithm(uint32_t algorithm_id)
{
    switch (algorithm_id)
    {
    case SGX_QL_ALG_MLDSA_65:
        return SGX_QL_TRUSTED_MLDSA_65_BLOB_SIZE_SDK;
    case SGX_QL_ALG_ECDSA_P256:
    default:
        return SGX_QL_TRUSTED_ECDSA_BLOB_SIZE_SDK;
    }
}
```

```c
const uint32_t tdqe_blob_size = get_tdqe_blob_size_for_algorithm(m_att_key_algorithm_id);
```

### Tests run
- Wrapper library rebuilt successfully:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

- Runtime wrapper test still passed:

```text
[mldsa_get_quote_size td_ql_logic.cpp:1853] [tdx-quote-debug] mldsa_get_quote_size: quote_size=7102 (default certification data path only).
[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=7102)
```

## Step 17: Added a real ML-DSA `gen_att_key(...)` branch inside the TDQE

### File
`confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`

### What changed
- Added a TDQE-local helper to map `algorithm_id` to the expected sealed-blob size
- Extended `gen_att_key(...)` so it no longer rejects ML-DSA immediately
- Added a separate ML-DSA plaintext/ciphertext path inside `gen_att_key(...)`
- The ML-DSA path now:
  - copies authentication data into the ML-DSA plaintext structure
  - derives the attestation seed from the seal key
  - calls `tdqe_mldsa65_keygen(...)`
  - computes `SHA256(public_key || authentication_data)` into `mldsa_id`
  - creates the QE report for PCE certification
  - seals an ML-DSA-shaped TDQE blob

### Code

```c
static uint32_t get_tdqe_blob_size_for_algorithm(uint32_t algorithm_id)
{
    switch (algorithm_id) {
    case SGX_QL_ALG_MLDSA_65:
        return SGX_QL_TRUSTED_MLDSA_65_BLOB_SIZE_SDK;
    case SGX_QL_ALG_ECDSA_P256:
    default:
        return SGX_QL_TRUSTED_ECDSA_BLOB_SIZE_SDK;
    }
}
```

```c
ref_plaintext_mldsa_65_data_sdk_t plaintext_data_mldsa;
ref_ciphertext_mldsa_65_data_sdk_t mldsa_ciphertext_data;
ref_ciphertext_mldsa_65_data_sdk_t* pmldsa_ciphertext_data = &mldsa_ciphertext_data;
const uint32_t expected_blob_size = get_tdqe_blob_size_for_algorithm(algorithm_id);
```

```c
if (!is_supported_att_key_algorithm(algorithm_id)) {
    return(TDQE_ERROR_UNSUPPORTED_ATT_KEY_ID);
}

if (expected_blob_size != blob_size) {
    return(TDQE_ERROR_INVALID_PARAMETER);
}
```

```c
plaintext_data_mldsa.authentication_data_size = authentication_data_size;
if (p_authentication_data) {
    sgx_lfence();
    memcpy(plaintext_data_mldsa.authentication_data, p_authentication_data, sizeof(plaintext_data_mldsa.authentication_data));
}

ret = get_att_key_based_from_seal_key_mldsa(plaintext_data_mldsa.mldsa_att_public_key,
    pmldsa_ciphertext_data->mldsa_private_key,
    &req_key_id);
```

```c
sgx_status = sgx_sha256_update((uint8_t*)plaintext_data_mldsa.mldsa_att_public_key,
    sizeof(plaintext_data_mldsa.mldsa_att_public_key),
    sha_handle);
...
sgx_status = sgx_sha256_get_hash(sha_handle, &plaintext_data_mldsa.mldsa_id);
...
memcpy(&report_data, &plaintext_data_mldsa.mldsa_id, sizeof(plaintext_data_mldsa.mldsa_id));
```

```c
plaintext_data_mldsa.seal_blob_type = SGX_QL_SEAL_MLDSA_65_KEY_BLOB;
plaintext_data_mldsa.mldsa_key_version = SGX_QL_MLDSA_65_KEY_BLOB_VERSION_0;
sgx_status = sgx_seal_data(sizeof(plaintext_data_mldsa),
    reinterpret_cast<uint8_t*>(&plaintext_data_mldsa),
    sizeof(*pmldsa_ciphertext_data),
    reinterpret_cast<uint8_t*>(pmldsa_ciphertext_data),
    blob_size,
    (sgx_sealed_data_t*)p_blob);
```

### Important limitation
- This only makes `gen_att_key(...)` produce an ML-DSA-shaped blob
- The rest of the TDQE and wrapper still need to consume that blob end to end:
  - `verify_blob_internal(...)`
  - wrapper-side sealed-blob parsing in `td_ql_logic.cpp`
  - `store_cert_data(...)`
  - `gen_quote(...)`

### Tests run
- TDQE syntax check passed:

```bash
g++ -std=c++14 -fsyntax-only \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include/tlibc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp
```

- Wrapper library rebuilt successfully after the TDQE changes:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

## Step 20: Added a host-side dynamic test for the TDQE ML-DSA adapter

### What changed
- Added a dedicated dynamic test harness for the imported ML-DSA backend and the local TDQE adapter:
  - [tdx_tests/test_tdqe_mldsa_adapter.c](/home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdqe_mldsa_adapter.c)
- Added a host-only `randombytes()` stub needed when compiling the single-file upstream amalgamation directly into the test binary:
  - [tdx_tests/test_randombytes_stub.c](/home/alocin-local/tdx-pq-attestation/tdx_tests/test_randombytes_stub.c)
- Fixed the imported upstream config so the vendored library actually builds as ML-DSA-65 and excludes randomized APIs:
  - [mldsa_native_config.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/mldsa_native_config.h)
- Fixed the local TDQE adapter so deterministic sign/verify prepare the pure-ML-DSA domain-separation prefix before calling the upstream internal APIs:
  - [tdqe_mldsa_adapter.c](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/tdqe_mldsa_adapter.c)

### Why this step was needed
- The first host-side dynamic test failed at link time because `mldsa_native.c` still referenced `randombytes()`.
- After adding the host-only stub, the test linked but `tdqe_mldsa65_sign()` still failed at runtime.
- Root causes:
  - the imported upstream config was still at the default parameter set `44`
  - the adapter incorrectly called `signature_internal()` / `verify_internal()` with `pre == NULL` and `prelen == 0`, even though the upstream internal API expects the pure-ML-DSA domain-separation prefix to be precomputed by the caller

### Code added

File: [tdx_tests/test_randombytes_stub.c](/home/alocin-local/tdx-pq-attestation/tdx_tests/test_randombytes_stub.c)

```c
int randombytes(uint8_t *out, size_t outlen)
{
    size_t i = 0;

    if (NULL == out) {
        return -1;
    }

    for (i = 0; i < outlen; ++i) {
        out[i] = (uint8_t)(0xA5u ^ (uint8_t)i);
    }

    return 0;
}
```

File: [tdx_tests/test_tdqe_mldsa_adapter.c](/home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdqe_mldsa_adapter.c)

```c
if (0 != tdqe_mldsa65_keygen(public_key, private_key, seed)) {
    fprintf(stderr, "[test] tdqe_mldsa65_keygen failed\n");
    return 1;
}

if (0 != tdqe_mldsa65_sign(signature, message, sizeof(message), private_key)) {
    fprintf(stderr, "[test] tdqe_mldsa65_sign failed\n");
    return 1;
}

if (0 != tdqe_mldsa65_verify(signature, message, sizeof(message), public_key)) {
    fprintf(stderr, "[test] tdqe_mldsa65_verify failed for valid signature\n");
    return 1;
}
```

```c
tampered_message[0] ^= 0x01u;
if (0 == tdqe_mldsa65_verify(signature, tampered_message, sizeof(tampered_message), public_key)) {
    fprintf(stderr, "[test] tdqe_mldsa65_verify unexpectedly accepted a tampered message\n");
    return 1;
}

signature[0] ^= 0x01u;
if (0 == tdqe_mldsa65_verify(signature, message, sizeof(message), public_key)) {
    fprintf(stderr, "[test] tdqe_mldsa65_verify unexpectedly accepted a tampered signature\n");
    return 1;
}
```

```c
if ((0 != memcmp(public_key, public_key_again, sizeof(public_key))) ||
    (0 != memcmp(private_key, private_key_again, sizeof(private_key)))) {
    fprintf(stderr, "[test] tdqe_mldsa65_keygen is not deterministic for the same seed\n");
    return 1;
}

if (0 == memcmp(public_key, public_key_other, sizeof(public_key))) {
    fprintf(stderr, "[test] tdqe_mldsa65_keygen produced the same public key for different seeds\n");
    return 1;
}
```

### Code modified

File: [mldsa_native_config.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/mldsa_native_config.h)

```c
#ifndef MLD_CONFIG_PARAMETER_SET
#define MLD_CONFIG_PARAMETER_SET \
  65 /* TDQE integration uses ML-DSA-65 */
#endif
```

```c
#define MLD_CONFIG_NO_RANDOMIZED_API
```

File: [tdqe_mldsa_adapter.c](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/tdqe_mldsa_adapter.c)

```c
uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES] = {0};
size_t pre_len = 0;
...
pre_len = MLD_API_NAMESPACE(prepare_domain_separation_prefix)(pre,
    NULL,
    0,
    NULL,
    0,
    MLD_PREHASH_NONE);
if (0 == pre_len) {
    return -1;
}
```

```c
ret = MLD_API_NAMESPACE(signature_internal)(signature,
    &signature_len,
    message,
    message_len,
    pre,
    pre_len,
    deterministic_rnd,
    private_key,
    0);
```

```c
return MLD_API_NAMESPACE(verify_internal)(signature,
    SGX_QL_MLDSA_65_SIG_SIZE,
    message,
    message_len,
    pre,
    pre_len,
    public_key,
    0);
```

### Tests run

- Rebuilt the host-side adapter test:

```bash
gcc -std=c11 \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/src \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux \
  /home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdqe_mldsa_adapter.c \
  /home/alocin-local/tdx-pq-attestation/tdx_tests/test_randombytes_stub.c \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/tdqe_mldsa_adapter.c \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/pq/mldsa-native/mldsa/mldsa_native.c \
  -o /home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdqe_mldsa_adapter
```

- Ran the dynamic test successfully:

```bash
/home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdqe_mldsa_adapter
```

Output:

```text
[test] TDQE ML-DSA adapter passed: keygen/sign/verify deterministic checks OK
[test] sizes: pub=1952 priv=4032 sig=3309
```

- Confirmed the TDQE enclave build still succeeds after the adapter/config fixes:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

### Result
- The imported ML-DSA backend is now verified dynamically for the exact TDQE-facing adapter API:
  - deterministic key generation from a fixed seed
  - deterministic signing
  - verification success on valid input
  - verification failure on tampered message/signature
- This does not yet mean end-to-end ML-DSA quote generation works.
- It does mean the cryptographic backend and the local adapter are now proven to work independently of the remaining TDQE quote-path plumbing.

## Step 21: Generalized TDQE `gen_quote(...)` to open and sign from both ECDSA and ML-DSA blobs

### What changed
- Added a new internal helper to unseal and reseal either attestation-key blob type while returning the algorithm-specific secret data:
  - [quoting_enclave_tdqe.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp)
    - `verify_blob_data_any_internal(...)`
- Updated [gen_quote(...)](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp) to:
  - accept the correct blob size for the selected `algorithm_id`
  - unseal either an ECDSA blob or an ML-DSA blob
  - read common metadata (`authentication_data`, `qe_id`, `qe_report`, `cert_pce_info`, `cert_cpu_svn`, encrypted PPID) from the right plaintext/ciphertext structure
  - keep the existing ECDSA signing/verification path unchanged
  - add a real ML-DSA quote-signing branch using:
    - `tdqe_mldsa65_sign(...)`
    - `tdqe_mldsa65_verify(...)`
  - write the correct algorithm-specific attestation public key into the quote signature area

### Code added

File: [quoting_enclave_tdqe.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp)

```c
static tdqe_error_t verify_blob_data_any_internal(uint8_t *p_blob,
    uint32_t blob_size,
    uint32_t algorithm_id,
    uint8_t *p_is_resealed,
    ref_plaintext_ecdsa_data_sdk_t *p_plaintext_ecdsa,
    ref_ciphertext_ecdsa_data_sdk_t *p_secret_ecdsa_data,
    ref_plaintext_mldsa_65_data_sdk_t *p_plaintext_mldsa,
    ref_ciphertext_mldsa_65_data_sdk_t *p_secret_mldsa_data)
```

```c
if (algorithm_id == SGX_QL_ALG_ECDSA_P256) {
    ...
    sgx_status = sgx_unseal_data(p_sealed_blob,
        reinterpret_cast<uint8_t *>(p_plaintext_ecdsa),
        &plaintext_length,
        reinterpret_cast<uint8_t *>(p_secret_ecdsa_data),
        &decryptedtext_length);
    ...
} else {
    ...
    sgx_status = sgx_unseal_data(p_sealed_blob,
        reinterpret_cast<uint8_t *>(p_plaintext_mldsa),
        &plaintext_length,
        reinterpret_cast<uint8_t *>(p_secret_mldsa_data),
        &decryptedtext_length);
    ...
}
```

### Code modified

File: [quoting_enclave_tdqe.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp)

`gen_quote(...)` now allocates both plaintext/ciphertext variants and derives common metadata pointers from the selected algorithm:

```c
ref_plaintext_ecdsa_data_sdk_t plaintext;
ref_plaintext_mldsa_65_data_sdk_t plaintext_mldsa;
...
ref_ciphertext_ecdsa_data_sdk_t* pciphertext = &ociphertext->v;
ref_ciphertext_mldsa_65_data_sdk_t ciphertext_mldsa;
ref_ciphertext_mldsa_65_data_sdk_t* pciphertext_mldsa = &ciphertext_mldsa;
...
uint32_t authentication_data_size = 0;
const uint8_t *p_blob_authentication_data = NULL;
const sgx_key_128bit_t *p_blob_qe_id = NULL;
const sgx_report_t *p_blob_qe_report = NULL;
const sgx_ec256_signature_t *p_blob_qe_report_sig = NULL;
const sgx_pce_info_t *p_blob_cert_pce_info = NULL;
const sgx_cpu_svn_t *p_blob_cert_cpu_svn = NULL;
uint8_t blob_is_clear_ppid = 0;
const ref_encrypted_ppid_t *p_blob_encrypted_ppid = NULL;
```

```c
ret = random_stack_advance(verify_blob_data_any_internal,p_blob,
    blob_size,
    algorithm_id,
    &is_resealed,
    &plaintext,
    pciphertext,
    &plaintext_mldsa,
    pciphertext_mldsa);
```

```c
if (algorithm_id == SGX_QL_ALG_ECDSA_P256) {
    authentication_data_size = plaintext.authentication_data_size;
    p_blob_authentication_data = plaintext.authentication_data;
    p_blob_qe_id = &plaintext.qe_id;
    ...
} else {
    authentication_data_size = plaintext_mldsa.authentication_data_size;
    p_blob_authentication_data = plaintext_mldsa.authentication_data;
    p_blob_qe_id = &plaintext_mldsa.qe_id;
    ...
}
```

The quote-signing section now dispatches on the selected attestation algorithm:

```c
if (algorithm_id == SGX_QL_ALG_ECDSA_P256) {
    sgx_status = sgx_ecdsa_sign(...);
    ...
    sgx_status = sgx_ecdsa_verify(...);
    ...
    memcpy(p_quote_sig_pub_key, &plaintext.ecdsa_att_public_key, sizeof(plaintext.ecdsa_att_public_key));
} else {
    if (0 != tdqe_mldsa65_sign(p_quote_sig,
        p_quote_buf,
        sign_buf_size,
        pciphertext_mldsa->mldsa_private_key)) {
        ret = TDQE_ERROR_UNEXPECTED;
        goto ret_point;
    }
    if (0 != tdqe_mldsa65_verify(p_quote_sig,
        p_quote_buf,
        sign_buf_size,
        plaintext_mldsa.mldsa_att_public_key)) {
        ret = TDQE_ERROR_UNEXPECTED;
        goto ret_point;
    }
    memcpy(p_quote_sig_pub_key,
        plaintext_mldsa.mldsa_att_public_key,
        sizeof(plaintext_mldsa.mldsa_att_public_key));
}
```

The shared certification-data copy now reads from algorithm-neutral pointers instead of assuming ECDSA plaintext/ciphertext layout:

```c
memcpy(&(p_qe_report_cert_data->qe_report), &p_blob_qe_report->body, sizeof(p_qe_report_cert_data->qe_report));
memcpy(p_qe_report_cert_data->qe_report_sig, p_blob_qe_report_sig, sizeof(p_qe_report_cert_data->qe_report_sig));
...
memcpy(p_cert_encrypted_ppid_info_data->enc_ppid, p_blob_encrypted_ppid->encrypted_ppid, sizeof(p_cert_encrypted_ppid_info_data->enc_ppid));
p_cert_encrypted_ppid_info_data->pce_info = *p_blob_cert_pce_info;
memcpy(&p_cert_encrypted_ppid_info_data->cpu_svn, p_blob_cert_cpu_svn, sizeof(p_cert_encrypted_ppid_info_data->cpu_svn));
```

### Tests run

- Rebuilt the TDQE enclave after the `gen_quote(...)` changes:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
SIGN =>  libsgx_tdqe.signed.so
```

- Rebuilt the TDX wrapper after the TDQE changes:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

- Re-ran the host-side ML-DSA adapter dynamic test to confirm the backend still behaves correctly:

```bash
/home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdqe_mldsa_adapter
```

Output:

```text
[test] TDQE ML-DSA adapter passed: keygen/sign/verify deterministic checks OK
[test] sizes: pub=1952 priv=4032 sig=3309
```

### Result
- `gen_quote(...)` is no longer structurally ECDSA-only.
- The TDQE can now build with a real ML-DSA signing branch for the quote body while still preserving the existing ECDSA path.
- This still does not mean end-to-end ML-DSA quote generation from the public wrapper works yet, because the remaining certification-storage path is still not generalized:
  - `store_cert_data(...)` is still typed as `ref_plaintext_ecdsa_data_sdk_t *`
  - `tdqe.edl` still exposes only the ECDSA plaintext type for certification storage
  - the wrapper certification flow in `td_ql_logic.cpp` still prepares ECDSA-typed plaintext for the TDQE

## Step 22: Generalized certification storage across EDL, wrapper, and TDQE

### What changed
- Changed the TDQE ECALL signature for certification storage from an ECDSA-specific plaintext struct to an opaque byte buffer plus explicit size:
  - [tdqe.edl](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/tdqe.edl)
- Updated the wrapper-side `certify_key(...)` helper to accept opaque plaintext bytes and dispatch internally based on the plaintext size:
  - [td_ql_logic.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.h)
  - [td_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp)
- Reworked the TDQE-side `store_cert_data(...)` implementation so it:
  - infers the attestation algorithm from the blob size
  - validates the matching plaintext payload size
  - unseals either ECDSA or ML-DSA blob contents
  - checks the `qe_report.body.report_data` against the right key identifier (`ecdsa_id` or `mldsa_id`)
  - reseals the updated blob using the matching plaintext/ciphertext layout
  - preserves the existing ECDSA behavior
  - adds the parallel ML-DSA storage path
  - [quoting_enclave_tdqe.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp)

### Code modified

File: [tdqe.edl](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/tdqe.edl)

```c
public uint32_t store_cert_data([in, size = plaintext_data_size] uint8_t *p_plaintext_data,
                                uint32_t plaintext_data_size,
                                sgx_ql_cert_key_type_t certification_key_type,
                                [in, size = encrypted_ppid_size] uint8_t* p_encrypted_ppid,
                                uint32_t encrypted_ppid_size,
                                [in, out, size = blob_size] uint8_t *p_blob,
                                uint32_t blob_size);
```

File: [td_ql_logic.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.h)

```c
tee_att_error_t certify_key(uint8_t* p_ecdsa_blob,
    uint8_t* p_plaintext_data,
    uint32_t plaintext_data_size,
    uint8_t* p_encrypted_ppid,
    uint32_t encrypted_ppid_size,
    sgx_ql_cert_key_type_t certification_key_type);
```

File: [td_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp)

`certify_key(...)` now dispatches the PCE report-signing inputs from either plaintext layout:

```c
if (plaintext_data_size == sizeof(ref_plaintext_ecdsa_data_sdk_t)) {
    p_plaintext_ecdsa = reinterpret_cast<ref_plaintext_ecdsa_data_sdk_t *>(p_plaintext_data);
    p_cert_pce_isv_svn = &p_plaintext_ecdsa->cert_pce_info.pce_isv_svn;
    p_cert_cpu_svn = &p_plaintext_ecdsa->cert_cpu_svn;
    p_qe_report = &p_plaintext_ecdsa->qe_report;
    p_qe_report_cert_key_sig = &p_plaintext_ecdsa->qe_report_cert_key_sig;
} else if (plaintext_data_size == sizeof(ref_plaintext_mldsa_65_data_sdk_t)) {
    p_plaintext_mldsa = reinterpret_cast<ref_plaintext_mldsa_65_data_sdk_t *>(p_plaintext_data);
    p_cert_pce_isv_svn = &p_plaintext_mldsa->cert_pce_info.pce_isv_svn;
    p_cert_cpu_svn = &p_plaintext_mldsa->cert_cpu_svn;
    p_qe_report = &p_plaintext_mldsa->qe_report;
    p_qe_report_cert_key_sig = &p_plaintext_mldsa->qe_report_cert_key_sig;
}
```

The wrapper certification path now builds the right plaintext struct before calling the ECALL:

```c
refqt_ret = certify_key(m_ecdsa_blob,
                        reinterpret_cast<uint8_t*>(&plaintext_data_mldsa),
                        sizeof(plaintext_data_mldsa),
                        encrypted_ppid,
                        REF_RSA_OAEP_3072_MOD_SIZE,
                        certification_key_type);
```

File: [quoting_enclave_tdqe.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp)

`store_cert_data(...)` now accepts opaque plaintext input:

```c
uint32_t store_cert_data(uint8_t *p_plaintext_data,
    uint32_t plaintext_data_size,
    sgx_ql_cert_key_type_t cert_key_type,
    uint8_t *p_encrypted_ppid,
    uint32_t encrypted_ppid_size,
    uint8_t *p_blob,
    uint32_t blob_size)
```

It determines the selected attestation algorithm from `blob_size` and validates the matching plaintext payload:

```c
if (blob_size == SGX_QL_TRUSTED_ECDSA_BLOB_SIZE_SDK) {
    algorithm_id = SGX_QL_ALG_ECDSA_P256;
    if (plaintext_data_size != sizeof(input_plaintext_ecdsa)) {
        return(TDQE_ERROR_INVALID_PARAMETER);
    }
    memcpy(&input_plaintext_ecdsa, p_plaintext_data, sizeof(input_plaintext_ecdsa));
} else {
    algorithm_id = SGX_QL_ALG_MLDSA_65;
    if (plaintext_data_size != sizeof(input_plaintext_mldsa)) {
        return(TDQE_ERROR_INVALID_PARAMETER);
    }
    memcpy(&input_plaintext_mldsa, p_plaintext_data, sizeof(input_plaintext_mldsa));
}
```

It now reuses the algorithm-aware unseal helper:

```c
ret = random_stack_advance(verify_blob_data_any_internal,p_blob,
    blob_size,
    algorithm_id,
    &is_resealed,
    &local_plaintext_data,
    pciphertext_data,
    &local_plaintext_data_mldsa,
    &ciphertext_data_mldsa);
```

And it compares the right key identifier against `qe_report.body.report_data`:

```c
if (algorithm_id == SGX_QL_ALG_ECDSA_P256) {
    if (0 != memcmp(&local_plaintext_data.ecdsa_id,
            &input_plaintext_ecdsa.qe_report.body.report_data,
            sizeof(local_plaintext_data.ecdsa_id))) {
        ret = TDQE_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }
} else {
    if (0 != memcmp(&local_plaintext_data_mldsa.mldsa_id,
            &input_plaintext_mldsa.qe_report.body.report_data,
            sizeof(local_plaintext_data_mldsa.mldsa_id))) {
        ret = TDQE_ERROR_INVALID_PARAMETER;
        goto ret_point;
    }
}
```

### Tests run

- Rebuilt the TDQE enclave successfully after the EDL and certification-storage changes:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
SIGN =>  libsgx_tdqe.signed.so
```

- Rebuilt the TDX wrapper successfully after the wrapper-side certification changes:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

- Re-ran the host-side ML-DSA adapter test:

```bash
/home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdqe_mldsa_adapter
```

Output:

```text
[test] TDQE ML-DSA adapter passed: keygen/sign/verify deterministic checks OK
[test] sizes: pub=1952 priv=4032 sig=3309
```

- Rebuilt and ran the wrapper algorithm-selection test:

```bash
g++ -std=c++14 \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/inc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux \
  -I/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe \
  -I/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include \
  /home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdx_wrapper_algorithms.cpp \
  -L/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  -L/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux \
  -L/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/lib64 \
  -Wl,-rpath,/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
  -Wl,-rpath,/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux \
  -Wl,-rpath,/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/lib64 \
  -lsgx_tdx_logic -lsgx_urts -lpthread -ldl \
  -o /home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdx_wrapper_algorithms
```

```bash
/home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdx_wrapper_algorithms
```

Output:

```text
[mldsa_get_quote_size td_ql_logic.cpp:2079] [tdx-quote-debug] mldsa_get_quote_size: quote_size=7102 (default certification data path only).
[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=7102)
```

- Attempted an ECDSA direct smoke test with repo-local libraries:

```bash
LD_LIBRARY_PATH=/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux:/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux:/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux:/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/lib64 \
  /home/alocin-local/tdx-pq-attestation/tdx_tests/test_app_direct
```

Result in this environment:

```text
[test] using verifier challenge from demo:fallback
[test] WARNING: no valid verifier challenge configured; using demo challenge (NOT production)
[test] --------------- request TD REPORT...
[test] tdx_att_get_report failed: 0xa
```

### Result
- The certification-storage path is now generalized across:
  - TDQE EDL
  - TDQE sealing logic
  - wrapper-side certification flow
- The existing ECDSA build path still compiles cleanly.
- The ML-DSA adapter and wrapper-selection tests still pass.
- The remaining gap is no longer certification storage. The next real step is an end-to-end ML-DSA quote-generation test path that exercises:
  - `init_quote`
  - certification storage
  - `get_quote`
  - quote parsing / verification

## Step 23: Added a dedicated ML-DSA wrapper end-to-end test runner and cleaned up the test layout

### What changed
- Moved the wrapper-focused ML-DSA test sources under a dedicated subdirectory:
  - [test_tdx_wrapper_mldsa_e2e.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/test_tdx_wrapper_mldsa_e2e.cpp)
  - [test_tdx_wrapper_algorithms.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/test_tdx_wrapper_algorithms.cpp)
- Added a dedicated runner script for the ML-DSA wrapper end-to-end flow:
  - [run_mldsa_e2e.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/run_mldsa_e2e.sh)
- Added a short layout guide for the test directory:
  - [README.md](/home/alocin-local/tdx-pq-attestation/tdx_tests/README.md)

### Why this step was needed
- The wrapper ML-DSA end-to-end test had grown beyond an ad-hoc one-off compile command.
- The test needed a stable runner that:
  - builds the repo-local TDQE
  - builds the repo-local wrapper and `libtdx_attest`
  - compiles the new end-to-end test with the correct repo-local include and library paths
  - runs it with the expected runtime library path
- The top-level `tdx_tests/` directory had started to mix:
  - helper binaries
  - legacy top-level tests
  - new wrapper-specific ML-DSA work

### Code added

File: [run_mldsa_e2e.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/run_mldsa_e2e.sh)

```bash
echo "[INFO] Building repo-local TDQE..."
make -C "$TDQE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK"

echo "[INFO] Building repo-local TDX quote wrapper..."
make -C "$TDX_QUOTE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK"

echo "[INFO] Building repo-local libtdx_attest..."
make -C "$TDX_ATTEST_LINUX_DIR"
```

```bash
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  ... \
  "$SCRIPT_DIR/test_tdx_wrapper_mldsa_e2e.cpp" \
  ... \
  -lsgx_tdx_logic -ltdx_attest -lsgx_urts -lpthread -ldl \
  -o "$OUT_BIN"
```

```bash
TEST_TDQE_PATH="$TDQE_SIGNED" \
LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
  "$OUT_BIN"
```

File: [README.md](/home/alocin-local/tdx-pq-attestation/tdx_tests/README.md)

```md
## Layout

- `wrapper/`
  - wrapper-facing ML-DSA and algorithm-selection test sources
  - helper runner scripts for wrapper tests
- `sgxsdk/`
  - repo-local SDK copy used by the local test/build scripts
- top-level binaries and legacy sources
  - kept in place to avoid breaking existing flows such as `run_tdx_tests.sh`
```

### Code modified

File: [test_tdx_wrapper_mldsa_e2e.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/test_tdx_wrapper_mldsa_e2e.cpp)

The test now accepts the TDQE path from the environment and passes it into the wrapper context creation:

```c
const char *tdqe_path = std::getenv("TEST_TDQE_PATH");
...
tee_ret = tee_att_create_context(nullptr, tdqe_path, &default_context);
...
tee_ret = tee_att_create_context(&att_key_id, tdqe_path, &context);
```

### Tests run

- The new end-to-end test source compiled successfully from the new `tdx_tests/wrapper/` location:

```bash
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  ... \
  /home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/test_tdx_wrapper_mldsa_e2e.cpp \
  ... \
  -o /home/alocin-local/tdx-pq-attestation/tdx_tests/test_tdx_wrapper_mldsa_e2e
```

- The new runner script executed successfully through all build steps:

```bash
/home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/run_mldsa_e2e.sh
```

Build-stage result:

```text
[INFO] Building repo-local TDQE...
[INFO] Building repo-local TDX quote wrapper...
[INFO] Building repo-local libtdx_attest...
[INFO] Compiling ML-DSA wrapper end-to-end test...
[INFO] Running ML-DSA wrapper end-to-end test...
```

Runtime result in the current environment:

```text
[test] tee_att_init_quote(MLDSA_65) failed: 0x1100d
```

Interpreted wrapper error:

```text
TEE_ATT_INTERFACE_UNAVAILABLE
```

### Result
- The test directory is cleaner for the new wrapper ML-DSA work.
- There is now a single script to build and run the public ML-DSA wrapper end-to-end test.
- The script itself is not the current blocker.
- The current blocker is the public wrapper flow failing inside `tee_att_init_quote(MLDSA_65)` with `TEE_ATT_INTERFACE_UNAVAILABLE`, which means the next debugging step is in the enclave/interface loading path of the public wrapper flow rather than in:
  - the ML-DSA crypto backend
  - the TDQE build
  - the certification-storage plumbing
  - the test runner

## Step 24: Fixed the ML-DSA wrapper runner to avoid a broken repo-local PCE runtime pairing

### What changed
- I diagnosed the `TEE_ATT_INTERFACE_UNAVAILABLE (0x1100d)` failure in the new public ML-DSA wrapper test runner.
- The issue was not in the ML-DSA quote path itself. It was in the runtime library selection of the test script:
  - the repo-local `libsgx_pce_logic.so.1` was being forced through `LD_LIBRARY_PATH`
  - that wrapper resolves `libsgx_pce.signed.so.1` relative to its own directory
  - there is no matching PCE signed enclave in `QuoteGeneration/pce_wrapper/linux/`
  - so `sgx_pce_get_target()` failed and the wrapper returned `TEE_ATT_INTERFACE_UNAVAILABLE`
- I changed the runner to select the PCE runtime directory dynamically:
  - use the repo-local PCE wrapper directory only if it also contains `libsgx_pce.signed.so.1` or `libsgx_pce.signed.so`
  - otherwise fall back to the system SGX runtime directory `/lib/x86_64-linux-gnu`, where the matching PCE runtime artifacts are installed on this machine

### Why this step was needed
- The earlier version of the script always exported:

```bash
LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}"
```

- That made the new ML-DSA end-to-end test load the repo-local `libsgx_pce_logic.so.1`.
- In this repository checkout, the repo-local PCE wrapper directory does not contain:

```text
libsgx_pce.signed.so.1
```

- The repo-local PCE wrapper resolves the enclave path relative to its own `.so` path:

File: [pce_wrapper.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/pce_wrapper.cpp)

```c
#define PCE_ENCLAVE_NAME "libsgx_pce.signed.so.1"
#define PCE_ENCLAVE_NAME_LEGACY "libsgx_pce.signed.so"
...
(void)strncat(p_file_path,PCE_ENCLAVE_NAME, strnlen(PCE_ENCLAVE_NAME,buf_size));
...
(void)strncat(p_file_path,PCE_ENCLAVE_NAME_LEGACY, strnlen(PCE_ENCLAVE_NAME_LEGACY,buf_size));
```

- Because the matching signed enclave was missing beside the repo-local wrapper, `load_pce()` could not load the PCE enclave and returned `SGX_PCE_INTERFACE_UNAVAILABLE`.

### Code modified

File: [run_mldsa_e2e.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/run_mldsa_e2e.sh)

Added runtime selection variables:

```bash
SYSTEM_PCE_DIR="/lib/x86_64-linux-gnu"
PCE_RUNTIME_LIB_DIR="$SYSTEM_PCE_DIR"
```

Added dynamic selection logic:

```bash
if [[ -f "$PCE_WRAPPER_LINUX_DIR/libsgx_pce.signed.so.1" || -f "$PCE_WRAPPER_LINUX_DIR/libsgx_pce.signed.so" ]]; then
  PCE_RUNTIME_LIB_DIR="$PCE_WRAPPER_LINUX_DIR"
fi
```

Changed the runtime launch environment:

```bash
echo "[INFO] Using PCE runtime library directory: $PCE_RUNTIME_LIB_DIR"
TEST_TDQE_PATH="$TDQE_SIGNED" \
LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_RUNTIME_LIB_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
  "$OUT_BIN"
```

### Tests run

- Confirmed the repo-local PCE wrapper resolves correctly only when explicitly forced in the environment:

```bash
LD_LIBRARY_PATH=/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux:... \
ldd /home/alocin-local/tdx-pq-attestation/tdx_tests/bin/test_tdx_wrapper_mldsa_e2e
```

Relevant result:

```text
libsgx_pce_logic.so.1 => /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux/libsgx_pce_logic.so.1
```

- Confirmed that the system SGX runtime provides the signed PCE enclave that the repo-local directory lacks:

```bash
ls -l /lib/x86_64-linux-gnu/libsgx_pce.signed.so /lib/x86_64-linux-gnu/libsgx_pce.signed.so.1
```

Result:

```text
/lib/x86_64-linux-gnu/libsgx_pce.signed.so -> libsgx_pce.signed.so.1
/lib/x86_64-linux-gnu/libsgx_pce.signed.so.1 -> libsgx_pce.signed.so.1.25.100.1
```

### Result
- The ML-DSA wrapper end-to-end runner no longer forces a broken local PCE-wrapper/runtime pairing.
- The script now prefers the system PCE runtime when the repo checkout does not include the matching PCE signed enclave.
- This keeps the repo-local TDQE and repo-local TDX wrapper in use, while letting the test reuse the machine's installed SGX PCE runtime artifacts.

## Step 25: Made the public ML-DSA wrapper runner skip cleanly on TDX-only machines without an SGX enclave device

### What changed
- After fixing the PCE runtime directory selection, I reran the wrapper ML-DSA end-to-end script.
- That exposed the next real environment failure:

```text
[load_pce pce_wrapper.cpp:174] Error, call sgx_create_enclave for PCE fail [load_pce], SGXError:2006.
[test] tee_att_init_quote(MLDSA_65) failed: 0x1100d
```

- `SGXError:2006` maps to `SGX_ERROR_NO_DEVICE`, which means the SGX runtime could not open an SGX enclave device.
- This is not a bug in the ML-DSA implementation. It is an environment limitation of this machine: the public wrapper flow uses the SGX PCE path during `tee_att_init_quote()`, and that path needs an SGX enclave device in addition to the TDX guest device.
- I updated the wrapper test script to detect the absence of an SGX enclave device and return a clear `SKIP` instead of a misleading failure.

### Why this step was needed
- The machine can run direct TDX attestation tests, but that is not sufficient for the public wrapper `tee_att_init_quote()` path.
- The public wrapper path still calls into the SGX PCE flow, which creates the PCE enclave.
- On a TDX-only machine without an SGX enclave device, the test can never pass dynamically, regardless of whether the ML-DSA code is correct.
- The script needed to distinguish:
  - code/build failures
  - environment/runtime unavailability

### Code modified

File: [run_mldsa_e2e.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/run_mldsa_e2e.sh)

Added SGX-device detection:

```bash
has_sgx_device() {
  [[ -e /dev/sgx_enclave || -e /dev/sgx/enclave || -e /dev/isgx ]]
}
```

Added a pre-run skip gate:

```bash
if ! has_sgx_device; then
  echo "[SKIP] No SGX enclave device found (/dev/sgx_enclave, /dev/sgx/enclave, or /dev/isgx)."
  echo "[SKIP] The public wrapper ML-DSA end-to-end test requires the SGX PCE path used by tee_att_init_quote()."
  echo "[SKIP] Repo-local TDQE/wrapper build succeeded; run this script on a machine with both TDX guest support and SGX PSW device support."
  exit 0
fi
```

I also removed the explicit executable `rpath` entry for the repo-local PCE wrapper directory:

```bash
-  -Wl,-rpath,"$PCE_WRAPPER_LINUX_DIR" \
```

This avoids accidentally biasing the executable toward the repo-local PCE wrapper at runtime when that directory does not contain a matching PCE signed enclave.

### Tests run

- Re-ran the wrapper ML-DSA end-to-end script after the PCE runtime-directory fix:

```bash
/home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/run_mldsa_e2e.sh
```

Observed runtime result before adding the skip gate:

```text
[INFO] Using PCE runtime library directory: /lib/x86_64-linux-gnu
[load_pce pce_wrapper.cpp:174] Error, call sgx_create_enclave for PCE fail [load_pce], SGXError:2006.
[test] tee_att_init_quote(MLDSA_65) failed: 0x1100d
```

- Decoded the SGX runtime failure from the local SDK header:

File: [sgx_error.h](/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/include/sgx_error.h)

```c
SGX_ERROR_NO_DEVICE          = SGX_MK_ERROR(0x2006),      /* Can't open SGX device */
```

### Result
- The ML-DSA wrapper end-to-end script now behaves correctly on this machine class.
- It still builds the repo-local TDQE, repo-local wrapper, and the ML-DSA end-to-end test binary.
- On a TDX-only environment without SGX enclave-device support, it reports a clear skip instead of a false code failure.
- This keeps the script useful both:
  - as a build/integration smoke test on TDX-only guests
  - as a real runtime wrapper test on machines that have both TDX guest support and SGX PCE runtime support

## Step 26: Added a separate TDX-only ML-DSA test suite instead of modifying the existing ECDSA direct test

### What changed
- I did not modify the existing direct ECDSA test in `tdx_tests/test_tdx_quote_wrapper.cpp`.
- Instead, I added a separate direct-path test probe and a separate runner for ML-DSA-related testing in the current `tdx_guest`-oriented environment.
- The new suite focuses on what can actually be exercised on this machine:
  - the real ML-DSA backend integrated into the TDQE
  - the quote/header/layout definitions for ML-DSA
  - the wrapper-side ML-DSA algorithm-selection and quote-size path
  - the current capabilities of the direct `libtdx_attest` API

### Why this step was needed
- The user explicitly asked for a new test instead of adapting the existing ECDSA test.
- The direct `libtdx_attest` path is not yet ML-DSA-selectable in the current implementation.
- I confirmed that in the `tdx_attest` source:

File: [tdx_attest.c](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c)

```c
static const tdx_uuid_t g_intel_tdqe_uuid = {TDX_SGX_ECDSA_ATTESTATION_ID};
```

```c
if (p_att_key_id_list && memcmp(p_att_key_id_list, &g_intel_tdqe_uuid,
                sizeof(g_intel_tdqe_uuid))) {
    return TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID;
}
```

```c
if (TDX_ATTEST_SUCCESS == ret && p_att_key_id) {
    *p_att_key_id = g_intel_tdqe_uuid;
}
```

```c
if (p_att_key_id_list) {
    p_att_key_id_list[0] = g_intel_tdqe_uuid;
}
*p_list_size = 1;
```

- This means the direct TDX attestation API currently exposes only the default Intel TDQE UUID path, which is still the ECDSA one.
- So the correct solution was:
  - keep the ECDSA direct test untouched
  - add a new ML-DSA-oriented suite that is honest about what is and is not exposed through the direct API today

### Code added

File: [test_tdx_direct_mldsa_probe.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/test_tdx_direct_mldsa_probe.cpp)

This new probe:
- queries the direct TDX attestation key-id list
- requests a real TD report
- requests a real quote through `tdx_att_get_quote`
- parses the quote header
- prints whether the direct path is still ECDSA-only or has begun exposing ML-DSA

Relevant code:

```c++
attest_ret = tdx_att_get_supported_att_key_ids(nullptr, &supported_id_count);
...
attest_ret = tdx_att_get_supported_att_key_ids(supported_ids.data(), &supported_id_count);
...
attest_ret = tdx_att_get_report(&report_data, &td_report);
...
attest_ret = tdx_att_get_quote(&report_data,
                               supported_ids.data(),
                               supported_id_count,
                               &selected_att_key_id,
                               &quote,
                               &quote_size,
                               0);
```

```c++
if (is_intel_tdqe_ecdsa_uuid(selected_att_key_id) &&
    quote_header->att_key_type == SGX_QL_ALG_ECDSA_P256) {
    std::printf("[test] direct TDX attestation path is currently ECDSA-only on this build/runtime.\n");
    std::printf("[test] ML-DSA direct quote selection is not yet exposed through libtdx_attest.\n");
}
```

File: [run_mldsa_tdx_only_tests.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh)

This new runner:
- builds the repo-local TDQE
- builds the repo-local TDX quote wrapper
- builds the repo-local `libtdx_attest`
- compiles and runs:
  - the TDQE ML-DSA adapter test
  - the ML-DSA header/layout static test
  - the TDQE ML-DSA quote-layout static test
  - the wrapper ML-DSA algorithm-selection test
  - the direct TDX capability probe

Relevant code:

```bash
TDQE_MLDSA_ADAPTER_BIN="$BIN_DIR/test_tdqe_mldsa_adapter"
QUOTE_HEADERS_BIN="$BIN_DIR/test_quote_headers_mldsa"
TDQE_LAYOUT_BIN="$BIN_DIR/test_tdqe_quote_layout_mldsa"
WRAPPER_ALGORITHMS_BIN="$BIN_DIR/test_tdx_wrapper_algorithms"
TDX_DIRECT_PROBE_BIN="$BIN_DIR/test_tdx_direct_mldsa_probe"
```

```bash
echo "[INFO] Running TDQE ML-DSA adapter test..."
"$TDQE_MLDSA_ADAPTER_BIN"
...
echo "[INFO] Running wrapper ML-DSA algorithm-selection test..."
LD_LIBRARY_PATH="$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
  "$WRAPPER_ALGORITHMS_BIN"
```

I also added direct-device permission handling:

```bash
for dev in /dev/tdx_guest /dev/tdx-guest /dev/tdx*; do
  if [[ -e "$dev" ]]; then
    TDX_GUEST_DEV="$dev"
    break
  fi
done
```

```bash
if [[ ! -r "$TDX_GUEST_DEV" || ! -w "$TDX_GUEST_DEV" ]]; then
  echo "[SKIP] Insufficient permissions on $TDX_GUEST_DEV; skipping the direct TDX ML-DSA capability probe."
  echo "[SKIP] Run this script with elevated privileges to exercise the direct TDX path."
  exit 0
fi
```

### Code modified

File: [README.md](/home/alocin-local/tdx-pq-attestation/tdx_tests/README.md)

Added the new `direct/` area and the new runner entry point:

```md
- `direct/`
  - TDX direct-path probes and runner scripts
  - intended for environments that have `tdx_guest` but not necessarily the SGX PCE device path
```

```md
- TDX-only ML-DSA component and capability flow:
  - `./tdx_tests/direct/run_mldsa_tdx_only_tests.sh`
```

### Tests run

- Ran the new separate TDX-only ML-DSA suite:

```bash
/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Observed output:

```text
[INFO] Running TDQE ML-DSA adapter test...
[test] TDQE ML-DSA adapter passed: keygen/sign/verify deterministic checks OK
[test] sizes: pub=1952 priv=4032 sig=3309
[INFO] Running quote header ML-DSA layout test...
[INFO] Running TDQE ML-DSA quote layout test...
[INFO] Running wrapper ML-DSA algorithm-selection test...
[mldsa_get_quote_size td_ql_logic.cpp:2079] [tdx-quote-debug] mldsa_get_quote_size: quote_size=7102 (default certification data path only).
[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=7102)
[SKIP] Insufficient permissions on /dev/tdx_guest; skipping the direct TDX ML-DSA capability probe.
[SKIP] Run this script with elevated privileges to exercise the direct TDX path.
```

Before adding the permission-aware skip, the direct probe had reached the TDX device and failed with:

```text
[test] direct supported att key id[0]: e86c046e8cc44d958173fc43c1fa4f3f
[test] tdx_att_get_report failed: 0xa
```

where `0xa` is `TDX_ATTEST_ERROR_DEVICE_FAILURE` from the direct API.

### Result
- The existing ECDSA direct test remains untouched.
- There is now a separate ML-DSA-oriented test suite for the current environment.
- The new suite gives useful signal today:
  - ML-DSA crypto backend works
  - ML-DSA quote/header/layout definitions are consistent
  - wrapper-side ML-DSA selection and quote-size logic works
  - the direct `libtdx_attest` path is still gated by the currently exposed direct API and by `tdx_guest` device permissions

## Step 27: Refactored `tdx_tests/` into role-based subdirectories and kept compatibility entry points

### What changed
- I reorganized `tdx_tests/` so that sources, runners, shared helpers, verifier code, and generated artifacts are no longer mixed at the top level.
- The refactor was done conservatively:
  - existing flows were preserved
  - the familiar top-level command `./tdx_tests/run_tdx_ecdsa_tests.sh` still works through a compatibility shim
  - build paths in the repo-local `Makefile` and test runners were updated to the new locations

### New layout

The test tree is now structured like this:

```text
tdx_tests/
├─ bin/
├─ common/
├─ direct/
├─ format/
├─ tdqe/
├─ verifier/
├─ wrapper/
├─ sgxsdk/
├─ README.md
└─ run_tdx_ecdsa_tests.sh
```

### Files moved

- Shared helpers:
  - [utils.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/common/utils.cpp)
  - [utils.h](/home/alocin-local/tdx-pq-attestation/tdx_tests/common/utils.h)

- Direct-path tests and runners:
  - [run_tdx_ecdsa_tests.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_tdx_ecdsa_tests.sh)
  - [test_tdx_quote_wrapper.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/test_tdx_quote_wrapper.cpp)
  - [test_tdx_direct_mldsa_probe.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/test_tdx_direct_mldsa_probe.cpp)

- Verifier source:
  - [local_tdx_verifier.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/verifier/local_tdx_verifier.cpp)

- TDQE/ML-DSA backend tests:
  - [test_tdqe_mldsa_adapter.c](/home/alocin-local/tdx-pq-attestation/tdx_tests/tdqe/test_tdqe_mldsa_adapter.c)
  - [test_tdqe_quote_layout_mldsa.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/tdqe/test_tdqe_quote_layout_mldsa.cpp)
  - [test_randombytes_stub.c](/home/alocin-local/tdx-pq-attestation/tdx_tests/tdqe/test_randombytes_stub.c)

- Quote-format static tests:
  - [test_quote_headers_mldsa.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/format/test_quote_headers_mldsa.cpp)

- Generated artifacts/logs moved under:
  - [bin](/home/alocin-local/tdx-pq-attestation/tdx_tests/bin)

### Code added

File: [run_tdx_ecdsa_tests.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/run_tdx_ecdsa_tests.sh)

This is a compatibility shim so the old top-level command still works:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/direct/run_tdx_ecdsa_tests.sh" "$@"
```

### Code modified

File: [run_tdx_ecdsa_tests.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_tdx_ecdsa_tests.sh)

I updated the moved direct ECDSA runner to use the new structure:

```bash
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
...
BIN_DIR="$TESTS_DIR/bin"
VERIFIER_BIN="$BIN_DIR/local_tdx_verifier"
VERIFIER_LOG="$BIN_DIR/local_tdx_verifier.log"
TEST_APP_BIN="$BIN_DIR/test_app_direct"
```

It now compiles the moved verifier and helper sources:

```bash
g++ ... \
    -I"$TESTS_DIR/common" \
    -I"$TESTS_DIR/sgxsdk/include" \
    "$TESTS_DIR/verifier/local_tdx_verifier.cpp" \
    "$TESTS_DIR/common/utils.cpp" \
    ... \
    -o "$VERIFIER_BIN"
```

and the moved direct ECDSA test:

```bash
g++ ... \
    -I"$TESTS_DIR/common" \
    "$TESTS_DIR/direct/test_tdx_quote_wrapper.cpp" \
    "$TESTS_DIR/common/utils.cpp" \
    ... \
    -o "$TEST_APP_BIN"
```

File: [run_mldsa_tdx_only_tests.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh)

I updated the ML-DSA suite runner to use the new `tdqe/` and `format/` locations:

```bash
"$TESTS_DIR/tdqe/test_tdqe_mldsa_adapter.c"
"$TESTS_DIR/tdqe/test_randombytes_stub.c"
```

```bash
"$TESTS_DIR/format/test_quote_headers_mldsa.cpp"
```

```bash
"$TESTS_DIR/tdqe/test_tdqe_quote_layout_mldsa.cpp"
```

File: [test_quote_headers_mldsa.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/format/test_quote_headers_mldsa.cpp)

I removed the old relative include paths that became invalid after the move:

```c++
#include "sgx_quote_3.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"
#include "ecdsa_quote.h"
```

File: [test_tdqe_quote_layout_mldsa.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/tdqe/test_tdqe_quote_layout_mldsa.cpp)

I did the same here:

```c++
#include "sgx_quote_4.h"
#include "ecdsa_quote.h"
```

File: [Makefile](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux/Makefile)

I updated the `test_app` target to the new direct/common source paths:

```make
test_app: $(Quote_Name) ../../../../../tdx_tests/direct/test_tdx_quote_wrapper.cpp ../../../../../tdx_tests/common/utils.cpp
```

```make
$(CXX) $(Quote_Cpp_Flags) -I../.. -I../../tdx_attest -I../../common/inc -I../../../../../tdx_tests/common \
    ../../../../../tdx_tests/direct/test_tdx_quote_wrapper.cpp ../../../../../tdx_tests/common/utils.cpp ...
```

File: [README.md](/home/alocin-local/tdx-pq-attestation/tdx_tests/README.md)

I rewrote the overview to document the new role-based structure and the main entry points.

### Tests run

- Verified shell syntax for the refactored runners:

```bash
bash -n /home/alocin-local/tdx-pq-attestation/tdx_tests/run_tdx_ecdsa_tests.sh \
       /home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_tdx_ecdsa_tests.sh \
       /home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

- Re-ran the refactored ML-DSA suite successfully:

```bash
/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Observed result:

```text
[INFO] Running TDQE ML-DSA adapter test...
[test] TDQE ML-DSA adapter passed: keygen/sign/verify deterministic checks OK
[test] sizes: pub=1952 priv=4032 sig=3309
[INFO] Running quote header ML-DSA layout test...
[INFO] Running TDQE ML-DSA quote layout test...
[INFO] Running wrapper ML-DSA algorithm-selection test...
[mldsa_get_quote_size td_ql_logic.cpp:2079] [tdx-quote-debug] mldsa_get_quote_size: quote_size=7102 (default certification data path only).
[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=7102)
[SKIP] Insufficient permissions on /dev/tdx_guest; skipping the direct TDX ML-DSA capability probe.
[SKIP] Run this script with elevated privileges to exercise the direct TDX path.
```

### Result
- `tdx_tests/` is now organized by responsibility instead of by historical accumulation.
- Shared code, direct-path tests, wrapper tests, TDQE tests, verifier code, and generated artifacts are separated clearly.
- Existing entry points were preserved through compatibility glue instead of forcing the user to relearn the old command immediately.

## Step 28: Started exposing ML-DSA attestation-key selection through `libtdx_attest`

### What changed
- I began wiring ML-DSA selection into the direct TDX attestation path instead of leaving it hardcoded to the legacy ECDSA UUID only.
- The implementation is split into two pieces:
  - `libtdx_attest` now understands two direct-path UUIDs
  - the direct ML-DSA probe now explicitly requests the ML-DSA UUID when it is advertised

### Why this step was needed
- The direct probe previously passed the whole supported-id list back into `tdx_att_get_quote()`.
- Even after adding ML-DSA support to the direct API, that would still allow the lower layer to choose the first match, which could keep selecting ECDSA.
- To test the real direct-path ML-DSA capability, the probe must request ML-DSA explicitly once the direct API advertises it.

### Code modified

File: [tdx_attest.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.h)

Added a new direct-path UUID constant for ML-DSA:

```c
#define TDX_SGX_MLDSA_65_ATTESTATION_ID                \
{                                                      \
    0xe8, 0x6c, 0x04, 0x6e, 0x8c, 0xc4, 0x4d, 0x95,    \
    0x81, 0x73, 0xfc, 0x43, 0xc1, 0xfa, 0x4f, 0x40     \
}
```

File: [tdx_attest.c](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c)

The direct library now defines both UUIDs:

```c
static const tdx_uuid_t g_intel_tdqe_ecdsa_uuid = {TDX_SGX_ECDSA_ATTESTATION_ID};
static const tdx_uuid_t g_intel_tdqe_mldsa_65_uuid = {TDX_SGX_MLDSA_65_ATTESTATION_ID};
```

The direct quote-request blob now carries the attestation-key UUID list instead of always passing `NULL, 0`:

```c
qgs_msg_ret = qgs_msg_gen_get_quote_req((uint8_t*)p_tdx_report, sizeof(*p_tdx_report),
    p_id_list, id_list_size, &p_req, &msg_size);
```

The direct response parser now accepts and returns the selected UUID from the quote-service response:

```c
if (p_selected_att_key_id) {
    if (p_selected_id_ && id_size_ == sizeof(*p_selected_att_key_id)) {
        memcpy(p_selected_att_key_id, p_selected_id_, sizeof(*p_selected_att_key_id));
    } else if (p_selected_id_ == NULL && id_size_ == 0) {
        *p_selected_att_key_id = g_intel_tdqe_ecdsa_uuid;
    } else {
        return TDX_ATTEST_ERROR_UNEXPECTED;
    }
}
```

The direct API now reports two supported attestation key IDs:

```c
if (p_att_key_id_list) {
    if (*p_list_size < 2) {
        *p_list_size = 2;
        return TDX_ATTEST_ERROR_INVALID_PARAMETER;
    }
    p_att_key_id_list[0] = g_intel_tdqe_ecdsa_uuid;
    p_att_key_id_list[1] = g_intel_tdqe_mldsa_65_uuid;
}
*p_list_size = 2;
```

File: [test_tdx_direct_mldsa_probe.cpp](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/test_tdx_direct_mldsa_probe.cpp)

The probe now recognizes the new ML-DSA UUID:

```c++
static bool is_intel_tdqe_mldsa_uuid(const tdx_uuid_t& att_key_id)
{
    static const uint8_t kIntelTdqeMldsaAttestationId[TDX_UUID_SIZE] = TDX_SGX_MLDSA_65_ATTESTATION_ID;
    return std::memcmp(att_key_id.d, kIntelTdqeMldsaAttestationId, sizeof(kIntelTdqeMldsaAttestationId)) == 0;
}
```

and explicitly requests ML-DSA when the direct API advertises it:

```c++
const tdx_uuid_t *requested_id_list = supported_ids.data();
uint32_t requested_id_count = supported_id_count;
...
if (is_intel_tdqe_mldsa_uuid(supported_ids[i])) {
    requested_mldsa_id = supported_ids[i];
    requested_id_list = &requested_mldsa_id;
    requested_id_count = 1;
    found_mldsa_uuid = true;
    print_uuid("direct requested att key id: ", requested_mldsa_id);
    break;
}
```

```c++
attest_ret = tdx_att_get_quote(&report_data,
                               requested_id_list,
                               requested_id_count,
                               &selected_att_key_id,
                               &quote,
                               &quote_size,
                               0);
```

### Additional integration work

File: [qgs_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/qgs_ql_logic.cpp)

I started the matching server-side work so the local QGS path can map direct TDX UUIDs to wrapper key selection and return the selected UUID in the response.

File: [Makefile](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/Makefile)

Added the include path needed by that QGS-side UUID-mapping work:

```make
-I$(TOP_DIR)/quote_wrapper/tdx_attest \
```

### Tests run

- Rebuilt the direct TDX attestation library successfully after the direct UUID/path changes:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
LINK =>  libtdx_attest.so
```

- Re-ran the ML-DSA direct-path suite in the current non-root environment:

```bash
/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Observed result:

```text
[test] TDQE ML-DSA adapter passed: keygen/sign/verify deterministic checks OK
[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=7102)
[SKIP] Insufficient permissions on /dev/tdx_guest; skipping the direct TDX ML-DSA capability probe.
```

- Attempted to rebuild the local QGS component for the server-side half of the direct-UUID wiring:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Current environment blocker:

```text
fatal error: boost/asio.hpp: No such file or directory
```

### Result
- The direct TDX attestation client path is no longer structurally ECDSA-only.
- The direct ML-DSA probe is now prepared to request ML-DSA explicitly, instead of accidentally preferring ECDSA by list order.
- The remaining unknown is the runtime/service side:
  - whether the current TDX quote service actually honors the new direct ML-DSA UUID
  - and, for the local QGS build path, the missing Boost headers in this environment

### Additional runtime evidence

The direct probe was then run with elevated privileges, so it could exercise `/dev/tdx_guest` end-to-end:

```bash
sudo ./tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Observed direct-path result:

```text
[test] direct supported att key id[0]: e86c046e8cc44d958173fc43c1fa4f3f
[test] direct supported att key id[1]: e86c046e8cc44d958173fc43c1fa4f40
[test] direct requested att key id: e86c046e8cc44d958173fc43c1fa4f40
[test] direct selected att key id: 00000000000000000000000000000000
[test] direct quote header version=4 att_key_type=2 quote_size=8000
```

Interpretation:
- the direct client-side API changes are visible: two attestation key IDs are now advertised
- the direct probe did request the ML-DSA UUID specifically
- the generated quote still came back with `att_key_type=2` (ECDSA)
- the selected attestation key id in the response came back as all zeros instead of a valid UUID

This means the remaining blocker is now clearly on the quote-service side rather than the direct client library:
- either the current TDX quote service ignores the requested ML-DSA UUID and still generates the default ECDSA quote
- or it does not yet populate `selected_id` correctly when non-default key selection is requested

### Follow-up build result after installing Boost headers

After installing the missing Boost development headers, the local QGS component built successfully:

```bash
cd /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs
make SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Relevant result:

```text
g++ -o qgs ... qgs_ql_logic.o ... -lboost_system -lboost_thread ...
cc -o test_client test_client.o -L../qgs_msg_lib/linux -lqgs_msg
```

This confirms that:
- the server-side ML-DSA selection changes in `qgs_ql_logic.cpp` now compile cleanly
- the include-path adjustment in `qgs/Makefile` is correct
- the remaining work is runtime verification of which quote service path the direct TDX flow is actually using on the machine

## Step 29: traced the direct transport and confirmed the runtime was bypassing local QGS

### What I changed

File: [tdx_attest.c](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c)

Added direct-path tracing controlled by `TDX_ATTEST_TRACE_DIRECT`, so the runtime path used by `tdx_att_get_quote()` can be observed without changing the public API.

Relevant code:

```c
if (direct_trace_enabled()) {
    fprintf(stderr, "[tdx-attest-trace] generate_get_quote_blob request att key ids count=%u\n",
            list_size);
}
```

```c
if (direct_trace_enabled()) {
    fprintf(stderr, "[tdx-attest-trace] quote transport=configfs\n");
}
```

### Tests run

Ran the direct ML-DSA probe with tracing enabled:

```bash
sudo env TDX_ATTEST_TRACE_DIRECT=1 ./tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Observed trace:

```text
[tdx-attest-trace] generate_get_quote_blob request att key ids count=1
[tdx-attest-trace]   id[0]=e86c046e8cc44d958173fc43c1fa4f40
[tdx-attest-trace] quote transport=configfs
```

### Result

This proved that:
- the ML-DSA UUID request is really being sent by the direct client path
- the quote did not come from the locally built QGS server
- the direct runtime in this environment is using the `configfs` quote provider, which is still returning an ECDSA quote and an all-zero `selected_id`

## Step 30: added a forced local-QGS transport to the direct attestation client

### What I changed

File: [tdx_attest.c](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c)

Added a new optional transport that talks directly to a Unix-domain socket exposed by a locally built `qgs`, and made the direct quote path try it before `vsock`, `configfs`, and `tdcall`.

Relevant code:

```c
#define TDX_ATTEST_LOCAL_QGS_SOCKET_ENV "TDX_ATTEST_LOCAL_QGS_SOCKET"
#define TDX_ATTEST_FORCE_LOCAL_QGS_ENV "TDX_ATTEST_FORCE_LOCAL_QGS"
#define DEFAULT_TDX_ATTEST_LOCAL_QGS_SOCKET "/var/run/tdx-qgs/qgs.socket"
```

```c
static tdx_attest_error_t local_qgs_get_quote_payload(
    const uint8_t *p_get_quote_blob,
    uint32_t get_quote_blob_size,
    uint32_t *p_payload_body_size)
{
    ...
    unix_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    ...
    if (connect(unix_sock, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == -1) {
        ...
    }
    ...
}
```

```c
ret = local_qgs_get_quote_payload((uint8_t*)p_get_quote_blob->data, p_get_quote_blob->in_len, &payload_body_size);
if (ret == TDX_ATTEST_SUCCESS) {
    if (direct_trace_enabled()) {
        fprintf(stderr, "[tdx-attest-trace] quote transport=local-qgs\n");
    }
} else if (local_qgs_forced()) {
    goto done;
}
```

### Tests run

Rebuilt the direct attestation library:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
LINK =>  libtdx_attest.so
```

### Result

The direct client can now be forced to bypass the kernel/provider path and use a local QGS instance controlled by the repository code.

## Step 31: made the local QGS socket path configurable and wired the ML-DSA direct runner to it

### What I changed

File: [server_main.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/server_main.cpp)

Made the QGS Unix socket path configurable with `QGS_SOCKET_PATH`, instead of hardwiring `/var/run/tdx-qgs/qgs.socket`.

Relevant code:

```c++
#define QGS_SOCKET_PATH_ENV "QGS_SOCKET_PATH"
```

```c++
const char* getQgsSocketPath()
{
    const char* env_socket_path = getenv(QGS_SOCKET_PATH_ENV);
    if (env_socket_path != NULL && env_socket_path[0] != '\0') {
        return env_socket_path;
    }

    return QGS_UNIX_SOCKET_FILE;
}
```

```c++
asio::local::stream_protocol::endpoint unix_ep(socket_path);
```

File: [run_mldsa_tdx_only_tests.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh)

Updated the ML-DSA direct runner so it:
- builds the local `qgs`
- starts it in the background on a repo-local socket
- sets `TDX_ATTEST_FORCE_LOCAL_QGS=1`
- sets `TDX_ATTEST_LOCAL_QGS_SOCKET` to that repo-local socket
- gives the `qgs` process the `LD_LIBRARY_PATH` it needs to load `libsgx_tdx_logic.so`

Relevant code:

```bash
QGS_SOCKET_PATH="${QGS_SOCKET_PATH:-$BIN_DIR/qgs.socket}"
QGS_LOG_PATH="${QGS_LOG_PATH:-$BIN_DIR/qgs.log}"
QGS_LD_LIBRARY_PATH="$QGS_DIR:$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR"
```

```bash
QGS_SOCKET_PATH="$QGS_SOCKET_PATH" \
LD_LIBRARY_PATH="$QGS_LD_LIBRARY_PATH:${LD_LIBRARY_PATH:-}" \
  "$QGS_DIR/qgs" --no-daemon --debug >"$QGS_LOG_PATH" 2>&1 &
```

```bash
TDX_ATTEST_FORCE_LOCAL_QGS=1 \
TDX_ATTEST_LOCAL_QGS_SOCKET="$QGS_SOCKET_PATH" \
LD_LIBRARY_PATH="$TDX_ATTEST_LINUX_DIR:${LD_LIBRARY_PATH:-}" \
  "$TDX_DIRECT_PROBE_BIN"
```

File: [README.md](/home/alocin-local/tdx-pq-attestation/tdx_tests/README.md)

Documented that the ML-DSA direct runner now forces `libtdx_attest` through the repo-local QGS path instead of `configfs`.

### Tests run

Rebuilt the local QGS server after the socket-path change:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
g++ -o qgs se_trace.o server_main.o qgs_server.o qgs_log.o qgs_ql_logic.o ...
```

Syntax-checked the updated runner:

```bash
bash -n /home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Result:

```text
[no output; syntax check passed]
```

Started the local QGS server on a repo-local socket to verify the new path:

```bash
timeout 2s env \
  QGS_SOCKET_PATH=/home/alocin-local/tdx-pq-attestation/tdx_tests/bin/qgs.socket \
  LD_LIBRARY_PATH=/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs:/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux:/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux:/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/lib64 \
  /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/qgs --no-daemon --debug
```

Observed result:

```text
Use unix socket: /home/alocin-local/tdx-pq-attestation/tdx_tests/bin/qgs.socket
Added signal handler
About to create QgsServer
About to start main loop
...
Socket file removed
```

### Result

The repository now has an end-to-end test path that can force the direct attestation client away from `configfs` and onto the locally built QGS implementation under repository control.

## Step 32: added forced-path hang diagnostics for the local-QGS direct ML-DSA flow

### What I changed

File: [qgs_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/qgs_ql_logic.cpp)

Added explicit progress logs around the direct `GET_QUOTE_REQ` server path, so the local `qgs` now reports whether it reached:
- request inflation
- algorithm-aware context selection
- `tee_att_get_quote_size`
- `tee_att_get_quote`
- response generation

Relevant code:

```c++
QGS_LOG_INFO("GET_QUOTE_REQ: report_size=%u id_list_size=%u\n", report_size, id_list_size);
```

```c++
QGS_LOG_INFO("GET_QUOTE_REQ: calling tee_att_get_quote_size\n");
```

```c++
QGS_LOG_INFO("GET_QUOTE_REQ: calling tee_att_get_quote\n");
```

```c++
QGS_LOG_INFO("GET_QUOTE_REQ: generating success response size=%u\n", size);
```

File: [run_mldsa_tdx_only_tests.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh)

Added a timeout around the direct ML-DSA probe and automatic dump of the recent `qgs.log` on failure, so a hang no longer leaves the test runner silent.

Relevant code:

```bash
DIRECT_PROBE_TIMEOUT_SECONDS="${DIRECT_PROBE_TIMEOUT_SECONDS:-20}"
```

```bash
timeout "$DIRECT_PROBE_TIMEOUT_SECONDS" "$TDX_DIRECT_PROBE_BIN" || {
  probe_status=$?
  echo "[ERROR] Direct TDX ML-DSA capability probe failed with status $probe_status"
  echo "[ERROR] Recent QGS log:"
  tail -n 200 "$QGS_LOG_PATH" || true
  exit "$probe_status"
}
```

### Tests run

Rebuilt the local QGS after adding the extra GET_QUOTE diagnostics:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
g++ -o qgs se_trace.o server_main.o qgs_server.o qgs_log.o qgs_ql_logic.o ...
```

Syntax-checked the updated direct ML-DSA runner:

```bash
bash -n /home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Result:

```text
[no output; syntax check passed]
```

### Result

If the forced local-QGS path still hangs, the next run will report where the server stopped instead of requiring a separate manual log inspection.

## Step 33: added non-buffered QGS tracing around the internal `tee_att_*` calls

### What I changed

File: [qgs_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/qgs_ql_logic.cpp)

Added explicit `fprintf(stderr, ...)` + `fflush(stderr)` markers at the start of `get_resp()` and immediately around:
- `qgs_msg_get_type`
- `tee_att_create_context`
- bootstrap `tee_att_init_quote`
- `ensure_context_for_quote_request`
- `tee_att_get_quote_size`
- `tee_att_get_quote`

Relevant code:

```c++
fprintf(stderr, "[qgs-debug] get_resp enter req_size=%u\n", req_size);
fflush(stderr);
```

```c++
fprintf(stderr, "[qgs-debug] about to call tee_att_create_context\n");
fflush(stderr);
ret = tee_att_create_context(NULL, NULL, &p_ctx);
fprintf(stderr, "[qgs-debug] tee_att_create_context ret=0x%x ctx=%p\n", ret, (void*)p_ctx);
fflush(stderr);
```

```c++
fprintf(stderr, "[qgs-debug] about to call tee_att_get_quote_size\n");
fflush(stderr);
```

```c++
fprintf(stderr, "[qgs-debug] about to call tee_att_get_quote\n");
fflush(stderr);
```

### Tests run

Rebuilt the local QGS after adding the new non-buffered tracing:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
g++ -o qgs se_trace.o server_main.o qgs_server.o qgs_log.o qgs_ql_logic.o ...
```

### Result

The next forced local-QGS run will reveal the exact first `tee_att_*` call that does not return in the ML-DSA direct path.

## Step 34: fixed the forced local-QGS runner to start QGS with a worker thread

### What I changed

File: [run_mldsa_tdx_only_tests.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh)

After running the forced local-QGS flow, the log consistently stopped at:

```text
unpack message successfully in thread [...]
```

and none of the new `[qgs-debug] get_resp ...` markers ever appeared.

That indicates the request was accepted and queued, but the `asio::post(m_pool, ...)` worker task never ran. The root cause is that the local `qgs` was being started without `/etc/qgs.conf` and without `-n=...`, which leaves `num_threads = 0`.

I fixed the runner to start the local `qgs` with at least one worker thread by default.

Relevant code:

```bash
QGS_NUM_THREADS="${QGS_NUM_THREADS:-1}"
```

```bash
"$QGS_DIR/qgs" --no-daemon --debug "-n=$QGS_NUM_THREADS" >"$QGS_LOG_PATH" 2>&1 &
```

### Tests run

Syntax-checked the updated runner:

```bash
bash -n /home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Result:

```text
[no output; syntax check passed]
```

### Result

The forced local-QGS flow no longer depends on `/etc/qgs.conf` to have a non-zero worker-thread count, so the next run should finally execute `get_resp()` instead of stalling before the first `qgs_ql_logic.cpp` diagnostic marker.

## Step 35: made the runner report wrapper/QGS unavailability explicitly on `tdx_guest`-only systems

### What I changed

File: [run_mldsa_tdx_only_tests.sh](/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh)

After forcing the direct client onto the repo-local `qgs`, the first real failure in this environment was:

```text
[qgs-debug] tee_att_init_quote bootstrap ret=0x1100d
```

with the matching hint:

```text
Please use the correct uRTS library from PSW package.
```

That means the forced local `qgs` / `tee_att_*` bootstrap path is unavailable on this machine because it still depends on the SGX PCE/PSW interface, while the machine only exposes `tdx_guest`.

I left the runner structure unchanged, but added a clearer unavailable-environment message when that specific failure pattern appears in `qgs.log`.

Relevant code:

```bash
print_qgs_unavailable_hint() {
  if [[ -f "$QGS_LOG_PATH" ]] && \
     grep -Eq 'tee_att_init_quote bootstrap ret=0x1100d|Please use the correct uRTS library from PSW package\.' "$QGS_LOG_PATH"; then
    echo "[UNAVAILABLE] The forced local QGS / tee_att path is unavailable in this environment."
    echo "[UNAVAILABLE] This machine exposes TDX guest attestation, but the wrapper/QGS bootstrap still requires the SGX PCE/PSW interface."
    echo "[UNAVAILABLE] On a tdx_guest-only system, this ML-DSA direct-wrapper path cannot complete end-to-end."
  fi
}
```

### Tests run

Syntax-checked the updated runner:

```bash
bash -n /home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Result:

```text
[no output; syntax check passed]
```

### Result

The direct ML-DSA runner now distinguishes between:
- a real transport/runtime bug in the forced local-QGS path
- and the expected wrapper/QGS unavailability on `tdx_guest`-only systems

## Step 36: executed the planned TDX-only regression and ML-DSA component tests

### What I ran

ECDSA direct regression:

```bash
cd /home/alocin-local/tdx-pq-attestation/tdx_tests/direct
sudo ./run_tdx_ecdsa_tests.sh
```

ML-DSA TDX-only suite:

```bash
/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

### Observed ECDSA direct result

The direct TDX ECDSA flow completed successfully:

```text
[test] quote generated successfully: 8000 bytes
[test] verifier response: {"success":true,"is_valid":true,"quote_verification_result":"OK","quote_verification_result_code":0,"collateral_expiration_status":0,"qv_ret":0}
```

The same run also surfaced a follow-up issue in the metadata returned by the direct path:

```text
[test] --------------- selected attestation key id: 00000000000000000000000000000000
[test] selected attestation key profile: unknown/non-default
```

So:
- direct ECDSA report generation still works
- direct ECDSA quote generation still works
- local verification still succeeds
- but the selected attestation key id metadata is now reported as all zeros in the direct flow

### Observed ML-DSA TDX-only result

The TDX-only ML-DSA suite passed the local non-SGX-dependent blocks:

```text
[test] TDQE ML-DSA adapter passed: keygen/sign/verify deterministic checks OK
[test] sizes: pub=1952 priv=4032 sig=3309
[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=7102)
[SKIP] Insufficient permissions on /dev/tdx_guest; skipping the direct TDX ML-DSA capability probe.
```

### Result

This completed the currently executable parts of the TDX-only test plan on this machine:
- ECDSA direct-path regression: passed functionally
- ML-DSA backend / header / layout / wrapper-plumbing tests: passed
- direct-path key-selection metadata still needs cleanup, because the direct ECDSA flow now reports an all-zero selected attestation key id even when quote generation and verification succeed

## Step 37: fixed the direct `configfs` path so it no longer leaves `selected_att_key_id` at all zeros

### Root cause

The direct ECDSA regression showed:

```text
[test] --------------- selected attestation key id: 00000000000000000000000000000000
[test] selected attestation key profile: unknown/non-default
```

even though:
- the quote was generated successfully
- the local verifier accepted it

The cause was in [tdx_attest.c](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c):
- the `vsock`, `local-qgs`, and `tdcall` paths go through `extract_quote_from_blob_payload(...)`, which fills `p_att_key_id`
- the `configfs` path returns the quote directly through `configfs_get_quote(...)` and never set `p_att_key_id`

So when the direct runtime used `configfs`, the caller saw an all-zero UUID simply because the output parameter was never populated.

### What I changed

File: [tdx_attest.c](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/tdx_attest.c)

Added an explicit fallback assignment in the `configfs` success path:

```c
if (TDX_ATTEST_SUCCESS == ret && p_att_key_id != NULL) {
    *p_att_key_id = g_intel_tdqe_ecdsa_uuid;
}
```

This is intentionally conservative:
- it only affects the `configfs` path
- it only runs when quote generation succeeded
- it preserves the existing behavior of the other transports
- it reflects the current observed reality of the `configfs` provider on this machine, which still returns ECDSA quotes

### Tests run

Rebuilt the direct attestation library:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_attest/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
LINK =>  libtdx_attest.so
```

### Result

The direct `configfs` path no longer leaves the selected attestation key id output parameter uninitialized. The next direct ECDSA run should report the default ECDSA UUID instead of `000...000`.

## Step 38: re-ran the direct ML-DSA probe after the selected-id fix and confirmed the real TDX-only limitation

### What I ran

```bash
sudo ./tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

### Observed result

The local non-SGX-dependent ML-DSA checks still passed:

```text
[test] TDQE ML-DSA adapter passed: keygen/sign/verify deterministic checks OK
[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=7102)
```

The direct public-path probe still could not complete end-to-end:

```text
[test] direct supported att key id[0]: e86c046e8cc44d958173fc43c1fa4f3f
[test] direct supported att key id[1]: e86c046e8cc44d958173fc43c1fa4f40
[test] direct requested att key id: e86c046e8cc44d958173fc43c1fa4f40
[test] tdx_att_get_quote failed: 0x4
[UNAVAILABLE] The forced local QGS / tee_att path is unavailable in this environment.
```

The detailed QGS-side diagnostics show the precise first failure:

```text
[qgs-debug] tee_att_init_quote bootstrap ret=0x1100d hash_size=32
tee_att_init_quote return 0x1100d
Please use the correct uRTS library from PSW package.
```

### Final conclusion for this machine

There are two distinct TDX public-path realities on this host:

1. `configfs` direct path:
- can generate a valid direct ECDSA quote
- does not expose a real ML-DSA selection hook through the current `tdx_att_get_quote()` provider path

2. forced local `qgs/tee_att_*` path:
- does receive the requested ML-DSA UUID
- does enter the repo-local code
- but cannot bootstrap on this machine because the wrapper/QGS stack still requires SGX PCE/PSW

So, on this `tdx_guest`-only system:
- ML-DSA is working in the local TDQE/backend/layout/wrapper test surfaces
- ML-DSA is **not** testable end-to-end through the public direct TDX quote path yet

### Result

This closes the current investigation goal:
- the remaining blocker is no longer ambiguous
- it is not a transport bug
- it is not a selected-id parsing bug
- it is an environment/provider limitation of the public direct path on this machine

## Step 39: started the trusted TDX-only ML-DSA work by isolating bootstrap mode in the wrapper context

### Why this step was needed

After the direct-path investigation, the next architectural goal became:
- stop treating the `qgs/tee_att_*` path as the runtime target on this `tdx_guest`-only machine
- prepare a repo-controlled trusted TDX-only path that still keeps quote signing inside TDQE

The first technical requirement for that is to separate:
- the current legacy bootstrap path, which is PCE/PSW-dependent
- a future trusted TDX-only bootstrap path, which will need different orchestration

Without making that distinction explicit in the wrapper context, the future bypass would turn into scattered ad-hoc conditionals around `PPID_RSA3072_ENCRYPTED`, `sgx_pce_get_target()`, and certification-data setup.

### What I changed

File: [todo](/home/alocin-local/tdx-pq-attestation/todo)

Added a new work plan section:
- `Piano di lavoro: trusted TDX-only ML-DSA path`

It defines:
- the security constraints
- the implementation steps
- the boundary between the public path and the future trusted repo-local path

File: [td_ql_logic.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.h)

Added explicit bootstrap-mode scaffolding to the internal TDX quote context:

```c++
enum tee_att_bootstrap_mode_t {
    TEE_ATT_BOOTSTRAP_LEGACY_PCE = 0,
    TEE_ATT_BOOTSTRAP_TRUSTED_TDX_ONLY = 1,
};
```

and:

```c++
tee_att_bootstrap_mode_t m_bootstrap_mode;
```

with the default constructor initializing:

```c++
m_bootstrap_mode(TEE_ATT_BOOTSTRAP_LEGACY_PCE)
```

File: [td_ql_wrapper.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_wrapper.cpp)

Added an explicit bootstrap-mode selector:

```c++
static tee_att_bootstrap_mode_t get_default_bootstrap_mode_for_algorithm(uint32_t algorithm_id)
{
    switch (algorithm_id)
    {
    case SGX_QL_ALG_MLDSA_65:
    case SGX_QL_ALG_ECDSA_P256:
    default:
        return TEE_ATT_BOOTSTRAP_LEGACY_PCE;
    }
}
```

and wired it into context creation:

```c++
p_context->m_bootstrap_mode = get_default_bootstrap_mode_for_algorithm(p_context->m_att_key_algorithm_id);
```

### What this does today

Functionally, nothing changes yet:
- ECDSA still uses the legacy bootstrap
- ML-DSA still uses the legacy bootstrap
- the runtime behavior is preserved

But the wrapper now has a dedicated place to switch only the bootstrap/orchestration path later, without conflating that change with the attestation-key algorithm itself.

### Tests run

Rebuilt the TDX quote wrapper after adding the bootstrap-mode scaffolding:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
LINK =>  libsgx_tdx_logic.so
```

### Result

The codebase now has an explicit internal seam for the next implementation step:
- keeping the current `legacy_pce` bootstrap intact
- while making room for a future `trusted_tdx_only` bootstrap path for ML-DSA

## Step 40: turned `bootstrap_mode` into a real `init_quote()` dispatch

### Why this step matters

Step 39 added the bootstrap-mode state, but the code path still called the old logic directly.
That was enough for annotation, but not enough for controlled evolution: the future TDX-only trusted path needs a dedicated function boundary so it can diverge from the legacy PCE bootstrap without cutting into `ecdsa_init_quote()`/`mldsa_init_quote()` themselves.

### What I changed

File: [td_ql_logic.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.h)

Added two explicit internal entry points:

```c++
tee_att_error_t legacy_init_quote(...);
tee_att_error_t trusted_tdx_only_init_quote(...);
```

File: [td_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp)

Split the old `init_quote()` logic into:

```c++
tee_att_error_t tee_att_config_t::legacy_init_quote(...)
```

which preserves the existing behavior, and:

```c++
tee_att_error_t tee_att_config_t::trusted_tdx_only_init_quote(...)
```

which is currently just an explicit placeholder:

```c++
SE_TRACE(SE_TRACE_NOTICE, "trusted_tdx_only_init_quote is not implemented yet.\n");
return TEE_ATT_INTERFACE_UNAVAILABLE;
```

Then changed `init_quote()` to dispatch on `m_bootstrap_mode`:

```c++
switch (m_bootstrap_mode)
{
case TEE_ATT_BOOTSTRAP_LEGACY_PCE:
    return legacy_init_quote(...);
case TEE_ATT_BOOTSTRAP_TRUSTED_TDX_ONLY:
    return trusted_tdx_only_init_quote(...);
default:
    return TEE_ATT_ERROR_UNEXPECTED;
}
```

### What this does today

Behavior is still unchanged at runtime because the wrapper still selects:

```c++
TEE_ATT_BOOTSTRAP_LEGACY_PCE
```

for both ECDSA and ML-DSA contexts.

But the wrapper now has a proper implementation seam where the future trusted TDX-only orchestration can be built without touching the legacy path.

### Tests run

Rebuilt the TDX quote wrapper after introducing the explicit bootstrap dispatch:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
LINK =>  libsgx_tdx_logic.so
```

### Result

The first implementation milestone of the trusted TDX-only plan is now complete:
- bootstrap mode exists in the context
- the current path is explicitly marked as `legacy_pce`
- `init_quote()` already has a dedicated slot for a future `trusted_tdx_only` implementation

## Step 41: isolated the first concrete legacy-PCE touchpoints into helper functions

### Why this step matters

The new `bootstrap_mode` dispatch created the right seam, but the legacy path still embedded its PCE assumptions directly inside `ecdsa_init_quote()`, `certify_key()`, and quote-size helpers.

The immediate next risk was obvious:
- if the future `trusted_tdx_only` path were implemented next, it would still have to navigate repeated inline checks for `PPID_RSA3072_ENCRYPTED`
- and repeated direct calls to `sgx_pce_get_target()`

So I extracted the first two legacy-only assumptions into explicit helpers on the internal context.

### What I changed

File: [td_ql_logic.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.h)

Added new private helpers:

```c++
bool uses_legacy_pce_bootstrap() const;
tee_att_error_t validate_legacy_certification_key_type(sgx_ql_cert_key_type_t certification_key_type) const;
tee_att_error_t legacy_get_pce_target_info(sgx_target_info_t* p_pce_target_info,
    sgx_isv_svn_t* p_pce_isv_svn);
```

File: [td_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp)

Implemented those helpers:

```c++
bool tee_att_config_t::uses_legacy_pce_bootstrap() const
{
    return m_bootstrap_mode == TEE_ATT_BOOTSTRAP_LEGACY_PCE;
}
```

```c++
tee_att_error_t tee_att_config_t::validate_legacy_certification_key_type(sgx_ql_cert_key_type_t certification_key_type) const
{
    if (!uses_legacy_pce_bootstrap()) {
        return TEE_ATT_ERROR_UNEXPECTED;
    }

    if (PPID_RSA3072_ENCRYPTED != certification_key_type) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid certification key type for legacy PCE bootstrap.\n");
        return TEE_ATT_ERROR_INVALID_PARAMETER;
    }

    return TEE_ATT_SUCCESS;
}
```

```c++
tee_att_error_t tee_att_config_t::legacy_get_pce_target_info(sgx_target_info_t *p_pce_target_info,
                                                             sgx_isv_svn_t *p_pce_isv_svn)
{
    ...
    pce_error = sgx_pce_get_target(p_pce_target_info, p_pce_isv_svn);
    ...
}
```

Then rewired the legacy path to use them:

- `ecdsa_init_quote(...)`
  - now validates the certification key type via `validate_legacy_certification_key_type(...)`
  - now gets PCE target info via `legacy_get_pce_target_info(...)`

- `certify_key(...)`
  - now validates the certification key type via `validate_legacy_certification_key_type(...)`

- `ecdsa_get_quote_size(...)`
  - now validates the certification key type via `validate_legacy_certification_key_type(...)`

- `mldsa_get_quote_size(...)`
  - now validates the certification key type via `validate_legacy_certification_key_type(...)`

### What this means

This does not change runtime behavior.

It does make the code much clearer:
- `PPID_RSA3072_ENCRYPTED` is now explicitly identified as a legacy-bootstrap assumption
- `sgx_pce_get_target()` is now explicitly identified as a legacy-bootstrap operation

Those are the first two legacy touchpoints that the future trusted TDX-only path will need to bypass or replace.

The next two still to isolate are:
- `sgx_pce_sign_report()`
- `get_platform_quote_cert_data()`

### Tests run

Rebuilt the TDX quote wrapper after the helper-based isolation:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
LINK =>  libsgx_tdx_logic.so
```

### Result

The trusted TDX-only plan now has its first concrete code-level isolation:
- bootstrap state is explicit
- `init_quote()` dispatch is explicit
- the first legacy PCE assumptions are now encapsulated instead of repeated inline

## Step 42: isolated the remaining two main legacy-PCE touchpoints behind explicit helpers

### Why this step matters

After Step 41, two big legacy assumptions were still embedded directly in the init/certification flow:
- `sgx_pce_sign_report()`
- `get_platform_quote_cert_data()`

Those are central to the old certification bootstrap, so leaving them inline would still make the future trusted TDX-only path hard to separate cleanly.

### What I changed

File: [td_ql_logic.h](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.h)

Added two more private helpers:

```c++
tee_att_error_t legacy_pce_sign_report(const sgx_isv_svn_t* p_cert_pce_isv_svn,
    const sgx_cpu_svn_t* p_cert_cpu_svn,
    const sgx_report_t* p_qe_report,
    sgx_ec256_signature_t* p_pce_sig);
```

```c++
tee_att_error_t legacy_get_platform_quote_cert_data(sgx_ql_pck_cert_id_t* p_pck_cert_id,
    sgx_cpu_svn_t* p_cert_cpu_svn,
    sgx_isv_svn_t* p_cert_pce_isv_svn,
    uint32_t* p_cert_data_size,
    uint8_t* p_cert_data);
```

File: [td_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp)

Implemented both helpers:

`legacy_pce_sign_report(...)`
- guards usage with `uses_legacy_pce_bootstrap()`
- wraps `sgx_pce_sign_report(...)`
- translates PCE errors centrally
- validates the returned signature size

`legacy_get_platform_quote_cert_data(...)`
- guards usage with `uses_legacy_pce_bootstrap()`
- delegates to the existing `get_platform_quote_cert_data(...)`

Then replaced the direct call sites already in the main bootstrap path:

- in `certify_key(...)`
  - replaced the direct `sgx_pce_sign_report(...)` call with `legacy_pce_sign_report(...)`

- in the init/bootstrap path
  - replaced the first `get_platform_quote_cert_data(...)` calls with `legacy_get_platform_quote_cert_data(...)`

### What this means

Functionality is still unchanged.

But the important legacy assumptions are now all explicit:
- `PPID_RSA3072_ENCRYPTED`
- `sgx_pce_get_target()`
- `sgx_pce_sign_report()`
- `get_platform_quote_cert_data()`

This was the exact isolation target for Step 1 of the trusted TDX-only plan.

### Tests run

Rebuilt the TDX quote wrapper after adding the two new legacy helpers and rewiring the first call sites:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
LINK =>  libsgx_tdx_logic.so
```

### Result

Step 1 of the trusted TDX-only plan is now complete in code:
- the legacy bootstrap mode is explicit
- `init_quote()` dispatch is explicit
- the four main legacy PCE touchpoints are explicit helper boundaries

The next implementation step can now move from “identify and isolate” to “start giving `trusted_tdx_only_init_quote()` a real behavior”.

## Step 43: implemented the first real trusted TDX-only ML-DSA bootstrap path

### Why this step matters

Until this step, `trusted_tdx_only_init_quote(...)` was just a stub returning `TEE_ATT_INTERFACE_UNAVAILABLE`.

That meant the new bootstrap split existed in structure only, but the ML-DSA path still had no way to initialize a trusted local attestation key without falling back to the legacy PCE bootstrap.

The goal here was not to fake attestation in userspace. The goal was to keep the key and signing boundary inside the TDQE while introducing the first repo-controlled bootstrap path that does not require `sgx_pce_get_target()` or the platform quote provider.

### What I changed

File: [td_ql_wrapper.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_wrapper.cpp)

Changed the default bootstrap selection so ML-DSA now uses the new trusted local mode by default:

```c++
static tee_att_bootstrap_mode_t get_default_bootstrap_mode_for_algorithm(uint32_t algorithm_id)
{
    switch (algorithm_id)
    {
    case SGX_QL_ALG_MLDSA_65:
        return TEE_ATT_BOOTSTRAP_TRUSTED_TDX_ONLY;
    case SGX_QL_ALG_ECDSA_P256:
    default:
        return TEE_ATT_BOOTSTRAP_LEGACY_PCE;
    }
}
```

File: [td_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp)

Replaced the stubbed `trusted_tdx_only_init_quote(...)` with a first real implementation for `SGX_QL_ALG_MLDSA_65`.

The new implementation:
- rejects non-ML-DSA requests explicitly
- loads the TDQE as usual
- uses the normal in-memory / persistent blob mutex path
- reuses an existing ML-DSA blob if one is already valid
- otherwise generates a new ML-DSA attestation key by calling TDQE `gen_att_key(...)`
- uses a synthetic local `sgx_target_info_t` based on the loaded enclave attributes, with `SGX_FLAGS_PROVISION_KEY` set and `SGX_FLAGS_DEBUG` cleared
- loads `qe_id`
- completes the blob by calling TDQE `store_cert_data(...)` with local-only certification metadata
- verifies the resulting blob again and returns the `pub_key_id`
- persists the new blob with the ML-DSA-specific blob label

The core of the new path is:

```c++
sgx_status = gen_att_key(m_eid,
                         (uint32_t*)&tdqe_error,
                         m_ecdsa_blob,
                         tdqe_blob_size,
                         static_cast<uint32_t>(m_att_key_algorithm_id),
                         &local_target_info,
                         &tdqe_report,
                         &authentication_data[0],
                         sizeof(authentication_data));
```

followed by a local-only blob completion:

```c++
sgx_status = store_cert_data(m_eid,
                             (uint32_t*)&tdqe_error,
                             reinterpret_cast<uint8_t*>(&plaintext_data_mldsa),
                             sizeof(plaintext_data_mldsa),
                             certification_key_type,
                             NULL,
                             0,
                             m_ecdsa_blob,
                             tdqe_blob_size);
```

Important properties of this implementation:
- it does not move signing or key material outside the TDQE
- it does not call legacy PCE bootstrap helpers
- it does not claim platform-verifiable certification data
- it only builds a trusted local ML-DSA blob sufficient for repo-controlled TDX-only testing

### Tests run

Rebuilt the TDX quote wrapper after implementing the trusted ML-DSA bootstrap:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
LINK =>  libsgx_tdx_logic.so
```

### Result

The bootstrap split is no longer only structural.

For ML-DSA, the wrapper now has a first repo-controlled trusted TDX-only initialization path that:
- creates or reloads an ML-DSA attestation-key blob
- keeps the trust boundary inside the TDQE
- avoids the legacy PCE bootstrap entirely

## Step 44: aligned ML-DSA quote-size and quote-generation with the trusted TDX-only bootstrap

### Why this step matters

After Step 43, the ML-DSA bootstrap existed, but the quote-side methods still assumed the legacy bootstrap:
- `mldsa_get_quote_size(...)` still called the legacy certification-key validator
- `mldsa_get_quote(...)` still reused the old `ecdsa_get_quote(...)` path

That meant the new bootstrap could initialize a blob, but the public wrapper flow still failed before quote generation.

### What I changed

File: [td_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp)

#### 1. `mldsa_get_quote_size(...)`

Removed the legacy-PCE-specific guard and replaced it with a plain certification-key-type validation:

```c++
if (PPID_RSA3072_ENCRYPTED != certification_key_type) {
    return TEE_ATT_ERROR_INVALID_PARAMETER;
}
```

This allows the ML-DSA size path to work under `TEE_ATT_BOOTSTRAP_TRUSTED_TDX_ONLY`.

#### 2. `mldsa_get_quote(...)`

Added a real ML-DSA quote path for non-legacy bootstrap mode.

When the bootstrap is still legacy, it keeps the old behavior:

```c++
if (uses_legacy_pce_bootstrap()) {
    return ecdsa_get_quote(p_app_report, p_quote, quote_size);
}
```

Otherwise it now:
- loads the TDQE
- reads the ML-DSA blob from persistent storage or in-memory cache
- verifies the blob with TDQE `verify_blob(...)`
- persists the blob again if it was resealed
- calls TDQE `gen_quote(...)` directly with:
  - the ML-DSA blob
  - `algorithm_id = SGX_QL_ALG_MLDSA_65`
  - `p_certification_data = NULL`
  - `cert_data_size = 0`

The new core call is:

```c++
sgx_status = gen_quote(m_eid,
                       (uint32_t*)&tdqe_error,
                       (uint8_t*)m_ecdsa_blob,
                       tdqe_blob_size,
                       static_cast<uint32_t>(m_att_key_algorithm_id),
                       p_app_report,
                       NULL,
                       NULL,
                       NULL,
                       p_quote,
                       quote_size,
                       NULL,
                       0);
```

This is the first wrapper-side ML-DSA quote-generation path that does not route through platform quote provider bootstrap assumptions.

### Tests run

Rebuilt the wrapper again:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
LINK =>  libsgx_tdx_logic.so
```

Ran the local ML-DSA TDX-only suite:

```bash
./tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Observed result:

```text
[test] TDQE ML-DSA adapter passed: keygen/sign/verify deterministic checks OK
[test] sizes: pub=1952 priv=4032 sig=3309
[mldsa_get_quote_size td_ql_logic.cpp:2485] [tdx-quote-debug] mldsa_get_quote_size: quote_size=7102 (default certification data path only).
[test] wrapper algorithm selection and ML-DSA quote-size checks passed (mldsa=7102)
[SKIP] Insufficient permissions on /dev/tdx_guest; skipping the direct TDX ML-DSA capability probe.
```

### Result

The trusted TDX-only ML-DSA path now covers both:
- initialization of a trusted local ML-DSA blob
- wrapper-side quote-size and quote-generation plumbing that no longer depends on legacy PCE bootstrap assumptions

What is verified right now:
- the wrapper builds
- the ML-DSA bootstrap path is selected by default
- `tee_att_get_quote_size(MLDSA_65)` works again under the new bootstrap mode
- the TDX-only local suite still passes the ML-DSA backend/layout/plumbing checks

What still remains to verify with real `/dev/tdx_guest` access:
- whether the direct privileged probe can now obtain a quote through the new trusted local ML-DSA wrapper path end-to-end

## Step 45: fixed QGS GET_QUOTE request wiring so the selected ML-DSA context is initialized before quote generation

### Why this step matters

After Steps 43 and 44, the wrapper side had a real trusted TDX-only ML-DSA bootstrap path.

But the direct privileged probe still failed through the forced local `qgs` path with:

```text
tee_att_init_quote bootstrap ret=0x1100d
```

The key issue was in the `qgs` request flow:
- when the thread-local context did not exist yet, `get_resp(...)` created a default context with `tee_att_create_context(NULL, ...)`
- for non-platform-info requests, it immediately called `tee_att_init_quote(...)` on that default context
- only later, inside `GET_QUOTE_REQ`, it parsed the requested attestation-key UUID and switched the context through `ensure_context_for_quote_request(...)`

So the first bootstrap was happening on the wrong context before the ML-DSA request had been applied.

### What I changed

File: [qgs_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/qgs_ql_logic.cpp)

#### 1. Skip the generic early bootstrap for `GET_QUOTE_REQ`

Changed the early `ptr.get() == 0` bootstrap block so it now skips `GET_QUOTE_REQ`:

```c++
if (req_type != GET_PLATFORM_INFO_REQ && req_type != GET_QUOTE_REQ) {
    ...
    tee_att_ret = tee_att_init_quote(ptr.get(), &qe_target_info, false, &hash_size, hash);
    ...
}
```

This ensures that quote requests no longer initialize a default context before the request-specific attestation-key selection is known.

#### 2. Initialize the selected context explicitly inside `GET_QUOTE_REQ`

Right after:

```c++
tee_att_ret = ensure_context_for_quote_request(p_id_list, id_list_size, &selected_tdx_uuid);
```

I added a selected-context bootstrap:

```c++
sgx_target_info_t qe_target_info = {};
uint8_t hash[32] = {0};
size_t hash_size = sizeof(hash);
tee_att_ret = tee_att_init_quote(ptr.get(), &qe_target_info, false, &hash_size, hash);
```

with matching debug traces:

```text
[qgs-debug] GET_QUOTE_REQ about to call tee_att_init_quote selected-context bootstrap
[qgs-debug] GET_QUOTE_REQ tee_att_init_quote selected-context ret=...
```

If that initialization fails, `GET_QUOTE_REQ` now stops immediately with an error response instead of falling through to `tee_att_get_quote_size()` / `tee_att_get_quote()` on an uninitialized or wrong context.

### Tests run

Rebuilt QGS after the request-wiring fix:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
g++ -o qgs ... qgs_ql_logic.o ...
```

Also rebuilt the wrapper again to keep the local QGS dependencies aligned:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
make: Leaving directory '.../tdx_quote/linux'
```

### Result

The forced local `qgs` path no longer bootstraps a default context before applying the requested attestation-key UUID.

That means the next privileged probe will test the correct thing:
- whether `GET_QUOTE_REQ` with ML-DSA now initializes the selected ML-DSA context
- and whether the remaining failure, if any, is still a real environment limitation or a later-stage wrapper/backend issue

## Step 46: removed the QGS dependency on the default context when selecting the requested ML-DSA key

### Why this step matters

After Step 45, the forced local `qgs` path still timed out very early. The logs showed:

```text
GET_QUOTE_REQ: report_size=1024 id_list_size=16
About to delete ctx in cleanup
```

This strongly suggested that request-specific context selection was still going wrong before the selected-context bootstrap completed.

The likely root cause was in `select_tdx_att_key_id_from_uuid_list(...)`:
- it was using `tee_att_get_keyid(ptr.get(), ...)` on the thread-local default context
- then mutating only `algorithm_id`
- so request selection still depended on an existing context even though `GET_QUOTE_REQ` is exactly the place where we want to select or replace that context

### What I changed

File: [qgs_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/qgs_ql_logic.cpp)

#### 1. Embedded local default attestation key IDs in QGS

Added two local static constants that mirror the wrapper defaults:
- `k_qgs_default_ecdsa_p256_att_key_id`
- `k_qgs_default_mldsa_65_att_key_id`

These contain the same TDQE identity metadata and differ only in `algorithm_id`.

This avoids relying on non-exported wrapper globals and avoids depending on the current context to construct the requested key id.

#### 2. Reworked request selection to use those local defaults directly

Changed `select_tdx_att_key_id_from_uuid_list(...)` so it now copies the full requested attestation key id directly from the local constants:

```c++
std::memcpy(&p_selected_key_id->base,
            &k_qgs_default_mldsa_65_att_key_id,
            sizeof(k_qgs_default_mldsa_65_att_key_id));
```

and similarly for ECDSA.

So request selection is now based purely on:
- the incoming UUID list
- the known local wrapper-compatible default key ids

not on the already-existing context.

#### 3. Added explicit request-selection tracing

Added debug traces inside `ensure_context_for_quote_request(...)`:

```text
[qgs-debug] ensure_context requested algorithm_id=...
[qgs-debug] ensure_context current algorithm_id=...
[qgs-debug] ensure_context about to create selected context algorithm_id=...
[qgs-debug] ensure_context create_context ret=... ctx=...
```

These traces will show whether `GET_QUOTE_REQ` is really switching to an ML-DSA context before the bootstrap call.

### Tests run

Rebuilt QGS after embedding the local default key ids and removing the dependency on the default context:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
g++ -o qgs ... qgs_ql_logic.o ...
```

### Result

`GET_QUOTE_REQ` key selection in `qgs` no longer depends on the current/default context.

The next privileged probe should now tell us one of two things clearly:
- either the selected ML-DSA context is now created correctly and the failure moves deeper into the bootstrap / quote-generation path
- or there is still a later-stage wrapper/backend limitation after correct ML-DSA context selection

## Step 47: fixed a double-free in QGS when switching from the default ECDSA context to ML-DSA

### Why this step matters

After Step 46, the new traces showed:

```text
[qgs-debug] ensure_context requested algorithm_id=5
[qgs-debug] ensure_context current algorithm_id=2
About to delete ctx in cleanup
```

and then the flow stopped before:
- creating the selected ML-DSA context
- bootstrapping it

That pointed directly at the context switch path itself.

The bug was here in `ensure_context_for_quote_request(...)`:

```c++
tee_att_free_context(ptr.get());
ptr.reset(nullptr);
```

But `ptr` is a `boost::thread_specific_ptr<tee_att_config_t>` with a cleanup function that already frees the context on reset. So the old code was freeing the same context twice during the switch from ECDSA to ML-DSA.

### What I changed

File: [qgs_ql_logic.cpp](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/qgs_ql_logic.cpp)

Removed the explicit free and left the `thread_specific_ptr` cleanup as the single owner:

```c++
ptr.reset(nullptr);
```

This preserves the intended context switch while avoiding the double-free during ML-DSA selection.

### Tests run

Rebuilt QGS after removing the duplicate free:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk
```

Result:

```text
make: Nothing to be done for 'all'.
```

### Result

The ML-DSA context switch in `qgs` no longer tears down the old thread-local context twice.

The next privileged probe should now show whether:
- the selected ML-DSA context is created successfully
- and where the next real failure occurs after the context switch

## Step 48: confirmed that QGS now creates the selected ML-DSA context and that the remaining failure is QE loading via SGX uRTS

### Why this step matters

After Step 47, the remaining question was whether `GET_QUOTE_REQ` could finally:
- switch from the default ECDSA context to the requested ML-DSA context
- bootstrap that selected context

That is exactly what the next privileged probe clarified.

### What the probe showed

The probe now reaches the ML-DSA context switch cleanly:

```text
[qgs-debug] ensure_context requested algorithm_id=5
[qgs-debug] ensure_context current algorithm_id=2
[qgs-debug] ensure_context about to create selected context algorithm_id=5
[qgs-debug] ensure_context create_context ret=0x0 ctx=...
[qgs-debug] ensure_context_for_quote_request ret=0x0
GET_QUOTE_REQ: selected uuid=e86c046e... algorithm-aware context ready
```

So the important part is now confirmed:
- QGS is no longer stuck on the default ECDSA context
- it does create a real ML-DSA wrapper context
- the request wiring and context switching bugs are resolved

The new failure now happens later, during the selected-context bootstrap:

```text
[qgs-debug] GET_QUOTE_REQ about to call tee_att_init_quote selected-context bootstrap
[load_qe td_ql_logic.cpp:599] Error, call sgx_create_enclave QE fail [load_qe], SGXError:0001.
[qgs-debug] GET_QUOTE_REQ tee_att_init_quote selected-context ret=0x11001 hash_size=32
GET_QUOTE_REQ selected-context tee_att_init_quote return 0x11001
Please use the correct uRTS library from PSW package.
```

### What this means

This is a materially better result than before.

Before this step, the forced local QGS path was failing while:
- bootstrapping the wrong context
- or tearing the context down incorrectly during ECDSA -> ML-DSA switching

Now the failure has moved to:
- `load_qe()`
- specifically `sgx_create_enclave`

That means:
- the ML-DSA request wiring is now working
- the selected ML-DSA context is real
- the remaining blocker is the runtime requirement to load the QE through SGX uRTS / PSW

### Tests run

Privileged probe:

```bash
cd /home/alocin-local/tdx-pq-attestation/tdx_tests/direct
sudo env TDX_ATTEST_TRACE_DIRECT=1 ./run_mldsa_tdx_only_tests.sh
```

Observed result:

```text
[test] direct requested att key id: e86c046e8cc44d958173fc43c1fa4f40
[tdx-attest-trace] generate_get_quote_blob request att key ids count=1
[tdx-attest-trace]   id[0]=e86c046e8cc44d958173fc43c1fa4f40
[qgs-debug] ensure_context requested algorithm_id=5
[qgs-debug] ensure_context current algorithm_id=2
[qgs-debug] ensure_context about to create selected context algorithm_id=5
[qgs-debug] ensure_context create_context ret=0x0 ctx=...
[qgs-debug] GET_QUOTE_REQ tee_att_init_quote selected-context ret=0x11001 hash_size=32
```

### Result

The forced local QGS path is now blocked at the real remaining boundary:
- QE enclave loading through SGX uRTS / PSW

So the current state is:
- ML-DSA request selection: working
- ML-DSA wrapper context creation: working
- trusted TDX-only ML-DSA bootstrap in the wrapper: implemented
- end-to-end public-wrapper probing on this host: still unavailable because the selected context still needs SGX QE loading support that a `tdx_guest`-only system does not provide

## Step 49: enabled real SGX simulation-mode linking for the TDQE/QGS/TDX-wrapper path

### Why this step matters

At this point it was clear that:
- the host does not provide SGX hardware
- QEMU without SGX-capable host hardware would not help
- the only realistic local experiment left was to make the repo actually use `SGX_MODE=SIM`

The repo already had a global `SGX_MODE ?= HW` setting, and the local SDK includes all the required simulation libraries:

```text
libsgx_trts_sim.a
libsgx_tservice_sim.a
libsgx_uae_service_sim.so
libsgx_urts_sim.so
```

But the TDQE / QGS / TDX-wrapper path was not honoring that mode.

### What I changed

File: [ae/dep/buildenv.mk](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/dep/buildenv.mk)

Changed the enclave-side runtime libraries to respect `SGX_MODE`:

```make
ifneq ($(SGX_MODE), HW)
URTSLIB := -lsgx_urts_sim
TRTSLIB := -lsgx_trts_sim
EXTERNAL_LIB_NO_CRYPTO += -lsgx_tservice_sim
else
URTSLIB := -lsgx_urts
TRTSLIB := -lsgx_trts
EXTERNAL_LIB_NO_CRYPTO += -lsgx_tservice
endif
```

File: [QuoteGeneration/quote_wrapper/qgs/Makefile](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/Makefile)

Changed the QGS untrusted runtime libraries to respect `SGX_MODE`:

```make
ifneq ($(SGX_MODE), HW)
QGS_URTS_LIBS = -lsgx_urts_sim -lsgx_uae_service_sim
else
QGS_URTS_LIBS = -lsgx_urts -lsgx_uae_service
endif
```

File: [QuoteGeneration/quote_wrapper/tdx_quote/linux/Makefile](/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/linux/Makefile)

Changed the TDX wrapper untrusted link path to respect `SGX_MODE`:

```make
ifneq ($(SGX_MODE), HW)
Quote_Urts_Libs := -lsgx_urts_sim -lsgx_uae_service_sim
else
Quote_Urts_Libs := -lsgx_urts -lsgx_uae_service
endif
```

### Tests run

Checked that the local SDK really contains the simulation libraries:

```bash
ls /home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk/lib64 | rg "sgx_(urts|urts_sim|uae_service|uae_service_sim|trts|trts_sim|tservice|tservice_sim)"
```

Result:

```text
libsgx_trts.a
libsgx_trts_sim.a
libsgx_tservice.a
libsgx_tservice_sim.a
libsgx_uae_service.so
libsgx_uae_service_sim.so
libsgx_urts.so
libsgx_urts.so.2
libsgx_urts_sim.so
```

Then did clean rebuilds in simulation mode.

#### TDQE

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux clean
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk SGX_MODE=SIM
```

Observed link/sign output included:

```text
... -lsgx_trts_sim ... -lsgx_tservice_sim ...
<EnclaveConfiguration>
    ...
    <HW>0</HW>
    ...
</EnclaveConfiguration>
SIGN =>  libsgx_tdqe.signed.so
```

#### QGS and TDX wrapper

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs clean
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk SGX_MODE=SIM
```

Observed link output included:

```text
... libsgx_tdx_logic.so
... -lsgx_urts_sim -lsgx_uae_service_sim ...
g++ -o qgs ...
```

The clean TDX wrapper rebuild also linked successfully with the simulation runtimes:

```text
g++ ... -lsgx_urts_sim -lsgx_uae_service_sim ... -o libsgx_tdx_logic.so
LINK =>  libsgx_tdx_logic.so
```

### Result

The path `TDQE -> tdx_quote -> qgs` now genuinely supports simulation-mode linking.

That does not yet prove the ML-DSA end-to-end flow will work in SIM, but it materially changes the environment story:
- we are no longer blocked strictly on missing SGX hardware for this path
- we now have a repo-local way to exercise the SGX-dependent wrapper/QGS path against simulation runtimes

The next step should be to run the local QGS / wrapper probe under `SGX_MODE=SIM` and see whether the previous `sgx_create_enclave` failure disappears or moves deeper into the ML-DSA quote bootstrap.

## Step 36: Diagnose the simulation-mode enclave load failure and fix the runner/runtime assumptions

### What changed

After switching the local `QGS/tee_att` path to `SGX_MODE=SIM`, the direct probe reached the ML-DSA-selected context and failed deeper in `load_qe()` with:

```text
[load_qe td_ql_logic.cpp:599] Error, call sgx_create_enclave QE fail [load_qe], SGXError:200f.
```

I traced that failure to two concrete issues:

1. The runtime test runner was not consistently propagating `SGX_MODE=SIM` or simulation runtime libraries to every build/run step.
2. `load_qe()` expects the signed enclave file name `libsgx_tdqe.signed.so.1`, while the TDQE build output directory only contained `libsgx_tdqe.signed.so`.

### Files changed

- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux/Makefile`
- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/id_enclave/linux/Makefile`
- `/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh`

### Code changed

#### 1. Create versioned signed-enclave symlinks in TDQE

In `ae/tdqe/linux/Makefile` I added a major-version alias for the signed enclave:

```make
SIGNED_TDQE_NAME := libsgx_$(AENAME)$(if $(FIPS),-fips).signed.so
SIGNED_TDQE_MAJOR := $(SIGNED_TDQE_NAME).$(call get_major_version,TDQE_VERSION)
```

and after signing:

```make
$(SIGNED_TDQE_NAME): $(SONAME) $(TDQE_CONFIG_FILE) $(TDQE_KEY_FILE)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(TDQE_KEY_FILE) -enclave $< -out $@ -config $(TDQE_CONFIG_FILE)
	@$(LN) $(SIGNED_TDQE_NAME) $(SIGNED_TDQE_MAJOR)
	@echo "SIGN =>  $@"
```

cleanup also removes the versioned alias:

```make
	@$(RM) *.signed.so
	@$(RM) *.signed.so.*
```

#### 2. Apply the same fix to ID_ENCLAVE

In `ae/id_enclave/linux/Makefile` I added the matching signed-enclave alias:

```make
SIGNED_IDE_NAME := libsgx_$(AENAME)$(if $(FIPS),-fips).signed.so
SIGNED_IDE_MAJOR := $(SIGNED_IDE_NAME).$(call get_major_version,IDE_VERSION)
```

and after signing:

```make
$(SIGNED_IDE_NAME): $(SONAME) $(IDE_CONFIG_FILE) $(IDE_KEY_FILE)
	@$(SGX_ENCLAVE_SIGNER) sign -key $(IDE_KEY_FILE) -enclave $< -out $@ -config $(IDE_CONFIG_FILE)
	@$(LN) $(SIGNED_IDE_NAME) $(SIGNED_IDE_MAJOR)
```

#### 3. Make the direct ML-DSA runner actually respect `SGX_MODE=SIM`

In `tdx_tests/direct/run_mldsa_tdx_only_tests.sh` I added:

```bash
SGX_MODE_VALUE="${SGX_MODE:-HW}"
```

and a helper to guarantee the signed-enclave major alias exists even on incremental builds where `make` does not rerun the signer:

```bash
ensure_signed_enclave_major_link() {
  local signed_path="$1"
  local major_path="$2"
  if [[ -f "$signed_path" && ! -e "$major_path" ]]; then
    ln -sf "$(basename "$signed_path")" "$major_path"
  fi
}
```

The TDQE build step now uses the requested mode and guarantees the alias:

```bash
make -C "$TDQE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
ensure_signed_enclave_major_link \
  "$TDQE_LINUX_DIR/libsgx_tdqe.signed.so" \
  "$TDQE_LINUX_DIR/libsgx_tdqe.signed.so.1"
```

The runner also now propagates `SGX_MODE` into the wrapper and QGS builds:

```bash
make -C "$TDX_QUOTE_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
make -C "$QGS_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
```

and chooses the correct runtime library in SIM:

```bash
URTS_LINK_LIB="-lsgx_urts"

if [[ "$SGX_MODE_VALUE" == "SIM" ]]; then
  URTS_LIB_DIR="$LOCAL_SGX_SDK/lib64"
  URTS_LINK_LIB="-lsgx_urts_sim"
elif [[ -f "$SYSTEM_URTS_DIR/libsgx_urts.so" ]]; then
  URTS_LIB_DIR="$SYSTEM_URTS_DIR"
fi
```

That value is used both for the wrapper algorithm-selection test link and for the direct probe runtime `LD_LIBRARY_PATH`.

### Tests run

Validated runner syntax:

```bash
bash -n /home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Result: passed.

Verified the root cause in code and runtime artifacts:

```bash
sed -n '543,640p' /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp
ls -l /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux
```

This showed:
- `load_qe()` calls `sgx_create_enclave(...)`
- `TDQE_ENCLAVE_NAME` is `libsgx_tdqe.signed.so.1`
- the directory only had `libsgx_tdqe.signed.so`

Verified that incremental `make` alone does not create the missing alias:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk SGX_MODE=SIM
ls -l /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/linux/libsgx_tdqe.signed.so*
```

Observed result before rerunning the full probe:

```text
make: Nothing to be done for 'all'.
-rw-rw-r-- ... libsgx_tdqe.signed.so
```

That confirmed the need for the runner-side alias creation as well.

I also tried to rebuild `id_enclave` in SIM mode:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/id_enclave/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk SGX_MODE=SIM
```

This currently fails in the local SDK environment with:

```text
/usr/bin/ld: cannot find -lsgx_trts_sim: No such file or directory
/usr/bin/ld: cannot find -lsgx_tservice_sim: No such file or directory
```

### Result

The immediate `SGXError:200f` diagnosis is now concrete:
- it was consistent with the QE loader looking for `libsgx_tdqe.signed.so.1`
- the runner and build artifacts were not guaranteeing that file existed
- the simulation-mode runner also had incomplete `_sim` propagation

The next probe should no longer fail for the same trivial file-name/runtime-library reasons. If it still fails, the failure will be deeper in enclave loading or in the ML-DSA bootstrap itself.

## Step 37: Pass the real TDQE signed-enclave path into QGS instead of relying on the wrapper library directory

### What changed

After the previous fix, the simulation-mode probe still failed with:

```text
[load_qe td_ql_logic.cpp:599] Error, call sgx_create_enclave QE fail [load_qe], SGXError:200f.
```

The next diagnosis showed that `tee_att_create_context()` was still being called by `QGS` with `p_qe_path == NULL`.

That matters because in `td_ql_logic.cpp`, `get_qe_path()` behaves like this:
- if `tdqe_path` is set in the context, use it directly
- otherwise derive a path relative to the binary/library that called into the wrapper

For local `QGS` this fallback is wrong for TDQE loading, because the wrapper library lives under:

```text
QuoteGeneration/quote_wrapper/tdx_quote/linux
```

while the actual signed TDQE enclave lives under:

```text
ae/tdqe/linux
```

So the remaining `200f` was still consistent with “wrong file path”, even after the `.signed.so.1` alias existed.

### Files changed

- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs/qgs_ql_logic.cpp`
- `/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh`

### Code changed

#### 1. Teach QGS to accept an explicit TDQE file path from the environment

In `qgs_ql_logic.cpp` I added:

```cpp
static const char *get_qgs_tdqe_path()
{
    const char *configured_path = std::getenv("QGS_TDQE_PATH");
    if (configured_path != NULL && configured_path[0] != '\0') {
        return configured_path;
    }
    return NULL;
}
```

and changed all local context creation sites from:

```cpp
tee_att_create_context(..., NULL, &p_ctx);
```

to:

```cpp
tee_att_create_context(..., get_qgs_tdqe_path(), &p_ctx);
```

This applies both to:
- the initial default context creation
- the algorithm-aware replacement context for ML-DSA

#### 2. Export the correct TDQE path from the direct ML-DSA test runner

In `run_mldsa_tdx_only_tests.sh` I added:

```bash
QGS_TDQE_PATH="${QGS_TDQE_PATH:-$TDQE_LINUX_DIR/libsgx_tdqe.signed.so.1}"
```

and passed it when launching QGS:

```bash
QGS_SOCKET_PATH="$QGS_SOCKET_PATH" \
QGS_TDQE_PATH="$QGS_TDQE_PATH" \
LD_LIBRARY_PATH="$QGS_LD_LIBRARY_PATH:${LD_LIBRARY_PATH:-}" \
  "$QGS_DIR/qgs" --no-daemon --debug "-n=$QGS_NUM_THREADS" >"$QGS_LOG_PATH" 2>&1 &
```

That means the local `QGS` now points the wrapper directly at the real TDQE signed-enclave file instead of relying on the fallback path logic.

### Tests run

Validated the runner syntax again:

```bash
bash -n /home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh
```

Result: passed.

Rebuilt local `QGS` in simulation mode after the new path wiring:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/qgs \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk SGX_MODE=SIM
```

Observed final link line included the simulation runtimes:

```text
g++ -o qgs ... -lsgx_urts_sim -lsgx_uae_service_sim ...
```

### Result

The remaining `sgx_create_enclave(...)=200f` path is no longer forced to rely on the wrapper library directory to locate the TDQE enclave.

The next probe will tell us whether the enclave now loads correctly, or whether there is another deeper simulation-mode issue beyond simple file location.

## Step 38: Remove the remaining hardware-runtime mismatch in `pce_wrapper` for simulation mode

### What changed

After the explicit `QGS_TDQE_PATH` fix, the simulation-mode probe no longer failed with a plain path-lookup issue. Instead, `QGS` reached:

```text
GET_QUOTE_REQ: selected uuid=e86c046e... algorithm-aware context ready
[qgs-debug] GET_QUOTE_REQ about to call tee_att_init_quote selected-context bootstrap
```

and then the `QGS` process died with `SIGILL`.

That pointed to a runtime mismatch inside the local user-space stack rather than a simple ML-DSA selection bug. I checked the local linkage and found that `pce_wrapper` was still hardcoded to the hardware SGX runtime even under `SGX_MODE=SIM`.

### Files changed

- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux/Makefile`
- `/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh`

### Code changed

#### 1. Make `pce_wrapper` respect `SGX_MODE`

In `QuoteGeneration/pce_wrapper/linux/Makefile`, the old code was:

```make
Link_Flags := $(SGX_COMMON_CFLAGS) -L$(ROOT_DIR)/build/linux -L$(SGX_SDK)/lib64 -lsgx_urts -lpthread -ldl
```

I changed it to:

```make
ifneq ($(SGX_MODE), HW)
PCE_URTS_LIBS := -lsgx_urts_sim
else
PCE_URTS_LIBS := -lsgx_urts
endif
Link_Flags := $(SGX_COMMON_CFLAGS) -L$(ROOT_DIR)/build/linux -L$(SGX_SDK)/lib64 $(PCE_URTS_LIBS) -lpthread -ldl
```

That removes the last obvious hardware-only runtime dependency from the local wrapper stack in simulation mode.

#### 2. Build `pce_wrapper` explicitly in the direct ML-DSA runner

The runner previously relied on indirect rebuilds. I added an explicit step so the local test path is reproducible:

```bash
echo "[INFO] Building repo-local PCE wrapper..."
make -C "$PCE_WRAPPER_LINUX_DIR" SGX_SDK="$LOCAL_SGX_SDK" SGX_MODE="$SGX_MODE_VALUE"
```

This now runs before the `tdx_quote` and `qgs` builds.

### Tests run

Rebuilt `pce_wrapper` in simulation mode:

```bash
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux clean
make -C /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux \
     SGX_SDK=/home/alocin-local/tdx-pq-attestation/tdx_tests/sgxsdk SGX_MODE=SIM
ldd /home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/pce_wrapper/linux/libsgx_pce_logic.so
```

Observed new link line:

```text
... -lsgx_urts_sim ...
```

and `ldd` showed:

```text
libsgx_urts_sim.so => not found
```

which is expected without the explicit `LD_LIBRARY_PATH`, but it importantly confirmed that the binary now depends on the simulation runtime instead of the hardware runtime.

### Result

The local wrapper stack is now more internally consistent in `SGX_MODE=SIM`:
- `qgs` uses `_sim`
- `tdx_quote` uses `_sim`
- `pce_wrapper` now also uses `_sim`

This removes another strong candidate for the `SIGILL` observed during ML-DSA bootstrap under simulation mode.

## Step 39: Add a minimal TDQE simulation loader probe to separate SGX simulation runtime failures from ML-DSA logic

### What changed

Even after aligning the local wrapper stack to `SGX_MODE=SIM`, the `QGS` process still died with `SIGILL` right after:

```text
GET_QUOTE_REQ: selected uuid=e86c046e... algorithm-aware context ready
[qgs-debug] GET_QUOTE_REQ about to call tee_att_init_quote selected-context bootstrap
```

At that point the most useful next isolation step was to determine whether the failure is:
- in the ML-DSA quote bootstrap logic, or
- already in the plain `sgx_create_enclave(...)` call used to load the TDQE enclave under the simulation runtime

### Files changed

- `/home/alocin-local/tdx-pq-attestation/tdx_tests/tdqe/test_tdqe_sim_loader.cpp`
- `/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh`

### Code changed

#### 1. New minimal TDQE loader probe

I added `tdx_tests/tdqe/test_tdqe_sim_loader.cpp`, a tiny host-side test that does only:

```cpp
sgx_create_enclave(enclave_path, 0, &token, &updated, &eid, &misc);
```

and prints the resulting SGX status code.

This intentionally bypasses:
- `QGS`
- ML-DSA selection
- quote generation
- blob handling

so that we can tell whether the host can even load `libsgx_tdqe.signed.so.1` through `libsgx_urts_sim`.

#### 2. Wire the new probe into the direct ML-DSA runner

In `run_mldsa_tdx_only_tests.sh` I added:

```bash
TDQE_SIM_LOADER_BIN="$BIN_DIR/test_tdqe_sim_loader"
```

then compile it with the same runtime library family selected by `SGX_MODE`:

```bash
g++ -std=c++14 -O2 -Wall -Wextra -Werror \
  -I"$LOCAL_SGX_SDK/include" \
  "$TESTS_DIR/tdqe/test_tdqe_sim_loader.cpp" \
  -L"$URTS_LIB_DIR" \
  -Wl,-rpath,"$URTS_LIB_DIR" \
  "$URTS_LINK_LIB" -lpthread -ldl \
  -o "$TDQE_SIM_LOADER_BIN"
```

and run it automatically before `QGS` when `SGX_MODE=SIM`:

```bash
if [[ "$SGX_MODE_VALUE" == "SIM" ]]; then
  echo "[INFO] Running TDQE simulation loader probe..."
  LD_LIBRARY_PATH="$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
    "$TDQE_SIM_LOADER_BIN" "$QGS_TDQE_PATH"
fi
```

### Result

The next `SIM` run will tell us immediately whether:
- the host can load the TDQE enclave with `sgx_urts_sim`, or
- the simulation runtime itself is already the failing layer

That sharply separates “runtime simulation is broken on this machine” from “ML-DSA logic is broken in the repo code”.

## Step 40: Add a direct `tee_att_init_quote()` ML-DSA probe to bypass QGS and isolate the crash layer

### What changed

The simulation-mode run continued far enough to show that:
- `QGS` accepts the ML-DSA request
- the algorithm-aware context is created correctly
- the crash happens immediately after:

```text
[qgs-debug] GET_QUOTE_REQ about to call tee_att_init_quote selected-context bootstrap
```

At that point the right next isolation step is to remove `QGS` itself from the equation and call the wrapper directly.

### Files changed

- `/home/alocin-local/tdx-pq-attestation/tdx_tests/wrapper/test_tdx_mldsa_init_quote_probe.cpp`
- `/home/alocin-local/tdx-pq-attestation/tdx_tests/direct/run_mldsa_tdx_only_tests.sh`

### Code changed

#### 1. New direct wrapper probe

I added `tdx_tests/wrapper/test_tdx_mldsa_init_quote_probe.cpp`.

It does only:

1. build an explicit ML-DSA `tee_att_att_key_id_t`
2. call:

```cpp
tee_att_create_context(&att_key_id, tdqe_path, &ctx);
```

3. call:

```cpp
tee_att_init_quote(ctx, &qe_target_info, false, &pub_key_id_size, (uint8_t*)&pub_key_id);
```

4. print the returned status code

This removes:
- `QGS`
- socket transport
- request parsing
- thread-pool scheduling

from the failing path.

#### 2. Run it automatically in the `SIM` ML-DSA test flow

In `run_mldsa_tdx_only_tests.sh` I added:

```bash
WRAPPER_INIT_QUOTE_PROBE_BIN="$BIN_DIR/test_tdx_mldsa_init_quote_probe"
```

then compile it against the same wrapper/runtime selection:

```bash
g++ ... \
  "$TESTS_DIR/wrapper/test_tdx_mldsa_init_quote_probe.cpp" \
  -L"$TDX_QUOTE_LINUX_DIR" \
  -L"$PCE_WRAPPER_LINUX_DIR" \
  -L"$URTS_LIB_DIR" \
  ... \
  -lsgx_tdx_logic "$URTS_LINK_LIB" -lpthread -ldl \
  -o "$WRAPPER_INIT_QUOTE_PROBE_BIN"
```

and in `SGX_MODE=SIM` run it before the `QGS` path:

```bash
LD_LIBRARY_PATH="$TDX_QUOTE_LINUX_DIR:$PCE_WRAPPER_LINUX_DIR:$URTS_LIB_DIR:${LD_LIBRARY_PATH:-}" \
  "$WRAPPER_INIT_QUOTE_PROBE_BIN" "$QGS_TDQE_PATH"
```

### Result

The next simulation-mode run will answer a very specific question:

- if this new probe crashes too, the problem is inside `tee_att_init_quote()` / wrapper / TDQE simulation runtime
- if it succeeds and only `QGS` crashes, then the remaining issue is in `QGS`-side orchestration

### Follow-up correction

The first draft of `test_tdx_mldsa_init_quote_probe.cpp` used two symbols that are not part of the public wrapper headers:
- `g_tdqe_mrsigner`
- an implicit declaration path for `ref_sha256_hash_t`

I corrected that test by:
- including `user_types.h` explicitly for `ref_sha256_hash_t`
- embedding the TDQE `mrsigner` bytes locally in the test instead of relying on the non-exported global from `td_ql_wrapper.cpp`

This keeps the probe self-contained and linkable against the public wrapper surface.

I also had to adjust the runner compile flags for this new probe to include the internal common headers:

```bash
-I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal"
-I"$REPO_ROOT/confidential-computing.tee.dcap-pq/QuoteGeneration/common/inc/internal/linux"
```

because `user_types.h` includes `se_trace.h`.

### Probe result

The follow-up `SIM` run produced the decisive split:

```text
[INFO] Running TDQE simulation loader probe...
[test] loading enclave: .../ae/tdqe/linux/libsgx_tdqe.signed.so.1
[test] sgx_create_enclave returned: 0x0000
[test] enclave load/unload completed
```

so the host can load the TDQE enclave successfully with `sgx_urts_sim`.

But the next direct wrapper probe failed like this:

```text
[INFO] Running wrapper ML-DSA init_quote probe...
[test] creating ML-DSA context with TDQE path: .../libsgx_tdqe.signed.so.1
[test] tee_att_create_context ret=0x0 ctx=...
Illegal instruction (core dumped)
```

This is the key result:
- the crash is **not** in `QGS`
- the crash is **not** in basic `sgx_create_enclave(...)`
- the crash happens inside the wrapper path entered by `tee_att_init_quote()` for ML-DSA under `SGX_MODE=SIM`

That narrows the next debugging target to the first operations inside `tee_att_init_quote()` / `trusted_tdx_only_init_quote()` rather than transport, server logic, or raw enclave loading.

## Step 41: Add fine-grained bootstrap markers inside `trusted_tdx_only_init_quote()`

### What changed

Once the direct wrapper probe showed:
- `tee_att_create_context()` succeeds
- `sgx_create_enclave()` for the TDQE succeeds in `SIM`
- but `tee_att_init_quote()` still dies with `SIGILL`

the next useful step was to instrument the first critical calls inside the ML-DSA trusted bootstrap.

### File changed

- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

### Code changed

Inside `tee_att_config_t::trusted_tdx_only_init_quote(...)` I added unbuffered `stderr` markers before and after the main steps:

- function entry
- `load_qe()`
- target-info setup
- blob mutex lock
- `read_persistent_data(...)`
- `verify_blob(...)`
- `gen_att_key(...)`
- `load_id_enclave_get_id(...)`
- `store_cert_data(...)`
- final `verify_blob(...)`

Representative examples:

```cpp
fprintf(stderr, "[tdx-quote-debug] trusted_tdx_only_init_quote about to load_qe\n");
fflush(stderr);
```

```cpp
fprintf(stderr, "[tdx-quote-debug] trusted_tdx_only_init_quote gen_att_key sgx=0x%x tdqe=0x%x\n",
        sgx_status,
        tdqe_error);
fflush(stderr);
```

### Result

The next `SIM` run should now tell us exactly which bootstrap step is the last one reached before `SIGILL`.

That will distinguish between:
- a crash before any persistent-data/blob path
- a crash in `verify_blob(...)`
- a crash in `gen_att_key(...)`
- a crash later in `store_cert_data(...)`

## Step 42: Add enclave-side `verify_blob()` markers to isolate whether the crash is in unseal or report creation

### What changed

The instrumented wrapper run narrowed the `SIGILL` to this sequence:

```text
[tdx-quote-debug] trusted_tdx_only_init_quote read_persistent_data ret=0x1100e
[tdx-quote-debug] trusted_tdx_only_init_quote about to verify_blob
Illegal instruction
```

So the next boundary to instrument was the TDQE-side helper that actually performs blob verification.

### File changed

- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`

### Code changed

The first intent was to add enclave-side logging around:
- function entry
- computed sealed-blob lengths
- `sgx_unseal_data(...)` for both ECDSA and ML-DSA branches
- `sgx_create_report(...)` after successful unseal

However, direct stdio-style printing was brittle in this enclave build, and switching to `SE_TRACE(...)` introduced a new unresolved dependency on `se_trace_internal` at link time.

The non-invasive fix was to replace those prints with a lightweight internal stage counter:

```cpp
static volatile uint32_t g_tdqe_debug_stage = 0;
```

and then advance it at the key checkpoints:

```cpp
g_tdqe_debug_stage = 100; // enter verify_blob_data_any_internal
g_tdqe_debug_stage = 101; // lengths computed
g_tdqe_debug_stage = 120; // before sgx_unseal_data on ML-DSA blob
g_tdqe_debug_stage = 121; // after sgx_unseal_data on ML-DSA blob
g_tdqe_debug_stage = 130; // before sgx_create_report
g_tdqe_debug_stage = 131; // after sgx_create_report
```

### Result

The next run should tell us whether the `SIGILL` happens:
- before or during `sgx_unseal_data(...)`, or
- after unseal, at `sgx_create_report(...)`

### Follow-up correction

The previous logging-based attempts (`fprintf`, `printf`, `SE_TRACE`) were all rolled back because they either did not compile cleanly in this enclave translation unit or introduced a new link-time dependency.

The current state is the stage-counter instrumentation only, which keeps the TDQE build linkable.

## Step 43: Fix the ML-DSA trusted bootstrap bug that verified an uninitialized blob when no persistent blob existed

### What changed

The latest simulation-mode run produced this key sequence:

```text
[tdx-quote-debug] trusted_tdx_only_init_quote read_persistent_data ret=0x1100e
[tdx-quote-debug] trusted_tdx_only_init_quote about to verify_blob
Illegal instruction
```

That exposed a real logic bug in the trusted ML-DSA bootstrap path.

### File changed

- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

### Bug

When `read_persistent_data()` failed because the ML-DSA blob was not present yet, the code did this:

```cpp
if (TEE_ATT_SUCCESS != refqt_ret) {
    SE_TRACE(... "Falling back to in-memory cache");
    refqt_ret = TEE_ATT_SUCCESS;
}
```

and then continued straight into:

```cpp
sgx_status = verify_blob(..., (uint8_t*)m_ecdsa_blob, ...);
```

That means it attempted to verify an uninitialized in-memory blob on the first run instead of generating a fresh trusted local key.

### Fix

Now the missing-blob case immediately switches to key generation:

```cpp
if (TEE_ATT_SUCCESS != refqt_ret) {
    SE_TRACE(SE_TRACE_WARNING, "ML-DSA blob does not exist in persistent storage. Generating a new trusted local key.\n");
    refqt_ret = TEE_ATT_SUCCESS;
    gen_new_key = true;
    break;
}
```

### Result

This is not just extra tracing. It is a real functional bug fix in the ML-DSA trusted bootstrap path and is a strong candidate for the `SIGILL` observed on first-run `SIM` execution.

## 2026-04-11: Added enclave-to-host stage OCALLs for ML-DSA crash isolation

### Files changed

- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/tdqe.edl`
- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`
- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

### Change

Added a minimal `ocall_debug_message(const char *msg)` path from TDQE to the untrusted wrapper and wired the existing ML-DSA stage markers through it.

The enclave now emits readable `[tdqe-debug] ...` messages before and after the critical substeps in:

- `verify_blob_data_any_internal(...)`
- the ML-DSA branch of `gen_att_key(...)`

and the untrusted side prints those markers to `stderr` from `td_ql_logic.cpp`.

### Purpose

The wrapper-side trace had already narrowed the `SIM` crash to the ML-DSA `gen_att_key(...)` path. The new OCALL messages let the next run show the exact last enclave substep reached before the `SIGILL`, without relying on enclave `printf`/`SE_TRACE` linkage.

### Follow-up

The first textual markers were still too late in the ML-DSA path. Additional early messages were added at:

- `gen_att_key: enter`
- `gen_att_key mldsa: branch selected`
- `gen_att_key mldsa: before/after authdata copy`
- `get_att_key_based_from_seal_key_mldsa(...)` entry
- before/after seal-key seed derivation
- before/after `tdqe_mldsa65_keygen(...)`

so the next run can distinguish ECALL-transition failure from seed-derivation failure from ML-DSA keygen failure.

### Additional bridge tracing

Because no TDQE-side message was appearing before the `SIGILL`, extra debug prints were also added around the ECALL bridge:

- untrusted side in `tdx_quote/linux/tdqe_u.c` before and after `sgx_ecall(..., gen_att_key, ...)`
- trusted stub side in `ae/tdqe/linux/tdqe_t.c` before pointer checks, after buffer copies, and immediately before the real `gen_att_key(...)` body call

This will let the next run distinguish:

- crash before `sgx_ecall`
- crash inside the trusted marshalling stub
- crash only after control reaches the real `gen_att_key(...)` implementation

## 2026-04-11: Temporarily removed randomized ciphertext buffer from gen_att_key prologue

### File changed

- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`

### Change

In `gen_att_key(...)`, the temporary ECDSA ciphertext buffer was switched from:

- `randomly_placed_object<custom_alignment_aligned<...>>`

to a plain local stack object:

- `ref_ciphertext_ecdsa_data_sdk_t ciphertext_data = {};`

with `pciphertext_data` pointing to that simple buffer.

### Purpose

The first TDQE-side debug print in `gen_att_key(...)` was not appearing at all, while the trusted ECALL stub was reaching the call site successfully. That strongly suggested the crash was happening in the prologue before the first explicit debug marker, and the randomized/aligned helper object was the first non-trivial construct in the function body.

This is a diagnostic change to verify whether the `SIGILL` is caused by that prologue object construction.

## 2026-04-11: Split gen_att_key into entry wrapper and implementation helper

### File changed

- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`

### Change

`gen_att_key(...)` was split into:

- `gen_att_key(...)`: minimal exported wrapper that only emits `gen_att_key wrapper: enter`
- `gen_att_key_impl(...)`: the full original body

### Purpose

This isolates whether the `SIGILL` happens:

- in the prologue/entry of the exported enclave function itself
- or only after control reaches the real implementation body

## 2026-04-11: Extracted ML-DSA gen_att_key path into a dedicated helper

### File changed

- `/home/alocin-local/tdx-pq-attestation/confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`

### Change

The ML-DSA branch of `gen_att_key_impl(...)` was moved into a dedicated helper:

- `gen_att_key_mldsa_impl(...)`

The top-level `gen_att_key_impl(...)` now keeps the shared validation and ECDSA path, while the large ML-DSA local buffers and logic live in the dedicated helper.

### Purpose

This is the safest structural way to reduce the stack frame and prologue complexity of `gen_att_key_impl(...)` without changing the trust boundary, crypto ownership, or the overall attestation flow.

### Follow-up

`gen_att_key_impl(...)` was then reduced further to a near-minimal dispatch wrapper:

- shared validation stays in `gen_att_key_impl(...)`
- ECDSA logic moved to `gen_att_key_ecdsa_impl(...)`
- ML-DSA logic stays in `gen_att_key_mldsa_impl(...)`

and the ML-DSA helper was updated to manage its own SHA handle when called without an external one.

### Additional tracing

After the split, the crash moved far enough that `gen_att_key impl: enter` became visible. Extra textual markers were then added after each early shared validation step in `gen_att_key_impl(...)` so the next run can pinpoint which of the first common checks (platform capability, enclave-pointer checks, target attributes, authdata checks, or helper dispatch) is the last one reached.

### Additional narrowing

That tracing then isolated the crash to the very first platform capability check inside `gen_att_key_impl(...)`, namely `is_verify_report2_available()`. Textual markers were added inside that helper before and after:

- local dummy report initialization
- each `report_type` field assignment
- the call to `sgx_verify_report2(...)`

so the next run can determine whether the `SIGILL` happens in basic struct setup or specifically inside the `sgx_verify_report2` leaf.

### SIM-only bypass

The trace then showed the `SIGILL` occurs specifically at `sgx_verify_report2(...)` in simulation mode. To keep using `SIM` as a diagnostic environment for the ML-DSA flow, `is_verify_report2_available()` now returns `true` under `SE_SIM` with an explicit debug message:

- `is_verify_report2_available: SE_SIM bypass -> true`

This bypass is intentionally limited to simulation builds and is not a production-path change.

### Build fix

The first attempt still executed the real `sgx_verify_report2(...)` path because the TDQE enclave build was receiving `SGX_MODE=SIM` but not the `SE_SIM` preprocessor define. The TDQE Linux makefile now adds:

- `DEFINES += -DSE_SIM` when `SGX_MODE != HW`

so the simulation-only bypass actually becomes active in enclave builds.

### Runner fix

The SIM test runner was also updated to run `clean` on the TDQE, PCE wrapper, TDX quote wrapper, and QGS before rebuilding in `SGX_MODE=SIM`. Without that, `make` could incorrectly reuse old objects and hide changes to simulation-only compile-time guards.

## 2026-04-11: ML-DSA TDQE path now reaches successful keygen/report/seal in SIM

### Result observed

After the `SE_SIM` bypass became active, the TDQE ML-DSA path progressed successfully through:

- ML-DSA key derivation
- `tdqe_mldsa65_keygen(...)`
- SHA-256 key-id derivation
- `sgx_create_report(...)`
- `sgx_seal_data(...)`

and returned:

- `trusted_tdx_only_init_quote gen_att_key sgx=0x0 tdqe=0x0`

This confirms the trusted ML-DSA key-generation and sealing path itself is working in simulation.

### New blocker

The next failure moved to:

- `load_id_enclave_get_id ret=0x200f`

which indicates the wrapper could not load the ID enclave file.

### Fix

Two follow-up fixes were applied:

- the SIM runner now builds `ae/id_enclave/linux` and creates `libsgx_id_enclave.signed.so.1`
- `tee_att_create_context(...)` now derives `ide_path` automatically from the provided `tdqe_path`, replacing the basename with `libsgx_id_enclave.signed.so.1`

so the wrapper can load the sibling ID enclave from the same repo-local enclave directory.

### SIM link fix for ID enclave

The local SDK only provides `libsgx_trts_sim.a` and `libsgx_tservice_sim.a` in `lib64`, not in `lib64/cve_2020_0551_load`. The ID enclave makefile previously forced:

- `MITIGATION-CVE-2020-0551 := LOAD`

unconditionally, which pushed simulation builds to the wrong trusted-library directory and caused link failures.

The makefile now enables that mitigation only for `SGX_MODE=HW`, so `SIM` builds link against the correct `lib64` simulation libraries.

### Additional ID-enclave loading trace

After the ID enclave began building successfully, the wrapper still returned `0x200f` from `load_id_enclave_get_id(...)`. Extra debug prints were added around `load_id_enclave(...)` to show:

- the exact resolved `id_enclave_path`
- `access(..., R_OK)` and `access(..., X_OK)` on that path
- the raw `sgx_create_enclave(...)` status code

so the next run can distinguish path-resolution issues from loader/runtime issues on the actual signed enclave file.

### Root cause found

The added path trace showed the wrapper was resolving:

- `/.../ae/tdqe/linux/libsgx_id_enclave.signed.so.1`

while the actual file exists at:

- `/.../ae/id_enclave/linux/libsgx_id_enclave.signed.so.1`

So the remaining `0x200f` was not a loader mystery; it was a bad derived path. The context-path setup now derives `ide_path` from the provided TDQE path by switching the component directory from `tdqe` to `id_enclave` and then appending `/linux/libsgx_id_enclave.signed.so.1`.

## 2026-04-11: Added final-stage gen_quote tracing

### Context

After fixing the ID enclave path, the local SIM flow progressed through:

- trusted ML-DSA `gen_att_key`
- `store_cert_data`
- final `verify_blob`
- `tee_att_init_quote`
- `tee_att_get_quote_size`
- entry into `tee_att_get_quote`

### Change

Added textual debug markers at the start of the TDQE `gen_quote(...)` body and after each early common precondition step:

- report2 availability
- randomized ciphertext buffer setup
- local buffer zeroing
- required pointer checks
- algorithm and blob-size checks
- certification-data validation
- enclave-buffer checks
- quote version determination

### Purpose

This isolates whether the remaining failure in the ML-DSA quote path is in the `gen_quote(...)` prologue, the common parameter validation, or only later in the quote-construction logic.

### Follow-up

Once the `gen_quote(...)` entry and early prechecks were confirmed, additional markers were added deeper in the quote-construction flow:

- before/after `sgx_verify_report2(...)`
- before/after each SHA-384 hash over the TD report structures
- before/after `verify_blob_data_any_internal(...)`
- after quote-size/sign-buffer setup
- before/after `sgx_create_report(...)` for QE report data
- before/after `tdqe_mldsa65_sign(...)`
- before/after `tdqe_mldsa65_verify(...)`
- after certification-data population

so the next run can isolate the first failing step of the final ML-DSA quote assembly.

### SIM-only gen_quote bypass

The added tracing then showed the remaining `get_quote` failure was specifically at:

- `sgx_verify_report2(&p_td_report->report_mac_struct)`

inside `gen_quote(...)`.

To keep the simulation environment useful for end-to-end ML-DSA debugging, that call is now also bypassed under `SE_SIM`, with an explicit marker:

- `gen_quote: SE_SIM bypass sgx_verify_report2`

This is intentionally scoped to simulation builds only.

## Step N: Tightened the direct ML-DSA probe and reduced residual debug noise

### Files
- `tdx_tests/direct/test_tdx_direct_mldsa_probe.cpp`
- `confidential-computing.tee.dcap-pq/ae/tdqe/quoting_enclave_tdqe.cpp`
- `confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp`

### What changed
- The direct ML-DSA probe is now strict:
  - it fails if the ML-DSA attestation key id is not advertised
  - it fails if the selected attestation key id is all-zero
  - it fails if the selected attestation key id is not the ML-DSA default UUID
  - it fails if the quote header does not report `SGX_QL_ALG_MLDSA_65`
- The enclave-side debug callback now suppresses the one-off investigation markers and keeps only the explicit `SE_SIM bypass` messages.
- The wrapper-side `fprintf(...)` probes used to localize `init_quote` and `get_quote` failures were removed now that the path is understood.

### Why this was needed
- The probe should now behave as a real regression test for the repo-local ML-DSA direct path instead of merely printing what happened.
- The earlier instrumentation had served its purpose and was producing large logs that obscured the actual test result.

### Tests run
- Not re-run from the tool after this cleanup step.
- The immediately preceding run had already demonstrated:
  - `tee_att_init_quote ret=0x0`
  - direct selected ML-DSA attestation key id
  - quote header `att_key_type=5`
  - final message that the direct path was exposing ML-DSA quotes

## Step N+1: Added an ML-DSA quote verification support probe

### Files
- `tdx_tests/verifier/test_tdx_mldsa_quote_verify_probe.cpp`
- `tdx_tests/direct/run_mldsa_tdx_only_tests.sh`

### What changed
- Added a new verifier-side support probe that:
  - generates a real ML-DSA quote through the wrapper path
  - confirms the generated quote header reports `SGX_QL_ALG_MLDSA_65`
  - calls `tee_qv_get_collateral(...)`
  - calls `tdx_qv_verify_quote(...)`
  - classifies the result into:
    - supported
    - format/certification-data unsupported
    - parser accepted the quote but verification could not complete because collateral/runtime support was missing
- Updated the ML-DSA direct runner to:
  - build QCNL/QPL/QuoteVerification when the local SGXSSL package is available
  - compile the new verification probe
  - run it before the direct QGS probe
  - report `UNSUPPORTED` or `PARTIAL` without misreporting them as successful verification

### Why this was needed
- Up to this point the repository had strong evidence that ML-DSA quote generation worked in the repo-local path, but not whether the verification stack recognized those quotes.
- Source inspection showed no existing ML-DSA-specific handling in `QuoteVerification/QVL`, so a runtime support probe was needed instead of assuming verifier compatibility.

### Tests run
- Not re-run from the tool after adding this probe.

## Step N+2: Identified the current verifier-side ML-DSA rejection points

### Files inspected
- `confidential-computing.tee.dcap-pq/QuoteVerification/QVL/Src/AttestationLibrary/src/QuoteVerification/QuoteConstants.h`
- `confidential-computing.tee.dcap-pq/QuoteVerification/QVL/Src/AttestationLibrary/src/QuoteVerification/Quote.cpp`
- `confidential-computing.tee.dcap-pq/ae/QvE/qve/qve.cpp`

### What was confirmed
- The current QVL parser still allows only one attestation key type:

```c++
const std::array<uint16_t, 1> ALLOWED_ATTESTATION_KEY_TYPES = {{ ECDSA_256_WITH_P256_CURVE }};
```

- `Quote.cpp` still validates v4/v5 quote auth-data through the ECDSA-only path and rejects unsupported attestation key types before any ML-DSA-specific parsing could happen.
- `qve.cpp` still extracts the QE certification chain through the legacy path that expects the known certification data flow and returns `SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED` when that expectation is not met.

### Why this matters
- The generation side is no longer the blocker.
- The verifier stack is currently blocked first by:
  1. attestation key type allowlist
  2. ECDSA-specific auth-data parsing
  3. certification-data extraction assumptions in QvE

### Tests run
- Source inspection only.
- The runtime support probe had already reported:
  - `verifier does not support ML-DSA quote format/certification data yet`
## 2026-04-11 - Verifier-side ML-DSA work and current blocker

- Added verifier-side ML-DSA parsing and signature verification scaffolding in QVL:
  - `QuoteConstants.h`: added `MLDSA_65`, signature/public-key byte lengths, and allowed attestation key type.
  - `QuoteStructures.{h,cpp}`: added ML-DSA quote auth-data structures and parsing support.
  - `Quote.{h,cpp}`: added ML-DSA auth-data handling plus generic accessors for attestation-key bytes and quote signature bytes.
  - `QuoteVerifier.cpp`: wired ML-DSA quote-signature verification via `tdqe_mldsa65_verify(...)` while preserving the ECDSA-only PCK/QE-report verification path.
- Extended `QuoteVerification/dcap_quoteverify/linux/Makefile` so quoteverify builds include:
  - `ae/tdqe/tdqe_mldsa_adapter.c`
  - `ae/pq/mldsa-native/mldsa/mldsa_native.c`
  - corresponding include paths under `ae/tdqe`, `ae/pq/...`, and QVL commons.
- Added `tdx_tests/verifier/test_tdx_mldsa_quote_verify_probe.cpp`:
  - generates a local ML-DSA quote,
  - checks quote header/key type,
  - probes `tee_qv_get_collateral(...)` and `tdx_qv_verify_quote(...)`,
  - classifies verifier behavior as supported / unsupported / partial.
- Fixed trusted TDX-only ML-DSA blob initialization in `td_ql_logic.cpp`:
  - aligned `m_raw_pce_isvsvn` sentinel handling for the trusted path,
  - populated ML-DSA blob `cert_pce_info` and `raw_pce_info` consistently so later quote generation/verifier probes no longer fail on raw-PCE mismatch.
- Started aligning ML-DSA quote generation with the ECDSA collateral-aware path:
  - `mldsa_get_quote_size(...)` and `mldsa_get_quote(...)` now attempt `get_platform_quote_cert_data(...)`,
  - if successful they prepare a `PCK_CERT_CHAIN`-backed certification-data path,
  - otherwise they are intended to fall back to the existing local-only certification-data path.
- Current status:
  - the raw-PCE mismatch is fixed,
  - the verifier probe now reaches `get_platform_quote_cert_data(...)`,
  - `mldsa_get_quote_size(...)` now degrades correctly to the local-only certification-data path when the platform collateral API returns `0xe019` (`TEE_NETWORK_ERROR`),
  - the isolated verifier probe now proves the next blocker is not quote parsing:
    - `Quote::parse()` and `validate()` succeed on the generated ML-DSA quote,
    - `tee_qv_get_collateral(...)` extracts certification data `size=404`, `type=3`,
    - the verifier then returns `SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED (0xe01c)`.
- Current verifier conclusion:
  - ML-DSA quote generation works in the repo-local `SIM` path,
  - QVL can parse and validate the ML-DSA quote structure,
  - the remaining unsupported point is certification-data type handling in the verifier collateral path:
    - the current generated quote still carries local-only certification data `type=3`,
    - the verifier collateral path expects the supported PCK-chain certification data type and rejects the local-only type as unsupported.
- Follow-up verifier refactor:
  - refactored `ae/QvE/qve/qve.cpp` collateral extraction to rely on the ML-DSA-aware QVL parser path rather than treating the older certification-data helper layer as the primary source of truth,
  - reran the isolated verifier probe and confirmed the same functional outcome after the refactor:
    - quote parse succeeds,
    - quote validate succeeds,
    - QE certification data is extracted successfully,
    - extracted certification data still reports `type=3`,
    - `tee_qv_get_collateral(...)` returns `SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED (0xe01c)`.
- Added real-path diagnostics for ML-DSA platform collateral retrieval:
  - `QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp` now logs the `sgx_ql_pck_cert_id_t` inputs passed into `get_platform_quote_cert_data(...)`, including QE3 ID prefix, encrypted-PPID presence/size, crypto suite, PCE ID, and raw CPU/PCE SVN prefixes.
  - the same function now also logs the raw QPL return code and returned `sgx_ql_config_t` metadata when `sgx_ql_get_quote_config(...)` returns.
  - `QuoteGeneration/qpl/sgx_default_quote_provider.cpp` now logs the incoming quote-config request fields and the raw `sgx_qcnl_get_pck_cert_chain(...)` return code.
  - `QuoteGeneration/qcnl/sgx_default_qcnl_wrapper.cpp` now logs the QCNL-side request fields and the final `CertificationService::get_pck_cert_chain(...)` return code.
- Purpose of the new diagnostics:
  - distinguish malformed/incomplete `sgx_ql_pck_cert_id_t` input from a genuine PCS/QCNL network or TLS failure,
  - keep the ML-DSA generation path unchanged while exposing why `get_platform_quote_cert_data(...)` still falls back to local-only certification data `type=3`.
- Clarified the ML-DSA test QCNL config:
  - `tdx_tests/sgx_default_qcnl_local_test.conf` now sets both `pccs_url` and `collateral_service` explicitly to the local test service at `https://localhost:8081/sgx/certification/v4/`.
  - reason: QCNL uses `pccs_url` for PCK certificate retrieval, while `collateral_service` is part of the verifier collateral path; both must point to the repo-controlled local service for ML-DSA experiments.
- Added explicit local PCCS bootstrap support to `tdx_tests/direct/run_mldsa_tdx_only_tests.sh`:
  - generates a self-signed TLS keypair under `QuoteGeneration/pccs/service/ssl_key/` if missing,
  - starts `pccs_server.js` locally with deterministic test tokens and `CachingFillMode=OFFLINE`,
  - writes PCCS logs to `tdx_tests/bin/pccs.log`,
  - can optionally preload offline collateral via `LOCAL_PCCS_PLATFORM_COLLATERAL_JSON=...`.
- Aligned the ML-DSA QCNL test config with that local PCCS bootstrap:
  - `tdx_tests/sgx_default_qcnl_local_test.conf` now sets `"use_secure_cert": false` because the repo-local PCCS test service uses a self-signed certificate.
- Added a narrowly scoped local-test fallback for an empty local PCCS cache:
  - `QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp` now treats `TEE_ATT_PLATFORM_UNKNOWN` / `SGX_QL_PLATFORM_UNKNOWN` as eligible for local-only certification-data fallback only when the environment variable `TDX_MLDSA_LOCAL_PCCS_EMPTY_FALLBACK=1` is set.
  - `tdx_tests/direct/run_mldsa_tdx_only_tests.sh` exports that variable by default for the repo-local ML-DSA test flow.
  - security posture: real deployments keep the old behavior unless they explicitly opt in, so an empty/unknown PCCS cache is still a hard error outside the local test harness.
- Upgraded the ML-DSA verifier probe into a working local verifier fallback:
  - `tdx_tests/verifier/test_tdx_mldsa_quote_verify_probe.cpp` now performs local quote-integrity verification when the DCAP collateral path cannot complete:
    - parses the v4 ML-DSA signature area,
    - validates `SHA256(attest_pub_key || qe_auth_data)` against `QE reportData`,
    - verifies the quote signature with `tdqe_mldsa65_verify(...)` over the signed quote payload.
  - `tdx_tests/direct/run_mldsa_tdx_only_tests.sh` now links the probe against the built TDQE ML-DSA adapter objects and `-lcrypto`.
  - effect: the local test flow can now verify ML-DSA quotes meaningfully even when the PCCS cache is empty and the quote therefore falls back to local-only certification data `type=3`.
- Re-aligned the ML-DSA runner with the original ECDSA behavior:
  - the repo-local PCCS bootstrap, the local ML-DSA verifier probe, and `TDX_MLDSA_LOCAL_PCCS_EMPTY_FALLBACK` are now enabled only in `SGX_MODE=SIM`,
  - outside simulation mode the runner skips the local verifier path instead of forcing it.
- Current practical status after comparing ECDSA:
  - ECDSA local tests only bootstrap a local verifier server on `127.0.0.1:8123`; they do not provide a local collateral service.
  - For ML-DSA, the missing infrastructure piece is a PCCS-compatible local service with cached or imported platform collateral.
