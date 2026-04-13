#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "td_ql_wrapper.h"
#include "user_types.h"

static int fail(const char* message, tee_att_error_t err)
{
    std::printf("[test] %s: 0x%x\n", message, static_cast<unsigned>(err));
    return 1;
}

int main()
{
    const char* tdqe_path = std::getenv("TEST_TDQE_PATH");
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
    err = tee_att_create_context(&mldsa_key_id, tdqe_path, &mldsa_context);
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

    size_t pub_key_id_size = 0;
    err = tee_att_init_quote(mldsa_context, nullptr, false, &pub_key_id_size, nullptr);
    if (err != TEE_ATT_SUCCESS) {
        tee_att_free_context(mldsa_context);
        return fail("tee_att_init_quote(MLDSA_65) size query failed", err);
    }

    if (pub_key_id_size == 0) {
        tee_att_free_context(mldsa_context);
        return fail("tee_att_init_quote(MLDSA_65) returned zero pub_key_id_size", TEE_ATT_ERROR_UNEXPECTED);
    }

    sgx_target_info_t qe_target_info = {};
    ref_sha256_hash_t pub_key_id = {};
    pub_key_id_size = sizeof(pub_key_id);
    err = tee_att_init_quote(mldsa_context,
                             &qe_target_info,
                             false,
                             &pub_key_id_size,
                             reinterpret_cast<uint8_t*>(&pub_key_id));
    if (err != TEE_ATT_SUCCESS) {
        tee_att_free_context(mldsa_context);
        return fail("tee_att_init_quote(MLDSA_65) bootstrap failed", err);
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
