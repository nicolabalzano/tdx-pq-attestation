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

struct mldsa_variant_t {
    uint32_t algorithm_id;
    const char* label;
};

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

    uint32_t last_mldsa_quote_size = 0;
    const mldsa_variant_t variants[] = {
        { SGX_QL_ALG_MLDSA_65, "MLDSA_65" },
        { SGX_QL_ALG_MLDSA_87, "MLDSA_87" },
    };

    for (const auto& variant : variants) {
        tee_att_att_key_id_t mldsa_key_id = default_key_id;
        mldsa_key_id.base.algorithm_id = variant.algorithm_id;

        tee_att_config_t* mldsa_context = nullptr;
        err = tee_att_create_context(&mldsa_key_id, tdqe_path, &mldsa_context);
        if (err != TEE_ATT_SUCCESS) {
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_create_context(%s) failed", variant.label);
            return fail(message, err);
        }

        tee_att_att_key_id_t returned_mldsa_key_id = {};
        err = tee_att_get_keyid(mldsa_context, &returned_mldsa_key_id);
        if (err != TEE_ATT_SUCCESS) {
            tee_att_free_context(mldsa_context);
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_get_keyid(%s) failed", variant.label);
            return fail(message, err);
        }

        if (returned_mldsa_key_id.base.algorithm_id != variant.algorithm_id) {
            tee_att_free_context(mldsa_context);
            char message[128] = {};
            std::snprintf(message, sizeof(message), "returned key id algorithm is not %s", variant.label);
            return fail(message, TEE_ATT_ERROR_UNEXPECTED);
        }

        size_t pub_key_id_size = 0;
        err = tee_att_init_quote(mldsa_context, nullptr, false, &pub_key_id_size, nullptr);
        if (err != TEE_ATT_SUCCESS) {
            tee_att_free_context(mldsa_context);
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_init_quote(%s) size query failed", variant.label);
            return fail(message, err);
        }

        if (pub_key_id_size == 0) {
            tee_att_free_context(mldsa_context);
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_init_quote(%s) returned zero pub_key_id_size", variant.label);
            return fail(message, TEE_ATT_ERROR_UNEXPECTED);
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
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_init_quote(%s) bootstrap failed", variant.label);
            return fail(message, err);
        }

        err = tee_att_get_quote_size(mldsa_context, &last_mldsa_quote_size);
        if (err != TEE_ATT_SUCCESS) {
            tee_att_free_context(mldsa_context);
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_get_quote_size(%s) failed", variant.label);
            return fail(message, err);
        }

        if (last_mldsa_quote_size == 0) {
            tee_att_free_context(mldsa_context);
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_get_quote_size(%s) returned zero", variant.label);
            return fail(message, TEE_ATT_ERROR_UNEXPECTED);
        }

        err = tee_att_free_context(mldsa_context);
        if (err != TEE_ATT_SUCCESS) {
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_free_context(%s) failed", variant.label);
            return fail(message, err);
        }
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

    std::printf("[test] wrapper algorithm selection and ML-DSA quote-size checks passed (last_mldsa=%u)\n",
                last_mldsa_quote_size);
    return 0;
}
