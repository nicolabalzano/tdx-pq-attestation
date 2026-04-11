#include <cstdio>
#include <cstdint>
#include <cstring>

#include "td_ql_wrapper.h"
#include "user_types.h"

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <tdqe-signed-enclave-path>\n", argv[0]);
        return 2;
    }

    static const uint8_t kTdqeMrsigner[32] = {
        0x8c, 0x4f, 0x57, 0x75, 0xd7, 0x96, 0x50, 0x3e,
        0x96, 0x13, 0x7f, 0x77, 0xc6, 0x8a, 0x82, 0x9a,
        0x00, 0x56, 0xac, 0x8d, 0xed, 0x70, 0x14, 0x0b,
        0x08, 0x1b, 0x09, 0x44, 0x90, 0xc5, 0x7b, 0xff
    };
    tee_att_att_key_id_t att_key_id = {};
    tee_att_config_t* ctx = nullptr;
    sgx_target_info_t qe_target_info = {};
    ref_sha256_hash_t pub_key_id = {};
    size_t pub_key_id_size = sizeof(pub_key_id);

    att_key_id.base.mrsigner_length = 32;
    std::memcpy(att_key_id.base.mrsigner, kTdqeMrsigner, sizeof(kTdqeMrsigner));
    att_key_id.base.prod_id = 2;
    att_key_id.base.algorithm_id = SGX_QL_ALG_MLDSA_65;

    std::fprintf(stderr, "[test] creating ML-DSA context with TDQE path: %s\n", argv[1]);
    tee_att_error_t ret = tee_att_create_context(&att_key_id, argv[1], &ctx);
    std::fprintf(stderr, "[test] tee_att_create_context ret=0x%x ctx=%p\n", ret, static_cast<void*>(ctx));
    if (ret != TEE_ATT_SUCCESS || ctx == nullptr) {
        return 1;
    }

    ret = tee_att_init_quote(ctx,
                             &qe_target_info,
                             false,
                             &pub_key_id_size,
                             reinterpret_cast<uint8_t*>(&pub_key_id));
    std::fprintf(stderr, "[test] tee_att_init_quote ret=0x%x pub_key_id_size=%zu\n", ret, pub_key_id_size);

    tee_att_free_context(ctx);
    return ret == TEE_ATT_SUCCESS ? 0 : 1;
}
