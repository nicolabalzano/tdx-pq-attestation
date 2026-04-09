#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "tdx_attest/tdx_attest.h"
#include "td_ql_wrapper.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"

static int fail(const char *message, uint32_t code)
{
    std::printf("[test] %s: 0x%x\n", message, code);
    return 1;
}

static bool has_any_nonzero_byte(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        if (data[i] != 0) {
            return true;
        }
    }
    return false;
}

int main()
{
    tee_att_att_key_id_t att_key_id = {};
    tee_att_att_key_id_t default_key_id = {};
    tee_att_config_t *default_context = nullptr;
    tee_att_config_t *context = nullptr;
    tee_att_error_t tee_ret = TEE_ATT_SUCCESS;
    tdx_attest_error_t attest_ret = TDX_ATTEST_SUCCESS;
    size_t pub_key_id_size = 0;
    sgx_target_info_t qe_target_info = {};
    std::vector<uint8_t> pub_key_id;
    tdx_report_data_t report_data = {};
    tdx_report_t td_report = {};
    uint32_t quote_size = 0;
    std::vector<uint8_t> quote;
    const sgx_quote4_header_t *quote_header = nullptr;
    const uint8_t *signature_data = nullptr;
    uint32_t signature_data_len = 0;
    const char *tdqe_path = std::getenv("TEST_TDQE_PATH");

    tee_ret = tee_att_create_context(nullptr, tdqe_path, &default_context);
    if (tee_ret != TEE_ATT_SUCCESS) {
        return fail("tee_att_create_context(default) failed", tee_ret);
    }

    tee_ret = tee_att_get_keyid(default_context, &default_key_id);
    if (tee_ret != TEE_ATT_SUCCESS) {
        tee_att_free_context(default_context);
        return fail("tee_att_get_keyid(default) failed", tee_ret);
    }

    tee_ret = tee_att_free_context(default_context);
    if (tee_ret != TEE_ATT_SUCCESS) {
        return fail("tee_att_free_context(default) failed", tee_ret);
    }

    att_key_id = default_key_id;
    att_key_id.base.algorithm_id = SGX_QL_ALG_MLDSA_65;

    tee_ret = tee_att_create_context(&att_key_id, tdqe_path, &context);
    if (tee_ret != TEE_ATT_SUCCESS) {
        return fail("tee_att_create_context(MLDSA_65) failed", tee_ret);
    }

    tee_ret = tee_att_init_quote(context, nullptr, false, &pub_key_id_size, nullptr);
    if (tee_ret != TEE_ATT_SUCCESS) {
        tee_att_free_context(context);
        return fail("tee_att_init_quote(size query) failed", tee_ret);
    }
    if (pub_key_id_size == 0) {
        tee_att_free_context(context);
        return fail("tee_att_init_quote(size query) returned zero size", TEE_ATT_ERROR_UNEXPECTED);
    }

    pub_key_id.resize(pub_key_id_size, 0);
    tee_ret = tee_att_init_quote(context,
                                 &qe_target_info,
                                 false,
                                 &pub_key_id_size,
                                 pub_key_id.data());
    if (tee_ret != TEE_ATT_SUCCESS) {
        tee_att_free_context(context);
        return fail("tee_att_init_quote(MLDSA_65) failed", tee_ret);
    }

    if (!has_any_nonzero_byte(pub_key_id.data(), pub_key_id.size())) {
        tee_att_free_context(context);
        return fail("tee_att_init_quote returned an all-zero pub_key_id", TEE_ATT_ERROR_UNEXPECTED);
    }

    tee_ret = tee_att_get_quote_size(context, &quote_size);
    if (tee_ret != TEE_ATT_SUCCESS) {
        tee_att_free_context(context);
        return fail("tee_att_get_quote_size(MLDSA_65) failed", tee_ret);
    }
    if (quote_size == 0) {
        tee_att_free_context(context);
        return fail("tee_att_get_quote_size(MLDSA_65) returned zero", TEE_ATT_ERROR_UNEXPECTED);
    }

    for (size_t i = 0; i < sizeof(report_data.d); ++i) {
        report_data.d[i] = static_cast<uint8_t>(0x80u + i);
    }

    attest_ret = tdx_att_get_report(&report_data, &td_report);
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        tee_att_free_context(context);
        return fail("tdx_att_get_report failed", attest_ret);
    }

    quote.resize(quote_size, 0);
    tee_ret = tee_att_get_quote(context,
                                td_report.d,
                                static_cast<uint32_t>(sizeof(td_report.d)),
                                nullptr,
                                quote.data(),
                                quote_size);
    if (tee_ret != TEE_ATT_SUCCESS) {
        tee_att_free_context(context);
        return fail("tee_att_get_quote(MLDSA_65) failed", tee_ret);
    }

    quote_header = reinterpret_cast<const sgx_quote4_header_t *>(quote.data());
    if (quote_header->att_key_type != SGX_QL_ALG_MLDSA_65) {
        tee_att_free_context(context);
        return fail("quote header att_key_type is not MLDSA_65", quote_header->att_key_type);
    }

    if (quote_header->version == QE_QUOTE_VERSION_V5) {
        const sgx_quote5_t *quote5 = reinterpret_cast<const sgx_quote5_t *>(quote.data());
        if (quote5->size + sizeof(uint32_t) + sizeof(sgx_quote5_t) > quote.size()) {
            tee_att_free_context(context);
            return fail("quote v5 body size is invalid", TEE_ATT_ERROR_UNEXPECTED);
        }
        signature_data_len = *reinterpret_cast<const uint32_t *>(quote5->body + quote5->size);
        signature_data = quote5->body + quote5->size + sizeof(uint32_t);
    } else if (quote_header->version == 4) {
        const sgx_quote4_t *quote4 = reinterpret_cast<const sgx_quote4_t *>(quote.data());
        signature_data_len = quote4->signature_data_len;
        signature_data = quote4->signature_data;
    } else {
        tee_att_free_context(context);
        return fail("unexpected quote version", quote_header->version);
    }

    if (signature_data_len < sizeof(sgx_mldsa_65_sig_data_v4_t)) {
        tee_att_free_context(context);
        return fail("signature_data_len is too small for MLDSA payload", signature_data_len);
    }

    if (!has_any_nonzero_byte(signature_data, SGX_QL_MLDSA_65_SIG_SIZE)) {
        tee_att_free_context(context);
        return fail("MLDSA signature payload is all zero", TEE_ATT_ERROR_UNEXPECTED);
    }

    const sgx_mldsa_65_sig_data_v4_t *sig_data =
        reinterpret_cast<const sgx_mldsa_65_sig_data_v4_t *>(signature_data);
    if (!has_any_nonzero_byte(sig_data->attest_pub_key, sizeof(sig_data->attest_pub_key))) {
        tee_att_free_context(context);
        return fail("MLDSA attestation public key is all zero", TEE_ATT_ERROR_UNEXPECTED);
    }

    tee_ret = tee_att_free_context(context);
    if (tee_ret != TEE_ATT_SUCCESS) {
        return fail("tee_att_free_context failed", tee_ret);
    }

    std::printf("[test] ML-DSA end-to-end wrapper flow passed: quote_size=%u version=%u sig_len=%u\n",
                quote_size,
                static_cast<unsigned>(quote_header->version),
                signature_data_len);
    return 0;
}
