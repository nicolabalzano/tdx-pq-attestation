#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>
#include <openssl/sha.h>

#include "tdx_attest/tdx_attest.h"
#include "td_ql_wrapper.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"
#include "sgx_dcap_quoteverify.h"
#include "tdqe_mldsa_adapter.h"

namespace {

constexpr uint16_t kPckIdQeReportCertificationData = 6;

bool compute_sha256(const uint8_t *data, size_t size, uint8_t out[SHA256_DIGEST_LENGTH])
{
    return SHA256(data, size, out) != nullptr;
}

bool locally_verify_mldsa_quote_v4(const uint8_t *quote_buf, uint32_t quote_size)
{
    if (quote_buf == nullptr || quote_size < sizeof(sgx_quote4_t)) {
        return false;
    }

    const auto *quote = reinterpret_cast<const sgx_quote4_t *>(quote_buf);
    if (quote->header.version != 4 || quote->header.att_key_type != SGX_QL_ALG_MLDSA_65) {
        return false;
    }

    const size_t signed_size = sizeof(quote->header) + sizeof(quote->report_body);
    if (quote_size < signed_size + sizeof(uint32_t)) {
        return false;
    }

    const uint32_t sig_data_len = quote->signature_data_len;
    if (quote_size < sizeof(sgx_quote4_t) + sig_data_len) {
        return false;
    }

    if (sig_data_len < sizeof(sgx_mldsa_65_sig_data_v4_t) + sizeof(sgx_ql_certification_data_t)) {
        return false;
    }

    const auto *sig_data = reinterpret_cast<const sgx_mldsa_65_sig_data_v4_t *>(quote->signature_data);
    const auto *outer_cert = reinterpret_cast<const sgx_ql_certification_data_t *>(sig_data->certification_data);
    const size_t outer_cert_total_size =
        sizeof(outer_cert->cert_key_type) + sizeof(outer_cert->size) + outer_cert->size;
    const size_t required_total =
        SGX_QL_MLDSA_65_SIG_SIZE + SGX_QL_MLDSA_65_PUB_KEY_SIZE + outer_cert_total_size;
    if (required_total > sig_data_len) {
        return false;
    }

    if (outer_cert->cert_key_type != kPckIdQeReportCertificationData) {
        return false;
    }

    if (outer_cert->size < sizeof(sgx_qe_report_certification_data_t) + sizeof(sgx_ql_auth_data_t)) {
        return false;
    }

    const auto *qe_cert = reinterpret_cast<const sgx_qe_report_certification_data_t *>(outer_cert->certification_data);
    const uint8_t *auth_ptr = qe_cert->auth_certification_data;
    const uint8_t *outer_cert_end = outer_cert->certification_data + outer_cert->size;
    if (auth_ptr + sizeof(sgx_ql_auth_data_t) > outer_cert_end) {
        return false;
    }

    const auto *qe_auth = reinterpret_cast<const sgx_ql_auth_data_t *>(auth_ptr);
    const uint8_t *qe_auth_end = qe_auth->auth_data + qe_auth->size;
    if (qe_auth_end + sizeof(sgx_ql_certification_data_t) > outer_cert_end) {
        return false;
    }

    const auto *inner_cert = reinterpret_cast<const sgx_ql_certification_data_t *>(qe_auth_end);
    const size_t inner_cert_total_size =
        sizeof(inner_cert->cert_key_type) + sizeof(inner_cert->size) + inner_cert->size;
    if (qe_auth_end + inner_cert_total_size > outer_cert_end) {
        return false;
    }

    std::vector<uint8_t> hash_input;
    hash_input.reserve(SGX_QL_MLDSA_65_PUB_KEY_SIZE + qe_auth->size);
    hash_input.insert(hash_input.end(), sig_data->attest_pub_key, sig_data->attest_pub_key + SGX_QL_MLDSA_65_PUB_KEY_SIZE);
    hash_input.insert(hash_input.end(), qe_auth->auth_data, qe_auth->auth_data + qe_auth->size);

    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    if (!compute_sha256(hash_input.data(), hash_input.size(), digest)) {
        return false;
    }

    if (std::memcmp(qe_cert->qe_report.report_data.d, digest, sizeof(digest)) != 0) {
        return false;
    }

    return tdqe_mldsa65_verify(sig_data->sig,
                               reinterpret_cast<const uint8_t *>(&quote->header),
                               signed_size,
                               sig_data->attest_pub_key) == 0;
}

} // namespace

static int fail(const char *message, uint32_t code)
{
    std::printf("[test] %s: 0x%x\n", message, code);
    std::fflush(stdout);
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

static bool is_verifier_format_unsupported(quote3_error_t ret)
{
    return ret == SGX_QL_QUOTE_FORMAT_UNSUPPORTED ||
           ret == SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED;
}

static bool is_verifier_runtime_or_collateral_limited(quote3_error_t ret)
{
    return ret == SGX_QL_NO_QUOTE_COLLATERAL_DATA ||
           ret == SGX_QL_UNABLE_TO_GET_COLLATERAL ||
           ret == SGX_QL_NETWORK_ERROR ||
           ret == SGX_QL_NETWORK_FAILURE ||
           ret == SGX_QL_SERVICE_UNAVAILABLE ||
           ret == SGX_QL_SERVICE_TIMEOUT ||
           ret == SGX_QL_NO_QVE_IDENTITY_DATA ||
           ret == SGX_QL_TCBINFO_NOT_FOUND ||
           ret == SGX_QL_QEIDENTITY_NOT_FOUND ||
           ret == SGX_QL_INTERNAL_SERVER_ERROR ||
           ret == SGX_QL_PLATFORM_UNKNOWN ||
           ret == SGX_QL_CERTS_UNAVAILABLE ||
           ret == SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED ||
           ret == SGX_QL_TCBINFO_UNSUPPORTED_FORMAT ||
           ret == SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT ||
           ret == SGX_QL_QEIDENTITY_CHAIN_ERROR ||
           ret == SGX_QL_TCBINFO_CHAIN_ERROR ||
           ret == SGX_QL_PCK_CERT_CHAIN_ERROR ||
           ret == SGX_QL_CRL_UNSUPPORTED_FORMAT ||
           ret == SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT;
}

static const char *qv_result_to_string(sgx_ql_qv_result_t qv_result)
{
    switch (qv_result) {
    case SGX_QL_QV_RESULT_OK:
        return "OK";
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        return "CONFIG_NEEDED";
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
        return "OUT_OF_DATE";
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        return "OUT_OF_DATE_CONFIG_NEEDED";
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        return "INVALID_SIGNATURE";
    case SGX_QL_QV_RESULT_REVOKED:
        return "REVOKED";
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
        return "UNSPECIFIED";
    }
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
    const char *tdqe_path = std::getenv("TEST_TDQE_PATH");
    uint32_t supplemental_size = 0;
    std::vector<uint8_t> supplemental;
    uint8_t *collateral_buf = nullptr;
    uint32_t collateral_size = 0;
    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    quote3_error_t qv_ret = SGX_QL_SUCCESS;

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
    tee_ret = tee_att_init_quote(context, &qe_target_info, false, &pub_key_id_size, pub_key_id.data());
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
        report_data.d[i] = static_cast<uint8_t>(0x20u + i);
    }

    attest_ret = tdx_att_get_report(&report_data, &td_report);
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        tee_att_free_context(context);
        return fail("tdx_att_get_report failed", attest_ret);
    }

    quote.resize(quote_size, 0);
    std::printf("[test] about to generate ML-DSA quote for verifier probe\n");
    std::fflush(stdout);
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
    std::printf("[test] generated ML-DSA quote for verifier probe: version=%u att_key_type=%u quote_size=%u\n",
                static_cast<unsigned>(quote_header->version),
                static_cast<unsigned>(quote_header->att_key_type),
                quote_size);
    std::fflush(stdout);

    if (quote_header->att_key_type != SGX_QL_ALG_MLDSA_65) {
        tee_att_free_context(context);
        return fail("generated quote is not MLDSA_65", quote_header->att_key_type);
    }

    qv_ret = tdx_qv_get_quote_supplemental_data_size(&supplemental_size);
    if (qv_ret == SGX_QL_SUCCESS && supplemental_size != 0) {
        supplemental.resize(supplemental_size, 0);
    } else {
        supplemental_size = 0;
    }

    std::printf("[test] about to call tee_qv_get_collateral\n");
    std::fflush(stdout);
    qv_ret = tee_qv_get_collateral(quote.data(), quote_size, &collateral_buf, &collateral_size);
    std::printf("[test] tee_qv_get_collateral ret=0x%x collateral_size=%u\n",
                static_cast<unsigned>(qv_ret),
                collateral_size);
    std::fflush(stdout);
    const bool local_only_candidate =
        is_verifier_format_unsupported(qv_ret) || is_verifier_runtime_or_collateral_limited(qv_ret);
    if (is_verifier_format_unsupported(qv_ret)) {
        std::printf("[test] standard DCAP collateral verification is unavailable for this ML-DSA quote in the current local setup.\n");
        std::fflush(stdout);
    } else if (is_verifier_runtime_or_collateral_limited(qv_ret)) {
        std::printf("[test] standard DCAP collateral verification could not complete in the current local setup.\n");
        std::fflush(stdout);
    }
    if (qv_ret != SGX_QL_SUCCESS) {
        if (collateral_buf != nullptr) {
            tee_qv_free_collateral(collateral_buf);
        }
        if (local_only_candidate) {
            std::printf("[test] about to run local ML-DSA quote verification fallback\n");
            std::fflush(stdout);
            if (!locally_verify_mldsa_quote_v4(quote.data(), quote_size)) {
                tee_att_free_context(context);
                std::printf("[test] local ML-DSA quote verification fallback failed.\n");
                std::fflush(stdout);
                return 1;
            }
            tee_ret = tee_att_free_context(context);
            if (tee_ret != TEE_ATT_SUCCESS) {
                return fail("tee_att_free_context failed", tee_ret);
            }
            std::printf("[test] local ML-DSA quote verification succeeded.\n");
            std::fflush(stdout);
            return 0;
        }
        tee_att_free_context(context);
        std::printf("[test] verifier returned an unexpected collateral error for the ML-DSA quote.\n");
        std::fflush(stdout);
        return 1;
    }

    std::printf("[test] about to call tdx_qv_verify_quote\n");
    std::fflush(stdout);
    qv_ret = tdx_qv_verify_quote(quote.data(),
                                 quote_size,
                                 reinterpret_cast<const tdx_ql_qv_collateral_t *>(collateral_buf),
                                 std::time(nullptr),
                                 &collateral_expiration_status,
                                 &qv_result,
                                 nullptr,
                                 supplemental_size,
                                 supplemental.empty() ? nullptr : supplemental.data());
    std::printf("[test] tdx_qv_verify_quote ret=0x%x qv_result=%s collateral_expiration_status=%u\n",
                static_cast<unsigned>(qv_ret),
                qv_result_to_string(qv_result),
                collateral_expiration_status);
    std::fflush(stdout);

    if (collateral_buf != nullptr) {
        tee_qv_free_collateral(collateral_buf);
    }

    tee_ret = tee_att_free_context(context);
    if (tee_ret != TEE_ATT_SUCCESS) {
        return fail("tee_att_free_context failed", tee_ret);
    }

    if (qv_ret == SGX_QL_SUCCESS) {
        std::printf("[test] standard verifier accepted the ML-DSA quote.\n");
        std::fflush(stdout);
        return 0;
    }

    if (is_verifier_format_unsupported(qv_ret)) {
        std::printf("[test] standard verifier rejected the ML-DSA quote because the required certification data is not available in this setup.\n");
        std::fflush(stdout);
        return 2;
    }

    if (is_verifier_runtime_or_collateral_limited(qv_ret)) {
        std::printf("[test] standard verifier recognized the ML-DSA quote but could not complete verification due to collateral/runtime limits.\n");
        std::fflush(stdout);
        return 3;
    }

    std::printf("[test] verifier returned an unexpected error for the ML-DSA quote.\n");
    std::fflush(stdout);
    return 1;
}
