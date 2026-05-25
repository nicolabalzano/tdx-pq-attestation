#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
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
constexpr uint16_t kPckIdPckCertChain = 5;

struct mldsa_variant_t {
    uint32_t algorithm_id;
    uint32_t sig_size;
    uint32_t pub_key_size;
    const uint8_t *uuid_bytes;
    const char *label;
};

static mldsa_variant_t get_requested_variant()
{
    const char *value = std::getenv("TEST_MLDSA_ALG");
    if (value != nullptr && std::strcmp(value, "44") == 0) {
        static const uint8_t kMldsa44AttestationId[TDX_UUID_SIZE] = TDX_SGX_MLDSA_44_ATTESTATION_ID;
        return {SGX_QL_ALG_MLDSA_44,
                SGX_QL_MLDSA_44_SIG_SIZE,
                SGX_QL_MLDSA_44_PUB_KEY_SIZE,
                kMldsa44AttestationId,
                "MLDSA_44"};
    }
    if (value != nullptr && std::strcmp(value, "87") == 0) {
        static const uint8_t kMldsa87AttestationId[TDX_UUID_SIZE] = TDX_SGX_MLDSA_87_ATTESTATION_ID;
        return {SGX_QL_ALG_MLDSA_87,
                SGX_QL_MLDSA_87_SIG_SIZE,
                SGX_QL_MLDSA_87_PUB_KEY_SIZE,
                kMldsa87AttestationId,
                "MLDSA_87"};
    }

    static const uint8_t kMldsa65AttestationId[TDX_UUID_SIZE] = TDX_SGX_MLDSA_65_ATTESTATION_ID;
    return {SGX_QL_ALG_MLDSA_65,
            SGX_QL_MLDSA_65_SIG_SIZE,
            SGX_QL_MLDSA_65_PUB_KEY_SIZE,
            kMldsa65AttestationId,
            "MLDSA_65"};
}

static bool is_sim_mode()
{
    const char *value = std::getenv("SGX_MODE");
    return value != nullptr && std::strcmp(value, "SIM") == 0;
}

static bool allow_local_quote_verify_fallback()
{
    if (is_sim_mode()) {
        return true;
    }

    const char *value = std::getenv("TEST_MLDSA_ALLOW_LOCAL_FALLBACK");
    return value != nullptr && std::strcmp(value, "1") == 0;
}

static bool allow_local_tdqe_identity_override()
{
    if (is_sim_mode()) {
        return false;
    }

    const char *value = std::getenv("TEST_MLDSA_ALLOW_LOCAL_TDQE_IDENTITY");
    if (value != nullptr) {
        return std::strcmp(value, "1") == 0;
    }
    return true;
}

static bool require_stock_qe_identity()
{
    const char *value = std::getenv("TEST_MLDSA_REQUIRE_STOCK_QE_IDENTITY");
    return value != nullptr && std::strcmp(value, "1") == 0;
}

static const char *local_pcs_identity_file_path()
{
    const char *value = std::getenv("TEST_MLDSA_LOCAL_PCS_IDENTITY_FILE");
    if (value == nullptr || value[0] == '\0') {
        return nullptr;
    }
    return value;
}

static bool should_use_direct_tdx_quote_path()
{
    const char *value = std::getenv("TEST_MLDSA_USE_DIRECT_TDX");
    if (value != nullptr) {
        return std::strcmp(value, "1") == 0;
    }
    return !is_sim_mode();
}

static bool is_requested_mldsa_uuid(const tdx_uuid_t& att_key_id, const mldsa_variant_t& variant)
{
    return std::memcmp(att_key_id.d, variant.uuid_bytes, TDX_UUID_SIZE) == 0;
}

static bool is_all_zero_uuid(const tdx_uuid_t& att_key_id)
{
    static const tdx_uuid_t kZero = {};
    return std::memcmp(att_key_id.d, kZero.d, sizeof(kZero.d)) == 0;
}

static void print_uuid(const char *label, const tdx_uuid_t& value)
{
    std::printf("[test] %s", label);
    for (size_t i = 0; i < sizeof(value.d); ++i) {
        std::printf("%02x", value.d[i]);
    }
    std::printf("\n");
}

bool compute_sha256(const uint8_t *data, size_t size, uint8_t out[SHA256_DIGEST_LENGTH])
{
    return SHA256(data, size, out) != nullptr;
}

std::string bytes_to_hex(const uint8_t *data, size_t size)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.resize(size * 2);
    for (size_t i = 0; i < size; ++i) {
        result[i * 2] = kHex[(data[i] >> 4) & 0x0f];
        result[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return result;
}

std::string make_local_tdqe_identity_json(const sgx_report_body_t& qe_report)
{
    static const char *kIssueDate = "2026-01-01T00:00:00Z";
    static const char *kNextUpdate = "2126-01-01T00:00:00Z";
    static const char *kTcbDate = "2026-01-01T00:00:00Z";
    static const char *kZeroSignature =
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000";

    const auto miscselect_hex = bytes_to_hex(
        reinterpret_cast<const uint8_t *>(&qe_report.misc_select),
        sizeof(qe_report.misc_select));
    const auto attributes_hex = bytes_to_hex(
        reinterpret_cast<const uint8_t *>(&qe_report.attributes),
        sizeof(qe_report.attributes));
    const auto mrsigner_hex = bytes_to_hex(
        qe_report.mr_signer.m,
        sizeof(qe_report.mr_signer.m));
    const auto miscselect_mask_hex = std::string(sizeof(qe_report.misc_select) * 2, 'f');
    const auto attributes_mask_hex = std::string(sizeof(qe_report.attributes) * 2, 'f');

    std::string body;
    body.reserve(1024);
    body += R"({"id":"TD_QE","version":2,"issueDate":")";
    body += kIssueDate;
    body += R"(","nextUpdate":")";
    body += kNextUpdate;
    body += R"(","tcbEvaluationDataNumber":0,"miscselect":")";
    body += miscselect_hex;
    body += R"(","miscselectMask":")";
    body += miscselect_mask_hex;
    body += R"(","attributes":")";
    body += attributes_hex;
    body += R"(","attributesMask":")";
    body += attributes_mask_hex;
    body += R"(","mrsigner":")";
    body += mrsigner_hex;
    body += R"(","isvprodid":)";
    body += std::to_string(static_cast<unsigned>(qe_report.isv_prod_id));
    body += R"(,"tcbLevels":[{"tcb":{"isvsvn":)";
    body += std::to_string(static_cast<unsigned>(qe_report.isv_svn));
    body += R"(},"tcbDate":")";
    body += kTcbDate;
    body += R"(","tcbStatus":"UpToDate","advisoryIDs":[]}],"localtdqe":true})";

    std::string wrapped;
    wrapped.reserve(body.size() + 160);
    wrapped += R"({"enclaveIdentity":)";
    wrapped += body;
    wrapped += R"(,"signature":")";
    wrapped += kZeroSignature;
    wrapped += R"("})";
    return wrapped;
}

bool quote_binds_report_data_v4(const uint8_t *quote_buf,
                                uint32_t quote_size,
                                const tdx_report_data_t& expected_report_data)
{
    if (quote_buf == nullptr || quote_size < sizeof(sgx_quote4_t)) {
        return false;
    }

    const auto *quote = reinterpret_cast<const sgx_quote4_t *>(quote_buf);
    if (quote->header.version != 4) {
        return false;
    }

    return std::memcmp(quote->report_body.report_data.d,
                       expected_report_data.d,
                       sizeof(expected_report_data.d)) == 0;
}

bool locally_verify_mldsa_quote_v4(const uint8_t *quote_buf, uint32_t quote_size, const mldsa_variant_t& variant)
{
    if (quote_buf == nullptr || quote_size < sizeof(sgx_quote4_t)) {
        return false;
    }

    const auto *quote = reinterpret_cast<const sgx_quote4_t *>(quote_buf);
    if (quote->header.version != 4 || quote->header.att_key_type != variant.algorithm_id) {
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

    const uint8_t *signature = quote->signature_data;
    const uint8_t *attest_pub_key = nullptr;
    const uint8_t *certification_data = nullptr;
    if (variant.algorithm_id == SGX_QL_ALG_MLDSA_87) {
        if (sig_data_len < sizeof(sgx_mldsa_87_sig_data_v4_t) + sizeof(sgx_ql_certification_data_t)) {
            return false;
        }
        const auto *sig_data = reinterpret_cast<const sgx_mldsa_87_sig_data_v4_t *>(quote->signature_data);
        attest_pub_key = sig_data->attest_pub_key;
        certification_data = sig_data->certification_data;
    } else if (variant.algorithm_id == SGX_QL_ALG_MLDSA_44) {
        if (sig_data_len < sizeof(sgx_mldsa_44_sig_data_v4_t) + sizeof(sgx_ql_certification_data_t)) {
            return false;
        }
        const auto *sig_data = reinterpret_cast<const sgx_mldsa_44_sig_data_v4_t *>(quote->signature_data);
        attest_pub_key = sig_data->attest_pub_key;
        certification_data = sig_data->certification_data;
    } else {
        if (sig_data_len < sizeof(sgx_mldsa_65_sig_data_v4_t) + sizeof(sgx_ql_certification_data_t)) {
            return false;
        }
        const auto *sig_data = reinterpret_cast<const sgx_mldsa_65_sig_data_v4_t *>(quote->signature_data);
        attest_pub_key = sig_data->attest_pub_key;
        certification_data = sig_data->certification_data;
    }

    const auto *outer_cert = reinterpret_cast<const sgx_ql_certification_data_t *>(certification_data);
    const size_t outer_cert_total_size =
        sizeof(outer_cert->cert_key_type) + sizeof(outer_cert->size) + outer_cert->size;
    const size_t required_total = variant.sig_size + variant.pub_key_size + outer_cert_total_size;
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
    hash_input.reserve(variant.pub_key_size + qe_auth->size);
    hash_input.insert(hash_input.end(), attest_pub_key, attest_pub_key + variant.pub_key_size);
    hash_input.insert(hash_input.end(), qe_auth->auth_data, qe_auth->auth_data + qe_auth->size);

    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    if (!compute_sha256(hash_input.data(), hash_input.size(), digest)) {
        return false;
    }

    if (std::memcmp(qe_cert->qe_report.report_data.d, digest, sizeof(digest)) != 0) {
        return false;
    }

    if (variant.algorithm_id == SGX_QL_ALG_MLDSA_87) {
        return tdqe_mldsa87_verify(signature,
                                   reinterpret_cast<const uint8_t *>(&quote->header),
                                   signed_size,
                                   attest_pub_key) == 0;
    }
    if (variant.algorithm_id == SGX_QL_ALG_MLDSA_44) {
        return tdqe_mldsa44_verify(signature,
                                   reinterpret_cast<const uint8_t *>(&quote->header),
                                   signed_size,
                                   attest_pub_key) == 0;
    }
    return tdqe_mldsa65_verify(signature,
                               reinterpret_cast<const uint8_t *>(&quote->header),
                               signed_size,
                               attest_pub_key) == 0;
}

bool make_local_tdqe_identity_from_quote(const uint8_t *quote_buf,
                                         uint32_t quote_size,
                                         std::string& local_qe_identity)
{
    if (quote_buf == nullptr || quote_size < sizeof(sgx_quote4_t)) {
        return false;
    }

    const mldsa_variant_t variant = get_requested_variant();
    const auto *quote = reinterpret_cast<const sgx_quote4_t *>(quote_buf);
    if (quote->header.version != 4 || quote->header.att_key_type != variant.algorithm_id) {
        return false;
    }

    const auto *outer_cert = reinterpret_cast<const sgx_ql_certification_data_t *>(
        quote_buf + sizeof(sgx_quote4_t) + variant.sig_size + variant.pub_key_size);
    if (outer_cert->cert_key_type != kPckIdQeReportCertificationData ||
        outer_cert->size < sizeof(sgx_qe_report_certification_data_t)) {
        return false;
    }

    const auto *qe_cert = reinterpret_cast<const sgx_qe_report_certification_data_t *>(
        outer_cert->certification_data);
    local_qe_identity = make_local_tdqe_identity_json(qe_cert->qe_report);
    return true;
}

bool override_qe_identity_with_local_tdqe(const uint8_t *quote_buf,
                                          uint32_t quote_size,
                                          sgx_ql_qve_collateral_t& collateral,
                                          std::string& local_qe_identity)
{
    if (!make_local_tdqe_identity_from_quote(quote_buf, quote_size, local_qe_identity)) {
        return false;
    }

    collateral.qe_identity = const_cast<char *>(local_qe_identity.c_str());
    collateral.qe_identity_size = static_cast<uint32_t>(local_qe_identity.size() + 1);
    return true;
}

bool write_local_tdqe_identity_for_private_pcs(const uint8_t *quote_buf, uint32_t quote_size)
{
    const char *path = local_pcs_identity_file_path();
    if (path == nullptr) {
        return true;
    }

    std::string local_qe_identity;
    if (!make_local_tdqe_identity_from_quote(quote_buf, quote_size, local_qe_identity)) {
        std::printf("[test] failed to derive local TDQE identity from ML-DSA quote for private PCS.\n");
        std::fflush(stdout);
        return false;
    }

    FILE *fp = std::fopen(path, "wb");
    if (fp == nullptr) {
        std::printf("[test] failed to open private PCS TDQE identity file for writing: %s\n", path);
        std::fflush(stdout);
        return false;
    }
    const size_t written = std::fwrite(local_qe_identity.data(), 1, local_qe_identity.size(), fp);
    const int close_ret = std::fclose(fp);
    if (written != local_qe_identity.size() || close_ret != 0) {
        std::printf("[test] failed to write complete private PCS TDQE identity file: %s\n", path);
        std::fflush(stdout);
        return false;
    }

    std::printf("[test] wrote local TDQE identity for private PCS: %s\n", path);
    std::fflush(stdout);
    return true;
}

bool select_direct_mldsa_key_id(const mldsa_variant_t& variant, tdx_uuid_t *requested_mldsa_id)
{
    uint32_t supported_id_count = 0;
    tdx_attest_error_t attest_ret =
        tdx_att_get_supported_att_key_ids(nullptr, &supported_id_count);
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        std::printf("[test] tdx_att_get_supported_att_key_ids(size) failed: 0x%x\n", attest_ret);
        std::fflush(stdout);
        return false;
    }

    if (supported_id_count == 0) {
        std::printf("[test] no direct TDX attestation key ids were reported\n");
        std::fflush(stdout);
        return false;
    }

    std::vector<tdx_uuid_t> supported_ids(supported_id_count);
    attest_ret = tdx_att_get_supported_att_key_ids(supported_ids.data(), &supported_id_count);
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        std::printf("[test] tdx_att_get_supported_att_key_ids(list) failed: 0x%x\n", attest_ret);
        std::fflush(stdout);
        return false;
    }

    for (uint32_t i = 0; i < supported_id_count; ++i) {
        char label[64] = {};
        std::snprintf(label, sizeof(label), "direct supported att key id[%u]: ", i);
        print_uuid(label, supported_ids[i]);
    }

    for (uint32_t i = 0; i < supported_id_count; ++i) {
        if (is_requested_mldsa_uuid(supported_ids[i], variant)) {
            *requested_mldsa_id = supported_ids[i];
            print_uuid("direct requested att key id: ", *requested_mldsa_id);
            return true;
        }
    }

    std::printf("[test] direct TDX attestation API does not advertise the requested %s attestation key id.\n",
                variant.label);
    std::fflush(stdout);
    return false;
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
    const mldsa_variant_t variant = get_requested_variant();
    const bool use_direct_tdx_quote_path = should_use_direct_tdx_quote_path();
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
    tdx_uuid_t requested_direct_att_key_id = {};
    tdx_uuid_t selected_direct_att_key_id = {};

    for (size_t i = 0; i < sizeof(report_data.d); ++i) {
        report_data.d[i] = static_cast<uint8_t>(0x20u + i);
    }

    if (use_direct_tdx_quote_path) {
        if (!select_direct_mldsa_key_id(variant, &requested_direct_att_key_id)) {
            return 1;
        }

        attest_ret = tdx_att_get_report(&report_data, &td_report);
        if (attest_ret != TDX_ATTEST_SUCCESS) {
            return fail("tdx_att_get_report failed", attest_ret);
        }

        uint8_t *direct_quote = nullptr;
        std::printf("[test] about to generate direct ML-DSA quote for verifier probe\n");
        std::fflush(stdout);
        attest_ret = tdx_att_get_quote(&report_data,
                                       &requested_direct_att_key_id,
                                       1,
                                       &selected_direct_att_key_id,
                                       &direct_quote,
                                       &quote_size,
                                       0);
        if (attest_ret != TDX_ATTEST_SUCCESS) {
            return fail("tdx_att_get_quote failed", attest_ret);
        }

        print_uuid("direct selected att key id: ", selected_direct_att_key_id);

        quote.assign(direct_quote, direct_quote + quote_size);
        tdx_att_free_quote(direct_quote);

        if (is_all_zero_uuid(selected_direct_att_key_id)) {
            return fail("direct TDX attestation service returned an all-zero selected att key id",
                        TDX_ATTEST_ERROR_UNEXPECTED);
        }
    } else {
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
        att_key_id.base.algorithm_id = variant.algorithm_id;

        tee_ret = tee_att_create_context(&att_key_id, tdqe_path, &context);
        if (tee_ret != TEE_ATT_SUCCESS) {
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_create_context(%s) failed", variant.label);
            return fail(message, tee_ret);
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
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_init_quote(%s) failed", variant.label);
            return fail(message, tee_ret);
        }

        if (!has_any_nonzero_byte(pub_key_id.data(), pub_key_id.size())) {
            tee_att_free_context(context);
            return fail("tee_att_init_quote returned an all-zero pub_key_id", TEE_ATT_ERROR_UNEXPECTED);
        }

        tee_ret = tee_att_get_quote_size(context, &quote_size);
        if (tee_ret != TEE_ATT_SUCCESS) {
            tee_att_free_context(context);
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_get_quote_size(%s) failed", variant.label);
            return fail(message, tee_ret);
        }
        if (quote_size == 0) {
            tee_att_free_context(context);
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_get_quote_size(%s) returned zero", variant.label);
            return fail(message, TEE_ATT_ERROR_UNEXPECTED);
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
            char message[128] = {};
            std::snprintf(message, sizeof(message), "tee_att_get_quote(%s) failed", variant.label);
            return fail(message, tee_ret);
        }
    }

    quote_header = reinterpret_cast<const sgx_quote4_header_t *>(quote.data());
    std::printf("[test] generated ML-DSA quote for verifier probe: version=%u att_key_type=%u quote_size=%u\n",
                static_cast<unsigned>(quote_header->version),
                static_cast<unsigned>(quote_header->att_key_type),
                quote_size);
    std::fflush(stdout);

    if (quote_header->att_key_type != variant.algorithm_id) {
        tee_att_free_context(context);
        char message[128] = {};
        std::snprintf(message, sizeof(message), "generated quote is not %s", variant.label);
        return fail(message, quote_header->att_key_type);
    }

    if (use_direct_tdx_quote_path && !is_requested_mldsa_uuid(selected_direct_att_key_id, variant)) {
        std::printf("[test] warning: direct TDX attestation path returned a selected att key id that does not match %s.\n",
                    variant.label);
        std::printf("[test] warning: the quote header still reports the requested attestation algorithm, continuing.\n");
        std::fflush(stdout);
    }

    if (!quote_binds_report_data_v4(quote.data(), quote_size, report_data)) {
        if (context != nullptr) {
            tee_att_free_context(context);
        }
        return fail("generated quote does not bind the expected report_data", TEE_ATT_ERROR_UNEXPECTED);
    }

    if (!is_sim_mode()) {
        const auto *sig_cert = reinterpret_cast<const sgx_ql_certification_data_t *>(
            quote.data() + sizeof(sgx_quote4_t) + variant.sig_size + variant.pub_key_size);
        std::printf("[test] quote certification data: outer_type=%u outer_size=%u\n",
                    static_cast<unsigned>(sig_cert->cert_key_type),
                    static_cast<unsigned>(sig_cert->size));
        if (sig_cert->size >= sizeof(sgx_qe_report_certification_data_t) + sizeof(sgx_ql_auth_data_t)) {
            const auto *qe_cert = reinterpret_cast<const sgx_qe_report_certification_data_t *>(
                sig_cert->certification_data);
            const auto *qe_auth = reinterpret_cast<const sgx_ql_auth_data_t *>(
                qe_cert->auth_certification_data);
            const auto *inner_cert = reinterpret_cast<const sgx_ql_certification_data_t *>(
                qe_auth->auth_data + qe_auth->size);
            std::printf("[test] quote certification data: inner_type=%u inner_size=%u qe_auth_size=%u\n",
                        static_cast<unsigned>(inner_cert->cert_key_type),
                        static_cast<unsigned>(inner_cert->size),
                        static_cast<unsigned>(qe_auth->size));
            if (sig_cert->cert_key_type != kPckIdQeReportCertificationData ||
                inner_cert->cert_key_type != kPckIdPckCertChain) {
                if (context != nullptr) {
                    tee_att_free_context(context);
                }
                std::printf("[test] hardware ML-DSA quote is not carrying the standard QE report + PCK cert chain certification data required for full DCAP verification.\n");
                std::fflush(stdout);
                return 1;
            }
        }
        std::fflush(stdout);
    }

    if (!write_local_tdqe_identity_for_private_pcs(quote.data(), quote_size)) {
        if (context != nullptr) {
            tee_att_free_context(context);
        }
        return 1;
    }

    qv_ret = tdx_qv_get_quote_supplemental_data_size(&supplemental_size);
    if (qv_ret == SGX_QL_SUCCESS && supplemental_size != 0) {
        supplemental.resize(supplemental_size, 0);
    } else {
        supplemental_size = 0;
    }

    if (is_sim_mode()) {
        std::printf("[test] skipping standard DCAP collateral retrieval for %s in SGX simulation mode.\n",
                    variant.label);
        std::fflush(stdout);
        qv_ret = SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED;
    } else {
        std::printf("[test] about to call tee_qv_get_collateral\n");
        std::fflush(stdout);
        qv_ret = tee_qv_get_collateral(quote.data(), quote_size, &collateral_buf, &collateral_size);
        std::printf("[test] tee_qv_get_collateral ret=0x%x collateral_size=%u\n",
                    static_cast<unsigned>(qv_ret),
                    collateral_size);
        std::fflush(stdout);
    }
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
        if (local_only_candidate && allow_local_quote_verify_fallback()) {
            std::printf("[test] about to run local ML-DSA quote verification fallback\n");
            std::fflush(stdout);
            if (!locally_verify_mldsa_quote_v4(quote.data(), quote_size, variant)) {
                if (context != nullptr) {
                    tee_att_free_context(context);
                }
                std::printf("[test] local ML-DSA quote verification fallback failed.\n");
                std::fflush(stdout);
                return 1;
            }
            if (context != nullptr) {
                tee_ret = tee_att_free_context(context);
                if (tee_ret != TEE_ATT_SUCCESS) {
                    return fail("tee_att_free_context failed", tee_ret);
                }
            }
            std::printf("[test] local ML-DSA quote verification succeeded.\n");
            std::fflush(stdout);
            return 0;
        }
        if (context != nullptr) {
            tee_att_free_context(context);
        }
        std::printf("[test] verifier returned an unexpected collateral error for the ML-DSA quote.\n");
        std::fflush(stdout);
        return 1;
    }

    std::printf("[test] about to call tdx_qv_verify_quote\n");
    std::fflush(stdout);
    const auto *verify_collateral =
        reinterpret_cast<const tdx_ql_qv_collateral_t *>(collateral_buf);
    qv_ret = tdx_qv_verify_quote(quote.data(),
                                 quote_size,
                                 verify_collateral,
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

    sgx_ql_qve_collateral_t local_tdqe_collateral = {};
    std::string local_tdqe_identity_json;
    bool used_local_tdqe_identity_override = false;
    if (qv_ret == SGX_QL_QEIDENTITY_MISMATCH &&
        collateral_buf != nullptr) {
        if (require_stock_qe_identity()) {
            if (collateral_buf != nullptr) {
                tee_qv_free_collateral(collateral_buf);
                collateral_buf = nullptr;
            }
            if (context != nullptr) {
                tee_ret = tee_att_free_context(context);
                if (tee_ret != TEE_ATT_SUCCESS) {
                    return fail("tee_att_free_context failed", tee_ret);
                }
            }
            std::printf("[test] stock Intel QE identity verification is required, but the quote mismatched the PCCS TD_QE identity.\n");
            std::fflush(stdout);
            return 5;
        }
        if (allow_local_tdqe_identity_override()) {
            local_tdqe_collateral = *reinterpret_cast<const sgx_ql_qve_collateral_t *>(collateral_buf);
            if (override_qe_identity_with_local_tdqe(quote.data(),
                                                     quote_size,
                                                     local_tdqe_collateral,
                                                     local_tdqe_identity_json)) {
#ifndef _WIN32
                setenv("TDX_MLDSA_ALLOW_LOCAL_TDQE_IDENTITY", "1", 1);
#endif
                collateral_expiration_status = 1;
                qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;
                std::printf("[test] standard verifier reported QEIDENTITY_MISMATCH; retrying with local TDQE identity collateral.\n");
                std::fflush(stdout);
                qv_ret = tdx_qv_verify_quote(quote.data(),
                                             quote_size,
                                             reinterpret_cast<const tdx_ql_qv_collateral_t *>(&local_tdqe_collateral),
                                             std::time(nullptr),
                                             &collateral_expiration_status,
                                             &qv_result,
                                             nullptr,
                                             supplemental_size,
                                             supplemental.empty() ? nullptr : supplemental.data());
                used_local_tdqe_identity_override = true;
                std::printf("[test] tdx_qv_verify_quote(local TDQE identity) ret=0x%x qv_result=%s collateral_expiration_status=%u\n",
                            static_cast<unsigned>(qv_ret),
                            qv_result_to_string(qv_result),
                            collateral_expiration_status);
                std::fflush(stdout);
            }
        }
    }

    if (collateral_buf != nullptr) {
        tee_qv_free_collateral(collateral_buf);
    }

    if (qv_ret != SGX_QL_SUCCESS &&
        (is_verifier_format_unsupported(qv_ret) || is_verifier_runtime_or_collateral_limited(qv_ret)) &&
        allow_local_quote_verify_fallback()) {
        std::printf("[test] standard verifier could not complete for the ML-DSA quote; falling back to local quote verification.\n");
        std::fflush(stdout);
        if (!locally_verify_mldsa_quote_v4(quote.data(), quote_size, variant)) {
            if (context != nullptr) {
                tee_att_free_context(context);
            }
            std::printf("[test] local ML-DSA quote verification fallback failed.\n");
            std::fflush(stdout);
            return 1;
        }
        if (context != nullptr) {
            tee_ret = tee_att_free_context(context);
            if (tee_ret != TEE_ATT_SUCCESS) {
                return fail("tee_att_free_context failed", tee_ret);
            }
        }
        std::printf("[test] local ML-DSA quote verification succeeded.\n");
        std::fflush(stdout);
        return 0;
    }

    if (context != nullptr) {
        tee_ret = tee_att_free_context(context);
        if (tee_ret != TEE_ATT_SUCCESS) {
            return fail("tee_att_free_context failed", tee_ret);
        }
    }

    if (qv_ret == SGX_QL_SUCCESS) {
        if (used_local_tdqe_identity_override) {
            std::printf("[test] verifier mode: local_tdqe_identity_override\n");
        } else if (local_pcs_identity_file_path() != nullptr) {
            std::printf("[test] verifier mode: local_pcs_tdqe_identity\n");
        } else {
            std::printf("[test] verifier mode: stock_dcap\n");
        }
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
