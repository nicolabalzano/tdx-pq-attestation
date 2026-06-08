#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#include <x86intrin.h>

#include "tdx_attest/tdx_attest.h"
#include "td_ql_wrapper.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"
#include "sgx_dcap_quoteverify.h"

namespace {

constexpr uint32_t kTdxTeeType = 0x00000081;
constexpr uint16_t kQuoteVersion4 = 4;
constexpr uint16_t kQuoteVersion5 = 5;
constexpr uint16_t kQuoteV5BodyTypeTdx10 = 2;
constexpr uint16_t kQuoteV5BodyTypeTdx15 = 3;
constexpr uint16_t kQuoteV5BodyTypeTdx15Ex = 4;
constexpr uint16_t kPckIdQeReportCertificationData = 6;
constexpr uint16_t kPckIdPckCertChain = 5;

struct variant_t {
    const char* name;
    uint32_t algorithm_id;
    uint32_t sig_size;
    uint32_t pub_key_size;
    bool is_mldsa;
    std::array<uint8_t, TDX_UUID_SIZE> uuid;
};

enum class path_mode_t {
    wrapper,
    direct,
};

struct stage_metric_t {
    bool present = false;
    uint64_t nanoseconds = 0;
    uint64_t cycles = 0;
};

struct sample_t {
    int iteration = 0;
    bool warmup = false;
    bool success = false;
    std::string failure_stage;
    uint32_t tee_error = 0;
    uint32_t attest_error = 0;
    uint32_t qv_ret = 0;
    std::string qv_result = "UNSET";
    uint32_t collateral_expiration_status = 0;
    uint16_t quote_version = 0;
    uint16_t att_key_type = 0;
    uint32_t quote_size = 0;
    uint32_t collateral_size = 0;
    bool quote_binds_report_data = false;
    bool used_local_tdqe_identity_file = false;
    std::string selected_att_key_id_hex;
    stage_metric_t context_create;
    stage_metric_t init_quote_size_query;
    stage_metric_t init_quote_full;
    stage_metric_t quote_size_query;
    stage_metric_t report_generation;
    stage_metric_t quote_generation;
    stage_metric_t collateral_fetch;
    stage_metric_t verification;
    stage_metric_t end_to_end;
};

struct benchmark_config_t {
    variant_t variant;
    path_mode_t path_mode = path_mode_t::wrapper;
    int measured_iterations = 10;
    int warmup_iterations = 1;
    bool stop_after_quote_size = false;
    std::string output_path;
    std::string tdqe_path;
    std::string verifier_mode;
    std::string qcnl_conf_path;
    std::string selected_quote_transport;
    std::string local_tdqe_identity_file;
    std::string execution_context;
};

struct bootstrap_state_t {
    bool wrapper_ready = false;
    tee_att_att_key_id_t default_key_id = {};
    bool direct_ready = false;
    std::vector<tdx_uuid_t> supported_att_key_ids;
};

static variant_t get_variant()
{
    const char* value = std::getenv("TEST_BENCH_ALG");

    if (value != nullptr && std::strcmp(value, "ecdsa") == 0) {
        return {"ecdsa_p256", 2u, 0u, 0u, false, {}};
    }

    if (value != nullptr && std::strcmp(value, "44") == 0) {
        return {
            "mldsa_44",
            SGX_QL_ALG_MLDSA_44,
            SGX_QL_MLDSA_44_SIG_SIZE,
            SGX_QL_MLDSA_44_PUB_KEY_SIZE,
            true,
            {TDX_SGX_MLDSA_44_ATTESTATION_ID}
        };
    }

    if (value != nullptr && std::strcmp(value, "87") == 0) {
        return {
            "mldsa_87",
            SGX_QL_ALG_MLDSA_87,
            SGX_QL_MLDSA_87_SIG_SIZE,
            SGX_QL_MLDSA_87_PUB_KEY_SIZE,
            true,
            {TDX_SGX_MLDSA_87_ATTESTATION_ID}
        };
    }

    return {
        "mldsa_65",
        SGX_QL_ALG_MLDSA_65,
        SGX_QL_MLDSA_65_SIG_SIZE,
        SGX_QL_MLDSA_65_PUB_KEY_SIZE,
        true,
        {TDX_SGX_MLDSA_65_ATTESTATION_ID}
    };
}

static path_mode_t get_path_mode()
{
    const char* value = std::getenv("TEST_BENCH_PATH_MODE");
    if (value != nullptr && std::strcmp(value, "direct") == 0) {
        return path_mode_t::direct;
    }
    return path_mode_t::wrapper;
}

static int get_env_int(const char* name, int default_value)
{
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0') {
        return default_value;
    }
    const long parsed = std::strtol(value, nullptr, 10);
    if (parsed <= 0 || parsed > std::numeric_limits<int>::max()) {
        return default_value;
    }
    return static_cast<int>(parsed);
}

static bool get_env_bool(const char* name, bool default_value)
{
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0') {
        return default_value;
    }
    return std::strcmp(value, "1") == 0 || std::strcmp(value, "true") == 0 ||
           std::strcmp(value, "TRUE") == 0;
}

static const char* qv_result_to_string(sgx_ql_qv_result_t result)
{
    switch (result) {
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
            return "UNSPECIFIED";
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            return "SW_HARDENING_NEEDED";
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            return "CONFIG_AND_SW_HARDENING_NEEDED";
        case SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED:
            return "TD_RELAUNCH_ADVISED";
        case SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
            return "TD_RELAUNCH_ADVISED_CONFIG_NEEDED";
        default:
            return "UNKNOWN";
    }
}

static uint64_t now_ns()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

static uint64_t rdtscp_now()
{
    unsigned aux = 0;
    return __rdtscp(&aux);
}

static std::string json_escape(const std::string& input)
{
    std::ostringstream oss;
    for (const char ch : input) {
        switch (ch) {
            case '\\':
                oss << "\\\\";
                break;
            case '"':
                oss << "\\\"";
                break;
            case '\n':
                oss << "\\n";
                break;
            case '\r':
                oss << "\\r";
                break;
            case '\t':
                oss << "\\t";
                break;
            default:
                if (static_cast<unsigned char>(ch) < 0x20u) {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<unsigned>(static_cast<unsigned char>(ch))
                        << std::dec << std::setfill(' ');
                } else {
                    oss << ch;
                }
                break;
        }
    }
    return oss.str();
}

static std::string bytes_to_hex(const uint8_t* data, size_t size)
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

static void fill_report_data(const variant_t& variant, int iteration, tdx_report_data_t* report_data)
{
    std::memset(report_data, 0, sizeof(*report_data));
    const uint32_t salt = variant.algorithm_id * 29u + static_cast<uint32_t>(iteration * 7);
    for (size_t i = 0; i < sizeof(report_data->d); ++i) {
        report_data->d[i] = static_cast<uint8_t>((salt + static_cast<uint32_t>(i)) & 0xffu);
    }
}

static const tee_report_data_t* extract_report_data_from_quote(const uint8_t* quote, size_t quote_size)
{
    if (quote == nullptr || quote_size < sizeof(sgx_quote4_header_t)) {
        return nullptr;
    }

    const auto* header = reinterpret_cast<const sgx_quote4_header_t*>(quote);
    if (header->tee_type != kTdxTeeType) {
        return nullptr;
    }

    if (header->version == kQuoteVersion4) {
        if (quote_size < sizeof(sgx_quote4_t)) {
            return nullptr;
        }
        const auto* q4 = reinterpret_cast<const sgx_quote4_t*>(quote);
        return &q4->report_body.report_data;
    }

    if (header->version == kQuoteVersion5) {
        if (quote_size < sizeof(sgx_quote5_t)) {
            return nullptr;
        }
        const auto* q5 = reinterpret_cast<const sgx_quote5_t*>(quote);
        if ((sizeof(sgx_quote5_t) + q5->size) > quote_size) {
            return nullptr;
        }
        if (q5->type == kQuoteV5BodyTypeTdx10) {
            if (q5->size < sizeof(sgx_report2_body_t)) {
                return nullptr;
            }
            return &reinterpret_cast<const sgx_report2_body_t*>(q5->body)->report_data;
        }
        if (q5->type == kQuoteV5BodyTypeTdx15) {
            if (q5->size < sizeof(sgx_report2_body_v1_5_t)) {
                return nullptr;
            }
            return &reinterpret_cast<const sgx_report2_body_v1_5_t*>(q5->body)->report_data;
        }
        if (q5->type == kQuoteV5BodyTypeTdx15Ex) {
            if (q5->size < sizeof(sgx_report2_body_v1_5_ex_t)) {
                return nullptr;
            }
            return &reinterpret_cast<const sgx_report2_body_v1_5_ex_t*>(q5->body)->report_data;
        }
    }

    return nullptr;
}

static bool extract_quote_metadata(const uint8_t* quote,
                                   size_t quote_size,
                                   uint16_t* quote_version,
                                   uint16_t* att_key_type)
{
    if (quote == nullptr || quote_size < sizeof(sgx_quote4_header_t)) {
        return false;
    }

    const auto* header = reinterpret_cast<const sgx_quote4_header_t*>(quote);
    if (quote_version != nullptr) {
        *quote_version = header->version;
    }
    if (att_key_type != nullptr) {
        *att_key_type = header->att_key_type;
    }
    return true;
}

static bool quote_binds_report_data(const uint8_t* quote,
                                    size_t quote_size,
                                    const tdx_report_data_t& expected_report_data)
{
    const tee_report_data_t* embedded = extract_report_data_from_quote(quote, quote_size);
    if (embedded == nullptr) {
        return false;
    }
    return std::memcmp(embedded->d, expected_report_data.d, sizeof(expected_report_data.d)) == 0;
}

static std::string make_local_tdqe_identity_json(const sgx_report_body_t& qe_report)
{
    static const char* kIssueDate = "2026-01-01T00:00:00Z";
    static const char* kNextUpdate = "2126-01-01T00:00:00Z";
    static const char* kTcbDate = "2026-01-01T00:00:00Z";
    static const char* kZeroSignature =
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000";

    const auto miscselect_hex = bytes_to_hex(
        reinterpret_cast<const uint8_t*>(&qe_report.misc_select),
        sizeof(qe_report.misc_select));
    const auto attributes_hex = bytes_to_hex(
        reinterpret_cast<const uint8_t*>(&qe_report.attributes),
        sizeof(qe_report.attributes));
    const auto mrsigner_hex = bytes_to_hex(qe_report.mr_signer.m, sizeof(qe_report.mr_signer.m));
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

static bool make_local_tdqe_identity_from_quote(const uint8_t* quote_buf,
                                                uint32_t quote_size,
                                                const variant_t& variant,
                                                std::string* local_identity_json)
{
    if (!variant.is_mldsa || quote_buf == nullptr || local_identity_json == nullptr ||
        quote_size < sizeof(sgx_quote4_t)) {
        return false;
    }

    const auto* quote = reinterpret_cast<const sgx_quote4_t*>(quote_buf);
    if (quote->header.version != 4 || quote->header.att_key_type != variant.algorithm_id) {
        return false;
    }

    const auto* outer_cert = reinterpret_cast<const sgx_ql_certification_data_t*>(
        quote_buf + sizeof(sgx_quote4_t) + variant.sig_size + variant.pub_key_size);
    if (outer_cert->cert_key_type != kPckIdQeReportCertificationData ||
        outer_cert->size < sizeof(sgx_qe_report_certification_data_t)) {
        return false;
    }

    const auto* qe_cert = reinterpret_cast<const sgx_qe_report_certification_data_t*>(
        outer_cert->certification_data);
    *local_identity_json = make_local_tdqe_identity_json(qe_cert->qe_report);
    return true;
}

static bool write_local_tdqe_identity_file(const benchmark_config_t& config,
                                           const uint8_t* quote_buf,
                                           uint32_t quote_size)
{
    if (config.local_tdqe_identity_file.empty()) {
        return true;
    }

    std::string local_identity_json;
    if (!make_local_tdqe_identity_from_quote(quote_buf, quote_size, config.variant, &local_identity_json)) {
        return false;
    }

    std::ofstream out(config.local_tdqe_identity_file, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }
    out.write(local_identity_json.data(), static_cast<std::streamsize>(local_identity_json.size()));
    return out.good();
}

static tee_att_att_key_id_t build_requested_key_id(const variant_t& variant,
                                                   const tee_att_att_key_id_t& default_key_id)
{
    tee_att_att_key_id_t requested = default_key_id;
    requested.base.algorithm_id = variant.algorithm_id;
    return requested;
}

static bool prepare_wrapper_bootstrap(const benchmark_config_t& config, bootstrap_state_t* bootstrap, std::string* error)
{
    tee_att_config_t* default_context = nullptr;
    tee_att_error_t tee_ret = tee_att_create_context(nullptr,
                                                     config.tdqe_path.empty() ? nullptr : config.tdqe_path.c_str(),
                                                     &default_context);
    if (tee_ret != TEE_ATT_SUCCESS || default_context == nullptr) {
        if (error != nullptr) {
            *error = "tee_att_create_context(default) failed: 0x" + bytes_to_hex(
                reinterpret_cast<const uint8_t*>(&tee_ret), sizeof(tee_ret));
        }
        return false;
    }

    tee_ret = tee_att_get_keyid(default_context, &bootstrap->default_key_id);
    tee_att_free_context(default_context);
    if (tee_ret != TEE_ATT_SUCCESS) {
        if (error != nullptr) {
            *error = "tee_att_get_keyid(default) failed: 0x" + bytes_to_hex(
                reinterpret_cast<const uint8_t*>(&tee_ret), sizeof(tee_ret));
        }
        return false;
    }

    bootstrap->wrapper_ready = true;
    return true;
}

static bool prepare_direct_bootstrap(const benchmark_config_t&, bootstrap_state_t* bootstrap, std::string* error)
{
    uint32_t supported_id_count = 0;
    tdx_attest_error_t attest_ret = tdx_att_get_supported_att_key_ids(nullptr, &supported_id_count);
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        if (error != nullptr) {
            *error = "tdx_att_get_supported_att_key_ids(size) failed";
        }
        return false;
    }
    bootstrap->supported_att_key_ids.resize(supported_id_count);
    if (supported_id_count != 0) {
        attest_ret = tdx_att_get_supported_att_key_ids(bootstrap->supported_att_key_ids.data(), &supported_id_count);
        if (attest_ret != TDX_ATTEST_SUCCESS) {
            if (error != nullptr) {
                *error = "tdx_att_get_supported_att_key_ids(list) failed";
            }
            return false;
        }
    }
    bootstrap->direct_ready = true;
    return true;
}

static bool measure_wrapper_iteration(const benchmark_config_t& config,
                                      const bootstrap_state_t& bootstrap,
                                      int iteration,
                                      bool warmup,
                                      sample_t* sample)
{
    sample->iteration = iteration;
    sample->warmup = warmup;
    sample->success = false;
    sample->qv_result = "UNSET";

    tdx_report_data_t report_data = {};
    fill_report_data(config.variant, iteration, &report_data);

    tee_att_config_t* context = nullptr;
    tee_att_error_t tee_ret = TEE_ATT_SUCCESS;
    tdx_attest_error_t attest_ret = TDX_ATTEST_SUCCESS;
    uint32_t quote_size = 0;
    size_t pub_key_id_size = 0;
    std::vector<uint8_t> pub_key_id;
    tdx_report_t td_report = {};
    std::vector<uint8_t> quote;
    sgx_target_info_t qe_target_info = {};
    uint8_t* collateral_buf = nullptr;
    uint32_t collateral_size = 0;
    uint32_t supplemental_size = 0;
    std::vector<uint8_t> supplemental;
    sgx_ql_qv_result_t qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    quote3_error_t qv_ret = SGX_QL_SUCCESS;
    uint32_t collateral_expiration_status = 1;

    const tee_att_att_key_id_t requested_key_id = build_requested_key_id(config.variant, bootstrap.default_key_id);

    const uint64_t end_to_end_ns_start = now_ns();
    const uint64_t end_to_end_cycles_start = rdtscp_now();

    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        tee_ret = tee_att_create_context(&requested_key_id,
                                         config.tdqe_path.empty() ? nullptr : config.tdqe_path.c_str(),
                                         &context);
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->context_create = {true, t1 - t0, c1 - c0};
    }
    if (tee_ret != TEE_ATT_SUCCESS || context == nullptr) {
        sample->tee_error = tee_ret;
        sample->failure_stage = "context_create";
        return false;
    }

    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        tee_ret = tee_att_init_quote(context, nullptr, false, &pub_key_id_size, nullptr);
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->init_quote_size_query = {true, t1 - t0, c1 - c0};
    }
    if (tee_ret != TEE_ATT_SUCCESS || pub_key_id_size == 0) {
        sample->tee_error = tee_ret;
        sample->failure_stage = "init_quote_size_query";
        tee_att_free_context(context);
        return false;
    }

    pub_key_id.resize(pub_key_id_size, 0);
    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        tee_ret = tee_att_init_quote(context,
                                     &qe_target_info,
                                     false,
                                     &pub_key_id_size,
                                     pub_key_id.data());
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->init_quote_full = {true, t1 - t0, c1 - c0};
    }
    if (tee_ret != TEE_ATT_SUCCESS) {
        sample->tee_error = tee_ret;
        sample->failure_stage = "init_quote_full";
        tee_att_free_context(context);
        return false;
    }

    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        tee_ret = tee_att_get_quote_size(context, &quote_size);
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->quote_size_query = {true, t1 - t0, c1 - c0};
    }
    if (tee_ret != TEE_ATT_SUCCESS || quote_size == 0) {
        sample->tee_error = tee_ret;
        sample->failure_stage = "quote_size_query";
        tee_att_free_context(context);
        return false;
    }
    sample->quote_size = quote_size;

    if (config.stop_after_quote_size) {
        sample->att_key_type = static_cast<uint16_t>(config.variant.algorithm_id);
        const uint64_t end_to_end_cycles_end = rdtscp_now();
        const uint64_t end_to_end_ns_end = now_ns();
        sample->end_to_end = {true,
                              end_to_end_ns_end - end_to_end_ns_start,
                              end_to_end_cycles_end - end_to_end_cycles_start};
        tee_att_free_context(context);
        sample->success = true;
        return true;
    }

    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        attest_ret = tdx_att_get_report(&report_data, &td_report);
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->report_generation = {true, t1 - t0, c1 - c0};
    }
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        sample->attest_error = attest_ret;
        sample->failure_stage = "report_generation";
        tee_att_free_context(context);
        return false;
    }

    quote.resize(quote_size, 0);
    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        tee_ret = tee_att_get_quote(context,
                                    td_report.d,
                                    static_cast<uint32_t>(sizeof(td_report.d)),
                                    nullptr,
                                    quote.data(),
                                    quote_size);
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->quote_generation = {true, t1 - t0, c1 - c0};
    }
    tee_att_free_context(context);
    if (tee_ret != TEE_ATT_SUCCESS) {
        sample->tee_error = tee_ret;
        sample->failure_stage = "quote_generation";
        return false;
    }

    if (!extract_quote_metadata(quote.data(), quote.size(), &sample->quote_version, &sample->att_key_type)) {
        sample->failure_stage = "quote_parse";
        return false;
    }

    sample->quote_binds_report_data = quote_binds_report_data(quote.data(), quote.size(), report_data);
    if (!sample->quote_binds_report_data) {
        sample->failure_stage = "quote_binding";
        return false;
    }

    if (config.variant.is_mldsa && !config.local_tdqe_identity_file.empty()) {
        if (!write_local_tdqe_identity_file(config, quote.data(), static_cast<uint32_t>(quote.size()))) {
            sample->failure_stage = "local_tdqe_identity_write";
            return false;
        }
        sample->used_local_tdqe_identity_file = true;
    }

    qv_ret = tdx_qv_get_quote_supplemental_data_size(&supplemental_size);
    if (qv_ret == SGX_QL_SUCCESS && supplemental_size != 0) {
        supplemental.resize(supplemental_size, 0);
    } else {
        supplemental_size = 0;
    }

    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        qv_ret = tee_qv_get_collateral(quote.data(),
                                       static_cast<uint32_t>(quote.size()),
                                       &collateral_buf,
                                       &collateral_size);
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->collateral_fetch = {true, t1 - t0, c1 - c0};
    }
    sample->qv_ret = qv_ret;
    sample->collateral_size = collateral_size;
    if (qv_ret != SGX_QL_SUCCESS) {
        sample->failure_stage = "collateral_fetch";
        if (collateral_buf != nullptr) {
            tee_qv_free_collateral(collateral_buf);
        }
        return false;
    }

    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        qv_ret = tdx_qv_verify_quote(quote.data(),
                                     static_cast<uint32_t>(quote.size()),
                                     reinterpret_cast<const tdx_ql_qv_collateral_t*>(collateral_buf),
                                     std::time(nullptr),
                                     &collateral_expiration_status,
                                     &qv_result,
                                     nullptr,
                                     supplemental_size,
                                     supplemental.empty() ? nullptr : supplemental.data());
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->verification = {true, t1 - t0, c1 - c0};
    }
    sample->qv_ret = qv_ret;
    sample->qv_result = qv_result_to_string(qv_result);
    sample->collateral_expiration_status = collateral_expiration_status;
    if (collateral_buf != nullptr) {
        tee_qv_free_collateral(collateral_buf);
    }
    if (qv_ret != SGX_QL_SUCCESS || qv_result != SGX_QL_QV_RESULT_OK) {
        sample->failure_stage = "verification";
        return false;
    }

    const uint64_t end_to_end_cycles_end = rdtscp_now();
    const uint64_t end_to_end_ns_end = now_ns();
    sample->end_to_end = {true,
                          end_to_end_ns_end - end_to_end_ns_start,
                          end_to_end_cycles_end - end_to_end_cycles_start};
    sample->success = true;
    return true;
}

static bool find_requested_direct_att_key_id(const benchmark_config_t& config,
                                             const bootstrap_state_t& bootstrap,
                                             tdx_uuid_t* requested_att_key_id)
{
    if (!config.variant.is_mldsa) {
        std::memset(requested_att_key_id, 0, sizeof(*requested_att_key_id));
        return true;
    }

    for (const auto& supported_id : bootstrap.supported_att_key_ids) {
        if (std::memcmp(supported_id.d, config.variant.uuid.data(), TDX_UUID_SIZE) == 0) {
            *requested_att_key_id = supported_id;
            return true;
        }
    }
    return false;
}

static bool measure_direct_iteration(const benchmark_config_t& config,
                                     const bootstrap_state_t& bootstrap,
                                     int iteration,
                                     bool warmup,
                                     sample_t* sample)
{
    sample->iteration = iteration;
    sample->warmup = warmup;
    sample->success = false;
    sample->qv_result = "UNSET";

    tdx_report_data_t report_data = {};
    fill_report_data(config.variant, iteration, &report_data);

    tdx_uuid_t requested_att_key_id = {};
    if (!find_requested_direct_att_key_id(config, bootstrap, &requested_att_key_id)) {
        sample->failure_stage = "direct_att_key_resolution";
        return false;
    }

    tdx_report_t td_report = {};
    tdx_attest_error_t attest_ret = TDX_ATTEST_SUCCESS;
    uint8_t* quote_buf = nullptr;
    uint32_t quote_size = 0;
    tdx_uuid_t selected_att_key_id = {};
    uint8_t* collateral_buf = nullptr;
    uint32_t collateral_size = 0;
    uint32_t supplemental_size = 0;
    std::vector<uint8_t> supplemental;
    sgx_ql_qv_result_t qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    quote3_error_t qv_ret = SGX_QL_SUCCESS;
    uint32_t collateral_expiration_status = 1;

    const uint64_t end_to_end_ns_start = now_ns();
    const uint64_t end_to_end_cycles_start = rdtscp_now();

    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        attest_ret = tdx_att_get_report(&report_data, &td_report);
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->report_generation = {true, t1 - t0, c1 - c0};
    }
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        sample->attest_error = attest_ret;
        sample->failure_stage = "report_generation";
        return false;
    }

    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        attest_ret = tdx_att_get_quote(&report_data,
                                       config.variant.is_mldsa ? &requested_att_key_id : nullptr,
                                       config.variant.is_mldsa ? 1u : 0u,
                                       &selected_att_key_id,
                                       &quote_buf,
                                       &quote_size,
                                       0);
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->quote_generation = {true, t1 - t0, c1 - c0};
    }
    if (attest_ret != TDX_ATTEST_SUCCESS || quote_buf == nullptr || quote_size == 0) {
        sample->attest_error = attest_ret;
        sample->failure_stage = "quote_generation";
        return false;
    }

    sample->selected_att_key_id_hex = bytes_to_hex(selected_att_key_id.d, sizeof(selected_att_key_id.d));
    sample->quote_size = quote_size;
    if (!extract_quote_metadata(quote_buf, quote_size, &sample->quote_version, &sample->att_key_type)) {
        tdx_att_free_quote(quote_buf);
        sample->failure_stage = "quote_parse";
        return false;
    }

    sample->quote_binds_report_data = quote_binds_report_data(quote_buf, quote_size, report_data);
    if (!sample->quote_binds_report_data) {
        tdx_att_free_quote(quote_buf);
        sample->failure_stage = "quote_binding";
        return false;
    }

    if (config.variant.is_mldsa && !config.local_tdqe_identity_file.empty()) {
        if (!write_local_tdqe_identity_file(config, quote_buf, quote_size)) {
            tdx_att_free_quote(quote_buf);
            sample->failure_stage = "local_tdqe_identity_write";
            return false;
        }
        sample->used_local_tdqe_identity_file = true;
    }

    qv_ret = tdx_qv_get_quote_supplemental_data_size(&supplemental_size);
    if (qv_ret == SGX_QL_SUCCESS && supplemental_size != 0) {
        supplemental.resize(supplemental_size, 0);
    } else {
        supplemental_size = 0;
    }

    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        qv_ret = tee_qv_get_collateral(quote_buf, quote_size, &collateral_buf, &collateral_size);
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->collateral_fetch = {true, t1 - t0, c1 - c0};
    }
    sample->qv_ret = qv_ret;
    sample->collateral_size = collateral_size;
    if (qv_ret != SGX_QL_SUCCESS) {
        tdx_att_free_quote(quote_buf);
        if (collateral_buf != nullptr) {
            tee_qv_free_collateral(collateral_buf);
        }
        sample->failure_stage = "collateral_fetch";
        return false;
    }

    {
        const uint64_t t0 = now_ns();
        const uint64_t c0 = rdtscp_now();
        qv_ret = tdx_qv_verify_quote(quote_buf,
                                     quote_size,
                                     reinterpret_cast<const tdx_ql_qv_collateral_t*>(collateral_buf),
                                     std::time(nullptr),
                                     &collateral_expiration_status,
                                     &qv_result,
                                     nullptr,
                                     supplemental_size,
                                     supplemental.empty() ? nullptr : supplemental.data());
        const uint64_t c1 = rdtscp_now();
        const uint64_t t1 = now_ns();
        sample->verification = {true, t1 - t0, c1 - c0};
    }
    sample->qv_ret = qv_ret;
    sample->qv_result = qv_result_to_string(qv_result);
    sample->collateral_expiration_status = collateral_expiration_status;
    if (collateral_buf != nullptr) {
        tee_qv_free_collateral(collateral_buf);
    }
    tdx_att_free_quote(quote_buf);
    if (qv_ret != SGX_QL_SUCCESS || qv_result != SGX_QL_QV_RESULT_OK) {
        sample->failure_stage = "verification";
        return false;
    }

    const uint64_t end_to_end_cycles_end = rdtscp_now();
    const uint64_t end_to_end_ns_end = now_ns();
    sample->end_to_end = {true,
                          end_to_end_ns_end - end_to_end_ns_start,
                          end_to_end_cycles_end - end_to_end_cycles_start};
    sample->success = true;
    return true;
}

static std::string stage_metric_json(const stage_metric_t& metric)
{
    std::ostringstream oss;
    oss << "{"
        << "\"present\":" << (metric.present ? "true" : "false") << ","
        << "\"nanoseconds\":" << metric.nanoseconds << ","
        << "\"cycles\":" << metric.cycles
        << "}";
    return oss.str();
}

static std::string sample_json(const sample_t& sample)
{
    std::ostringstream oss;
    oss << "{"
        << "\"iteration\":" << sample.iteration << ","
        << "\"warmup\":" << (sample.warmup ? "true" : "false") << ","
        << "\"success\":" << (sample.success ? "true" : "false") << ","
        << "\"failure_stage\":\"" << json_escape(sample.failure_stage) << "\","
        << "\"tee_error\":" << sample.tee_error << ","
        << "\"attest_error\":" << sample.attest_error << ","
        << "\"qv_ret\":" << sample.qv_ret << ","
        << "\"qv_result\":\"" << json_escape(sample.qv_result) << "\","
        << "\"collateral_expiration_status\":" << sample.collateral_expiration_status << ","
        << "\"quote_version\":" << sample.quote_version << ","
        << "\"att_key_type\":" << sample.att_key_type << ","
        << "\"quote_size\":" << sample.quote_size << ","
        << "\"collateral_size\":" << sample.collateral_size << ","
        << "\"quote_binds_report_data\":" << (sample.quote_binds_report_data ? "true" : "false") << ","
        << "\"used_local_tdqe_identity_file\":" << (sample.used_local_tdqe_identity_file ? "true" : "false") << ","
        << "\"selected_att_key_id_hex\":\"" << json_escape(sample.selected_att_key_id_hex) << "\","
        << "\"stages\":{"
        << "\"context_create\":" << stage_metric_json(sample.context_create) << ","
        << "\"init_quote_size_query\":" << stage_metric_json(sample.init_quote_size_query) << ","
        << "\"init_quote_full\":" << stage_metric_json(sample.init_quote_full) << ","
        << "\"quote_size_query\":" << stage_metric_json(sample.quote_size_query) << ","
        << "\"report_generation\":" << stage_metric_json(sample.report_generation) << ","
        << "\"quote_generation\":" << stage_metric_json(sample.quote_generation) << ","
        << "\"collateral_fetch\":" << stage_metric_json(sample.collateral_fetch) << ","
        << "\"verification\":" << stage_metric_json(sample.verification) << ","
        << "\"end_to_end\":" << stage_metric_json(sample.end_to_end)
        << "}"
        << "}";
    return oss.str();
}

static std::string current_time_utc()
{
    std::time_t now = std::time(nullptr);
    std::tm tm = {};
    gmtime_r(&now, &tm);
    char buffer[64] = {};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buffer;
}

static bool write_result_json(const benchmark_config_t& config,
                              const std::string& setup_error,
                              const std::vector<sample_t>& samples)
{
    std::ofstream out(config.output_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    out << "{\n";
    out << "  \"generated_at_utc\": \"" << json_escape(current_time_utc()) << "\",\n";
    out << "  \"scenario\": {\n";
    out << "    \"algorithm\": \"" << json_escape(config.variant.name) << "\",\n";
    out << "    \"att_key_type_expected\": " << config.variant.algorithm_id << ",\n";
    out << "    \"path_mode\": \"" << (config.path_mode == path_mode_t::wrapper ? "wrapper" : "direct") << "\",\n";
    out << "    \"execution_context\": \"" << json_escape(config.execution_context) << "\",\n";
    out << "    \"verifier_mode\": \"" << json_escape(config.verifier_mode) << "\",\n";
    out << "    \"measured_iterations\": " << config.measured_iterations << ",\n";
    out << "    \"warmup_iterations\": " << config.warmup_iterations << ",\n";
    out << "    \"stop_after_quote_size\": " << (config.stop_after_quote_size ? "true" : "false") << ",\n";
    out << "    \"qcnl_conf_path\": \"" << json_escape(config.qcnl_conf_path) << "\",\n";
    out << "    \"quote_transport\": \"" << json_escape(config.selected_quote_transport) << "\",\n";
    out << "    \"tdqe_path\": \"" << json_escape(config.tdqe_path) << "\",\n";
    out << "    \"local_tdqe_identity_file\": \"" << json_escape(config.local_tdqe_identity_file) << "\"\n";
    out << "  },\n";
    out << "  \"setup_error\": \"" << json_escape(setup_error) << "\",\n";
    out << "  \"samples\": [\n";
    for (size_t i = 0; i < samples.size(); ++i) {
        out << "    " << sample_json(samples[i]);
        if (i + 1 != samples.size()) {
            out << ",";
        }
        out << "\n";
    }
    out << "  ]\n";
    out << "}\n";
    return out.good();
}

}  // namespace

int main()
{
    benchmark_config_t config;
    config.variant = get_variant();
    config.path_mode = get_path_mode();
    config.measured_iterations = get_env_int("TEST_BENCH_ITERATIONS", 10);
    config.warmup_iterations = get_env_int("TEST_BENCH_WARMUP", 1);
    config.stop_after_quote_size = get_env_bool("TEST_BENCH_STOP_AFTER_QUOTE_SIZE", false);

    const char* output_path = std::getenv("TEST_BENCH_OUTPUT_JSON");
    if (output_path == nullptr || output_path[0] == '\0') {
        std::fprintf(stderr, "TEST_BENCH_OUTPUT_JSON is required\n");
        return 2;
    }
    config.output_path = output_path;

    const char* tdqe_path = std::getenv("TEST_TDQE_PATH");
    if (tdqe_path != nullptr) {
        config.tdqe_path = tdqe_path;
    }
    const char* verifier_mode = std::getenv("TEST_BENCH_VERIFIER_MODE");
    if (verifier_mode != nullptr) {
        config.verifier_mode = verifier_mode;
    }
    const char* qcnl_conf_path = std::getenv("QCNL_CONF_PATH");
    if (qcnl_conf_path != nullptr) {
        config.qcnl_conf_path = qcnl_conf_path;
    }
    const char* transport = std::getenv("TEST_BENCH_QUOTE_TRANSPORT");
    if (transport != nullptr) {
        config.selected_quote_transport = transport;
    }
    const char* execution_context = std::getenv("TEST_BENCH_EXECUTION_CONTEXT");
    if (execution_context != nullptr) {
        config.execution_context = execution_context;
    }
    const char* identity_file = std::getenv("TEST_LOCAL_TDQE_IDENTITY_FILE");
    if (identity_file != nullptr) {
        config.local_tdqe_identity_file = identity_file;
    }

    std::string setup_error;
    bootstrap_state_t bootstrap;
    if (config.path_mode == path_mode_t::wrapper) {
        prepare_wrapper_bootstrap(config, &bootstrap, &setup_error);
    } else {
        prepare_direct_bootstrap(config, &bootstrap, &setup_error);
    }

    std::vector<sample_t> samples;
    const int total_iterations = config.warmup_iterations + config.measured_iterations;
    samples.reserve(static_cast<size_t>(total_iterations));

    if (setup_error.empty()) {
        for (int i = 0; i < total_iterations; ++i) {
            sample_t sample;
            const bool warmup = i < config.warmup_iterations;
            if (config.path_mode == path_mode_t::wrapper) {
                measure_wrapper_iteration(config, bootstrap, i, warmup, &sample);
            } else {
                measure_direct_iteration(config, bootstrap, i, warmup, &sample);
            }
            samples.push_back(sample);
        }
    }

    if (!write_result_json(config, setup_error, samples)) {
        std::fprintf(stderr, "failed to write benchmark JSON: %s\n", config.output_path.c_str());
        return 3;
    }

    const size_t success_count = std::count_if(samples.begin(), samples.end(), [](const sample_t& sample) {
        return sample.success && !sample.warmup;
    });

    std::printf("[bench] wrote %s (%zu/%d measured iterations succeeded)\n",
                config.output_path.c_str(),
                success_count,
                config.measured_iterations);
    if (!setup_error.empty()) {
        std::printf("[bench] setup error: %s\n", setup_error.c_str());
    }
    return 0;
}
