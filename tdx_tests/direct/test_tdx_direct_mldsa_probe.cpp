#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

#include "tdx_attest/tdx_attest.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"

static bool is_intel_tdqe_mldsa_uuid(const tdx_uuid_t& att_key_id)
{
    static const uint8_t kIntelTdqeMldsaAttestationId[TDX_UUID_SIZE] = TDX_SGX_MLDSA_65_ATTESTATION_ID;
    return std::memcmp(att_key_id.d, kIntelTdqeMldsaAttestationId, sizeof(kIntelTdqeMldsaAttestationId)) == 0;
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

int main()
{
    uint32_t supported_id_count = 0;
    tdx_attest_error_t attest_ret = tdx_att_get_supported_att_key_ids(nullptr, &supported_id_count);
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        std::printf("[test] tdx_att_get_supported_att_key_ids(size) failed: 0x%x\n", attest_ret);
        return 1;
    }
    if (supported_id_count == 0) {
        std::printf("[test] no direct TDX attestation key ids were reported\n");
        return 1;
    }

    std::vector<tdx_uuid_t> supported_ids(supported_id_count);
    attest_ret = tdx_att_get_supported_att_key_ids(supported_ids.data(), &supported_id_count);
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        std::printf("[test] tdx_att_get_supported_att_key_ids(list) failed: 0x%x\n", attest_ret);
        return 1;
    }

    for (uint32_t i = 0; i < supported_id_count; ++i) {
        char label[64] = {0};
        std::snprintf(label, sizeof(label), "direct supported att key id[%u]: ", i);
        print_uuid(label, supported_ids[i]);
    }

    const tdx_uuid_t *requested_id_list = supported_ids.data();
    uint32_t requested_id_count = supported_id_count;
    tdx_uuid_t requested_mldsa_id = {};
    bool found_mldsa_uuid = false;

    for (uint32_t i = 0; i < supported_id_count; ++i) {
        if (is_intel_tdqe_mldsa_uuid(supported_ids[i])) {
            requested_mldsa_id = supported_ids[i];
            requested_id_list = &requested_mldsa_id;
            requested_id_count = 1;
            found_mldsa_uuid = true;
            print_uuid("direct requested att key id: ", requested_mldsa_id);
            break;
        }
    }

    if (!found_mldsa_uuid) {
        std::printf("[test] direct TDX attestation API does not advertise the ML-DSA attestation key id.\n");
        return 1;
    }

    tdx_report_data_t report_data = {};
    for (size_t i = 0; i < sizeof(report_data.d); ++i) {
        report_data.d[i] = static_cast<uint8_t>(0x40u + i);
    }

    tdx_report_t td_report = {};
    attest_ret = tdx_att_get_report(&report_data, &td_report);
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        std::printf("[test] tdx_att_get_report failed: 0x%x\n", attest_ret);
        return 1;
    }

    uint8_t *quote = nullptr;
    uint32_t quote_size = 0;
    tdx_uuid_t selected_att_key_id = {};
    attest_ret = tdx_att_get_quote(&report_data,
                                   requested_id_list,
                                   requested_id_count,
                                   &selected_att_key_id,
                                   &quote,
                                   &quote_size,
                                   0);
    if (attest_ret != TDX_ATTEST_SUCCESS) {
        std::printf("[test] tdx_att_get_quote failed: 0x%x\n", attest_ret);
        return 1;
    }

    print_uuid("direct selected att key id: ", selected_att_key_id);

    if (quote_size < sizeof(sgx_quote4_header_t)) {
        std::printf("[test] direct quote size is too small: %u\n", quote_size);
        tdx_att_free_quote(quote);
        return 1;
    }

    const sgx_quote4_header_t *quote_header = reinterpret_cast<const sgx_quote4_header_t *>(quote);
    std::printf("[test] direct quote header version=%u att_key_type=%u quote_size=%u\n",
                static_cast<unsigned>(quote_header->version),
                static_cast<unsigned>(quote_header->att_key_type),
                quote_size);

    if (is_all_zero_uuid(selected_att_key_id)) {
        std::printf("[test] direct TDX attestation service returned an all-zero selected att key id.\n");
        tdx_att_free_quote(quote);
        return 1;
    }

    if (!is_intel_tdqe_mldsa_uuid(selected_att_key_id)) {
        std::printf("[test] direct TDX attestation path selected a non-ML-DSA attestation key id.\n");
        tdx_att_free_quote(quote);
        return 1;
    }

    if (quote_header->att_key_type != SGX_QL_ALG_MLDSA_65) {
        std::printf("[test] direct quote header did not report ML-DSA attestation type.\n");
        tdx_att_free_quote(quote);
        return 1;
    }

    std::printf("[test] direct TDX attestation path is exposing ML-DSA quotes.\n");

    tdx_att_free_quote(quote);
    return 0;
}
