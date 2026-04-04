/*
 * Copyright(c) 2011-2026 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include <vector>
 
#include "tdx_attest/tdx_attest.h"
#include "tdx_quote/inc/td_ql_wrapper.h"

#define REPORT_DATA_ENV_HEX "TDX_VERIFIER_CHALLENGE_HEX"

// Helper function to print a byte array in a readable format
static void print_u8_list(const uint8_t* data, size_t size)
{
    std::printf("[");
    for (size_t i = 0; i < size; ++i) {
        std::printf("%u", (unsigned)data[i]);
        if (i + 1 != size) {
            std::printf(", ");
        }
    }
    std::printf("]");
}

static ssize_t find_subsequence(const uint8_t* haystack, size_t haystack_size,
                                const uint8_t* needle, size_t needle_size)
{
    if (!haystack || !needle || needle_size == 0 || haystack_size < needle_size) {
        return -1;
    }
    for (size_t i = 0; i <= haystack_size - needle_size; ++i) {
        if (0 == std::memcmp(haystack + i, needle, needle_size)) {
            return (ssize_t)i;
        }
    }
    return -1;
}

// function to print the report data and TD report in a structured dictionary format
static void print_report_dictionary(const tdx_report_data_t& report_data,
                                    const tdx_report_t& td_report)
{
    const uint32_t first_u32_le =
        (uint32_t)td_report.d[0] |
        ((uint32_t)td_report.d[1] << 8) |
        ((uint32_t)td_report.d[2] << 16) |
        ((uint32_t)td_report.d[3] << 24);

    const ssize_t report_data_offset =
        find_subsequence(td_report.d, sizeof(td_report.d), report_data.d, sizeof(report_data.d));

    std::printf("[test] report_dict = {\n");
    std::printf("  \"report_data_size\": %zu,\n", sizeof(report_data.d));
    std::printf("  \"report_data\": ");
    print_u8_list(report_data.d, sizeof(report_data.d));
    std::printf(",\n");
    std::printf("  \"td_report_size\": %zu,\n", sizeof(td_report.d));
    std::printf("  \"td_report_first_u32_le\": %u,\n", first_u32_le);
    std::printf("  \"td_report_first_32_bytes\": ");
    print_u8_list(td_report.d, 32);
    std::printf(",\n");
    std::printf("  \"report_data_found_in_td_report\": %s,\n", (report_data_offset >= 0) ? "true" : "false");
    std::printf("  \"report_data_offset\": %zd\n", report_data_offset);
    std::printf("}\n");
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static bool parse_hex_64(const char* hex, uint8_t out[64])
{
    if (!hex) {
        return false;
    }

    size_t nibble_count = 0;
    for (const char* p = hex; *p; ++p) {
        if (*p == ' ' || *p == ':' || *p == '-' || *p == '_') {
            continue;
        }
        if (hex_nibble(*p) < 0) {
            return false;
        }
        ++nibble_count;
    }
    if (nibble_count != 128) {
        return false;
    }

    size_t out_idx = 0;
    int hi = -1;
    for (const char* p = hex; *p; ++p) {
        if (*p == ' ' || *p == ':' || *p == '-' || *p == '_') {
            continue;
        }
        int v = hex_nibble(*p);
        if (hi < 0) {
            hi = v;
        }
        else {
            out[out_idx++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    return out_idx == 64;
}

// Fill report-data with verifier-provided challenge (production style).
// Expected env var: TDX_VERIFIER_CHALLENGE_HEX = 128 hex chars (64 bytes).
static bool fill_report_data_from_verifier_challenge(tdx_report_data_t *p_report_data)
{
    if (!p_report_data) {
        return false;
    }

    const char* challenge_hex = std::getenv(REPORT_DATA_ENV_HEX);
    if (challenge_hex && parse_hex_64(challenge_hex, p_report_data->d)) {
        std::printf("[test] using verifier challenge from %s\n", REPORT_DATA_ENV_HEX);
        return true;
    }

    // Fallback only for local demo/testing.
    const char* demo_hex =
        "00112233445566778899aabbccddeeff"
        "102132435465768798a9babcbddcedfe"
        "0123456789abcdeffedcba9876543210"
        "a1a2a3a4a5a6a7a8a9aaabacadaeaf00";

    bool ok = parse_hex_64(demo_hex, p_report_data->d);
    if (ok) {
        std::printf("[test] WARNING: %s not set/invalid; using demo challenge (NOT production)\n", REPORT_DATA_ENV_HEX);
    }
    return ok;
}

static bool sgx_enclave_device_available()
{
    return (0 == access("/dev/sgx_enclave", F_OK)) || (0 == access("/dev/isgx", F_OK));
}

int main()
{
    // Input data that will be cryptographically bound to the TD report.
    tdx_report_data_t report_data = {{0}};

    // Raw TD report returned by the TDX guest-attest interface.
    tdx_report_t td_report = {{0}};

    // Context owned by the TDX quote wrapper (lifecycle: create -> use -> free).
    tee_att_config_t *p_ctx = nullptr;

    // Return codes from the two APIs used in this test:
    // - tdx_attest (guest side report retrieval)
    // - td_ql_wrapper (quote wrapper flow)
    tee_att_error_t tee_ret = TEE_ATT_SUCCESS;
    tdx_attest_error_t attest_ret = TDX_ATTEST_SUCCESS;

    // Step 1) Prepare report-data payload from verifier challenge.
    if (!fill_report_data_from_verifier_challenge(&report_data)) {
        std::printf("[test] failed to load report_data from verifier challenge\n");
        return 1;
    }

    // Step 2) Always fetch and print the real TD report.
    std::printf("[test] request TD report...\n");
    attest_ret = tdx_att_get_report(&report_data, &td_report);
    if (TDX_ATTEST_SUCCESS != attest_ret) {
        std::printf("[test] tdx_att_get_report failed: 0x%x\n", attest_ret);
        return 1;
    }
    print_report_dictionary(report_data, td_report);

    // In TDX-only guests there may be no SGX enclave device.
    // In that case, use the real direct quote flow via tdx_attest.
    if (!sgx_enclave_device_available()) {
        std::printf("[test] SGX enclave device not present; using direct real tdx_att_get_quote() path...\n");
        uint8_t *p_quote = nullptr;
        uint32_t quote_size = 0;
        attest_ret = tdx_att_get_quote(&report_data, nullptr, 0, nullptr, &p_quote, &quote_size, 0);
        if (TDX_ATTEST_SUCCESS != attest_ret) {
            std::printf("[test] tdx_att_get_quote failed: 0x%x\n", attest_ret);
            return 1;
        }
        std::printf("[test] quote generated successfully via tdx_att_get_quote: %u bytes\n", quote_size);
        tdx_att_free_quote(p_quote);
        return 0;
    }

    // Step 3) Create quote-wrapper context with default attestation key identity.
    std::printf("[test] create TDX quote context...\n");
    tee_ret = tee_att_create_context(nullptr, nullptr, &p_ctx);
    if (TEE_ATT_SUCCESS != tee_ret || nullptr == p_ctx) {
        std::printf("[test] tee_att_create_context failed: 0x%x\n", tee_ret);
        return 1;
    }

    // Step 3.1) Point wrapper explicitly to locally built TDQE/ID enclaves.
    // We run test_app from quote_wrapper/tdx_quote/linux, so these relative paths resolve correctly.
    const char* tdqe_so_path = "../../../../ae/tdqe/linux/libsgx_tdqe.signed.so";
    const char* ide_so_path  = "../../../../ae/id_enclave/linux/libsgx_id_enclave.signed.so";

    tee_ret = tee_att_set_path(p_ctx, TEE_ATT_TDQE, tdqe_so_path);
    if (TEE_ATT_SUCCESS != tee_ret) {
        std::printf("[test] tee_att_set_path(TDQE) failed: 0x%x (%s)\n", tee_ret, tdqe_so_path);
        tee_att_free_context(p_ctx);
        return 1;
    }

    tee_ret = tee_att_set_path(p_ctx, TEE_ATT_IDE, ide_so_path);
    if (TEE_ATT_SUCCESS != tee_ret) {
        std::printf("[test] tee_att_set_path(IDE) failed: 0x%x (%s)\n", tee_ret, ide_so_path);
        tee_att_free_context(p_ctx);
        return 1;
    }

    // Step 4) Query required public-key-id buffer size.
    // Passing p_pub_key_id == nullptr is the official size-query pattern.
    size_t pub_key_id_size = 0;
    tee_ret = tee_att_init_quote(p_ctx, nullptr, false, &pub_key_id_size, nullptr);
    if (TEE_ATT_SUCCESS != tee_ret || 0 == pub_key_id_size) {
        std::printf("[test] tee_att_init_quote(size query) failed: 0x%x, size=%zu\n", tee_ret, pub_key_id_size);
        tee_att_free_context(p_ctx);
        return 1;
    }

    // Step 5) Retrieve the actual public-key-id of the selected attestation key.
    // When p_pub_key_id is not NULL, the API expects a valid QE target-info buffer.
    sgx_target_info_t qe_target_info = {};
    std::vector<uint8_t> pub_key_id(pub_key_id_size, 0);
    tee_ret = tee_att_init_quote(p_ctx, &qe_target_info, false, &pub_key_id_size, pub_key_id.data());
    if (TEE_ATT_SUCCESS != tee_ret) {
        std::printf("[test] tee_att_init_quote failed: 0x%x\n", tee_ret);
        tee_att_free_context(p_ctx);
        return 1;
    }

    // Step 6) Ask wrapper for required quote buffer size.
    uint32_t quote_size = 0;
    tee_ret = tee_att_get_quote_size(p_ctx, &quote_size);
    if (TEE_ATT_SUCCESS != tee_ret || 0 == quote_size) {
        std::printf("[test] tee_att_get_quote_size failed: 0x%x, quote_size=%u\n", tee_ret, quote_size);
        tee_att_free_context(p_ctx);
        return 1;
    }

    // Step 7) Generate quote from the TD report.
    // This is the call that triggers debug prints added around quote generation.
    std::vector<uint8_t> quote(quote_size, 0);
    std::printf("[test] generate quote (this should trigger [tdx-quote-debug] prints)...\n");
    tee_ret = tee_att_get_quote(
        p_ctx,
        reinterpret_cast<const uint8_t *>(&td_report),
        (uint32_t)sizeof(td_report),
        nullptr,
        quote.data(),
        quote_size);

    if (TEE_ATT_SUCCESS != tee_ret) {
        std::printf("[test] tee_att_get_quote failed: 0x%x\n", tee_ret);
        tee_att_free_context(p_ctx);
        return 1;
    }

    std::printf("[test] quote generated successfully: %u bytes\n", quote_size);

    // Step 8) Clean up wrapper context.
    tee_att_free_context(p_ctx);
    return 0;
}
