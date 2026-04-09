/*
 * Copyright(c) 2011-2026 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>

#include "tdx_attest/tdx_attest.h"
#include "utils.h"

static bool is_default_intel_tdqe_ecdsa_key_id(const tdx_uuid_t& att_key_id)
{
    static const uint8_t kIntelTdqeEcdsaAttestationId[16] = {
        0xe8, 0x6c, 0x04, 0x6e, 0x8c, 0xc4, 0x4d, 0x95,
        0x81, 0x73, 0xfc, 0x43, 0xc1, 0xfa, 0x4f, 0x3f
    };
    return std::memcmp(att_key_id.d, kIntelTdqeEcdsaAttestationId, sizeof(kIntelTdqeEcdsaAttestationId)) == 0;
}

static void print_attestation_key_id(const tdx_uuid_t& att_key_id)
{
    std::printf("[test] --------------- selected attestation key id: ");
    for (size_t i = 0; i < sizeof(att_key_id.d); ++i) {
        std::printf("%02x", att_key_id.d[i]);
    }
    std::printf("\n");

    if (is_default_intel_tdqe_ecdsa_key_id(att_key_id)) {
        std::printf("[test] selected attestation key profile: Intel TDQE / ECDSA P-256\n");
        std::printf("[test] attestation private key material is not exposed by the TDX quoting path\n");
    } else {
        std::printf("[test] selected attestation key profile: unknown/non-default\n");
    }
}

int main()
{
    // Input data that will be cryptographically bound to the TD report.
    tdx_report_data_t report_data = {{0}};

    // Raw TD report returned by the TDX guest-attest interface.
    tdx_report_t td_report = {{0}};

    // Return code from tdx_attest APIs.
    tdx_attest_error_t attest_ret = TDX_ATTEST_SUCCESS;

    // Step 1) Prepare report-data payload from verifier challenge.
    std::string report_data_source;
    bool used_demo_fallback = false;
    if (!load_report_data_for_attestation(&report_data, &report_data_source, &used_demo_fallback)) {
        std::printf("[test] failed to load report_data from verifier challenge\n");
        return 1;
    }
    std::printf("[test] using verifier challenge from %s\n", report_data_source.c_str());
    if (used_demo_fallback) {
        std::printf("[test] WARNING: no valid verifier challenge configured; using demo challenge (NOT production)\n");
    }

    // Step 2) Always fetch and print the real TD report.
    std::printf("[test] --------------- request TD REPORT...\n");
    attest_ret = tdx_att_get_report(&report_data, &td_report);
    if (TDX_ATTEST_SUCCESS != attest_ret) {
        std::printf("[test] tdx_att_get_report failed: 0x%x\n", attest_ret);
        return 1;
    }
    print_report_dictionary(report_data, td_report);

    // Step 3) Generate quote directly via tdx_attest.
    std::printf("[test] --------------- generate quote via direct tdx_att_get_quote() path...\n");
    uint8_t *p_quote = nullptr;
    uint32_t quote_size = 0;
    tdx_uuid_t selected_att_key_id = {};

    attest_ret = tdx_att_get_quote(&report_data, nullptr, 0, &selected_att_key_id,
                                   &p_quote, &quote_size, 0);
    if (TDX_ATTEST_SUCCESS != attest_ret) {
        std::printf("[test] tdx_att_get_quote failed: 0x%x\n", attest_ret);
        return 1;
    }

    std::printf("[test] quote generated successfully: %u bytes\n", quote_size);
    print_attestation_key_id(selected_att_key_id);
    std::string verifier_response;
    if (!submit_quote_to_verifier(p_quote, quote_size, report_data, &verifier_response)) {
        tdx_att_free_quote(p_quote);
        return 1;
    }

    if (!verifier_response.empty()) {
        std::printf("[test] verifier response: %s\n", verifier_response.c_str());
    } else {
        if (verifier_submit_is_configured()) {
            std::printf("[test] verifier submission returned an empty response body\n");
        } else {
            std::printf("[test] verifier submission skipped (no %s configured)\n", "TDX_VERIFIER_SUBMIT_URL");
        }
    }

    tdx_att_free_quote(p_quote);
    return 0;
}
