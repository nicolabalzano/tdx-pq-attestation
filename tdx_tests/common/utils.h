#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

#include "tdx_attest/tdx_attest.h"

void print_report_dictionary(const tdx_report_data_t& report_data,
                             const tdx_report_t& td_report);

bool parse_hex_64(const char* hex, uint8_t out[64]);

bool parse_hex_bytes(const std::string& input, std::vector<uint8_t>* out);

bool decode_base64(const std::string& input, std::vector<uint8_t>* out);

std::string encode_base64(const uint8_t* data, size_t size);

std::string bytes_to_hex(const uint8_t* data, size_t size);

bool extract_json_string_field(const std::string& json,
                               const char* key,
                               std::string* value);

bool fetch_report_data_from_verifier(tdx_report_data_t* p_report_data,
                                     std::string* source_description);

bool verifier_submit_is_configured();

bool load_report_data_for_attestation(tdx_report_data_t* p_report_data,
                                      std::string* source_description,
                                      bool* used_demo_fallback);

bool submit_quote_to_verifier(const uint8_t* quote,
                              uint32_t quote_size,
                              const tdx_report_data_t& report_data,
                              std::string* verifier_response);
