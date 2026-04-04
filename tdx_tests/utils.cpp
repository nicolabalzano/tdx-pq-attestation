#include "utils.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/types.h>
#include <vector>

#include <curl/curl.h>

namespace {

constexpr const char* kChallengeUrlEnv = "TDX_VERIFIER_CHALLENGE_URL";
constexpr const char* kChallengeMethodEnv = "TDX_VERIFIER_CHALLENGE_METHOD";
constexpr const char* kChallengeBodyEnv = "TDX_VERIFIER_CHALLENGE_BODY";
constexpr const char* kChallengeHexEnv = "TDX_VERIFIER_CHALLENGE_HEX";
constexpr const char* kSubmitUrlEnv = "TDX_VERIFIER_SUBMIT_URL";
constexpr const char* kSubmitMethodEnv = "TDX_VERIFIER_SUBMIT_METHOD";
constexpr const char* kAuthHeaderEnv = "TDX_VERIFIER_AUTH_HEADER";
constexpr const char* kExtraHeaderEnv = "TDX_VERIFIER_EXTRA_HEADER";
constexpr size_t kReportDataSize = 64;
constexpr const char* kDemoChallengeHex =
    "00112233445566778899aabbccddeeff"
    "102132435465768798a9babcbddcedfe"
    "0123456789abcdeffedcba9876543210"
    "a1a2a3a4a5a6a7a8a9aaabacadaeaf00";

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

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static std::string sanitize_hex(const std::string& input)
{
    std::string hex;
    hex.reserve(input.size());
    for (char c : input) {
        if (c == ' ' || c == ':' || c == '-' || c == '_') {
            continue;
        }
        hex.push_back(c);
    }
    return hex;
}

static bool parse_hex_bytes_impl(const std::string& input, std::vector<uint8_t>* out)
{
    if (!out) {
        return false;
    }

    const std::string hex = sanitize_hex(input);
    if (hex.empty() || (hex.size() % 2) != 0) {
        return false;
    }

    out->clear();
    out->reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = hex_nibble(hex[i]);
        const int lo = hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            out->clear();
            return false;
        }
        out->push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

static int base64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2;
    return -1;
}

static bool decode_base64_impl(const std::string& input, std::vector<uint8_t>* out)
{
    if (!out) {
        return false;
    }

    std::string compact;
    compact.reserve(input.size());
    for (unsigned char c : input) {
        if (!std::isspace(c)) {
            compact.push_back(static_cast<char>(c));
        }
    }

    if (compact.empty() || (compact.size() % 4) != 0) {
        return false;
    }

    out->clear();
    out->reserve((compact.size() / 4) * 3);
    for (size_t i = 0; i < compact.size(); i += 4) {
        int vals[4] = {0, 0, 0, 0};
        for (size_t j = 0; j < 4; ++j) {
            vals[j] = base64_value(static_cast<unsigned char>(compact[i + j]));
            if (vals[j] == -1) {
                out->clear();
                return false;
            }
        }

        if (vals[0] < 0 || vals[1] < 0) {
            out->clear();
            return false;
        }

        out->push_back(static_cast<uint8_t>((vals[0] << 2) | (vals[1] >> 4)));
        if (vals[2] == -2) {
            if (vals[3] != -2 || i + 4 != compact.size()) {
                out->clear();
                return false;
            }
            break;
        }

        if (vals[2] < 0) {
            out->clear();
            return false;
        }

        out->push_back(static_cast<uint8_t>(((vals[1] & 0x0f) << 4) | (vals[2] >> 2)));
        if (vals[3] == -2) {
            if (i + 4 != compact.size()) {
                out->clear();
                return false;
            }
            break;
        }

        if (vals[3] < 0) {
            out->clear();
            return false;
        }

        out->push_back(static_cast<uint8_t>(((vals[2] & 0x03) << 6) | vals[3]));
    }
    return true;
}

static std::string encode_base64_impl(const uint8_t* data, size_t size)
{
    static const char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((size + 2) / 3) * 4);

    for (size_t i = 0; i < size; i += 3) {
        const size_t remaining = size - i;
        const uint32_t chunk =
            (static_cast<uint32_t>(data[i]) << 16) |
            ((remaining > 1 ? static_cast<uint32_t>(data[i + 1]) : 0U) << 8) |
            (remaining > 2 ? static_cast<uint32_t>(data[i + 2]) : 0U);

        out.push_back(kAlphabet[(chunk >> 18) & 0x3f]);
        out.push_back(kAlphabet[(chunk >> 12) & 0x3f]);
        out.push_back(remaining > 1 ? kAlphabet[(chunk >> 6) & 0x3f] : '=');
        out.push_back(remaining > 2 ? kAlphabet[chunk & 0x3f] : '=');
    }

    return out;
}

static std::string bytes_to_hex_impl(const uint8_t* data, size_t size)
{
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(kDigits[(data[i] >> 4) & 0x0f]);
        out.push_back(kDigits[data[i] & 0x0f]);
    }
    return out;
}

static bool decode_string_to_bytes(const std::string& encoded, std::vector<uint8_t>* out)
{
    std::vector<uint8_t> bytes;
    // Accept either hex or base64 so the test can interoperate with different verifier payloads.
    if (parse_hex_bytes_impl(encoded, &bytes)) {
        *out = bytes;
        return true;
    }
    if (decode_base64_impl(encoded, &bytes)) {
        *out = bytes;
        return true;
    }
    return false;
}

static bool bytes_to_report_data(const std::vector<uint8_t>& bytes, tdx_report_data_t* p_report_data)
{
    if (!p_report_data || bytes.empty() || bytes.size() > kReportDataSize) {
        return false;
    }

    std::memset(p_report_data->d, 0, sizeof(p_report_data->d));
    std::memcpy(p_report_data->d, bytes.data(), bytes.size());
    return true;
}

static size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    if (!ptr || !userdata) {
        return 0;
    }

    std::string* output = static_cast<std::string*>(userdata);
    output->append(ptr, size * nmemb);
    return size * nmemb;
}

static bool perform_http_json_request(const char* url,
                                      const char* method,
                                      const std::string* body,
                                      long* http_code,
                                      std::string* response)
{
    if (!url || !method || !http_code || !response) {
        return false;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        return false;
    }

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    const char* auth_header = std::getenv(kAuthHeaderEnv);
    if (auth_header && auth_header[0] != '\0') {
        headers = curl_slist_append(headers, auth_header);
    }

    const char* extra_header = std::getenv(kExtraHeaderEnv);
    if (extra_header && extra_header[0] != '\0') {
        headers = curl_slist_append(headers, extra_header);
    }

    response->clear();
    *http_code = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    // The verifier may need time to fetch quote-verification collateral on a cold cache.
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 180L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    if (0 != std::strcmp(method, "GET")) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
        if (body) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body->c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body->size()));
        }
    }

    const CURLcode rc = curl_easy_perform(curl);
    bool ok = (rc == CURLE_OK);
    if (ok) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_code);
    } else {
        std::printf("[test] curl request failed: %s\n", curl_easy_strerror(rc));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return ok;
}

static bool extract_json_string_field_impl(const std::string& json,
                                           const char* key,
                                           std::string* value)
{
    if (!key || !value) {
        return false;
    }

    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return false;
    }

    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) {
        return false;
    }

    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) {
        return false;
    }

    const size_t begin = pos + 1;
    pos = begin;
    while (pos < json.size()) {
        pos = json.find('"', pos);
        if (pos == std::string::npos) {
            return false;
        }
        if (pos == begin || json[pos - 1] != '\\') {
            *value = json.substr(begin, pos - begin);
            return true;
        }
        ++pos;
    }
    return false;
}

static bool extract_json_bool_field(const std::string& json,
                                    const char* key,
                                    bool* value)
{
    if (!key || !value) {
        return false;
    }

    const std::string needle = std::string("\"") + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return false;
    }

    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) {
        return false;
    }

    ++pos;
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) {
        ++pos;
    }

    if (json.compare(pos, 4, "true") == 0) {
        *value = true;
        return true;
    }
    if (json.compare(pos, 5, "false") == 0) {
        *value = false;
        return true;
    }
    return false;
}

static std::string getenv_or_default(const char* name, const char* fallback)
{
    const char* value = std::getenv(name);
    if (value && value[0] != '\0') {
        return value;
    }
    return fallback;
}

static bool verifier_response_is_success(const std::string& response)
{
    static const char* kBoolKeys[] = {"is_valid", "valid", "verified", "ok", "success"};
    for (const char* key : kBoolKeys) {
        bool value = false;
        if (extract_json_bool_field(response, key, &value)) {
            return value;
        }
    }

    static const char* kStringKeys[] = {"status", "result", "verification_result"};
    for (const char* key : kStringKeys) {
        std::string value;
        if (extract_json_string_field_impl(response, key, &value)) {
            std::transform(value.begin(), value.end(), value.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return value == "ok" || value == "success" || value == "verified" ||
                   value == "accepted" || value == "pass" || value == "passed" ||
                   value == "valid";
        }
    }

    return false;
}

}  // namespace

bool parse_hex_bytes(const std::string& input, std::vector<uint8_t>* out)
{
    return parse_hex_bytes_impl(input, out);
}

bool decode_base64(const std::string& input, std::vector<uint8_t>* out)
{
    return decode_base64_impl(input, out);
}

std::string encode_base64(const uint8_t* data, size_t size)
{
    return encode_base64_impl(data, size);
}

std::string bytes_to_hex(const uint8_t* data, size_t size)
{
    return bytes_to_hex_impl(data, size);
}

bool extract_json_string_field(const std::string& json,
                               const char* key,
                               std::string* value)
{
    return extract_json_string_field_impl(json, key, value);
}

void print_report_dictionary(const tdx_report_data_t& report_data,
                             const tdx_report_t& td_report)
{
    const uint32_t first_u32_le =
        (uint32_t)td_report.d[0] |
        ((uint32_t)td_report.d[1] << 8) |
        ((uint32_t)td_report.d[2] << 16) |
        ((uint32_t)td_report.d[3] << 24);

    const ssize_t report_data_offset =
        find_subsequence(td_report.d, sizeof(td_report.d), report_data.d, sizeof(report_data.d));

    std::printf("{\n");
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

bool parse_hex_64(const char* hex, uint8_t out[64])
{
    if (!hex) {
        return false;
    }

    std::vector<uint8_t> bytes;
    if (!parse_hex_bytes_impl(hex, &bytes) || bytes.size() != 64) {
        return false;
    }

    std::memcpy(out, bytes.data(), 64);
    return true;
}

bool fetch_report_data_from_verifier(tdx_report_data_t* p_report_data,
                                     std::string* source_description)
{
    if (!p_report_data) {
        return false;
    }

    const char* challenge_hex = std::getenv(kChallengeHexEnv);
    // A pre-fetched challenge can be injected directly for simple runs or debugging.
    if (challenge_hex && parse_hex_64(challenge_hex, p_report_data->d)) {
        if (source_description) {
            *source_description = std::string("env:") + kChallengeHexEnv;
        }
        return true;
    }

    const char* challenge_url = std::getenv(kChallengeUrlEnv);
    if (!challenge_url || challenge_url[0] == '\0') {
        return false;
    }

    const std::string method = getenv_or_default(kChallengeMethodEnv, "GET");
    const char* body_env = std::getenv(kChallengeBodyEnv);
    const std::string body = body_env ? std::string(body_env) : std::string();

    long http_code = 0;
    std::string response;
    if (!perform_http_json_request(challenge_url,
                                   method.c_str(),
                                   body_env ? &body : nullptr,
                                   &http_code,
                                   &response)) {
        return false;
    }

    if (http_code < 200 || http_code >= 300) {
        std::printf("[test] verifier challenge endpoint returned HTTP %ld\n", http_code);
        std::printf("[test] verifier response body: %s\n", response.c_str());
        return false;
    }

    static const char* kChallengeFields[] = {
        "challenge_hex", "nonce_hex", "report_data_hex",
        "challenge", "nonce", "report_data",
        "challenge_b64", "nonce_b64", "report_data_b64"
    };

    std::string encoded;
    // Try a small set of common field names rather than hard-coding one verifier schema.
    for (const char* field : kChallengeFields) {
        if (extract_json_string_field_impl(response, field, &encoded)) {
            std::vector<uint8_t> bytes;
            if (decode_string_to_bytes(encoded, &bytes) &&
                bytes_to_report_data(bytes, p_report_data)) {
                if (source_description) {
                    *source_description = std::string("verifier:") + challenge_url + "#" + field;
                }
                return true;
            }
        }
    }

    std::printf("[test] verifier challenge response did not contain a supported challenge field\n");
    std::printf("[test] verifier response body: %s\n", response.c_str());
    return false;
}

bool verifier_submit_is_configured()
{
    const char* submit_url = std::getenv(kSubmitUrlEnv);
    return submit_url && submit_url[0] != '\0';
}

bool load_report_data_for_attestation(tdx_report_data_t* p_report_data,
                                      std::string* source_description,
                                      bool* used_demo_fallback)
{
    if (!p_report_data) {
        return false;
    }

    if (used_demo_fallback) {
        *used_demo_fallback = false;
    }

    if (fetch_report_data_from_verifier(p_report_data, source_description)) {
        return true;
    }

    // Keep a fixed fallback only for self-contained local testing when no verifier
    // challenge source is configured yet.
    if (!parse_hex_64(kDemoChallengeHex, p_report_data->d)) {
        return false;
    }

    if (source_description) {
        *source_description = "demo:fallback";
    }
    if (used_demo_fallback) {
        *used_demo_fallback = true;
    }
    return true;
}

bool submit_quote_to_verifier(const uint8_t* quote,
                              uint32_t quote_size,
                              const tdx_report_data_t& report_data,
                              std::string* verifier_response)
{
    const char* submit_url = std::getenv(kSubmitUrlEnv);
    if (!submit_url || submit_url[0] == '\0') {
        if (verifier_response) {
            verifier_response->clear();
        }
        return true;
    }

    if (!quote || quote_size == 0) {
        return false;
    }

    const std::string quote_b64 = encode_base64_impl(quote, quote_size);
    const std::string report_data_hex = bytes_to_hex_impl(report_data.d, sizeof(report_data.d));
    // Send both the quote and the report_data requested by the verifier to simplify local validation.
    const std::string body =
        std::string("{\"quote_base64\":\"") + quote_b64 +
        "\",\"quote_size\":" + std::to_string(quote_size) +
        ",\"report_data_hex\":\"" + report_data_hex + "\"}";

    const std::string method = getenv_or_default(kSubmitMethodEnv, "POST");
    long http_code = 0;
    std::string response;
    if (!perform_http_json_request(submit_url, method.c_str(), &body, &http_code, &response)) {
        return false;
    }

    if (verifier_response) {
        *verifier_response = response;
    }

    if (http_code < 200 || http_code >= 300) {
        std::printf("[test] verifier submit endpoint returned HTTP %ld\n", http_code);
        std::printf("[test] verifier response body: %s\n", response.c_str());
        return false;
    }

    if (!verifier_response_is_success(response)) {
        std::printf("[test] verifier response did not confirm attestation success\n");
        std::printf("[test] verifier response body: %s\n", response.c_str());
        return false;
    }

    return true;
}
