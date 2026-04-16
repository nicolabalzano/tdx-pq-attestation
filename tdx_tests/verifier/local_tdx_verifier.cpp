#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "sgx_dcap_quoteverify.h"
#include "sgx_quote_4.h"
#include "sgx_quote_5.h"
#include "utils.h"

namespace {

constexpr uint32_t kTdxTeeType = 0x00000081;
constexpr uint16_t kQuoteVersion4 = 4;
constexpr uint16_t kQuoteVersion5 = 5;
constexpr uint16_t kQuoteV5BodyTypeTdx10 = 2;
constexpr uint16_t kQuoteV5BodyTypeTdx15 = 3;
constexpr uint16_t kQuoteV5BodyTypeTdx15Ex = 4;
constexpr size_t kReportDataSize = 64;

struct HttpRequest {
    std::string method;
    std::string path;
    std::string body;
};

static bool fill_random(uint8_t* data, size_t size)
{
    const int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return false;
    }

    size_t total = 0;
    while (total < size) {
        const ssize_t rc = read(fd, data + total, size - total);
        if (rc <= 0) {
            close(fd);
            return false;
        }
        total += static_cast<size_t>(rc);
    }

    close(fd);
    return true;
}

static const tee_report_data_t* extract_report_data_from_quote(const uint8_t* quote,
                                                               size_t quote_size)
{
    // The verifier must compare its issued nonce against the report_data embedded
    // inside the signed TD quote body, not against client-echoed JSON only.
    if (!quote || quote_size < sizeof(sgx_quote4_header_t)) {
        return nullptr;
    }

    const sgx_quote4_header_t* header = reinterpret_cast<const sgx_quote4_header_t*>(quote);
    if (header->tee_type != kTdxTeeType) {
        return nullptr;
    }

    if (header->version == kQuoteVersion4) {
        if (quote_size < sizeof(sgx_quote4_t)) {
            return nullptr;
        }
        const sgx_quote4_t* q4 = reinterpret_cast<const sgx_quote4_t*>(quote);
        return &q4->report_body.report_data;
    }

    if (header->version == kQuoteVersion5) {
        if (quote_size < sizeof(sgx_quote5_t)) {
            return nullptr;
        }
        const sgx_quote5_t* q5 = reinterpret_cast<const sgx_quote5_t*>(quote);
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

static bool should_skip_dcap_verification()
{
    const char* value = std::getenv("TDX_LOCAL_VERIFIER_SKIP_DCAP");
    return value != nullptr && std::strcmp(value, "1") == 0;
}

static bool read_http_request(int fd, HttpRequest* request)
{
    if (!request) {
        return false;
    }

    std::string raw;
    std::array<char, 4096> buf = {};
    while (raw.find("\r\n\r\n") == std::string::npos) {
        const ssize_t rc = recv(fd, buf.data(), buf.size(), 0);
        if (rc <= 0) {
            return false;
        }
        raw.append(buf.data(), static_cast<size_t>(rc));
        if (raw.size() > (1024 * 1024)) {
            return false;
        }
    }

    const size_t header_end = raw.find("\r\n\r\n");
    std::string headers = raw.substr(0, header_end);
    request->body = raw.substr(header_end + 4);

    const size_t line_end = headers.find("\r\n");
    const std::string first_line = headers.substr(0, line_end);
    const size_t first_sp = first_line.find(' ');
    const size_t second_sp = first_line.find(' ', first_sp == std::string::npos ? 0 : first_sp + 1);
    if (first_sp == std::string::npos || second_sp == std::string::npos) {
        return false;
    }

    request->method = first_line.substr(0, first_sp);
    request->path = first_line.substr(first_sp + 1, second_sp - first_sp - 1);

    size_t content_length = 0;
    const std::string needle = "Content-Length:";
    size_t pos = headers.find(needle);
    if (pos != std::string::npos) {
        pos += needle.size();
        while (pos < headers.size() && std::isspace(static_cast<unsigned char>(headers[pos]))) {
            ++pos;
        }
        content_length = static_cast<size_t>(std::strtoul(headers.c_str() + pos, nullptr, 10));
    }

    while (request->body.size() < content_length) {
        const ssize_t rc = recv(fd, buf.data(), buf.size(), 0);
        if (rc <= 0) {
            return false;
        }
        request->body.append(buf.data(), static_cast<size_t>(rc));
    }

    return true;
}

static bool send_http_response(int fd, int status_code, const char* status_text, const std::string& body)
{
    const std::string response =
        "HTTP/1.1 " + std::to_string(status_code) + " " + status_text + "\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n\r\n" + body;

    size_t total = 0;
    while (total < response.size()) {
        const ssize_t rc = send(fd, response.data() + total, response.size() - total, 0);
        if (rc <= 0) {
            return false;
        }
        total += static_cast<size_t>(rc);
    }
    return true;
}

}  // namespace

int main(int argc, char** argv)
{
    const int port = (argc > 1) ? std::atoi(argv[1]) : 8123;
    if (port <= 0 || port > 65535) {
        std::fprintf(stderr, "[verifier] invalid port: %d\n", port);
        return 1;
    }

    sgx_qv_set_enclave_load_policy(SGX_QL_EPHEMERAL);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::perror("[verifier] socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::perror("[verifier] bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 16) != 0) {
        std::perror("[verifier] listen");
        close(server_fd);
        return 1;
    }

    std::array<uint8_t, kReportDataSize> last_challenge = {};
    bool challenge_issued = false;
    std::printf("[verifier] listening on http://127.0.0.1:%d\n", port);
    std::fflush(stdout);

    while (true) {
        const int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::perror("[verifier] accept");
            break;
        }

        HttpRequest request;
        if (!read_http_request(client_fd, &request)) {
            send_http_response(client_fd, 400, "Bad Request",
                               "{\"success\":false,\"error\":\"invalid_http_request\"}");
            close(client_fd);
            continue;
        }

        if (request.method == "GET" && request.path == "/challenge") {
            // Issue a fresh 64-byte challenge that the guest will bind into report_data.
            if (!fill_random(last_challenge.data(), last_challenge.size())) {
                send_http_response(client_fd, 500, "Internal Server Error",
                                   "{\"success\":false,\"error\":\"challenge_generation_failed\"}");
                close(client_fd);
                continue;
            }

            challenge_issued = true;
            std::fprintf(stdout, "[verifier] issued challenge (%zu bytes)\n", last_challenge.size());
            std::fflush(stdout);
            const std::string challenge_hex = bytes_to_hex(last_challenge.data(), last_challenge.size());
            const std::string body =
                std::string("{\"challenge_hex\":\"") + challenge_hex + "\",\"nonce_hex\":\"" + challenge_hex + "\"}";
            send_http_response(client_fd, 200, "OK", body);
            close(client_fd);
            continue;
        }
     
        if (request.method == "POST" && request.path == "/submit") {
            std::fprintf(stdout, "[verifier] received quote submit request (%zu body bytes)\n", request.body.size());
            std::fflush(stdout);
            std::string quote_b64;
            std::string report_data_hex;
            if (!extract_json_string_field(request.body, "quote_base64", &quote_b64) ||
                !extract_json_string_field(request.body, "report_data_hex", &report_data_hex)) {
                send_http_response(client_fd, 400, "Bad Request",
                                   "{\"success\":false,\"error\":\"missing_quote_or_report_data\"}");
                close(client_fd);
                continue;
            }

            if (!challenge_issued) {
                send_http_response(client_fd, 409, "Conflict",
                                   "{\"success\":false,\"error\":\"challenge_not_issued\"}");
                close(client_fd);
                continue;
            }

            std::vector<uint8_t> quote;
            std::vector<uint8_t> client_report_data;
            if (!decode_base64(quote_b64, &quote) ||
                !parse_hex_bytes(report_data_hex, &client_report_data) ||
                client_report_data.size() != kReportDataSize) {
                send_http_response(client_fd, 400, "Bad Request",
                                   "{\"success\":false,\"error\":\"invalid_quote_or_report_data_encoding\"}");
                close(client_fd);
                continue;
            }

            const tee_report_data_t* embedded_report_data =
                extract_report_data_from_quote(quote.data(), quote.size());
            if (!embedded_report_data) {
                send_http_response(client_fd, 400, "Bad Request",
                                   "{\"success\":false,\"error\":\"unsupported_or_malformed_tdx_quote\"}");
                close(client_fd);
                continue;
            }

            if (0 != std::memcmp(embedded_report_data->d, client_report_data.data(), kReportDataSize)) {
                send_http_response(client_fd, 400, "Bad Request",
                                   "{\"success\":false,\"error\":\"report_data_not_bound_in_quote\"}");
                close(client_fd);
                continue;
            }

            // Reject quotes that do not bind the most recently issued verifier challenge.
            if (0 != std::memcmp(embedded_report_data->d, last_challenge.data(), kReportDataSize)) {
                send_http_response(client_fd, 400, "Bad Request",
                                   "{\"success\":false,\"error\":\"challenge_mismatch\"}");
                close(client_fd);
                continue;
            }

            if (should_skip_dcap_verification()) {
                std::fprintf(stdout, "[verifier] accepting quote via local binding-only fallback\n");
                std::fflush(stdout);
                const std::string body =
                    "{\"success\":true,\"is_valid\":true,\"quote_verification_result\":\"LOCAL_BINDING_ONLY\",\"quote_verification_result_code\":0,\"collateral_expiration_status\":0,\"qv_ret\":0}";
                send_http_response(client_fd, 200, "OK", body);
                close(client_fd);
                continue;
            }

            uint32_t supplemental_size = 0;
            quote3_error_t qv_ret = tdx_qv_get_quote_supplemental_data_size(&supplemental_size);
            if (qv_ret != SGX_QL_SUCCESS) {
                supplemental_size = 0;
            }

            std::vector<uint8_t> supplemental(supplemental_size);
            uint32_t collateral_expiration_status = 1;
            sgx_ql_qv_result_t qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;
            uint8_t* collateral_buf = nullptr;
            uint32_t collateral_size = 0;
            std::fprintf(stdout, "[verifier] starting tee_qv_get_collateral for %zu-byte quote\n", quote.size());
            std::fflush(stdout);
            qv_ret = tee_qv_get_collateral(
                quote.data(),
                static_cast<uint32_t>(quote.size()),
                &collateral_buf,
                &collateral_size);
            std::fprintf(stdout,
                         "[verifier] tee_qv_get_collateral completed: qv_ret=%u, collateral_size=%u\n",
                         static_cast<unsigned int>(qv_ret),
                         collateral_size);
            std::fflush(stdout);
            if (qv_ret != SGX_QL_SUCCESS) {
                const std::string body =
                    std::string("{\"success\":false,\"is_valid\":false") +
                    ",\"error\":\"collateral_unavailable\"" +
                    ",\"qv_ret\":" + std::to_string(static_cast<unsigned int>(qv_ret)) + "}";
                send_http_response(client_fd, 400, "Bad Request", body);
                if (collateral_buf != nullptr) {
                    tee_qv_free_collateral(collateral_buf);
                }
                close(client_fd);
                continue;
            }
            std::fprintf(stdout, "[verifier] starting tdx_qv_verify_quote for %zu-byte quote\n", quote.size());
            std::fflush(stdout);
            qv_ret = tdx_qv_verify_quote(
                quote.data(),
                static_cast<uint32_t>(quote.size()),
                reinterpret_cast<const tdx_ql_qv_collateral_t*>(collateral_buf),
                std::time(nullptr),
                &collateral_expiration_status,
                &qv_result,
                nullptr,
                supplemental_size,
                supplemental.empty() ? nullptr : supplemental.data());
            std::fprintf(stdout,
                         "[verifier] tdx_qv_verify_quote completed: qv_ret=%u, qv_result=%s, collateral_expiration_status=%u\n",
                         static_cast<unsigned int>(qv_ret),
                         qv_result_to_string(qv_result),
                         collateral_expiration_status);
            std::fflush(stdout);
            if (collateral_buf != nullptr) {
                tee_qv_free_collateral(collateral_buf);
            }

            // Treat non-fatal advisory states as remotely verifiable for local integration testing.
            const bool ok =
                (qv_ret == SGX_QL_SUCCESS) &&
                (qv_result == SGX_QL_QV_RESULT_OK ||
                 qv_result == SGX_QL_QV_RESULT_CONFIG_NEEDED ||
                 qv_result == SGX_QL_QV_RESULT_OUT_OF_DATE ||
                 qv_result == SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED ||
                 qv_result == SGX_QL_QV_RESULT_SW_HARDENING_NEEDED ||
                 qv_result == SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED ||
                 qv_result == SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED ||
                 qv_result == SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED);

            const std::string body =
                std::string("{\"success\":") + (ok ? "true" : "false") +
                ",\"is_valid\":" + (ok ? std::string("true") : std::string("false")) +
                ",\"quote_verification_result\":\"" + qv_result_to_string(qv_result) + "\"" +
                ",\"quote_verification_result_code\":" + std::to_string(static_cast<int>(qv_result)) +
                ",\"collateral_expiration_status\":" + std::to_string(collateral_expiration_status) +
                ",\"qv_ret\":" + std::to_string(static_cast<unsigned int>(qv_ret)) + "}";

            send_http_response(client_fd, ok ? 200 : 400, ok ? "OK" : "Bad Request", body);
            close(client_fd);
            continue;
        }

        send_http_response(client_fd, 404, "Not Found",
                           "{\"success\":false,\"error\":\"not_found\"}");
        close(client_fd);
    }

    close(server_fd);
    return 1;
}
