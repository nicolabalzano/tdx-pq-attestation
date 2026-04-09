#include <cstddef>

#include "sgx_quote_4.h"
#include "ecdsa_quote.h"

static constexpr std::size_t kExpectedTdqeDefaultEcdsaSignSize =
    sizeof(sgx_ecdsa_sig_data_v4_t) +
    sizeof(sgx_ql_auth_data_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_qe_report_certification_data_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t) +
    REF_ECDSDA_AUTHENTICATION_DATA_SIZE;

static constexpr std::size_t kExpectedTdqeDefaultMldsaSignSize =
    sizeof(sgx_mldsa_65_sig_data_v4_t) +
    sizeof(sgx_ql_auth_data_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_qe_report_certification_data_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t) +
    REF_ECDSDA_AUTHENTICATION_DATA_SIZE;

static_assert(kExpectedTdqeDefaultMldsaSignSize > kExpectedTdqeDefaultEcdsaSignSize,
              "ML-DSA TDQE sign_size should be larger than the ECDSA one");

static_assert(kExpectedTdqeDefaultMldsaSignSize ==
              kExpectedTdqeDefaultEcdsaSignSize +
              (sizeof(sgx_mldsa_65_sig_data_v4_t) - sizeof(sgx_ecdsa_sig_data_v4_t)),
              "Only the algorithm-specific signature payload should change the TDQE default sign_size");

int main()
{
    return 0;
}
