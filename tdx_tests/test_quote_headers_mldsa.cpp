#include <cstddef>
#include <type_traits>

#include "../confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h"
#include "../confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h"
#include "../confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_5.h"
#include "../confidential-computing.tee.dcap-pq/QuoteGeneration/quote_wrapper/common/inc/ecdsa_quote.h"

static constexpr std::size_t kExpectedMldsaDefaultQuote5Size =
    sizeof(sgx_quote5_t) +
    sizeof(sgx_report2_body_v1_5_ex_t) +
    sizeof(uint32_t) +
    sizeof(sgx_mldsa_65_sig_data_v4_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_qe_report_certification_data_t) +
    sizeof(sgx_ql_auth_data_t) +
    REF_ECDSDA_AUTHENTICATION_DATA_SIZE +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t);

static constexpr std::size_t kExpectedEcdsaDefaultQuote5Size =
    sizeof(sgx_quote5_t) +
    sizeof(sgx_report2_body_v1_5_ex_t) +
    sizeof(uint32_t) +
    sizeof(sgx_ecdsa_sig_data_v4_t) +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_qe_report_certification_data_t) +
    sizeof(sgx_ql_auth_data_t) +
    REF_ECDSDA_AUTHENTICATION_DATA_SIZE +
    sizeof(sgx_ql_certification_data_t) +
    sizeof(sgx_ql_ppid_rsa3072_encrypted_cert_info_t);

static_assert(SGX_QL_ALG_MLDSA_65 != SGX_QL_ALG_ECDSA_P256, "ML-DSA and ECDSA algorithm ids must differ");
static_assert(SGX_QL_ALG_MLDSA_65 < SGX_QL_ALG_MAX, "ML-DSA id must be within the supported enum range");
static_assert(SGX_QL_MLDSA_65_SIG_SIZE > 0, "ML-DSA signature size must be defined");
static_assert(SGX_QL_MLDSA_65_PUB_KEY_SIZE > 0, "ML-DSA public-key size must be defined");
static_assert(sizeof(sgx_ql_mldsa_65_sig_data_t) > sizeof(sgx_ql_ecdsa_sig_data_t),
              "The ML-DSA v3 signature layout should be larger than the ECDSA one");
static_assert(sizeof(sgx_mldsa_65_sig_data_v4_t) > sizeof(sgx_ecdsa_sig_data_v4_t),
              "The ML-DSA v4 signature layout should be larger than the ECDSA one");
static_assert(kExpectedMldsaDefaultQuote5Size > sizeof(sgx_quote5_t),
              "The derived ML-DSA quote size must include the body and signature payload");
static_assert(kExpectedMldsaDefaultQuote5Size > kExpectedEcdsaDefaultQuote5Size,
              "The derived ML-DSA quote size must be larger than the ECDSA one");
static_assert(offsetof(sgx_quote_header_t, att_key_type) == 2, "Quote header att_key_type offset changed unexpectedly");
static_assert(offsetof(sgx_quote4_header_t, att_key_type) == 2, "Quote4 header att_key_type offset changed unexpectedly");

int main()
{
    return 0;
}
