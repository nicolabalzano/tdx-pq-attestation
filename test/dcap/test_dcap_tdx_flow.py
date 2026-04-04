from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from helpers import DCAP_ROOT, assert_contains_all, extract_block, read_text


class TeeDcapTdxFlowTests(unittest.TestCase):
    def test_tdx_wrapper_advertises_ecdsa_as_default_algorithm(self) -> None:
        text = read_text(DCAP_ROOT / "QuoteGeneration" / "quote_wrapper" / "tdx_quote" / "td_ql_wrapper.cpp")
        assert_contains_all(
            text,
            [
                "g_default_ecdsa_p256_att_key_id",
                "SGX_QL_ALG_ECDSA_P256",
            ],
        )

    def test_tdx_wrapper_rejects_non_ecdsa_attestation_key_ids(self) -> None:
        text = read_text(DCAP_ROOT / "QuoteGeneration" / "quote_wrapper" / "tdx_quote" / "td_ql_wrapper.cpp")
        block = extract_block(text, "tee_att_error_t tee_att_create_context(", r"\n}\n\ntee_att_error_t tee_att_free_context")
        assert_contains_all(
            block,
            [
                "if (SGX_QL_ALG_ECDSA_P256 != p_att_key_id->base.algorithm_id)",
                "return(TEE_ATT_UNSUPPORTED_ATT_KEY_ID);",
            ],
        )

    def test_td_ql_logic_is_explicitly_ecdsa_specific(self) -> None:
        text = read_text(DCAP_ROOT / "QuoteGeneration" / "quote_wrapper" / "tdx_quote" / "td_ql_logic.cpp")
        assert_contains_all(
            text,
            [
                "tee_att_error_t tee_att_config_t::ecdsa_init_quote(",
                "tee_att_error_t tee_att_config_t::ecdsa_get_quote_size(",
                "tee_att_error_t tee_att_config_t::ecdsa_get_quote(",
                "ECDSA Blob",
            ],
        )

    def test_tdqe_builds_quote_with_ecdsa_signature_data(self) -> None:
        text = read_text(DCAP_ROOT / "ae" / "tdqe" / "quoting_enclave_tdqe.cpp")
        assert_contains_all(
            text,
            [
                "sizeof(sgx_ecdsa_sig_data_v4_t)",
                "p_quote->header.att_key_type = SGX_QL_ALG_ECDSA_P256;",
                "sgx_ecdsa_sign(",
                "sgx_ecdsa_verify(",
            ],
        )

    def test_quote_header_enum_has_no_dilithium_algorithm(self) -> None:
        text = read_text(DCAP_ROOT / "QuoteGeneration" / "quote_wrapper" / "common" / "inc" / "sgx_quote_3.h")
        assert_contains_all(
            text,
            [
                "SGX_QL_ALG_ECDSA_P256 = 2",
                "SGX_QL_ALG_ECDSA_P384 = 3",
            ],
        )
        self.assertNotIn("DILITHIUM", text)

    def test_signature_data_layout_is_ecdsa_specific(self) -> None:
        text = read_text(DCAP_ROOT / "QuoteGeneration" / "quote_wrapper" / "common" / "inc" / "sgx_quote_3.h")
        block = extract_block(text, "typedef struct _sgx_ql_ecdsa_sig_data_t {", r"\n} sgx_ql_ecdsa_sig_data_t;")
        assert_contains_all(
            block,
            [
                "sig[32*2]",
                "attest_pub_key[32*2]",
                "qe_report_sig[32*2]",
            ],
        )

    def test_verification_side_has_tdx_quote_verification_entrypoints(self) -> None:
        text = read_text(DCAP_ROOT / "QuoteVerification" / "dcap_quoteverify" / "tee_qv_class.cpp")
        assert_contains_all(
            text,
            [
                "tdx_qv::tee_get_verification_endorsement(",
                "tdx_qv_trusted::tee_get_verification_endorsement(",
            ],
        )


if __name__ == "__main__":
    unittest.main()
