from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
from helpers import GUEST_ROOT, assert_contains_all, extract_block, read_text


class TdxGuestFlowTests(unittest.TestCase):
    def test_tdreport_contains_report_mac_and_tdinfo(self) -> None:
        text = read_text(GUEST_ROOT / "src" / "tdcall.rs")
        block = extract_block(text, "pub struct TdReport {", r"\n}\n\npub struct PageAttr")
        assert_contains_all(
            block,
            [
                "pub report_mac: ReportMac",
                "pub tee_tcb_info: [u8; 239]",
                "pub tdinfo: TdInfo",
            ],
        )

    def test_get_report_maps_to_mr_report_tdx_leaf(self) -> None:
        text = read_text(GUEST_ROOT / "src" / "tdcall.rs")
        block = extract_block(text, "pub fn get_report(report_gpa: u64, data_gpa: u64)", r"\n}\n\n/// Extend a TDCS.RTMR measurement register\.")
        assert_contains_all(
            block,
            [
                "TdcallNum::MrReport as u64",
                "rcx: report_gpa",
                "rdx: data_gpa",
                "td_call(&mut args)",
            ],
        )

    def test_extend_rtmr_is_exposed_by_guest_crate(self) -> None:
        text = read_text(GUEST_ROOT / "src" / "tdcall.rs")
        block = extract_block(text, "pub fn extend_rtmr(extend_data_gpa: u64, reg_idx: u64)", r"\n}\n\n/// Verify a cryptographic REPORTMACSTRUCT")
        assert_contains_all(
            block,
            [
                "TdcallNum::MrRtmrExtend as u64",
                "rcx: extend_data_gpa",
                "rdx: reg_idx",
            ],
        )

    def test_get_quote_is_only_a_raw_tdvmcall(self) -> None:
        text = read_text(GUEST_ROOT / "src" / "tdvmcall.rs")
        block = extract_block(text, "pub fn get_quote(shared_gpa: u64, size: u64)", r"\n}\n\n/// The guest TD may request that the host VMM specify which interrupt vector to use as an event-notify vector\.")
        assert_contains_all(
            block,
            [
                "TdVmcallNum::GetQuote as u64",
                "r12: shared_gpa",
                "r13: size",
                "td_vmcall(&mut args)",
            ],
        )
        self.assertNotIn("Dilithium", block)
        self.assertNotIn("ECDSA", block)

    def test_service_vmcall_exists_for_richer_command_response_protocols(self) -> None:
        text = read_text(GUEST_ROOT / "src" / "tdvmcall.rs")
        block = extract_block(text, "pub fn get_td_service(", r"\n}\n\npub fn report_fatal_error_simple")
        assert_contains_all(
            block,
            [
                "TdVmcallNum::Service as u64",
                "r12: shared_gpa_input",
                "r13: shared_gpa_output",
                "r14: interrupt_vector",
                "r15: time_out",
            ],
        )

    def test_guest_repo_has_no_high_level_quote_protocol_yet(self) -> None:
        tdvmcall = read_text(GUEST_ROOT / "src" / "tdvmcall.rs")
        lib_rs = read_text(GUEST_ROOT / "src" / "lib.rs")
        self.assertNotIn("QuoteRequest", tdvmcall)
        self.assertNotIn("QuoteResponse", tdvmcall)
        self.assertNotIn("QuoteAlgorithm", tdvmcall)
        self.assertNotIn("QuoteAlgorithm", lib_rs)


if __name__ == "__main__":
    unittest.main()
