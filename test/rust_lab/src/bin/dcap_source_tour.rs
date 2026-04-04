use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("failed to locate repository root")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn print_matches(path: &Path, needles: &[&str]) {
    let text = read(path);
    println!("FILE: {}", path.display());
    for needle in needles {
        println!("  pattern: {needle}");
        let mut found = false;
        for (idx, line) in text.lines().enumerate() {
            if line.contains(needle) {
                println!("    L{}: {}", idx + 1, line.trim());
                found = true;
            }
        }
        if !found {
            println!("    not found");
        }
    }
    println!();
}

fn main() {
    let root = repo_root();
    let dcap = root.join("confidential-computing.tee.dcap");

    println!("== tee.dcap TDX quote flow tour ==");
    println!();
    println!("Flusso da seguire:");
    println!("  1. tdx-guest produce TDREPORT");
    println!("  2. QuoteGeneration/tdx_quote riceve il report");
    println!("  3. ae/tdqe costruisce e firma il quote");
    println!("  4. QuoteVerification verifica il quote");
    println!();

    let wrapper = dcap.join("QuoteGeneration/quote_wrapper/tdx_quote/td_ql_wrapper.cpp");
    let logic = dcap.join("QuoteGeneration/quote_wrapper/tdx_quote/td_ql_logic.cpp");
    let tdqe = dcap.join("ae/tdqe/quoting_enclave_tdqe.cpp");
    let quote_h = dcap.join("QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h");
    let verify = dcap.join("QuoteVerification/dcap_quoteverify/tee_qv_class.cpp");

    print_matches(
        &wrapper,
        &[
            "g_default_ecdsa_p256_att_key_id",
            "SGX_QL_ALG_ECDSA_P256",
            "tee_att_create_context",
        ],
    );

    print_matches(
        &logic,
        &[
            "tee_att_config_t::ecdsa_init_quote(",
            "tee_att_config_t::ecdsa_get_quote_size(",
            "tee_att_config_t::ecdsa_get_quote(",
        ],
    );

    print_matches(
        &tdqe,
        &[
            "p_quote->header.att_key_type = SGX_QL_ALG_ECDSA_P256;",
            "sgx_ecdsa_sign(",
            "sgx_ecdsa_verify(",
            "sizeof(sgx_ecdsa_sig_data_v4_t)",
        ],
    );

    print_matches(
        &quote_h,
        &[
            "SGX_QL_ALG_ECDSA_P256 = 2",
            "typedef struct _sgx_ql_ecdsa_sig_data_t {",
            "uint16_t            att_key_type;",
        ],
    );

    print_matches(
        &verify,
        &[
            "tdx_qv::tee_get_verification_endorsement(",
            "tdx_qv_trusted::tee_get_verification_endorsement(",
        ],
    );

    println!("Conclusione:");
    println!("  - tdx-guest espone primitive TDX guest");
    println!("  - tee.dcap implementa davvero generazione e verifica del quote");
    println!("  - per Dilithium il lavoro critico e' in tee.dcap, non nel guest crate");
}
