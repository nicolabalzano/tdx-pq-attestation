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
    let guest = root.join("confidential-computing.tdx.tdx-guest");

    println!("== tdx-guest source tour ==");
    println!();
    println!("Flusso da seguire:");
    println!("  1. il guest prepara report_data");
    println!("  2. chiama TDG.MR.REPORT per ottenere TDREPORT");
    println!("  3. opzionalmente estende RTMR");
    println!("  4. chiama TDVMCALL<GetQuote> verso VMM/QGS");
    println!("  5. il guest NON firma il quote");
    println!();

    let tdcall = guest.join("src/tdcall.rs");
    let tdvmcall = guest.join("src/tdvmcall.rs");
    let lib_rs = guest.join("src/lib.rs");
    let readme = guest.join("README.md");

    print_matches(
        &readme,
        &[
            "TDG.MR.REPORT",
            "TDG.MR.RTMR.EXTEND",
            "GetQuote",
        ],
    );

    print_matches(
        &tdcall,
        &[
            "pub struct TdReport {",
            "pub struct ReportMac {",
            "pub struct TdInfo {",
            "pub fn get_report(report_gpa: u64, data_gpa: u64) -> Result<(), TdCallError>",
            "TdcallNum::MrReport as u64",
            "pub fn extend_rtmr(extend_data_gpa: u64, reg_idx: u64) -> Result<(), TdCallError>",
            "TdcallNum::MrRtmrExtend as u64",
        ],
    );

    print_matches(
        &tdvmcall,
        &[
            "pub fn get_quote(shared_gpa: u64, size: u64) -> Result<(), TdVmcallError>",
            "TdVmcallNum::GetQuote as u64",
            "pub fn get_td_service(",
            "TdVmcallNum::Service as u64",
        ],
    );

    print_matches(
        &lib_rs,
        &[
            "pub mod tdcall;",
            "pub mod tdvmcall;",
            "pub fn is_tdx_guest_early() -> bool",
            "pub fn init_tdx() -> Result<TdgVpInfo, InitError>",
        ],
    );

    println!("Conclusione:");
    println!("  - get_report() crea TDREPORT");
    println!("  - extend_rtmr() aggiorna le measurement runtime");
    println!("  - get_quote() e' solo una richiesta al VMM/QGS");
    println!("  - la firma ECDSA o Dilithium NON avviene in questo crate");
}
