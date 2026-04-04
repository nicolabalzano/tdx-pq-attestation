use std::any::type_name;
use std::mem::{align_of, size_of, MaybeUninit};

use tdx_guest::tdcall::{extend_rtmr, get_report, ReportMac, TdCallError, TdInfo, TdReport};
use tdx_guest::tdvmcall::{get_quote, TdVmcallError};

#[repr(align(64))]
struct Aligned64<const N: usize>([u8; N]);

fn print_signature<F>(name: &str, _: F) {
    println!("{name}: {}", type_name::<F>());
}

fn main() {
    println!("== tdx-guest API tour ==");
    println!();

    println!("1. Strutture principali del report");
    println!(
        "TdReport   size={} align={}",
        size_of::<TdReport>(),
        align_of::<TdReport>()
    );
    println!(
        "ReportMac  size={} align={}",
        size_of::<ReportMac>(),
        align_of::<ReportMac>()
    );
    println!(
        "TdInfo     size={} align={}",
        size_of::<TdInfo>(),
        align_of::<TdInfo>()
    );
    println!();

    println!("2. API importanti");
    let _get_report: fn(u64, u64) -> Result<(), TdCallError> = get_report;
    let _extend_rtmr: fn(u64, u64) -> Result<(), TdCallError> = extend_rtmr;
    let _get_quote: fn(u64, u64) -> Result<(), TdVmcallError> = get_quote;

    print_signature("tdx_guest::tdcall::get_report", get_report);
    print_signature("tdx_guest::tdcall::extend_rtmr", extend_rtmr);
    print_signature("tdx_guest::tdvmcall::get_quote", get_quote);
    println!();

    println!("3. Buffer da preparare");
    let mut report = MaybeUninit::<TdReport>::zeroed();
    let report_data = Aligned64([0u8; 64]);
    let extend_chunk = Aligned64([0u8; 48]);
    let shared_quote_buffer = Aligned64([0u8; 4096]);

    let report_addr = report.as_mut_ptr() as u64;
    let report_data_addr = report_data.0.as_ptr() as u64;
    let extend_chunk_addr = extend_chunk.0.as_ptr() as u64;
    let quote_shared_addr = shared_quote_buffer.0.as_ptr() as u64;

    println!("TDREPORT buffer addr   = 0x{report_addr:016x}");
    println!("report_data addr       = 0x{report_data_addr:016x}");
    println!("RTMR extend chunk addr = 0x{extend_chunk_addr:016x}");
    println!("quote shared addr      = 0x{quote_shared_addr:016x}");
    println!("quote shared size      = {}", shared_quote_buffer.0.len());
    println!();

    println!("4. Sequenza mentale corretta");
    println!(" - get_report(report_gpa, data_gpa)");
    println!(" - opzionale: extend_rtmr(chunk_gpa, reg_idx)");
    println!(" - get_quote(shared_gpa, size)");
    println!(" - il guest NON firma il quote: notifica il VMM/QGS");
    println!();

    println!("5. Esecuzione reale");
    let in_tdx = tdx_guest::is_tdx_guest_early();
    println!("is_tdx_guest_early() = {in_tdx}");

    if !in_tdx {
        println!("Ambiente non TDX: salto le TDCALL/TDVMCALL reali.");
        println!("Questo e' il comportamento atteso su una macchina normale.");
        return;
    }

    println!("Ambiente TDX rilevato, provo le primitive.");

    match get_report(report_addr, report_data_addr) {
        Ok(()) => println!("get_report(): OK"),
        Err(err) => println!("get_report(): ERR {err:?}"),
    }

    match extend_rtmr(extend_chunk_addr, 0) {
        Ok(()) => println!("extend_rtmr(): OK"),
        Err(err) => println!("extend_rtmr(): ERR {err:?}"),
    }

    match get_quote(quote_shared_addr, shared_quote_buffer.0.len() as u64) {
        Ok(()) => println!("get_quote(): OK"),
        Err(err) => println!("get_quote(): ERR {err:?}"),
    }
}
