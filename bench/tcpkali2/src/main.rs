// Modified for Rut benchmarks (2026-10-10): binary payload handling,
// full latency sampling, echo verification, or benchmark metadata.
// See RUT.md for per-file changes and upstream provenance.
mod command;
mod csv_export;
mod error;
mod runner;
mod stats;
mod tcp_worker;
mod utils;
mod websocket_worker;

use crate::command::{new_command, worker_count};
use crate::error::TcpKaliError;
use crate::runner::async_main;

/// TCPKali2 main function
///
/// # Returns
/// * `Result<(), TcpKaliError>` - Execution result
fn main() -> Result<(), TcpKaliError> {
    eprintln!(
        "TCPKALI2_BENCH full_latency={} verify={}",
        std::env::var("TCPKALI2_BENCH_FULL_LATENCY").as_deref() == Ok("1"),
        std::env::var("TCPKALI2_BENCH_VERIFY").as_deref() == Ok("1")
    );
    let matches = new_command();
    crate::command::validate_payload_verification(
        matches.get_flag("websocket"),
        matches.get_flag("pipeline"),
        std::env::var("TCPKALI2_BENCH_VERIFY").as_deref() == Ok("1"),
    )?;
    let workers = worker_count(&matches);
    if workers == 0 {
        return Err(TcpKaliError::Config(
            "workers must be greater than 0".into(),
        ));
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;

    rt.block_on(async_main(matches))
}
