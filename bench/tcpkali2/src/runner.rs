//! Load test runner module
//!
//! Responsible for managing asynchronous task execution, statistics collection and result reporting

use crate::command::{Config, worker_count};
use crate::error::TcpKaliError;
use crate::stats::Stats;
use crate::tcp_worker::tcp_worker;
use crate::utils::duration_for_count;
use crate::websocket_worker::websocket_worker;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time;

fn handshakes_ready(transports: u64, failures: u64, expected: u64) -> bool {
    transports.saturating_add(failures) >= expected
}

fn initializations_ready(initialized: u64, expected: u64) -> bool {
    initialized >= expected
}

fn measurement_elapsed(start: time::Instant, end: time::Instant) -> Duration {
    end.duration_since(start)
}

fn handshake_timeout(connect_timeout: Duration) -> Duration {
    connect_timeout.saturating_add(Duration::from_secs(1))
}

async fn wait_for_readiness(
    tasks: &mut JoinSet<Result<(), TcpKaliError>>,
    stats: &Stats,
    expected: u64,
    transport_stage: bool,
    deadline: Option<(time::Instant, &'static str)>,
    quiet: bool,
) -> Result<bool, TcpKaliError> {
    loop {
        let ready = if transport_stage {
            handshakes_ready(
                stats.transport_connections.load(Ordering::Relaxed),
                stats.connection_errors.load(Ordering::Relaxed),
                expected,
            )
        } else {
            initializations_ready(
                stats.initialized_connections.load(Ordering::Relaxed),
                expected,
            )
        };
        if ready {
            return Ok(true);
        }
        if let Some((deadline, message)) = deadline
            && time::Instant::now() >= deadline
        {
            return Err(TcpKaliError::Timeout(message.into()));
        }

        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result {
                    report_task_result(result, quiet);
                }
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                return Ok(false);
            }
            _ = time::sleep(Duration::from_millis(1)) => {}
        }
    }
}

async fn abort_and_reap(tasks: &mut JoinSet<Result<(), TcpKaliError>>) {
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        report_task_result(result, true);
    }
}

/// Asynchronous main function responsible for executing load tests
///
/// # Arguments
/// - `matches`: Command line argument matches
///
/// # Returns
/// - `Result<(), TcpKaliError>`: Execution result
pub async fn async_main(matches: clap::ArgMatches) -> Result<(), TcpKaliError> {
    let config = crate::command::parse_config(&matches)?;
    let stats = Arc::new(Stats::new());
    let (load_start_tx, load_start_rx) = tokio::sync::watch::channel(false);
    let (benchmark_start_tx, benchmark_start_rx) = tokio::sync::watch::channel(None);
    let workers = worker_count(&matches);
    // Collect targets for CSV export (use first target for the CSV row)
    let targets: Vec<String> = matches
        .get_many::<String>("host:port")
        .unwrap()
        .cloned()
        .collect();

    // Periodically output real-time statistics
    let stats_printer = (!config.quiet).then(|| spawn_stats_printer(stats.clone()));

    let mut tasks = JoinSet::new();
    let connection_start = time::Instant::now();
    let mut spawned_connections = 0u64;
    let connection_batch_size = (config.connect_rate / 1_000).max(1);

    // Spawn progressively instead of creating thousands of sleeping tasks. An
    // absolute deadline preserves the requested aggregate connection rate.
    for target in targets.iter() {
        for _ in 0..config.connections {
            if config.connect_rate > 0
                && spawned_connections > 0
                && spawned_connections.is_multiple_of(connection_batch_size)
            {
                let deadline =
                    connection_start + duration_for_count(spawned_connections, config.connect_rate);
                time::sleep_until(deadline).await;
            }

            let task_config = config.clone();
            let task_stats = stats.clone();
            let target = target.clone();
            let task_load_start = load_start_rx.clone();
            let task_benchmark_start = config.channel_lifetime.map(|_| benchmark_start_rx.clone());

            tasks.spawn(async move {
                if task_config.use_websocket {
                    websocket_worker(
                        &target,
                        task_config,
                        task_stats,
                        task_load_start,
                        task_benchmark_start,
                    )
                    .await
                } else {
                    tcp_worker(
                        &target,
                        task_config,
                        task_stats,
                        task_load_start,
                        task_benchmark_start,
                    )
                    .await
                }
            });
            spawned_connections += 1;

            while let Some(result) = tasks.try_join_next() {
                report_task_result(result, config.quiet);
            }
        }
    }

    // Bound only TCP/WebSocket transport establishment with connect_timeout.
    let handshake_deadline = time::Instant::now() + handshake_timeout(config.connect_timeout);
    let transport_ready = wait_for_readiness(
        &mut tasks,
        &stats,
        spawned_connections,
        true,
        Some((
            handshake_deadline,
            "timed out waiting for connection handshakes",
        )),
        config.quiet,
    )
    .await;
    match transport_ready {
        Ok(true) => {}
        Ok(false) => {
            abort_and_reap(&mut tasks).await;
            if let Some(stats_printer) = stats_printer {
                stats_printer.abort();
            }
            return Ok(());
        }
        Err(error) => {
            abort_and_reap(&mut tasks).await;
            if let Some(stats_printer) = stats_printer {
                stats_printer.abort();
            }
            return Err(error);
        }
    }

    // Optional first-message echoes have their own timeout after the transport
    // is ready, so they may outlast connect_timeout without hanging forever.
    let init_deadline = time::Instant::now() + config.init_timeout;
    let initialization_ready = wait_for_readiness(
        &mut tasks,
        &stats,
        spawned_connections,
        false,
        Some((
            init_deadline,
            "timed out waiting for connection initialization",
        )),
        config.quiet,
    )
    .await;
    match initialization_ready {
        Ok(true) => {}
        Ok(false) => {
            abort_and_reap(&mut tasks).await;
            if let Some(stats_printer) = stats_printer {
                stats_printer.abort();
            }
            return Ok(());
        }
        Err(error) => {
            abort_and_reap(&mut tasks).await;
            if let Some(stats_printer) = stats_printer {
                stats_printer.abort();
            }
            return Err(error);
        }
    }
    let _ = load_start_tx.send(true);

    // Warmup phase
    let start_time = warmup_phase(&config, &stats, &benchmark_start_tx).await;

    // Execute benchmark
    let measurement_end = execute_benchmark(&config, &stats, &mut tasks).await;

    if let Some(stats_printer) = stats_printer {
        stats_printer.abort();
    }

    let elapsed = measurement_elapsed(start_time, measurement_end);

    // Output statistical results
    Stats::print_final_stats(&stats, elapsed, !config.quiet);

    // Export to CSV if --output is specified
    if let Some(ref path) = config.output {
        let target = targets.first().map(|s| s.as_str()).unwrap_or("");
        crate::csv_export::export_csv(path, &config, &stats, elapsed, target, workers);
    }

    Ok(())
}

/// Spawn statistics printer task
fn spawn_stats_printer(stats: Arc<Stats>) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Wait for warmup to complete
        while stats.is_warmup() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Reset the live window at the warmup boundary.
        let now = crate::utils::unix_timestamp_millis();
        stats
            .last_print_time
            .store(now, std::sync::atomic::Ordering::Relaxed);
        stats.last_print_count.store(
            stats
                .total_requests
                .load(std::sync::atomic::Ordering::Relaxed),
            std::sync::atomic::Ordering::Relaxed,
        );

        let mut interval = time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            if stats.is_shutting_down() {
                break;
            }

            let qps = stats.get_qps();
            let current_count = stats.total_requests.load(Ordering::Relaxed);
            let hist = stats.latency_histogram.lock();
            let p50 = if hist.is_empty() {
                0
            } else {
                hist.value_at_percentile(50.0)
            };
            let p95 = if hist.is_empty() {
                0
            } else {
                hist.value_at_percentile(95.0)
            };
            let p99 = if hist.is_empty() {
                0
            } else {
                hist.value_at_percentile(99.0)
            };

            println!(
                "[Live] QPS: {:.0} | Req: {} | Latency(us): P50={} P95={} P99={}",
                qps, current_count, p50, p95, p99
            );
        }
    })
}

/// Warmup phase processing
async fn warmup_phase(
    config: &Config,
    stats: &Arc<Stats>,
    benchmark_start_tx: &tokio::sync::watch::Sender<Option<time::Instant>>,
) -> time::Instant {
    // If warmup duration is 0, skip warmup phase
    if config.warmup_duration.as_secs_f64() == 0.0 {
        let start_time = time::Instant::now();
        let _ = benchmark_start_tx.send(Some(start_time));
        stats.end_warmup();
        return start_time;
    }

    if !config.quiet {
        println!(
            "Warming up for {} seconds...",
            config.warmup_duration.as_secs()
        );
    }
    // Wait for warmup to complete
    time::sleep(config.warmup_duration).await;
    // Publish the measurement boundary before workers become measurement-eligible.
    let start_time = time::Instant::now();
    let _ = benchmark_start_tx.send(Some(start_time));
    // Reset statistics
    stats.end_warmup();
    // Output log
    if !config.quiet {
        println!(
            "Warmup completed. Starting benchmark for {} seconds...",
            config.duration.as_secs()
        );
    }
    start_time
}

/// Execute benchmark
async fn execute_benchmark(
    config: &Config,
    stats: &Arc<Stats>,
    tasks: &mut JoinSet<Result<(), TcpKaliError>>,
) -> time::Instant {
    tokio::select! {
        _ = time::sleep(config.duration) => {}
        _ = tokio::signal::ctrl_c() => {}
    }

    let measurement_end = time::Instant::now();
    // Mark benchmark as shutting down
    stats.set_shutting_down();
    tasks.abort_all();

    while let Some(result) = tasks.join_next().await {
        report_task_result(result, config.quiet);
    }
    measurement_end
}

fn report_task_result(result: Result<Result<(), TcpKaliError>, JoinError>, quiet: bool) {
    match result {
        Ok(Err(error)) if !quiet => eprintln!("Task error: {}", error),
        Err(error) if !error.is_cancelled() && !quiet => eprintln!("Task join error: {}", error),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{handshake_timeout, handshakes_ready, initializations_ready, measurement_elapsed};
    use crate::stats::{ConnectionInitialization, Stats};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use tokio::task::JoinSet;
    use tokio::time::{Duration, Instant};

    #[test]
    fn warmup_gate_waits_for_every_handshake_attempt() {
        assert!(!handshakes_ready(2, 0, 3));
        assert!(handshakes_ready(2, 1, 3));
        assert!(handshakes_ready(0, 3, 3));
    }

    #[test]
    fn transport_readiness_is_independent_of_first_message_initialization() {
        assert!(handshakes_ready(1, 0, 1));
        assert!(!initializations_ready(0, 1));
        assert!(initializations_ready(1, 1));
    }

    #[tokio::test]
    async fn initialization_gate_terminates_and_counts_worker_panic_once() {
        let stats = Arc::new(Stats::new());
        let mut tasks = JoinSet::new();
        let worker_stats = stats.clone();
        tasks.spawn(async move {
            worker_stats
                .transport_connections
                .fetch_add(1, Ordering::Relaxed);
            let _initialization = ConnectionInitialization::new(&worker_stats);
            panic!("simulated worker task failure");
        });

        assert!(
            super::wait_for_readiness(&mut tasks, &stats, 1, false, None, true)
                .await
                .unwrap()
        );
        assert_eq!(stats.connection_errors.load(Ordering::Relaxed), 1);
        assert_eq!(stats.initialized_connections.load(Ordering::Relaxed), 1);
        assert!(tasks.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn silent_first_message_times_out_and_reaps_connection() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut first = [0; 4];
            stream.read_exact(&mut first).await.unwrap();
            let mut extra = [0; 1];
            assert_eq!(stream.read(&mut extra).await.unwrap(), 0);
        });
        let matches = crate::command::command()
            .try_get_matches_from(vec![
                "tcpkali2".to_string(),
                "-q".to_string(),
                "--connect-timeout".to_string(),
                "25ms".to_string(),
                "--init-timeout".to_string(),
                "50ms".to_string(),
                "--first-message".to_string(),
                "init".to_string(),
                address.to_string(),
            ])
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), super::async_main(matches))
            .await
            .expect("runner did not enforce the initialization deadline");
        assert!(matches!(
            result,
            Err(crate::error::TcpKaliError::Timeout(message))
                if message == "timed out waiting for connection initialization"
        ));
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("runner did not close the pending worker")
            .unwrap();
    }

    #[test]
    fn readiness_timeout_tracks_configured_connection_timeout() {
        assert_eq!(
            handshake_timeout(Duration::from_secs(45)),
            Duration::from_secs(46)
        );
    }

    #[tokio::test]
    async fn elapsed_stops_at_measurement_boundary_before_teardown() {
        let start = Instant::now();
        tokio::time::sleep(Duration::from_millis(5)).await;
        let end = Instant::now();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(measurement_elapsed(start, end) < Duration::from_millis(15));
    }
}
