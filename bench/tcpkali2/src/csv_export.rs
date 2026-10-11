// Modified for Rut benchmarks (2026-10-10): binary payload handling,
// full latency sampling, echo verification, or benchmark metadata.
// See RUT.md for per-file changes and upstream provenance.
use crate::command::Config;
use crate::stats::{Stats, megabits_per_second, rate_per_second};
use std::fs;
use std::io::{self, BufRead, Write};
use std::sync::atomic::Ordering;
use std::time::Duration;

/// All CSV column headers in a fixed order.
const HEADERS: &[&str] = &[
    "timestamp",
    "target",
    "connections",
    "connect_rate",
    "connect_timeout_s",
    "channel_lifetime_s",
    "duration_s",
    "warmup_s",
    "workers",
    "nagle",
    "pipeline",
    "websocket",
    "message_size",
    "message_rate",
    "total_connections",
    "success_rate_pct",
    "total_requests",
    "connection_errors",
    "connection_error_rate_pct",
    "requests_per_sec",
    "throughput_mb",
    "bandwidth_mb_s",
    "traffic_down_mbps",
    "traffic_up_mbps",
    "latency_avg_us",
    "latency_min_us",
    "latency_p50_us",
    "latency_p90_us",
    "latency_p95_us",
    "latency_p99_us",
    "latency_max_us",
    "latency_samples",
    "latency_sample_shift",
    "verify_payload",
];

/// Build the header line from the fixed column list.
fn header_line() -> String {
    HEADERS.join(",")
}

/// Build a data row from config and stats.
fn build_row(
    config: &Config,
    stats: &Stats,
    duration: Duration,
    target: &str,
    workers: usize,
) -> String {
    let hist = stats.latency_histogram.lock();
    let total_bytes_sent = stats.total_bytes_sent.load(Ordering::Relaxed);
    let total_bytes_received = stats.total_bytes_received.load(Ordering::Relaxed);
    let total_bytes = total_bytes_sent + total_bytes_received;
    let total_requests = stats.total_requests.load(Ordering::Relaxed);
    let qps = rate_per_second(total_requests, duration);

    let total_connections = stats.total_connections.load(Ordering::Relaxed) as f64;
    let success_connections = stats.success_connections.load(Ordering::Relaxed) as f64;
    let success_rate = if total_connections > 0.0 {
        success_connections / total_connections * 100.0
    } else {
        0.0
    };

    let connection_errors = stats.connection_errors.load(Ordering::Relaxed);
    let connection_error_rate = stats.connection_error_rate();
    let bandwidth = rate_per_second(total_bytes, duration) / 1_000_000.0;
    let traffic_down_mbps = megabits_per_second(total_bytes_received, duration);
    let traffic_up_mbps = megabits_per_second(total_bytes_sent, duration);

    // Get current UTC timestamp in RFC 3339 format without external crate
    let timestamp = {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = d.as_secs();
        // Convert epoch seconds to date-time components
        let (year, month, day, hour, min, sec) = epoch_to_datetime(secs);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hour, min, sec
        )
    };

    let channel_lifetime_str = config
        .channel_lifetime
        .map(|d| format!("{:.2}", d.as_secs_f64()))
        .unwrap_or_else(|| "-1".to_string());

    let message_rate_str = config
        .message_rate
        .map(|r| r.to_string())
        .unwrap_or_else(|| "-1".to_string());

    let values: Vec<String> = vec![
        timestamp,
        target.to_string(),
        config.connections.to_string(),
        config.connect_rate.to_string(),
        format!("{:.2}", config.connect_timeout.as_secs_f64()),
        channel_lifetime_str,
        format!("{:.2}", config.duration.as_secs_f64()),
        format!("{:.2}", config.warmup_duration.as_secs_f64()),
        workers.to_string(),
        config.nagle.to_string(),
        config.pipeline.to_string(),
        config.use_websocket.to_string(),
        config
            .message
            .as_ref()
            .map_or(config.message_size, bytes::Bytes::len)
            .to_string(),
        message_rate_str,
        format!("{}", total_connections),
        format!("{:.1}", success_rate),
        total_requests.to_string(),
        connection_errors.to_string(),
        format!("{:.2}", connection_error_rate),
        format!("{:.2}", qps),
        format!("{:.2}", total_bytes as f64 / 1_000_000.0),
        format!("{:.2}", bandwidth),
        format!("{:.2}", traffic_down_mbps),
        format!("{:.2}", traffic_up_mbps),
        format!("{:.1}", hist.mean()),
        format!("{}", hist.min()),
        format!("{}", hist.value_at_percentile(50.0)),
        format!("{}", hist.value_at_percentile(90.0)),
        format!("{}", hist.value_at_percentile(95.0)),
        format!("{}", hist.value_at_percentile(99.0)),
        format!("{}", hist.max()),
        hist.len().to_string(),
        stats.latency_sample_shift.to_string(),
        stats.verify_payload.to_string(),
    ];

    values.join(",")
}

/// Convert epoch seconds (UTC) to (year, month, day, hour, minute, second).
fn epoch_to_datetime(epoch: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec = epoch % 60;
    let min = (epoch / 60) % 60;
    let hour = (epoch / 3600) % 24;
    let mut days = epoch / 86400;

    // Calculate year
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if days < days_in_year {
            break;
        }
        days -= days_in_year;
        year += 1;
    }

    // Calculate month and day
    let days_in_months: [u64; 12] = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0u64;
    for (i, &dim) in days_in_months.iter().enumerate() {
        if days < dim {
            month = i as u64 + 1;
            break;
        }
        days -= dim;
    }
    let day = days + 1;

    (year, month, day, hour, min, sec)
}

fn is_leap(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Export benchmark results to a CSV file.
///
/// - If the file does not exist, creates it with headers + data row.
/// - If it exists and headers match, appends the data row.
/// - If it exists but headers don't match, silently overwrites with correct headers + data row.
pub fn export_csv(
    path: &str,
    config: &Config,
    stats: &Stats,
    duration: Duration,
    target: &str,
    workers: usize,
) -> io::Result<()> {
    let expected_header = header_line();
    let row = build_row(config, stats, duration, target, workers);

    match fs::File::open(path) {
        Ok(file) => {
            let reader = std::io::BufReader::new(file);
            if let Some(first_line) = reader.lines().next().transpose()?
                && first_line.trim() == expected_header
            {
                let mut file = fs::OpenOptions::new().append(true).open(path)?;
                write_csv_lines(&mut file, std::iter::once(row.as_str()))?;
                return Ok(());
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut file = fs::File::create(path)?;
    write_csv_lines(&mut file, [expected_header.as_str(), row.as_str()])
}

fn write_csv_lines(
    writer: &mut impl Write,
    lines: impl IntoIterator<Item = impl AsRef<str>>,
) -> io::Result<()> {
    for line in lines {
        writeln!(writer, "{}", line.as_ref())?;
    }
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::{HEADERS, build_row, export_csv, write_csv_lines};
    use crate::command::Config;
    use crate::stats::Stats;
    use bytes::Bytes;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    #[test]
    fn csv_row_uses_consistent_error_and_rate_units() {
        let payload = Bytes::from_static(b"abc");
        let config = Config {
            duration: Duration::from_secs(2),
            warmup_duration: Duration::ZERO,
            message_size: 128,
            quiet: true,
            nagle: false,
            pipeline: false,
            connections: 4,
            connect_rate: 0,
            connect_timeout: Duration::from_secs(1),
            init_timeout: Duration::from_secs(30),
            channel_lifetime: None,
            first_message: None,
            message: Some(payload.clone()),
            pipeline_message: Some(payload),
            pipeline_batch_size: 1,
            message_rate: None,
            use_websocket: false,
            output: None,
        };
        let stats = Stats::new();
        stats.total_connections.store(4, Ordering::Relaxed);
        stats.success_connections.store(1, Ordering::Relaxed);
        stats.connection_errors.store(3, Ordering::Relaxed);
        stats.total_requests.store(10, Ordering::Relaxed);
        stats
            .total_bytes_received
            .store(1_000_000, Ordering::Relaxed);
        stats.total_bytes_sent.store(2_000_000, Ordering::Relaxed);

        let row = build_row(&config, &stats, Duration::from_secs(2), "localhost:1", 1);
        let values: Vec<_> = row.split(',').collect();
        assert_eq!(values.len(), HEADERS.len());

        let value = |header: &str| values[HEADERS.iter().position(|item| *item == header).unwrap()];
        assert_eq!(value("message_size"), "3");
        assert_eq!(value("connection_errors"), "3");
        assert_eq!(value("connection_error_rate_pct"), "75.00");
        assert_eq!(value("traffic_down_mbps"), "4.00");
        assert_eq!(value("traffic_up_mbps"), "8.00");
    }

    #[test]
    fn csv_export_propagates_create_and_write_failures() {
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("injected write failure"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        assert!(write_csv_lines(&mut FailingWriter, ["row"]).is_err());

        let config = Config {
            duration: Duration::from_secs(1),
            warmup_duration: Duration::ZERO,
            message_size: 1,
            quiet: true,
            nagle: false,
            pipeline: false,
            connections: 1,
            connect_rate: 0,
            connect_timeout: Duration::from_secs(1),
            init_timeout: Duration::from_secs(30),
            channel_lifetime: None,
            first_message: None,
            message: Some(Bytes::from_static(b"x")),
            pipeline_message: None,
            pipeline_batch_size: 1,
            message_rate: None,
            use_websocket: false,
            output: None,
        };
        let path = std::env::temp_dir().join(format!(
            "tcpkali2-csv-missing-{}/out.csv",
            std::process::id()
        ));
        let stats = Stats::new();
        assert!(
            export_csv(
                &path.to_string_lossy(),
                &config,
                &stats,
                Duration::from_secs(1),
                "",
                1
            )
            .is_err()
        );
    }
}
