// Modified for Rut benchmarks (2026-10-10): binary payload handling,
// full latency sampling, echo verification, or benchmark metadata.
// See RUT.md for per-file changes and upstream provenance.
use crate::command::{Config, pipeline_in_flight_batches};
use crate::error::TcpKaliError;
use crate::stats::{ConnectionInitialization, LocalStatsCache, Stats};
use crate::utils::{RatePacer, wait_for_benchmark_lifetime, wait_for_load_start};

use bytes::Bytes;
use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use tokio::time::{self, Instant};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};
use tungstenite::Message;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsWriter = SplitSink<WsStream, Message>;
type WsReader = SplitStream<WsStream>;

fn ping_payload(message: &Bytes, sequence: u64, verify: bool) -> Bytes {
    if verify && message.len() >= std::mem::size_of::<u64>() {
        let mut sequenced = message.to_vec();
        sequenced[..8].copy_from_slice(&sequence.to_be_bytes());
        Bytes::from(sequenced)
    } else {
        message.clone()
    }
}

fn first_payload_matches(expected: &Bytes, received: &[u8], verify: bool) -> bool {
    !verify || expected.as_ref() == received
}

macro_rules! log_error {
    ($stats:expr, $config:expr, $($arg:tt)*) => {
        if !$stats.is_shutting_down() && !$config.quiet {
            eprintln!($($arg)*);
        }
    };
}

struct SentBatch {
    sent_at: Instant,
    remaining: usize,
    measurement: bool,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

/// Runs one WebSocket connection without a per-message shutdown check.
pub async fn websocket_worker(
    target: &str,
    config: Arc<Config>,
    stats: Arc<Stats>,
    load_start: tokio::sync::watch::Receiver<bool>,
    benchmark_start: Option<tokio::sync::watch::Receiver<Option<Instant>>>,
) -> Result<(), TcpKaliError> {
    let worker = run_websocket_worker(target, &config, &stats, load_start);
    tokio::pin!(worker);

    if let Some(lifetime) = config.channel_lifetime {
        let benchmark_start = benchmark_start.expect("Benchmark start receiver must be provided");
        tokio::select! {
            result = &mut worker => result,
            _ = wait_for_benchmark_lifetime(benchmark_start, lifetime) => Ok(()),
        }
    } else {
        worker.await
    }
}

async fn run_websocket_worker(
    target: &str,
    config: &Config,
    stats: &Stats,
    load_start: tokio::sync::watch::Receiver<bool>,
) -> Result<(), TcpKaliError> {
    stats.total_connections.fetch_add(1, Ordering::Relaxed);
    let mut initialization = ConnectionInitialization::new(stats);

    let ws_url = if target.starts_with("ws://") || target.starts_with("wss://") {
        target.to_string()
    } else {
        format!("ws://{}", target)
    };

    let ws_stream = match time::timeout(
        config.connect_timeout,
        connect_async_with_config(&ws_url, None, !config.nagle),
    )
    .await
    {
        Ok(Ok((stream, _))) => stream,
        Ok(Err(error)) => {
            log_error!(
                stats,
                config,
                "Failed to connect to WebSocket {}: {}",
                ws_url,
                error
            );
            return Ok(());
        }
        Err(_) => {
            log_error!(stats, config, "WebSocket connection timeout to {}", ws_url);
            return Ok(());
        }
    };

    stats.transport_connections.fetch_add(1, Ordering::Relaxed);
    initialization.transport_ready();
    let (mut write, mut read) = ws_stream.split();

    if let Some(first_message) = &config.first_message {
        let sent_at = Instant::now();
        if let Err(error) = write.send(Message::Binary(first_message.clone())).await {
            log_error!(
                stats,
                config,
                "Failed to send first WebSocket message: {}",
                error
            );
            return Ok(());
        }

        match read.next().await {
            Some(Ok(Message::Binary(data)))
                if first_payload_matches(first_message, &data, stats.verify_payload) =>
            {
                let latency_us = sent_at.elapsed().as_micros().max(1) as u64;
                stats.record_latency(latency_us, 0);
                stats.record_request(first_message.len(), data.len());
            }
            Some(Ok(Message::Binary(_))) => {
                log_error!(stats, config, "First WebSocket echo payload mismatch");
                return Ok(());
            }
            Some(Err(error)) => {
                log_error!(
                    stats,
                    config,
                    "Failed to read first message response: {}",
                    error
                );
                return Ok(());
            }
            _ => {
                log_error!(stats, config, "Unexpected response to first message");
                return Ok(());
            }
        }
    }

    initialization.succeed();
    wait_for_load_start(load_start).await;

    let message = config.message.as_ref().expect("Message must be provided");
    if message.is_empty() || config.message_rate == Some(0) {
        std::future::pending::<()>().await;
        return Ok(());
    }

    if config.pipeline {
        run_pipeline(write, read, config, stats).await
    } else {
        run_pingpong(write, read, config, stats).await
    }
}

async fn run_pingpong(
    mut write: WsWriter,
    mut read: WsReader,
    config: &Config,
    stats: &Stats,
) -> Result<(), TcpKaliError> {
    let verify = stats.verify_payload;
    let message = config.message.as_ref().expect("Message must be provided");
    let mut sequence = 0u64;
    let mut pacer = RatePacer::new(config.message_rate);
    let mut local_stats = LocalStatsCache::new(stats);

    loop {
        pacer.wait().await;
        let sent_at = Instant::now();
        let measurement = !stats.is_warmup();

        let payload = ping_payload(message, sequence, verify);
        if let Err(error) = write.send(Message::Binary(payload.clone())).await {
            log_error!(stats, config, "WebSocket send error: {}", error);
            stats.record_connection_error();
            return Ok(());
        }

        loop {
            match read.next().await {
                Some(Ok(Message::Ping(data))) => {
                    if let Err(error) = write.send(Message::Pong(data)).await {
                        log_error!(stats, config, "WebSocket pong error: {}", error);
                        stats.record_connection_error();
                        return Ok(());
                    }
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Binary(data))) => {
                    if verify && data.as_ref() != payload.as_ref() {
                        log_error!(stats, config, "WebSocket echo payload mismatch");
                        stats.record_connection_error();
                        return Ok(());
                    }
                    if measurement {
                        local_stats.record_responses(
                            1,
                            payload.len(),
                            data.len(),
                            sent_at.elapsed().as_micros().max(1) as u64,
                        );
                    }
                    sequence = sequence.wrapping_add(1);
                    pacer.advance(1);
                    break;
                }
                Some(Ok(_)) => {
                    log_error!(stats, config, "Unexpected WebSocket data frame");
                    stats.record_connection_error();
                    return Ok(());
                }
                Some(Err(error)) => {
                    log_error!(stats, config, "WebSocket receive error: {}", error);
                    stats.record_connection_error();
                    return Ok(());
                }
                None => {
                    if !stats.is_shutting_down() {
                        stats.record_connection_error();
                    }
                    return Ok(());
                }
            }
        }
    }
}

async fn run_pipeline(
    write: WsWriter,
    read: WsReader,
    config: &Config,
    stats: &Stats,
) -> Result<(), TcpKaliError> {
    let (sent_tx, sent_rx) = mpsc::unbounded_channel();
    tokio::select! {
        result = pipeline_writer(write, config, stats, sent_tx) => result,
        result = pipeline_reader(read, config, stats, sent_rx) => result,
    }
}

async fn pipeline_writer(
    mut write: WsWriter,
    config: &Config,
    stats: &Stats,
    sent_tx: mpsc::UnboundedSender<SentBatch>,
) -> Result<(), TcpKaliError> {
    let message = config.message.as_ref().expect("Message must be provided");
    let mut pacer = RatePacer::new(config.message_rate);
    let message_count = pacer.batch_size(config.pipeline_batch_size);
    let window = Arc::new(Semaphore::new(pipeline_in_flight_batches(
        message.len(),
        message_count,
    )));

    loop {
        pacer.wait().await;
        let permit = window
            .clone()
            .acquire_owned()
            .await
            .expect("Pipeline semaphore must remain open");

        let sent_at = Instant::now();
        if sent_tx
            .send(SentBatch {
                sent_at,
                remaining: message_count,
                measurement: !stats.is_warmup(),
                _permit: permit,
            })
            .is_err()
        {
            return Ok(());
        }

        for _ in 0..message_count {
            if let Err(error) = write.feed(Message::Binary(message.clone())).await {
                log_error!(stats, config, "WebSocket send error: {}", error);
                stats.record_connection_error();
                return Ok(());
            }
        }
        if let Err(error) = write.flush().await {
            log_error!(stats, config, "WebSocket flush error: {}", error);
            stats.record_connection_error();
            return Ok(());
        }

        pacer.advance(message_count);
    }
}

async fn pipeline_reader(
    mut read: WsReader,
    config: &Config,
    stats: &Stats,
    mut sent_rx: mpsc::UnboundedReceiver<SentBatch>,
) -> Result<(), TcpKaliError> {
    let message_size = config
        .message
        .as_ref()
        .expect("Message must be provided")
        .len();
    let mut current_batch: Option<SentBatch> = None;
    let mut local_stats = LocalStatsCache::new(stats);

    while let Some(message) = read.next().await {
        match message {
            Ok(Message::Binary(data)) => {
                let mut batch = match current_batch.take() {
                    Some(batch) => batch,
                    None => match sent_rx.recv().await {
                        Some(batch) => batch,
                        None => return Ok(()),
                    },
                };

                if batch.measurement {
                    local_stats.record_responses(
                        1,
                        message_size,
                        data.len(),
                        batch.sent_at.elapsed().as_micros().max(1) as u64,
                    );
                }
                batch.remaining -= 1;
                if batch.remaining > 0 {
                    current_batch = Some(batch);
                }
            }
            Ok(Message::Close(_)) => {
                if !stats.is_shutting_down() {
                    stats.record_connection_error();
                }
                return Ok(());
            }
            Ok(Message::Text(_)) => {
                log_error!(stats, config, "Unexpected WebSocket text frame in binary pipeline");
                stats.record_connection_error();
                return Ok(());
            }
            Ok(_) => continue,
            Err(error) => {
                log_error!(stats, config, "WebSocket receive error: {}", error);
                stats.record_connection_error();
                return Ok(());
            }
        }
    }

    if !stats.is_shutting_down() {
        stats.record_connection_error();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{first_payload_matches, ping_payload, websocket_worker};
    use crate::command::Config;
    use crate::stats::Stats;
    use bytes::Bytes;
    use futures::{SinkExt, StreamExt};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;
    use tungstenite::Message;

    #[test]
    fn unverified_ping_preserves_exact_payload() {
        let message = Bytes::from_static(b"abcdefgh");
        assert_eq!(ping_payload(&message, 7, false), message);
        assert_eq!(&ping_payload(&message, 7, true)[..8], &7u64.to_be_bytes());
        assert!(first_payload_matches(&message, b"wrong", false));
        assert!(!first_payload_matches(&message, b"wrong", true));
        assert!(first_payload_matches(&message, b"abcdefgh", true));
    }

    #[tokio::test]
    async fn pingpong_rejects_corrupt_echo() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = accept_async(stream).await.unwrap();
            let first = ws.next().await.unwrap().unwrap();
            ws.send(tungstenite::Message::Ping(Bytes::from_static(b"control")))
                .await
                .unwrap();
            let _ = ws.next().await;
            ws.send(first).await
                .unwrap();
            let _ = ws.next().await;
            ws.send(tungstenite::Message::Binary(Bytes::from_static(b"\0\0\0\0\0\0\0\0")))
                .await
                .unwrap();
        });
        let config = Arc::new(Config {
            duration: Duration::from_secs(1),
            warmup_duration: Duration::ZERO,
            message_size: 8,
            quiet: true,
            nagle: false,
            pipeline: false,
            connections: 1,
            connect_rate: 0,
            connect_timeout: Duration::from_secs(1),
            init_timeout: Duration::from_secs(1),
            channel_lifetime: None,
            first_message: None,
            message: Some(Bytes::from_static(b"abcdefgh")),
            pipeline_message: None,
            pipeline_batch_size: 1,
            message_rate: None,
            use_websocket: true,
            output: None,
        });
        let mut metrics = Stats::new();
        metrics.verify_payload = true;
        let stats = Arc::new(metrics);
        stats.end_warmup();
        let (_tx, rx) = tokio::sync::watch::channel(true);
        tokio::time::timeout(
            Duration::from_secs(2),
            websocket_worker(&address.to_string(), config, stats.clone(), rx, None),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        assert_eq!(stats.connection_errors.load(Ordering::Relaxed), 1);
        assert_eq!(stats.total_requests.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipeline_echo_records_responses_and_flushes_on_cancel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.unwrap();
            while let Some(Ok(message)) = websocket.next().await {
                if message.is_binary() {
                    websocket.send(message).await.unwrap();
                }
            }
        });

        let payload = Bytes::from_static(b"echo payload");
        let config = Arc::new(Config {
            duration: Duration::from_millis(200),
            warmup_duration: Duration::ZERO,
            message_size: payload.len(),
            quiet: true,
            nagle: false,
            pipeline: true,
            connections: 1,
            connect_rate: 0,
            connect_timeout: Duration::from_secs(1),
            init_timeout: Duration::from_secs(1),
            channel_lifetime: None,
            first_message: None,
            message: Some(payload.clone()),
            pipeline_message: Some(payload),
            pipeline_batch_size: 8,
            message_rate: Some(8_000),
            use_websocket: true,
            output: None,
        });
        let stats = Arc::new(Stats::new());
        stats.end_warmup();

        let worker_stats = stats.clone();
        let (_load_start_tx, load_start_rx) = tokio::sync::watch::channel(true);
        let worker = tokio::spawn(async move {
            websocket_worker(
                &address.to_string(),
                config,
                worker_stats,
                load_start_rx,
                None,
            )
            .await
            .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while stats.total_requests.load(Ordering::Relaxed) < 500 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("WebSocket echo worker did not produce responses");
        worker.abort();
        let _ = worker.await;
        server.abort();
        let _ = server.await;

        let responses = stats.total_requests.load(Ordering::Relaxed);
        assert!(responses >= 500, "only recorded {responses} responses");
        assert!(
            responses <= 2_000,
            "rate limiter allowed {responses} responses"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipeline_excludes_warmup_batch_and_counts_peer_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sent_tx, sent_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.unwrap();
            let message = websocket.next().await.unwrap().unwrap();
            sent_tx.send(()).unwrap();
            resume_rx.await.unwrap();
            websocket.send(message).await.unwrap();
            websocket.send(Message::Close(None)).await.unwrap();
        });

        let payload = Bytes::from_static(b"warmup");
        let config = Arc::new(Config {
            duration: Duration::from_secs(1),
            warmup_duration: Duration::ZERO,
            message_size: payload.len(),
            quiet: true,
            nagle: false,
            pipeline: true,
            connections: 1,
            connect_rate: 0,
            connect_timeout: Duration::from_secs(1),
            init_timeout: Duration::from_secs(1),
            channel_lifetime: None,
            first_message: None,
            message: Some(payload.clone()),
            pipeline_message: Some(payload),
            pipeline_batch_size: 1,
            message_rate: Some(1),
            use_websocket: true,
            output: None,
        });
        let stats = Arc::new(Stats::new());
        let worker_stats = stats.clone();
        let (_load_start_tx, load_start_rx) = tokio::sync::watch::channel(true);
        let worker = tokio::spawn(async move {
            websocket_worker(
                &address.to_string(),
                config,
                worker_stats,
                load_start_rx,
                None,
            )
            .await
            .unwrap();
        });

        tokio::time::timeout(Duration::from_secs(1), sent_rx)
            .await
            .expect("pipeline did not send its warmup batch")
            .unwrap();
        stats.end_warmup();
        resume_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("pipeline did not stop on peer close")
            .unwrap();
        server.await.unwrap();

        assert_eq!(stats.total_requests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.connection_errors.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pipeline_rejects_unexpected_text_replies() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = accept_async(stream).await.unwrap();
            assert!(websocket.next().await.unwrap().unwrap().is_binary());
            websocket
                .send(Message::Text("unexpected".into()))
                .await
                .unwrap();
        });

        let payload = Bytes::from_static(b"binary");
        let config = Arc::new(Config {
            duration: Duration::from_secs(1),
            warmup_duration: Duration::ZERO,
            message_size: payload.len(),
            quiet: true,
            nagle: false,
            pipeline: true,
            connections: 1,
            connect_rate: 0,
            connect_timeout: Duration::from_secs(1),
            init_timeout: Duration::from_secs(1),
            channel_lifetime: None,
            first_message: None,
            message: Some(payload.clone()),
            pipeline_message: Some(payload),
            pipeline_batch_size: 1,
            message_rate: Some(1),
            use_websocket: true,
            output: None,
        });
        let stats = Arc::new(Stats::new());
        stats.end_warmup();
        let worker_stats = stats.clone();
        let (_load_start_tx, load_start_rx) = tokio::sync::watch::channel(true);
        let worker = tokio::spawn(async move {
            websocket_worker(
                &address.to_string(),
                config,
                worker_stats,
                load_start_rx,
                None,
            )
            .await
            .unwrap();
        });

        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("pipeline did not stop on text reply")
            .unwrap();
        server.await.unwrap();
        assert_eq!(stats.total_requests.load(Ordering::Relaxed), 0);
        assert_eq!(stats.connection_errors.load(Ordering::Relaxed), 1);
    }
}
