//! Throughput sender similar to libzmq's local/remote throughput tools.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use bytes::Bytes;
use celerity::io::PushSocket;

const HANDSHAKE_SETTLE_DELAY: Duration = Duration::from_millis(100);

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "remote_thr".to_owned());
    let endpoint = args.next().ok_or_else(|| usage(&program))?;
    let message_size = parse_positive_usize(args.next(), "message_size", &program)?;
    let message_count = parse_positive_usize(args.next(), "message_count", &program)?;

    if args.next().is_some() {
        return Err(usage(&program));
    }

    let socket = PushSocket::connect(&endpoint)
        .await
        .map_err(|err| err.to_string())?;
    let payload = Bytes::from(vec![0_u8; message_size]);

    // Give the connection a brief moment to clear handshake/setup before the timed loop.
    tokio::time::sleep(HANDSHAKE_SETTLE_DELAY).await;

    let started = Instant::now();
    for _ in 0..message_count {
        socket
            .send(vec![payload.clone()])
            .await
            .map_err(|err| err.to_string())?;
    }
    let elapsed = started.elapsed();

    let elapsed_micros = elapsed.as_micros().max(1);
    let message_size = u128::try_from(message_size).map_err(|_| "message_size overflowed")?;
    let message_count = u128::try_from(message_count).map_err(|_| "message_count overflowed")?;
    let messages_per_second =
        message_count.saturating_mul(100).saturating_mul(1_000_000) / elapsed_micros;
    let mebibytes_per_second = message_size
        .saturating_mul(message_count)
        .saturating_mul(100)
        .saturating_mul(1_000_000)
        / elapsed_micros
        / (1024 * 1024);

    println!("endpoint: {endpoint}");
    println!("message size: {message_size} bytes");
    println!("message count: {message_count}");
    println!(
        "elapsed: {}.{:06} s",
        elapsed.as_secs(),
        elapsed.subsec_micros()
    );
    println!(
        "send rate: {} msg/s",
        format_hundredths(messages_per_second)
    );
    println!(
        "send bandwidth: {} MiB/s",
        format_hundredths(mebibytes_per_second),
    );

    Ok(())
}

fn parse_positive_usize(value: Option<String>, name: &str, program: &str) -> Result<usize, String> {
    let value = value.ok_or_else(|| usage(program))?;
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("invalid {name}: {value}"))?;
    if parsed == 0 {
        return Err(format!("{name} must be greater than zero"));
    }
    Ok(parsed)
}

fn usage(program: &str) -> String {
    format!("usage: {program} <endpoint> <message_size> <message_count>")
}

fn format_hundredths(value: u128) -> String {
    format!("{}.{:02}", value / 100, value % 100)
}
