//! Throughput receiver similar to libzmq's local/remote throughput tools.

mod common;

use std::process::ExitCode;
use std::time::Instant;

use celerity::io::PullSocket;
use common::{format_elapsed, format_hundredths, parse_positive_usize, usage};

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
    let program = args.next().unwrap_or_else(|| "local_thr".to_owned());
    let usage_tail = "<endpoint> <message_size> <message_count>";
    let endpoint = args.next().ok_or_else(|| usage(&program, usage_tail))?;
    let message_size = parse_positive_usize(args.next(), "message_size", &program, usage_tail)?;
    let message_count = parse_positive_usize(args.next(), "message_count", &program, usage_tail)?;

    if args.next().is_some() {
        return Err(usage(&program, usage_tail));
    }

    let mut socket = PullSocket::bind(&endpoint)
        .await
        .map_err(|err| err.to_string())?;

    let first = socket.recv().await.map_err(|err| err.to_string())?;
    let first_size: usize = first.iter().map(bytes::Bytes::len).sum();
    if first_size != message_size {
        return Err(format!(
            "message 0 had {first_size} bytes, expected {message_size}",
        ));
    }

    // Mirror libzmq's throughput tool: wait for one warmup message, then time the steady-state run.
    let started = Instant::now();
    for index in 1..=message_count {
        let message = socket.recv().await.map_err(|err| err.to_string())?;
        let received_size: usize = message.iter().map(bytes::Bytes::len).sum();
        if received_size != message_size {
            return Err(format!(
                "message {index} had {received_size} bytes, expected {message_size}",
            ));
        }
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
    println!("elapsed: {} s", format_elapsed(elapsed));
    println!(
        "throughput: {} msg/s",
        format_hundredths(messages_per_second),
    );
    println!(
        "bandwidth: {} MiB/s",
        format_hundredths(mebibytes_per_second),
    );

    Ok(())
}
