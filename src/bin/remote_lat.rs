//! Latency requester similar to libzmq's local/remote latency tools.

#[path = "support/perf_common.rs"]
mod perf_common;

use std::process::ExitCode;
use std::time::Instant;

use bytes::Bytes;
use celerity::io::{ReqSocket, TokioCelerityError};
use perf_common::{
    CONNECT_RETRY_DELAY, format_elapsed, format_hundredths, parse_positive_usize, usage,
};

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
    let program = args.next().unwrap_or_else(|| "remote_lat".to_owned());
    let usage_tail = "<endpoint> <message_size> <roundtrip_count>";
    let endpoint = args.next().ok_or_else(|| usage(&program, usage_tail))?;
    let message_size = parse_positive_usize(args.next(), "message_size", &program, usage_tail)?;
    let roundtrip_count =
        parse_positive_usize(args.next(), "roundtrip_count", &program, usage_tail)?;

    if args.next().is_some() {
        return Err(usage(&program, usage_tail));
    }

    let socket = connect_requester(&endpoint).await?;
    let payload = vec![Bytes::from(vec![0_u8; message_size])];

    // One warmup roundtrip keeps handshake/setup out of the timed loop.
    let warmup = socket
        .request(payload.clone())
        .await
        .map_err(|err| err.to_string())?;
    validate_message_size(&warmup, message_size, 0)?;

    let started = Instant::now();
    for index in 1..=roundtrip_count {
        let reply = socket
            .request(payload.clone())
            .await
            .map_err(|err| err.to_string())?;
        validate_message_size(&reply, message_size, index)?;
    }
    let elapsed = started.elapsed();

    let elapsed_nanos = elapsed.as_nanos().max(1);
    let roundtrip_count =
        u128::try_from(roundtrip_count).map_err(|_| "roundtrip_count overflowed")?;
    let latency_micros = elapsed_nanos.saturating_mul(100) / roundtrip_count / 1_000;

    println!("endpoint: {endpoint}");
    println!("message size: {message_size} bytes");
    println!("roundtrip count: {roundtrip_count}");
    println!("elapsed: {} s", format_elapsed(elapsed));
    println!("average latency: {} us", format_hundredths(latency_micros));

    Ok(())
}

fn validate_message_size(
    message: &[Bytes],
    expected_size: usize,
    index: usize,
) -> Result<(), String> {
    let received_size: usize = message.iter().map(Bytes::len).sum();
    if received_size != expected_size {
        return Err(format!(
            "reply {index} had {received_size} bytes, expected {expected_size}",
        ));
    }
    Ok(())
}

async fn connect_requester(endpoint: &str) -> Result<ReqSocket, String> {
    loop {
        match ReqSocket::connect(endpoint).await {
            Ok(socket) => return Ok(socket),
            Err(TokioCelerityError::Connect { source, .. })
                if source.kind() == std::io::ErrorKind::ConnectionRefused =>
            {
                tokio::time::sleep(CONNECT_RETRY_DELAY).await;
            }
            Err(err) => return Err(err.to_string()),
        }
    }
}
