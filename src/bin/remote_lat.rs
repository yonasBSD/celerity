//! Latency requester similar to libzmq's local/remote latency tools.

use std::process::ExitCode;
use std::time::Instant;

use bytes::Bytes;
use celerity::io::ReqSocket;

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
    let endpoint = args.next().ok_or_else(|| usage(&program))?;
    let message_size = parse_positive_usize(args.next(), "message_size", &program)?;
    let roundtrip_count = parse_positive_usize(args.next(), "roundtrip_count", &program)?;

    if args.next().is_some() {
        return Err(usage(&program));
    }

    let socket = ReqSocket::connect(&endpoint)
        .await
        .map_err(|err| err.to_string())?;
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
    println!(
        "elapsed: {}.{:06} s",
        elapsed.as_secs(),
        elapsed.subsec_micros()
    );
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
    format!("usage: {program} <endpoint> <message_size> <roundtrip_count>")
}

fn format_hundredths(value: u128) -> String {
    format!("{}.{:02}", value / 100, value % 100)
}
