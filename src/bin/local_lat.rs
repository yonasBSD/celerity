//! Latency responder similar to libzmq's local/remote latency tools.

use std::process::ExitCode;

use bytes::Bytes;
use celerity::io::RepSocket;

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
    let program = args.next().unwrap_or_else(|| "local_lat".to_owned());
    let endpoint = args.next().ok_or_else(|| usage(&program))?;
    let message_size = parse_positive_usize(args.next(), "message_size", &program)?;
    let roundtrip_count = parse_positive_usize(args.next(), "roundtrip_count", &program)?;

    if args.next().is_some() {
        return Err(usage(&program));
    }

    let mut socket = RepSocket::bind(&endpoint)
        .await
        .map_err(|err| err.to_string())?;

    for index in 0..=roundtrip_count {
        let message = socket.recv().await.map_err(|err| err.to_string())?;
        let received_size: usize = message.iter().map(Bytes::len).sum();
        if received_size != message_size {
            return Err(format!(
                "message {index} had {received_size} bytes, expected {message_size}",
            ));
        }

        socket.reply(message).await.map_err(|err| err.to_string())?;
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
