//! Throughput sender similar to libzmq's local/remote throughput tools.

mod common;

use std::process::ExitCode;

use bytes::Bytes;
use celerity::io::{PushSocket, TokioCelerityError};
use common::{CONNECT_RETRY_DELAY, parse_positive_usize, usage};

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
    let usage_tail = "<endpoint> <message_size> <message_count>";
    let endpoint = args.next().ok_or_else(|| usage(&program, usage_tail))?;
    let message_size = parse_positive_usize(args.next(), "message_size", &program, usage_tail)?;
    let message_count = parse_positive_usize(args.next(), "message_count", &program, usage_tail)?;

    if args.next().is_some() {
        return Err(usage(&program, usage_tail));
    }

    let socket = connect_pusher(&endpoint).await?;
    let payload = Bytes::from(vec![0_u8; message_size]);
    let flush_every = flush_interval(message_size);

    // One warmup message lets the receiver start timing after the pipe is hot.
    socket
        .send(vec![payload.clone()])
        .await
        .map_err(|err| err.to_string())?;
    flush_sender(&socket).await?;

    for index in 0..message_count {
        socket
            .send(vec![payload.clone()])
            .await
            .map_err(|err| err.to_string())?;

        if (index + 1) % flush_every == 0 {
            flush_sender(&socket).await?;
        }
    }

    flush_sender(&socket).await?;

    Ok(())
}

async fn connect_pusher(endpoint: &str) -> Result<PushSocket, String> {
    loop {
        match PushSocket::connect(endpoint).await {
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

async fn flush_sender(socket: &PushSocket) -> Result<(), String> {
    match socket.flush().await {
        Ok(())
        | Err(
            TokioCelerityError::BackgroundTaskEnded
            | TokioCelerityError::ChannelClosed("connection task"),
        ) => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}

fn flush_interval(message_size: usize) -> usize {
    if message_size < (32 * 1024) {
        usize::MAX
    } else {
        const TARGET_BATCH_BYTES: usize = 1 << 19;
        (TARGET_BATCH_BYTES / message_size.max(1)).max(1)
    }
}
