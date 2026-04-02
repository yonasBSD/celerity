use std::process::ExitCode;
use std::time::Duration;

use bytes::Bytes;
use clap::{Parser, Subcommand};
use tokio::time::sleep;

use celerity::io::{PubSocket, SubSocket, TokioCelerityError};

const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(200);

#[derive(Debug, Parser)]
#[command(name = "cel-cat")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(name = "pub")]
    Publish {
        #[arg(long, default_value_t = 750)]
        linger_ms: u64,
        endpoint: String,
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        message: Vec<String>,
    },
    #[command(name = "sub")]
    Subscribe { endpoint: String },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<(), TokioCelerityError> {
    match Cli::parse().command {
        Command::Publish {
            linger_ms,
            endpoint,
            message,
        } => {
            let message = message.join(" ");
            let mut socket = PubSocket::bind(&endpoint).await?;
            let _ = socket
                .wait_for_subscriber(Duration::from_millis(linger_ms))
                .await?;
            socket.send(vec![Bytes::from(message)]).await?;
            Ok(())
        }
        Command::Subscribe { endpoint } => {
            let mut socket = connect_subscriber(&endpoint).await?;
            socket.subscribe(Bytes::new()).await?;

            loop {
                match socket.recv().await {
                    Ok(message) => println!("{}", render_message(&message)),
                    Err(TokioCelerityError::BackgroundTaskEnded) => return Ok(()),
                    Err(TokioCelerityError::Io(err))
                        if matches!(
                            err.kind(),
                            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof
                        ) =>
                    {
                        return Ok(());
                    }
                    Err(err) => return Err(err),
                }
            }
        }
    }
}

async fn connect_subscriber(endpoint: &str) -> Result<SubSocket, TokioCelerityError> {
    loop {
        match SubSocket::connect(endpoint).await {
            Ok(socket) => return Ok(socket),
            Err(TokioCelerityError::Connect { source, .. })
                if source.kind() == std::io::ErrorKind::ConnectionRefused =>
            {
                sleep(CONNECT_RETRY_DELAY).await;
            }
            Err(err) => return Err(err),
        }
    }
}

fn render_message(message: &[Bytes]) -> String {
    message
        .iter()
        .map(|frame| String::from_utf8_lossy(frame).into_owned())
        .collect::<Vec<_>>()
        .join("\t")
}
