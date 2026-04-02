mod endpoint;
mod runtime;
mod socket;
mod transport;

use std::io;
use std::time::Duration;

use thiserror::Error;

pub use endpoint::{BindOptions, ConnectOptions, Endpoint, TransportKind, TransportMeta};
pub use runtime::TokioCelerity;
pub use socket::{PubSocket, RepSocket, ReqSocket, SubSocket};
pub use transport::AnyStream;

pub(crate) const DEFAULT_CHANNEL_CAPACITY: usize = 1;
pub(crate) const READ_BUFFER_CAPACITY: usize = 8 * 1024;
pub(crate) const MAX_DRAIN_ACTIONS_PER_TURN: usize = 128;
pub(crate) const MAX_DRAIN_BYTES_PER_TURN: usize = 1 << 20;
pub(crate) const SUBSCRIPTION_SETTLE_DELAY: Duration = Duration::from_millis(50);

#[derive(Debug, Error)]
pub enum TokioCelerityError {
    #[error("unsupported endpoint scheme: {0}")]
    UnsupportedEndpoint(String),
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("failed to resolve endpoint {endpoint}: {source}")]
    Resolve {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to bind endpoint {endpoint}: {source}")]
    Bind {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to connect to endpoint {endpoint}: {source}")]
    Connect {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("local authorization failed for {endpoint}: {reason}")]
    LocalAuth { endpoint: String, reason: String },
    #[error("high water mark exceeded")]
    QueueFull,
    #[error("handshake timed out")]
    HandshakeTimeout,
    #[error("channel closed: {0}")]
    ChannelClosed(&'static str),
    #[error("background task ended")]
    BackgroundTaskEnded,
    #[error("background task failed: {0}")]
    BackgroundTaskFailed(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Protocol(#[from] crate::ProtocolError),
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

pub(crate) fn capacity_from_hwm(value: usize) -> usize {
    value.max(DEFAULT_CHANNEL_CAPACITY)
}
