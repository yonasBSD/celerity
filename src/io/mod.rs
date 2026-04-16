//! Tokio transport adapters and higher-level socket wrappers.

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

/// An error returned by the Tokio runtime and socket adapters.
#[derive(Debug, Error)]
pub enum TokioCelerityError {
    /// The endpoint used an unsupported scheme.
    #[error("unsupported endpoint scheme: {0}")]
    UnsupportedEndpoint(String),
    /// The endpoint string was malformed.
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    /// Endpoint resolution failed.
    #[error("failed to resolve endpoint {endpoint}: {source}")]
    Resolve {
        /// The endpoint that failed to resolve.
        endpoint: String,
        #[source]
        /// The underlying I/O error.
        source: io::Error,
    },
    /// Binding a listener failed.
    #[error("failed to bind endpoint {endpoint}: {source}")]
    Bind {
        /// The endpoint that failed to bind.
        endpoint: String,
        #[source]
        /// The underlying I/O error.
        source: io::Error,
    },
    /// Connecting to a remote endpoint failed.
    #[error("failed to connect to endpoint {endpoint}: {source}")]
    Connect {
        /// The endpoint that failed to connect.
        endpoint: String,
        #[source]
        /// The underlying I/O error.
        source: io::Error,
    },
    /// Local authorization checks rejected the transport.
    #[error("local authorization failed for {endpoint}: {reason}")]
    LocalAuth {
        /// The endpoint that failed local authorization.
        endpoint: String,
        /// A human-readable explanation of the failed check.
        reason: String,
    },
    /// A high-water mark prevented more data from being queued.
    #[error("high water mark exceeded")]
    QueueFull,
    /// The handshake did not complete before its deadline.
    #[error("handshake timed out")]
    HandshakeTimeout,
    /// A runtime channel closed unexpectedly.
    #[error("channel closed: {0}")]
    ChannelClosed(&'static str),
    /// A background task ended without an explicit protocol error.
    #[error("background task ended")]
    BackgroundTaskEnded,
    /// A background task failed with a terminal error message.
    #[error("background task failed: {0}")]
    BackgroundTaskFailed(String),
    /// An underlying Tokio or std I/O error.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A protocol-layer error surfaced through the runtime.
    #[error(transparent)]
    Protocol(#[from] crate::ProtocolError),
    /// Joining a spawned Tokio task failed.
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),
}

pub(crate) fn capacity_from_hwm(value: usize) -> usize {
    value.max(DEFAULT_CHANNEL_CAPACITY)
}
