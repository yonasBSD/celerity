//! Endpoint parsing, binding options, and transport metadata.

use std::fmt;
use std::net::SocketAddr;
#[cfg(unix)]
use std::path::{Path, PathBuf};

use crate::LinkScope;

use super::TokioCelerityError;

/// The concrete transport used by an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    /// TCP over an IP network.
    Tcp,
    /// A Unix domain socket endpoint.
    Ipc,
}

/// A parsed endpoint address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// A TCP host:port target.
    Tcp(String),
    #[cfg(unix)]
    /// An absolute Unix domain socket path.
    Ipc(PathBuf),
}

impl Endpoint {
    /// Parses a TCP or IPC endpoint string.
    ///
    /// Bare `host:port` values are treated as TCP. On Unix platforms,
    /// `ipc:///absolute/path.sock` is also accepted.
    ///
    /// # Errors
    ///
    /// Returns [`TokioCelerityError::InvalidEndpoint`] for malformed endpoint
    /// strings and [`TokioCelerityError::UnsupportedEndpoint`] for schemes the
    /// runtime does not support.
    pub fn parse(endpoint: &str) -> Result<Self, TokioCelerityError> {
        if let Some(target) = endpoint.strip_prefix("tcp://") {
            if target.is_empty() {
                return Err(TokioCelerityError::InvalidEndpoint(endpoint.to_owned()));
            }
            return Ok(Self::Tcp(target.to_owned()));
        }

        #[cfg(unix)]
        if let Some(path) = endpoint.strip_prefix("ipc://") {
            if path.is_empty() {
                return Err(TokioCelerityError::InvalidEndpoint(endpoint.to_owned()));
            }
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(TokioCelerityError::InvalidEndpoint(endpoint.to_owned()));
            }
            return Ok(Self::Ipc(path));
        }

        #[cfg(not(unix))]
        if endpoint.starts_with("ipc://") {
            return Err(TokioCelerityError::UnsupportedEndpoint(endpoint.to_owned()));
        }

        if endpoint.contains("://") {
            return Err(TokioCelerityError::UnsupportedEndpoint(endpoint.to_owned()));
        }

        if endpoint.is_empty() {
            return Err(TokioCelerityError::InvalidEndpoint(endpoint.to_owned()));
        }

        Ok(Self::Tcp(endpoint.to_owned()))
    }

    /// Returns the transport kind implied by the endpoint.
    pub fn transport_kind(&self) -> TransportKind {
        match self {
            Self::Tcp(_) => TransportKind::Tcp,
            #[cfg(unix)]
            Self::Ipc(_) => TransportKind::Ipc,
        }
    }

    pub(crate) fn tcp_target(&self) -> Result<&str, TokioCelerityError> {
        match self {
            Self::Tcp(target) => Ok(target),
            #[cfg(unix)]
            Self::Ipc(_) => Err(TokioCelerityError::UnsupportedEndpoint(self.to_string())),
        }
    }

    #[cfg(unix)]
    pub(crate) fn ipc_path(&self) -> Result<&Path, TokioCelerityError> {
        match self {
            Self::Ipc(path) => Ok(path.as_path()),
            Self::Tcp(_) => Err(TokioCelerityError::UnsupportedEndpoint(self.to_string())),
        }
    }

    pub(crate) fn from_local_addr(addr: SocketAddr) -> Self {
        Self::Tcp(addr.to_string())
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp(target) => write!(f, "{target}"),
            #[cfg(unix)]
            Self::Ipc(path) => write!(f, "ipc://{}", path.display()),
        }
    }
}

/// Marker type for future connect-time options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConnectOptions;

/// Listener configuration used when binding an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindOptions {
    /// File mode applied to a newly created IPC socket path.
    pub ipc_mode: u32,
    /// Whether an abandoned IPC socket should be removed before binding.
    pub remove_stale_socket: bool,
    /// Whether the bound IPC socket path should be removed on drop.
    pub remove_on_drop: bool,
    /// Whether missing parent directories should be created automatically.
    pub create_parent_dirs: bool,
}

impl Default for BindOptions {
    fn default() -> Self {
        Self {
            ipc_mode: 0o600,
            remove_stale_socket: true,
            remove_on_drop: true,
            create_parent_dirs: false,
        }
    }
}

/// Runtime metadata derived from an accepted or connected transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportMeta {
    /// The transport family in use.
    pub kind: TransportKind,
    /// Whether the transport is local-only or potentially remote.
    pub link_scope: LinkScope,
    /// Whether NULL security is authorized for this local transport.
    pub null_authorized: bool,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    #[cfg(unix)]
    use std::path::PathBuf;

    use super::{Endpoint, TransportKind};
    use crate::io::TokioCelerityError;

    fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("expected Ok(..), got Err({err:?})"),
        }
    }

    fn err<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected Err(..), got Ok(..)"),
            Err(err) => err,
        }
    }

    #[test]
    fn tcp_helpers_roundtrip() {
        let endpoint = Endpoint::Tcp("127.0.0.1:5555".to_owned());
        assert_eq!(endpoint.transport_kind(), TransportKind::Tcp);
        assert_eq!(ok(endpoint.tcp_target()), "127.0.0.1:5555");

        let derived =
            Endpoint::from_local_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6000));
        assert_eq!(derived.to_string(), "127.0.0.1:6000");
    }

    #[test]
    #[cfg(unix)]
    fn scheme_specific_helpers_reject_the_wrong_endpoint_kind() {
        let tcp = Endpoint::Tcp("127.0.0.1:5555".to_owned());
        let ipc = Endpoint::Ipc(PathBuf::from("/tmp/celerity.sock"));

        assert!(matches!(
            err(tcp.ipc_path()),
            TokioCelerityError::UnsupportedEndpoint(_)
        ));
        assert!(matches!(
            err(ipc.tcp_target()),
            TokioCelerityError::UnsupportedEndpoint(_)
        ));
    }
}
