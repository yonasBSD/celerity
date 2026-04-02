use std::io::{self, IoSlice};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::path::{Path, PathBuf};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

use crate::{LinkScope, LocalAuthPolicy};

use super::{BindOptions, Endpoint, TokioCelerityError, TransportKind, TransportMeta};

#[derive(Debug)]
pub enum AnyStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Ipc(UnixStream),
}

impl From<TcpStream> for AnyStream {
    fn from(stream: TcpStream) -> Self {
        Self::Tcp(stream)
    }
}

#[cfg(unix)]
impl From<UnixStream> for AnyStream {
    fn from(stream: UnixStream) -> Self {
        Self::Ipc(stream)
    }
}

impl AnyStream {
    pub(crate) async fn read_buf(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read_buf(buf).await,
            #[cfg(unix)]
            Self::Ipc(stream) => stream.read_buf(buf).await,
        }
    }

    pub(crate) async fn write_all_vectored(&mut self, chunks: &[Bytes]) -> io::Result<()> {
        let mut index = 0_usize;
        let mut offset = 0_usize;

        while index < chunks.len() {
            let mut slices = Vec::with_capacity(chunks.len() - index);
            if offset > 0 {
                slices.push(IoSlice::new(&chunks[index][offset..]));
                for chunk in &chunks[index + 1..] {
                    slices.push(IoSlice::new(chunk));
                }
            } else {
                for chunk in &chunks[index..] {
                    slices.push(IoSlice::new(chunk));
                }
            }

            let written = match self {
                Self::Tcp(stream) => stream.write_vectored(&slices).await?,
                #[cfg(unix)]
                Self::Ipc(stream) => stream.write_vectored(&slices).await?,
            };
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write returned zero",
                ));
            }

            let mut consumed = written;
            while consumed > 0 {
                let current = chunks[index].len() - offset;
                if consumed < current {
                    offset += consumed;
                    consumed = 0;
                } else {
                    consumed -= current;
                    index += 1;
                    offset = 0;
                }
            }
        }

        Ok(())
    }
}

pub(crate) enum AnyListener {
    Tcp {
        listener: TcpListener,
        endpoint: Endpoint,
    },
    #[cfg(unix)]
    Ipc {
        listener: UnixListener,
        endpoint: Endpoint,
        guard: IpcGuard,
    },
}

impl AnyListener {
    pub(crate) async fn accept(&self) -> Result<(AnyStream, TransportMeta), TokioCelerityError> {
        match self {
            Self::Tcp { listener, .. } => {
                let (stream, addr) = listener.accept().await?;
                stream.set_nodelay(true)?;
                Ok((
                    AnyStream::Tcp(stream),
                    TransportMeta {
                        kind: TransportKind::Tcp,
                        link_scope: classify_link_scope(addr),
                        null_authorized: addr.ip().is_loopback(),
                    },
                ))
            }
            #[cfg(unix)]
            Self::Ipc {
                listener, guard, ..
            } => {
                let (stream, _) = listener.accept().await?;
                Ok((
                    AnyStream::Ipc(stream),
                    TransportMeta {
                        kind: TransportKind::Ipc,
                        link_scope: LinkScope::Local,
                        null_authorized: guard.null_authorized,
                    },
                ))
            }
        }
    }

    pub(crate) fn endpoint(&self) -> &Endpoint {
        match self {
            Self::Tcp { endpoint, .. } => endpoint,
            #[cfg(unix)]
            Self::Ipc { endpoint, .. } => endpoint,
        }
    }

    pub(crate) fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp { listener, .. } => listener.local_addr().ok(),
            #[cfg(unix)]
            Self::Ipc { .. } => None,
        }
    }
}

#[cfg(unix)]
pub(crate) struct IpcGuard {
    path: PathBuf,
    dev: u64,
    ino: u64,
    remove_on_drop: bool,
    null_authorized: bool,
}

#[cfg(unix)]
impl Drop for IpcGuard {
    fn drop(&mut self) {
        if !self.remove_on_drop {
            return;
        }

        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.dev() == self.dev && metadata.ino() == self.ino {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(crate) fn classify_link_scope(addr: SocketAddr) -> LinkScope {
    if addr.ip().is_loopback() {
        LinkScope::Local
    } else {
        LinkScope::NonLocal
    }
}

pub(crate) async fn connect_any_stream(
    endpoint: &Endpoint,
    local_auth: LocalAuthPolicy,
) -> Result<(AnyStream, TransportMeta), TokioCelerityError> {
    match endpoint {
        Endpoint::Tcp(_) => connect_tcp(endpoint).await,
        #[cfg(unix)]
        Endpoint::Ipc(_) => connect_ipc(endpoint, local_auth).await,
    }
}

async fn connect_tcp(
    endpoint: &Endpoint,
) -> Result<(AnyStream, TransportMeta), TokioCelerityError> {
    let target = endpoint.tcp_target()?;
    let mut addrs = lookup_host(target)
        .await
        .map_err(|source| TokioCelerityError::Resolve {
            endpoint: endpoint.to_string(),
            source,
        })?;

    let mut last_error = None;
    let mut saw_address = false;
    while let Some(addr) = addrs.next() {
        saw_address = true;
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok((
                    AnyStream::Tcp(stream),
                    TransportMeta {
                        kind: TransportKind::Tcp,
                        link_scope: classify_link_scope(addr),
                        null_authorized: addr.ip().is_loopback(),
                    },
                ));
            }
            Err(err) => last_error = Some(err),
        }
    }

    if !saw_address {
        return Err(TokioCelerityError::InvalidEndpoint(endpoint.to_string()));
    }

    Err(TokioCelerityError::Connect {
        endpoint: endpoint.to_string(),
        source: last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "no resolved addresses")
        }),
    })
}

#[cfg(unix)]
async fn connect_ipc(
    endpoint: &Endpoint,
    local_auth: LocalAuthPolicy,
) -> Result<(AnyStream, TransportMeta), TokioCelerityError> {
    let path = endpoint.ipc_path()?;
    let inspection = inspect_ipc_path(path).map_err(|reason| TokioCelerityError::LocalAuth {
        endpoint: endpoint.to_string(),
        reason,
    })?;
    if local_auth == LocalAuthPolicy::FilesystemStrict && !inspection.null_authorized {
        return Err(TokioCelerityError::LocalAuth {
            endpoint: endpoint.to_string(),
            reason: "socket path or parent directory failed strict ownership checks".to_owned(),
        });
    }

    let stream = UnixStream::connect(path)
        .await
        .map_err(|source| TokioCelerityError::Connect {
            endpoint: endpoint.to_string(),
            source,
        })?;

    Ok((
        AnyStream::Ipc(stream),
        TransportMeta {
            kind: TransportKind::Ipc,
            link_scope: LinkScope::Local,
            null_authorized: inspection.null_authorized,
        },
    ))
}

pub(crate) async fn bind_any_listener(
    endpoint: &Endpoint,
    bind_options: BindOptions,
    local_auth: LocalAuthPolicy,
) -> Result<AnyListener, TokioCelerityError> {
    match endpoint {
        Endpoint::Tcp(_) => bind_tcp_listener(endpoint).await,
        #[cfg(unix)]
        Endpoint::Ipc(_) => bind_ipc_listener(endpoint, bind_options, local_auth).await,
    }
}

async fn bind_tcp_listener(endpoint: &Endpoint) -> Result<AnyListener, TokioCelerityError> {
    let target = endpoint.tcp_target()?;
    let listener = TcpListener::bind(target)
        .await
        .map_err(|source| TokioCelerityError::Bind {
            endpoint: endpoint.to_string(),
            source,
        })?;
    let actual = Endpoint::from_local_addr(listener.local_addr()?);

    Ok(AnyListener::Tcp {
        listener,
        endpoint: actual,
    })
}

#[cfg(unix)]
async fn bind_ipc_listener(
    endpoint: &Endpoint,
    bind_options: BindOptions,
    local_auth: LocalAuthPolicy,
) -> Result<AnyListener, TokioCelerityError> {
    let path = endpoint.ipc_path()?;
    if bind_options.create_parent_dirs {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| TokioCelerityError::Bind {
                endpoint: endpoint.to_string(),
                source,
            })?;
        }
    }

    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(TokioCelerityError::Bind {
                endpoint: endpoint.to_string(),
                source: io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "path exists and is not a socket",
                ),
            });
        }

        match UnixStream::connect(path).await {
            Ok(_) => {
                return Err(TokioCelerityError::Bind {
                    endpoint: endpoint.to_string(),
                    source: io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "socket already has a live listener",
                    ),
                });
            }
            Err(err)
                if bind_options.remove_stale_socket
                    && matches!(
                        err.kind(),
                        io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::NotFound
                            | io::ErrorKind::AddrNotAvailable
                    ) =>
            {
                std::fs::remove_file(path).map_err(|source| TokioCelerityError::Bind {
                    endpoint: endpoint.to_string(),
                    source,
                })?;
            }
            Err(err) => {
                return Err(TokioCelerityError::Bind {
                    endpoint: endpoint.to_string(),
                    source: err,
                });
            }
        }
    }

    let listener = UnixListener::bind(path).map_err(|source| TokioCelerityError::Bind {
        endpoint: endpoint.to_string(),
        source,
    })?;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(bind_options.ipc_mode))
        .map_err(|source| TokioCelerityError::Bind {
            endpoint: endpoint.to_string(),
            source,
        })?;

    let metadata = std::fs::symlink_metadata(path).map_err(|source| TokioCelerityError::Bind {
        endpoint: endpoint.to_string(),
        source,
    })?;
    let inspection = inspect_ipc_path(path).map_err(|reason| TokioCelerityError::LocalAuth {
        endpoint: endpoint.to_string(),
        reason,
    })?;
    if local_auth == LocalAuthPolicy::FilesystemStrict && !inspection.null_authorized {
        return Err(TokioCelerityError::LocalAuth {
            endpoint: endpoint.to_string(),
            reason: "socket path or parent directory failed strict ownership checks".to_owned(),
        });
    }

    Ok(AnyListener::Ipc {
        listener,
        endpoint: Endpoint::Ipc(path.to_path_buf()),
        guard: IpcGuard {
            path: path.to_path_buf(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            remove_on_drop: bind_options.remove_on_drop,
            null_authorized: inspection.null_authorized,
        },
    })
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
struct IpcInspection {
    null_authorized: bool,
}

#[cfg(unix)]
fn inspect_ipc_path(path: &Path) -> Result<IpcInspection, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat socket path: {err}"))?;
    if !metadata.file_type().is_socket() {
        return Err("IPC endpoint is not a socket".to_owned());
    }

    let parent = path
        .parent()
        .ok_or_else(|| "IPC endpoint has no parent directory".to_owned())?;
    let parent_metadata = std::fs::metadata(parent)
        .map_err(|err| format!("failed to stat parent directory: {err}"))?;

    let current_uid = unsafe { libc::geteuid() };
    let owner_matches = metadata.uid() == current_uid;
    let parent_owner_matches = parent_metadata.uid() == current_uid;
    let parent_world_writable = parent_metadata.mode() & 0o002 != 0;
    let socket_private_enough = metadata.mode() & 0o077 == 0;

    Ok(IpcInspection {
        null_authorized: owner_matches
            && parent_owner_matches
            && !parent_world_writable
            && socket_private_enough,
    })
}
