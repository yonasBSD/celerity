use std::collections::VecDeque;
use std::future::{pending, ready};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::{
    CelerityPeer, HwmConfig, HwmPolicy, LinkScope, OutboundItem, PeerConfig, PeerEvent,
    ProtocolAction, SecurityMechanism,
};

use super::transport::{AnyStream, connect_any_stream};
use super::{
    Endpoint, MAX_DRAIN_ACTIONS_PER_TURN, MAX_DRAIN_BYTES_PER_TURN, READ_BUFFER_CAPACITY,
    TokioCelerityError, TransportKind, TransportMeta, capacity_from_hwm,
};

#[derive(Debug, Clone)]
pub(crate) enum DriverStatus {
    CleanShutdown,
    Failed(String),
}

#[derive(Debug)]
pub(crate) enum RuntimeCommand {
    Submit(OutboundItem, oneshot::Sender<()>),
}

#[derive(Debug)]
struct QueuedOutbound {
    item: OutboundItem,
    bytes: usize,
}

#[derive(Debug)]
pub(crate) struct ConnectionHandle {
    pub(crate) command_tx: mpsc::Sender<RuntimeCommand>,
    pub(crate) terminal_rx: watch::Receiver<Option<DriverStatus>>,
}

#[derive(Debug, Clone, Copy)]
struct DrainState {
    handshake_completed: bool,
    has_more: bool,
}

pub struct TokioCelerity {
    command_tx: mpsc::Sender<RuntimeCommand>,
    event_rx: mpsc::Receiver<PeerEvent>,
    task: JoinHandle<Result<(), TokioCelerityError>>,
    terminal_rx: watch::Receiver<Option<DriverStatus>>,
}

impl TokioCelerity {
    pub async fn connect(endpoint: &str, config: PeerConfig) -> Result<Self, TokioCelerityError> {
        let endpoint = Endpoint::parse(endpoint)?;
        let (stream, transport) = connect_any_stream(&endpoint, config.security.local_auth).await?;
        Self::from_stream(stream, transport, config)
    }

    pub fn from_stream<S>(
        stream: S,
        transport: TransportMeta,
        config: PeerConfig,
    ) -> Result<Self, TokioCelerityError>
    where
        S: Into<AnyStream> + Send + 'static,
    {
        let config = apply_transport_policy(config, transport)?;
        config.validate_policy()?;
        let command_capacity = capacity_from_hwm(config.hwm.outbound_messages);
        let event_capacity = capacity_from_hwm(config.hwm.inbound_messages);
        let (command_tx, command_rx) = mpsc::channel(command_capacity);
        let (event_tx, event_rx) = mpsc::channel(event_capacity);
        let (terminal_tx, terminal_rx) = watch::channel(None);
        let stream = stream.into();

        let task = tokio::spawn(async move {
            let result = run_tokio_peer(stream, config, command_rx, event_tx).await;
            let status = match &result {
                Ok(()) => DriverStatus::CleanShutdown,
                Err(err) => DriverStatus::Failed(err.to_string()),
            };
            let _ = terminal_tx.send(Some(status));
            result
        });

        Ok(Self {
            command_tx,
            event_rx,
            task,
            terminal_rx,
        })
    }

    pub async fn send(&self, item: OutboundItem) -> Result<(), TokioCelerityError> {
        send_runtime_command(&self.command_tx, &self.terminal_rx, item).await
    }

    pub async fn try_send(&self, item: OutboundItem) -> Result<(), TokioCelerityError> {
        try_send_runtime_command(&self.command_tx, &self.terminal_rx, item).await
    }

    pub async fn recv(&mut self) -> Option<PeerEvent> {
        self.event_rx.recv().await
    }

    pub async fn join(self) -> Result<(), TokioCelerityError> {
        self.task.await?
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        ConnectionHandle,
        mpsc::Receiver<PeerEvent>,
        JoinHandle<Result<(), TokioCelerityError>>,
    ) {
        (
            ConnectionHandle {
                command_tx: self.command_tx,
                terminal_rx: self.terminal_rx,
            },
            self.event_rx,
            self.task,
        )
    }
}

async fn run_tokio_peer(
    mut stream: AnyStream,
    config: PeerConfig,
    mut command_rx: mpsc::Receiver<RuntimeCommand>,
    event_tx: mpsc::Sender<PeerEvent>,
) -> Result<(), TokioCelerityError> {
    let hwm = config.hwm;
    let handshake_deadline = curve_handshake_deadline(&config);
    let mut peer = CelerityPeer::new(config);
    let mut read_buf = BytesMut::with_capacity(READ_BUFFER_CAPACITY);
    let mut pending: VecDeque<QueuedOutbound> = VecDeque::new();
    let mut pending_bytes = 0_usize;
    // Application sends queue here until the handshake opens the traffic phase.
    let mut ready_for_traffic = false;
    let mut needs_drain = true;

    loop {
        tokio::select! {
            biased;

            _ = wait_for_handshake_deadline(handshake_deadline), if !ready_for_traffic => {
                return Err(TokioCelerityError::HandshakeTimeout);
            }

            _ = ready(()), if needs_drain => {
                // Drain protocol output before taking more input or new commands.
                needs_drain = false;
                let drain = pump_peer_actions(&mut peer, &mut stream, &event_tx, hwm).await?;
                if drain.handshake_completed {
                    ready_for_traffic = true;
                }

                if ready_for_traffic && !pending.is_empty() {
                    // Release everything queued once the peer reports handshake completion.
                    while let Some(queued) = pending.pop_front() {
                        pending_bytes = pending_bytes.saturating_sub(queued.bytes);
                        peer.submit(queued.item)?;
                    }
                    needs_drain = true;
                } else if drain.has_more {
                    needs_drain = true;
                    tokio::task::yield_now().await;
                }
            }

            read = stream.read_buf(&mut read_buf), if should_read(hwm, &read_buf) => {
                let count = read?;
                if count == 0 {
                    return Ok(());
                }

                let chunk = read_buf.split().freeze();
                peer.handle_input_bytes(chunk)?;
                needs_drain = true;
            }

            command = command_rx.recv(), if ready_for_traffic || can_take_command(hwm, pending.len(), pending_bytes) => {
                match command {
                    Some(RuntimeCommand::Submit(item, ack)) => {
                        if ready_for_traffic {
                            peer.submit(item)?;
                            let _ = ack.send(());
                            needs_drain = true;
                        } else if queue_has_headroom(hwm, pending.len(), pending_bytes) {
                            // Before READY, we queue locally instead of touching the peer state.
                            let bytes = outbound_item_bytes(&item);
                            pending_bytes = pending_bytes.saturating_add(bytes);
                            pending.push_back(QueuedOutbound { item, bytes });
                            let _ = ack.send(());
                        } else if hwm.policy == HwmPolicy::DropNewest {
                            let _ = ack.send(());
                        } else {
                            return Err(TokioCelerityError::QueueFull);
                        }
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

fn should_read(hwm: HwmConfig, read_buf: &BytesMut) -> bool {
    read_buf.len() < hwm.inbound_bytes.max(READ_BUFFER_CAPACITY)
}

fn queue_has_headroom(hwm: HwmConfig, pending_messages: usize, pending_bytes: usize) -> bool {
    pending_messages < capacity_from_hwm(hwm.outbound_messages)
        && pending_bytes < hwm.outbound_bytes.max(READ_BUFFER_CAPACITY)
}

fn can_take_command(hwm: HwmConfig, pending_messages: usize, pending_bytes: usize) -> bool {
    hwm.policy == HwmPolicy::DropNewest || queue_has_headroom(hwm, pending_messages, pending_bytes)
}

async fn pump_peer_actions(
    peer: &mut CelerityPeer,
    stream: &mut AnyStream,
    event_tx: &mpsc::Sender<PeerEvent>,
    hwm: HwmConfig,
) -> Result<DrainState, TokioCelerityError> {
    let mut handshake_completed = false;
    // Batch consecutive writes so we do not await for every tiny frame.
    let mut writes = Vec::new();
    let mut actions = 0_usize;
    let mut written_bytes = 0_usize;
    let mut has_more = false;

    while actions < MAX_DRAIN_ACTIONS_PER_TURN && written_bytes < MAX_DRAIN_BYTES_PER_TURN {
        let Some(action) = peer.poll_output() else {
            break;
        };
        actions += 1;

        match action {
            ProtocolAction::Write(bytes) => {
                written_bytes = written_bytes.saturating_add(bytes.len());
                writes.push(bytes);
            }
            ProtocolAction::Event(event) => {
                // Flush pending bytes before surfacing events across an await boundary.
                if !writes.is_empty() {
                    stream.write_all_vectored(&writes).await?;
                    writes.clear();
                }

                if matches!(event, PeerEvent::HandshakeComplete { .. }) {
                    handshake_completed = true;
                }
                forward_peer_event(event_tx, event, hwm).await?;
            }
        }
    }

    if !writes.is_empty() {
        stream.write_all_vectored(&writes).await?;
    }

    if actions == MAX_DRAIN_ACTIONS_PER_TURN || written_bytes >= MAX_DRAIN_BYTES_PER_TURN {
        has_more = true;
    }

    Ok(DrainState {
        handshake_completed,
        has_more,
    })
}

async fn forward_peer_event(
    event_tx: &mpsc::Sender<PeerEvent>,
    event: PeerEvent,
    hwm: HwmConfig,
) -> Result<(), TokioCelerityError> {
    // Only message events are droppable; control flow events must always get through.
    if hwm.policy == HwmPolicy::DropNewest && matches!(event, PeerEvent::Message(_)) {
        return match event_tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(TokioCelerityError::ChannelClosed("peer event channel"))
            }
        };
    }

    event_tx
        .send(event)
        .await
        .map_err(|_| TokioCelerityError::ChannelClosed("peer event channel"))
}

fn curve_handshake_deadline(config: &PeerConfig) -> Option<Instant> {
    if config.security.mechanism != SecurityMechanism::Curve {
        return None;
    }

    let timeout_ms = config.security.curve.as_ref()?.handshake_timeout_ms;
    if timeout_ms == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_millis(timeout_ms))
    }
}

async fn wait_for_handshake_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => pending::<()>().await,
    }
}

pub(crate) async fn send_runtime_command(
    command_tx: &mpsc::Sender<RuntimeCommand>,
    terminal_rx: &watch::Receiver<Option<DriverStatus>>,
    item: OutboundItem,
) -> Result<(), TokioCelerityError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    command_tx
        .send(RuntimeCommand::Submit(item, reply_tx))
        .await
        .map_err(|_| terminal_error(terminal_rx.borrow().as_ref()))?;

    reply_rx
        .await
        .map_err(|_| terminal_error(terminal_rx.borrow().as_ref()))?;

    Ok(())
}

pub(crate) async fn try_send_runtime_command(
    command_tx: &mpsc::Sender<RuntimeCommand>,
    terminal_rx: &watch::Receiver<Option<DriverStatus>>,
    item: OutboundItem,
) -> Result<(), TokioCelerityError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    command_tx
        .try_send(RuntimeCommand::Submit(item, reply_tx))
        .map_err(|err| match err {
            mpsc::error::TrySendError::Full(_) => TokioCelerityError::QueueFull,
            mpsc::error::TrySendError::Closed(_) => terminal_error(terminal_rx.borrow().as_ref()),
        })?;

    reply_rx
        .await
        .map_err(|_| terminal_error(terminal_rx.borrow().as_ref()))?;
    Ok(())
}

fn terminal_error(status: Option<&DriverStatus>) -> TokioCelerityError {
    match status {
        Some(DriverStatus::CleanShutdown) => TokioCelerityError::BackgroundTaskEnded,
        Some(DriverStatus::Failed(message)) => {
            TokioCelerityError::BackgroundTaskFailed(message.clone())
        }
        None => TokioCelerityError::ChannelClosed("connection task"),
    }
}

fn apply_transport_policy(
    mut config: PeerConfig,
    transport: TransportMeta,
) -> Result<PeerConfig, TokioCelerityError> {
    config.link_scope = transport.link_scope;

    if config.security.mechanism == SecurityMechanism::Null {
        match transport.kind {
            TransportKind::Tcp => {
                if transport.link_scope == LinkScope::Local
                    && !config.security.policy.allow_null_loopback
                    && !config.security.allow_insecure_null
                {
                    return Err(TokioCelerityError::LocalAuth {
                        endpoint: "tcp".to_owned(),
                        reason: "NULL is disabled on loopback TCP by policy".to_owned(),
                    });
                }
            }
            TransportKind::Ipc => {
                // IPC NULL can be gated both by policy and filesystem checks.
                if !config.security.policy.allow_null_ipc && !config.security.allow_insecure_null {
                    return Err(TokioCelerityError::LocalAuth {
                        endpoint: "ipc".to_owned(),
                        reason: "NULL is disabled on IPC by policy".to_owned(),
                    });
                }
                if config.security.local_auth == crate::LocalAuthPolicy::FilesystemStrict
                    && !transport.null_authorized
                {
                    return Err(TokioCelerityError::LocalAuth {
                        endpoint: "ipc".to_owned(),
                        reason:
                            "filesystem ownership or permissions are too loose for strict NULL IPC"
                                .to_owned(),
                    });
                }
            }
        }
    }

    Ok(config)
}

fn outbound_item_bytes(item: &OutboundItem) -> usize {
    match item {
        OutboundItem::Message(message) => message.iter().map(Bytes::len).sum(),
        OutboundItem::Subscribe(topic) | OutboundItem::Cancel(topic) => topic.len(),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        HwmConfig, HwmPolicy, LinkScope, LocalAuthPolicy, PeerConfig, SecurityConfig,
        SecurityMechanism, SecurityPolicy, SecurityRole, SocketType,
    };

    use super::{
        DriverStatus, READ_BUFFER_CAPACITY, TransportKind, TransportMeta, apply_transport_policy,
        can_take_command, curve_handshake_deadline, queue_has_headroom, terminal_error,
    };
    use crate::io::TokioCelerityError;

    #[test]
    fn curve_handshake_deadline_depends_on_mechanism_and_timeout() {
        let null_config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local);
        assert!(curve_handshake_deadline(&null_config).is_none());

        let mut curve = crate::CurveConfig::default();
        curve.handshake_timeout_ms = 0;
        let curve_config =
            PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
                .with_security(SecurityConfig::curve().with_curve_config(curve));
        assert!(curve_handshake_deadline(&curve_config).is_none());

        let curve_config =
            PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
                .with_security(SecurityConfig::curve());
        assert!(curve_handshake_deadline(&curve_config).is_some());
    }

    #[test]
    fn queue_helpers_respect_policy_and_capacity() {
        let mut hwm = HwmConfig::default();
        hwm.outbound_messages = 1;
        hwm.outbound_bytes = 1;

        assert!(queue_has_headroom(hwm, 0, 0));
        assert!(!queue_has_headroom(hwm, 1, 0));
        assert!(!queue_has_headroom(hwm, 0, READ_BUFFER_CAPACITY));
        assert!(!can_take_command(hwm, 1, READ_BUFFER_CAPACITY));

        hwm.policy = HwmPolicy::DropNewest;
        assert!(can_take_command(hwm, 1, READ_BUFFER_CAPACITY));
    }

    #[test]
    fn terminal_error_maps_driver_status() {
        assert!(matches!(
            terminal_error(None),
            TokioCelerityError::ChannelClosed("connection task")
        ));
        assert!(matches!(
            terminal_error(Some(&DriverStatus::CleanShutdown)),
            TokioCelerityError::BackgroundTaskEnded
        ));
        assert_eq!(
            terminal_error(Some(&DriverStatus::Failed("boom".to_owned()))).to_string(),
            "background task failed: boom"
        );
    }

    #[test]
    fn apply_transport_policy_rejects_disallowed_loopback_null() {
        let policy = SecurityPolicy {
            allow_null_loopback: false,
            allow_null_ipc: true,
            require_curve_non_local: true,
        };
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::new(SecurityMechanism::Null).with_policy(policy));

        let err = apply_transport_policy(
            config,
            TransportMeta {
                kind: TransportKind::Tcp,
                link_scope: LinkScope::Local,
                null_authorized: true,
            },
        )
        .unwrap_err();
        assert!(matches!(err, TokioCelerityError::LocalAuth { .. }));
    }

    #[test]
    fn apply_transport_policy_rejects_ipc_null_when_policy_disabled() {
        let policy = SecurityPolicy {
            allow_null_loopback: true,
            allow_null_ipc: false,
            require_curve_non_local: true,
        };
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::new(SecurityMechanism::Null).with_policy(policy));

        let err = apply_transport_policy(
            config,
            TransportMeta {
                kind: TransportKind::Ipc,
                link_scope: LinkScope::Local,
                null_authorized: true,
            },
        )
        .unwrap_err();
        assert!(matches!(err, TokioCelerityError::LocalAuth { .. }));
    }

    #[test]
    fn apply_transport_policy_rejects_strict_ipc_without_authorization() {
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::null());
        let err = apply_transport_policy(
            config,
            TransportMeta {
                kind: TransportKind::Ipc,
                link_scope: LinkScope::Local,
                null_authorized: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, TokioCelerityError::LocalAuth { .. }));
    }

    #[test]
    fn apply_transport_policy_allows_relaxed_ipc_null() {
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(
                SecurityConfig::null().with_local_auth_policy(LocalAuthPolicy::FilesystemRelaxed),
            );

        let applied = apply_transport_policy(
            config,
            TransportMeta {
                kind: TransportKind::Ipc,
                link_scope: LinkScope::Local,
                null_authorized: false,
            },
        )
        .unwrap();
        assert_eq!(applied.link_scope, LinkScope::Local);
    }
}
