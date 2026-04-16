use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::{
    HwmConfig, LinkScope, LocalAuthPolicy, Multipart, PatternAction, PeerConfig, PeerEvent,
    PubCore, RepCore, ReqCore, SecurityConfig, SecurityRole, SocketType, SubCore,
};

use super::runtime::{
    ConnectionHandle, TokioCelerity, send_runtime_command, try_send_runtime_command,
};
use super::transport::{AnyListener, bind_any_listener, connect_any_stream};
use super::{
    BindOptions, ConnectOptions, Endpoint, SUBSCRIPTION_SETTLE_DELAY, TokioCelerityError,
    capacity_from_hwm,
};

pub struct PubSocket {
    command_tx: mpsc::Sender<PubCommand>,
    ready_rx: watch::Receiver<usize>,
    endpoint: Endpoint,
    local_addr: Option<SocketAddr>,
    task: JoinHandle<Result<(), TokioCelerityError>>,
}

impl PubSocket {
    pub async fn bind(endpoint: &str) -> Result<Self, TokioCelerityError> {
        Self::bind_with_options(endpoint, BindOptions::default()).await
    }

    pub async fn bind_with_options(
        endpoint: &str,
        bind_options: BindOptions,
    ) -> Result<Self, TokioCelerityError> {
        let endpoint = Endpoint::parse(endpoint)?;
        let listener = bind_any_listener(
            &endpoint,
            bind_options,
            SecurityConfig::default_for(LinkScope::Local).local_auth,
        )
        .await?;
        let local_addr = listener.local_addr();
        let bound_endpoint = listener.endpoint().clone();
        let command_capacity = capacity_from_hwm(HwmConfig::default().outbound_messages);
        let (command_tx, command_rx) = mpsc::channel(command_capacity);
        let (ready_tx, ready_rx) = watch::channel(0_usize);

        let task =
            tokio::spawn(async move { run_pub_socket(listener, command_rx, ready_tx).await });

        Ok(Self {
            command_tx,
            ready_rx,
            endpoint: bound_endpoint,
            local_addr,
            task,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr.expect("publisher is not bound on TCP")
    }

    pub async fn wait_for_subscriber(
        &mut self,
        timeout: std::time::Duration,
    ) -> Result<bool, TokioCelerityError> {
        if *self.ready_rx.borrow() > 0 {
            // Give subscription frames a brief moment to reach the publisher.
            tokio::time::sleep(SUBSCRIPTION_SETTLE_DELAY).await;
            return Ok(true);
        }

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let changed = tokio::time::timeout_at(deadline, self.ready_rx.changed()).await;
            match changed {
                Ok(Ok(())) if *self.ready_rx.borrow() > 0 => {
                    tokio::time::sleep(SUBSCRIPTION_SETTLE_DELAY).await;
                    return Ok(true);
                }
                Ok(Ok(())) => continue,
                Ok(Err(_)) => return Ok(*self.ready_rx.borrow() > 0),
                Err(_) => return Ok(*self.ready_rx.borrow() > 0),
            }
        }
    }

    pub async fn send(&self, message: Multipart) -> Result<(), TokioCelerityError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(PubCommand::Send(message, reply_tx))
            .await
            .map_err(|_| TokioCelerityError::ChannelClosed("pub command channel"))?;
        reply_rx
            .await
            .map_err(|_| TokioCelerityError::ChannelClosed("pub command response channel"))?
    }

    pub async fn join(self) -> Result<(), TokioCelerityError> {
        self.task.await?
    }
}

pub struct SubSocket {
    command_tx: mpsc::Sender<SubCommand>,
    message_rx: mpsc::Receiver<Result<Multipart, TokioCelerityError>>,
    task: JoinHandle<Result<(), TokioCelerityError>>,
}

impl SubSocket {
    pub async fn connect(endpoint: &str) -> Result<Self, TokioCelerityError> {
        Self::connect_with_options(endpoint, ConnectOptions).await
    }

    pub async fn connect_with_options(
        endpoint: &str,
        _options: ConnectOptions,
    ) -> Result<Self, TokioCelerityError> {
        let endpoint = Endpoint::parse(endpoint)?;
        let (stream, transport) =
            connect_any_stream(&endpoint, LocalAuthPolicy::FilesystemStrict).await?;
        let config = PeerConfig::new(SocketType::Sub, SecurityRole::Client, transport.link_scope);
        let connection = TokioCelerity::from_stream(stream, transport, config)?;
        let (command_tx, command_rx) =
            mpsc::channel(capacity_from_hwm(HwmConfig::default().outbound_messages));
        let (message_tx, message_rx) =
            mpsc::channel(capacity_from_hwm(HwmConfig::default().inbound_messages));
        let task =
            tokio::spawn(async move { run_sub_socket(connection, command_rx, message_tx).await });

        Ok(Self {
            command_tx,
            message_rx,
            task,
        })
    }

    pub async fn subscribe(&self, topic: Bytes) -> Result<(), TokioCelerityError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SubCommand::Subscribe(topic, reply_tx))
            .await
            .map_err(|_| TokioCelerityError::ChannelClosed("sub command channel"))?;
        reply_rx
            .await
            .map_err(|_| TokioCelerityError::ChannelClosed("sub command response channel"))?
    }

    pub async fn cancel(&self, topic: Bytes) -> Result<(), TokioCelerityError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(SubCommand::Cancel(topic, reply_tx))
            .await
            .map_err(|_| TokioCelerityError::ChannelClosed("sub command channel"))?;
        reply_rx
            .await
            .map_err(|_| TokioCelerityError::ChannelClosed("sub command response channel"))?
    }

    pub async fn recv(&mut self) -> Result<Multipart, TokioCelerityError> {
        match self.message_rx.recv().await {
            Some(result) => result,
            None => Err(self.join_on_closed_channel().await),
        }
    }

    pub async fn join(self) -> Result<(), TokioCelerityError> {
        self.task.await?
    }

    async fn join_on_closed_channel(&mut self) -> TokioCelerityError {
        match (&mut self.task).await {
            Ok(Ok(())) => TokioCelerityError::BackgroundTaskEnded,
            Ok(Err(err)) => err,
            Err(err) => TokioCelerityError::Join(err),
        }
    }
}

pub struct ReqSocket {
    command_tx: mpsc::Sender<ReqCommand>,
    task: JoinHandle<Result<(), TokioCelerityError>>,
}

impl ReqSocket {
    pub async fn connect(endpoint: &str) -> Result<Self, TokioCelerityError> {
        let endpoint = Endpoint::parse(endpoint)?;
        let (stream, transport) =
            connect_any_stream(&endpoint, LocalAuthPolicy::FilesystemStrict).await?;
        let config = PeerConfig::new(SocketType::Req, SecurityRole::Client, transport.link_scope);
        let connection = TokioCelerity::from_stream(stream, transport, config)?;
        let (command_tx, command_rx) =
            mpsc::channel(capacity_from_hwm(HwmConfig::default().outbound_messages));
        let task = tokio::spawn(async move { run_req_socket(connection, command_rx).await });

        Ok(Self { command_tx, task })
    }

    pub async fn request(&self, message: Multipart) -> Result<Multipart, TokioCelerityError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(ReqCommand::Request(message, reply_tx))
            .await
            .map_err(|_| TokioCelerityError::ChannelClosed("req command channel"))?;
        reply_rx
            .await
            .map_err(|_| TokioCelerityError::ChannelClosed("req response channel"))?
    }

    pub async fn join(self) -> Result<(), TokioCelerityError> {
        self.task.await?
    }
}

pub struct RepSocket {
    command_tx: mpsc::Sender<RepCommand>,
    request_rx: mpsc::Receiver<Result<Multipart, TokioCelerityError>>,
    endpoint: Endpoint,
    local_addr: Option<SocketAddr>,
    task: JoinHandle<Result<(), TokioCelerityError>>,
}

impl RepSocket {
    pub async fn bind(endpoint: &str) -> Result<Self, TokioCelerityError> {
        Self::bind_with_options(endpoint, BindOptions::default()).await
    }

    pub async fn bind_with_options(
        endpoint: &str,
        bind_options: BindOptions,
    ) -> Result<Self, TokioCelerityError> {
        let endpoint = Endpoint::parse(endpoint)?;
        let listener = bind_any_listener(
            &endpoint,
            bind_options,
            SecurityConfig::default_for(LinkScope::Local).local_auth,
        )
        .await?;
        let local_addr = listener.local_addr();
        let bound_endpoint = listener.endpoint().clone();
        let (command_tx, command_rx) =
            mpsc::channel(capacity_from_hwm(HwmConfig::default().outbound_messages));
        let (request_tx, request_rx) =
            mpsc::channel(capacity_from_hwm(HwmConfig::default().inbound_messages));
        let task =
            tokio::spawn(async move { run_rep_socket(listener, command_rx, request_tx).await });

        Ok(Self {
            command_tx,
            request_rx,
            endpoint: bound_endpoint,
            local_addr,
            task,
        })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr.expect("responder is not bound on TCP")
    }

    pub async fn recv(&mut self) -> Result<Multipart, TokioCelerityError> {
        match self.request_rx.recv().await {
            Some(result) => result,
            None => Err(self.join_on_closed_channel().await),
        }
    }

    pub async fn reply(&self, message: Multipart) -> Result<(), TokioCelerityError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(RepCommand::Reply(message, reply_tx))
            .await
            .map_err(|_| TokioCelerityError::ChannelClosed("rep command channel"))?;
        reply_rx
            .await
            .map_err(|_| TokioCelerityError::ChannelClosed("rep command response channel"))?
    }

    pub async fn join(self) -> Result<(), TokioCelerityError> {
        self.task.await?
    }

    async fn join_on_closed_channel(&mut self) -> TokioCelerityError {
        match (&mut self.task).await {
            Ok(Ok(())) => TokioCelerityError::BackgroundTaskEnded,
            Ok(Err(err)) => err,
            Err(err) => TokioCelerityError::Join(err),
        }
    }
}

#[derive(Debug)]
enum PubCommand {
    Send(Multipart, oneshot::Sender<Result<(), TokioCelerityError>>),
}

#[derive(Debug)]
enum SubCommand {
    Subscribe(Bytes, oneshot::Sender<Result<(), TokioCelerityError>>),
    Cancel(Bytes, oneshot::Sender<Result<(), TokioCelerityError>>),
}

#[derive(Debug)]
enum ReqCommand {
    Request(
        Multipart,
        oneshot::Sender<Result<Multipart, TokioCelerityError>>,
    ),
}

#[derive(Debug)]
enum RepCommand {
    Reply(Multipart, oneshot::Sender<Result<(), TokioCelerityError>>),
}

#[derive(Debug)]
enum PeerUpdate {
    Event { peer: u64, event: PeerEvent },
    Closed { peer: u64 },
}

async fn run_pub_socket(
    listener: AnyListener,
    mut command_rx: mpsc::Receiver<PubCommand>,
    ready_tx: watch::Sender<usize>,
) -> Result<(), TokioCelerityError> {
    let (update_tx, mut update_rx) = mpsc::unbounded_channel();
    let mut pub_core = PubCore::new();
    let mut peers = HashMap::new();
    let mut ready_peers = HashSet::new();
    let mut next_peer_id = 0_u64;

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, transport) = accept?;
                let peer = next_peer_id;
                next_peer_id = next_peer_id.wrapping_add(1);
                let config = PeerConfig::new(SocketType::Pub, SecurityRole::Server, transport.link_scope);
                let connection = TokioCelerity::from_stream(stream, transport, config)?;
                let handle = spawn_peer_forwarder(peer, connection, update_tx.clone());
                peers.insert(peer, handle);
            }
            command = command_rx.recv() => {
                match command {
                    Some(PubCommand::Send(message, reply_tx)) => {
                        let result = dispatch_pub_message(&pub_core, &peers, message).await;
                        let _ = reply_tx.send(result);
                    }
                    None => return Ok(()),
                }
            }
            update = update_rx.recv() => {
                match update {
                    Some(PeerUpdate::Event { peer, event }) => {
                        if matches!(event, PeerEvent::HandshakeComplete { .. }) {
                            // A transport is publish-ready only after the ZMTP handshake finishes.
                            ready_peers.insert(peer);
                            let _ = ready_tx.send(ready_peers.len());
                        }
                        if let PeerEvent::Subscription { .. } = &event {
                            pub_core.on_peer_event(peer, event)?;
                        }
                    }
                    Some(PeerUpdate::Closed { peer }) => {
                        pub_core.remove_peer(peer);
                        peers.remove(&peer);
                        ready_peers.remove(&peer);
                        let _ = ready_tx.send(ready_peers.len());
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

async fn dispatch_pub_message(
    pub_core: &PubCore<u64>,
    peers: &HashMap<u64, ConnectionHandle>,
    message: Multipart,
) -> Result<(), TokioCelerityError> {
    for action in pub_core.publish(&message)? {
        if let PatternAction::Send { peer, item } = action {
            if let Some(handle) = peers.get(&peer) {
                // PUB fanout is best-effort; a full peer queue does not stall everyone else.
                match try_send_runtime_command(&handle.command_tx, &handle.terminal_rx, item).await
                {
                    Ok(()) | Err(TokioCelerityError::QueueFull) => {}
                    Err(TokioCelerityError::BackgroundTaskEnded)
                    | Err(TokioCelerityError::ChannelClosed(_)) => {}
                    Err(err) => return Err(err),
                }
            }
        }
    }

    Ok(())
}

async fn run_sub_socket(
    mut connection: TokioCelerity,
    mut command_rx: mpsc::Receiver<SubCommand>,
    message_tx: mpsc::Sender<Result<Multipart, TokioCelerityError>>,
) -> Result<(), TokioCelerityError> {
    let peer = 0_u64;
    let mut sub_core = SubCore::new();
    let _ = sub_core.add_peer(peer);

    let result = loop {
        tokio::select! {
            command = command_rx.recv() => {
                match command {
                    Some(SubCommand::Subscribe(topic, reply_tx)) => {
                        let result = async {
                            for action in sub_core.subscribe(&topic)? {
                                send_sub_action(&connection, action).await?;
                            }
                            Ok(())
                        }.await;
                        let _ = reply_tx.send(result);
                    }
                    Some(SubCommand::Cancel(topic, reply_tx)) => {
                        let result = async {
                            for action in sub_core.cancel(&topic)? {
                                send_sub_action(&connection, action).await?;
                            }
                            Ok(())
                        }.await;
                        let _ = reply_tx.send(result);
                    }
                    None => break Ok(()),
                }
            }
            event = connection.recv() => {
                match event {
                    Some(event) => {
                        for action in sub_core.on_peer_event(peer, event)? {
                            if let PatternAction::Deliver { message, .. } = action {
                                message_tx
                                    .send(Ok(message))
                                    .await
                                    .map_err(|_| TokioCelerityError::ChannelClosed("sub message channel"))?;
                            }
                        }
                    }
                    None => break connection.join().await,
                }
            }
        }
    };

    if let Err(err) = &result {
        let _ = message_tx.send(Err(background_error(err))).await;
    }

    result
}

async fn send_sub_action(
    connection: &TokioCelerity,
    action: PatternAction<u64>,
) -> Result<(), TokioCelerityError> {
    if let PatternAction::Send { item, .. } = action {
        connection.send(item).await?;
    }
    Ok(())
}

async fn run_req_socket(
    mut connection: TokioCelerity,
    mut command_rx: mpsc::Receiver<ReqCommand>,
) -> Result<(), TokioCelerityError> {
    let peer = 0_u64;
    let mut req_core = ReqCore::new();
    req_core.add_peer(peer);
    let mut queue = VecDeque::new();
    let mut in_flight: Option<oneshot::Sender<Result<Multipart, TokioCelerityError>>> = None;

    let result = loop {
        tokio::select! {
            command = command_rx.recv() => {
                match command {
                    Some(ReqCommand::Request(message, reply_tx)) => {
                        queue.push_back((message, reply_tx));
                        drive_req_queue(&mut req_core, &connection, &mut queue, &mut in_flight).await?;
                    }
                    None => break Ok(()),
                }
            }
            event = connection.recv() => {
                match event {
                    Some(event) => {
                        for action in req_core.on_peer_event(peer, event)? {
                            if let PatternAction::Deliver { message, .. } = action {
                                if let Some(reply_tx) = in_flight.take() {
                                    let _ = reply_tx.send(Ok(message));
                                }
                            }
                        }
                        drive_req_queue(&mut req_core, &connection, &mut queue, &mut in_flight).await?;
                    }
                    None => break connection.join().await,
                }
            }
        }
    };

    if let Err(err) = &result {
        while let Some((_, reply_tx)) = queue.pop_front() {
            let _ = reply_tx.send(Err(background_error(err)));
        }
        if let Some(reply_tx) = in_flight.take() {
            let _ = reply_tx.send(Err(background_error(err)));
        }
    }

    result
}

async fn drive_req_queue(
    req_core: &mut ReqCore<u64>,
    connection: &TokioCelerity,
    queue: &mut VecDeque<(
        Multipart,
        oneshot::Sender<Result<Multipart, TokioCelerityError>>,
    )>,
    in_flight: &mut Option<oneshot::Sender<Result<Multipart, TokioCelerityError>>>,
) -> Result<(), TokioCelerityError> {
    if in_flight.is_some() {
        // REQ cannot send the next request until the current reply lands.
        return Ok(());
    }

    let Some((message, reply_tx)) = queue.pop_front() else {
        return Ok(());
    };

    match req_core.send(message)? {
        PatternAction::Send { item, .. } => {
            connection.send(item).await?;
            *in_flight = Some(reply_tx);
        }
        PatternAction::Deliver { .. } => {}
    }

    Ok(())
}

async fn run_rep_socket(
    listener: AnyListener,
    mut command_rx: mpsc::Receiver<RepCommand>,
    request_tx: mpsc::Sender<Result<Multipart, TokioCelerityError>>,
) -> Result<(), TokioCelerityError> {
    let (update_tx, mut update_rx) = mpsc::unbounded_channel();
    let mut rep_core = RepCore::new();
    let mut peers = HashMap::new();
    let mut next_peer_id = 0_u64;

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, transport) = accept?;
                let peer = next_peer_id;
                next_peer_id = next_peer_id.wrapping_add(1);
                // Register the peer before events arrive so request routing has a queue.
                rep_core.add_peer(peer);
                let config = PeerConfig::new(SocketType::Rep, SecurityRole::Server, transport.link_scope);
                let connection = TokioCelerity::from_stream(stream, transport, config)?;
                let handle = spawn_peer_forwarder(peer, connection, update_tx.clone());
                peers.insert(peer, handle);
            }
            command = command_rx.recv() => {
                match command {
                    Some(RepCommand::Reply(message, reply_tx)) => {
                        let result = async {
                            let actions = rep_core.reply(message)?;
                            apply_rep_actions(&peers, &request_tx, actions).await
                        }.await;
                        let _ = reply_tx.send(result);
                    }
                    None => return Ok(()),
                }
            }
            update = update_rx.recv() => {
                match update {
                    Some(PeerUpdate::Event { peer, event }) => {
                        for action in rep_core.on_peer_event(peer, event)? {
                            if let PatternAction::Deliver { message, .. } = action {
                                request_tx
                                    .send(Ok(message))
                                    .await
                                    .map_err(|_| TokioCelerityError::ChannelClosed("rep request channel"))?;
                            }
                        }
                    }
                    Some(PeerUpdate::Closed { peer }) => {
                        peers.remove(&peer);
                        let actions = rep_core.remove_peer(peer)?;
                        apply_rep_actions(&peers, &request_tx, actions).await?;
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

async fn apply_rep_actions(
    peers: &HashMap<u64, ConnectionHandle>,
    request_tx: &mpsc::Sender<Result<Multipart, TokioCelerityError>>,
    actions: Vec<PatternAction<u64>>,
) -> Result<(), TokioCelerityError> {
    for action in actions {
        match action {
            PatternAction::Send { peer, item } => {
                let Some(handle) = peers.get(&peer) else {
                    return Err(TokioCelerityError::BackgroundTaskEnded);
                };
                send_runtime_command(&handle.command_tx, &handle.terminal_rx, item).await?;
            }
            PatternAction::Deliver { message, .. } => {
                request_tx
                    .send(Ok(message))
                    .await
                    .map_err(|_| TokioCelerityError::ChannelClosed("rep request channel"))?;
            }
        }
    }
    Ok(())
}

fn spawn_peer_forwarder(
    peer: u64,
    connection: TokioCelerity,
    update_tx: mpsc::UnboundedSender<PeerUpdate>,
) -> ConnectionHandle {
    let (handle, mut event_rx, task) = connection.into_parts();
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            if update_tx.send(PeerUpdate::Event { peer, event }).is_err() {
                return;
            }
        }

        let _ = task.await;
        let _ = update_tx.send(PeerUpdate::Closed { peer });
    });
    handle
}

fn background_error(err: &TokioCelerityError) -> TokioCelerityError {
    TokioCelerityError::BackgroundTaskFailed(err.to_string())
}
