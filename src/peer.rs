use std::collections::VecDeque;

use bytes::Bytes;

use crate::security::{HandshakeComplete, Mechanism};
use crate::wire::{
    Command, FrameFlags, GREETING_SIZE, InputBuffer, decode_command, decode_greeting,
    encode_greeting, greeting_as_server, try_decode_frame,
};
use crate::{
    MetadataMap, OutboundItem, PeerConfig, PeerEvent, ProtocolAction, ProtocolError,
    SecurityMechanism, SecurityRole,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerState {
    Greeting,
    Handshake,
    Traffic,
    Closed,
}

#[derive(Debug)]
pub struct CelerityPeer {
    config: PeerConfig,
    local_metadata: MetadataMap,
    input: InputBuffer,
    mechanism: Mechanism,
    state: PeerState,
    output: VecDeque<ProtocolAction>,
    current_message: Vec<Bytes>,
    terminal_error: Option<ProtocolError>,
}

impl CelerityPeer {
    pub fn new(config: PeerConfig) -> Self {
        let mechanism = Mechanism::new(&config);
        let mut output = VecDeque::new();
        let mut state = PeerState::Greeting;
        let mut terminal_error = None;
        let mut local_metadata = MetadataMap::new();

        match config
            .validate_policy()
            .and_then(|()| config.handshake_metadata())
        {
            Ok(metadata) => {
                local_metadata = metadata;
                output.push_back(ProtocolAction::Write(encode_greeting(&config)));
            }
            Err(err) => {
                state = PeerState::Closed;
                terminal_error = Some(err);
            }
        }

        Self {
            config,
            local_metadata,
            input: InputBuffer::default(),
            mechanism,
            state,
            output,
            current_message: Vec::new(),
            terminal_error,
        }
    }

    pub fn handle_input(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        self.handle_input_bytes(Bytes::copy_from_slice(data))
    }

    pub fn handle_input_bytes(&mut self, data: Bytes) -> Result<(), ProtocolError> {
        self.ensure_open()?;
        self.input.push(data);

        loop {
            match self.state {
                PeerState::Greeting => {
                    let Some(bytes) = self.input.take_exact(GREETING_SIZE) else {
                        break;
                    };
                    self.process_greeting(bytes)?;
                }
                PeerState::Handshake => {
                    let Some(frame) = try_decode_frame(&mut self.input)? else {
                        break;
                    };
                    if !frame.flags.contains(FrameFlags::COMMAND) {
                        return self.fail(ProtocolError::UnexpectedMessageDuringHandshake);
                    }

                    let command = decode_command(frame.body)?;
                    self.process_handshake_command(command)?;
                }
                PeerState::Traffic => {
                    let Some(frame) = try_decode_frame(&mut self.input)? else {
                        break;
                    };
                    self.process_traffic_frame(frame.flags, frame.body)?;
                }
                PeerState::Closed => return self.ensure_open(),
            }
        }

        Ok(())
    }

    pub fn submit(&mut self, item: OutboundItem) -> Result<(), ProtocolError> {
        self.ensure_open()?;
        if self.state != PeerState::Traffic {
            return Err(ProtocolError::PeerNotReady);
        }

        for bytes in self.mechanism.encode_outbound(&item)? {
            self.output.push_back(ProtocolAction::Write(bytes));
        }

        Ok(())
    }

    pub fn poll_output(&mut self) -> Option<ProtocolAction> {
        self.output.pop_front()
    }

    fn process_greeting(&mut self, bytes: Bytes) -> Result<(), ProtocolError> {
        let greeting = decode_greeting(bytes)?;
        let expected = self.config.security.mechanism;
        if greeting.mechanism != expected {
            return self.fail(ProtocolError::MechanismMismatch {
                expected,
                actual: greeting.mechanism,
            });
        }

        let expected_as_server = greeting_as_server(
            expected,
            match self.config.security_role {
                SecurityRole::Client => SecurityRole::Server,
                SecurityRole::Server => SecurityRole::Client,
            },
        );

        if greeting.as_server != expected_as_server {
            if expected == SecurityMechanism::Null && greeting.as_server != 0 {
                return self.fail(ProtocolError::InvalidAsServer(greeting.as_server));
            }
            if expected == SecurityMechanism::Curve {
                return self.fail(ProtocolError::InvalidAsServer(greeting.as_server));
            }
        }

        self.state = PeerState::Handshake;
        if let Some(complete) =
            self.mechanism
                .on_greeting(&self.config, &self.local_metadata, &mut self.output)?
        {
            self.finish_handshake(complete);
        }

        Ok(())
    }

    fn process_handshake_command(&mut self, command: Command) -> Result<(), ProtocolError> {
        if let Some(complete) = self.mechanism.on_command(
            &self.config,
            &self.local_metadata,
            command,
            &mut self.output,
        )? {
            self.finish_handshake(complete);
        }

        Ok(())
    }

    fn process_traffic_frame(
        &mut self,
        flags: FrameFlags,
        body: Bytes,
    ) -> Result<(), ProtocolError> {
        if flags.contains(FrameFlags::COMMAND) {
            if !self.current_message.is_empty() {
                return self.fail(ProtocolError::InvalidCommandFrame);
            }

            match decode_command(body)? {
                Command::Ready(_) => self.fail(ProtocolError::UnexpectedTrafficCommand("READY")),
                Command::Error(reason) => self.fail(ProtocolError::RemoteError(
                    String::from_utf8_lossy(&reason).into_owned(),
                )),
                Command::Subscribe(topic) => {
                    self.output
                        .push_back(ProtocolAction::Event(PeerEvent::Subscription {
                            subscribe: true,
                            topic,
                        }));
                    Ok(())
                }
                Command::Cancel(topic) => {
                    self.output
                        .push_back(ProtocolAction::Event(PeerEvent::Subscription {
                            subscribe: false,
                            topic,
                        }));
                    Ok(())
                }
                Command::Hello(_) => self.fail(ProtocolError::UnexpectedTrafficCommand("HELLO")),
                Command::Welcome(_) => {
                    self.fail(ProtocolError::UnexpectedTrafficCommand("WELCOME"))
                }
                Command::Initiate(_) => {
                    self.fail(ProtocolError::UnexpectedTrafficCommand("INITIATE"))
                }
                Command::Message(payload) => self.process_secure_message(payload),
            }
        } else {
            self.process_plain_traffic_frame(flags, body)
        }
    }

    fn process_secure_message(&mut self, payload: Bytes) -> Result<(), ProtocolError> {
        let decrypted = self.mechanism.decode_message(payload)?;
        let mut input = InputBuffer::default();
        input.push(decrypted);

        loop {
            let Some(frame) = try_decode_frame(&mut input)? else {
                if input.remaining() == 0 {
                    return Ok(());
                }
                return self.fail(ProtocolError::InvalidEncryptedMessage);
            };

            if frame.flags.contains(FrameFlags::COMMAND) {
                match decode_command(frame.body)? {
                    Command::Ready(_) => {
                        return self.fail(ProtocolError::UnexpectedTrafficCommand("READY"));
                    }
                    Command::Error(reason) => {
                        return self.fail(ProtocolError::RemoteError(
                            String::from_utf8_lossy(&reason).into_owned(),
                        ));
                    }
                    Command::Subscribe(topic) => {
                        self.output
                            .push_back(ProtocolAction::Event(PeerEvent::Subscription {
                                subscribe: true,
                                topic,
                            }));
                    }
                    Command::Cancel(topic) => {
                        self.output
                            .push_back(ProtocolAction::Event(PeerEvent::Subscription {
                                subscribe: false,
                                topic,
                            }));
                    }
                    Command::Hello(_) => {
                        return self.fail(ProtocolError::UnexpectedTrafficCommand("HELLO"));
                    }
                    Command::Welcome(_) => {
                        return self.fail(ProtocolError::UnexpectedTrafficCommand("WELCOME"));
                    }
                    Command::Initiate(_) => {
                        return self.fail(ProtocolError::UnexpectedTrafficCommand("INITIATE"));
                    }
                    Command::Message(_) => {
                        return self.fail(ProtocolError::InvalidEncryptedMessage);
                    }
                }
            } else {
                self.process_plain_traffic_frame(frame.flags, frame.body)?;
            }
        }
    }

    fn process_plain_traffic_frame(
        &mut self,
        flags: FrameFlags,
        body: Bytes,
    ) -> Result<(), ProtocolError> {
        self.current_message.push(body);
        if flags.contains(FrameFlags::MORE) {
            Ok(())
        } else {
            let message = std::mem::take(&mut self.current_message);
            self.output
                .push_back(ProtocolAction::Event(PeerEvent::Message(message)));
            Ok(())
        }
    }

    fn finish_handshake(&mut self, complete: HandshakeComplete) {
        self.state = PeerState::Traffic;
        self.output
            .push_back(ProtocolAction::Event(PeerEvent::HandshakeComplete {
                peer_socket_type: complete.peer_socket_type,
                metadata: complete.metadata,
            }));
    }

    fn fail<T>(&mut self, err: ProtocolError) -> Result<T, ProtocolError> {
        self.state = PeerState::Closed;
        self.terminal_error = Some(err.clone());
        Err(err)
    }

    fn ensure_open(&self) -> Result<(), ProtocolError> {
        if let Some(err) = &self.terminal_error {
            return Err(err.clone());
        }
        if self.state == PeerState::Closed {
            return Err(ProtocolError::ConnectionClosed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::CelerityPeer;
    use crate::{
        LinkScope, OutboundItem, PeerConfig, PeerEvent, ProtocolAction, ProtocolError,
        SecurityConfig, SecurityRole, SocketType,
    };

    fn local_config(socket_type: SocketType, role: SecurityRole) -> PeerConfig {
        PeerConfig::new(socket_type, role, LinkScope::Local)
    }

    #[cfg(feature = "curve")]
    fn non_local_curve(socket_type: SocketType, role: SecurityRole) -> PeerConfig {
        PeerConfig::new(socket_type, role, LinkScope::NonLocal)
            .with_security(SecurityConfig::curve())
    }

    fn non_local_insecure_null(socket_type: SocketType, role: SecurityRole) -> PeerConfig {
        PeerConfig::new(socket_type, role, LinkScope::NonLocal)
            .with_security(SecurityConfig::null().with_insecure_null(true))
    }

    fn pump(
        left: &mut CelerityPeer,
        right: &mut CelerityPeer,
    ) -> Result<Vec<PeerEvent>, ProtocolError> {
        let mut events = Vec::new();
        let mut progress = true;

        while progress {
            progress = false;

            while let Some(action) = left.poll_output() {
                progress = true;
                match action {
                    ProtocolAction::Write(bytes) => right.handle_input_bytes(bytes)?,
                    ProtocolAction::Event(event) => events.push(event),
                }
            }

            while let Some(action) = right.poll_output() {
                progress = true;
                match action {
                    ProtocolAction::Write(bytes) => left.handle_input_bytes(bytes)?,
                    ProtocolAction::Event(event) => events.push(event),
                }
            }
        }

        Ok(events)
    }

    #[test]
    fn byte_by_byte_greeting_parsing() {
        let mut client = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(local_config(SocketType::Rep, SecurityRole::Server));
        let _ = server.poll_output();

        let greeting = match client.poll_output().unwrap() {
            ProtocolAction::Write(bytes) => bytes,
            ProtocolAction::Event(_) => unreachable!(),
        };

        for byte in greeting.iter().copied().take(greeting.len() - 1) {
            server.handle_input(&[byte]).unwrap();
            assert!(server.poll_output().is_none());
        }

        server
            .handle_input(&[greeting[greeting.len() - 1]])
            .unwrap();
        assert!(server.poll_output().is_none());
    }

    #[test]
    fn null_handshake_completes() {
        let mut client = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(local_config(SocketType::Rep, SecurityRole::Server));

        let events = pump(&mut client, &mut server).unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| matches!(event, PeerEvent::HandshakeComplete { .. }))
        );
    }

    #[test]
    fn incompatible_socket_types_are_rejected() {
        let mut left = CelerityPeer::new(local_config(SocketType::Pub, SecurityRole::Client));
        let mut right = CelerityPeer::new(local_config(SocketType::Pub, SecurityRole::Server));

        let err = pump(&mut left, &mut right).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::IncompatibleSocketTypes {
                local: SocketType::Pub,
                remote: SocketType::Pub,
            }
        );
    }

    #[test]
    #[cfg(feature = "curve")]
    fn curve_handshake_completes() {
        let mut client = CelerityPeer::new(non_local_curve(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(non_local_curve(SocketType::Rep, SecurityRole::Server));

        let events = pump(&mut client, &mut server).unwrap();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| matches!(event, PeerEvent::HandshakeComplete { .. }))
        );
    }

    #[test]
    fn remote_null_is_fail_closed_without_opt_in() {
        let mut peer = CelerityPeer::new(
            PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::NonLocal)
                .with_security(SecurityConfig::null()),
        );
        assert_eq!(
            peer.handle_input(&[]).unwrap_err(),
            ProtocolError::InsecureNullForNonLocal
        );
        assert!(peer.poll_output().is_none());
    }

    #[test]
    fn explicit_insecure_null_opt_in_allows_remote_handshake() {
        let mut client = CelerityPeer::new(non_local_insecure_null(
            SocketType::Req,
            SecurityRole::Client,
        ));
        let mut server = CelerityPeer::new(non_local_insecure_null(
            SocketType::Rep,
            SecurityRole::Server,
        ));

        let events = pump(&mut client, &mut server).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn traffic_messages_emit_events() {
        let mut client = CelerityPeer::new(local_config(SocketType::Req, SecurityRole::Client));
        let mut server = CelerityPeer::new(local_config(SocketType::Rep, SecurityRole::Server));
        let _ = pump(&mut client, &mut server).unwrap();

        client
            .submit(OutboundItem::Message(vec![
                Bytes::from_static(b""),
                Bytes::from_static(b"ping"),
            ]))
            .unwrap();

        let events = pump(&mut client, &mut server).unwrap();
        assert!(events.iter().any(|event| matches!(
            event,
            PeerEvent::Message(message)
                if message == &vec![Bytes::from_static(b""), Bytes::from_static(b"ping")]
        )));
    }
}
