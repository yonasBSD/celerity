use std::collections::VecDeque;

use bytes::Bytes;

use crate::wire::{
    Command, decode_metadata, encode_command, encode_message_frame_actions, encode_ready,
};
use crate::{MetadataMap, OutboundItem, PeerConfig, ProtocolAction, ProtocolError, SecurityRole};

use super::{HandshakeComplete, MechanismDriver, validate_remote_metadata};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NullMechanism {
    sent_ready: bool,
    received_ready: bool,
    peer_metadata: Option<MetadataMap>,
}

impl MechanismDriver for NullMechanism {
    fn on_greeting(
        &mut self,
        config: &PeerConfig,
        local_metadata: &MetadataMap,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<Option<HandshakeComplete>, ProtocolError> {
        if matches!(config.security_role, SecurityRole::Client) && !self.sent_ready {
            output.push_back(ProtocolAction::Write(encode_ready(local_metadata)?));
            self.sent_ready = true;
        }

        self.finish_if_ready()
    }

    fn on_command(
        &mut self,
        config: &PeerConfig,
        local_metadata: &MetadataMap,
        command: Command,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<Option<HandshakeComplete>, ProtocolError> {
        match command {
            Command::Ready(bytes) => {
                let metadata = decode_metadata(bytes)?;
                let _ = validate_remote_metadata(config, &metadata)?;
                self.received_ready = true;
                self.peer_metadata = Some(metadata);

                if matches!(config.security_role, SecurityRole::Server) && !self.sent_ready {
                    output.push_back(ProtocolAction::Write(encode_ready(local_metadata)?));
                    self.sent_ready = true;
                }

                self.finish_if_ready()
            }
            Command::Error(reason) => Err(ProtocolError::RemoteError(
                String::from_utf8_lossy(&reason).into_owned(),
            )),
            Command::Subscribe(_) => Err(ProtocolError::UnexpectedHandshakeCommand("SUBSCRIBE")),
            Command::Cancel(_) => Err(ProtocolError::UnexpectedHandshakeCommand("CANCEL")),
            Command::Hello(_) => Err(ProtocolError::UnexpectedHandshakeCommand("HELLO")),
            Command::Welcome(_) => Err(ProtocolError::UnexpectedHandshakeCommand("WELCOME")),
            Command::Initiate(_) => Err(ProtocolError::UnexpectedHandshakeCommand("INITIATE")),
            Command::Message(_) => Err(ProtocolError::UnexpectedHandshakeCommand("MESSAGE")),
        }
    }

    fn encode_outbound(
        &mut self,
        item: &OutboundItem,
    ) -> Result<Vec<ProtocolAction>, ProtocolError> {
        match item {
            OutboundItem::Message(message) => encode_message_frame_actions(message),
            OutboundItem::Subscribe(topic) => Ok(vec![ProtocolAction::Write(encode_command(
                Command::Subscribe(topic.clone()),
            )?)]),
            OutboundItem::Cancel(topic) => Ok(vec![ProtocolAction::Write(encode_command(
                Command::Cancel(topic.clone()),
            )?)]),
        }
    }

    fn decode_message(&mut self, _payload: Bytes) -> Result<Bytes, ProtocolError> {
        Err(ProtocolError::UnexpectedTrafficCommand("MESSAGE"))
    }
}

impl NullMechanism {
    fn finish_if_ready(&self) -> Result<Option<HandshakeComplete>, ProtocolError> {
        if !self.sent_ready || !self.received_ready {
            return Ok(None);
        }

        self.peer_metadata
            .as_ref()
            .map(|metadata| {
                Ok(HandshakeComplete {
                    peer_socket_type: metadata.socket_type()?,
                    metadata: metadata.clone(),
                })
            })
            .transpose()
    }
}
