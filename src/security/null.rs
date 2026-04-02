use std::collections::VecDeque;

use bytes::Bytes;

use crate::wire::{Command, decode_metadata, encode_outbound_item, encode_ready};
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

        Ok(self.finish_if_ready())
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
                let peer_socket_type = validate_remote_metadata(config, &metadata)?;
                self.received_ready = true;
                self.peer_metadata = Some(metadata.clone());

                if matches!(config.security_role, SecurityRole::Server) && !self.sent_ready {
                    output.push_back(ProtocolAction::Write(encode_ready(local_metadata)?));
                    self.sent_ready = true;
                }

                Ok(self
                    .finish_if_ready()
                    .or_else(|| {
                        self.peer_metadata
                            .as_ref()
                            .map(|metadata| HandshakeComplete {
                                peer_socket_type,
                                metadata: metadata.clone(),
                            })
                    })
                    .filter(|_| self.sent_ready && self.received_ready))
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

    fn encode_outbound(&mut self, item: &OutboundItem) -> Result<Vec<Bytes>, ProtocolError> {
        encode_outbound_item(item)
    }

    fn decode_message(&mut self, _payload: Bytes) -> Result<Bytes, ProtocolError> {
        Err(ProtocolError::UnexpectedTrafficCommand("MESSAGE"))
    }
}

impl NullMechanism {
    fn finish_if_ready(&self) -> Option<HandshakeComplete> {
        if self.sent_ready && self.received_ready {
            self.peer_metadata
                .as_ref()
                .map(|metadata| HandshakeComplete {
                    peer_socket_type: metadata.socket_type().expect("validated before completion"),
                    metadata: metadata.clone(),
                })
        } else {
            None
        }
    }
}
