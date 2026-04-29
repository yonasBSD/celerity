mod curve;
mod null;

use std::collections::VecDeque;

use bytes::Bytes;

use crate::wire::Command;
use crate::{
    MetadataMap, OutboundItem, PeerConfig, ProtocolAction, ProtocolError, SecurityMechanism,
    SocketType,
};

use curve::CurveMechanism;
use null::NullMechanism;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HandshakeComplete {
    pub(crate) peer_socket_type: SocketType,
    pub(crate) metadata: MetadataMap,
}

pub(crate) trait MechanismDriver {
    fn on_greeting(
        &mut self,
        config: &PeerConfig,
        local_metadata: &MetadataMap,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<Option<HandshakeComplete>, ProtocolError>;

    fn on_command(
        &mut self,
        config: &PeerConfig,
        local_metadata: &MetadataMap,
        command: Command,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<Option<HandshakeComplete>, ProtocolError>;

    fn encode_outbound(
        &mut self,
        item: &OutboundItem,
    ) -> Result<Vec<ProtocolAction>, ProtocolError>;

    fn decode_message(&mut self, payload: Bytes) -> Result<Bytes, ProtocolError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mechanism {
    Null(NullMechanism),
    Curve(Box<CurveMechanism>),
}

impl Mechanism {
    pub(crate) fn new(config: &PeerConfig) -> Self {
        match config.security.mechanism {
            SecurityMechanism::Null => Self::Null(NullMechanism::default()),
            SecurityMechanism::Curve => {
                Self::Curve(Box::new(CurveMechanism::new(config.security_role)))
            }
        }
    }

    pub(crate) fn on_greeting(
        &mut self,
        config: &PeerConfig,
        local_metadata: &MetadataMap,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<Option<HandshakeComplete>, ProtocolError> {
        match self {
            Self::Null(driver) => driver.on_greeting(config, local_metadata, output),
            Self::Curve(driver) => driver.on_greeting(config, local_metadata, output),
        }
    }

    pub(crate) fn on_command(
        &mut self,
        config: &PeerConfig,
        local_metadata: &MetadataMap,
        command: Command,
        output: &mut VecDeque<ProtocolAction>,
    ) -> Result<Option<HandshakeComplete>, ProtocolError> {
        match self {
            Self::Null(driver) => driver.on_command(config, local_metadata, command, output),
            Self::Curve(driver) => driver.on_command(config, local_metadata, command, output),
        }
    }

    pub(crate) fn encode_outbound(
        &mut self,
        item: &OutboundItem,
    ) -> Result<Vec<ProtocolAction>, ProtocolError> {
        match self {
            Self::Null(driver) => driver.encode_outbound(item),
            Self::Curve(driver) => driver.encode_outbound(item),
        }
    }

    pub(crate) fn decode_message(&mut self, payload: Bytes) -> Result<Bytes, ProtocolError> {
        match self {
            Self::Null(driver) => driver.decode_message(payload),
            Self::Curve(driver) => driver.decode_message(payload),
        }
    }
}

pub(crate) fn validate_remote_metadata(
    config: &PeerConfig,
    metadata: &MetadataMap,
) -> Result<SocketType, ProtocolError> {
    let peer_socket_type = metadata.socket_type()?;
    // Socket compatibility is checked after the handshake exposes peer metadata.
    if !config.socket_type.is_compatible_with(peer_socket_type) {
        return Err(ProtocolError::IncompatibleSocketTypes {
            local: config.socket_type,
            remote: peer_socket_type,
        });
    }

    Ok(peer_socket_type)
}

#[cfg(feature = "curve")]
pub(crate) fn curve_config(config: &PeerConfig) -> Result<&crate::CurveConfig, ProtocolError> {
    config
        .security
        .curve
        .as_ref()
        .ok_or(ProtocolError::MissingCurveConfig)
}
