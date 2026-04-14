#[cfg(feature = "tokio")]
pub mod io;
pub mod pattern;
mod peer;
mod security;
mod wire;

use bytes::Bytes;
use thiserror::Error;

pub use pattern::{PatternAction, PubCore, RepCore, ReqCore, SubCore};
pub use peer::CelerityPeer;

pub type Multipart = Vec<Bytes>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketType {
    Pub,
    Sub,
    Req,
    Rep,
}

impl SocketType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pub => "PUB",
            Self::Sub => "SUB",
            Self::Req => "REQ",
            Self::Rep => "REP",
        }
    }

    pub(crate) fn from_bytes(value: &[u8]) -> Result<Self, ProtocolError> {
        match value {
            b"PUB" => Ok(Self::Pub),
            b"SUB" => Ok(Self::Sub),
            b"REQ" => Ok(Self::Req),
            b"REP" => Ok(Self::Rep),
            _ => Err(ProtocolError::InvalidSocketType(Bytes::copy_from_slice(
                value,
            ))),
        }
    }

    pub(crate) const fn is_compatible_with(self, remote: Self) -> bool {
        matches!(
            (self, remote),
            (Self::Pub, Self::Sub)
                | (Self::Sub, Self::Pub)
                | (Self::Req, Self::Rep)
                | (Self::Rep, Self::Req)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkScope {
    Local,
    NonLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityMechanism {
    Null,
    Curve,
}

impl SecurityMechanism {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Null => "NULL",
            Self::Curve => "CURVE-RS",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalAuthPolicy {
    FilesystemStrict,
    FilesystemRelaxed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    X25519HkdfSha256ChaCha20Poly1305,
}

impl CipherSuite {
    #[cfg_attr(not(feature = "curve"), allow(dead_code))]
    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::X25519HkdfSha256ChaCha20Poly1305 => 1,
        }
    }

    #[cfg_attr(not(feature = "curve"), allow(dead_code))]
    pub(crate) fn from_id(id: u8) -> Result<Self, ProtocolError> {
        match id {
            1 => Ok(Self::X25519HkdfSha256ChaCha20Poly1305),
            _ => Err(ProtocolError::UnsupportedCipherSuite(id)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityPolicy {
    pub allow_null_loopback: bool,
    pub allow_null_ipc: bool,
    pub require_curve_non_local: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            allow_null_loopback: true,
            allow_null_ipc: true,
            require_curve_non_local: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurveKeyPair {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

impl CurveKeyPair {
    pub const fn from_parts(secret: [u8; 32], public: [u8; 32]) -> Self {
        Self { secret, public }
    }

    #[cfg(feature = "curve")]
    pub fn from_secret(secret: [u8; 32]) -> Self {
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret_key = StaticSecret::from(secret);
        let public = PublicKey::from(&secret_key);
        Self {
            secret,
            public: public.to_bytes(),
        }
    }

    #[cfg(feature = "curve")]
    pub fn generate() -> Self {
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurveConfig {
    pub server_public_key: Option<[u8; 32]>,
    pub local_static_keypair: CurveKeyPair,
    pub allowed_client_keys: Vec<[u8; 32]>,
    pub handshake_timeout_ms: u64,
    pub rekey_messages: u64,
    pub rekey_bytes: u64,
    pub cipher_suite: CipherSuite,
}

impl Default for CurveConfig {
    fn default() -> Self {
        #[cfg(feature = "curve")]
        let local_static_keypair = CurveKeyPair::from_secret([7; 32]);
        #[cfg(not(feature = "curve"))]
        let local_static_keypair = CurveKeyPair::from_parts([7; 32], [0; 32]);

        Self {
            server_public_key: None,
            local_static_keypair,
            allowed_client_keys: Vec::new(),
            handshake_timeout_ms: 5_000,
            rekey_messages: 1_000_000,
            rekey_bytes: 1 << 30,
            cipher_suite: CipherSuite::X25519HkdfSha256ChaCha20Poly1305,
        }
    }
}

impl CurveConfig {
    #[cfg(feature = "curve")]
    pub fn with_generated_keypair(self) -> Self {
        let mut next = self;
        next.local_static_keypair = CurveKeyPair::generate();
        next
    }

    #[cfg(not(feature = "curve"))]
    pub fn with_generated_keypair(self) -> Self {
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HwmPolicy {
    Block,
    DropNewest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwmConfig {
    pub inbound_messages: usize,
    pub outbound_messages: usize,
    pub inbound_bytes: usize,
    pub outbound_bytes: usize,
    pub policy: HwmPolicy,
}

impl Default for HwmConfig {
    fn default() -> Self {
        Self {
            inbound_messages: 64,
            outbound_messages: 64,
            inbound_bytes: 1 << 20,
            outbound_bytes: 1 << 20,
            policy: HwmPolicy::Block,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityConfig {
    pub mechanism: SecurityMechanism,
    pub allow_insecure_null: bool,
    pub policy: SecurityPolicy,
    pub local_auth: LocalAuthPolicy,
    pub curve: Option<CurveConfig>,
}

impl SecurityConfig {
    pub fn new(mechanism: SecurityMechanism) -> Self {
        Self {
            mechanism,
            allow_insecure_null: false,
            policy: SecurityPolicy::default(),
            local_auth: LocalAuthPolicy::FilesystemStrict,
            curve: match mechanism {
                SecurityMechanism::Null => None,
                SecurityMechanism::Curve => Some(CurveConfig::default()),
            },
        }
    }

    pub fn null() -> Self {
        Self::new(SecurityMechanism::Null)
    }

    pub fn curve() -> Self {
        Self::new(SecurityMechanism::Curve)
    }

    pub fn default_for(link_scope: LinkScope) -> Self {
        match link_scope {
            // Local links default to NULL for easier same-host bootstrapping.
            LinkScope::Local => Self::null(),
            LinkScope::NonLocal => Self::curve(),
        }
    }

    pub fn with_insecure_null(mut self, allow_insecure_null: bool) -> Self {
        self.allow_insecure_null = allow_insecure_null;
        self
    }

    pub fn with_policy(mut self, policy: SecurityPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_local_auth_policy(mut self, local_auth: LocalAuthPolicy) -> Self {
        self.local_auth = local_auth;
        self
    }

    pub fn with_curve_config(mut self, curve: CurveConfig) -> Self {
        self.curve = Some(curve);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataMap {
    entries: Vec<(Bytes, Bytes)>,
}

impl MetadataMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        name: impl Into<Bytes>,
        value: impl Into<Bytes>,
    ) -> Result<(), ProtocolError> {
        self.insert_bytes(name.into(), value.into())
    }

    pub fn get(&self, name: &str) -> Option<&Bytes> {
        self.get_bytes(name.as_bytes())
    }

    pub fn get_bytes(&self, name: &[u8]) -> Option<&Bytes> {
        self.entries
            .iter()
            // Metadata lookup is case-insensitive even though bytes are preserved.
            .find(|(candidate, _)| candidate.as_ref().eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Bytes, &Bytes)> {
        self.entries.iter().map(|(name, value)| (name, value))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn insert_bytes(&mut self, name: Bytes, value: Bytes) -> Result<(), ProtocolError> {
        validate_metadata_name(&name)?;

        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|(candidate, _)| candidate.as_ref().eq_ignore_ascii_case(&name))
        {
            // Reinsertions replace the previous value instead of duplicating the key.
            *existing = (name, value);
        } else {
            self.entries.push((name, value));
        }

        Ok(())
    }

    pub(crate) fn socket_type(&self) -> Result<SocketType, ProtocolError> {
        let value = self
            .get("Socket-Type")
            .ok_or(ProtocolError::MissingMetadata("Socket-Type"))?;
        SocketType::from_bytes(value)
    }
}

fn validate_metadata_name(name: &[u8]) -> Result<(), ProtocolError> {
    if name.is_empty() || name.len() > u8::MAX as usize {
        return Err(ProtocolError::InvalidMetadataName(Bytes::copy_from_slice(
            name,
        )));
    }

    if name
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
    {
        Ok(())
    } else {
        Err(ProtocolError::InvalidMetadataName(Bytes::copy_from_slice(
            name,
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub socket_type: SocketType,
    pub security_role: SecurityRole,
    pub link_scope: LinkScope,
    pub security: SecurityConfig,
    pub identity: Option<Bytes>,
    pub metadata: MetadataMap,
    pub hwm: HwmConfig,
}

impl PeerConfig {
    pub fn new(
        socket_type: SocketType,
        security_role: SecurityRole,
        link_scope: LinkScope,
    ) -> Self {
        Self {
            socket_type,
            security_role,
            link_scope,
            security: SecurityConfig::default_for(link_scope),
            identity: None,
            metadata: MetadataMap::new(),
            hwm: HwmConfig::default(),
        }
    }

    pub fn with_security(mut self, security: SecurityConfig) -> Self {
        self.security = security;
        self
    }

    pub fn with_identity(mut self, identity: impl Into<Bytes>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    pub fn with_metadata(mut self, metadata: MetadataMap) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_hwm(mut self, hwm: HwmConfig) -> Self {
        self.hwm = hwm;
        self
    }

    pub(crate) fn validate_policy(&self) -> Result<(), ProtocolError> {
        // Remote NULL stays fail-closed unless the caller opts in explicitly.
        if self.security.mechanism == SecurityMechanism::Null
            && self.link_scope == LinkScope::NonLocal
            && self.security.policy.require_curve_non_local
            && !self.security.allow_insecure_null
        {
            return Err(ProtocolError::InsecureNullForNonLocal);
        }

        if self.security.mechanism == SecurityMechanism::Curve {
            // CURVE always needs an attached key/config block before we handshake.
            let curve = self
                .security
                .curve
                .as_ref()
                .ok_or(ProtocolError::MissingCurveConfig)?;

            #[cfg(feature = "curve")]
            validate_curve_keypair(&curve.local_static_keypair)?;
            #[cfg(not(feature = "curve"))]
            let _ = curve;
        }

        Ok(())
    }

    pub(crate) fn handshake_metadata(&self) -> Result<MetadataMap, ProtocolError> {
        let mut metadata = MetadataMap::new();
        metadata.insert("Socket-Type", self.socket_type.as_str())?;

        if let Some(identity) = &self.identity {
            metadata.insert("Identity", identity.clone())?;
        }

        for (name, value) in self.metadata.iter() {
            // Reserved handshake keys come from explicit config, not caller metadata.
            if !name.as_ref().eq_ignore_ascii_case(b"Socket-Type")
                && !name.as_ref().eq_ignore_ascii_case(b"Identity")
            {
                metadata.insert(name.clone(), value.clone())?;
            }
        }

        Ok(metadata)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundItem {
    Message(Multipart),
    Subscribe(Bytes),
    Cancel(Bytes),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvent {
    HandshakeComplete {
        peer_socket_type: SocketType,
        metadata: MetadataMap,
    },
    Message(Multipart),
    Subscription {
        subscribe: bool,
        topic: Bytes,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolAction {
    Write(Bytes),
    Event(PeerEvent),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("connection is closed")]
    ConnectionClosed,
    #[error("peer is not ready for traffic")]
    PeerNotReady,
    #[error("multipart messages must contain at least one frame")]
    EmptyMessage,
    #[error("invalid ZMTP greeting signature")]
    InvalidGreetingSignature,
    #[error("unsupported ZMTP version {major}.{minor}")]
    UnsupportedVersion { major: u8, minor: u8 },
    #[error("invalid greeting filler bytes")]
    InvalidGreetingFiller,
    #[error("unsupported security mechanism {0}")]
    MechanismUnsupported(&'static str),
    #[error("unsupported security mechanism name {0}")]
    UnsupportedMechanismName(String),
    #[error("security mechanism mismatch: expected {expected:?}, got {actual:?}")]
    MechanismMismatch {
        expected: SecurityMechanism,
        actual: SecurityMechanism,
    },
    #[error("invalid as-server field {0}")]
    InvalidAsServer(u8),
    #[error("NULL security is disabled for non-local links without explicit opt-in")]
    InsecureNullForNonLocal,
    #[error("missing CURVE configuration")]
    MissingCurveConfig,
    #[error("unsupported cipher suite id {0}")]
    UnsupportedCipherSuite(u8),
    #[error("CURVE handshake failed: {0}")]
    CurveHandshake(&'static str),
    #[error("CURVE authentication failed")]
    CurveAuthenticationFailed,
    #[error("CURVE replay detected")]
    CurveReplayDetected,
    #[error("configured CURVE public key does not match the secret key")]
    InvalidCurveKeyPair,
    #[error("invalid encrypted traffic frame")]
    InvalidEncryptedMessage,
    #[error("invalid frame flags 0x{0:02x}")]
    InvalidFrameFlags(u8),
    #[error("command frames must not set MORE")]
    CommandWithMore,
    #[error("frame length uses the reserved sign bit")]
    NegativeFrameLength,
    #[error("frame size {0} exceeds platform limits")]
    FrameTooLarge(u64),
    #[error("invalid command frame")]
    InvalidCommandFrame,
    #[error("unexpected message frame during handshake")]
    UnexpectedMessageDuringHandshake,
    #[error("unexpected command {0} during handshake")]
    UnexpectedHandshakeCommand(&'static str),
    #[error("unexpected command {0} during traffic")]
    UnexpectedTrafficCommand(&'static str),
    #[error("remote peer reported fatal error: {0}")]
    RemoteError(String),
    #[error("invalid metadata name {0:?}")]
    InvalidMetadataName(Bytes),
    #[error("missing metadata property {0}")]
    MissingMetadata(&'static str),
    #[error("invalid socket type {0:?}")]
    InvalidSocketType(Bytes),
    #[error("incompatible socket types: local {local:?}, remote {remote:?}")]
    IncompatibleSocketTypes {
        local: SocketType,
        remote: SocketType,
    },
    #[error("missing request envelope delimiter")]
    MissingEnvelopeDelimiter,
    #[error("request messages must contain at least one body frame")]
    MissingBodyFrames,
    #[error("no available peers")]
    NoAvailablePeers,
    #[error("REQ state violation: {0}")]
    ReqStateViolation(&'static str),
    #[error("REP state violation: {0}")]
    RepStateViolation(&'static str),
    #[error("subscription was not active")]
    UnknownSubscription,
}

#[cfg(feature = "curve")]
fn validate_curve_keypair(keypair: &CurveKeyPair) -> Result<(), ProtocolError> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::from(keypair.secret);
    let derived = PublicKey::from(&secret).to_bytes();
    if derived == keypair.public {
        Ok(())
    } else {
        Err(ProtocolError::InvalidCurveKeyPair)
    }
}
