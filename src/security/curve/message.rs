use bytes::{Buf, Bytes};

use crate::wire::decode_metadata;
use crate::{CipherSuite, MetadataMap, ProtocolError};

#[derive(Debug)]
pub(super) struct Hello {
    pub(super) version: u8,
    pub(super) cipher_suite: CipherSuite,
    pub(super) client_eph_public: [u8; 32],
    pub(super) server_key_hash: [u8; 32],
    pub(super) client_nonce_seed: [u8; 8],
}

pub(super) fn parse_hello(mut payload: Bytes) -> Result<Hello, ProtocolError> {
    if payload.len() != 74 {
        return Err(ProtocolError::CurveHandshake("invalid HELLO payload"));
    }

    let version = payload.get_u8();
    let cipher_suite = CipherSuite::from_id(payload.get_u8())?;
    let client_eph_public = payload
        .split_to(32)
        .as_ref()
        .try_into()
        .expect("length already checked");
    let server_key_hash = payload
        .split_to(32)
        .as_ref()
        .try_into()
        .expect("length already checked");
    let client_nonce_seed = payload
        .split_to(8)
        .as_ref()
        .try_into()
        .expect("length already checked");

    Ok(Hello {
        version,
        cipher_suite,
        client_eph_public,
        server_key_hash,
        client_nonce_seed,
    })
}

#[derive(Debug)]
pub(super) struct WelcomeFrame {
    pub(super) cipher_suite: CipherSuite,
    pub(super) server_eph_public: [u8; 32],
    pub(super) ciphertext: Bytes,
}

pub(super) fn parse_welcome(mut payload: Bytes) -> Result<WelcomeFrame, ProtocolError> {
    if payload.len() < 33 + 16 {
        return Err(ProtocolError::CurveHandshake("invalid WELCOME payload"));
    }

    let cipher_suite = CipherSuite::from_id(payload.get_u8())?;
    let server_eph_public = payload
        .split_to(32)
        .as_ref()
        .try_into()
        .expect("length already checked");
    Ok(WelcomeFrame {
        cipher_suite,
        server_eph_public,
        ciphertext: payload,
    })
}

#[derive(Debug)]
pub(super) struct WelcomeBody {
    pub(super) server_static_public: [u8; 32],
    pub(super) cookie: [u8; 32],
    pub(super) server_nonce_seed: [u8; 8],
}

pub(super) fn decode_welcome_body(mut body: Bytes) -> Result<WelcomeBody, ProtocolError> {
    if body.len() != 73 {
        return Err(ProtocolError::CurveHandshake("invalid WELCOME body"));
    }

    let version = body.get_u8();
    if version != 1 {
        return Err(ProtocolError::CurveHandshake("unsupported WELCOME version"));
    }

    let server_static_public = body
        .split_to(32)
        .as_ref()
        .try_into()
        .expect("length already checked");
    let cookie = body
        .split_to(32)
        .as_ref()
        .try_into()
        .expect("length already checked");
    let server_nonce_seed = body
        .split_to(8)
        .as_ref()
        .try_into()
        .expect("length already checked");

    Ok(WelcomeBody {
        server_static_public,
        cookie,
        server_nonce_seed,
    })
}

#[derive(Debug)]
pub(super) struct Initiate {
    pub(super) client_static_public: [u8; 32],
    pub(super) ciphertext: Bytes,
}

pub(super) fn parse_initiate(mut payload: Bytes) -> Result<Initiate, ProtocolError> {
    if payload.len() < 32 + 16 {
        return Err(ProtocolError::CurveHandshake("invalid INITIATE payload"));
    }

    let client_static_public = payload
        .split_to(32)
        .as_ref()
        .try_into()
        .expect("length already checked");
    Ok(Initiate {
        client_static_public,
        ciphertext: payload,
    })
}

#[derive(Debug)]
pub(super) struct InitiateBody {
    pub(super) cookie: [u8; 32],
    pub(super) metadata: MetadataMap,
}

pub(super) fn decode_initiate_body(mut body: Bytes) -> Result<InitiateBody, ProtocolError> {
    if body.len() < 36 {
        return Err(ProtocolError::CurveHandshake("invalid INITIATE body"));
    }

    let cookie = body
        .split_to(32)
        .as_ref()
        .try_into()
        .expect("length already checked");
    let metadata_len = body.get_u32() as usize;
    if body.len() != metadata_len {
        return Err(ProtocolError::CurveHandshake("invalid INITIATE metadata"));
    }

    let metadata = decode_metadata(body)?;
    Ok(InitiateBody { cookie, metadata })
}

pub(super) fn append_transcript(transcript: &mut Vec<u8>, label: &[u8], payload: &[u8]) {
    transcript.extend_from_slice(&(label.len() as u16).to_be_bytes());
    transcript.extend_from_slice(label);
    transcript.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    transcript.extend_from_slice(payload);
}
