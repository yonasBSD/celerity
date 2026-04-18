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
    let client_eph_public = take_array::<32>(&mut payload, "invalid HELLO payload")?;
    let server_key_hash = take_array::<32>(&mut payload, "invalid HELLO payload")?;
    let client_nonce_seed = take_array::<8>(&mut payload, "invalid HELLO payload")?;

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
    let server_eph_public = take_array::<32>(&mut payload, "invalid WELCOME payload")?;
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

    let server_static_public = take_array::<32>(&mut body, "invalid WELCOME body")?;
    let cookie = take_array::<32>(&mut body, "invalid WELCOME body")?;
    let server_nonce_seed = take_array::<8>(&mut body, "invalid WELCOME body")?;

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

    let client_static_public = take_array::<32>(&mut payload, "invalid INITIATE payload")?;
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

    let cookie = take_array::<32>(&mut body, "invalid INITIATE body")?;
    let metadata_len = body.get_u32() as usize;
    if body.len() != metadata_len {
        return Err(ProtocolError::CurveHandshake("invalid INITIATE metadata"));
    }

    let metadata = decode_metadata(body)?;
    Ok(InitiateBody { cookie, metadata })
}

pub(super) fn append_transcript(
    transcript: &mut Vec<u8>,
    label: &[u8],
    payload: &[u8],
) -> Result<(), ProtocolError> {
    let label_len =
        u16::try_from(label.len()).map_err(|_| ProtocolError::CurveHandshake("label too large"))?;
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| ProtocolError::CurveHandshake("payload too large"))?;

    transcript.extend_from_slice(&label_len.to_be_bytes());
    transcript.extend_from_slice(label);
    transcript.extend_from_slice(&payload_len.to_be_bytes());
    transcript.extend_from_slice(payload);

    Ok(())
}

fn take_array<const N: usize>(
    payload: &mut Bytes,
    error: &'static str,
) -> Result<[u8; N], ProtocolError> {
    if payload.len() < N {
        return Err(ProtocolError::CurveHandshake(error));
    }

    let bytes = payload.split_to(N);
    let mut out = [0_u8; N];
    out.copy_from_slice(bytes.as_ref());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use bytes::{BufMut, Bytes, BytesMut};

    use super::{
        append_transcript, decode_initiate_body, decode_welcome_body, parse_hello, parse_initiate,
        parse_welcome,
    };
    use crate::ProtocolError;

    fn err<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected Err(..), got Ok(..)"),
            Err(err) => err,
        }
    }

    #[test]
    fn hello_and_welcome_reject_invalid_lengths() {
        assert_eq!(
            err(parse_hello(Bytes::from_static(&[0; 10]))),
            ProtocolError::CurveHandshake("invalid HELLO payload")
        );
        assert_eq!(
            err(parse_welcome(Bytes::from_static(&[0; 40]))),
            ProtocolError::CurveHandshake("invalid WELCOME payload")
        );
    }

    #[test]
    fn welcome_body_rejects_unsupported_version() {
        let mut body = BytesMut::with_capacity(73);
        body.put_u8(9);
        body.extend_from_slice(&[0; 72]);

        assert_eq!(
            err(decode_welcome_body(body.freeze())),
            ProtocolError::CurveHandshake("unsupported WELCOME version")
        );
    }

    #[test]
    fn initiate_parsers_reject_truncated_payloads() {
        assert_eq!(
            err(parse_initiate(Bytes::from_static(&[0; 20]))),
            ProtocolError::CurveHandshake("invalid INITIATE payload")
        );

        let mut body = BytesMut::with_capacity(36);
        body.extend_from_slice(&[0; 32]);
        body.put_u32(4);
        assert_eq!(
            err(decode_initiate_body(body.freeze())),
            ProtocolError::CurveHandshake("invalid INITIATE metadata")
        );
    }

    #[test]
    fn append_transcript_records_label_and_payload_lengths() {
        let mut transcript = Vec::new();
        assert!(append_transcript(&mut transcript, b"HELLO", b"abc").is_ok());

        assert_eq!(
            transcript,
            vec![
                0, 5, b'H', b'E', b'L', b'L', b'O', 0, 0, 0, 3, b'a', b'b', b'c'
            ]
        );
    }
}
