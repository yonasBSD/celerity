//! Public API smoke tests.

use bytes::Bytes;
use celerity::{MetadataMap, ProtocolError};

#[cfg(feature = "tokio")]
use celerity::io::{Endpoint, TokioCelerityError, TransportKind};

fn ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => panic!("expected Ok(..), got Err({err:?})"),
    }
}

fn err<T, E>(result: Result<T, E>) -> E {
    match result {
        Ok(_) => panic!("expected Err(..), got Ok(..)"),
        Err(err) => err,
    }
}

#[test]
fn metadata_map_replaces_keys_case_insensitively() {
    let mut metadata = MetadataMap::new();
    ok(metadata.insert("Identity", "first"));
    ok(metadata.insert("identity", "second"));

    assert_eq!(metadata.len(), 1);
    assert_eq!(
        metadata.get("IDENTITY").cloned(),
        Some(Bytes::from_static(b"second"))
    );
}

#[test]
fn metadata_map_rejects_invalid_names() {
    assert_eq!(
        err(MetadataMap::new().insert("", "value")),
        ProtocolError::InvalidMetadataName(Bytes::new())
    );
    assert_eq!(
        err(MetadataMap::new().insert("bad name", "value")),
        ProtocolError::InvalidMetadataName(Bytes::from_static(b"bad name"))
    );

    let long_name = vec![b'a'; 256];
    assert_eq!(
        err(MetadataMap::new().insert(Bytes::from(long_name.clone()), "value")),
        ProtocolError::InvalidMetadataName(Bytes::from(long_name))
    );
}

#[cfg(feature = "tokio")]
#[test]
fn endpoint_parsing_accepts_tcp_and_ipc_inputs() {
    assert_eq!(
        ok(Endpoint::parse("tcp://127.0.0.1:5555")),
        Endpoint::Tcp("127.0.0.1:5555".to_owned())
    );
    assert_eq!(
        ok(Endpoint::parse("127.0.0.1:5555")),
        Endpoint::Tcp("127.0.0.1:5555".to_owned())
    );

    #[cfg(unix)]
    assert_eq!(
        ok(Endpoint::parse("ipc:///tmp/celerity-test.sock")).transport_kind(),
        TransportKind::Ipc
    );
}

#[cfg(feature = "tokio")]
#[test]
fn endpoint_parsing_rejects_invalid_inputs() {
    assert!(matches!(
        err(Endpoint::parse("")),
        TokioCelerityError::InvalidEndpoint(endpoint) if endpoint.is_empty()
    ));
    assert!(matches!(
        err(Endpoint::parse("tcp://")),
        TokioCelerityError::InvalidEndpoint(endpoint) if endpoint == "tcp://"
    ));
    assert!(matches!(
        err(Endpoint::parse("udp://127.0.0.1:5555")),
        TokioCelerityError::UnsupportedEndpoint(endpoint)
            if endpoint == "udp://127.0.0.1:5555"
    ));

    #[cfg(unix)]
    assert!(matches!(
        err(Endpoint::parse("ipc://relative.sock")),
        TokioCelerityError::InvalidEndpoint(endpoint) if endpoint == "ipc://relative.sock"
    ));
}
