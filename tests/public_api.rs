use bytes::Bytes;
use celerity::{MetadataMap, ProtocolError};

#[cfg(feature = "tokio")]
use celerity::io::{Endpoint, TokioCelerityError, TransportKind};

#[test]
fn metadata_map_replaces_keys_case_insensitively() {
    let mut metadata = MetadataMap::new();
    metadata.insert("Identity", "first").unwrap();
    metadata.insert("identity", "second").unwrap();

    assert_eq!(metadata.len(), 1);
    assert_eq!(
        metadata.get("IDENTITY").cloned(),
        Some(Bytes::from_static(b"second"))
    );
}

#[test]
fn metadata_map_rejects_invalid_names() {
    assert_eq!(
        MetadataMap::new().insert("", "value").unwrap_err(),
        ProtocolError::InvalidMetadataName(Bytes::new())
    );
    assert_eq!(
        MetadataMap::new().insert("bad name", "value").unwrap_err(),
        ProtocolError::InvalidMetadataName(Bytes::from_static(b"bad name"))
    );

    let long_name = vec![b'a'; 256];
    assert_eq!(
        MetadataMap::new()
            .insert(Bytes::from(long_name.clone()), "value")
            .unwrap_err(),
        ProtocolError::InvalidMetadataName(Bytes::from(long_name))
    );
}

#[cfg(feature = "tokio")]
#[test]
fn endpoint_parsing_accepts_tcp_and_ipc_inputs() {
    assert_eq!(
        Endpoint::parse("tcp://127.0.0.1:5555").unwrap(),
        Endpoint::Tcp("127.0.0.1:5555".to_owned())
    );
    assert_eq!(
        Endpoint::parse("127.0.0.1:5555").unwrap(),
        Endpoint::Tcp("127.0.0.1:5555".to_owned())
    );

    #[cfg(unix)]
    assert_eq!(
        Endpoint::parse("ipc:///tmp/celerity-test.sock")
            .unwrap()
            .transport_kind(),
        TransportKind::Ipc
    );
}

#[cfg(feature = "tokio")]
#[test]
fn endpoint_parsing_rejects_invalid_inputs() {
    assert!(matches!(
        Endpoint::parse("").unwrap_err(),
        TokioCelerityError::InvalidEndpoint(endpoint) if endpoint.is_empty()
    ));
    assert!(matches!(
        Endpoint::parse("tcp://").unwrap_err(),
        TokioCelerityError::InvalidEndpoint(endpoint) if endpoint == "tcp://"
    ));
    assert!(matches!(
        Endpoint::parse("udp://127.0.0.1:5555").unwrap_err(),
        TokioCelerityError::UnsupportedEndpoint(endpoint)
            if endpoint == "udp://127.0.0.1:5555"
    ));

    #[cfg(unix)]
    assert!(matches!(
        Endpoint::parse("ipc://relative.sock").unwrap_err(),
        TokioCelerityError::InvalidEndpoint(endpoint) if endpoint == "ipc://relative.sock"
    ));
}
