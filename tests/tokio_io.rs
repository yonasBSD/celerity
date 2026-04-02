#![cfg(feature = "tokio")]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use celerity::io::{
    Endpoint, PubSocket, RepSocket, ReqSocket, SubSocket, TokioCelerity, TokioCelerityError,
    TransportKind, TransportMeta,
};
#[cfg(feature = "curve")]
use celerity::{CurveConfig, ProtocolError, SecurityConfig};
use celerity::{
    HwmConfig, HwmPolicy, LinkScope, OutboundItem, PeerConfig, PeerEvent, SecurityRole, SocketType,
};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn endpoint_parsing_supports_tcp_and_ipc() {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tokio_celerity_delivers_subscription_events_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();

    let server = tokio::spawn(async move {
        let (stream, addr) = listener.accept().await.unwrap();
        let transport = TransportMeta {
            kind: TransportKind::Tcp,
            link_scope: if addr.ip().is_loopback() {
                LinkScope::Local
            } else {
                LinkScope::NonLocal
            },
            null_authorized: addr.ip().is_loopback(),
        };
        let mut server = TokioCelerity::from_stream(
            stream,
            transport,
            PeerConfig::new(SocketType::Pub, SecurityRole::Server, transport.link_scope),
        )
        .unwrap();

        loop {
            match timeout(Duration::from_secs(1), server.recv())
                .await
                .unwrap()
            {
                Some(PeerEvent::Subscription { subscribe, topic }) => {
                    return (subscribe, topic);
                }
                Some(_) => {}
                None => panic!("server closed before subscription arrived"),
            }
        }
    });

    let client = TokioCelerity::connect(
        &endpoint,
        PeerConfig::new(SocketType::Sub, SecurityRole::Client, LinkScope::Local),
    )
    .await
    .unwrap();
    client
        .send(OutboundItem::Subscribe(Bytes::from_static(b"topic")))
        .await
        .unwrap();

    let (subscribe, topic) = server.await.unwrap();
    assert!(subscribe);
    assert_eq!(topic, Bytes::from_static(b"topic"));
}

#[cfg(feature = "curve")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn curve_roundtrip_over_tcp_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();

    let server = tokio::spawn(async move {
        let (stream, addr) = listener.accept().await.unwrap();
        let transport = TransportMeta {
            kind: TransportKind::Tcp,
            link_scope: if addr.ip().is_loopback() {
                LinkScope::Local
            } else {
                LinkScope::NonLocal
            },
            null_authorized: addr.ip().is_loopback(),
        };
        let config = PeerConfig::new(SocketType::Rep, SecurityRole::Server, transport.link_scope)
            .with_security(SecurityConfig::curve());
        let mut server = TokioCelerity::from_stream(stream, transport, config).unwrap();

        loop {
            match timeout(Duration::from_secs(2), server.recv())
                .await
                .unwrap()
            {
                Some(PeerEvent::Message(message)) => {
                    assert_eq!(message, vec![Bytes::new(), Bytes::from_static(b"ping")]);
                    server
                        .send(OutboundItem::Message(vec![
                            Bytes::new(),
                            Bytes::from_static(b"pong"),
                        ]))
                        .await
                        .unwrap();
                    return;
                }
                Some(_) => {}
                None => panic!("server closed before request arrived"),
            }
        }
    });

    let mut client = TokioCelerity::connect(
        &endpoint,
        PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::curve()),
    )
    .await
    .unwrap();
    client
        .send(OutboundItem::Message(vec![
            Bytes::new(),
            Bytes::from_static(b"ping"),
        ]))
        .await
        .unwrap();

    loop {
        match timeout(Duration::from_secs(2), client.recv())
            .await
            .unwrap()
        {
            Some(PeerEvent::Message(message)) => {
                assert_eq!(message, vec![Bytes::new(), Bytes::from_static(b"pong")]);
                break;
            }
            Some(_) => {}
            None => panic!("client closed before reply arrived"),
        }
    }

    server.await.unwrap();
}

#[cfg(feature = "curve")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn curve_handshake_timeout_is_enforced() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();

    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let mut curve = CurveConfig::default().with_generated_keypair();
    curve.handshake_timeout_ms = 50;
    let client = TokioCelerity::connect(
        &endpoint,
        PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::curve().with_curve_config(curve)),
    )
    .await
    .unwrap();

    let err = client.join().await.unwrap_err();
    assert!(matches!(err, TokioCelerityError::HandshakeTimeout));
    server.await.unwrap();
}

#[cfg(feature = "curve")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn curve_keypair_mismatch_is_rejected_early() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
    });

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut curve = CurveConfig::default().with_generated_keypair();
    curve.local_static_keypair.public[0] ^= 0x01;
    let err = match TokioCelerity::from_stream(
        stream,
        TransportMeta {
            kind: TransportKind::Tcp,
            link_scope: LinkScope::Local,
            null_authorized: true,
        },
        PeerConfig::new(SocketType::Req, SecurityRole::Client, LinkScope::Local)
            .with_security(SecurityConfig::curve().with_curve_config(curve)),
    ) {
        Ok(_) => panic!("mismatched CURVE keypair should be rejected"),
        Err(err) => err,
    };

    assert!(matches!(
        err,
        TokioCelerityError::Protocol(ProtocolError::InvalidCurveKeyPair)
    ));
    accepted.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drop_newest_drops_pre_auth_messages_instead_of_blocking() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();

    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
    });

    let mut hwm = HwmConfig::default();
    hwm.outbound_messages = 1;
    hwm.policy = HwmPolicy::DropNewest;

    let client = TokioCelerity::connect(
        &endpoint,
        PeerConfig::new(SocketType::Pub, SecurityRole::Client, LinkScope::Local).with_hwm(hwm),
    )
    .await
    .unwrap();

    timeout(
        Duration::from_millis(100),
        client.send(OutboundItem::Message(vec![Bytes::from_static(b"first")])),
    )
    .await
    .unwrap()
    .unwrap();
    timeout(
        Duration::from_millis(100),
        client.send(OutboundItem::Message(vec![Bytes::from_static(b"second")])),
    )
    .await
    .unwrap()
    .unwrap();

    let _ = timeout(Duration::from_secs(1), client.join())
        .await
        .unwrap();
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pub_sub_roundtrip_over_tcp() {
    let mut publisher = PubSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = publisher.local_addr().to_string();
    let mut subscriber = SubSocket::connect(&endpoint).await.unwrap();

    subscriber.subscribe(Bytes::new()).await.unwrap();
    assert!(
        publisher
            .wait_for_subscriber(Duration::from_secs(1))
            .await
            .unwrap()
    );

    publisher
        .send(vec![Bytes::from_static(b"hello")])
        .await
        .unwrap();

    let message = timeout(Duration::from_secs(1), subscriber.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(message, vec![Bytes::from_static(b"hello")]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publisher_send_without_subscribers_is_a_noop() {
    let publisher = PubSocket::bind("127.0.0.1:0").await.unwrap();
    publisher
        .send(vec![Bytes::from_static(b"orphaned")])
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn req_rep_roundtrip_over_tcp() {
    let mut responder = RepSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = responder.local_addr().to_string();
    let requester = ReqSocket::connect(&endpoint).await.unwrap();

    let server = tokio::spawn(async move {
        let message = responder.recv().await.unwrap();
        assert_eq!(message, vec![Bytes::from_static(b"ping")]);
        responder
            .reply(vec![Bytes::from_static(b"pong")])
            .await
            .unwrap();
    });

    let reply = requester
        .request(vec![Bytes::from_static(b"ping")])
        .await
        .unwrap();
    assert_eq!(reply, vec![Bytes::from_static(b"pong")]);

    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rep_socket_keeps_progress_with_two_clients() {
    let mut responder = RepSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = responder.local_addr().to_string();
    let requester_one = ReqSocket::connect(&endpoint).await.unwrap();
    let requester_two = ReqSocket::connect(&endpoint).await.unwrap();

    let first = tokio::spawn(async move {
        requester_one
            .request(vec![Bytes::from_static(b"one")])
            .await
            .unwrap()
    });

    let first_message = timeout(Duration::from_secs(1), responder.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first_message, vec![Bytes::from_static(b"one")]);

    let second = tokio::spawn(async move {
        requester_two
            .request(vec![Bytes::from_static(b"two")])
            .await
            .unwrap()
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    responder
        .reply(vec![Bytes::from_static(b"ack-one")])
        .await
        .unwrap();

    let second_message = timeout(Duration::from_secs(1), responder.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second_message, vec![Bytes::from_static(b"two")]);

    responder
        .reply(vec![Bytes::from_static(b"ack-two")])
        .await
        .unwrap();

    assert_eq!(first.await.unwrap(), vec![Bytes::from_static(b"ack-one")]);
    assert_eq!(second.await.unwrap(), vec![Bytes::from_static(b"ack-two")]);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_pub_sub_roundtrip_and_cleanup() {
    let path = unique_ipc_path("pub-sub");
    let endpoint = format!("ipc://{}", path.display());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();

    {
        let mut publisher = PubSocket::bind(&endpoint).await.unwrap();
        let mut subscriber = SubSocket::connect(&endpoint).await.unwrap();
        subscriber.subscribe(Bytes::new()).await.unwrap();
        assert!(
            publisher
                .wait_for_subscriber(Duration::from_secs(1))
                .await
                .unwrap()
        );
        publisher
            .send(vec![Bytes::from_static(b"hello-ipc")])
            .await
            .unwrap();
        let message = timeout(Duration::from_secs(1), subscriber.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(message, vec![Bytes::from_static(b"hello-ipc")]);
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!path.exists(), "IPC socket file should be removed on drop");
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_stale_socket_is_replaced() {
    let path = unique_ipc_path("stale");
    let endpoint = format!("ipc://{}", path.display());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let stale = std::os::unix::net::UnixListener::bind(&path).unwrap();
    drop(stale);

    {
        let socket = PubSocket::bind(&endpoint).await.unwrap();
        assert!(path.exists());
        drop(socket);
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !path.exists(),
        "stale socket replacement should still clean up"
    );
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_strict_auth_rejects_world_writable_parent() {
    let parent = unique_ipc_parent("bad-parent");
    std::fs::create_dir_all(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let path = parent.join("celerity.sock");
    let endpoint = format!("ipc://{}", path.display());

    let err = match PubSocket::bind(&endpoint).await {
        Ok(_) => panic!("bind should fail for a world-writable parent directory"),
        Err(err) => err,
    };
    assert!(matches!(err, TokioCelerityError::LocalAuth { .. }));

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&parent);
}

#[cfg(unix)]
fn unique_ipc_path(name: &str) -> std::path::PathBuf {
    unique_ipc_parent(name).join("celerity.sock")
}

#[cfg(unix)]
fn unique_ipc_parent(name: &str) -> std::path::PathBuf {
    let mut path = std::path::PathBuf::from("/tmp");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    path.push(format!("cel-{name}-{}-{unique}", std::process::id()));
    path
}
