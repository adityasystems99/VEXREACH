use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use private_relay_crypto::{LinkInitiator, LinkRekeyPolicy, LinkResponder, StaticKeypair};
use private_relay_network::{
    accept_noise_link, accept_noise_link_with_rekey, connect_noise_link,
    connect_noise_link_with_rekey, split_framed_session, ClientConfigFile, DestinationPolicy,
    NetworkError, PeerDescriptor, RelayConfig, RelayRole,
};
use private_relay_protocol::{Cell, CircuitId, Command, ProtocolError, OUTER_WIRE_FRAME_BYTES};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// Mock `AsyncRead + AsyncWrite` wrapper forcing tiny chunk reads/writes (1–7 bytes) to verify partial TCP handling.
struct TrickleStream<S> {
    inner: S,
    max_chunk: usize,
}

impl<S: AsyncRead + Unpin> AsyncRead for TrickleStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let cap = buf.remaining().min(self.max_chunk);
        let mut temp = vec![0u8; cap];
        let mut temp_buf = ReadBuf::new(&mut temp);
        match Pin::new(&mut self.inner).poll_read(cx, &mut temp_buf) {
            Poll::Ready(Ok(())) => {
                buf.put_slice(temp_buf.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrickleStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let slice = &buf[..buf.len().min(self.max_chunk)];
        Pin::new(&mut self.inner).poll_write(cx, slice)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn ssrf_policy_blocks_private_and_loopback_by_default() {
    let default_policy = DestinationPolicy::default();

    for ip in [
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V6("fe80::1".parse().unwrap()),
        IpAddr::V6("fec0::1".parse().unwrap()),
        IpAddr::V6("fc00::1".parse().unwrap()),
        IpAddr::V6("100::1".parse().unwrap()),
        IpAddr::V6("64:ff9b::127.0.0.1".parse().unwrap()),
        IpAddr::V6("2001::1".parse().unwrap()),
        IpAddr::V6("2001:2::1".parse().unwrap()),
        IpAddr::V6("2002:7f00:1::".parse().unwrap()),
        IpAddr::V6("2002:a9fe:a9fe::".parse().unwrap()),
        IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
        IpAddr::V6("::127.0.0.1".parse().unwrap()),
        IpAddr::V6("::10.0.0.1".parse().unwrap()),
        IpAddr::V6("::169.254.169.254".parse().unwrap()),
        IpAddr::V6("::ffff:0:127.0.0.1".parse().unwrap()),
    ] {
        assert!(
            matches!(
                default_policy.validate_ip(ip),
                Err(NetworkError::PolicyDenied(_))
            ),
            "expected SSRF policy denial for {ip}"
        );
    }

    assert!(default_policy
        .validate_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
        .is_ok());

    let res = default_policy.resolve_and_validate("127.0.0.1:8080").await;
    assert!(matches!(res, Err(NetworkError::PolicyDenied(_))));

    let zone_res = default_policy
        .resolve_and_validate("[fe80::1%eth0]:80")
        .await;
    assert!(matches!(zone_res, Err(NetworkError::PolicyDenied(_))));

    // Loopback test override never loosens metadata/private transition addresses.
    let loopback_policy = DestinationPolicy {
        allow_loopback_for_test: true,
        allow_private_targets_for_test: false,
        allowed_targets: Vec::new(),
    };
    assert!(loopback_policy
        .validate_ip(IpAddr::V6("::169.254.169.254".parse().unwrap()))
        .is_err());
    assert!(loopback_policy
        .validate_ip(IpAddr::V6("2002:a9fe:a9fe::".parse().unwrap()))
        .is_err());

    // Private-target test override strictly requires explicit allowed_targets and STILL denies loopback/metadata.
    let private_empty_allowlist = DestinationPolicy {
        allow_loopback_for_test: false,
        allow_private_targets_for_test: true,
        allowed_targets: Vec::new(),
    };
    assert!(private_empty_allowlist
        .validate_ip(IpAddr::V4(Ipv4Addr::new(172, 18, 0, 2)))
        .is_err());

    let container_policy = DestinationPolicy {
        allow_loopback_for_test: false,
        allow_private_targets_for_test: true,
        allowed_targets: vec!["demo-dest:9000".into()],
    };
    assert!(container_policy
        .validate_ip(IpAddr::V4(Ipv4Addr::new(172, 18, 0, 2)))
        .is_ok());
    assert!(container_policy
        .validate_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)))
        .is_err());
    assert!(container_policy
        .validate_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
        .is_err());
    assert!(matches!(
        container_policy.resolve_and_validate("10.0.0.1:80").await,
        Err(NetworkError::PolicyDenied(_))
    ));

    // Explicit test loopback flag + allowlist works only for listed targets.
    let test_policy = DestinationPolicy {
        allow_loopback_for_test: true,
        allow_private_targets_for_test: false,
        allowed_targets: vec!["127.0.0.1:8080".into()],
    };
    assert!(test_policy
        .resolve_and_validate("127.0.0.1:8080")
        .await
        .is_ok());
    assert!(matches!(
        test_policy.resolve_and_validate("127.0.0.1:9999").await,
        Err(NetworkError::PolicyDenied(_))
    ));
}

#[tokio::test]
async fn partial_tcp_reads_writes_and_multiple_frames_over_noise_link() {
    let (a, b) = tokio::io::duplex(2048);
    let mut trickle_a = TrickleStream {
        inner: a,
        max_chunk: 7,
    };
    let mut trickle_b = TrickleStream {
        inner: b,
        max_chunk: 5,
    };

    let kp_init = StaticKeypair::generate().unwrap();
    let kp_resp = StaticKeypair::generate().unwrap();

    // Run Noise_IK handshake over trickled partial stream!
    let mut init = LinkInitiator::new(&kp_init, *kp_resp.public()).unwrap();
    let msg1 = init.write_msg1().unwrap();
    let (msg2, sess_resp) = LinkResponder::new(&kp_resp)
        .unwrap()
        .process_msg1_and_finish(&msg1)
        .unwrap();
    let sess_init = init.finish_with_msg2(&msg2).unwrap();
    let _ = (&mut trickle_a, &mut trickle_b);

    let (mut _ra, mut wa) = split_framed_session(trickle_a, sess_init);
    let (mut rb, mut _wb) = split_framed_session(trickle_b, sess_resp);

    let timeout = Duration::from_secs(3);
    let cid = CircuitId::new(11).unwrap();
    let frames = vec![
        Cell::new(cid, Command::Create, 0, vec![0xAA; 48]).unwrap(),
        Cell::new(cid, Command::RelayData, 0, vec![0xBB; 300]).unwrap(),
        Cell::new(cid, Command::RelayData, 1, vec![0xCC; 571]).unwrap(),
    ];

    let send_task = tokio::spawn(async move {
        for cell in frames {
            wa.send_cell(&cell, timeout).await.unwrap();
        }
        wa
    });

    let c1 = rb.recv_cell(timeout).await.unwrap();
    let c2 = rb.recv_cell(timeout).await.unwrap();
    let c3 = rb.recv_cell(timeout).await.unwrap();
    assert_eq!(c1.body, vec![0xAA; 48]);
    assert_eq!(c2.body, vec![0xBB; 300]);
    assert_eq!(c3.body, vec![0xCC; 571]);
    let _ = send_task.await.unwrap();
}

#[tokio::test]
async fn tcp_link_rejects_bad_prefix_truncated_eof_and_bad_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let kp_server = StaticKeypair::generate().unwrap();
    let kp_wrong = StaticKeypair::generate().unwrap();
    let kp_client = StaticKeypair::generate().unwrap();

    // 1. Auth failure on wrong expected pubkey.
    let srv_kp_clone = kp_server.clone();
    let accept_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accept_noise_link(stream, &srv_kp_clone, Duration::from_secs(2)).await
    });

    let cli_res = connect_noise_link(
        &addr.to_string(),
        &kp_client,
        *kp_wrong.public(),
        Duration::from_secs(2),
    )
    .await;
    let srv_err = accept_task.await.unwrap().err();
    assert!(
        matches!(srv_err, Some(NetworkError::Crypto(_))),
        "expected responder crypto rejection on wrong server key, got {srv_err:?}"
    );
    let cli_err = cli_res.err();
    assert!(
        matches!(
            cli_err,
            Some(NetworkError::ConnectionClosed) | Some(NetworkError::Crypto(_))
        ),
        "expected initiator rejection on closed/bad handshake, got {cli_err:?}"
    );

    // 2. Truncated frame (< 600B) & abrupt EOF detection.
    let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let kp_s2 = kp_server.clone();
    tokio::spawn(async move {
        let (stream, _) = listener2.accept().await.unwrap();
        let (mut r, _w, _) = accept_noise_link(stream, &kp_s2, Duration::from_secs(2))
            .await
            .unwrap();
        let err = r.recv_cell(Duration::from_secs(2)).await.unwrap_err();
        assert!(matches!(err, NetworkError::ConnectionClosed));
    });

    let stream = TcpStream::connect(addr2).await.unwrap();
    let (mut r, mut w) = tokio::io::split(stream);
    let sess = private_relay_network::transport::run_initiator_handshake(
        &mut r,
        &mut w,
        &kp_client,
        *kp_server.public(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let _ = sess;
    // Send truncated 120-byte junk and close abruptly.
    w.write_all(&[0u8; 120]).await.unwrap();
    w.shutdown().await.unwrap();

    // 3. Bad outer length prefix (!= 598) over established session rejected as Protocol error.
    let (a, mut b) = tokio::io::duplex(OUTER_WIRE_FRAME_BYTES * 2);
    let mut init = LinkInitiator::new(&kp_client, *kp_server.public()).unwrap();
    let msg1 = init.write_msg1().unwrap();
    let (msg2, sess_srv) = LinkResponder::new(&kp_server)
        .unwrap()
        .process_msg1_and_finish(&msg1)
        .unwrap();
    let _sess_cli = init.finish_with_msg2(&msg2).unwrap();
    let (mut ra, _wa) = split_framed_session(a, sess_srv);

    let mut bad_wire = [0u8; OUTER_WIRE_FRAME_BYTES];
    bad_wire[0..2].copy_from_slice(&400u16.to_be_bytes());
    b.write_all(&bad_wire).await.unwrap();
    b.flush().await.unwrap();
    let err = ra.recv_cell(Duration::from_secs(2)).await.unwrap_err();
    assert!(matches!(
        err,
        NetworkError::Protocol(ProtocolError::InvalidOuterLengthPrefix { .. })
    ));

    // Config round-trip test.
    let cfg =
        RelayConfig::with_generated_keypair("entry-1", RelayRole::Entry, "127.0.0.1:0", &kp_server);
    let toml_str = cfg.to_toml_string().unwrap();
    let parsed = RelayConfig::from_toml_str(&toml_str).unwrap();
    assert_eq!(parsed.id, "entry-1");
    assert_eq!(parsed.role, RelayRole::Entry);
}

#[tokio::test]
async fn tcp_link_rekey_byte_limit_simultaneous_and_interrupted_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let kp_srv = StaticKeypair::generate().unwrap();
    let kp_cli = StaticKeypair::generate().unwrap();

    // Byte threshold = 1200B (triggers automatic rekey before every 3rd outgoing cell).
    let policy = LinkRekeyPolicy {
        max_bytes: 1200,
        max_age: Duration::from_secs(3600),
    };

    let srv_kp = kp_srv.clone();
    let srv_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut r, mut w, _) =
            accept_noise_link_with_rekey(stream, &srv_kp, Duration::from_secs(2), policy)
                .await
                .unwrap();

        for i in 1..=6u32 {
            let c = r.recv_cell(Duration::from_secs(2)).await.unwrap();
            assert_eq!(c.circuit_id.get(), i);
        }
        assert_eq!(r.rekey_epochs().unwrap().1, 2);

        // Explicit trigger on server writer + reply frame back to client.
        w.trigger_rekey(Duration::from_secs(2)).await.unwrap();
        w.send_cell(
            &Cell::new(
                CircuitId::new(99).unwrap(),
                Command::RelayData,
                0,
                vec![5; 8],
            )
            .unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(w.rekey_epochs().unwrap().0, 1);
        (r, w)
    });

    let (mut cr, mut cw) = connect_noise_link_with_rekey(
        &addr.to_string(),
        &kp_cli,
        *kp_srv.public(),
        Duration::from_secs(2),
        policy,
    )
    .await
    .unwrap();

    for i in 1..=6u32 {
        let cell = Cell::new(CircuitId::new(i).unwrap(), Command::Create, 0, vec![2; 12]).unwrap();
        cw.send_cell(&cell, Duration::from_secs(2)).await.unwrap();
    }
    assert_eq!(cw.rekey_epochs().unwrap().0, 2);

    let reply = cr.recv_cell(Duration::from_secs(2)).await.unwrap();
    assert_eq!(reply.circuit_id.get(), 99);
    assert_eq!(cr.rekey_epochs().unwrap(), (2, 1));

    let (mut sr, mut sw) = srv_task.await.unwrap();

    // Test consecutive empty rekey flood (> 4 without intervening Cell) fails closed.
    let cli_flood = tokio::spawn(async move {
        for _ in 0..5 {
            if cw.trigger_rekey(Duration::from_secs(2)).await.is_err() {
                break;
            }
        }
        cw
    });
    let err = sr.recv_cell(Duration::from_secs(2)).await.unwrap_err();
    assert!(matches!(err, NetworkError::Protocol(_)));
    let _cw = cli_flood.await.unwrap();
    let _ = sw.shutdown().await;
    drop(cr);

    // Interrupted rekey mid-frame over TCP fails closed on EOF.
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = l2.local_addr().unwrap();
    let kp_srv2 = kp_srv.clone();
    let recv_task2 = tokio::spawn(async move {
        let (stream, _) = l2.accept().await.unwrap();
        let (mut r, _w, _) = accept_noise_link(stream, &kp_srv2, Duration::from_secs(2))
            .await
            .unwrap();
        r.recv_cell(Duration::from_secs(2)).await
    });
    let s2 = TcpStream::connect(addr2).await.unwrap();
    let (mut r2, mut w2) = tokio::io::split(s2);
    let mut sess = private_relay_network::transport::run_initiator_handshake(
        &mut r2,
        &mut w2,
        &kp_cli,
        *kp_srv.public(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let rk_wire = sess.seal_rekey_and_rotate().unwrap();
    // Send half a rekey frame and drop socket abruptly.
    w2.write_all(&rk_wire[..250]).await.unwrap();
    w2.shutdown().await.unwrap();
    let interr = recv_task2.await.unwrap().err().unwrap();
    assert!(matches!(interr, NetworkError::ConnectionClosed));
}

#[test]
fn config_rejects_invalid_roles_mismatched_keys_loop_and_bounds() {
    let kp_entry = StaticKeypair::generate().unwrap();
    let kp_mid = StaticKeypair::generate().unwrap();
    let kp_exit = StaticKeypair::generate().unwrap();

    // 1. Mismatched private/public keypair rejected.
    let mut bad_kp_cfg =
        RelayConfig::with_generated_keypair("e1", RelayRole::Entry, "127.0.0.1:9101", &kp_entry);
    bad_kp_cfg.public_key_hex = private_relay_network::encode_hex(kp_mid.public());
    assert!(matches!(
        bad_kp_cfg.validate(),
        Err(NetworkError::Crypto(_))
    ));

    // 2. Invalid listen_addr rejected.
    let mut bad_addr_cfg =
        RelayConfig::with_generated_keypair("e1", RelayRole::Entry, "not-an-ip:9101", &kp_entry);
    assert!(matches!(
        bad_addr_cfg.validate(),
        Err(NetworkError::Config(_))
    ));
    bad_addr_cfg.listen_addr = "127.0.0.1:9101".into();

    // 3. Exit with allowed_next_peers rejected.
    let mut bad_exit_cfg =
        RelayConfig::with_generated_keypair("x1", RelayRole::Exit, "127.0.0.1:9103", &kp_exit);
    bad_exit_cfg.allowed_next_peers = vec![PeerDescriptor {
        id: "m1".into(),
        role: RelayRole::Middle,
        addr: "127.0.0.1:9102".into(),
        public_key_hex: private_relay_network::encode_hex(kp_mid.public()),
    }];
    assert!(matches!(
        bad_exit_cfg.validate(),
        Err(NetworkError::Config(_))
    ));

    // 4. Entry referencing Exit directly or self key rejected.
    let mut bad_hop_cfg =
        RelayConfig::with_generated_keypair("e1", RelayRole::Entry, "127.0.0.1:9101", &kp_entry);
    bad_hop_cfg.allowed_next_peers = vec![PeerDescriptor {
        id: "x1".into(),
        role: RelayRole::Exit,
        addr: "127.0.0.1:9103".into(),
        public_key_hex: private_relay_network::encode_hex(kp_exit.public()),
    }];
    assert!(matches!(
        bad_hop_cfg.validate(),
        Err(NetworkError::Config(_))
    ));

    bad_hop_cfg.allowed_next_peers = vec![PeerDescriptor {
        id: "self-loop".into(),
        role: RelayRole::Middle,
        addr: "127.0.0.1:9101".into(),
        public_key_hex: private_relay_network::encode_hex(kp_entry.public()),
    }];
    assert!(matches!(
        bad_hop_cfg.validate(),
        Err(NetworkError::Config(_))
    ));

    // 5. Invalid link_rekey_bytes (< 600) or zero connection limit rejected.
    let mut bad_bounds_cfg =
        RelayConfig::with_generated_keypair("e1", RelayRole::Entry, "127.0.0.1:9101", &kp_entry);
    bad_bounds_cfg.link_rekey_bytes = 599;
    assert!(matches!(
        bad_bounds_cfg.validate(),
        Err(NetworkError::Config(_))
    ));
    bad_bounds_cfg.link_rekey_bytes = 600;
    bad_bounds_cfg.max_concurrent_connections = 0;
    assert!(matches!(
        bad_bounds_cfg.validate(),
        Err(NetworkError::Config(_))
    ));

    let mut bad_priv_cfg =
        RelayConfig::with_generated_keypair("x2", RelayRole::Exit, "0.0.0.0:9103", &kp_exit);
    bad_priv_cfg.allow_private_targets_for_test = true;
    assert!(matches!(
        bad_priv_cfg.validate(),
        Err(NetworkError::Config(_))
    ));
    bad_priv_cfg.allowed_targets = vec!["demo-dest:9000".into()];
    assert!(bad_priv_cfg.validate().is_ok());

    // 6. ClientConfigFile rejects role mismatch or duplicate hop keys.
    let mut ccfg = ClientConfigFile {
        entry: PeerDescriptor {
            id: "e1".into(),
            role: RelayRole::Entry,
            addr: "127.0.0.1:9101".into(),
            public_key_hex: private_relay_network::encode_hex(kp_entry.public()),
        },
        middle: PeerDescriptor {
            id: "m1".into(),
            role: RelayRole::Middle,
            addr: "127.0.0.1:9102".into(),
            public_key_hex: private_relay_network::encode_hex(kp_mid.public()),
        },
        exit: PeerDescriptor {
            id: "x1".into(),
            role: RelayRole::Exit,
            addr: "127.0.0.1:9103".into(),
            public_key_hex: private_relay_network::encode_hex(kp_exit.public()),
        },
        handshake_timeout_ms: 5000,
        io_timeout_ms: 5000,
        request_timeout_ms: 10000,
        link_rekey_interval_secs: 3600,
        link_rekey_bytes: 1_073_741_824,
    };
    assert!(ccfg.validate().is_ok());
    ccfg.middle.role = RelayRole::Exit;
    assert!(ccfg.validate().is_err());
    ccfg.middle.role = RelayRole::Middle;
    ccfg.exit.public_key_hex = ccfg.entry.public_key_hex.clone();
    assert!(ccfg.validate().is_err());
}
