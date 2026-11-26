use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use private_relay_crypto::{LinkInitiator, LinkResponder, StaticKeypair};
use private_relay_network::{
    accept_noise_link, connect_noise_link, split_framed_session, DestinationPolicy, NetworkError,
    RelayConfig, RelayRole,
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
        IpAddr::V6("fc00::1".parse().unwrap()),
        IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
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

    // Explicit test loopback flag + allowlist works only for listed targets.
    let test_policy = DestinationPolicy {
        allow_loopback_for_test: true,
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
