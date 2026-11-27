use std::sync::{Arc, Mutex};
use std::time::Duration;

use private_relay_client::{ClientConfig, ClientError, RelayClient};
use private_relay_crypto::{HopHandshakeInitiator, LinkRekeyPolicy, StaticKeypair};
use private_relay_network::{connect_noise_link, PeerDescriptor, RelayConfig, RelayRole};
use private_relay_protocol::{
    Cell, CircuitId, CircuitState, Command, DestroyReason, RequestErrorCode, MAX_MESSAGE_BYTES,
    OUTER_WIRE_FRAME_BYTES,
};
use private_relay_relay::{RelayHandle, RelayServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;
use tracing::field::{Field, Visit};
use tracing::span;
use tracing::{Event, Id, Metadata, Subscriber};

struct TestNetwork {
    entry: RelayHandle,
    middle: RelayHandle,
    exit: RelayHandle,
}

impl TestNetwork {
    async fn start(allow_loopback: bool, dest_timeout_ms: u64) -> Self {
        let exit_kp = StaticKeypair::generate().unwrap();
        let mut exit_cfg =
            RelayConfig::with_generated_keypair("exit-1", RelayRole::Exit, "127.0.0.1:0", &exit_kp);
        exit_cfg.allow_loopback_for_test = allow_loopback;
        exit_cfg.destination_io_timeout_ms = dest_timeout_ms;
        let exit = RelayServer::start(exit_cfg).await.unwrap();

        let mid_kp = StaticKeypair::generate().unwrap();
        let mut mid_cfg = RelayConfig::with_generated_keypair(
            "middle-1",
            RelayRole::Middle,
            "127.0.0.1:0",
            &mid_kp,
        );
        mid_cfg.allowed_next_peers = vec![exit.peer_descriptor().clone()];
        let middle = RelayServer::start(mid_cfg).await.unwrap();

        let entry_kp = StaticKeypair::generate().unwrap();
        let mut entry_cfg = RelayConfig::with_generated_keypair(
            "entry-1",
            RelayRole::Entry,
            "127.0.0.1:0",
            &entry_kp,
        );
        entry_cfg.allowed_next_peers = vec![middle.peer_descriptor().clone()];
        let entry = RelayServer::start(entry_cfg).await.unwrap();

        Self {
            entry,
            middle,
            exit,
        }
    }

    fn route(&self) -> [PeerDescriptor; 3] {
        [
            self.entry.peer_descriptor().clone(),
            self.middle.peer_descriptor().clone(),
            self.exit.peer_descriptor().clone(),
        ]
    }

    async fn shutdown(self) {
        self.entry.shutdown().await;
        self.middle.shutdown().await;
        self.exit.shutdown().await;
    }
}

async fn spawn_echo_destination() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                if s.read_to_end(&mut buf).await.is_ok() {
                    // Transform slightly to prove destination execution (reverse for small, invert bits for large).
                    for b in &mut buf {
                        *b ^= 0x5A;
                    }
                    let _ = s.write_all(&buf).await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn e2e_three_hop_empty_small_and_exact_64kib_requests_succeed() {
    let net = TestNetwork::start(true, 5_000).await;
    let dest = spawn_echo_destination().await;

    let mut circuit = RelayClient::connect_three_hop(net.route(), ClientConfig::default())
        .await
        .unwrap();
    assert_eq!(circuit.state(), CircuitState::Open);
    assert_eq!(net.entry.active_circuit_count(), 1);
    assert_eq!(net.middle.active_circuit_count(), 1);
    assert_eq!(net.exit.active_circuit_count(), 1);

    // 1) Empty 0-byte request
    let resp0 = circuit.send_request(&dest, b"").await.unwrap();
    assert!(resp0.is_empty());

    // 2) Small ASCII payload
    let small = b"private-relay v0.1 e2e check";
    let resp1 = circuit.send_request(&dest, small).await.unwrap();
    let expected1: Vec<u8> = small.iter().map(|b| b ^ 0x5A).collect();
    assert_eq!(resp1, expected1);

    // 3) Exact maximum 64 KiB (65,536 bytes) request + response across 136/135 chunks
    let large: Vec<u8> = (0..MAX_MESSAGE_BYTES).map(|i| (i % 251) as u8).collect();
    let resp2 = circuit.send_request(&dest, &large).await.unwrap();
    assert_eq!(resp2.len(), MAX_MESSAGE_BYTES);
    let expected2: Vec<u8> = large.iter().map(|b| b ^ 0x5A).collect();
    assert_eq!(resp2, expected2);

    circuit.close().await.unwrap();
    sleep(Duration::from_millis(80)).await;
    assert_eq!(net.entry.active_circuit_count(), 0);
    assert_eq!(net.middle.active_circuit_count(), 0);
    assert_eq!(net.exit.active_circuit_count(), 0);

    net.shutdown().await;
}

#[tokio::test]
async fn e2e_ssrf_and_destination_connect_errors_propagate_without_crashing_circuit() {
    // 1) SSRF disabled -> PolicyDenied on loopback destination
    let blocked_net = TestNetwork::start(false, 2_000).await;
    let dest = spawn_echo_destination().await;
    let mut circuit = RelayClient::connect_three_hop(blocked_net.route(), ClientConfig::default())
        .await
        .unwrap();
    let err = circuit.send_request(&dest, b"ssrf").await.unwrap_err();
    assert!(matches!(
        err,
        ClientError::RemoteError(RequestErrorCode::PolicyDenied)
    ));
    circuit.close().await.unwrap();
    blocked_net.shutdown().await;

    // 2) Unbound port -> ConnectFailed, yet circuit remains healthy for subsequent request
    let open_net = TestNetwork::start(true, 5_000).await;
    let temp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port_addr = temp.local_addr().unwrap().to_string();
    drop(temp);

    let mut circuit2 = RelayClient::connect_three_hop(open_net.route(), ClientConfig::default())
        .await
        .unwrap();
    let err2 = circuit2
        .send_request(&closed_port_addr, b"hello")
        .await
        .unwrap_err();
    assert!(
        matches!(
            err2,
            ClientError::RemoteError(RequestErrorCode::ConnectFailed)
        ),
        "expected ConnectFailed, got {err2:?}"
    );

    let resp_ok = circuit2.send_request(&dest, b"still-alive").await.unwrap();
    assert_eq!(
        resp_ok,
        b"still-alive".iter().map(|b| b ^ 0x5A).collect::<Vec<u8>>()
    );
    circuit2.close().await.unwrap();
    open_net.shutdown().await;
}

#[tokio::test]
async fn e2e_oversized_request_and_oversized_response_are_enforced() {
    let net = TestNetwork::start(true, 5_000).await;

    let flood_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let flood_addr = flood_listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = flood_listener.accept().await {
            let mut req = Vec::new();
            let _ = s.read_to_end(&mut req).await;
            let oversized = vec![0x41u8; MAX_MESSAGE_BYTES + 2048];
            let _ = s.write_all(&oversized).await;
            let _ = s.shutdown().await;
        }
    });

    let mut circuit = RelayClient::connect_three_hop(net.route(), ClientConfig::default())
        .await
        .unwrap();

    // Oversized request (> 64 KiB) rejected locally before sending
    let too_big_req = vec![0x55u8; MAX_MESSAGE_BYTES + 1];
    let req_err = circuit
        .send_request(&flood_addr, &too_big_req)
        .await
        .unwrap_err();
    assert!(matches!(req_err, ClientError::Protocol(_)));

    // Oversized response (> 64 KiB) stopped at Exit with PayloadTooLarge
    let resp_err = circuit
        .send_request(&flood_addr, b"trigger-flood")
        .await
        .unwrap_err();
    assert!(matches!(
        resp_err,
        ClientError::RemoteError(RequestErrorCode::PayloadTooLarge)
    ));

    circuit.close().await.unwrap();
    net.shutdown().await;
}

#[tokio::test]
async fn e2e_slow_destination_triggers_exit_timeout_code() {
    let net = TestNetwork::start(true, 300).await;
    let slow_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = slow_listener.accept().await {
            let mut req = Vec::new();
            let _ = s.read_to_end(&mut req).await;
            sleep(Duration::from_millis(1200)).await;
        }
    });

    let mut circuit = RelayClient::connect_three_hop(net.route(), ClientConfig::default())
        .await
        .unwrap();
    let err = circuit.send_request(&slow_addr, b"slow").await.unwrap_err();
    assert!(matches!(
        err,
        ClientError::RemoteError(RequestErrorCode::Timeout)
    ));

    circuit.close().await.unwrap();
    net.shutdown().await;
}

#[tokio::test]
async fn e2e_relay_unavailable_and_wrong_pubkey_fail_cleanly() {
    let net = TestNetwork::start(true, 2_000).await;

    // 1) Wrong Entry public key triggers Noise authentication failure
    let mut bad_route = net.route();
    bad_route[0].public_key_hex = "02".repeat(32);
    let auth_err = RelayClient::connect_three_hop(bad_route, ClientConfig::default())
        .await
        .err()
        .unwrap();
    assert!(matches!(
        auth_err,
        ClientError::Network(_) | ClientError::Crypto(_)
    ));

    // 2) Unreachable Middle in Entry allowlist -> PeerDisconnected destroy & 0 leaked Entry circuits
    let fake_kp = StaticKeypair::generate().unwrap();
    let mut dead_mid = PeerDescriptor {
        id: "dead-mid".into(),
        role: RelayRole::Middle,
        addr: "127.0.0.1:9".into(),
        public_key_hex: private_relay_network::encode_hex(fake_kp.public()),
    };

    let entry2_kp = StaticKeypair::generate().unwrap();
    let mut entry2_cfg = RelayConfig::with_generated_keypair(
        "entry-dead-mid",
        RelayRole::Entry,
        "127.0.0.1:0",
        &entry2_kp,
    );
    entry2_cfg.allowed_next_peers = vec![dead_mid.clone()];
    let entry2 = RelayServer::start(entry2_cfg).await.unwrap();
    dead_mid.addr = "127.0.0.1:9".into();

    let route_dead_mid = [
        entry2.peer_descriptor().clone(),
        dead_mid,
        net.exit.peer_descriptor().clone(),
    ];
    let ext_err = RelayClient::connect_three_hop(
        route_dead_mid,
        ClientConfig {
            handshake_timeout: Duration::from_millis(800),
            io_timeout: Duration::from_millis(800),
            request_timeout: Duration::from_secs(2),
        },
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(
        ext_err,
        ClientError::CircuitDestroyed(DestroyReason::PeerDisconnected)
            | ClientError::CircuitDestroyed(DestroyReason::HandshakeTimeout)
            | ClientError::Network(_)
    ));

    sleep(Duration::from_millis(120)).await;
    assert_eq!(entry2.active_circuit_count(), 0);

    entry2.shutdown().await;
    net.shutdown().await;
}

#[tokio::test]
async fn e2e_middle_shutdown_mid_circuit_propagates_destroy_and_cleans_up() {
    let net = TestNetwork::start(true, 5_000).await;
    let dest = spawn_echo_destination().await;
    let route = net.route();

    let mut circuit = RelayClient::connect_three_hop(route, ClientConfig::default())
        .await
        .unwrap();
    let first = circuit.send_request(&dest, b"before-crash").await.unwrap();
    assert_eq!(
        first,
        b"before-crash"
            .iter()
            .map(|b| b ^ 0x5A)
            .collect::<Vec<u8>>()
    );

    // Tear down Middle relay abruptly; wait for disconnect propagation across Entry & Exit.
    let TestNetwork {
        entry,
        middle,
        exit,
    } = net;
    middle.shutdown().await;
    sleep(Duration::from_millis(100)).await;

    let err = circuit
        .send_request(&dest, b"after-crash")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ClientError::CircuitDestroyed(DestroyReason::PeerDisconnected)
            | ClientError::CircuitDestroyed(DestroyReason::Normal)
            | ClientError::Network(_)
    ));

    sleep(Duration::from_millis(80)).await;
    assert_eq!(entry.active_circuit_count(), 0);
    assert_eq!(exit.active_circuit_count(), 0);

    entry.shutdown().await;
    exit.shutdown().await;
}

#[tokio::test]
async fn e2e_tampered_frame_or_hop_ciphertext_destroys_circuit() {
    let net = TestNetwork::start(true, 5_000).await;

    // 1) Hop ciphertext tamper: flip 1 bit of inner hop ciphertext sent on valid Noise link to Entry
    let client_kp = StaticKeypair::generate().unwrap();
    let entry_pub = net.entry.peer_descriptor().public_key().unwrap();
    let (mut reader, mut writer) = connect_noise_link(
        &net.entry.peer_descriptor().addr,
        &client_kp,
        entry_pub,
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    let cid = CircuitId::from_role_bits(42, true).unwrap();
    let mut init1 = HopHandshakeInitiator::new(1, entry_pub).unwrap();
    writer
        .send_cell(
            &Cell::new(cid, Command::Create, 0, init1.write_msg1().unwrap()).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    let created = reader.recv_cell(Duration::from_secs(2)).await.unwrap();
    let _hop1 = init1.finish_with_msg2(&created.body).unwrap();

    let tampered_body = vec![0xAAu8; 64];
    writer
        .send_cell(
            &Cell::new(cid, Command::Extend, 0, tampered_body).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    let resp = reader.recv_cell(Duration::from_secs(2)).await.unwrap();
    assert_eq!(resp.command, Command::Destroy);
    assert_eq!(resp.destroy_reason().unwrap(), DestroyReason::CryptoFail);

    // 2) Outer Noise wire MITM tamper via TCP bitflip proxy -> Noise rejects frame & closes connection
    let entry_addr = net.entry.peer_descriptor().addr.clone();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        if let Ok((mut client_s, _)) = proxy_listener.accept().await {
            if let Ok(mut server_s) = tokio::net::TcpStream::connect(&entry_addr).await {
                let (mut cr, mut cw) = client_s.split();
                let (mut sr, mut sw) = server_s.split();
                let to_server = async {
                    // Forward Noise_IK handshake frames cleanly, then flip 1 bit in the first 600B cell
                    let mut buf = [0u8; 2048];
                    let mut sent_bytes = 0usize;
                    let mut flipped = false;
                    while let Ok(n) = cr.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        sent_bytes += n;
                        // Noise_IK client handshake is 96B msg1 + 2B prefix; subsequent 600B frame is Cell
                        if !flipped && n >= OUTER_WIRE_FRAME_BYTES && sent_bytes > 120 {
                            buf[n - 10] ^= 0x01;
                            flipped = true;
                        }
                        if sw.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                };
                let to_client = async {
                    let _ = tokio::io::copy(&mut sr, &mut cw).await;
                };
                tokio::join!(to_server, to_client);
            }
        }
    });

    let mut proxy_route = net.route();
    proxy_route[0].addr = proxy_addr;
    let proxy_err = RelayClient::connect_three_hop(
        proxy_route,
        ClientConfig {
            handshake_timeout: Duration::from_secs(2),
            io_timeout: Duration::from_secs(2),
            request_timeout: Duration::from_secs(2),
        },
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(proxy_err, ClientError::Network(_)));

    net.shutdown().await;
}

struct LogCaptureSubscriber {
    lines: Arc<Mutex<Vec<String>>>,
}

static GLOBAL_LOG_LINES: std::sync::OnceLock<Arc<Mutex<Vec<String>>>> = std::sync::OnceLock::new();

fn global_log_buffer() -> &'static Arc<Mutex<Vec<String>>> {
    GLOBAL_LOG_LINES.get_or_init(|| {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let subscriber = LogCaptureSubscriber {
            lines: Arc::clone(&lines),
        };
        let _ = tracing::subscriber::set_global_default(subscriber);
        lines
    })
}

struct FieldVisitor<'a>(&'a mut String);
impl Visit for FieldVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.push_str(&format!(" {}={:?}", field.name(), value));
    }
}

impl Subscriber for LogCaptureSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _span: &span::Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _span: &Id, _values: &span::Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut line = String::new();
        event.record(&mut FieldVisitor(&mut line));
        if let Ok(mut guard) = self.lines.lock() {
            guard.push(line);
        }
    }
    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
}

#[tokio::test]
async fn tracing_logs_never_contain_ips_destinations_keys_or_payloads() {
    let lines = global_log_buffer();
    let start_idx = lines.lock().unwrap().len();

    let net = TestNetwork::start(true, 5_000).await;
    let route = net.route();
    let dest = spawn_echo_destination().await;
    let canary_payload = b"CANARY_SECRET_USER_DATA_999";

    let mut circuit = RelayClient::connect_three_hop(route.clone(), ClientConfig::default())
        .await
        .unwrap();
    let _ = circuit.send_request(&dest, canary_payload).await.unwrap();
    circuit.close().await.unwrap();
    net.shutdown().await;

    let captured = {
        let guard = lines.lock().unwrap();
        guard[start_idx..].join("\n")
    };
    assert!(
        !captured.is_empty(),
        "expected tracing events to be captured"
    );
    assert!(
        !captured.contains("127.0.0.1"),
        "IP leaked in logs: {captured}"
    );
    assert!(
        !captured.contains(&dest),
        "Destination leaked in logs: {captured}"
    );
    for hop in &route {
        assert!(
            !captured.contains(&hop.public_key_hex),
            "Relay public key hex leaked in logs: {captured}"
        );
    }
    assert!(
        !captured.contains("CANARY_SECRET_USER_DATA_999"),
        "Payload leaked in logs: {captured}"
    );
}

#[tokio::test]
async fn e2e_three_hop_survives_automatic_link_rekeys() {
    // Configure aggressive 1200-byte rekey threshold on all 3 relays and Client->Entry link.
    let exit_kp = StaticKeypair::generate().unwrap();
    let mut exit_cfg =
        RelayConfig::with_generated_keypair("exit-rk", RelayRole::Exit, "127.0.0.1:0", &exit_kp);
    exit_cfg.allow_loopback_for_test = true;
    exit_cfg.link_rekey_bytes = 1200;
    let exit = RelayServer::start(exit_cfg).await.unwrap();

    let mid_kp = StaticKeypair::generate().unwrap();
    let mut mid_cfg =
        RelayConfig::with_generated_keypair("mid-rk", RelayRole::Middle, "127.0.0.1:0", &mid_kp);
    mid_cfg.allowed_next_peers = vec![exit.peer_descriptor().clone()];
    mid_cfg.link_rekey_bytes = 1200;
    let middle = RelayServer::start(mid_cfg).await.unwrap();

    let entry_kp = StaticKeypair::generate().unwrap();
    let mut entry_cfg =
        RelayConfig::with_generated_keypair("entry-rk", RelayRole::Entry, "127.0.0.1:0", &entry_kp);
    entry_cfg.allowed_next_peers = vec![middle.peer_descriptor().clone()];
    entry_cfg.link_rekey_bytes = 1200;
    let entry = RelayServer::start(entry_cfg).await.unwrap();

    let dest = spawn_echo_destination().await;
    let route = [
        entry.peer_descriptor().clone(),
        middle.peer_descriptor().clone(),
        exit.peer_descriptor().clone(),
    ];
    let rekey_policy = LinkRekeyPolicy {
        max_bytes: 1200,
        max_age: Duration::from_secs(3600),
    };

    let mut circuit =
        RelayClient::connect_three_hop_with_rekey(route, ClientConfig::default(), rekey_policy)
            .await
            .unwrap();

    let payload: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let resp = circuit.send_request(&dest, &payload).await.unwrap();
    let expected: Vec<u8> = payload.iter().map(|b| b ^ 0x5A).collect();
    assert_eq!(resp, expected);

    // Confirm multiple synchronized automatic Noise link rekeys occurred in BOTH directions.
    let (out_epoch, in_epoch) = circuit.link_rekey_epochs().unwrap();
    assert!(
        out_epoch >= 5,
        "expected outgoing link rekeys, got {out_epoch}"
    );
    assert!(
        in_epoch >= 5,
        "expected incoming link rekeys, got {in_epoch}"
    );

    circuit.close().await.unwrap();
    entry.shutdown().await;
    middle.shutdown().await;
    exit.shutdown().await;
}

#[tokio::test]
async fn e2e_redirect_response_is_not_followed_to_ssrf_target() {
    let net = TestNetwork::start(true, 5_000).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = listener.accept().await {
            let mut req = Vec::new();
            let _ = s.read_to_end(&mut req).await;
            let _ = s
                .write_all(
                    b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = s.shutdown().await;
        }
    });

    let mut circuit = RelayClient::connect_three_hop(net.route(), ClientConfig::default())
        .await
        .unwrap();
    let raw = circuit
        .send_request(&dest, b"GET /redirect HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(raw.starts_with(b"HTTP/1.1 302 Found"));

    circuit.close().await.unwrap();
    net.shutdown().await;
}

#[tokio::test]
async fn e2e_client_request_timeout_closes_circuit_and_prevents_reuse_desync() {
    let net = TestNetwork::start(true, 3_000).await;
    let slow_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = slow_listener.accept().await {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf).await;
            sleep(Duration::from_millis(1_500)).await;
        }
    });

    let cfg = ClientConfig {
        handshake_timeout: Duration::from_secs(2),
        io_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_millis(180),
    };
    let mut circuit = RelayClient::connect_three_hop(net.route(), cfg)
        .await
        .unwrap();

    let err = circuit.send_request(&slow_addr, b"slow").await.unwrap_err();
    assert!(matches!(
        err,
        ClientError::Network(private_relay_network::NetworkError::Timeout(_))
    ));
    assert!(circuit.state().is_closed());

    // Reusing the timed-out circuit must fail cleanly locally rather than colliding with Exit state.
    let reuse_err = circuit
        .send_request(&slow_addr, b"retry")
        .await
        .unwrap_err();
    assert!(matches!(reuse_err, ClientError::InvalidState(_)));

    sleep(Duration::from_millis(150)).await;
    assert_eq!(net.entry.active_circuit_count(), 0);
    assert_eq!(net.middle.active_circuit_count(), 0);
    assert_eq!(net.exit.active_circuit_count(), 0);

    net.shutdown().await;
}
