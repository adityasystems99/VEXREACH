use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use private_relay_client::{ClientConfig, RelayClient};
use private_relay_crypto::StaticKeypair;
use private_relay_network::{PeerDescriptor, RelayConfig, RelayRole};
use private_relay_relay::{RelayHandle, RelayServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct TestThreeHopHarness {
    entry_desc: PeerDescriptor,
    middle_desc: PeerDescriptor,
    exit_desc: PeerDescriptor,
    dest_addr: String,
    entry_handle: RelayHandle,
    middle_handle: RelayHandle,
    exit_handle: RelayHandle,
}

impl TestThreeHopHarness {
    async fn start_with_dest_handler<F, Fut>(dest_handler: F) -> Self
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = dest_listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = dest_listener.accept().await {
                    let fut = dest_handler(stream);
                    tokio::spawn(fut);
                }
            }
        });

        let entry_kp = StaticKeypair::generate().unwrap();
        let middle_kp = StaticKeypair::generate().unwrap();
        let exit_kp = StaticKeypair::generate().unwrap();

        let mut exit_cfg = RelayConfig::with_generated_keypair(
            "exit-resilience",
            RelayRole::Exit,
            "127.0.0.1:0",
            &exit_kp,
        );
        exit_cfg.allow_loopback_for_test = true;
        exit_cfg.max_concurrent_connections = 128;
        exit_cfg.max_concurrent_circuits = 512;
        exit_cfg.allowed_targets = vec![dest_addr.clone()];
        exit_cfg.metrics_addr = Some("127.0.0.1:0".to_owned());
        let exit_handle = RelayServer::start(exit_cfg).await.unwrap();
        let exit_desc = exit_handle.peer_descriptor().clone();

        let mut middle_cfg = RelayConfig::with_generated_keypair(
            "middle-resilience",
            RelayRole::Middle,
            "127.0.0.1:0",
            &middle_kp,
        );
        middle_cfg.allow_loopback_for_test = true;
        middle_cfg.max_concurrent_connections = 128;
        middle_cfg.max_concurrent_circuits = 512;
        middle_cfg.allowed_next_peers = vec![exit_desc.clone()];
        middle_cfg.metrics_addr = Some("127.0.0.1:0".to_owned());
        let middle_handle = RelayServer::start(middle_cfg).await.unwrap();
        let middle_desc = middle_handle.peer_descriptor().clone();

        let mut entry_cfg = RelayConfig::with_generated_keypair(
            "entry-resilience",
            RelayRole::Entry,
            "127.0.0.1:0",
            &entry_kp,
        );
        entry_cfg.allow_loopback_for_test = true;
        entry_cfg.max_concurrent_connections = 128;
        entry_cfg.max_concurrent_circuits = 512;
        entry_cfg.max_circuits_per_peer_ip = 64;
        entry_cfg.allowed_next_peers = vec![middle_desc.clone()];
        entry_cfg.metrics_addr = Some("127.0.0.1:0".to_owned());
        let entry_handle = RelayServer::start(entry_cfg).await.unwrap();
        let entry_desc = entry_handle.peer_descriptor().clone();

        Self {
            entry_desc,
            middle_desc,
            exit_desc,
            dest_addr,
            entry_handle,
            middle_handle,
            exit_handle,
        }
    }

    fn route(&self) -> [PeerDescriptor; 3] {
        [
            self.entry_desc.clone(),
            self.middle_desc.clone(),
            self.exit_desc.clone(),
        ]
    }

    async fn shutdown(self) {
        self.entry_handle.shutdown().await;
        self.middle_handle.shutdown().await;
        self.exit_handle.shutdown().await;
    }
}

async fn run_concurrent_batch(
    route: [PeerDescriptor; 3],
    target: &str,
    concurrency: usize,
) -> (usize, usize, Duration) {
    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::with_capacity(concurrency);
    let started = Instant::now();

    for i in 0..concurrency {
        let r = route.clone();
        let tgt = target.to_owned();
        let succ = Arc::clone(&success_count);
        let fail = Arc::clone(&failure_count);
        tasks.push(tokio::spawn(async move {
            let cfg = ClientConfig {
                handshake_timeout: Duration::from_secs(5),
                io_timeout: Duration::from_secs(5),
                request_timeout: Duration::from_secs(10),
            };
            match RelayClient::connect_three_hop(r, cfg).await {
                Ok(mut circuit) => {
                    let req = format!("GET /load-{i} HTTP/1.1\r\nHost: test\r\n\r\n");
                    match circuit.send_request(&tgt, req.as_bytes()).await {
                        Ok(resp) if resp.starts_with(b"HTTP/1.1 200 OK") => {
                            succ.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            fail.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    let _ = circuit.close().await;
                }
                Err(_) => {
                    fail.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for t in tasks {
        let _ = t.await;
    }

    (
        success_count.load(Ordering::Relaxed),
        failure_count.load(Ordering::Relaxed),
        started.elapsed(),
    )
}

async fn scrape_metrics(addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf).await;
    String::from_utf8_lossy(&buf).into_owned()
}

/// Day 9 Concurrency Ramp: 1, 5, 10, and 25 concurrent clients + state cleanup verification.
#[tokio::test]
async fn resilience_concurrency_ramp_1_5_10_25_and_state_cleanup() {
    let harness = TestThreeHopHarness::start_with_dest_handler(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello-load",
            )
            .await;
    })
    .await;

    for n in [1usize, 5, 10, 25] {
        let (ok, err, elapsed) = run_concurrent_batch(harness.route(), &harness.dest_addr, n).await;
        let rps = (ok as f64) / elapsed.as_secs_f64().max(0.001);
        println!("concurrency={n}: ok={ok} err={err} elapsed={elapsed:?} rps={rps:.1}");
        assert_eq!(ok, n, "all {n} concurrent clients must succeed");
        assert_eq!(err, 0);
    }

    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(harness.entry_handle.active_circuit_count(), 0);
    assert_eq!(harness.middle_handle.active_circuit_count(), 0);
    assert_eq!(harness.exit_handle.active_circuit_count(), 0);

    harness.shutdown().await;
}

/// Day 9 Failure Injection: abrupt reset, malformed non-HTTP destination bytes, and repeated error resilience.
#[tokio::test]
async fn resilience_destination_failures_malformed_and_recovery() {
    let mode = Arc::new(AtomicUsize::new(0));
    let mode_clone = Arc::clone(&mode);

    let harness = TestThreeHopHarness::start_with_dest_handler(move |mut stream| {
        let m = mode_clone.load(Ordering::Relaxed);
        async move {
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            match m {
                0 => drop(stream), // abrupt reset / empty EOF
                1 => {
                    // Malformed binary / non-HTTP bytes
                    let _ = stream.write_all(&[0xFF, 0x00, 0xFE, 0x7F, 0x01]).await;
                }
                _ => {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                }
            }
        }
    })
    .await;

    let cfg = ClientConfig {
        handshake_timeout: Duration::from_secs(5),
        io_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(5),
    };

    // 1. Abrupt destination EOF returns cleanly; repeated SSRF failures stay isolated.
    let mut circuit = RelayClient::connect_three_hop(harness.route(), cfg)
        .await
        .unwrap();
    let eof_res = circuit
        .send_request(&harness.dest_addr, b"GET /reset HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(eof_res.is_empty());

    // 2. Malformed binary destination payload passes safely without crashing Exit or Client.
    mode.store(1, Ordering::Relaxed);
    let malformed = circuit
        .send_request(&harness.dest_addr, b"GET /bad HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert_eq!(malformed, vec![0xFF, 0x00, 0xFE, 0x7F, 0x01]);

    // 3. Repeated SSRF errors do not break healthy circuit reuse.
    for _ in 0..5 {
        assert!(circuit
            .send_request("169.254.169.254:80", b"GET / HTTP/1.1\r\n\r\n")
            .await
            .is_err());
    }
    mode.store(2, Ordering::Relaxed);
    let ok = circuit
        .send_request(&harness.dest_addr, b"GET /recover HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(ok.starts_with(b"HTTP/1.1 200 OK"));
    let _ = circuit.close().await;

    harness.shutdown().await;
}

/// Day 9 Failure Injection: Entry SIGTERM/shutdown mid-request drains active tasks cleanly.
#[tokio::test]
async fn resilience_entry_sigterm_mid_request_drains_cleanly() {
    let harness = TestThreeHopHarness::start_with_dest_handler(|mut stream| async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await;
    })
    .await;

    let mut circuit = RelayClient::connect_three_hop(
        harness.route(),
        ClientConfig {
            handshake_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
        },
    )
    .await
    .unwrap();
    let target = harness.dest_addr.clone();
    let client_task = tokio::spawn(async move {
        circuit
            .send_request(&target, b"GET /slow-drain HTTP/1.1\r\n\r\n")
            .await
    });

    tokio::time::sleep(Duration::from_millis(80)).await;
    let shutdown_start = Instant::now();
    harness.entry_handle.shutdown().await;
    assert!(shutdown_start.elapsed() < Duration::from_secs(4));

    let _ = client_task.await;
    harness.middle_handle.shutdown().await;
    harness.exit_handle.shutdown().await;
}

/// Day 9 Restart & Recovery: Entry/Middle/Exit fail closed when down and recover on restart.
#[tokio::test]
async fn resilience_relay_restart_fail_closed_and_recovery() {
    let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest_addr = dest_listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = dest_listener.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            });
        }
    });

    let ekp = StaticKeypair::generate().unwrap();
    let mkp = StaticKeypair::generate().unwrap();
    let xkp = StaticKeypair::generate().unwrap();

    let mut xcfg =
        RelayConfig::with_generated_keypair("exit-r", RelayRole::Exit, "127.0.0.1:0", &xkp);
    xcfg.allow_loopback_for_test = true;
    xcfg.allowed_targets = vec![dest_addr.clone()];
    let xhandle = RelayServer::start(xcfg).await.unwrap();
    let xdesc = xhandle.peer_descriptor().clone();

    let mut mcfg =
        RelayConfig::with_generated_keypair("mid-r", RelayRole::Middle, "127.0.0.1:0", &mkp);
    mcfg.allowed_next_peers = vec![xdesc.clone()];
    let mhandle = RelayServer::start(mcfg.clone()).await.unwrap();
    let mdesc = mhandle.peer_descriptor().clone();
    mcfg.listen_addr = mhandle.local_addr().to_string();

    let mut ecfg =
        RelayConfig::with_generated_keypair("ent-r", RelayRole::Entry, "127.0.0.1:0", &ekp);
    ecfg.allowed_next_peers = vec![mdesc.clone()];
    let ehandle = RelayServer::start(ecfg).await.unwrap();
    let edesc = ehandle.peer_descriptor().clone();

    let route = [edesc, mdesc, xdesc];
    let ccfg = ClientConfig {
        handshake_timeout: Duration::from_secs(2),
        io_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(4),
    };

    // Baseline succeeds before restart.
    let mut c1 = RelayClient::connect_three_hop(route.clone(), ccfg)
        .await
        .unwrap();
    assert!(c1
        .send_request(&dest_addr, b"GET /1 HTTP/1.1\r\n\r\n")
        .await
        .unwrap()
        .starts_with(b"HTTP/1.1 200 OK"));
    let _ = c1.close().await;

    // Shutdown Middle: new circuits must fail closed rather than bypassing Middle.
    mhandle.shutdown().await;
    assert!(RelayClient::connect_three_hop(route.clone(), ccfg)
        .await
        .is_err());

    // Restart Middle on same address/keypair: new circuits immediately succeed again.
    let mhandle_restarted = RelayServer::start(mcfg).await.unwrap();
    let mut c2 = RelayClient::connect_three_hop(route, ccfg).await.unwrap();
    assert!(c2
        .send_request(&dest_addr, b"GET /2 HTTP/1.1\r\n\r\n")
        .await
        .unwrap()
        .starts_with(b"HTTP/1.1 200 OK"));
    let _ = c2.close().await;

    ehandle.shutdown().await;
    mhandle_restarted.shutdown().await;
    xhandle.shutdown().await;
}

/// Day 10 E2E Observability: Live 3-hop traffic updates Entry/Middle/Exit Prometheus metrics without leaks.
#[tokio::test]
async fn e2e_three_hop_prometheus_metrics_and_privacy_bounds() {
    let harness = TestThreeHopHarness::start_with_dest_handler(|mut stream| async move {
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await;
    })
    .await;

    let mut circuit = RelayClient::connect_three_hop(
        harness.route(),
        ClientConfig {
            handshake_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(5),
        },
    )
    .await
    .unwrap();

    let ok = circuit
        .send_request(&harness.dest_addr, b"GET /secret-path HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    assert!(ok.starts_with(b"HTTP/1.1 200 OK"));
    assert!(circuit
        .send_request("169.254.169.254:80", b"GET /latest HTTP/1.1\r\n\r\n")
        .await
        .is_err());
    let _ = circuit.close().await;
    tokio::time::sleep(Duration::from_millis(80)).await;

    let e_m = scrape_metrics(harness.entry_handle.metrics_local_addr().unwrap()).await;
    let m_m = scrape_metrics(harness.middle_handle.metrics_local_addr().unwrap()).await;
    let x_m = scrape_metrics(harness.exit_handle.metrics_local_addr().unwrap()).await;

    for body in [&e_m, &m_m, &x_m] {
        assert!(body.contains("private_relay_up{"));
        assert!(body.contains("private_relay_circuits_created_total{"));
        assert!(body.contains("private_relay_hop_handshakes_total{"));
        assert!(!body.contains("127.0.0.1"));
        assert!(!body.contains("169.254.169.254"));
        assert!(!body.contains("secret-path"));
        assert!(!body.contains("/latest"));
    }

    assert!(e_m.contains(
        "private_relay_circuits_created_total{role=\"entry\",node=\"entry-resilience\"} 1"
    ));
    assert!(!e_m
        .contains("private_relay_bytes_sent_total{role=\"entry\",node=\"entry-resilience\"} 0\n"));
    assert!(m_m.contains(
        "private_relay_circuits_created_total{role=\"middle\",node=\"middle-resilience\"} 1"
    ));
    assert!(x_m.contains("private_relay_requests_total{role=\"exit\",node=\"exit-resilience\"} 2"));
    assert!(x_m.contains(
        "private_relay_requests_success_total{role=\"exit\",node=\"exit-resilience\"} 1"
    ));
    assert!(x_m
        .contains("private_relay_requests_failed_total{role=\"exit\",node=\"exit-resilience\"} 1"));
    assert!(
        x_m.contains("private_relay_ssrf_denials_total{role=\"exit\",node=\"exit-resilience\"} 1")
    );
    assert!(x_m.contains(
        "private_relay_request_duration_seconds_count{role=\"exit\",node=\"exit-resilience\"} 2"
    ));

    harness.shutdown().await;
}
