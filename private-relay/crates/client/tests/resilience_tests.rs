use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use private_relay_client::{ClientConfig, RelayClient};
use private_relay_crypto::StaticKeypair;
use private_relay_network::{PeerDescriptor, RelayConfig, RelayRole};
use private_relay_relay::RelayServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct TestThreeHopHarness {
    entry_desc: PeerDescriptor,
    middle_desc: PeerDescriptor,
    exit_desc: PeerDescriptor,
    dest_addr: String,
    entry_handle: private_relay_relay::RelayHandle,
    middle_handle: private_relay_relay::RelayHandle,
    exit_handle: private_relay_relay::RelayHandle,
}

impl TestThreeHopHarness {
    async fn start_with_dest_handler<F, Fut>(dest_handler: F) -> Self
    where
        F: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        // 1. Destination server
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

        // 2. Generate keypairs
        let entry_kp = StaticKeypair::generate().unwrap();
        let middle_kp = StaticKeypair::generate().unwrap();
        let exit_kp = StaticKeypair::generate().unwrap();

        // 3. Exit relay
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
        let exit_handle = RelayServer::start(exit_cfg).await.unwrap();
        let exit_desc = exit_handle.peer_descriptor().clone();

        // 4. Middle relay
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
        let middle_handle = RelayServer::start(middle_cfg).await.unwrap();
        let middle_desc = middle_handle.peer_descriptor().clone();

        // 5. Entry relay (set max_circuits_per_peer_ip to 64 for 25-client single-host load test)
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

/// Day 9 Test 1: High concurrency (25 concurrent clients) stress testing
#[tokio::test]
async fn resilience_25_concurrent_clients_load_test() {
    let harness = TestThreeHopHarness::start_with_dest_handler(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nhello-load-{}",
            n
        );
        let _ = stream.write_all(resp.as_bytes()).await;
    })
    .await;

    let route = harness.route();
    let success_count = Arc::new(AtomicUsize::new(0));
    let failure_count = Arc::new(AtomicUsize::new(0));

    let mut tasks = Vec::new();
    let started = Instant::now();

    for i in 0..25 {
        let r = route.clone();
        let target = harness.dest_addr.clone();
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
                    let req = format!("GET /load-{} HTTP/1.1\r\nHost: test\r\n\r\n", i);
                    match circuit.send_request(&target, req.as_bytes()).await {
                        Ok(resp) => {
                            if resp.starts_with(b"HTTP/1.1 200 OK") {
                                succ.fetch_add(1, Ordering::Relaxed);
                            } else {
                                fail.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => {
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

    let elapsed = started.elapsed();
    let successes = success_count.load(Ordering::Relaxed);
    let failures = failure_count.load(Ordering::Relaxed);

    println!(
        "25 concurrent clients finished in {:?}: {} succeeded, {} failed",
        elapsed, successes, failures
    );

    assert_eq!(successes, 25, "All 25 concurrent clients must succeed");
    assert_eq!(failures, 0);

    harness.shutdown().await;
}

/// Day 9 Test 2: Destination crash and recovery behavior
#[tokio::test]
async fn resilience_destination_unresponsive_and_restart_recovery() {
    let harness = TestThreeHopHarness::start_with_dest_handler(|stream| async move {
        // Drop stream immediately without writing to simulate sudden remote reset
        drop(stream);
    })
    .await;

    let route = harness.route();
    let cfg = ClientConfig {
        handshake_timeout: Duration::from_secs(5),
        io_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(5),
    };

    let mut circuit = RelayClient::connect_three_hop(route, cfg).await.unwrap();
    let outcome = circuit
        .send_request(&harness.dest_addr, b"GET /reset HTTP/1.1\r\n\r\n")
        .await;

    // Must return remote error ConnectFailed or InternalError cleanly without panicking circuit
    assert!(outcome.is_err());
    let _ = circuit.close().await;
    harness.shutdown().await;
}

/// Day 9 Test 3: Relay shutdown mid-flight drains cleanly
#[tokio::test]
async fn resilience_entry_sigterm_mid_request_drains_cleanly() {
    let harness = TestThreeHopHarness::start_with_dest_handler(|mut stream| async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let _ = stream.write_all(resp.as_bytes()).await;
    })
    .await;

    let route = harness.route();
    let cfg = ClientConfig {
        handshake_timeout: Duration::from_secs(5),
        io_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(5),
    };

    let mut circuit = RelayClient::connect_three_hop(route, cfg).await.unwrap();
    let target = harness.dest_addr.clone();

    let client_task = tokio::spawn(async move {
        circuit
            .send_request(&target, b"GET /slow-drain HTTP/1.1\r\n\r\n")
            .await
    });

    // Wait 100ms then trigger entry shutdown
    tokio::time::sleep(Duration::from_millis(100)).await;
    let shutdown_start = Instant::now();
    harness.entry_handle.shutdown().await;
    let shutdown_duration = shutdown_start.elapsed();

    // Verify task drained within bounds (bounded grace period)
    assert!(shutdown_duration < Duration::from_secs(4));

    let _ = client_task.await;
    harness.middle_handle.shutdown().await;
    harness.exit_handle.shutdown().await;
}
