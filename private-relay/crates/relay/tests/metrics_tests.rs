use std::time::Duration;

use private_relay_crypto::StaticKeypair;
use private_relay_network::{RelayConfig, RelayRole};
use private_relay_relay::RelayServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn metrics_endpoint_exposes_prometheus_text_format() {
    let kp = StaticKeypair::generate().unwrap();
    let mut config = RelayConfig::with_generated_keypair(
        "entry-metrics-test",
        RelayRole::Entry,
        "127.0.0.1:0",
        &kp,
    );
    config.allow_loopback_for_test = true;
    config.metrics_addr = Some("127.0.0.1:0".to_string());

    // Bind an ephemeral listener first to find an available port
    let probe_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics_addr = probe_listener.local_addr().unwrap();
    drop(probe_listener);

    config.metrics_addr = Some(metrics_addr.to_string());

    let handle = RelayServer::start(config).await.unwrap();
    handle.metrics().inc_circuits_created();
    handle.metrics().inc_requests();
    handle.metrics().inc_requests_success();
    handle.metrics().inc_ssrf_denied();
    handle.metrics().add_bytes_received(1200);

    // Give metrics listener 50ms to spawn
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut stream = TcpStream::connect(metrics_addr).await.unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    let resp_str = String::from_utf8_lossy(&response);

    assert!(resp_str.contains("HTTP/1.1 200 OK"));
    assert!(resp_str.contains(
        "private_relay_circuits_created_total{role=\"entry\",node=\"entry-metrics-test\"} 1"
    ));
    assert!(resp_str
        .contains("private_relay_active_circuits{role=\"entry\",node=\"entry-metrics-test\"} 1"));
    assert!(resp_str
        .contains("private_relay_requests_total{role=\"entry\",node=\"entry-metrics-test\"} 1"));
    assert!(resp_str.contains(
        "private_relay_requests_success_total{role=\"entry\",node=\"entry-metrics-test\"} 1"
    ));
    assert!(resp_str.contains(
        "private_relay_ssrf_denials_total{role=\"entry\",node=\"entry-metrics-test\"} 1"
    ));
    assert!(resp_str.contains(
        "private_relay_bytes_received_total{role=\"entry\",node=\"entry-metrics-test\"} 1200"
    ));
    assert!(resp_str.contains(
        "private_relay_frames_received_total{role=\"entry\",node=\"entry-metrics-test\"} 1"
    ));

    handle.shutdown().await;
}
