use std::time::Duration;

use private_relay_crypto::StaticKeypair;
use private_relay_network::{RelayConfig, RelayRole};
use private_relay_relay::RelayServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    String::from_utf8_lossy(&response).into_owned()
}

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
    config.metrics_addr = Some("127.0.0.1:0".to_owned());

    let handle = RelayServer::start(config).await.unwrap();
    let metrics_addr = handle
        .metrics_local_addr()
        .expect("metrics listener must report bound SocketAddr");

    handle.metrics().inc_circuits_created();
    handle.metrics().inc_hop_handshakes();
    handle.metrics().inc_requests();
    handle.metrics().inc_requests_success();
    handle.metrics().inc_ssrf_denied();
    handle.metrics().add_bytes_received(600);
    handle.metrics().add_bytes_sent(600);
    handle
        .metrics()
        .observe_request_duration(Duration::from_millis(18));

    let resp_str = http_get(metrics_addr, "/metrics").await;
    let health_str = http_get(metrics_addr, "/healthz").await;
    let missing_str = http_get(metrics_addr, "/unknown").await;

    assert!(health_str.starts_with("HTTP/1.1 200 OK"));
    assert!(missing_str.starts_with("HTTP/1.1 404 Not Found"));
    assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("private_relay_up{role=\"entry\",node=\"entry-metrics-test\"} 1"));
    assert!(resp_str.contains(
        "private_relay_circuits_created_total{role=\"entry\",node=\"entry-metrics-test\"} 1"
    ));
    assert!(resp_str
        .contains("private_relay_active_circuits{role=\"entry\",node=\"entry-metrics-test\"} 1"));
    assert!(resp_str.contains(
        "private_relay_hop_handshakes_total{role=\"entry\",node=\"entry-metrics-test\"} 1"
    ));
    assert!(resp_str
        .contains("private_relay_requests_total{role=\"entry\",node=\"entry-metrics-test\"} 1"));
    assert!(resp_str.contains(
        "private_relay_requests_success_total{role=\"entry\",node=\"entry-metrics-test\"} 1"
    ));
    assert!(resp_str.contains(
        "private_relay_ssrf_denials_total{role=\"entry\",node=\"entry-metrics-test\"} 1"
    ));
    assert!(resp_str.contains(
        "private_relay_bytes_received_total{role=\"entry\",node=\"entry-metrics-test\"} 600"
    ));
    assert!(resp_str.contains(
        "private_relay_bytes_sent_total{role=\"entry\",node=\"entry-metrics-test\"} 600"
    ));
    assert!(resp_str.contains(
        "private_relay_frames_received_total{role=\"entry\",node=\"entry-metrics-test\"} 1"
    ));
    assert!(resp_str
        .contains("private_relay_frames_sent_total{role=\"entry\",node=\"entry-metrics-test\"} 1"));
    assert!(resp_str.contains(
        "private_relay_request_duration_seconds_bucket{role=\"entry\",node=\"entry-metrics-test\",le=\"0.025\"} 1"
    ));
    assert!(resp_str.contains(
        "private_relay_request_duration_seconds_count{role=\"entry\",node=\"entry-metrics-test\"} 1"
    ));

    handle.shutdown().await;
}
