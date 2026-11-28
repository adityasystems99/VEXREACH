use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use private_relay_client::{ClientConfig, ClientError, RelayClient};
use private_relay_crypto::{LinkRekeyPolicy, StaticKeypair};
use private_relay_network::{RelayConfig, RelayRole};
use private_relay_protocol::RequestErrorCode;
use private_relay_relay::RelayServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let duration_secs: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            std::env::var("VEXREACH_SOAK_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(300);

    let workers: usize = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);

    // Aggressive link rekey threshold (64 KiB / 15s) exercises real cryptographic rotation continuously.
    let rekey_bytes = 64 * 1024u64;
    let rekey_interval_secs = 15u64;

    let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest_addr = dest_listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = dest_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(16384);
                let mut tmp = [0u8; 16384];
                loop {
                    match s.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        Err(_) => return,
                    }
                }
                for b in &mut buf {
                    *b ^= 0x5A;
                }
                let _ = s.write_all(&buf).await;
                let _ = s.shutdown().await;
            });
        }
    });

    let xkp = StaticKeypair::generate().unwrap();
    let mut xcfg =
        RelayConfig::with_generated_keypair("soak-exit", RelayRole::Exit, "127.0.0.1:0", &xkp);
    xcfg.allow_loopback_for_test = true;
    xcfg.allowed_targets = vec![dest_addr.clone()];
    xcfg.max_concurrent_connections = 256;
    xcfg.max_concurrent_circuits = 1024;
    xcfg.link_rekey_bytes = rekey_bytes;
    xcfg.link_rekey_interval_secs = rekey_interval_secs;
    let exit_handle = RelayServer::start(xcfg).await.unwrap();

    let mkp = StaticKeypair::generate().unwrap();
    let mut mcfg =
        RelayConfig::with_generated_keypair("soak-middle", RelayRole::Middle, "127.0.0.1:0", &mkp);
    mcfg.allow_loopback_for_test = true;
    mcfg.allowed_next_peers = vec![exit_handle.peer_descriptor().clone()];
    mcfg.max_concurrent_connections = 256;
    mcfg.max_concurrent_circuits = 1024;
    mcfg.link_rekey_bytes = rekey_bytes;
    mcfg.link_rekey_interval_secs = rekey_interval_secs;
    let middle_handle = RelayServer::start(mcfg).await.unwrap();

    let ekp = StaticKeypair::generate().unwrap();
    let mut ecfg =
        RelayConfig::with_generated_keypair("soak-entry", RelayRole::Entry, "127.0.0.1:0", &ekp);
    ecfg.allow_loopback_for_test = true;
    ecfg.allowed_next_peers = vec![middle_handle.peer_descriptor().clone()];
    ecfg.max_concurrent_connections = 256;
    ecfg.max_concurrent_circuits = 1024;
    ecfg.max_circuits_per_peer_ip = 256;
    ecfg.link_rekey_bytes = rekey_bytes;
    ecfg.link_rekey_interval_secs = rekey_interval_secs;
    let entry_handle = RelayServer::start(ecfg).await.unwrap();

    let route = [
        entry_handle.peer_descriptor().clone(),
        middle_handle.peer_descriptor().clone(),
        exit_handle.peer_descriptor().clone(),
    ];

    let req_ok = Arc::new(AtomicU64::new(0));
    let req_unexpected_err = Arc::new(AtomicU64::new(0));
    let expected_ssrf_denied = Arc::new(AtomicU64::new(0));
    let circuits_opened = Arc::new(AtomicU64::new(0));
    let conn_drops = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    let started = Instant::now();
    let total_dur = Duration::from_secs(duration_secs);
    let client_rekey = LinkRekeyPolicy {
        max_bytes: rekey_bytes,
        max_age: Duration::from_secs(rekey_interval_secs),
    };
    let client_cfg = ClientConfig {
        handshake_timeout: Duration::from_secs(5),
        io_timeout: Duration::from_secs(5),
        request_timeout: Duration::from_secs(10),
    };

    println!(
        "SOAK_START pid={} duration_secs={} workers={} rekey_bytes={} rekey_interval_s={}",
        std::process::id(),
        duration_secs,
        workers,
        rekey_bytes,
        rekey_interval_secs
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());

    let mut handles = Vec::with_capacity(workers);
    for w_id in 0..workers {
        let r = route.clone();
        let target = dest_addr.clone();
        let ok = Arc::clone(&req_ok);
        let uerr = Arc::clone(&req_unexpected_err);
        let ssrf = Arc::clone(&expected_ssrf_denied);
        let opened = Arc::clone(&circuits_opened);
        let drops = Arc::clone(&conn_drops);
        let stop_flag = Arc::clone(&stop);
        handles.push(tokio::spawn(async move {
            let sizes = [0usize, 1024, 12_288, 32_768, 65_536];
            let mut iter = 0usize;
            while !stop_flag.load(Ordering::Relaxed) && started.elapsed() < total_dur {
                let mut circ = match RelayClient::connect_three_hop_with_rekey(
                    r.clone(),
                    client_cfg,
                    client_rekey,
                )
                .await
                {
                    Ok(c) => {
                        opened.fetch_add(1, Ordering::Relaxed);
                        c
                    }
                    Err(_) => {
                        drops.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                };

                // Reuse each circuit for 100 varied requests before rotating cleanly, pacing to stay
                // below Windows' 120s TIME_WAIT (~16k ephemeral loopback port) ceiling during sustained soak.
                for step in 0..100usize {
                    if stop_flag.load(Ordering::Relaxed) || started.elapsed() >= total_dur {
                        break;
                    }
                    let sz = sizes[(iter + w_id + step) % sizes.len()];
                    let payload: Vec<u8> = (0..sz).map(|i| ((i + iter) % 251) as u8).collect();
                    match circ.send_request(&target, &payload).await {
                        Ok(resp)
                            if resp.len() == sz
                                && resp
                                    .iter()
                                    .zip(payload.iter())
                                    .all(|(&a, &b)| (a ^ 0x5A) == b) =>
                        {
                            ok.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(_) => {
                            uerr.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        Err(_) => {
                            uerr.fetch_add(1, Ordering::Relaxed);
                            drops.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }

                    // Periodically verify SSRF denial does not corrupt circuit state mid-soak.
                    if (iter + step) % 50 == 0 && w_id == 0 {
                        match circ
                            .send_request("169.254.169.254:80", b"GET / HTTP/1.1\r\n\r\n")
                            .await
                        {
                            Err(ClientError::RemoteError(RequestErrorCode::PolicyDenied)) => {
                                ssrf.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                uerr.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    tokio::time::sleep(Duration::from_millis(36)).await;
                }
                let _ = circ.close().await;
                iter += 1;
            }
        }));
    }

    // Periodic progress & metrics checkpoint every 30s (or sooner for short runs).
    let tick_dur = Duration::from_secs(30).min(total_dur.max(Duration::from_secs(1)));
    while started.elapsed() < total_dur {
        tokio::time::sleep(tick_dur.min(total_dur.saturating_sub(started.elapsed()))).await;
        let e_m = entry_handle.metrics();
        let m_m = middle_handle.metrics();
        let x_m = exit_handle.metrics();
        println!(
            "SOAK_TICK elapsed_s={:.1} ok={} ssrf_blocked={} unexpected_err={} drops={} frames_rx={} frames_tx={} rekeys={} active_circuits=({},{},{})",
            started.elapsed().as_secs_f64(),
            req_ok.load(Ordering::Relaxed),
            expected_ssrf_denied.load(Ordering::Relaxed),
            req_unexpected_err.load(Ordering::Relaxed),
            conn_drops.load(Ordering::Relaxed),
            e_m.frames_received_total.load(Ordering::Relaxed)
                + m_m.frames_received_total.load(Ordering::Relaxed)
                + x_m.frames_received_total.load(Ordering::Relaxed),
            e_m.frames_sent_total.load(Ordering::Relaxed)
                + m_m.frames_sent_total.load(Ordering::Relaxed)
                + x_m.frames_sent_total.load(Ordering::Relaxed),
            e_m.link_rekeys_total.load(Ordering::Relaxed)
                + m_m.link_rekeys_total.load(Ordering::Relaxed)
                + x_m.link_rekeys_total.load(Ordering::Relaxed),
            entry_handle.active_circuit_count(),
            middle_handle.active_circuit_count(),
            exit_handle.active_circuit_count(),
        );
        let _ = std::io::Write::flush(&mut std::io::stdout());
    }

    stop.store(true, Ordering::Release);
    for h in handles {
        let _ = h.await;
    }
    tokio::time::sleep(Duration::from_millis(120)).await;

    let e_m = entry_handle.metrics();
    let m_m = middle_handle.metrics();
    let x_m = exit_handle.metrics();
    let total_frames_rx = e_m.frames_received_total.load(Ordering::Relaxed)
        + m_m.frames_received_total.load(Ordering::Relaxed)
        + x_m.frames_received_total.load(Ordering::Relaxed);
    let total_frames_tx = e_m.frames_sent_total.load(Ordering::Relaxed)
        + m_m.frames_sent_total.load(Ordering::Relaxed)
        + x_m.frames_sent_total.load(Ordering::Relaxed);
    let total_rekeys = e_m.link_rekeys_total.load(Ordering::Relaxed)
        + m_m.link_rekeys_total.load(Ordering::Relaxed)
        + x_m.link_rekeys_total.load(Ordering::Relaxed);
    let total_auth_fail = e_m.hop_handshake_failures_total.load(Ordering::Relaxed)
        + m_m.hop_handshake_failures_total.load(Ordering::Relaxed)
        + x_m.hop_handshake_failures_total.load(Ordering::Relaxed);

    println!(
        "SOAK_SUMMARY elapsed_s={:.2} ok_requests={} ssrf_denied_ok={} unexpected_errors={} circuits_opened={} conn_drops={} relay_frames_rx={} relay_frames_tx={} total_relay_rekeys={} auth_failures={} post_active_circuits=({},{},{})",
        started.elapsed().as_secs_f64(),
        req_ok.load(Ordering::Relaxed),
        expected_ssrf_denied.load(Ordering::Relaxed),
        req_unexpected_err.load(Ordering::Relaxed),
        circuits_opened.load(Ordering::Relaxed),
        conn_drops.load(Ordering::Relaxed),
        total_frames_rx,
        total_frames_tx,
        total_rekeys,
        total_auth_fail,
        entry_handle.active_circuit_count(),
        middle_handle.active_circuit_count(),
        exit_handle.active_circuit_count(),
    );

    let leaked = entry_handle.active_circuit_count()
        + middle_handle.active_circuit_count()
        + exit_handle.active_circuit_count();
    let uerr = req_unexpected_err.load(Ordering::Relaxed);
    entry_handle.shutdown().await;
    middle_handle.shutdown().await;
    exit_handle.shutdown().await;

    assert_eq!(uerr, 0, "unexpected request errors during soak");
    assert_eq!(leaked, 0, "circuits leaked after soak");
}
