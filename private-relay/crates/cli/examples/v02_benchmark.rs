use std::sync::Arc;
use std::time::{Duration, Instant};

use private_relay_client::{ClientConfig, RelayClient};
use private_relay_crypto::{
    HopCipherState, HopHandshakeInitiator, HopHandshakeResponder, LinkInitiator, LinkResponder,
    StaticKeypair,
};
use private_relay_network::{PeerDescriptor, RelayConfig, RelayRole};
use private_relay_protocol::{
    chunk_request, decode_wire_record, encode_wire_record, Cell, CircuitId, Command, HopDirection,
    InnerPayload, MessageReassembler, OuterFramePlaintext, RequestId, MAX_CELL_BYTES,
};
use private_relay_relay::{RelayHandle, RelayServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zeroize::Zeroizing;

fn percentile_us(sorted_us: &[u64], pct: f64) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_us.len() - 1) as f64 * pct).round() as usize;
    sorted_us[idx.min(sorted_us.len() - 1)] as f64
}

fn format_stats(
    label: &str,
    size_bytes: usize,
    samples_us: &mut [u64],
    total_elapsed: Duration,
    ok: usize,
    err: usize,
) {
    samples_us.sort_unstable();
    let p50 = percentile_us(samples_us, 0.50);
    let p95 = percentile_us(samples_us, 0.95);
    let p99 = percentile_us(samples_us, 0.99);
    let secs = total_elapsed.as_secs_f64().max(1e-9);
    let rps = (ok as f64) / secs;
    // Full round-trip payload throughput (request + identical echoed response = 2 * size_bytes).
    let roundtrip_mib = ((ok as f64) * (size_bytes as f64) * 2.0) / (1024.0 * 1024.0);
    let mib_s = roundtrip_mib / secs;
    println!(
        "{label:38} size={size_bytes:6}B ok={ok:4} err={err:2} elapsed_ms={:8.2} rps={rps:8.1} mib_s={mib_s:7.2} p50_us={p50:9.1} p95_us={p95:9.1} p99_us={p99:9.1}",
        total_elapsed.as_secs_f64() * 1000.0
    );
}

fn bench_micro() {
    println!("=== MICROBENCHMARKS (release CPU single-thread hot paths) ===");
    let cid = CircuitId::new(1).unwrap();
    let cell = Cell::new(cid, Command::RelayData, 0, vec![0xAB; 496]).unwrap();
    let pad = [0x55u8; MAX_CELL_BYTES];

    // 1. Cell encode/decode + Frame pack/unpack + Wire wrap/unwrap.
    let iters = 100_000usize;
    let t0 = Instant::now();
    let mut acc = 0usize;
    for _ in 0..iters {
        let packed = OuterFramePlaintext::pack(&cell, &pad).unwrap();
        let wire = encode_wire_record(&[0x33u8; 598]).unwrap();
        let ct = decode_wire_record(&wire).unwrap();
        acc ^= ct[0] as usize;
        let dec = OuterFramePlaintext::unpack(&packed.bytes).unwrap();
        acc ^= dec.body.len();
    }
    let dt = t0.elapsed();
    println!(
        "micro_cell_frame_pack_unpack           iters={iters:6} elapsed_ms={:8.2} ops_s={:10.0} ns_op={:7.1} acc={}",
        dt.as_secs_f64() * 1000.0,
        iters as f64 / dt.as_secs_f64(),
        dt.as_nanos() as f64 / iters as f64,
        acc & 1
    );

    // 2. Fragmentation + reassembly per payload size.
    for size in [0usize, 1024, 12_288, 32_768, 65_536] {
        let payload = vec![0x42u8; size];
        let rid = RequestId::new(9).unwrap();
        let n_runs = if size >= 32_768 { 2_000 } else { 10_000 };
        let t_f = Instant::now();
        let mut total_bytes = 0usize;
        for _ in 0..n_runs {
            let chunks = chunk_request(rid, "dest:9000", &payload).unwrap();
            let mut reasm = MessageReassembler::for_request(rid);
            let mut out = None;
            for c in chunks {
                let b = c.encode().unwrap();
                let d = InnerPayload::decode(&b).unwrap();
                out = reasm.push(d).unwrap();
            }
            if let Some(private_relay_protocol::ReassembledMessage::Data(raw)) = out {
                total_bytes ^= raw.len();
            }
        }
        let d_f = t_f.elapsed();
        println!(
            "micro_frag_reasm_{size:05}B              iters={n_runs:6} elapsed_ms={:8.2} ops_s={:10.0} ns_op={:9.1} acc={}",
            d_f.as_secs_f64() * 1000.0,
            n_runs as f64 / d_f.as_secs_f64(),
            d_f.as_nanos() as f64 / n_runs as f64,
            total_bytes & 1
        );
    }

    // 3. Single-hop ChaCha20-Poly1305 HopCipherState seal+open (496B payload).
    let hop_key = Zeroizing::new([0x11u8; 32]);
    let mut hop_tx = HopCipherState::new(hop_key.clone(), HopDirection::Forward, 1).unwrap();
    let mut hop_rx = HopCipherState::new(hop_key, HopDirection::Forward, 1).unwrap();
    let hop_pt = [0x77u8; 496];
    let n_hop = 50_000usize;
    let t_h = Instant::now();
    let mut sum_h = 0usize;
    for _ in 0..n_hop {
        let ct = hop_tx.seal(&hop_pt).unwrap();
        let pt = hop_rx.open(&ct).unwrap();
        sum_h ^= pt[0] as usize;
    }
    let d_h = t_h.elapsed();
    println!(
        "micro_hop_aead_seal_open_496B          iters={n_hop:6} elapsed_ms={:8.2} ops_s={:10.0} ns_op={:9.1} acc={}",
        d_h.as_secs_f64() * 1000.0,
        n_hop as f64 / d_h.as_secs_f64(),
        d_h.as_nanos() as f64 / n_hop as f64,
        sum_h & 1
    );

    // 4. Full 3-hop Onion seal -> 3x relay peel -> 3x relay wrap -> Client open.
    let kp1 = StaticKeypair::generate().unwrap();
    let kp2 = StaticKeypair::generate().unwrap();
    let kp3 = StaticKeypair::generate().unwrap();
    let mut cli_crypto = private_relay_crypto::ClientCircuitCrypto::new();
    let mut h1 = HopHandshakeInitiator::new(1, *kp1.public()).unwrap();
    let (m1, mut r1) = HopHandshakeResponder::new(1, &kp1)
        .unwrap()
        .process_msg1_and_finish(&h1.write_msg1().unwrap())
        .unwrap();
    cli_crypto
        .push_hop(h1.finish_with_msg2(&m1).unwrap())
        .unwrap();
    let mut h2 = HopHandshakeInitiator::new(2, *kp2.public()).unwrap();
    let (m2, mut r2) = HopHandshakeResponder::new(2, &kp2)
        .unwrap()
        .process_msg1_and_finish(&h2.write_msg1().unwrap())
        .unwrap();
    cli_crypto
        .push_hop(h2.finish_with_msg2(&m2).unwrap())
        .unwrap();
    let mut h3 = HopHandshakeInitiator::new(3, *kp3.public()).unwrap();
    let (m3, mut r3) = HopHandshakeResponder::new(3, &kp3)
        .unwrap()
        .process_msg1_and_finish(&h3.write_msg1().unwrap())
        .unwrap();
    cli_crypto
        .push_hop(h3.finish_with_msg2(&m3).unwrap())
        .unwrap();

    let msg_inner = vec![0x99u8; 487];
    let n_3h = 20_000usize;
    let t_3h = Instant::now();
    let mut sum_3h = 0usize;
    for _ in 0..n_3h {
        let req_pt = private_relay_protocol::RelayHopPlaintext::Message(msg_inner.clone());
        let wire_body = cli_crypto.seal_forward_to_hop(3, &req_pt).unwrap();
        let b2 = match private_relay_protocol::RelayHopPlaintext::decode(
            &r1.forward.open(&wire_body).unwrap(),
        )
        .unwrap()
        {
            private_relay_protocol::RelayHopPlaintext::Forward(b) => b,
            _ => unreachable!(),
        };
        let b3 =
            match private_relay_protocol::RelayHopPlaintext::decode(&r2.forward.open(&b2).unwrap())
                .unwrap()
            {
                private_relay_protocol::RelayHopPlaintext::Forward(b) => b,
                _ => unreachable!(),
            };
        let out_p = r3.forward.open(&b3).unwrap();
        sum_3h ^= out_p.len();
        let bwd3 = r3.backward.seal(&out_p).unwrap();
        let bwd2 = r2.backward.seal(&bwd3).unwrap();
        let bwd1 = r1.backward.seal(&bwd2).unwrap();
        let dec = cli_crypto.open_backward_from_hop(3, &bwd1).unwrap();
        if let private_relay_protocol::RelayHopPlaintext::Message(v) = dec {
            sum_3h ^= v.len();
        }
    }
    let d_3h = t_3h.elapsed();
    println!(
        "micro_3hop_onion_roundtrip_487B        iters={n_3h:6} elapsed_ms={:8.2} ops_s={:10.0} ns_op={:9.1} acc={}",
        d_3h.as_secs_f64() * 1000.0,
        n_3h as f64 / d_3h.as_secs_f64(),
        d_3h.as_nanos() as f64 / n_3h as f64,
        sum_3h & 1
    );

    // 5. Noise_IK LinkSession 600B seal_cell + open_cell.
    let k_a = StaticKeypair::generate().unwrap();
    let k_b = StaticKeypair::generate().unwrap();
    let mut init = LinkInitiator::new(&k_a, *k_b.public()).unwrap();
    let ik1 = init.write_msg1().unwrap();
    let (ik2, mut sess_b) = LinkResponder::new(&k_b)
        .unwrap()
        .process_msg1_and_finish(&ik1)
        .unwrap();
    let mut sess_a = init.finish_with_msg2(&ik2).unwrap();

    let n_lnk = 20_000usize;
    let t_l = Instant::now();
    let mut sum_l = 0usize;
    for _ in 0..n_lnk {
        let w = sess_a.seal_cell(&cell).unwrap();
        let c = sess_b.open_cell(&w).unwrap();
        sum_l ^= c.body.len();
    }
    let d_l = t_l.elapsed();
    println!(
        "micro_noise_ik_link_seal_open_600B     iters={n_lnk:6} elapsed_ms={:8.2} ops_s={:10.0} ns_op={:9.1} acc={}",
        d_l.as_secs_f64() * 1000.0,
        n_lnk as f64 / d_l.as_secs_f64(),
        d_l.as_nanos() as f64 / n_lnk as f64,
        sum_l & 1
    );
}

struct BenchCluster {
    dest_addr: String,
    route: [PeerDescriptor; 3],
    entry: RelayHandle,
    middle: RelayHandle,
    exit: RelayHandle,
}

impl BenchCluster {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
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
                    let _ = s.write_all(&buf).await;
                    let _ = s.shutdown().await;
                });
            }
        });

        let xkp = StaticKeypair::generate().unwrap();
        let mut xcfg =
            RelayConfig::with_generated_keypair("bench-exit", RelayRole::Exit, "127.0.0.1:0", &xkp);
        xcfg.allow_loopback_for_test = true;
        xcfg.max_concurrent_connections = 512;
        xcfg.max_concurrent_circuits = 2048;
        let exit = RelayServer::start(xcfg).await.unwrap();

        let mkp = StaticKeypair::generate().unwrap();
        let mut mcfg = RelayConfig::with_generated_keypair(
            "bench-middle",
            RelayRole::Middle,
            "127.0.0.1:0",
            &mkp,
        );
        mcfg.allow_loopback_for_test = true;
        mcfg.max_concurrent_connections = 512;
        mcfg.max_concurrent_circuits = 2048;
        mcfg.allowed_next_peers = vec![exit.peer_descriptor().clone()];
        let middle = RelayServer::start(mcfg).await.unwrap();

        let ekp = StaticKeypair::generate().unwrap();
        let mut ecfg = RelayConfig::with_generated_keypair(
            "bench-entry",
            RelayRole::Entry,
            "127.0.0.1:0",
            &ekp,
        );
        ecfg.allow_loopback_for_test = true;
        ecfg.max_concurrent_connections = 512;
        ecfg.max_concurrent_circuits = 2048;
        ecfg.max_circuits_per_peer_ip = 512;
        ecfg.allowed_next_peers = vec![middle.peer_descriptor().clone()];
        let entry = RelayServer::start(ecfg).await.unwrap();

        let route = [
            entry.peer_descriptor().clone(),
            middle.peer_descriptor().clone(),
            exit.peer_descriptor().clone(),
        ];

        Self {
            dest_addr,
            route,
            entry,
            middle,
            exit,
        }
    }

    async fn shutdown(self) {
        self.entry.shutdown().await;
        self.middle.shutdown().await;
        self.exit.shutdown().await;
    }
}

async fn direct_tcp_request(addr: &str, payload: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut s = TcpStream::connect(addr).await?;
    let _ = s.set_nodelay(true);
    s.write_all(payload).await?;
    s.shutdown().await?;
    let mut out = Vec::with_capacity(payload.len());
    s.read_to_end(&mut out).await?;
    Ok(out)
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    println!("=== PRIVATE RELAY v0.2 PERFORMANCE BENCHMARK ===");
    println!(
        "threads={} os={} arch={}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    bench_micro();

    let cluster = BenchCluster::start().await;
    let cfg = ClientConfig {
        handshake_timeout: Duration::from_secs(10),
        io_timeout: Duration::from_secs(10),
        request_timeout: Duration::from_secs(30),
    };

    let sizes = [0usize, 1024, 12_288, 32_768, 65_536];

    println!("\n=== MACROBENCHMARK 1: COLD SINGLE REQUEST (CONNECT/HANDSHAKE + PAYLOAD) ===");
    for &sz in &sizes {
        let payload = vec![0x5Au8; sz];
        let mut dir_us = Vec::with_capacity(10);
        let t_dir = Instant::now();
        for _ in 0..10 {
            let s = Instant::now();
            let got = direct_tcp_request(&cluster.dest_addr, &payload)
                .await
                .unwrap();
            assert_eq!(got.len(), sz);
            dir_us.push(s.elapsed().as_micros() as u64);
        }
        format_stats("direct_cold_10x", sz, &mut dir_us, t_dir.elapsed(), 10, 0);

        let mut rel_us = Vec::with_capacity(10);
        let t_rel = Instant::now();
        for _ in 0..10 {
            let s = Instant::now();
            let mut c = RelayClient::connect_three_hop(cluster.route.clone(), cfg)
                .await
                .unwrap();
            let got = c.send_request(&cluster.dest_addr, &payload).await.unwrap();
            assert_eq!(got.len(), sz);
            let _ = c.close().await;
            rel_us.push(s.elapsed().as_micros() as u64);
        }
        format_stats("3hop_cold_10x", sz, &mut rel_us, t_rel.elapsed(), 10, 0);
    }

    println!("\n=== MACROBENCHMARK 2: SEQUENTIAL REUSED CIRCUIT VS DIRECT TCP ===");
    for &sz in &sizes {
        let iters = if sz >= 32_768 { 40usize } else { 100usize };
        let payload = Arc::new(vec![0x5Au8; sz]);

        let mut dir_us = Vec::with_capacity(iters);
        let t_dir = Instant::now();
        for _ in 0..iters {
            let s = Instant::now();
            let got = direct_tcp_request(&cluster.dest_addr, &payload)
                .await
                .unwrap();
            assert_eq!(got.len(), sz);
            dir_us.push(s.elapsed().as_micros() as u64);
        }
        format_stats(
            "direct_sequential",
            sz,
            &mut dir_us,
            t_dir.elapsed(),
            iters,
            0,
        );

        let mut rel_us = Vec::with_capacity(iters);
        let mut circ = RelayClient::connect_three_hop(cluster.route.clone(), cfg)
            .await
            .unwrap();
        let t_rel = Instant::now();
        for _ in 0..iters {
            let s = Instant::now();
            let got = circ
                .send_request(&cluster.dest_addr, &payload)
                .await
                .unwrap();
            assert_eq!(got.len(), sz);
            rel_us.push(s.elapsed().as_micros() as u64);
        }
        format_stats(
            "3hop_seq_reused_circuit",
            sz,
            &mut rel_us,
            t_rel.elapsed(),
            iters,
            0,
        );
        let _ = circ.close().await;
    }

    println!("\n=== MACROBENCHMARK 3: CONCURRENT CLIENTS (C=8 x 15 REQS = 120 PER PAYLOAD) ===");
    for &sz in &[1024usize, 32_768, 65_536] {
        let workers = 8usize;
        let per_worker = if sz == 65_536 { 8usize } else { 15usize };
        let payload = Arc::new(vec![0x3Cu8; sz]);

        // Direct baseline
        let t_dir = Instant::now();
        let mut dir_tasks = Vec::with_capacity(workers);
        for _ in 0..workers {
            let addr = cluster.dest_addr.clone();
            let p = Arc::clone(&payload);
            dir_tasks.push(tokio::spawn(async move {
                let mut lat = Vec::with_capacity(per_worker);
                for _ in 0..per_worker {
                    let s = Instant::now();
                    let g = direct_tcp_request(&addr, &p).await.unwrap();
                    assert_eq!(g.len(), p.len());
                    lat.push(s.elapsed().as_micros() as u64);
                }
                lat
            }));
        }
        let mut dir_all = Vec::with_capacity(workers * per_worker);
        for t in dir_tasks {
            dir_all.extend(t.await.unwrap());
        }
        let ok_d = dir_all.len();
        format_stats(
            "direct_concurrent_8w",
            sz,
            &mut dir_all,
            t_dir.elapsed(),
            ok_d,
            0,
        );

        // 3-Hop Private Relay concurrent circuits (opened concurrently before timed request loop).
        let mut circuits = Vec::with_capacity(workers);
        for _ in 0..workers {
            circuits.push(
                RelayClient::connect_three_hop(cluster.route.clone(), cfg)
                    .await
                    .unwrap(),
            );
        }
        let t_rel = Instant::now();
        let mut rel_tasks = Vec::with_capacity(workers);
        for mut circ in circuits {
            let addr = cluster.dest_addr.clone();
            let p = Arc::clone(&payload);
            rel_tasks.push(tokio::spawn(async move {
                let mut lat = Vec::with_capacity(per_worker);
                let mut errs = 0usize;
                for _ in 0..per_worker {
                    let s = Instant::now();
                    match circ.send_request(&addr, &p).await {
                        Ok(g) if g.len() == p.len() => lat.push(s.elapsed().as_micros() as u64),
                        _ => errs += 1,
                    }
                }
                let _ = circ.close().await;
                (lat, errs)
            }));
        }
        let mut rel_all = Vec::with_capacity(workers * per_worker);
        let mut rel_err = 0usize;
        for t in rel_tasks {
            let (l, e) = t.await.unwrap();
            rel_all.extend(l);
            rel_err += e;
        }
        let ok_r = rel_all.len();
        format_stats(
            "3hop_concurrent_8w",
            sz,
            &mut rel_all,
            t_rel.elapsed(),
            ok_r,
            rel_err,
        );
    }

    println!("\n=== MACROBENCHMARK 4: SUSTAINED TRAFFIC (5s x 4 CONCURRENT CIRCUITS @ 12KiB) ===");
    let sust_payload = Arc::new(vec![0x7Eu8; 12_288]);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut sust_circuits = Vec::with_capacity(4);
    for _ in 0..4 {
        sust_circuits.push(
            RelayClient::connect_three_hop(cluster.route.clone(), cfg)
                .await
                .unwrap(),
        );
    }
    let t_sust = Instant::now();
    let mut sust_tasks = Vec::with_capacity(4);
    for mut circ in sust_circuits {
        let addr = cluster.dest_addr.clone();
        let p = Arc::clone(&sust_payload);
        sust_tasks.push(tokio::spawn(async move {
            let mut lat = Vec::new();
            let mut errs = 0usize;
            while Instant::now() < deadline {
                let s = Instant::now();
                match circ.send_request(&addr, &p).await {
                    Ok(g) if g.len() == p.len() => lat.push(s.elapsed().as_micros() as u64),
                    _ => errs += 1,
                }
            }
            let _ = circ.close().await;
            (lat, errs)
        }));
    }
    let mut sust_all = Vec::new();
    let mut sust_err = 0usize;
    for t in sust_tasks {
        let (l, e) = t.await.unwrap();
        sust_all.extend(l);
        sust_err += e;
    }
    let ok_s = sust_all.len();
    format_stats(
        "3hop_sustained_5s_4w",
        12_288,
        &mut sust_all,
        t_sust.elapsed(),
        ok_s,
        sust_err,
    );

    tokio::time::sleep(Duration::from_millis(80)).await;
    println!(
        "POST_BENCH_ACTIVE_CIRCUITS entry={} middle={} exit={}",
        cluster.entry.active_circuit_count(),
        cluster.middle.active_circuit_count(),
        cluster.exit.active_circuit_count()
    );
    cluster.shutdown().await;
}
