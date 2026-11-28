use std::panic::{self, AssertUnwindSafe};
use std::time::{Duration, Instant};

use private_relay_cli::{
    build_http_request_from_url, parse_client_args, parse_http_health_response,
    parse_http_request_path, parse_relay_args, parse_sanitized_http_status, DestServerConfig,
};
use private_relay_crypto::{
    HopHandshakeInitiator, HopHandshakeResponder, LinkInitiator, LinkResponder, StaticKeypair,
};
use private_relay_network::{decode_hex_32, ClientConfigFile, DestinationPolicy, RelayConfig};
use private_relay_protocol::{
    chunk_request, chunk_response, decode_wire_record, encode_wire_record, Cell, CircuitId,
    Command, DecodedRequest, DestroyReason, ExtendDirective, InnerFlags, InnerPayload,
    MessageReassembler, OuterFramePlaintext, RelayHopPlaintext, RequestId, MAX_CELL_BODY_LEN,
    MAX_CELL_BYTES, MAX_CHUNKS_PER_MESSAGE, OUTER_CIPHERTEXT_LEN, OUTER_PLAINTEXT_LEN,
    OUTER_WIRE_FRAME_BYTES,
};

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_usize(&mut self, upper_exclusive: usize) -> usize {
        if upper_exclusive == 0 {
            return 0;
        }
        (self.next_u64() as usize) % upper_exclusive
    }

    fn mutate(&mut self, seeds: &[Vec<u8>], max_len: usize) -> Vec<u8> {
        let mut buf = if !seeds.is_empty() && (self.next_u64() % 10) < 8 {
            seeds[self.next_usize(seeds.len())].clone()
        } else {
            let len = self.next_usize(max_len.min(1024) + 1);
            let mut v = vec![0u8; len];
            for b in &mut v {
                *b = (self.next_u64() & 0xFF) as u8;
            }
            v
        };

        let ops = 1 + self.next_usize(4);
        for _ in 0..ops {
            match self.next_usize(6) {
                0 if !buf.is_empty() => {
                    let idx = self.next_usize(buf.len());
                    buf[idx] ^= 1u8 << (self.next_usize(8));
                }
                1 if !buf.is_empty() => {
                    let idx = self.next_usize(buf.len());
                    buf[idx] = (self.next_u64() & 0xFF) as u8;
                }
                2 if buf.len() < max_len => {
                    let idx = self.next_usize(buf.len() + 1);
                    let byte = (self.next_u64() & 0xFF) as u8;
                    buf.insert(idx, byte);
                }
                3 if !buf.is_empty() => {
                    let idx = self.next_usize(buf.len());
                    buf.remove(idx);
                }
                4 if buf.len() > 2 => {
                    let new_len = 1 + self.next_usize(buf.len());
                    buf.truncate(new_len);
                }
                _ => {
                    let boundary_vals: &[u8] =
                        &[0x00, 0x01, 0x02, 0x06, 0x09, 0x0f, 0x7f, 0x80, 0xff];
                    if !buf.is_empty() {
                        let idx = self.next_usize(buf.len());
                        buf[idx] = boundary_vals[self.next_usize(boundary_vals.len())];
                    }
                }
            }
        }
        buf.truncate(max_len);
        buf
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    let take = bytes.len().min(64);
    let mut s = String::with_capacity(take * 2 + 16);
    for &b in &bytes[..take] {
        s.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > take {
        s.push_str(&format!("...(len={})", bytes.len()));
    }
    s
}

struct CampaignResult {
    name: &'static str,
    executions: u64,
    elapsed: Duration,
    panics: u64,
    invariant_failures: u64,
    first_reproducer: Option<String>,
}

fn run_target<F>(
    name: &'static str,
    seeds: Vec<Vec<u8>>,
    max_len: usize,
    budget_iters: u64,
    seed_base: u64,
    mut func: F,
) -> CampaignResult
where
    F: FnMut(&[u8], &mut SplitMix64) -> Result<(), String>,
{
    let mut rng = SplitMix64(seed_base);
    let started = Instant::now();
    let mut executions = 0u64;
    let mut panics = 0u64;
    let mut invariant_failures = 0u64;
    let mut first_reproducer = None;

    // 1. Seed corpus deterministic pass first.
    for seed in &seeds {
        executions += 1;
        let res = panic::catch_unwind(AssertUnwindSafe(|| func(seed, &mut rng)));
        match res {
            Err(_) => {
                panics += 1;
                if first_reproducer.is_none() {
                    first_reproducer = Some(format!("PANIC on seed hex={}", hex_preview(seed)));
                }
            }
            Ok(Err(msg)) => {
                invariant_failures += 1;
                if first_reproducer.is_none() {
                    first_reproducer = Some(format!(
                        "INVARIANT_ERR({msg}) seed hex={}",
                        hex_preview(seed)
                    ));
                }
            }
            Ok(Ok(())) => {}
        }
    }

    // 2. Mutation campaign.
    for _ in 0..budget_iters {
        let input = rng.mutate(&seeds, max_len);
        executions += 1;
        let res = panic::catch_unwind(AssertUnwindSafe(|| func(&input, &mut rng)));
        match res {
            Err(_) => {
                panics += 1;
                if first_reproducer.is_none() {
                    first_reproducer =
                        Some(format!("PANIC on mutated hex={}", hex_preview(&input)));
                }
            }
            Ok(Err(msg)) => {
                invariant_failures += 1;
                if first_reproducer.is_none() {
                    first_reproducer = Some(format!(
                        "INVARIANT_ERR({msg}) mutated hex={}",
                        hex_preview(&input)
                    ));
                }
            }
            Ok(Ok(())) => {}
        }
    }

    CampaignResult {
        name,
        executions,
        elapsed: started.elapsed(),
        panics,
        invariant_failures,
        first_reproducer,
    }
}

fn main() {
    let iters_per_target: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);

    // Silence default panic hook output cleanly during catch_unwind checks while preserving failure reporting.
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let mut results = Vec::new();

    // Target 1: Protocol cell decoder (+ RelayHopPlaintext + DecodedRequest roundtrip).
    {
        let cid = CircuitId::new(1).unwrap();
        let dir = ExtendDirective {
            next_hop_addr: "middle:9102".into(),
            next_hop_pub: [0x22; 32],
            handshake_msg1: vec![0x33; 80],
        };
        let seeds = vec![
            Cell::new(cid, Command::Create, 0, vec![0xAA; 80])
                .unwrap()
                .encode()
                .unwrap(),
            Cell::new(cid, Command::RelayData, 0, vec![0xBB; MAX_CELL_BODY_LEN])
                .unwrap()
                .encode()
                .unwrap(),
            Cell::destroy(cid, DestroyReason::Normal).encode().unwrap(),
            RelayHopPlaintext::Forward(vec![0x11; 100])
                .encode()
                .unwrap(),
            RelayHopPlaintext::Extend(dir).encode().unwrap(),
            RelayHopPlaintext::Message(vec![0x22; 64]).encode().unwrap(),
            RelayHopPlaintext::Extended(vec![0x33; 80])
                .encode()
                .unwrap(),
            vec![],
            vec![0; 8],
            vec![0xFF; 600],
        ];
        results.push(run_target(
            "target_1_cell_and_hop_decoder",
            seeds,
            1024,
            iters_per_target,
            0x0101_2026_1128,
            |data, _| {
                if let Ok(cell) = Cell::decode(data) {
                    let re = cell
                        .encode()
                        .map_err(|e| format!("Cell::decode accepted un-encodable cell: {e}"))?;
                    if re != data {
                        return Err("Cell::decode->encode mismatch".into());
                    }
                    if cell.command == Command::Destroy && cell.destroy_reason().is_err() {
                        return Err("Destroy cell decoded with invalid reason".into());
                    }
                }
                if let Ok(pt) = RelayHopPlaintext::decode(data) {
                    pt.encode().map_err(|e| {
                        format!("RelayHopPlaintext::decode accepted invalid payload that fails encode: {e}")
                    })?;
                }
                let _ = DecodedRequest::parse(data);
                Ok(())
            },
        ));
    }

    // Target 2: Outer frame & Noise wire record decoder.
    {
        let cid = CircuitId::new(0x8000_0001).unwrap();
        let c = Cell::new(cid, Command::RelayData, 0, vec![0x77; 128]).unwrap();
        let packed = OuterFramePlaintext::pack(&c, &[0x55; MAX_CELL_BYTES]).unwrap();
        let rk = OuterFramePlaintext::pack_rekey_control(1, &[0x44; OUTER_PLAINTEXT_LEN]).unwrap();
        let wire = encode_wire_record(&[0x99u8; OUTER_CIPHERTEXT_LEN]).unwrap();
        let seeds = vec![
            packed.bytes.to_vec(),
            rk.bytes.to_vec(),
            wire.to_vec(),
            vec![0; OUTER_PLAINTEXT_LEN],
            vec![0xFF; OUTER_WIRE_FRAME_BYTES],
        ];
        results.push(run_target(
            "target_2_frame_and_wire_decoder",
            seeds,
            OUTER_WIRE_FRAME_BYTES + 64,
            iters_per_target,
            0x0202_2026_1128,
            |data, _| {
                if let Ok(slice) = decode_wire_record(data) {
                    if slice.len() != OUTER_CIPHERTEXT_LEN {
                        return Err("wire slice len mismatch".into());
                    }
                }
                if let Ok(frame) = OuterFramePlaintext::unpack_link_frame(data) {
                    match frame {
                        private_relay_protocol::LinkFrame::Cell(cell) => {
                            let _ = cell
                                .encode()
                                .map_err(|e| format!("unpacked cell failed re-encode: {e}"))?;
                        }
                        private_relay_protocol::LinkFrame::RekeyControl { epoch } => {
                            if epoch == 0 {
                                return Err("zero rekey epoch accepted".into());
                            }
                        }
                    }
                }
                Ok(())
            },
        ));
    }

    // Target 3: Fragment reassembly & raw/encoded InnerPayload fuzzing.
    {
        let rid = RequestId::new(1).unwrap();
        let req_chunks = chunk_request(rid, "example.com:80", &vec![b'A'; 2048]).unwrap();
        let resp_chunks = chunk_response(rid, &vec![b'B'; 2048]).unwrap();
        let mut seeds: Vec<Vec<u8>> = req_chunks
            .iter()
            .chain(resp_chunks.iter())
            .map(|c| c.encode().unwrap())
            .collect();
        seeds.push(vec![]);
        seeds.push(vec![
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            1,
            InnerFlags::ERROR | InnerFlags::FIRST | InnerFlags::FINAL,
        ]);

        results.push(run_target(
            "target_3_fragment_reassembly",
            seeds,
            600,
            iters_per_target,
            0x0303_2026_1128,
            |data, rng| {
                // 3a: Decoded chunk stream path.
                let mut reasm = MessageReassembler::for_request(rid);
                let _ = InnerPayload::decode(data).and_then(|chunk| reasm.push(chunk));

                // 3b: Multi-chunk sequence mutation including empty fragments with arbitrary flags.
                if data.len() >= 8 {
                    let count = data[0] as u16 % (MAX_CHUNKS_PER_MESSAGE + 4);
                    let rid_val = u32::from_be_bytes([data[1], data[2], data[3], data[4]]).max(1);
                    let r = RequestId::new(rid_val).unwrap();
                    let mut stream_reasm = MessageReassembler::for_response(r);
                    let raw_payload = InnerPayload {
                        request_id: r,
                        chunk_index: u16::from_be_bytes([data[5], data[6]]),
                        chunk_count: count,
                        flags: InnerFlags::from_u8(data[7] & 0x07).unwrap(),
                        fragment: data[8..].to_vec(),
                    };
                    let _ = stream_reasm.push(raw_payload);
                    let _ = rng.next_u64();
                }
                Ok(())
            },
        ));
    }

    // Target 4: HTTP response & CLI/URL request handling.
    {
        let seeds = vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}\n".to_vec(),
            b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/\r\n\r\n".to_vec(),
            b"HTTP/1.0 500 Err\n\nbad".to_vec(),
            b"http://example.com:8080/hello?x=1#frag".to_vec(),
            b"GET /medium HTTP/1.1\r\nHost: dest\r\n\r\n".to_vec(),
            vec![0xFF; 128],
        ];
        results.push(run_target(
            "target_4_http_response_and_url",
            seeds,
            2048,
            iters_per_target,
            0x0404_2026_1128,
            |data, _| {
                if let Some(status) = parse_sanitized_http_status(data) {
                    if status.chars().any(|c| c.is_control()) {
                        return Err("sanitized HTTP status emitted control char".into());
                    }
                }
                let _ = parse_http_health_response(data);
                if let Ok(s) = std::str::from_utf8(data) {
                    let _ = parse_http_request_path(s);
                    let _ = build_http_request_from_url(s);
                }
                Ok(())
            },
        ));
    }

    // Target 5: Config, secret-file hex decoder & SSRF target validator + secret canary non-leak check.
    {
        let canary_secret = "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe";
        let kp = StaticKeypair::generate().unwrap();
        let valid_cfg = RelayConfig::with_generated_keypair(
            "entry-fuzz",
            private_relay_network::RelayRole::Entry,
            "127.0.0.1:9101",
            &kp,
        )
        .to_toml_string()
        .unwrap();
        let secret_toml_broken = format!(
            "id = \"entry\"\nrole = \"entry\"\nlisten_addr = \"127.0.0.1:9101\"\npublic_key_hex = \"{}\"\nprivate_key_hex = \"{}\"\n[broken\n",
            private_relay_network::encode_hex(kp.public()),
            canary_secret
        );
        let seeds = vec![
            valid_cfg.into_bytes(),
            secret_toml_broken.into_bytes(),
            format!("private_key_hex = \"{canary_secret}\nbroken").into_bytes(),
            format!("private_key_hex = \"{canary_secret}\\z\"").into_bytes(),
            format!("private_key_hex = {canary_secret}").into_bytes(),
            format!("[{canary_secret}\nprivate_key_hex = \"{canary_secret}\"").into_bytes(),
            b"listen_addr = \"127.0.0.1:9000\"\nslow_delay_ms = 500\n".to_vec(),
            b"127.0.0.1:8080".to_vec(),
            b"[::1]:80".to_vec(),
        ];
        results.push(run_target(
            "target_5_config_and_secret_parser",
            seeds,
            2048,
            iters_per_target / 2,
            0x0505_2026_1128,
            |data, _| {
                let s = String::from_utf8_lossy(data);
                if let Err(e) = RelayConfig::from_toml_str(&s) {
                    let msg = e.to_string();
                    if msg.contains(canary_secret) {
                        return Err("RelayConfig parse error leaked private_key_hex canary!".into());
                    }
                }
                if let Err(e) = ClientConfigFile::from_toml_str(&s) {
                    let msg = e.to_string();
                    if msg.contains(canary_secret) {
                        return Err("ClientConfigFile parse error leaked canary!".into());
                    }
                }
                let _ = RelayConfig::read_public_key_from_toml_str(&s);
                let _ = DestServerConfig::from_toml_str(&s);
                let _ = decode_hex_32(&s);
                let policy = DestinationPolicy::default();
                if let Ok(ip) = s.trim().parse::<std::net::IpAddr>() {
                    let _ = policy.validate_ip(ip);
                }
                let _ = parse_client_args(&["--url".into(), s.to_string()]);
                let _ = parse_relay_args("relay-entry", &["--listen".into(), s.to_string()]);
                Ok(())
            },
        ));
    }

    // Target 6: Noise_IK & Noise_NK handshake untrusted byte handling.
    {
        let client_kp = StaticKeypair::generate().unwrap();
        let relay_kp = StaticKeypair::generate().unwrap();
        let mut link_init = LinkInitiator::new(&client_kp, *relay_kp.public()).unwrap();
        let ik_msg1 = link_init.write_msg1().unwrap();
        let (ik_msg2, _) = LinkResponder::new(&relay_kp)
            .unwrap()
            .process_msg1_and_finish(&ik_msg1)
            .unwrap();
        let mut hop_init = HopHandshakeInitiator::new(1, *relay_kp.public()).unwrap();
        let nk_msg1 = hop_init.write_msg1().unwrap();
        let (nk_msg2, _) = HopHandshakeResponder::new(1, &relay_kp)
            .unwrap()
            .process_msg1_and_finish(&nk_msg1)
            .unwrap();
        let seeds = vec![ik_msg1, ik_msg2, nk_msg1, nk_msg2, vec![], vec![0u8; 96]];

        results.push(run_target(
            "target_6_noise_handshake_inputs",
            seeds,
            256,
            iters_per_target / 2,
            0x0606_2026_1128,
            |data, _| {
                if let Ok(resp) = LinkResponder::new(&relay_kp) {
                    let _ = resp.process_msg1_and_finish(data);
                }
                if let Ok(init) = LinkInitiator::new(&client_kp, *relay_kp.public()) {
                    let _ = init.finish_with_msg2(data);
                }
                if let Ok(resp) = HopHandshakeResponder::new(1, &relay_kp) {
                    let _ = resp.process_msg1_and_finish(data);
                }
                if let Ok(init) = HopHandshakeInitiator::new(2, *relay_kp.public()) {
                    let _ = init.finish_with_msg2(data);
                }
                Ok(())
            },
        ));
    }

    panic::set_hook(prev_hook);

    let mut total_exec = 0u64;
    let mut total_fail = 0u64;
    for r in &results {
        total_exec += r.executions;
        total_fail += r.panics + r.invariant_failures;
        println!(
            "TARGET={} execs={} elapsed_ms={} panics={} invariant_failures={}",
            r.name,
            r.executions,
            r.elapsed.as_millis(),
            r.panics,
            r.invariant_failures
        );
        if let Some(ref rep) = r.first_reproducer {
            println!("  FIRST_REPRODUCER={rep}");
        }
    }
    println!("TOTAL_EXECS={total_exec} TOTAL_FAILURES={total_fail}");
    if total_fail > 0 {
        std::process::exit(1);
    }
}
