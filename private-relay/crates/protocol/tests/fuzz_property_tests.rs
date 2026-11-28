use private_relay_protocol::{
    chunk_request, chunk_response, decode_wire_record, encode_error_payload, encode_wire_record,
    Cell, CircuitId, Command, DecodedRequest, DestroyReason, ExtendDirective, InnerFlags,
    InnerPayload, LinkFrame, MessageReassembler, OuterFramePlaintext, ProtocolError,
    ReassembledMessage, RelayHopPlaintext, RequestErrorCode, RequestId, MAX_CELL_BODY_LEN,
    MAX_CELL_BYTES, MAX_CHUNKS_PER_MESSAGE, MAX_FRAGMENT_LEN, MAX_MESSAGE_BYTES,
    MAX_TARGET_ADDR_LEN, OUTER_CIPHERTEXT_LEN, OUTER_PLAINTEXT_LEN, OUTER_WIRE_FRAME_BYTES,
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

    fn next_usize(&mut self, max_excl: usize) -> usize {
        if max_excl == 0 {
            return 0;
        }
        (self.next_u64() as usize) % max_excl
    }

    fn gen_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = vec![0u8; len];
        for b in &mut out {
            *b = (self.next_u64() & 0xFF) as u8;
        }
        out
    }
}

/// Regression reproducer discovered by Target 1 fuzzing:
/// `RelayHopPlaintext::decode` previously accepted `Forward` or `Message` bodies `>= 571` bytes
/// even though `encode()` enforces `< 571`, breaking decode->encode symmetry.
#[test]
fn fuzz_regression_oversized_hop_plaintext_forward_and_message_rejected() {
    let mut oversized_fwd = vec![0x01u8];
    oversized_fwd.extend_from_slice(&vec![0xAB; MAX_CELL_BODY_LEN]);
    assert!(matches!(
        RelayHopPlaintext::decode(&oversized_fwd),
        Err(ProtocolError::PayloadTooLarge { .. })
    ));

    let mut oversized_msg = vec![0x03u8];
    oversized_msg.extend_from_slice(&vec![0xCD; MAX_CELL_BODY_LEN]);
    assert!(matches!(
        RelayHopPlaintext::decode(&oversized_msg),
        Err(ProtocolError::PayloadTooLarge { .. })
    ));
}

/// Regression for Target 3 (`MessageReassembler::push` directly receiving unvalidated struct):
/// Ensures `ERROR` chunks with empty fragment never panic and excessive `chunk_count` is rejected
/// before allocating `vec![false; chunk_count]`.
#[test]
fn fuzz_regression_reassembler_rejects_unvalidated_struct_without_panic_or_alloc() {
    let rid = RequestId::new(1).unwrap();
    let mut r1 = MessageReassembler::for_response(rid);
    let panic_candidate = InnerPayload {
        request_id: rid,
        chunk_index: 0,
        chunk_count: 1,
        flags: InnerFlags::from_u8(InnerFlags::FIRST | InnerFlags::FINAL | InnerFlags::ERROR)
            .unwrap(),
        fragment: Vec::new(),
    };
    assert!(matches!(
        r1.push(panic_candidate),
        Err(ProtocolError::MalformedPayload(_))
    ));

    let mut r2 = MessageReassembler::for_response(rid);
    let alloc_bomb = InnerPayload {
        request_id: rid,
        chunk_index: 0,
        chunk_count: u16::MAX,
        flags: InnerFlags::from_u8(InnerFlags::FIRST).unwrap(),
        fragment: vec![1, 2, 3],
    };
    assert_eq!(
        r2.push(alloc_bomb),
        Err(ProtocolError::InvalidChunkCount {
            count: u16::MAX,
            max: MAX_CHUNKS_PER_MESSAGE,
        })
    );

    // Regression: Cell::encode validates Destroy reason invariant symmetrically with Cell::decode.
    let bad_destroy = Cell {
        circuit_id: CircuitId::new(1).unwrap(),
        version: 1,
        command: Command::Destroy,
        flags: 0,
        body: vec![0x00, 0x01],
    };
    assert!(bad_destroy.encode().is_err());
}

#[test]
fn property_cell_frame_and_wire_roundtrip_and_invalid_len_rejection() {
    let mut rng = SplitMix64(0x000A_11CE_5EED_0001);
    let pad = rng.gen_bytes(OUTER_PLAINTEXT_LEN);

    for _ in 0..500 {
        let cid_raw = ((rng.next_u64() as u32) & 0x7FFF_FFFF).max(1);
        let init = (rng.next_u64() & 1) == 1;
        let cid = CircuitId::from_role_bits(cid_raw, init).unwrap();

        let cmds = [
            Command::Create,
            Command::Created,
            Command::Extend,
            Command::Extended,
            Command::RelayData,
            Command::Destroy,
        ];
        let cmd = cmds[rng.next_usize(cmds.len())];
        let cell = if cmd == Command::Destroy {
            let reasons = [
                DestroyReason::Normal,
                DestroyReason::ProtocolError,
                DestroyReason::CryptoFail,
                DestroyReason::IdleTimeout,
                DestroyReason::PeerDisconnected,
                DestroyReason::ResourceLimit,
                DestroyReason::HandshakeTimeout,
                DestroyReason::PolicyDenied,
            ];
            Cell::destroy(cid, reasons[rng.next_usize(reasons.len())])
        } else {
            let body_len = rng.next_usize(MAX_CELL_BODY_LEN + 1);
            Cell::new(
                cid,
                cmd,
                (rng.next_u64() & 0xFF) as u8,
                rng.gen_bytes(body_len),
            )
            .unwrap()
        };

        let encoded = cell.encode().unwrap();
        let decoded = Cell::decode(&encoded).unwrap();
        assert_eq!(decoded, cell);

        // OuterFramePlaintext invariance across arbitrary padding slices.
        let needed = MAX_CELL_BYTES - encoded.len();
        let max_start = OUTER_PLAINTEXT_LEN - needed;
        let offset = rng.next_usize(max_start + 1);
        let packed = OuterFramePlaintext::pack(&cell, &pad[offset..]).unwrap();
        assert_eq!(packed.bytes.len(), OUTER_PLAINTEXT_LEN);
        assert_eq!(
            OuterFramePlaintext::unpack_link_frame(&packed.bytes).unwrap(),
            LinkFrame::Cell(cell.clone())
        );
        if needed > 0 {
            assert!(matches!(
                OuterFramePlaintext::pack(&cell, &pad[..needed - 1]),
                Err(ProtocolError::InsufficientPadding { .. })
            ));
        }

        // Wire framing record invariance.
        let fake_ct = rng.gen_bytes(OUTER_CIPHERTEXT_LEN);
        let wire = encode_wire_record(&fake_ct).unwrap();
        assert_eq!(wire.len(), OUTER_WIRE_FRAME_BYTES);
        assert_eq!(decode_wire_record(&wire).unwrap(), &fake_ct[..]);

        // ExtendDirective roundtrip within max cell capacity.
        let addr_len = 1 + rng.next_usize(MAX_TARGET_ADDR_LEN);
        let addr: String = std::iter::repeat_n('x', addr_len).collect();
        let msg1_len = 1 + rng.next_usize(256);
        let pt = RelayHopPlaintext::Extend(ExtendDirective {
            next_hop_addr: addr,
            next_hop_pub: rng.gen_bytes(32).try_into().unwrap(),
            handshake_msg1: rng.gen_bytes(msg1_len),
        });
        let pt_enc = pt.encode().unwrap();
        assert_eq!(RelayHopPlaintext::decode(&pt_enc).unwrap(), pt);
    }

    // Invalid wire lengths and bad outer_len values always rejected without panic.
    for len in [0usize, 1, 2, 599, 601, 2048] {
        let buf = rng.gen_bytes(len);
        assert!(decode_wire_record(&buf).is_err());
    }
    let mut bad_prefix = [0u8; OUTER_WIRE_FRAME_BYTES];
    for wrong_prefix in [0u16, 1, 597, 599, u16::MAX] {
        bad_prefix[0..2].copy_from_slice(&wrong_prefix.to_be_bytes());
        assert!(decode_wire_record(&bad_prefix).is_err());
    }
}

#[test]
fn property_chunking_reassembly_bounds_ordering_duplicates_and_request_id_isolation() {
    let mut rng = SplitMix64(0xB0B0_5EED_0002);
    let boundary_sizes = [
        0usize,
        1,
        MAX_FRAGMENT_LEN - 1,
        MAX_FRAGMENT_LEN,
        MAX_FRAGMENT_LEN + 1,
        1024,
        12_288,
        32_768,
        MAX_MESSAGE_BYTES - 1,
        MAX_MESSAGE_BYTES,
    ];

    for (idx, &size) in boundary_sizes.iter().enumerate() {
        let rid = RequestId::new((idx as u32) + 1).unwrap();
        let target = format!("service-{idx}.internal:8080");
        let body = rng.gen_bytes(size);

        let req_chunks = chunk_request(rid, &target, &body).unwrap();
        assert!(req_chunks.len() <= MAX_CHUNKS_PER_MESSAGE as usize);
        let mut req_reasm = MessageReassembler::for_request(rid);
        let mut completed = None;
        for (i, ch) in req_chunks.iter().enumerate() {
            assert_eq!(ch.request_id, rid);
            assert_eq!(ch.chunk_index as usize, i);
            let encoded = ch.encode().unwrap();
            let decoded = InnerPayload::decode(&encoded).unwrap();
            completed = req_reasm.push(decoded).unwrap();
        }
        let parsed = match completed.unwrap() {
            ReassembledMessage::Data(raw) => DecodedRequest::parse(&raw).unwrap(),
            ReassembledMessage::Error(_) => panic!("expected request data"),
        };
        assert_eq!(parsed.target_host_port, target);
        assert_eq!(parsed.body, body);

        // Response chunk roundtrip + post-final immutability.
        let resp_chunks = chunk_response(rid, &body).unwrap();
        let mut resp_reasm = MessageReassembler::for_response(rid);
        let mut out = None;
        for ch in &resp_chunks {
            out = resp_reasm
                .push(InnerPayload::decode(&ch.encode().unwrap()).unwrap())
                .unwrap();
        }
        assert_eq!(out.unwrap(), ReassembledMessage::Data(body));
        assert_eq!(
            resp_reasm.push(resp_chunks[0].clone()),
            Err(ProtocolError::PayloadAfterFinal)
        );
    }

    // Ordering, duplicate chunk, wrong request_id, and missing chunk invariants on multi-chunk body.
    let rid1 = RequestId::new(100).unwrap();
    let rid2 = RequestId::new(101).unwrap();
    let chunks = chunk_response(rid1, &rng.gen_bytes(MAX_FRAGMENT_LEN * 3)).unwrap();
    assert_eq!(chunks.len(), 3);

    // Wrong RequestId rejected immediately.
    let mut r_wrong_id = MessageReassembler::for_response(rid2);
    assert!(matches!(
        r_wrong_id.push(chunks[0].clone()),
        Err(ProtocolError::RequestIdMismatch {
            expected: 101,
            actual: 100
        })
    ));

    // Missing chunk 0 (starting at chunk 1) rejected cleanly.
    let mut r_missing0 = MessageReassembler::for_response(rid1);
    assert_eq!(
        r_missing0.push(chunks[1].clone()),
        Err(ProtocolError::OutOfOrderOrMissingChunk {
            expected: 0,
            actual: 1
        })
    );

    // Duplicate chunk 0 and missing chunk 1 rejected cleanly.
    let mut r_dup = MessageReassembler::for_response(rid1);
    assert_eq!(r_dup.push(chunks[0].clone()).unwrap(), None);
    assert_eq!(
        r_dup.push(chunks[0].clone()),
        Err(ProtocolError::DuplicateChunk(0))
    );
    assert_eq!(
        r_dup.push(chunks[2].clone()),
        Err(ProtocolError::OutOfOrderOrMissingChunk {
            expected: 1,
            actual: 2
        })
    );

    // Oversized message (> 64 KiB) rejected both on chunking and decode.
    assert!(matches!(
        chunk_request(rid1, "a:80", &vec![0u8; MAX_MESSAGE_BYTES + 1]),
        Err(ProtocolError::PayloadTooLarge { .. })
    ));
    assert!(matches!(
        chunk_response(rid1, &vec![0u8; MAX_MESSAGE_BYTES + 1]),
        Err(ProtocolError::PayloadTooLarge { .. })
    ));

    // Error chunk uniqueness and decode invariance.
    for code in [
        RequestErrorCode::PolicyDenied,
        RequestErrorCode::DnsFailed,
        RequestErrorCode::ConnectFailed,
        RequestErrorCode::Timeout,
        RequestErrorCode::PayloadTooLarge,
        RequestErrorCode::ProtocolViolation,
        RequestErrorCode::InternalError,
    ] {
        let err_p = encode_error_payload(rid1, code);
        let mut r_err = MessageReassembler::for_response(rid1);
        assert_eq!(
            r_err
                .push(InnerPayload::decode(&err_p.encode().unwrap()).unwrap())
                .unwrap(),
            Some(ReassembledMessage::Error(code))
        );
    }
}
