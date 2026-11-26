use private_relay_protocol::{
    build_hop_aead_aad, chunk_request, chunk_response, decode_wire_record, encode_error_payload,
    encode_wire_record, Cell, CircuitId, CircuitState, Command, DecodedRequest, DestroyReason,
    ExtendDirective, HopDirection, InnerFlags, InnerPayload, MessageReassembler,
    OuterFramePlaintext, ProtocolError, ReassembledMessage, RelayHopPlaintext, RequestErrorCode,
    RequestId, RequestState, CELL_HEADER_LEN, HOP_AEAD_AAD_LEN, MAX_CELL_BODY_LEN, MAX_CELL_BYTES,
    MAX_CHUNKS_PER_MESSAGE, MAX_FRAGMENT_LEN, MAX_MESSAGE_BYTES, MAX_TARGET_ADDR_LEN,
    OUTER_CIPHERTEXT_LEN, OUTER_PLAINTEXT_LEN, OUTER_WIRE_FRAME_BYTES, PROTOCOL_VERSION,
};

#[test]
fn t01_t02_t03_valid_cell_encode_decode_and_roundtrips() {
    let cid = CircuitId::from_role_bits(42, true).expect("valid cid");
    assert!(cid.is_initiator_owned());

    let cells = vec![
        Cell::new(cid, Command::Create, 0x00, vec![0xAA; 48]).unwrap(),
        Cell::new(cid, Command::Created, 0x00, vec![0xBB; 48]).unwrap(),
        Cell::new(cid, Command::RelayData, 0x01, vec![0xCC; MAX_CELL_BODY_LEN]).unwrap(),
        Cell::destroy(cid, DestroyReason::Normal),
    ];

    for cell in &cells {
        let encoded = cell.encode().expect("encode cell");
        let decoded = Cell::decode(&encoded).expect("decode cell");
        assert_eq!(&decoded, cell);
    }

    let destroy_cell = Cell::destroy(cid, DestroyReason::CryptoFail);
    assert_eq!(
        destroy_cell.destroy_reason().unwrap(),
        DestroyReason::CryptoFail
    );
}

#[test]
fn t03_relay_hop_plaintext_roundtrips() {
    let dir = ExtendDirective {
        next_hop_addr: "127.0.0.1:9002".to_owned(),
        next_hop_pub: [0x11; 32],
        handshake_msg1: vec![0x22; 48],
    };
    let variants = vec![
        RelayHopPlaintext::Forward(vec![0x33; 100]),
        RelayHopPlaintext::Extend(dir),
        RelayHopPlaintext::Message(vec![0x44; 200]),
        RelayHopPlaintext::Extended(vec![0x55; 48]),
    ];

    for variant in &variants {
        let bytes = variant.encode().expect("encode hop plaintext");
        let decoded = RelayHopPlaintext::decode(&bytes).expect("decode hop plaintext");
        assert_eq!(&decoded, variant);
    }
}

#[test]
fn t04_t05_fixed_size_frame_and_padding_invariance() {
    let cid = CircuitId::new(1).unwrap();
    let small_cell = Cell::new(cid, Command::Create, 0, vec![0x42; 16]).unwrap();
    let max_cell = Cell::new(cid, Command::RelayData, 0, vec![0x77; MAX_CELL_BODY_LEN]).unwrap();

    // Test distinct padding bytes are tolerated on unpack without altering inner cell.
    let small_len = small_cell.encode().unwrap().len();
    let pad_needed = MAX_CELL_BYTES - small_len;
    let pad: Vec<u8> = (0..pad_needed).map(|i| (i % 251) as u8).collect();

    let packed_small = OuterFramePlaintext::pack(&small_cell, &pad).unwrap();
    let packed_max = OuterFramePlaintext::pack(&max_cell, &[]).unwrap();

    assert_eq!(packed_small.bytes.len(), OUTER_PLAINTEXT_LEN);
    assert_eq!(packed_max.bytes.len(), OUTER_PLAINTEXT_LEN);
    assert_eq!(packed_small.bytes.len(), 582);

    assert_eq!(
        OuterFramePlaintext::unpack(&packed_small.bytes).unwrap(),
        small_cell
    );
    assert_eq!(
        OuterFramePlaintext::unpack(&packed_max.bytes).unwrap(),
        max_cell
    );

    // Wire record wraps 598-byte Noise ciphertext into exact 600-byte TCP record.
    let fake_ct = [0x99u8; OUTER_CIPHERTEXT_LEN];
    let wire = encode_wire_record(&fake_ct).unwrap();
    assert_eq!(wire.len(), OUTER_WIRE_FRAME_BYTES);
    assert_eq!(wire.len(), 600);
    assert_eq!(decode_wire_record(&wire).unwrap(), &fake_ct[..]);

    // Reject insufficient caller padding instead of silent zero-padding.
    let err = OuterFramePlaintext::pack(&small_cell, &[0u8; 4]).unwrap_err();
    assert!(matches!(err, ProtocolError::InsufficientPadding { .. }));
}

#[test]
fn t06_invalid_frame_lengths_rejected() {
    let err = OuterFramePlaintext::unpack(&[0u8; 584]).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::InvalidOuterPlaintextLength {
            expected: 582,
            actual: 584
        }
    );

    // real_len = 0, real_len < 9, and real_len > 580 rejected.
    let mut bad_buf = [0u8; OUTER_PLAINTEXT_LEN];
    assert!(matches!(
        OuterFramePlaintext::unpack(&bad_buf),
        Err(ProtocolError::InvalidRealCellLength { .. })
    ));

    bad_buf[0..2].copy_from_slice(&8u16.to_be_bytes());
    assert!(matches!(
        OuterFramePlaintext::unpack(&bad_buf),
        Err(ProtocolError::InvalidRealCellLength { .. })
    ));

    bad_buf[0..2].copy_from_slice(&581u16.to_be_bytes());
    assert!(matches!(
        OuterFramePlaintext::unpack(&bad_buf),
        Err(ProtocolError::InvalidRealCellLength { .. })
    ));

    // Wire record length != 600 and declared outer_len != 598 rejected.
    assert!(matches!(
        decode_wire_record(&[0u8; 602]),
        Err(ProtocolError::InvalidWireFrameLength { .. })
    ));
    let mut bad_prefix_wire = [0u8; 600];
    bad_prefix_wire[0..2].copy_from_slice(&600u16.to_be_bytes());
    assert_eq!(
        decode_wire_record(&bad_prefix_wire),
        Err(ProtocolError::InvalidOuterLengthPrefix {
            expected: 598,
            actual: 600
        })
    );
}

#[test]
fn t07_truncated_messages_rejected() {
    assert_eq!(
        Cell::decode(&[0u8; CELL_HEADER_LEN - 1]),
        Err(ProtocolError::TruncatedHeader {
            expected: 9,
            actual: 8
        })
    );

    let cid = CircuitId::new(9).unwrap();
    let mut bytes = Cell::new(cid, Command::Create, 0, vec![1, 2, 3, 4])
        .unwrap()
        .encode()
        .unwrap();
    bytes.pop();
    assert_eq!(
        Cell::decode(&bytes),
        Err(ProtocolError::LengthMismatch {
            declared: 4,
            actual: 3
        })
    );

    assert!(matches!(
        InnerPayload::decode(&[0u8; 5]),
        Err(ProtocolError::TruncatedHeader { .. })
    ));

    assert!(matches!(
        DecodedRequest::parse(&[0, 10, b'a', b'b']),
        Err(ProtocolError::MalformedPayload(_))
    ));
}

#[test]
fn t08_oversized_messages_rejected() {
    let cid = CircuitId::new(1).unwrap();
    assert_eq!(
        Cell::new(cid, Command::RelayData, 0, vec![0u8; MAX_CELL_BODY_LEN + 1]),
        Err(ProtocolError::BodyTooLarge {
            declared: 572,
            max: 571
        })
    );

    let rid = RequestId::new(1).unwrap();
    let too_big = vec![0x55u8; MAX_MESSAGE_BYTES + 1];
    assert_eq!(
        chunk_request(rid, "example.com:80", &too_big),
        Err(ProtocolError::PayloadTooLarge {
            size: 65_537,
            max: 65_536
        })
    );
    assert_eq!(
        chunk_response(rid, &too_big),
        Err(ProtocolError::PayloadTooLarge {
            size: 65_537,
            max: 65_536
        })
    );

    // Fragment > 487 bytes rejected.
    let err = InnerPayload::new(
        rid,
        0,
        1,
        InnerFlags::from_u8(InnerFlags::FIRST | InnerFlags::FINAL).unwrap(),
        vec![0u8; MAX_FRAGMENT_LEN + 1],
    )
    .unwrap_err();
    assert_eq!(
        err,
        ProtocolError::PayloadTooLarge {
            size: 488,
            max: 487
        }
    );

    // Reassembler enforces strict byte ceiling.
    let mut small_reasm = MessageReassembler::with_limit(rid, 10);
    let chunk = InnerPayload::new(
        rid,
        0,
        1,
        InnerFlags::from_u8(InnerFlags::FIRST | InnerFlags::FINAL).unwrap(),
        vec![1u8; 11],
    )
    .unwrap();
    assert_eq!(
        small_reasm.push(chunk),
        Err(ProtocolError::PayloadTooLarge { size: 11, max: 10 })
    );
}

#[test]
fn t09_maximum_permitted_logical_request_and_response_roundtrip() {
    let rid = RequestId::new(77).unwrap();
    let max_target = "a".repeat(MAX_TARGET_ADDR_LEN - 4) + ":443";
    assert_eq!(max_target.len(), MAX_TARGET_ADDR_LEN);
    let max_body: Vec<u8> = (0..MAX_MESSAGE_BYTES).map(|i| (i % 251) as u8).collect();

    let req_chunks = chunk_request(rid, &max_target, &max_body).expect("max 64KiB + 255B target");
    assert!(req_chunks.len() <= MAX_CHUNKS_PER_MESSAGE as usize);
    assert_eq!(req_chunks.len(), 136);

    let mut req_reasm = MessageReassembler::for_request(rid);
    let mut req_out = None;
    for c in req_chunks {
        let encoded = c.encode().unwrap();
        let decoded = InnerPayload::decode(&encoded).unwrap();
        req_out = req_reasm.push(decoded).unwrap();
    }
    let parsed = match req_out.expect("completed request") {
        ReassembledMessage::Data(raw) => DecodedRequest::parse(&raw).unwrap(),
        ReassembledMessage::Error(_) => panic!("unexpected error"),
    };
    assert_eq!(parsed.target_host_port, max_target);
    assert_eq!(parsed.body, max_body);

    // Max 64 KiB response round trip.
    let resp_chunks = chunk_response(rid, &max_body).expect("max 64KiB response");
    let mut resp_reasm = MessageReassembler::for_response(rid);
    let mut resp_out = None;
    for c in resp_chunks {
        let encoded = c.encode().unwrap();
        let decoded = InnerPayload::decode(&encoded).unwrap();
        resp_out = resp_reasm.push(decoded).unwrap();
    }
    assert_eq!(resp_out.unwrap(), ReassembledMessage::Data(max_body));
}

#[test]
fn t10_t11_t12_chunk_ordering_missing_duplicate_and_count_validation() {
    let rid = RequestId::new(10).unwrap();
    let first_final = InnerFlags::from_u8(InnerFlags::FIRST).unwrap();
    let only_final = InnerFlags::from_u8(InnerFlags::FINAL).unwrap();
    let middle = InnerFlags::from_u8(InnerFlags::NONE).unwrap();

    // Invalid chunk count (0 and 141) and out-of-range chunk_index.
    assert_eq!(
        InnerPayload::new(rid, 0, 0, first_final, vec![]),
        Err(ProtocolError::InvalidChunkCount { count: 0, max: 140 })
    );
    assert_eq!(
        InnerPayload::new(rid, 0, 141, first_final, vec![]),
        Err(ProtocolError::InvalidChunkCount {
            count: 141,
            max: 140
        })
    );
    assert_eq!(
        InnerPayload::new(rid, 2, 2, only_final, vec![]),
        Err(ProtocolError::InvalidChunkIndex { index: 2, count: 2 })
    );

    // Duplicate chunk 0.
    let mut reasm_dup = MessageReassembler::for_response(rid);
    let c0 = InnerPayload::new(rid, 0, 3, first_final, vec![1, 2]).unwrap();
    assert_eq!(reasm_dup.push(c0.clone()).unwrap(), None);
    assert_eq!(
        reasm_dup.push(c0.clone()),
        Err(ProtocolError::DuplicateChunk(0))
    );

    // Missing chunk 1 (receiving 2 after 0).
    let c2 = InnerPayload::new(rid, 2, 3, only_final, vec![5, 6]).unwrap();
    assert_eq!(
        reasm_dup.push(c2),
        Err(ProtocolError::OutOfOrderOrMissingChunk {
            expected: 1,
            actual: 2
        })
    );

    // Mismatched chunk_count mid-message.
    let bad_count = InnerPayload::new(rid, 1, 2, only_final, vec![3]).unwrap();
    assert_eq!(
        reasm_dup.push(bad_count),
        Err(ProtocolError::ChunkCountMismatch {
            expected: 3,
            actual: 2
        })
    );

    // Extra chunk after final chunk.
    let mut reasm_done = MessageReassembler::for_response(rid);
    let one = InnerPayload::new(
        rid,
        0,
        1,
        InnerFlags::from_u8(InnerFlags::FIRST | InnerFlags::FINAL).unwrap(),
        vec![9],
    )
    .unwrap();
    assert!(reasm_done.push(one.clone()).unwrap().is_some());
    assert_eq!(reasm_done.push(one), Err(ProtocolError::PayloadAfterFinal));

    // Valid middle chunk creation + illegal FIRST flag on middle chunk.
    let valid_middle = InnerPayload::new(rid, 1, 3, middle, vec![3, 4]).unwrap();
    assert_eq!(valid_middle.chunk_index, 1);
    assert!(matches!(
        InnerPayload::new(rid, 1, 3, first_final, vec![1]),
        Err(ProtocolError::InvalidFlags(_))
    ));

    // Sanitized Exit error payload round trip.
    let err_chunk = encode_error_payload(rid, RequestErrorCode::PolicyDenied);
    let mut reasm_err = MessageReassembler::for_response(rid);
    let decoded_err = InnerPayload::decode(&err_chunk.encode().unwrap()).unwrap();
    assert_eq!(
        reasm_err.push(decoded_err).unwrap(),
        Some(ReassembledMessage::Error(RequestErrorCode::PolicyDenied))
    );
}

#[test]
fn t13_t14_invalid_request_circuit_ids_and_protocol_versions() {
    assert_eq!(RequestId::new(0), Err(ProtocolError::ZeroRequestId));
    assert_eq!(CircuitId::new(0), Err(ProtocolError::ZeroCircuitId));

    // Zero request_id rejected on wire decode.
    let mut raw_inner = vec![
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        InnerFlags::FIRST | InnerFlags::FINAL,
        0xAB,
    ];
    assert_eq!(
        InnerPayload::decode(&raw_inner),
        Err(ProtocolError::ZeroRequestId)
    );
    raw_inner[3] = 1;
    assert!(InnerPayload::decode(&raw_inner).is_ok());

    // Mismatched request_id rejected by reassembler.
    let mut reasm = MessageReassembler::for_response(RequestId::new(1).unwrap());
    let wrong_chunk = InnerPayload::new(
        RequestId::new(2).unwrap(),
        0,
        1,
        InnerFlags::from_u8(InnerFlags::FIRST | InnerFlags::FINAL).unwrap(),
        vec![1],
    )
    .unwrap();
    assert_eq!(
        reasm.push(wrong_chunk),
        Err(ProtocolError::RequestIdMismatch {
            expected: 1,
            actual: 2
        })
    );

    // Unsupported versions rejected cleanly.
    let cid = CircuitId::new(5).unwrap();
    let mut valid_cell = Cell::new(cid, Command::Create, 0, vec![1, 2])
        .unwrap()
        .encode()
        .unwrap();
    valid_cell[4] = 0x02;
    assert_eq!(
        Cell::decode(&valid_cell),
        Err(ProtocolError::UnsupportedVersion(0x02))
    );

    let bad_cell = Cell {
        circuit_id: cid,
        version: 0x00,
        command: Command::Create,
        flags: 0,
        body: vec![],
    };
    assert_eq!(
        bad_cell.encode(),
        Err(ProtocolError::UnsupportedVersion(0x00))
    );
}

#[test]
fn t15_circuit_and_request_state_transitions_and_aad_invariance() {
    let mut circuit = CircuitState::Building;
    assert!(!circuit.can_forward_data());
    assert!(circuit.mark_open().is_ok());
    assert!(circuit.can_forward_data());

    // Double open rejected.
    assert!(matches!(
        circuit.mark_open(),
        Err(ProtocolError::InvalidCircuitTransition { .. })
    ));

    assert!(circuit.destroy(DestroyReason::Normal).is_ok());
    assert!(circuit.is_closed());
    assert!(!circuit.can_forward_data());
    assert!(matches!(
        circuit.destroy(DestroyReason::ProtocolError),
        Err(ProtocolError::InvalidCircuitTransition { .. })
    ));

    // Request lifecycle transitions.
    let mut req = RequestState::Idle;
    assert!(req.finish_request().is_err());
    req.begin_request().unwrap();
    req.finish_request().unwrap();
    req.begin_response().unwrap();
    req.complete().unwrap();
    assert!(req.is_terminal());
    assert!(req.fail(RequestErrorCode::Timeout).is_err());

    // AEAD AAD omits link-local circuit_id and binds version, direction, hop_index, seq cleanly.
    let aad_fwd = build_hop_aead_aad(HopDirection::Forward, 2, 42).unwrap();
    let aad_bwd = build_hop_aead_aad(HopDirection::Backward, 2, 42).unwrap();
    assert_eq!(aad_fwd.len(), HOP_AEAD_AAD_LEN);
    assert_eq!(&aad_fwd[0..4], b"PRv1");
    assert_eq!(aad_fwd[4], PROTOCOL_VERSION);
    assert_ne!(aad_fwd, aad_bwd);
    assert_eq!(
        build_hop_aead_aad(HopDirection::Forward, 0, 0),
        Err(ProtocolError::InvalidHopIndex(0))
    );
    assert_eq!(
        build_hop_aead_aad(HopDirection::Forward, 4, 0),
        Err(ProtocolError::InvalidHopIndex(4))
    );
}
