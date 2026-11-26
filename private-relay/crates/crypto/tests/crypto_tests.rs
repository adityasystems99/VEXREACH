use private_relay_crypto::{
    parse_public_key, ClientCircuitCrypto, CryptoError, HopCipherState, HopHandshakeInitiator,
    HopHandshakeResponder, LinkInitiator, LinkResponder, StaticKeypair,
};
use private_relay_protocol::{
    chunk_request, chunk_response, Cell, CircuitId, Command, DestroyReason, ExtendDirective,
    HopDirection, InnerPayload, MessageReassembler, ReassembledMessage, RelayHopPlaintext,
    RequestId, MAX_CIRCUIT_SEQ, OUTER_WIRE_FRAME_BYTES,
};
use zeroize::Zeroizing;

#[test]
fn link_ik_handshake_authentication_and_frame_sealing() {
    let client_ephemeral = StaticKeypair::generate().unwrap();
    let entry_kp = StaticKeypair::generate().unwrap();
    let rogue_kp = StaticKeypair::generate().unwrap();

    // Valid mutually authenticated Noise_IK session.
    let mut init = LinkInitiator::new(&client_ephemeral, *entry_kp.public()).unwrap();
    let msg1 = init.write_msg1().unwrap();
    let resp = LinkResponder::new(&entry_kp).unwrap();
    let (msg2, mut entry_link) = resp.process_msg1_and_finish(&msg1).unwrap();
    let mut client_link = init.finish_with_msg2(&msg2).unwrap();

    assert_eq!(entry_link.remote_static_pub(), client_ephemeral.public());
    assert_eq!(client_link.remote_static_pub(), entry_kp.public());

    let cid = CircuitId::new(10).unwrap();
    let cell = Cell::new(cid, Command::Create, 0, vec![0xAB; 80]).unwrap();
    let wire = client_link.seal_cell(&cell).unwrap();
    assert_eq!(wire.len(), OUTER_WIRE_FRAME_BYTES);
    assert_eq!(entry_link.open_cell(&wire).unwrap(), cell);

    // Tampered ciphertext rejected cleanly.
    let mut tampered = wire;
    tampered[20] ^= 0x01;
    assert_eq!(
        entry_link.open_cell(&tampered),
        Err(CryptoError::AuthenticationFailed)
    );

    // Wrong responder static key rejected at handshake.
    let mut bad_init = LinkInitiator::new(&client_ephemeral, *rogue_kp.public()).unwrap();
    let bad_msg1 = bad_init.write_msg1().unwrap();
    let entry_resp = LinkResponder::new(&entry_kp).unwrap();
    assert_eq!(
        entry_resp.process_msg1_and_finish(&bad_msg1).err().unwrap(),
        CryptoError::HandshakeFailed
    );
}

#[test]
fn hop_nk_handshake_rejects_spoofed_identity_and_bad_messages() {
    let middle_kp = StaticKeypair::generate().unwrap();
    let spoofed_entry_kp = StaticKeypair::generate().unwrap();

    let mut init = HopHandshakeInitiator::new(2, *middle_kp.public()).unwrap();
    let msg1 = init.write_msg1().unwrap();
    assert_eq!(msg1.len(), 80);

    // Entry relay attempts MITM on msg1 using spoofed private key -> fails immediately.
    let rogue_resp = HopHandshakeResponder::new(2, &spoofed_entry_kp).unwrap();
    assert_eq!(
        rogue_resp.process_msg1_and_finish(&msg1).err().unwrap(),
        CryptoError::HandshakeFailed
    );

    // Honest Middle completes handshake -> Client accepts valid msg2.
    let resp = HopHandshakeResponder::new(2, &middle_kp).unwrap();
    let (msg2, _middle_keys) = resp.process_msg1_and_finish(&msg1).unwrap();
    assert_eq!(msg2.len(), 80);

    // Tampered msg2 rejected by Client.
    let mut bad_msg2 = msg2.clone();
    bad_msg2[40] ^= 0xFF;
    let mut init2 = HopHandshakeInitiator::new(2, *middle_kp.public()).unwrap();
    let msg1b = init2.write_msg1().unwrap();
    let (msg2b, _) = HopHandshakeResponder::new(2, &middle_kp)
        .unwrap()
        .process_msg1_and_finish(&msg1b)
        .unwrap();
    let mut bad_msg2b = msg2b;
    bad_msg2b[50] ^= 0x42;
    assert_eq!(
        init2.finish_with_msg2(&bad_msg2b).err().unwrap(),
        CryptoError::HandshakeFailed
    );
}

#[test]
fn aead_tamper_wrong_key_aad_metadata_replay_and_exhaustion() {
    let key_fwd = Zeroizing::new([0x11u8; 32]);
    let key_bwd = Zeroizing::new([0x22u8; 32]);
    let wrong_key = Zeroizing::new([0x99u8; 32]);

    let mut alice_fwd = HopCipherState::new(key_fwd.clone(), HopDirection::Forward, 1).unwrap();
    let mut relay_fwd = HopCipherState::new(key_fwd.clone(), HopDirection::Forward, 1).unwrap();
    let mut wrong_hop = HopCipherState::new(key_fwd, HopDirection::Forward, 2).unwrap();
    let mut wrong_dir = HopCipherState::new(key_bwd, HopDirection::Backward, 1).unwrap();
    let mut bad_key_rx = HopCipherState::new(wrong_key, HopDirection::Forward, 1).unwrap();

    let ct0 = alice_fwd.seal(b"secret payload 0").unwrap();
    let ct1 = alice_fwd.seal(b"secret payload 1").unwrap();

    // Modified ciphertext rejected.
    let mut mod_ct = ct0.clone();
    let last = mod_ct.len() - 1;
    mod_ct[last] ^= 0x01;
    assert_eq!(
        relay_fwd.open(&mod_ct),
        Err(CryptoError::AuthenticationFailed)
    );

    // Wrong key rejected.
    assert_eq!(
        bad_key_rx.open(&ct0),
        Err(CryptoError::AuthenticationFailed)
    );

    // Modified authenticated metadata (hop_index = 2 vs 1, or wrong direction) rejected!
    assert_eq!(wrong_hop.open(&ct0), Err(CryptoError::AuthenticationFailed));
    assert_eq!(wrong_dir.open(&ct0), Err(CryptoError::AuthenticationFailed));

    // Normal sequential decryption succeeds, then replaying ct0 fails strictly.
    assert_eq!(relay_fwd.open(&ct0).unwrap(), b"secret payload 0");
    assert_eq!(
        relay_fwd.open(&ct0),
        Err(CryptoError::SequenceMismatch {
            expected: 1,
            actual: 0
        })
    );

    // Tampered sequence prefix fails cleanly.
    let mut skipped_seq = ct1.clone();
    skipped_seq[7] = 9;
    assert_eq!(
        relay_fwd.open(&skipped_seq),
        Err(CryptoError::SequenceMismatch {
            expected: 1,
            actual: 9
        })
    );
    assert_eq!(relay_fwd.open(&ct1).unwrap(), b"secret payload 1");

    // Sequence exhaustion guard prevents nonce wrap/reuse.
    alice_fwd.set_seq_for_test(MAX_CIRCUIT_SEQ);
    assert_eq!(alice_fwd.seal(b"x"), Err(CryptoError::SequenceExhausted));
}

#[test]
fn three_hop_layered_onion_forward_and_backward_roundtrip() {
    let entry_kp = StaticKeypair::generate().unwrap();
    let middle_kp = StaticKeypair::generate().unwrap();
    let exit_kp = StaticKeypair::generate().unwrap();

    let mut client = ClientCircuitCrypto::new();

    // Build 3 independent hops via Noise_NK.
    let mut h1 = HopHandshakeInitiator::new(1, *entry_kp.public()).unwrap();
    let (m1, mut entry) = HopHandshakeResponder::new(1, &entry_kp)
        .unwrap()
        .process_msg1_and_finish(&h1.write_msg1().unwrap())
        .unwrap();
    client.push_hop(h1.finish_with_msg2(&m1).unwrap()).unwrap();

    let mut h2 = HopHandshakeInitiator::new(2, *middle_kp.public()).unwrap();
    let (m2, mut middle) = HopHandshakeResponder::new(2, &middle_kp)
        .unwrap()
        .process_msg1_and_finish(&h2.write_msg1().unwrap())
        .unwrap();
    client.push_hop(h2.finish_with_msg2(&m2).unwrap()).unwrap();

    let mut h3 = HopHandshakeInitiator::new(3, *exit_kp.public()).unwrap();
    let (m3, mut exit) = HopHandshakeResponder::new(3, &exit_kp)
        .unwrap()
        .process_msg1_and_finish(&h3.write_msg1().unwrap())
        .unwrap();
    client.push_hop(h3.finish_with_msg2(&m3).unwrap()).unwrap();

    // Forward: Client seals a bounded request for Exit across all 3 layers.
    let rid = RequestId::new(101).unwrap();
    let chunks = chunk_request(rid, "dest.local:8080", b"GET /ping HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(chunks.len(), 1);
    let inner_bytes = chunks[0].encode().unwrap();
    let onion_pkt = client
        .seal_forward_to_hop(3, &RelayHopPlaintext::Message(inner_bytes.clone()))
        .unwrap();

    // Entry peels only layer 1 -> sees Forward (blind to destination and plaintext).
    let entry_dec = RelayHopPlaintext::decode(&entry.forward.open(&onion_pkt).unwrap()).unwrap();
    let hop2_pkt = match entry_dec {
        RelayHopPlaintext::Forward(p) => p,
        _ => panic!("entry must only see Forward"),
    };

    // Middle peels only layer 2 -> sees Forward (blind to origin and destination).
    let middle_dec = RelayHopPlaintext::decode(&middle.forward.open(&hop2_pkt).unwrap()).unwrap();
    let hop3_pkt = match middle_dec {
        RelayHopPlaintext::Forward(p) => p,
        _ => panic!("middle must only see Forward"),
    };

    // Exit peels final layer 3 -> receives InnerPayload.
    let exit_dec = RelayHopPlaintext::decode(&exit.forward.open(&hop3_pkt).unwrap()).unwrap();
    let decoded_inner = match exit_dec {
        RelayHopPlaintext::Message(p) => InnerPayload::decode(&p).unwrap(),
        _ => panic!("exit expected Message"),
    };
    assert_eq!(decoded_inner.request_id, rid);

    // Backward: Exit seals response chunk, Middle wraps it, Entry wraps it -> Client peels all 3.
    let resp_chunks = chunk_response(rid, b"HTTP/1.1 200 OK\r\n\r\npong").unwrap();
    let exit_bwd = exit
        .backward
        .seal(
            &RelayHopPlaintext::Message(resp_chunks[0].encode().unwrap())
                .encode()
                .unwrap(),
        )
        .unwrap();
    let middle_bwd = middle.backward.seal(&exit_bwd).unwrap();
    let entry_bwd = entry.backward.seal(&middle_bwd).unwrap();

    let client_plain = client.open_backward_from_hop(3, &entry_bwd).unwrap();
    let mut reasm = MessageReassembler::for_response(rid);
    match client_plain {
        RelayHopPlaintext::Message(raw) => {
            let chunk = InnerPayload::decode(&raw).unwrap();
            assert_eq!(
                reasm.push(chunk).unwrap(),
                Some(ReassembledMessage::Data(
                    b"HTTP/1.1 200 OK\r\n\r\npong".to_vec()
                ))
            );
        }
        _ => panic!("expected response Message"),
    }

    // Confirm ExtendDirective + invalid key checks work.
    assert!(parse_public_key(&[0u8; 31]).is_err());
    let _dir = ExtendDirective {
        next_hop_addr: "127.0.0.1:9002".into(),
        next_hop_pub: *middle_kp.public(),
        handshake_msg1: vec![1; 80],
    };
    let _d = DestroyReason::Normal;
}
