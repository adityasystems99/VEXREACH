use private_relay_crypto::{
    HopHandshakeInitiator, HopHandshakeResponder, LinkInitiator, LinkResponder, StaticKeypair,
};
use private_relay_protocol::{Cell, CircuitId, Command, OUTER_WIRE_FRAME_BYTES};

#[test]
fn fuzz_noise_ik_and_nk_handshake_malformed_inputs_never_panic() {
    let client_kp = StaticKeypair::generate().unwrap();
    let relay_kp = StaticKeypair::generate().unwrap();

    let mut init_ik = LinkInitiator::new(&client_kp, *relay_kp.public()).unwrap();
    let valid_ik_m1 = init_ik.write_msg1().unwrap();
    let (valid_ik_m2, _) = LinkResponder::new(&relay_kp)
        .unwrap()
        .process_msg1_and_finish(&valid_ik_m1)
        .unwrap();

    let mut init_nk = HopHandshakeInitiator::new(1, *relay_kp.public()).unwrap();
    let valid_nk_m1 = init_nk.write_msg1().unwrap();
    let (valid_nk_m2, _) = HopHandshakeResponder::new(1, &relay_kp)
        .unwrap()
        .process_msg1_and_finish(&valid_nk_m1)
        .unwrap();

    for msg in [&valid_ik_m1, &valid_nk_m1] {
        for truncate in 0..msg.len() {
            assert!(LinkResponder::new(&relay_kp)
                .unwrap()
                .process_msg1_and_finish(&msg[..truncate])
                .is_err());
            assert!(HopHandshakeResponder::new(1, &relay_kp)
                .unwrap()
                .process_msg1_and_finish(&msg[..truncate])
                .is_err());
        }
        for byte_idx in 0..msg.len() {
            let mut flipped = msg.clone();
            flipped[byte_idx] ^= 0x80;
            if msg == &valid_ik_m1 {
                assert!(LinkResponder::new(&relay_kp)
                    .unwrap()
                    .process_msg1_and_finish(&flipped)
                    .is_err());
            } else {
                assert!(HopHandshakeResponder::new(1, &relay_kp)
                    .unwrap()
                    .process_msg1_and_finish(&flipped)
                    .is_err());
            }
        }
    }

    for msg2 in [&valid_ik_m2, &valid_nk_m2] {
        for truncate in 0..msg2.len() {
            let init = LinkInitiator::new(&client_kp, *relay_kp.public()).unwrap();
            assert!(init.finish_with_msg2(&msg2[..truncate]).is_err());
            let hinit = HopHandshakeInitiator::new(1, *relay_kp.public()).unwrap();
            assert!(hinit.finish_with_msg2(&msg2[..truncate]).is_err());
        }
        for byte_idx in 0..msg2.len() {
            let mut flipped = msg2.clone();
            flipped[byte_idx] ^= 0x01;
            let init = LinkInitiator::new(&client_kp, *relay_kp.public()).unwrap();
            assert!(init.finish_with_msg2(&flipped).is_err());
            let hinit = HopHandshakeInitiator::new(1, *relay_kp.public()).unwrap();
            assert!(hinit.finish_with_msg2(&flipped).is_err());
        }
    }
}

#[test]
fn invariant_malformed_wire_input_poisons_link_session_permanently() {
    let client_kp = StaticKeypair::generate().unwrap();
    let relay_kp = StaticKeypair::generate().unwrap();
    let mut init = LinkInitiator::new(&client_kp, *relay_kp.public()).unwrap();
    let m1 = init.write_msg1().unwrap();
    let (m2, mut srv) = LinkResponder::new(&relay_kp)
        .unwrap()
        .process_msg1_and_finish(&m1)
        .unwrap();
    let mut cli = init.finish_with_msg2(&m2).unwrap();

    let cell = Cell::new(CircuitId::new(1).unwrap(), Command::Create, 0, vec![7; 16]).unwrap();
    let mut tampered = cli.seal_cell(&cell).unwrap();
    tampered[OUTER_WIRE_FRAME_BYTES - 1] ^= 0x55;

    assert!(srv.open_frame(&tampered).is_err());
    assert!(srv.is_failed());
    // Subsequent valid frame must still be rejected cleanly after state failure.
    let valid2 = cli.seal_cell(&cell).unwrap();
    assert!(srv.open_frame(&valid2).is_err());
    assert!(srv.seal_cell(&cell).is_err());
}
