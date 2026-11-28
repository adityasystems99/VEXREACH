use std::time::Duration;

use private_relay_crypto::{
    CryptoError, HopCipherState, LinkInitiator, LinkRekeyPolicy, LinkResponder, LinkSession,
    StaticKeypair,
};
use private_relay_protocol::{
    encode_wire_record, Cell, CircuitId, Command, HopDirection, LinkFrame, OuterFramePlaintext,
    MAX_CIRCUIT_SEQ, OUTER_CIPHERTEXT_LEN, OUTER_PLAINTEXT_LEN, OUTER_WIRE_FRAME_BYTES,
};
use zeroize::Zeroizing;

fn establish_pair() -> (LinkSession, LinkSession) {
    let client_kp = StaticKeypair::generate().unwrap();
    let srv_kp = StaticKeypair::generate().unwrap();
    let mut init = LinkInitiator::new(&client_kp, *srv_kp.public()).unwrap();
    let msg1 = init.write_msg1().unwrap();
    let (msg2, srv) = LinkResponder::new(&srv_kp)
        .unwrap()
        .process_msg1_and_finish(&msg1)
        .unwrap();
    let cli = init.finish_with_msg2(&msg2).unwrap();
    (cli, srv)
}

#[test]
fn rekey_stress_all_ten_protocol_and_nonce_scenarios() {
    let cid = CircuitId::new(1).unwrap();
    let cell = Cell::new(cid, Command::RelayData, 0, vec![0x42; 120]).unwrap();

    // Scenario 1 & 2 & 8: Before threshold vs exact threshold & synchronization.
    let (mut cli, mut srv) = establish_pair();
    cli.set_rekey_policy(LinkRekeyPolicy {
        max_bytes: OUTER_WIRE_FRAME_BYTES as u64 * 3,
        max_age: Duration::from_secs(3600),
    });
    assert!(!cli.should_rekey_outgoing());
    for i in 0..2 {
        let f = cli.seal_cell(&cell).unwrap();
        assert_eq!(srv.open_cell(&f).unwrap(), cell);
        assert!(
            !cli.should_rekey_outgoing(),
            "unexpected early rekey at {i}"
        );
    }
    let f3 = cli.seal_cell(&cell).unwrap();
    assert_eq!(srv.open_cell(&f3).unwrap(), cell);
    assert!(
        cli.should_rekey_outgoing(),
        "expected rekey trigger at 3*600B"
    );

    let n_send_before = cli.sending_nonce();
    let rk = cli.seal_rekey_and_rotate().unwrap();
    assert_eq!(cli.sending_nonce(), n_send_before + 1);
    assert_eq!(
        srv.open_frame(&rk).unwrap(),
        LinkFrame::RekeyControl { epoch: 1 }
    );
    assert_eq!(cli.rekey_epochs(), (1, 0));
    assert_eq!(srv.rekey_epochs(), (0, 1));
    assert_eq!(cli.sending_nonce(), srv.receiving_nonce());

    // Scenario 3, 4 & 5: High-traffic simultaneous bidirectional consecutive rekeys (2,000 frames + >300 rotations).
    cli.set_rekey_policy(LinkRekeyPolicy {
        max_bytes: OUTER_WIRE_FRAME_BYTES as u64 * 4,
        max_age: Duration::from_secs(3600),
    });
    srv.set_rekey_policy(LinkRekeyPolicy {
        max_bytes: OUTER_WIRE_FRAME_BYTES as u64 * 5,
        max_age: Duration::from_secs(3600),
    });
    for i in 0..1000u32 {
        let mut payload = vec![(i & 0xFF) as u8; 64];
        let c_fwd = Cell::new(cid, Command::RelayData, 0, payload.clone()).unwrap();
        if cli.should_rekey_outgoing() {
            let rf = cli.seal_rekey_and_rotate().unwrap();
            assert!(matches!(
                srv.open_frame(&rf).unwrap(),
                LinkFrame::RekeyControl { .. }
            ));
        }
        let w_fwd = cli.seal_cell(&c_fwd).unwrap();
        assert_eq!(srv.open_cell(&w_fwd).unwrap(), c_fwd);

        payload[0] ^= 0xFF;
        let c_bwd = Cell::new(cid, Command::RelayData, 0, payload).unwrap();
        if srv.should_rekey_outgoing() {
            let rf_bwd = srv.seal_rekey_and_rotate().unwrap();
            assert!(matches!(
                cli.open_frame(&rf_bwd).unwrap(),
                LinkFrame::RekeyControl { .. }
            ));
        }
        let w_bwd = srv.seal_cell(&c_bwd).unwrap();
        assert_eq!(cli.open_cell(&w_bwd).unwrap(), c_bwd);
    }
    let (cli_out, cli_in) = cli.rekey_epochs();
    let (srv_out, srv_in) = srv.rekey_epochs();
    assert_eq!(cli_out, srv_in);
    assert_eq!(srv_out, cli_in);
    assert_eq!(cli_out, 250);
    assert_eq!(srv_out, 199);
    assert_eq!(cli.sending_nonce(), srv.receiving_nonce());
    assert_eq!(srv.sending_nonce(), cli.receiving_nonce());

    // Consecutive rekeys back-to-back remain synchronized.
    for expected_ep in (cli_out + 1)..=(cli_out + 10) {
        let rf = cli.seal_rekey_and_rotate().unwrap();
        assert_eq!(
            srv.open_frame(&rf).unwrap(),
            LinkFrame::RekeyControl { epoch: expected_ep }
        );
    }

    // Scenario 6 & 10: Invalid rekey control frame (epoch mismatch / version / magic) fails closed permanently.
    let (mut cli_bad, mut srv_bad) = establish_pair();
    let rk_ok = cli_bad.seal_rekey_and_rotate().unwrap();
    let _ = srv_bad.open_frame(&rk_ok).unwrap();
    let mut forged_bad_magic = [0u8; OUTER_PLAINTEXT_LEN];
    forged_bad_magic[0..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    forged_bad_magic[2..10].copy_from_slice(b"BADMAGIC");
    assert!(OuterFramePlaintext::unpack_link_frame(&forged_bad_magic).is_err());

    // Sending tampered rekey frame poisons receiver permanently.
    let mut rk2_tamper = cli_bad.seal_rekey_and_rotate().unwrap();
    rk2_tamper[OUTER_WIRE_FRAME_BYTES - 1] ^= 0x01;
    assert_eq!(
        srv_bad.open_frame(&rk2_tamper),
        Err(CryptoError::AuthenticationFailed)
    );
    assert!(srv_bad.is_failed());
    assert_eq!(
        srv_bad.open_cell(&cli_bad.seal_cell(&cell).unwrap()),
        Err(CryptoError::InvalidState("link session failed closed"))
    );
    assert_eq!(
        srv_bad.seal_rekey_and_rotate(),
        Err(CryptoError::InvalidState("link session failed closed"))
    );

    // Scenario 7: Lost or reordered rekey control frame causes immediate fail-closed desync rejection.
    let (mut cli_drop, mut srv_drop) = establish_pair();
    let _dropped_rk = cli_drop.seal_rekey_and_rotate().unwrap(); // Lost on wire!
    let post_drop_cell = cli_drop.seal_cell(&cell).unwrap();
    // Receiver still holds key_0 while sender moved to key_1 -> must reject rather than accepting/desyncing.
    assert_eq!(
        srv_drop.open_cell(&post_drop_cell),
        Err(CryptoError::AuthenticationFailed)
    );
    assert!(srv_drop.is_failed());

    let (mut cli_reord, mut srv_reord) = establish_pair();
    let c_before_rk = cli_reord.seal_cell(&cell).unwrap();
    let rk_reord = cli_reord.seal_rekey_and_rotate().unwrap();
    // Reorder: deliver rk_reord BEFORE c_before_rk! Both fail AuthenticationFailed at nonce 0!
    assert_eq!(
        srv_reord.open_frame(&rk_reord),
        Err(CryptoError::AuthenticationFailed)
    );
    assert!(srv_reord.is_failed());
    assert!(srv_reord.open_cell(&c_before_rk).is_err());

    // Scenario 9: Nonce exhaustion bounds on BOTH LinkSession (2^48 + tightened cap) and HopCipherState (2^32).
    let (mut cli_ex, mut srv_ex) = establish_pair();
    cli_ex.set_nonce_limit_for_test(2);
    cli_ex.set_rekey_policy(LinkRekeyPolicy {
        max_bytes: OUTER_WIRE_FRAME_BYTES as u64,
        max_age: Duration::from_secs(3600),
    });
    let w0 = cli_ex.seal_cell(&cell).unwrap();
    let w1 = cli_ex.seal_rekey_and_rotate().unwrap();
    // Nonce is now 2 == nonce_limit -> rekey must NOT bypass exhaustion, and both seal_rekey & seal_cell fail closed!
    assert!(!cli_ex.should_rekey_outgoing());
    assert_eq!(
        cli_ex.seal_rekey_and_rotate(),
        Err(CryptoError::SequenceExhausted)
    );
    assert!(cli_ex.is_failed());
    assert!(cli_ex.seal_cell(&cell).is_err());

    // Verify receiver opens up to receiving_nonce < 2^48 and rejects >= 2^48.
    assert_eq!(srv_ex.open_cell(&w0).unwrap(), cell);
    assert_eq!(
        srv_ex.open_frame(&w1).unwrap(),
        LinkFrame::RekeyControl { epoch: 1 }
    );
    srv_ex.set_receiving_nonce_for_test(1u64 << 48);
    let dummy_wire = encode_wire_record(&[0u8; OUTER_CIPHERTEXT_LEN]).unwrap();
    assert_eq!(
        srv_ex.open_frame(&dummy_wire),
        Err(CryptoError::SequenceExhausted)
    );
    assert!(srv_ex.is_failed());

    // Per-hop 2^32 ceiling check.
    let mut hop_tx =
        HopCipherState::new(Zeroizing::new([0x33; 32]), HopDirection::Forward, 1).unwrap();
    hop_tx.set_seq_for_test(MAX_CIRCUIT_SEQ);
    assert_eq!(hop_tx.seal(b"boom"), Err(CryptoError::SequenceExhausted));
}
