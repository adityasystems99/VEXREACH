use std::sync::Arc;

use private_relay_crypto::{
    CryptoError, HopHandshakeInitiator, HopHandshakeResponder, LinkInitiator, LinkResponder,
    ResolverDropStats, StaticKeypair,
};
use private_relay_protocol::{Cell, CircuitId, Command};

#[test]
fn key_lifecycle_noise_ik_handshake_and_session_drop_zeroizes_primitives() {
    let client_kp = StaticKeypair::generate().unwrap();
    let srv_kp = StaticKeypair::generate().unwrap();
    let wrong_kp = StaticKeypair::generate().unwrap();

    // 1. Completed Link_IK handshake + LinkSession Drop scrubs DH, Hash, HandshakeCipher, and TransportCiphers.
    let cli_stats = Arc::new(ResolverDropStats::default());
    let srv_stats = Arc::new(ResolverDropStats::default());
    {
        let mut init = LinkInitiator::new_with_drop_stats(
            &client_kp,
            *srv_kp.public(),
            Arc::clone(&cli_stats),
        )
        .unwrap();
        let m1 = init.write_msg1().unwrap();
        let (m2, srv_sess) = LinkResponder::new_with_drop_stats(&srv_kp, Arc::clone(&srv_stats))
            .unwrap()
            .process_msg1_and_finish(&m1)
            .unwrap();
        let mut cli_sess = init.finish_with_msg2(&m2).unwrap();

        let (dh_z, cy_z, h_r) = cli_stats.snapshot();
        // Handshake dropped s, e, handshake cipher, and hash inside into_transport_mode(); 2 transport ciphers remain alive.
        assert_eq!(dh_z, 2);
        assert_eq!(cy_z, 1);
        assert_eq!(h_r, 1);

        let c = Cell::new(CircuitId::new(1).unwrap(), Command::Create, 0, vec![5; 16]).unwrap();
        let w = cli_sess.seal_cell(&c).unwrap();
        let mut srv_sess = srv_sess;
        assert_eq!(srv_sess.open_cell(&w).unwrap(), c);
        drop(cli_sess);
        drop(srv_sess);
    }

    assert_eq!(cli_stats.snapshot(), (2, 3, 1));
    assert_eq!(srv_stats.snapshot(), (2, 3, 1));

    // 2. UnexpectedPeerIdentity failure must STILL scrub both handshake primitives AND split transport ciphers.
    let mismatch_stats = Arc::new(ResolverDropStats::default());
    let mut init_bad = LinkInitiator::new_with_drop_stats(
        &client_kp,
        *wrong_kp.public(),
        Arc::clone(&mismatch_stats),
    )
    .unwrap();
    let legit_peer = LinkResponder::new(&srv_kp).unwrap();
    // Responder expecting its own static key rejects msg1 sealed for wrong_kp,
    // and init_bad scrubs its DH/Cipher/Hash buffers when dropped on error.
    let m1 = init_bad.write_msg1().unwrap();
    assert_eq!(
        legit_peer.process_msg1_and_finish(&m1).err(),
        Some(CryptoError::HandshakeFailed)
    );
    let _ = init_bad.finish_with_msg2(&[0xAA; 48]);
    assert_eq!(mismatch_stats.snapshot(), (2, 3, 1));

    // Explicit UnexpectedPeerIdentity: responder returns different static key cleanly checked on into_transport_mode.
    // Note: Noise_IK authenticates static key inside msg1/msg2 hash, so corrupted msg1 triggers HandshakeFailed,
    // and early drop of LinkResponder scrubs responder static s_dh even on error or cancellation.
    let abort_stats = Arc::new(ResolverDropStats::default());
    {
        let resp = LinkResponder::new_with_drop_stats(&srv_kp, Arc::clone(&abort_stats)).unwrap();
        let err = resp.process_msg1_and_finish(&[0u8; 10]);
        assert_eq!(err.err(), Some(CryptoError::HandshakeFailed));
    }
    assert_eq!(abort_stats.snapshot(), (2, 3, 1));
}

#[test]
fn key_lifecycle_noise_nk_hop_handshakes_scrub_primitives_on_finish_and_abort() {
    let hop_kp = StaticKeypair::generate().unwrap();

    // 1. Successful Noise_NK hop handshake drops HandshakeState immediately after deriving HopCipherPair.
    let init_stats = Arc::new(ResolverDropStats::default());
    let resp_stats = Arc::new(ResolverDropStats::default());
    let mut init =
        HopHandshakeInitiator::new_with_drop_stats(2, *hop_kp.public(), Arc::clone(&init_stats))
            .unwrap();
    let m1 = init.write_msg1().unwrap();
    let (m2, _resp_ciphers) =
        HopHandshakeResponder::new_with_drop_stats(2, &hop_kp, Arc::clone(&resp_stats))
            .unwrap()
            .process_msg1_and_finish(&m1)
            .unwrap();
    let _cli_ciphers = init.finish_with_msg2(&m2).unwrap();
    assert_eq!(init_stats.snapshot(), (2, 3, 1));
    assert_eq!(resp_stats.snapshot(), (2, 3, 1));

    // 2. Corrupted/cancelled hop handshake before finish must also zero all DH, cipher, and hash buffers.
    let cancel_stats = Arc::new(ResolverDropStats::default());
    {
        let mut h = HopHandshakeInitiator::new_with_drop_stats(
            3,
            *hop_kp.public(),
            Arc::clone(&cancel_stats),
        )
        .unwrap();
        let _ = h.write_msg1().unwrap();
        // Dropped without receiving msg2!
    }
    assert_eq!(cancel_stats.snapshot(), (2, 3, 1));
}

#[test]
fn static_keypair_and_debug_output_never_expose_secret_bytes() {
    let kp = StaticKeypair::generate().unwrap();
    let dbg = format!("{kp:?}");
    let sec_hex = kp
        .secret_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert!(dbg.contains("[REDACTED]"));
    assert!(!dbg.contains(&sec_hex));
}
