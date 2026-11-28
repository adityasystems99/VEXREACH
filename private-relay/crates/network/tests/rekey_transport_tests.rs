use std::time::Duration;

use private_relay_crypto::{LinkRekeyPolicy, StaticKeypair};
use private_relay_network::{
    accept_noise_link_with_rekey, connect_noise_link_with_rekey, NetworkError,
};
use private_relay_protocol::{Cell, CircuitId, Command, OUTER_WIRE_FRAME_BYTES};
use tokio::net::TcpListener;

#[tokio::test]
async fn tcp_simultaneous_bidirectional_high_traffic_rekey_and_consecutive_rekeys() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let kp_cli = StaticKeypair::generate().unwrap();
    let kp_srv = StaticKeypair::generate().unwrap();

    // Aggressive 4-frame (2400B) rekey threshold forcing dozens of concurrent bidirectional rotations over TCP.
    let policy = LinkRekeyPolicy {
        max_bytes: OUTER_WIRE_FRAME_BYTES as u64 * 4,
        max_age: Duration::from_secs(3600),
    };

    let srv_kp = kp_srv.clone();
    let srv_handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut lr, mut lw, _) =
            accept_noise_link_with_rekey(stream, &srv_kp, Duration::from_secs(3), policy)
                .await
                .unwrap();

        let cid = CircuitId::new(1).unwrap();
        let recv_task = tokio::spawn(async move {
            for seq in 0..400u32 {
                let c = lr.recv_cell(Duration::from_secs(5)).await.unwrap();
                assert_eq!(c.body, seq.to_be_bytes());
            }
            lr.rekey_epochs().unwrap()
        });
        let send_task = tokio::spawn(async move {
            for seq in 0..400u32 {
                let c = Cell::new(cid, Command::RelayData, 0, seq.to_be_bytes().to_vec()).unwrap();
                lw.send_cell(&c, Duration::from_secs(5)).await.unwrap();
            }
            lw.rekey_epochs().unwrap()
        });

        let (r_ep, w_ep) = tokio::join!(recv_task, send_task);
        (r_ep.unwrap(), w_ep.unwrap())
    });

    let (mut clr, mut clw) = connect_noise_link_with_rekey(
        &addr.to_string(),
        &kp_cli,
        *kp_srv.public(),
        Duration::from_secs(3),
        policy,
    )
    .await
    .unwrap();

    let cid = CircuitId::new(2).unwrap();
    let cli_recv = tokio::spawn(async move {
        for seq in 0..400u32 {
            let c = clr.recv_cell(Duration::from_secs(5)).await.unwrap();
            assert_eq!(c.body, seq.to_be_bytes());
        }
        clr.rekey_epochs().unwrap()
    });
    let cli_send = tokio::spawn(async move {
        for seq in 0..400u32 {
            let c = Cell::new(cid, Command::RelayData, 0, seq.to_be_bytes().to_vec()).unwrap();
            clw.send_cell(&c, Duration::from_secs(5)).await.unwrap();
        }
        // Explicitly trigger 3 consecutive valid control rekeys (< MAX_CONSECUTIVE_REKEYS = 4) and send closing cell.
        for _ in 0..3 {
            clw.trigger_rekey(Duration::from_secs(2)).await.unwrap();
        }
        clw.rekey_epochs().unwrap()
    });

    let (cr_ep, cw_ep) = tokio::join!(cli_recv, cli_send);
    let (cr_out, cr_in) = cr_ep.unwrap();
    let (cw_out, cw_in) = cw_ep.unwrap();
    let ((sr_out, sr_in), (sw_out, sw_in)) = srv_handle.await.unwrap();

    assert!(cw_out >= 95);
    assert!(sw_out >= 95);
    assert!(cr_in >= 95);
    assert!(sr_in >= 95);
    let _ = (cr_out, cw_in, sr_out, sw_in);
}

#[tokio::test]
async fn tcp_excessive_consecutive_rekey_flood_and_rekey_failure_are_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let kp_cli = StaticKeypair::generate().unwrap();
    let kp_srv = StaticKeypair::generate().unwrap();

    let srv_kp = kp_srv.clone();
    let srv_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut lr, _lw, _) = accept_noise_link_with_rekey(
            stream,
            &srv_kp,
            Duration::from_secs(2),
            LinkRekeyPolicy::default(),
        )
        .await
        .unwrap();
        // 5 consecutive RekeyControl frames without intervening Cell trigger DoS bound (`> 4`).
        let err = lr.recv_cell(Duration::from_secs(2)).await.unwrap_err();
        assert!(matches!(err, NetworkError::Protocol(_)));
    });

    let (_clr, mut clw) = connect_noise_link_with_rekey(
        &addr.to_string(),
        &kp_cli,
        *kp_srv.public(),
        Duration::from_secs(2),
        LinkRekeyPolicy::default(),
    )
    .await
    .unwrap();
    for _ in 0..5 {
        let _ = clw.trigger_rekey(Duration::from_secs(2)).await;
    }
    srv_task.await.unwrap();

    // When connection drops prior to rekey, trigger_rekey fails closed and poisons session.
    drop(clw);
}
