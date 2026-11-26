use std::time::Duration;

use private_relay_crypto::{HopHandshakeInitiator, StaticKeypair};
use private_relay_network::{connect_noise_link, RelayConfig, RelayRole};
use private_relay_protocol::{
    chunk_request, Cell, CircuitId, Command, DestroyReason, ExtendDirective, InnerPayload,
    MessageReassembler, ReassembledMessage, RelayHopPlaintext, RequestErrorCode, RequestId,
};
use private_relay_relay::RelayServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn entry_rejects_early_relay_data_and_message_payload() {
    let entry_kp = StaticKeypair::generate().unwrap();
    let entry_cfg =
        RelayConfig::with_generated_keypair("entry-1", RelayRole::Entry, "127.0.0.1:0", &entry_kp);
    let entry = RelayServer::start(entry_cfg).await.unwrap();

    let client_kp = StaticKeypair::generate().unwrap();
    let (mut reader, mut writer) = connect_noise_link(
        &entry.peer_descriptor().addr,
        &client_kp,
        *entry_kp.public(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    let cid = CircuitId::from_role_bits(1, true).unwrap();
    let mut init1 = HopHandshakeInitiator::new(1, *entry_kp.public()).unwrap();
    let msg1 = init1.write_msg1().unwrap();
    writer
        .send_cell(
            &Cell::new(cid, Command::Create, 0, msg1).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

    let created = reader.recv_cell(Duration::from_secs(2)).await.unwrap();
    assert_eq!(created.command, Command::Created);
    let mut hop1 = init1.finish_with_msg2(&created.body).unwrap();

    // Sending RelayData to Entry before 3-hop construction completes must trigger DESTROY(ProtocolError).
    let sealed_msg = hop1
        .forward
        .seal(
            &RelayHopPlaintext::Message(b"illegal-at-entry".to_vec())
                .encode()
                .unwrap(),
        )
        .unwrap();
    writer
        .send_cell(
            &Cell::new(cid, Command::RelayData, 0, sealed_msg).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

    let resp = reader.recv_cell(Duration::from_secs(2)).await.unwrap();
    assert_eq!(resp.command, Command::Destroy);
    assert_eq!(resp.destroy_reason().unwrap(), DestroyReason::ProtocolError);

    entry.shutdown().await;
}

#[tokio::test]
async fn entry_rejects_unauthorized_middle_peer() {
    let entry_kp = StaticKeypair::generate().unwrap();
    let entry_cfg =
        RelayConfig::with_generated_keypair("entry-1", RelayRole::Entry, "127.0.0.1:0", &entry_kp);
    let entry = RelayServer::start(entry_cfg).await.unwrap();

    let rogue_middle_kp = StaticKeypair::generate().unwrap();
    let client_kp = StaticKeypair::generate().unwrap();
    let (mut reader, mut writer) = connect_noise_link(
        &entry.peer_descriptor().addr,
        &client_kp,
        *entry_kp.public(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    let cid = CircuitId::from_role_bits(1, true).unwrap();
    let mut init1 = HopHandshakeInitiator::new(1, *entry_kp.public()).unwrap();
    writer
        .send_cell(
            &Cell::new(cid, Command::Create, 0, init1.write_msg1().unwrap()).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    let created = reader.recv_cell(Duration::from_secs(2)).await.unwrap();
    let mut hop1 = init1.finish_with_msg2(&created.body).unwrap();

    let mut init2 = HopHandshakeInitiator::new(2, *rogue_middle_kp.public()).unwrap();
    let extend = RelayHopPlaintext::Extend(ExtendDirective {
        next_hop_addr: "127.0.0.1:9999".to_owned(),
        next_hop_pub: *rogue_middle_kp.public(),
        handshake_msg1: init2.write_msg1().unwrap(),
    });
    let sealed_ext = hop1.forward.seal(&extend.encode().unwrap()).unwrap();
    writer
        .send_cell(
            &Cell::new(cid, Command::Extend, 0, sealed_ext).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

    let resp = reader.recv_cell(Duration::from_secs(2)).await.unwrap();
    assert_eq!(resp.command, Command::Destroy);
    assert_eq!(resp.destroy_reason().unwrap(), DestroyReason::PolicyDenied);

    entry.shutdown().await;
}

#[tokio::test]
async fn entry_enforces_max_concurrent_circuits_capacity() {
    let entry_kp = StaticKeypair::generate().unwrap();
    let mut entry_cfg = RelayConfig::with_generated_keypair(
        "entry-cap",
        RelayRole::Entry,
        "127.0.0.1:0",
        &entry_kp,
    );
    entry_cfg.max_concurrent_circuits = 1;
    let entry = RelayServer::start(entry_cfg).await.unwrap();

    let client_kp = StaticKeypair::generate().unwrap();
    let (mut reader, mut writer) = connect_noise_link(
        &entry.peer_descriptor().addr,
        &client_kp,
        *entry_kp.public(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    let cid1 = CircuitId::from_role_bits(1, true).unwrap();
    let mut init1 = HopHandshakeInitiator::new(1, *entry_kp.public()).unwrap();
    writer
        .send_cell(
            &Cell::new(cid1, Command::Create, 0, init1.write_msg1().unwrap()).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(
        reader
            .recv_cell(Duration::from_secs(2))
            .await
            .unwrap()
            .command,
        Command::Created
    );

    let cid2 = CircuitId::from_role_bits(2, true).unwrap();
    let mut init2 = HopHandshakeInitiator::new(1, *entry_kp.public()).unwrap();
    writer
        .send_cell(
            &Cell::new(cid2, Command::Create, 0, init2.write_msg1().unwrap()).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    let rejected = reader.recv_cell(Duration::from_secs(2)).await.unwrap();
    assert_eq!(rejected.command, Command::Destroy);
    assert_eq!(rejected.circuit_id, cid2);
    assert_eq!(
        rejected.destroy_reason().unwrap(),
        DestroyReason::ResourceLimit
    );

    entry.shutdown().await;
}

#[tokio::test]
async fn exit_enforces_ssrf_and_handles_direct_valid_request() {
    let dest_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dest_addr = dest_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = dest_listener.accept().await {
            let mut req = Vec::new();
            let _ = s.read_to_end(&mut req).await;
            let _ = s.write_all(b"pong:").await;
            let _ = s.write_all(&req).await;
            let _ = s.shutdown().await;
        }
    });

    // Exit with `allow_loopback_for_test = false` rejects loopback IP at policy boundary cleanly.
    let exit_kp = StaticKeypair::generate().unwrap();
    let exit_cfg =
        RelayConfig::with_generated_keypair("exit-ssrf", RelayRole::Exit, "127.0.0.1:0", &exit_kp);
    let exit = RelayServer::start(exit_cfg).await.unwrap();

    let caller_kp = StaticKeypair::generate().unwrap();
    let (mut reader, mut writer) = connect_noise_link(
        &exit.peer_descriptor().addr,
        &caller_kp,
        *exit_kp.public(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    let cid = CircuitId::from_role_bits(7, true).unwrap();
    let mut init3 = HopHandshakeInitiator::new(3, *exit_kp.public()).unwrap();
    writer
        .send_cell(
            &Cell::new(cid, Command::Create, 0, init3.write_msg1().unwrap()).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    let created = reader.recv_cell(Duration::from_secs(2)).await.unwrap();
    let mut hop3 = init3.finish_with_msg2(&created.body).unwrap();

    let rid = RequestId::new(1).unwrap();
    let chunks = chunk_request(rid, &dest_addr.to_string(), b"ping").unwrap();
    for ch in chunks {
        let pt = RelayHopPlaintext::Message(ch.encode().unwrap())
            .encode()
            .unwrap();
        let sealed = hop3.forward.seal(&pt).unwrap();
        writer
            .send_cell(
                &Cell::new(cid, Command::RelayData, 0, sealed).unwrap(),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
    }

    let cell = reader.recv_cell(Duration::from_secs(2)).await.unwrap();
    assert_eq!(cell.command, Command::RelayData);
    let inner_pt = hop3.backward.open(&cell.body).unwrap();
    let inner_bytes = match RelayHopPlaintext::decode(&inner_pt).unwrap() {
        RelayHopPlaintext::Message(b) => b,
        other => panic!("unexpected plaintext: {other:?}"),
    };
    let chunk = InnerPayload::decode(&inner_bytes).unwrap();
    let mut reasm = MessageReassembler::for_response(rid);
    let msg = reasm.push(chunk).unwrap().unwrap();
    assert_eq!(
        msg,
        ReassembledMessage::Error(RequestErrorCode::PolicyDenied)
    );

    exit.shutdown().await;
}
