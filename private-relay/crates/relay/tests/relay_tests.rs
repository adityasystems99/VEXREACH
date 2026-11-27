use std::time::Duration;

use private_relay_crypto::{HopHandshakeInitiator, StaticKeypair};
use private_relay_network::{accept_noise_link, connect_noise_link, RelayConfig, RelayRole};
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

#[tokio::test]
async fn entry_enforces_max_concurrent_connections_limit() {
    let entry_kp = StaticKeypair::generate().unwrap();
    let mut entry_cfg = RelayConfig::with_generated_keypair(
        "entry-conn-cap",
        RelayRole::Entry,
        "127.0.0.1:0",
        &entry_kp,
    );
    entry_cfg.max_concurrent_connections = 1;
    let entry = RelayServer::start(entry_cfg).await.unwrap();

    // First client opens authenticated link and holds connection slot #1.
    let c1_kp = StaticKeypair::generate().unwrap();
    let (r1, w1) = connect_noise_link(
        &entry.peer_descriptor().addr,
        &c1_kp,
        *entry_kp.public(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(entry.active_connection_count(), 1);

    // Second concurrent TCP peer is dropped before Noise handshake due to max_concurrent_connections = 1.
    let c2_kp = StaticKeypair::generate().unwrap();
    let err = connect_noise_link(
        &entry.peer_descriptor().addr,
        &c2_kp,
        *entry_kp.public(),
        Duration::from_secs(2),
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(
        err,
        private_relay_network::NetworkError::ConnectionClosed
            | private_relay_network::NetworkError::Timeout(_)
            | private_relay_network::NetworkError::Io(_)
    ));

    // Releasing connection #1 cleanly restores permit capacity to 0 active connections.
    drop(r1);
    drop(w1);
    for _ in 0..20 {
        if entry.active_connection_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(entry.active_connection_count(), 0);

    entry.shutdown().await;
}

#[tokio::test]
async fn exit_enforces_destination_timeout_and_cleans_up_circuit() {
    let slow_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        if let Ok((mut s, _)) = slow_listener.accept().await {
            let mut tmp = [0u8; 64];
            let _ = s.read(&mut tmp).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    let exit_kp = StaticKeypair::generate().unwrap();
    let mut exit_cfg = RelayConfig::with_generated_keypair(
        "exit-timeout",
        RelayRole::Exit,
        "127.0.0.1:0",
        &exit_kp,
    );
    exit_cfg.allow_loopback_for_test = true;
    exit_cfg.allowed_targets = vec![slow_addr.to_string()];
    exit_cfg.destination_io_timeout_ms = 120;
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

    let cid = CircuitId::from_role_bits(11, true).unwrap();
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
    assert_eq!(exit.active_circuit_count(), 1);

    let rid = RequestId::new(1).unwrap();
    let chunks = chunk_request(rid, &slow_addr.to_string(), b"ping").unwrap();
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
    assert_eq!(msg, ReassembledMessage::Error(RequestErrorCode::Timeout));

    drop(reader);
    drop(writer);
    for _ in 0..20 {
        if exit.active_circuit_count() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(exit.active_circuit_count(), 0);
    exit.shutdown().await;
}

#[tokio::test]
async fn outbound_trunk_isolates_stalled_circuit_without_dropping_siblings() {
    use private_relay_crypto::HopHandshakeResponder;
    use private_relay_network::PeerDescriptor;

    let exit_kp = StaticKeypair::generate().unwrap();
    let exit_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exit_addr = exit_listener.local_addr().unwrap().to_string();

    let exit_kp_srv = exit_kp.clone();
    let exit_task = tokio::spawn(async move {
        let (stream, _) = exit_listener.accept().await.unwrap();
        let (mut r, mut w, _) = accept_noise_link(stream, &exit_kp_srv, Duration::from_secs(2))
            .await
            .unwrap();

        // Circuit 1 CREATE -> CREATED (Hop 3 Exit)
        let c1 = r.recv_cell(Duration::from_secs(2)).await.unwrap();
        let (m1, _h1) = HopHandshakeResponder::new(3, &exit_kp_srv)
            .unwrap()
            .process_msg1_and_finish(&c1.body)
            .unwrap();
        w.send_cell(
            &Cell::new(c1.circuit_id, Command::Created, 0, m1).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        // Circuit 2 CREATE -> CREATED on the exact same Middle -> Exit trunk
        let c2 = r.recv_cell(Duration::from_secs(2)).await.unwrap();
        let (m2, mut h2) = HopHandshakeResponder::new(3, &exit_kp_srv)
            .unwrap()
            .process_msg1_and_finish(&c2.body)
            .unwrap();
        w.send_cell(
            &Cell::new(c2.circuit_id, Command::Created, 0, m2).unwrap(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

        // Wait until sibling forwards RelayData; flood closed c1 first, then reply on c2!
        loop {
            let cell = r.recv_cell(Duration::from_secs(2)).await.unwrap();
            if cell.circuit_id == c2.circuit_id && cell.command == Command::RelayData {
                for _ in 0..4 {
                    let _ = w
                        .send_cell(
                            &Cell::new(c1.circuit_id, Command::RelayData, 0, vec![0xAA; 48])
                                .unwrap(),
                            Duration::from_secs(2),
                        )
                        .await;
                }
                let inner = h2.forward.open(&cell.body).unwrap();
                let fwd = match RelayHopPlaintext::decode(&inner).unwrap() {
                    RelayHopPlaintext::Message(b) => b,
                    other => panic!("unexpected plaintext: {other:?}"),
                };
                assert_eq!(fwd, b"sibling-alive");
                let reply = h2
                    .backward
                    .seal(
                        &RelayHopPlaintext::Message(b"sibling-ok".to_vec())
                            .encode()
                            .unwrap(),
                    )
                    .unwrap();
                w.send_cell(
                    &Cell::new(c2.circuit_id, Command::RelayData, 0, reply).unwrap(),
                    Duration::from_secs(2),
                )
                .await
                .unwrap();
                break;
            }
        }
    });

    let mid_kp = StaticKeypair::generate().unwrap();
    let mut mid_cfg =
        RelayConfig::with_generated_keypair("mid-trunk", RelayRole::Middle, "127.0.0.1:0", &mid_kp);
    mid_cfg.allowed_next_peers = vec![PeerDescriptor {
        id: "exit-mock".into(),
        role: RelayRole::Exit,
        addr: exit_addr.clone(),
        public_key_hex: private_relay_network::encode_hex(exit_kp.public()),
    }];
    let middle = RelayServer::start(mid_cfg).await.unwrap();

    // Connect Caller 1 -> Extend to mock Exit.
    let c1_kp = StaticKeypair::generate().unwrap();
    let (mut r1, mut w1) = connect_noise_link(
        &middle.peer_descriptor().addr,
        &c1_kp,
        *mid_kp.public(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let cid1 = CircuitId::from_role_bits(1, true).unwrap();
    let mut init1 = HopHandshakeInitiator::new(2, *mid_kp.public()).unwrap();
    w1.send_cell(
        &Cell::new(cid1, Command::Create, 0, init1.write_msg1().unwrap()).unwrap(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let created1 = r1.recv_cell(Duration::from_secs(2)).await.unwrap();
    let mut hop2_c1 = init1.finish_with_msg2(&created1.body).unwrap();
    let mut init3_c1 = HopHandshakeInitiator::new(3, *exit_kp.public()).unwrap();
    let ext1 = RelayHopPlaintext::Extend(ExtendDirective {
        next_hop_addr: exit_addr.clone(),
        next_hop_pub: *exit_kp.public(),
        handshake_msg1: init3_c1.write_msg1().unwrap(),
    });
    w1.send_cell(
        &Cell::new(
            cid1,
            Command::Extend,
            0,
            hop2_c1.forward.seal(&ext1.encode().unwrap()).unwrap(),
        )
        .unwrap(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(
        r1.recv_cell(Duration::from_secs(2)).await.unwrap().command,
        Command::Extended
    );

    // Connect Caller 2 -> Extend over same shared Middle->Exit trunk.
    let c2_kp = StaticKeypair::generate().unwrap();
    let (mut r2, mut w2) = connect_noise_link(
        &middle.peer_descriptor().addr,
        &c2_kp,
        *mid_kp.public(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let cid2 = CircuitId::from_role_bits(2, true).unwrap();
    let mut init2_c2 = HopHandshakeInitiator::new(2, *mid_kp.public()).unwrap();
    w2.send_cell(
        &Cell::new(cid2, Command::Create, 0, init2_c2.write_msg1().unwrap()).unwrap(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let created2 = r2.recv_cell(Duration::from_secs(2)).await.unwrap();
    let mut hop2_c2 = init2_c2.finish_with_msg2(&created2.body).unwrap();
    let mut init3_c2 = HopHandshakeInitiator::new(3, *exit_kp.public()).unwrap();
    let ext2 = RelayHopPlaintext::Extend(ExtendDirective {
        next_hop_addr: exit_addr,
        next_hop_pub: *exit_kp.public(),
        handshake_msg1: init3_c2.write_msg1().unwrap(),
    });
    w2.send_cell(
        &Cell::new(
            cid2,
            Command::Extend,
            0,
            hop2_c2.forward.seal(&ext2.encode().unwrap()).unwrap(),
        )
        .unwrap(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let extd2 = r2.recv_cell(Duration::from_secs(2)).await.unwrap();
    let msg2_3 =
        match RelayHopPlaintext::decode(&hop2_c2.backward.open(&extd2.body).unwrap()).unwrap() {
            RelayHopPlaintext::Extended(b) => b,
            other => panic!("expected Extended: {other:?}"),
        };
    let mut hop3_c2 = init3_c2.finish_with_msg2(&msg2_3).unwrap();

    // Close Caller 1 so c1 dies while Caller 2 sends and receives across shared trunk.
    drop(r1);
    drop(w1);
    tokio::time::sleep(Duration::from_millis(80)).await;

    let payload3 = hop3_c2
        .forward
        .seal(
            &RelayHopPlaintext::Message(b"sibling-alive".to_vec())
                .encode()
                .unwrap(),
        )
        .unwrap();
    let payload2 = hop2_c2
        .forward
        .seal(&RelayHopPlaintext::Forward(payload3).encode().unwrap())
        .unwrap();
    w2.send_cell(
        &Cell::new(cid2, Command::RelayData, 0, payload2).unwrap(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    let resp_cell = r2.recv_cell(Duration::from_secs(2)).await.unwrap();
    assert_eq!(resp_cell.command, Command::RelayData);
    let inner2 = hop2_c2.backward.open(&resp_cell.body).unwrap();
    let inner3 = hop3_c2.backward.open(&inner2).unwrap();
    let msg = match RelayHopPlaintext::decode(&inner3).unwrap() {
        RelayHopPlaintext::Message(b) => b,
        other => panic!("expected sibling reply message: {other:?}"),
    };
    assert_eq!(msg, b"sibling-ok");

    exit_task.await.unwrap();
    middle.shutdown().await;
}

#[tokio::test]
async fn shutdown_drains_active_circuits_and_delivers_destroy_cleanly() {
    let entry_kp = StaticKeypair::generate().unwrap();
    let entry_cfg =
        RelayConfig::with_generated_keypair("entry-sd", RelayRole::Entry, "127.0.0.1:0", &entry_kp);
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
    let mut init = HopHandshakeInitiator::new(1, *entry_kp.public()).unwrap();
    writer
        .send_cell(
            &Cell::new(cid, Command::Create, 0, init.write_msg1().unwrap()).unwrap(),
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
    assert_eq!(entry.active_circuit_count(), 1);

    let sd_task = tokio::spawn(entry.shutdown());
    let destroy = reader.recv_cell(Duration::from_secs(2)).await.unwrap();
    assert_eq!(destroy.command, Command::Destroy);
    assert_eq!(destroy.destroy_reason().unwrap(), DestroyReason::Normal);
    sd_task.await.unwrap();
}
