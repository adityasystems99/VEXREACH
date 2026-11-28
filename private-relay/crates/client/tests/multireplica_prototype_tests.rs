use std::sync::Arc;
use std::time::Duration;

use private_relay_client::{ClientConfig, ClientError, RelayClient};
use private_relay_crypto::StaticKeypair;
use private_relay_network::{PeerDescriptor, RelayConfig, RelayRole};
use private_relay_protocol::RequestErrorCode;
use private_relay_relay::{RelayHandle, RelayServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Isolated Option B + D multi-replica prototype topology:
/// 2 independent Entry replicas, 2 independent Middle replicas, and 2 independent Exit replicas
/// (6 unique X25519 keypairs — zero shared secrets or distributed circuit state).
struct MultiReplicaPrototypeCluster {
    dest_addr: String,
    entries: [RelayHandle; 2],
    middles: [RelayHandle; 2],
    exits: [RelayHandle; 2],
}

impl MultiReplicaPrototypeCluster {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dest_addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    if s.read_to_end(&mut buf).await.is_ok() {
                        for b in &mut buf {
                            *b ^= 0x33;
                        }
                        let _ = s.write_all(&buf).await;
                        let _ = s.shutdown().await;
                    }
                });
            }
        });

        let mut exit_handles = Vec::new();
        for name in ["exit-0", "exit-1"] {
            let kp = StaticKeypair::generate().unwrap();
            let mut cfg =
                RelayConfig::with_generated_keypair(name, RelayRole::Exit, "127.0.0.1:0", &kp);
            cfg.allow_loopback_for_test = true;
            cfg.allowed_targets = vec![dest_addr.clone()];
            exit_handles.push(RelayServer::start(cfg).await.unwrap());
        }
        let exit_descs: Vec<PeerDescriptor> = exit_handles
            .iter()
            .map(|h| h.peer_descriptor().clone())
            .collect();

        let mut middle_handles = Vec::new();
        for name in ["middle-0", "middle-1"] {
            let kp = StaticKeypair::generate().unwrap();
            let mut cfg =
                RelayConfig::with_generated_keypair(name, RelayRole::Middle, "127.0.0.1:0", &kp);
            cfg.allowed_next_peers = exit_descs.clone();
            middle_handles.push(RelayServer::start(cfg).await.unwrap());
        }
        let middle_descs: Vec<PeerDescriptor> = middle_handles
            .iter()
            .map(|h| h.peer_descriptor().clone())
            .collect();

        let mut entry_handles = Vec::new();
        for name in ["entry-0", "entry-1"] {
            let kp = StaticKeypair::generate().unwrap();
            let mut cfg =
                RelayConfig::with_generated_keypair(name, RelayRole::Entry, "127.0.0.1:0", &kp);
            cfg.allowed_next_peers = middle_descs.clone();
            entry_handles.push(RelayServer::start(cfg).await.unwrap());
        }

        let [e0, e1]: [RelayHandle; 2] = entry_handles.try_into().ok().unwrap();
        let [m0, m1]: [RelayHandle; 2] = middle_handles.try_into().ok().unwrap();
        let [x0, x1]: [RelayHandle; 2] = exit_handles.try_into().ok().unwrap();

        Self {
            dest_addr,
            entries: [e0, e1],
            middles: [m0, m1],
            exits: [x0, x1],
        }
    }

    fn route(&self, e_idx: usize, m_idx: usize, x_idx: usize) -> [PeerDescriptor; 3] {
        [
            self.entries[e_idx].peer_descriptor().clone(),
            self.middles[m_idx].peer_descriptor().clone(),
            self.exits[x_idx].peer_descriptor().clone(),
        ]
    }
}

#[tokio::test]
async fn multireplica_prototype_isolated_routing_identity_pinning_and_failover() {
    let cluster = MultiReplicaPrototypeCluster::start().await;
    let cfg = ClientConfig {
        handshake_timeout: Duration::from_secs(3),
        io_timeout: Duration::from_secs(3),
        request_timeout: Duration::from_secs(5),
    };

    // 1. Distinct per-replica X25519 keys guarantee zero shared secret distribution.
    assert_ne!(
        cluster.entries[0].peer_descriptor().public_key_hex,
        cluster.entries[1].peer_descriptor().public_key_hex
    );
    assert_ne!(
        cluster.middles[0].peer_descriptor().public_key_hex,
        cluster.middles[1].peer_descriptor().public_key_hex
    );
    assert_ne!(
        cluster.exits[0].peer_descriptor().public_key_hex,
        cluster.exits[1].peer_descriptor().public_key_hex
    );

    // 2. Concurrent client circuits pinned across crossed instance paths (E0->M1->X0 and E1->M0->X1).
    let path_a = cluster.route(0, 1, 0);
    let path_b = cluster.route(1, 0, 1);
    let dest = Arc::new(cluster.dest_addr.clone());

    let (mut c_a, mut c_b) = tokio::try_join!(
        RelayClient::connect_three_hop(path_a.clone(), cfg),
        RelayClient::connect_three_hop(path_b.clone(), cfg),
    )
    .unwrap();

    let payload_a = b"replica-path-alpha".to_vec();
    let payload_b = b"replica-path-beta".to_vec();
    let (resp_a, resp_b) = tokio::try_join!(
        c_a.send_request(&dest, &payload_a),
        c_b.send_request(&dest, &payload_b),
    )
    .unwrap();
    assert_eq!(
        resp_a,
        payload_a.iter().map(|b| b ^ 0x33).collect::<Vec<_>>()
    );
    assert_eq!(
        resp_b,
        payload_b.iter().map(|b| b ^ 0x33).collect::<Vec<_>>()
    );

    // 3. Cross-instance identity substitution fails closed (`entry-0` addr paired with `entry-1` pubkey).
    let mut mismatched = cluster.route(0, 0, 0);
    mismatched[0].public_key_hex = cluster.entries[1].peer_descriptor().public_key_hex.clone();
    assert!(RelayClient::connect_three_hop(mismatched, cfg)
        .await
        .is_err());

    // 4. Unauthorized/unlisted Exit address cannot be reached even across healthy Entry/Middle.
    let mut rogue_exit = cluster.exits[0].peer_descriptor().clone();
    rogue_exit.addr = "127.0.0.1:1".into();
    assert!(RelayClient::connect_three_hop(
        [
            cluster.entries[0].peer_descriptor().clone(),
            cluster.middles[0].peer_descriptor().clone(),
            rogue_exit,
        ],
        cfg
    )
    .await
    .is_err());

    // 5. Terminate middle-0: c_b (pinned to middle-0) stops cleanly; c_a (pinned to middle-1)
    // continues serving requests and SSRF checks with zero interruption!
    let [e0, e1] = cluster.entries;
    let [m0, m1] = cluster.middles;
    let [x0, x1] = cluster.exits;
    m0.shutdown().await;

    assert!(c_b.send_request(&dest, b"after-m0-down").await.is_err());

    let still_alive = c_a
        .send_request(&dest, b"still-pinned-on-m1")
        .await
        .unwrap();
    assert_eq!(
        still_alive,
        b"still-pinned-on-m1"
            .iter()
            .map(|b| b ^ 0x33)
            .collect::<Vec<_>>()
    );
    assert!(matches!(
        c_a.send_request("169.254.169.254:80", b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap_err(),
        ClientError::RemoteError(RequestErrorCode::PolicyDenied)
    ));
    let _ = c_a.close().await;

    // Client-side endpoint failover seamlessly builds new circuits avoiding failed middle-0.
    let mut failover = RelayClient::connect_three_hop(
        [
            e1.peer_descriptor().clone(),
            m1.peer_descriptor().clone(),
            x1.peer_descriptor().clone(),
        ],
        cfg,
    )
    .await
    .unwrap();
    assert_eq!(
        failover.send_request(&dest, b"failover-ok").await.unwrap(),
        b"failover-ok".iter().map(|b| b ^ 0x33).collect::<Vec<_>>()
    );
    let _ = failover.close().await;

    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(e0.active_circuit_count(), 0);
    assert_eq!(e1.active_circuit_count(), 0);
    assert_eq!(m1.active_circuit_count(), 0);
    assert_eq!(x0.active_circuit_count(), 0);
    assert_eq!(x1.active_circuit_count(), 0);

    e0.shutdown().await;
    e1.shutdown().await;
    m1.shutdown().await;
    x0.shutdown().await;
    x1.shutdown().await;
}
