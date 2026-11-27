use std::time::Duration;

use private_relay_crypto::{
    ClientCircuitCrypto, HopHandshakeInitiator, LinkRekeyPolicy, StaticKeypair,
};
use private_relay_network::{
    connect_noise_link_with_rekey, ClientConfigFile, LinkReader, LinkWriter, PeerDescriptor,
    RelayRole,
};
use private_relay_protocol::{
    chunk_request, Cell, CircuitId, CircuitState, Command, DestroyReason, ExtendDirective,
    InnerPayload, MessageReassembler, ProtocolError, ReassembledMessage, RelayHopPlaintext,
    RequestId, RequestState,
};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use crate::error::ClientError;

/// Client-side timing policy for circuit construction and bounded request/response exchanges.
#[derive(Debug, Clone, Copy)]
pub struct ClientConfig {
    pub handshake_timeout: Duration,
    pub io_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
        }
    }
}

impl ClientConfig {
    pub fn from_config_file(file: &ClientConfigFile) -> Self {
        Self {
            handshake_timeout: Duration::from_millis(file.handshake_timeout_ms),
            io_timeout: Duration::from_millis(file.io_timeout_ms),
            request_timeout: Duration::from_millis(file.request_timeout_ms),
        }
    }
}

/// Entrypoint for establishing authenticated 3-hop Private-Relay circuits.
pub struct RelayClient;

/// Live 3-hop onion-encrypted circuit (`Client -> Entry -> Middle -> Exit`).
pub struct ClientCircuit {
    cid: CircuitId,
    state: CircuitState,
    next_request_id: u32,
    last_request_id: Option<RequestId>,
    crypto: ClientCircuitCrypto,
    reader: LinkReader<ReadHalf<TcpStream>>,
    writer: LinkWriter<WriteHalf<TcpStream>>,
    config: ClientConfig,
}

impl RelayClient {
    /// Connects to `route[0]` (`Entry`), performs `Noise_IK` link authentication with a fresh
    /// ephemeral client keypair, and telescopically extends through `route[1]` (`Middle`) and
    /// `route[2]` (`Exit`).
    pub async fn connect_three_hop(
        route: [PeerDescriptor; 3],
        config: ClientConfig,
    ) -> Result<ClientCircuit, ClientError> {
        Self::connect_three_hop_with_rekey(route, config, LinkRekeyPolicy::default()).await
    }

    /// Connects a 3-hop circuit configuring an explicit [`LinkRekeyPolicy`] on the Client->Entry link.
    pub async fn connect_three_hop_with_rekey(
        route: [PeerDescriptor; 3],
        config: ClientConfig,
        rekey_policy: LinkRekeyPolicy,
    ) -> Result<ClientCircuit, ClientError> {
        if route[0].role != RelayRole::Entry
            || route[1].role != RelayRole::Middle
            || route[2].role != RelayRole::Exit
        {
            return Err(ClientError::InvalidRoute(
                "route must be ordered [Entry, Middle, Exit]",
            ));
        }

        let entry_pub = route[0].public_key()?;
        let middle_pub = route[1].public_key()?;
        let exit_pub = route[2].public_key()?;

        let client_ephemeral = StaticKeypair::generate()?;
        let (mut reader, mut writer) = connect_noise_link_with_rekey(
            &route[0].addr,
            &client_ephemeral,
            entry_pub,
            config.handshake_timeout,
            rekey_policy,
        )
        .await?;

        let cid = CircuitId::from_role_bits(1, true)?;
        let mut state = CircuitState::Building;
        let mut crypto = ClientCircuitCrypto::new();

        // Hop 1: CREATE -> CREATED (Entry)
        let mut init1 = HopHandshakeInitiator::new(1, entry_pub)?;
        let msg1_1 = init1.write_msg1()?;
        writer
            .send_cell(
                &Cell::new(cid, Command::Create, 0, msg1_1)?,
                config.io_timeout,
            )
            .await?;

        let created1 = recv_expected_cell(
            &mut reader,
            cid,
            Command::Created,
            config.handshake_timeout,
            &mut state,
        )
        .await?;
        crypto.push_hop(init1.finish_with_msg2(&created1.body)?)?;

        // Hop 2: EXTEND -> EXTENDED (Middle via Entry)
        let mut init2 = HopHandshakeInitiator::new(2, middle_pub)?;
        let dir2 = ExtendDirective {
            next_hop_addr: route[1].addr.clone(),
            next_hop_pub: middle_pub,
            handshake_msg1: init2.write_msg1()?,
        };
        let body2 = crypto.seal_forward_to_hop(1, &RelayHopPlaintext::Extend(dir2))?;
        writer
            .send_cell(
                &Cell::new(cid, Command::Extend, 0, body2)?,
                config.io_timeout,
            )
            .await?;

        let extended2 = recv_expected_cell(
            &mut reader,
            cid,
            Command::Extended,
            config.handshake_timeout,
            &mut state,
        )
        .await?;
        let msg2_2 = match crypto.open_backward_from_hop(1, &extended2.body)? {
            RelayHopPlaintext::Extended(b) => b,
            _ => {
                return Err(ClientError::Protocol(ProtocolError::MalformedPayload(
                    "expected EXTENDED response from hop 2",
                )))
            }
        };
        crypto.push_hop(init2.finish_with_msg2(&msg2_2)?)?;

        // Hop 3: EXTEND -> EXTENDED (Exit via Entry + Middle)
        let mut init3 = HopHandshakeInitiator::new(3, exit_pub)?;
        let dir3 = ExtendDirective {
            next_hop_addr: route[2].addr.clone(),
            next_hop_pub: exit_pub,
            handshake_msg1: init3.write_msg1()?,
        };
        let body3 = crypto.seal_forward_to_hop(2, &RelayHopPlaintext::Extend(dir3))?;
        writer
            .send_cell(
                &Cell::new(cid, Command::Extend, 0, body3)?,
                config.io_timeout,
            )
            .await?;

        let extended3 = recv_expected_cell(
            &mut reader,
            cid,
            Command::Extended,
            config.handshake_timeout,
            &mut state,
        )
        .await?;
        let msg2_3 = match crypto.open_backward_from_hop(2, &extended3.body)? {
            RelayHopPlaintext::Extended(b) => b,
            _ => {
                return Err(ClientError::Protocol(ProtocolError::MalformedPayload(
                    "expected EXTENDED response from hop 3",
                )))
            }
        };
        crypto.push_hop(init3.finish_with_msg2(&msg2_3)?)?;

        state.mark_open()?;
        debug!(circuit_id = cid.get(), "three-hop client circuit opened");

        Ok(ClientCircuit {
            cid,
            state,
            next_request_id: 1,
            last_request_id: None,
            crypto,
            reader,
            writer,
            config,
        })
    }
}

impl ClientCircuit {
    pub fn circuit_id(&self) -> CircuitId {
        self.cid
    }

    pub fn state(&self) -> CircuitState {
        self.state
    }

    pub fn last_request_id(&self) -> Option<RequestId> {
        self.last_request_id
    }

    pub fn link_rekey_epochs(&self) -> Result<(u64, u64), ClientError> {
        Ok(self.writer.rekey_epochs()?)
    }

    pub async fn trigger_link_rekey(&mut self) -> Result<(), ClientError> {
        Ok(self.writer.trigger_rekey(self.config.io_timeout).await?)
    }

    /// Sends a bounded (`<= 64 KiB`) request through all 3 relays to `target_host_port` (`host:port`)
    /// and returns the bounded (`<= 64 KiB`) response bytes.
    pub async fn send_request(
        &mut self,
        target_host_port: &str,
        body: &[u8],
    ) -> Result<Vec<u8>, ClientError> {
        if !self.state.can_forward_data() {
            return Err(ClientError::InvalidState("circuit is not open"));
        }

        let raw_rid = self.next_request_id;
        let rid = RequestId::new(raw_rid)?;
        self.last_request_id = Some(rid);
        self.next_request_id = raw_rid
            .checked_add(1)
            .ok_or(ClientError::InvalidState("request ID space exhausted"))?;

        let mut req_state = RequestState::Idle;
        req_state.begin_request()?;

        let chunks = chunk_request(rid, target_host_port, body)?;
        for ch in chunks {
            let inner = RelayHopPlaintext::Message(ch.encode()?);
            let sealed = self.crypto.seal_forward_to_hop(3, &inner)?;
            self.writer
                .send_cell(
                    &Cell::new(self.cid, Command::RelayData, 0, sealed)?,
                    self.config.io_timeout,
                )
                .await?;
        }
        req_state.finish_request()?;

        let deadline = self.config.request_timeout;
        let mut reasm = MessageReassembler::for_response(rid);

        let resp_res = timeout(deadline, async {
            loop {
                let cell = self
                    .reader
                    .recv_cell_with_timeouts(deadline, self.config.io_timeout)
                    .await?;
                if cell.circuit_id != self.cid {
                    return Err(ClientError::Protocol(ProtocolError::MalformedPayload(
                        "mismatched circuit ID in response",
                    )));
                }
                if cell.command == Command::Destroy {
                    let reason = cell.destroy_reason()?;
                    let _ = self.state.destroy(reason);
                    return Err(ClientError::CircuitDestroyed(reason));
                }
                if cell.command != Command::RelayData {
                    return Err(ClientError::Protocol(ProtocolError::MalformedPayload(
                        "expected RELAY_DATA cell on circuit",
                    )));
                }

                let inner_bytes = match self.crypto.open_backward_from_hop(3, &cell.body)? {
                    RelayHopPlaintext::Message(bytes) => bytes,
                    _ => {
                        return Err(ClientError::Protocol(ProtocolError::MalformedPayload(
                            "expected Message plaintext from exit hop",
                        )))
                    }
                };
                let chunk = InnerPayload::decode(&inner_bytes)?;
                if req_state == RequestState::AwaitingResponse {
                    req_state.begin_response()?;
                }

                match reasm.push(chunk)? {
                    None => {}
                    Some(ReassembledMessage::Data(bytes)) => {
                        req_state.complete()?;
                        return Ok(bytes);
                    }
                    Some(ReassembledMessage::Error(code)) => {
                        req_state.fail(code)?;
                        return Err(ClientError::RemoteError(code));
                    }
                }
            }
        })
        .await;

        match resp_res {
            Ok(inner) => inner,
            Err(_) => Err(ClientError::Network(
                private_relay_network::NetworkError::Timeout("awaiting circuit response"),
            )),
        }
    }

    /// Sends `DESTROY(Normal)` cleanly down the 3-hop circuit and shuts down the Entry transport link.
    pub async fn close(mut self) -> Result<(), ClientError> {
        if !self.state.is_closed() {
            let _ = self.state.destroy(DestroyReason::Normal);
            let _ = self
                .writer
                .send_cell(
                    &Cell::destroy(self.cid, DestroyReason::Normal),
                    self.config.io_timeout,
                )
                .await;
        }
        let _ = self.writer.shutdown().await;
        Ok(())
    }
}

async fn recv_expected_cell(
    reader: &mut LinkReader<ReadHalf<TcpStream>>,
    expected_cid: CircuitId,
    expected_cmd: Command,
    wait_timeout: Duration,
    state: &mut CircuitState,
) -> Result<Cell, ClientError> {
    let cell = reader.recv_cell(wait_timeout).await?;
    if cell.circuit_id != expected_cid {
        return Err(ClientError::Protocol(ProtocolError::MalformedPayload(
            "unexpected circuit ID during handshake",
        )));
    }
    if cell.command == Command::Destroy {
        let reason = cell.destroy_reason()?;
        let _ = state.destroy(reason);
        return Err(ClientError::CircuitDestroyed(reason));
    }
    if cell.command != expected_cmd {
        return Err(ClientError::Protocol(ProtocolError::MalformedPayload(
            "unexpected command during circuit handshake",
        )));
    }
    Ok(cell)
}
