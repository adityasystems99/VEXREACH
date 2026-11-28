use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use private_relay_crypto::{HopCipherPair, HopHandshakeResponder, StaticKeypair, Zeroizing};
use private_relay_network::{
    accept_noise_link_with_rekey, connect_noise_link_with_rekey, DestinationPolicy, LinkReader,
    LinkWriter, NetworkError, PeerDescriptor, RelayConfig, RelayMetrics, RelayRole,
    SharedRelayMetrics,
};
use private_relay_protocol::{
    chunk_response, encode_error_payload, Cell, CircuitId, CircuitState, Command, DecodedRequest,
    DestroyReason, ExtendDirective, InnerPayload, MessageReassembler, ReassembledMessage,
    RelayHopPlaintext, MAX_MESSAGE_BYTES,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{
    mpsc, oneshot, watch, Mutex as AsyncMutex, Notify, OwnedSemaphorePermit, Semaphore,
};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::error::RelayError;

type OutboundLinkMap = HashMap<(String, [u8; 32]), Arc<OutboundLinkHandle>>;
type DialLockMap = HashMap<(String, [u8; 32]), Arc<AsyncMutex<()>>>;
type PendingDestResponse =
    oneshot::Receiver<Result<Vec<u8>, private_relay_protocol::RequestErrorCode>>;

/// Shared runtime state for a running relay instance across all accepted links and circuits.
struct RelayRuntime {
    config: RelayConfig,
    keypair: StaticKeypair,
    dest_policy: DestinationPolicy,
    conn_semaphore: Arc<Semaphore>,
    active_circuits: AtomicUsize,
    active_tasks: AtomicUsize,
    drain_notify: Notify,
    per_ip_circuits: Mutex<HashMap<IpAddr, usize>>,
    outbound_links: AsyncMutex<OutboundLinkMap>,
    dial_locks: Mutex<DialLockMap>,
    shutdown_rx: watch::Receiver<bool>,
    metrics: SharedRelayMetrics,
}

/// RAII tracker ensuring `RelayHandle::shutdown()` waits cleanly for spawned tasks to exit.
struct TaskTrackGuard(Arc<RelayRuntime>);

impl TaskTrackGuard {
    fn spawn_counted(runtime: &Arc<RelayRuntime>) -> Self {
        runtime.active_tasks.fetch_add(1, Ordering::AcqRel);
        Self(Arc::clone(runtime))
    }
}

impl Drop for TaskTrackGuard {
    fn drop(&mut self) {
        if self.0.active_tasks.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.drain_notify.notify_waiters();
        }
    }
}

impl RelayRuntime {
    fn handshake_timeout(&self) -> Duration {
        Duration::from_millis(self.config.handshake_timeout_ms.max(100))
    }

    fn io_timeout(&self) -> Duration {
        Duration::from_millis(self.config.io_timeout_ms.max(100))
    }

    fn dest_io_timeout(&self) -> Duration {
        Duration::from_millis(self.config.destination_io_timeout_ms.max(100))
    }

    fn idle_ttl(&self) -> Duration {
        Duration::from_secs(self.config.idle_circuit_ttl_secs.max(1))
    }

    fn try_acquire_circuit_slot(self: &Arc<Self>, peer_ip: IpAddr) -> Option<CircuitSlotGuard> {
        // Reserve global circuit capacity first (CAS loop avoids exceeding `max_concurrent_circuits`).
        loop {
            let cur = self.active_circuits.load(Ordering::Acquire);
            if cur >= self.config.max_concurrent_circuits {
                return None;
            }
            if self
                .active_circuits
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }

        // Entry relays also bound circuits per client source IP (`ARCHITECTURE.md` / `KI-02`).
        let tracked_ip = if self.config.role == RelayRole::Entry {
            let mut map = match self.per_ip_circuits.lock() {
                Ok(g) => g,
                Err(_) => {
                    self.active_circuits.fetch_sub(1, Ordering::AcqRel);
                    return None;
                }
            };
            let count = map.entry(peer_ip).or_insert(0);
            if *count >= self.config.max_circuits_per_peer_ip {
                self.active_circuits.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
            *count += 1;
            Some(peer_ip)
        } else {
            None
        };

        self.metrics.inc_circuits_created();
        Some(CircuitSlotGuard {
            runtime: Arc::clone(self),
            tracked_ip,
        })
    }

    fn authorize_next_peer(&self, addr: &str, pub_key: &[u8; 32]) -> Result<(), DestroyReason> {
        let expected_next_role = match self.config.role {
            RelayRole::Entry => RelayRole::Middle,
            RelayRole::Middle => RelayRole::Exit,
            RelayRole::Exit => return Err(DestroyReason::ProtocolError),
        };

        for peer in &self.config.allowed_next_peers {
            if peer.role == expected_next_role
                && peer.addr == addr
                && peer.public_key().ok().as_ref() == Some(pub_key)
            {
                return Ok(());
            }
        }

        Err(DestroyReason::PolicyDenied)
    }

    async fn get_or_connect_outbound(
        self: &Arc<Self>,
        addr: &str,
        expected_pub: [u8; 32],
    ) -> Result<Arc<OutboundLinkHandle>, DestroyReason> {
        let key = (addr.to_owned(), expected_pub);
        {
            let mut pool = self.outbound_links.lock().await;
            if let Some(existing) = pool.get(&key) {
                if existing.is_alive() {
                    return Ok(Arc::clone(existing));
                }
                pool.remove(&key);
            }
        }

        // Per-peer dial mutex serializes duplicate connects to the same peer without blocking other peers.
        let dial_mutex = {
            let mut locks = self
                .dial_locks
                .lock()
                .map_err(|_| DestroyReason::ProtocolError)?;
            Arc::clone(
                locks
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
            )
        };
        let _dial_guard = dial_mutex.lock().await;

        {
            let mut pool = self.outbound_links.lock().await;
            if let Some(existing) = pool.get(&key) {
                if existing.is_alive() {
                    return Ok(Arc::clone(existing));
                }
                pool.remove(&key);
            }
        }

        let (reader, writer) = connect_noise_link_with_rekey(
            addr,
            &self.keypair,
            expected_pub,
            self.handshake_timeout(),
            self.config.link_rekey_policy(),
        )
        .await
        .map_err(|err| match err {
            NetworkError::Timeout(_) => DestroyReason::HandshakeTimeout,
            NetworkError::Crypto(_) => DestroyReason::CryptoFail,
            _ => DestroyReason::PeerDisconnected,
        })?;

        let handle = OutboundLinkHandle::spawn(Arc::clone(self), key.clone(), reader, writer);
        let mut pool = self.outbound_links.lock().await;
        pool.insert(key, Arc::clone(&handle));
        Ok(handle)
    }
}

/// RAII capacity guard ensuring global and per-IP counters are decremented on every teardown path.
struct CircuitSlotGuard {
    runtime: Arc<RelayRuntime>,
    tracked_ip: Option<IpAddr>,
}

impl Drop for CircuitSlotGuard {
    fn drop(&mut self) {
        if let Some(ip) = self.tracked_ip {
            if let Ok(mut map) = self.runtime.per_ip_circuits.lock() {
                if let Some(cnt) = map.get_mut(&ip) {
                    if *cnt <= 1 {
                        map.remove(&ip);
                    } else {
                        *cnt -= 1;
                    }
                }
            }
        }
        self.runtime.metrics.inc_circuits_destroyed();
        self.runtime.active_circuits.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Multiplexed outbound Noise link from `Entry -> Middle` or `Middle -> Exit`.
struct OutboundLinkHandle {
    tx: mpsc::Sender<Cell>,
    routes: Arc<Mutex<HashMap<CircuitId, mpsc::Sender<Cell>>>>,
    next_id: AtomicU32,
    alive: AtomicBool,
}

impl OutboundLinkHandle {
    fn spawn(
        runtime: Arc<RelayRuntime>,
        pool_key: (String, [u8; 32]),
        mut reader: LinkReader<ReadHalf<TcpStream>>,
        mut writer: LinkWriter<WriteHalf<TcpStream>>,
    ) -> Arc<Self> {
        let queue_cap = runtime.config.circuit_channel_capacity.max(64) * 2;
        let (tx, mut rx) = mpsc::channel::<Cell>(queue_cap);
        let routes: Arc<Mutex<HashMap<CircuitId, mpsc::Sender<Cell>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let handle = Arc::new(Self {
            tx,
            routes: Arc::clone(&routes),
            next_id: AtomicU32::new(1),
            alive: AtomicBool::new(true),
        });

        let io_timeout = runtime.io_timeout();
        let idle_ttl = runtime.idle_ttl();

        // Dedicated serialized Noise link writer task (drains final Destroy frames on shutdown).
        let handle_w = Arc::clone(&handle);
        let mut shutdown_w = runtime.shutdown_rx.clone();
        let routes_w = Arc::clone(&routes);
        let rt_w = Arc::clone(&runtime);
        let key_w = pool_key.clone();
        let writer_track = TaskTrackGuard::spawn_counted(&runtime);
        tokio::spawn(async move {
            let _track = writer_track;
            let mut shutting_down = false;
            let drain_sleep = sleep(Duration::from_millis(250));
            tokio::pin!(drain_sleep);
            loop {
                if shutting_down {
                    tokio::select! {
                        _ = &mut drain_sleep => break,
                        maybe_cell = rx.recv() => {
                            match maybe_cell {
                                Some(cell) => {
                                    let wait = io_timeout.min(Duration::from_millis(250));
                                    if writer.send_cell(&cell, wait).await.is_err() {
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                } else {
                    tokio::select! {
                        _ = shutdown_w.changed() => {
                            if *shutdown_w.borrow() {
                                shutting_down = true;
                                drain_sleep
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + Duration::from_millis(250));
                            }
                        }
                        maybe_cell = rx.recv() => {
                            match maybe_cell {
                                Some(first) => {
                                    let mut batch = vec![first];
                                    while batch.len() < 32 {
                                        match rx.try_recv() {
                                            Ok(next_cell) => batch.push(next_cell),
                                            Err(_) => break,
                                        }
                                    }
                                    let count = batch.len() as u64;
                                    if writer.send_cells_batch(&batch, io_timeout).await.is_err() {
                                        break;
                                    }
                                    rt_w.metrics.add_sent_frames(
                                        count,
                                        count * private_relay_protocol::OUTER_WIRE_FRAME_BYTES as u64,
                                    );
                                }
                                None => break,
                            }
                        }
                    }
                }
            }
            let _ = writer.shutdown().await;
            handle_w.alive.store(false, Ordering::Release);
            notify_routes_disconnected(&routes_w).await;
            let mut pool = rt_w.outbound_links.lock().await;
            if let Some(cur) = pool.get(&key_w) {
                if Arc::ptr_eq(cur, &handle_w) {
                    pool.remove(&key_w);
                }
            }
        });

        // Dedicated Noise link reader demuxer pushing downstream responses into per-circuit queues.
        let handle_r = Arc::clone(&handle);
        let mut shutdown_r = runtime.shutdown_rx.clone();
        let rt_r = Arc::clone(&runtime);
        let reader_track = TaskTrackGuard::spawn_counted(&runtime);
        tokio::spawn(async move {
            let _track = reader_track;
            loop {
                tokio::select! {
                    _ = shutdown_r.changed() => {
                        if *shutdown_r.borrow() {
                            break;
                        }
                    }
                    recv_res = reader.recv_cell_with_timeouts(idle_ttl, io_timeout) => {
                        match recv_res {
                            Ok(cell) => {
                                rt_r.metrics.inc_cells_processed();
                                rt_r.metrics.add_bytes_received(private_relay_protocol::OUTER_WIRE_FRAME_BYTES as u64);
                                let target = routes
                                    .lock()
                                    .ok()
                                    .and_then(|g| g.get(&cell.circuit_id).cloned());
                                if let Some(circuit_tx) = target {
                                    match circuit_tx.try_send(cell) {
                                        Ok(()) => {}
                                        Err(tokio::sync::mpsc::error::TrySendError::Full(c)) => {
                                            let cid = c.circuit_id;
                                            let wait = io_timeout.min(Duration::from_millis(500));
                                            if circuit_tx.send_timeout(c, wait).await.is_err() {
                                                if let Ok(mut g) = routes.lock() {
                                                    g.remove(&cid);
                                                }
                                                let _ = handle_r.tx.try_send(Cell::destroy(
                                                    cid,
                                                    DestroyReason::ResourceLimit,
                                                ));
                                            }
                                        }
                                        Err(tokio::sync::mpsc::error::TrySendError::Closed(c)) => {
                                            let cid = c.circuit_id;
                                            if let Ok(mut g) = routes.lock() {
                                                g.remove(&cid);
                                            }
                                            let _ = handle_r.tx.try_send(Cell::destroy(
                                                cid,
                                                DestroyReason::PeerDisconnected,
                                            ));
                                        }
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            handle_r.alive.store(false, Ordering::Release);
            notify_routes_disconnected(&routes).await;
            let mut pool = rt_r.outbound_links.lock().await;
            if let Some(cur) = pool.get(&pool_key) {
                if Arc::ptr_eq(cur, &handle_r) {
                    pool.remove(&pool_key);
                }
            }
        });

        handle
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire) && !self.tx.is_closed()
    }

    fn register_circuit(
        &self,
        cap: usize,
    ) -> Result<(CircuitId, mpsc::Receiver<Cell>), DestroyReason> {
        let mut guard = self
            .routes
            .lock()
            .map_err(|_| DestroyReason::ProtocolError)?;

        // Search up to a bounded number of IDs to handle unlikely wrap-around collisions cleanly.
        for _ in 0..1024 {
            let raw = self.next_id.fetch_add(1, Ordering::Relaxed) & 0x7FFF_FFFF;
            let non_zero = if raw == 0 { 1 } else { raw };
            let cid = CircuitId::from_role_bits(non_zero, true)
                .map_err(|_| DestroyReason::ProtocolError)?;
            if let std::collections::hash_map::Entry::Vacant(entry) = guard.entry(cid) {
                let (rx_tx, rx_rx) = mpsc::channel(cap);
                entry.insert(rx_tx);
                return Ok((cid, rx_rx));
            }
        }
        Err(DestroyReason::ResourceLimit)
    }

    fn unregister_circuit(&self, cid: CircuitId) {
        if let Ok(mut guard) = self.routes.lock() {
            guard.remove(&cid);
        }
    }

    async fn send(&self, cell: Cell, io_timeout: Duration) -> Result<(), DestroyReason> {
        if !self.is_alive() {
            return Err(DestroyReason::PeerDisconnected);
        }
        self.tx
            .send_timeout(cell, io_timeout)
            .await
            .map_err(|_| DestroyReason::PeerDisconnected)
    }
}

async fn notify_routes_disconnected(routes: &Arc<Mutex<HashMap<CircuitId, mpsc::Sender<Cell>>>>) {
    let entries: Vec<(CircuitId, mpsc::Sender<Cell>)> = {
        let mut guard = match routes.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        guard.drain().collect()
    };
    for (cid, tx) in entries {
        let _ = tx.try_send(Cell::destroy(cid, DestroyReason::PeerDisconnected));
    }
}

/// Public running relay server instance.
pub struct RelayServer;

/// Control handle for a spawned relay node; dropping does not stop cleanly—call [`RelayHandle::shutdown`].
pub struct RelayHandle {
    local_addr: SocketAddr,
    metrics_local_addr: Option<SocketAddr>,
    descriptor: PeerDescriptor,
    runtime: Arc<RelayRuntime>,
    shutdown_tx: watch::Sender<bool>,
    accept_task: JoinHandle<()>,
}

impl RelayHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn metrics_local_addr(&self) -> Option<SocketAddr> {
        self.metrics_local_addr
    }

    pub fn peer_descriptor(&self) -> &PeerDescriptor {
        &self.descriptor
    }

    pub fn active_circuit_count(&self) -> usize {
        self.runtime.active_circuits.load(Ordering::Acquire)
    }

    pub fn active_connection_count(&self) -> usize {
        self.runtime
            .config
            .max_concurrent_connections
            .saturating_sub(self.runtime.conn_semaphore.available_permits())
    }

    pub fn metrics(&self) -> &SharedRelayMetrics {
        &self.runtime.metrics
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.accept_task.await;
        let grace = self
            .runtime
            .io_timeout()
            .clamp(Duration::from_millis(1_500), Duration::from_secs(5));
        let _ = timeout(grace, async {
            loop {
                let notified = self.runtime.drain_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.runtime.active_tasks.load(Ordering::Acquire) == 0 {
                    break;
                }
                notified.await;
            }
        })
        .await;
        self.runtime.outbound_links.lock().await.clear();
    }
}

impl RelayServer {
    /// Validates `config`, binds the TCP listener, and spawns the Noise relay server loop.
    pub async fn start(config: RelayConfig) -> Result<RelayHandle, RelayError> {
        config.validate()?;
        let keypair = config.keypair()?;
        let listener = TcpListener::bind(&config.listen_addr).await?;
        let local_addr = listener.local_addr()?;

        let mut effective_config = config;
        effective_config.scrub_private_key();
        effective_config.listen_addr = local_addr.to_string();

        let descriptor = PeerDescriptor {
            id: effective_config.id.clone(),
            role: effective_config.role,
            addr: effective_config.listen_addr.clone(),
            public_key_hex: effective_config.public_key_hex.clone(),
        };

        let dest_policy = DestinationPolicy {
            allow_loopback_for_test: effective_config.allow_loopback_for_test,
            allow_private_targets_for_test: effective_config.allow_private_targets_for_test,
            allowed_targets: effective_config.allowed_targets.clone(),
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let metrics = Arc::new(RelayMetrics::new());
        metrics.set_capacity_limits(
            effective_config.max_concurrent_circuits,
            effective_config.max_concurrent_connections,
        );
        let runtime = Arc::new(RelayRuntime {
            config: effective_config.clone(),
            keypair,
            dest_policy,
            conn_semaphore: Arc::new(Semaphore::new(effective_config.max_concurrent_connections)),
            active_circuits: AtomicUsize::new(0),
            active_tasks: AtomicUsize::new(0),
            drain_notify: Notify::new(),
            per_ip_circuits: Mutex::new(HashMap::new()),
            outbound_links: AsyncMutex::new(HashMap::new()),
            dial_locks: Mutex::new(HashMap::new()),
            shutdown_rx: shutdown_rx.clone(),
            metrics: Arc::clone(&metrics),
        });

        let metrics_local_addr = if let Some(metrics_addr) =
            effective_config.metrics_addr.as_deref()
        {
            let m_listener = TcpListener::bind(metrics_addr).await?;
            let bound = m_listener.local_addr()?;
            let m_rt = Arc::clone(&runtime);
            let mut m_sd = shutdown_rx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = m_sd.changed() => {
                            if *m_sd.borrow() {
                                break;
                            }
                        }
                        accepted = m_listener.accept() => {
                            if let Ok((mut stream, _)) = accepted {
                                let rt_req = Arc::clone(&m_rt);
                                tokio::spawn(async move {
                                    let mut buf = [0u8; 1024];
                                    let Ok(Ok(n)) = timeout(Duration::from_secs(2), stream.read(&mut buf)).await else {
                                        return;
                                    };
                                    let req_text = String::from_utf8_lossy(&buf[..n]);
                                    let first_line = req_text.lines().next().unwrap_or("");
                                    let mut parts = first_line.split_whitespace();
                                    let method = parts.next().unwrap_or("");
                                    let raw_path = parts.next().unwrap_or("/");
                                    let path = raw_path.split('?').next().unwrap_or("/");
                                    let resp = if method != "GET" {
                                        "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
                                    } else if path == "/healthz" {
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n".to_owned()
                                    } else if path == "/metrics" {
                                        let role_str = match rt_req.config.role {
                                            RelayRole::Entry => "entry",
                                            RelayRole::Middle => "middle",
                                            RelayRole::Exit => "exit",
                                        };
                                        let body = rt_req.metrics.render_prometheus(role_str, &rt_req.config.id);
                                        format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                            body.len(),
                                            body
                                        )
                                    } else {
                                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
                                    };
                                    let _ = timeout(Duration::from_secs(2), stream.write_all(resp.as_bytes())).await;
                                    let _ = stream.shutdown().await;
                                });
                            }
                        }
                    }
                }
            });
            Some(bound)
        } else {
            None
        };

        info!(
            relay_id = %runtime.config.id,
            role = ?runtime.config.role,
            "relay node started"
        );

        let rt_accept = Arc::clone(&runtime);
        let mut sd_accept = shutdown_rx;
        let accept_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sd_accept.changed() => {
                        if *sd_accept.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, peer_addr)) => {
                                match Arc::clone(&rt_accept.conn_semaphore).try_acquire_owned() {
                                    Ok(permit) => {
                                        rt_accept.metrics.inc_connections_accepted();
                                        let rt_conn = Arc::clone(&rt_accept);
                                        let conn_track = TaskTrackGuard::spawn_counted(&rt_conn);
                                        tokio::spawn(async move {
                                            let _track = conn_track;
                                            handle_inbound_connection(rt_conn, stream, peer_addr, permit).await;
                                        });
                                    }
                                    Err(_) => {
                                        rt_accept.metrics.inc_connections_rejected();
                                        drop(stream);
                                        warn!(
                                            relay_id = %rt_accept.config.id,
                                            role = ?rt_accept.config.role,
                                            "inbound connection dropped due to max_concurrent_connections limit"
                                        );
                                    }
                                }
                            }
                            Err(_) => {
                                sleep(Duration::from_millis(20)).await;
                            }
                        }
                    }
                }
            }
            info!(
                relay_id = %rt_accept.config.id,
                role = ?rt_accept.config.role,
                "relay accept loop shutting down"
            );
        });

        Ok(RelayHandle {
            local_addr,
            metrics_local_addr,
            descriptor,
            runtime,
            shutdown_tx,
            accept_task,
        })
    }
}

async fn handle_inbound_connection(
    runtime: Arc<RelayRuntime>,
    stream: TcpStream,
    peer_addr: SocketAddr,
    _conn_permit: OwnedSemaphorePermit,
) {
    let peer_ip = peer_addr.ip();
    let (reader, writer, _remote_pub) = match accept_noise_link_with_rekey(
        stream,
        &runtime.keypair,
        runtime.handshake_timeout(),
        runtime.config.link_rekey_policy(),
    )
    .await
    {
        Ok(tuple) => tuple,
        Err(_) => {
            runtime.metrics.dec_connections_active();
            debug!(
                relay_id = %runtime.config.id,
                role = ?runtime.config.role,
                "inbound Noise handshake rejected"
            );
            return;
        }
    };

    spawn_inbound_link_loop(runtime.clone(), reader, writer, peer_ip).await;
    runtime.metrics.dec_connections_active();
}

async fn spawn_inbound_link_loop(
    runtime: Arc<RelayRuntime>,
    mut reader: LinkReader<ReadHalf<TcpStream>>,
    mut writer: LinkWriter<WriteHalf<TcpStream>>,
    peer_ip: IpAddr,
) {
    let queue_cap = runtime.config.circuit_channel_capacity.max(64) * 2;
    let (up_tx, mut up_rx) = mpsc::channel::<Cell>(queue_cap);
    let routes: Arc<Mutex<HashMap<CircuitId, mpsc::Sender<Cell>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let io_timeout = runtime.io_timeout();
    let idle_ttl = runtime.idle_ttl();
    let (writer_dead_tx, mut writer_dead_rx) = watch::channel(false);

    // Writer drains until all up_tx handles (reader + circuit teardown Destroy senders) drop.
    let rt_w = Arc::clone(&runtime);
    let mut last_tx_epoch = 0u64;
    let writer_handle = tokio::spawn(async move {
        while let Some(first) = up_rx.recv().await {
            let mut batch = vec![first];
            while batch.len() < 32 {
                match up_rx.try_recv() {
                    Ok(next_cell) => batch.push(next_cell),
                    Err(_) => break,
                }
            }
            let count = batch.len() as u64;
            if writer.send_cells_batch(&batch, io_timeout).await.is_err() {
                break;
            }
            rt_w.metrics.add_sent_frames(
                count,
                count * private_relay_protocol::OUTER_WIRE_FRAME_BYTES as u64,
            );
            if let Ok((tx_ep, _)) = writer.rekey_epochs() {
                if tx_ep > last_tx_epoch {
                    for _ in 0..(tx_ep - last_tx_epoch) {
                        rt_w.metrics.inc_link_rekeys();
                    }
                    last_tx_epoch = tx_ep;
                }
            }
        }
        let _ = writer.shutdown().await;
        let _ = writer_dead_tx.send(true);
    });

    let mut shutdown_r = runtime.shutdown_rx.clone();
    let mut last_rx_epoch = 0u64;
    loop {
        if *shutdown_r.borrow() {
            break;
        }
        tokio::select! {
            _ = shutdown_r.changed() => {
                if *shutdown_r.borrow() {
                    break;
                }
            }
            _ = writer_dead_rx.changed() => {
                if *writer_dead_rx.borrow() {
                    break;
                }
            }
            recv_res = reader.recv_cell_with_timeouts(idle_ttl, io_timeout) => {
                match recv_res {
                    Ok(cell) => {
                        runtime.metrics.inc_cells_processed();
                        runtime.metrics.add_bytes_received(private_relay_protocol::OUTER_WIRE_FRAME_BYTES as u64);
                        if let Ok((_, rx_ep)) = reader.rekey_epochs() {
                            if rx_ep > last_rx_epoch {
                                for _ in 0..(rx_ep - last_rx_epoch) {
                                    runtime.metrics.inc_link_rekeys();
                                }
                                last_rx_epoch = rx_ep;
                            }
                        }
                        dispatch_inbound_cell(
                            &runtime,
                            peer_ip,
                            &up_tx,
                            &routes,
                            cell,
                        ).await;
                    }
                    Err(_) => break,
                }
            }
        }
    }

    let exited_on_shutdown = *shutdown_r.borrow();
    if !exited_on_shutdown {
        notify_routes_disconnected(&routes).await;
    }
    drop(up_tx);
    let _ = timeout(io_timeout.min(Duration::from_secs(2)), writer_handle).await;
}

async fn dispatch_inbound_cell(
    runtime: &Arc<RelayRuntime>,
    peer_ip: IpAddr,
    up_tx: &mpsc::Sender<Cell>,
    routes: &Arc<Mutex<HashMap<CircuitId, mpsc::Sender<Cell>>>>,
    cell: Cell,
) {
    let cid = cell.circuit_id;
    let io_timeout = runtime.io_timeout();

    if cell.command == Command::Create {
        let already_exists = routes.lock().map(|g| g.contains_key(&cid)).unwrap_or(true);
        if already_exists {
            let _ = up_tx
                .send_timeout(Cell::destroy(cid, DestroyReason::ProtocolError), io_timeout)
                .await;
            return;
        }

        let Some(slot_guard) = runtime.try_acquire_circuit_slot(peer_ip) else {
            warn!(
                relay_id = %runtime.config.id,
                role = ?runtime.config.role,
                circuit_id = cid.get(),
                "circuit rejected due to resource capacity limit"
            );
            let _ = up_tx
                .send_timeout(Cell::destroy(cid, DestroyReason::ResourceLimit), io_timeout)
                .await;
            return;
        };

        let responder =
            match HopHandshakeResponder::new(runtime.config.role.hop_index(), &runtime.keypair) {
                Ok(r) => r,
                Err(_) => {
                    let _ = up_tx
                        .send_timeout(Cell::destroy(cid, DestroyReason::CryptoFail), io_timeout)
                        .await;
                    return;
                }
            };
        let (msg2, hop_ciphers) = match responder.process_msg1_and_finish(&cell.body) {
            Ok(pair) => pair,
            Err(_) => {
                runtime.metrics.inc_hop_handshake_failures();
                let _ = up_tx
                    .send_timeout(Cell::destroy(cid, DestroyReason::CryptoFail), io_timeout)
                    .await;
                return;
            }
        };

        let created_cell = match Cell::new(cid, Command::Created, 0, msg2) {
            Ok(c) => c,
            Err(_) => {
                runtime.metrics.inc_hop_handshake_failures();
                let _ = up_tx
                    .send_timeout(Cell::destroy(cid, DestroyReason::ProtocolError), io_timeout)
                    .await;
                return;
            }
        };

        let (c_tx, c_rx) = mpsc::channel(runtime.config.circuit_channel_capacity.max(1));
        {
            let Ok(mut guard) = routes.lock() else {
                return;
            };
            guard.insert(cid, c_tx);
        }

        if up_tx.send_timeout(created_cell, io_timeout).await.is_err() {
            if let Ok(mut guard) = routes.lock() {
                guard.remove(&cid);
            }
            return;
        }
        runtime.metrics.inc_hop_handshakes();

        debug!(
            relay_id = %runtime.config.id,
            role = ?runtime.config.role,
            circuit_id = cid.get(),
            "circuit hop established"
        );

        let rt_circuit = Arc::clone(runtime);
        let circuit_track = TaskTrackGuard::spawn_counted(&rt_circuit);
        let up_tx_circuit = up_tx.clone();
        let routes_circuit = Arc::clone(routes);
        tokio::spawn(async move {
            let _track = circuit_track;
            run_circuit_task(
                rt_circuit,
                cid,
                hop_ciphers,
                up_tx_circuit,
                c_rx,
                routes_circuit,
                slot_guard,
            )
            .await;
        });
        return;
    }

    let target = routes.lock().ok().and_then(|g| g.get(&cid).cloned());
    if let Some(c_tx) = target {
        if c_tx.send_timeout(cell, io_timeout).await.is_err() {
            if let Ok(mut guard) = routes.lock() {
                guard.remove(&cid);
            }
            let _ = up_tx
                .send_timeout(Cell::destroy(cid, DestroyReason::ResourceLimit), io_timeout)
                .await;
        }
    } else if cell.command != Command::Destroy {
        let _ = up_tx
            .send_timeout(Cell::destroy(cid, DestroyReason::ProtocolError), io_timeout)
            .await;
    }
}

struct NextHopBinding {
    link: Arc<OutboundLinkHandle>,
    downstream_cid: CircuitId,
    downstream_rx: mpsc::Receiver<Cell>,
}

async fn run_circuit_task(
    runtime: Arc<RelayRuntime>,
    cid: CircuitId,
    hop_ciphers: HopCipherPair,
    up_tx: mpsc::Sender<Cell>,
    up_rx: mpsc::Receiver<Cell>,
    upstream_routes: Arc<Mutex<HashMap<CircuitId, mpsc::Sender<Cell>>>>,
    _slot_guard: CircuitSlotGuard,
) {
    match runtime.config.role {
        RelayRole::Entry | RelayRole::Middle => {
            run_forwarding_circuit_task(runtime, cid, hop_ciphers, up_tx, up_rx, upstream_routes)
                .await;
        }
        RelayRole::Exit => {
            run_exit_circuit_task(runtime, cid, hop_ciphers, up_tx, up_rx, upstream_routes).await;
        }
    }
}

async fn run_forwarding_circuit_task(
    runtime: Arc<RelayRuntime>,
    cid: CircuitId,
    mut hop_ciphers: HopCipherPair,
    up_tx: mpsc::Sender<Cell>,
    mut up_rx: mpsc::Receiver<Cell>,
    upstream_routes: Arc<Mutex<HashMap<CircuitId, mpsc::Sender<Cell>>>>,
) {
    let io_timeout = runtime.io_timeout();
    let idle_ttl = runtime.idle_ttl();
    let mut state = CircuitState::Building;
    let mut next_hop: Option<NextHopBinding> = None;
    let mut destroy_reason = DestroyReason::Normal;
    let mut notify_upstream_destroy = false;
    let mut notify_downstream_destroy = false;
    let mut shutdown_rx = runtime.shutdown_rx.clone();

    let idle_sleep = sleep(idle_ttl);
    tokio::pin!(idle_sleep);

    loop {
        if *shutdown_rx.borrow() {
            destroy_reason = DestroyReason::Normal;
            notify_upstream_destroy = true;
            notify_downstream_destroy = next_hop.is_some();
            break;
        }
        if let Some(binding) = next_hop.as_mut() {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        destroy_reason = DestroyReason::Normal;
                        notify_upstream_destroy = true;
                        notify_downstream_destroy = true;
                        break;
                    }
                }
                _ = &mut idle_sleep => {
                    destroy_reason = DestroyReason::IdleTimeout;
                    notify_upstream_destroy = true;
                    notify_downstream_destroy = true;
                    break;
                }
                maybe_up = up_rx.recv() => {
                    idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_ttl);
                    match maybe_up {
                        Some(cell) => {
                            if cell.command == Command::Destroy {
                                destroy_reason = cell.destroy_reason().unwrap_or(DestroyReason::Normal);
                                notify_downstream_destroy = true;
                                break;
                            }
                            if let Err(r) = handle_forwarding_upstream_cell(
                                &runtime,
                                &mut state,
                                &mut hop_ciphers,
                                binding,
                                cell,
                            ).await {
                                destroy_reason = r;
                                notify_upstream_destroy = true;
                                notify_downstream_destroy = true;
                                break;
                            }
                        }
                        None => {
                            destroy_reason = DestroyReason::PeerDisconnected;
                            notify_downstream_destroy = true;
                            break;
                        }
                    }
                }
                maybe_down = binding.downstream_rx.recv() => {
                    idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_ttl);
                    match maybe_down {
                        Some(cell) => {
                            if cell.command == Command::Destroy {
                                destroy_reason = cell.destroy_reason().unwrap_or(DestroyReason::PeerDisconnected);
                                notify_upstream_destroy = true;
                                break;
                            }
                            match handle_forwarding_downstream_cell(
                                &runtime,
                                cid,
                                &mut state,
                                &mut hop_ciphers,
                                cell,
                            ) {
                                Ok(sealed_cell) => {
                                    if up_tx.send_timeout(sealed_cell, io_timeout).await.is_err() {
                                        destroy_reason = DestroyReason::PeerDisconnected;
                                        notify_downstream_destroy = true;
                                        break;
                                    }
                                }
                                Err(r) => {
                                    destroy_reason = r;
                                    notify_upstream_destroy = true;
                                    notify_downstream_destroy = true;
                                    break;
                                }
                            }
                        }
                        None => {
                            destroy_reason = DestroyReason::PeerDisconnected;
                            notify_upstream_destroy = true;
                            break;
                        }
                    }
                }
            }
        } else {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        destroy_reason = DestroyReason::Normal;
                        notify_upstream_destroy = true;
                        break;
                    }
                }
                _ = &mut idle_sleep => {
                    destroy_reason = DestroyReason::IdleTimeout;
                    notify_upstream_destroy = true;
                    break;
                }
                maybe_up = up_rx.recv() => {
                    idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_ttl);
                    match maybe_up {
                        Some(cell) => {
                            if cell.command == Command::Destroy {
                                break;
                            }
                            if cell.command != Command::Extend {
                                destroy_reason = DestroyReason::ProtocolError;
                                notify_upstream_destroy = true;
                                break;
                            }
                            let dir = match decode_extend_directive(
                                &runtime,
                                &mut hop_ciphers,
                                &cell.body,
                            ) {
                                Ok(dir) => dir,
                                Err(r) => {
                                    destroy_reason = r;
                                    notify_upstream_destroy = true;
                                    break;
                                }
                            };

                            let dial_fut = dial_and_create_downstream(&runtime, dir);
                            tokio::pin!(dial_fut);

                            enum DialWaitOutcome {
                                Ready(Result<(NextHopBinding, Vec<u8>), DestroyReason>),
                                Shutdown,
                                UpstreamAborted(DestroyReason, bool),
                            }

                            let outcome = loop {
                                tokio::select! {
                                    res = &mut dial_fut => {
                                        break DialWaitOutcome::Ready(res);
                                    }
                                    _ = shutdown_rx.changed() => {
                                        if *shutdown_rx.borrow() {
                                            break DialWaitOutcome::Shutdown;
                                        }
                                    }
                                    abort_up = up_rx.recv() => {
                                        match abort_up {
                                            Some(c) if c.command == Command::Destroy => {
                                                let r = c.destroy_reason().unwrap_or(DestroyReason::Normal);
                                                break DialWaitOutcome::UpstreamAborted(r, false);
                                            }
                                            Some(_) => {
                                                break DialWaitOutcome::UpstreamAborted(DestroyReason::ProtocolError, true);
                                            }
                                            None => {
                                                break DialWaitOutcome::UpstreamAborted(DestroyReason::PeerDisconnected, false);
                                            }
                                        }
                                    }
                                }
                            };

                            match outcome {
                                DialWaitOutcome::Ready(Ok((binding, created_body))) => {
                                    let ext_cell = match seal_extended_response(
                                        cid,
                                        &mut hop_ciphers,
                                        created_body,
                                    ) {
                                        Ok(c) => c,
                                        Err(r) => {
                                            binding.link.unregister_circuit(binding.downstream_cid);
                                            let _ = binding
                                                .link
                                                .send(Cell::destroy(binding.downstream_cid, r), io_timeout)
                                                .await;
                                            destroy_reason = r;
                                            notify_upstream_destroy = true;
                                            break;
                                        }
                                    };
                                    // Middle extends directly to Exit (`Open`); Entry extends to Middle (stays `Building` until Hop 3 `Extended`).
                                    if runtime.config.role == RelayRole::Middle {
                                        let _ = state.mark_open();
                                    }
                                    if up_tx.send_timeout(ext_cell, io_timeout).await.is_err() {
                                        binding.link.unregister_circuit(binding.downstream_cid);
                                        let _ = binding
                                            .link
                                            .send(Cell::destroy(binding.downstream_cid, DestroyReason::PeerDisconnected), io_timeout)
                                            .await;
                                        break;
                                    }
                                    next_hop = Some(binding);
                                }
                                DialWaitOutcome::Ready(Err(r)) => {
                                    destroy_reason = r;
                                    notify_upstream_destroy = true;
                                    break;
                                }
                                DialWaitOutcome::Shutdown => {
                                    destroy_reason = DestroyReason::Normal;
                                    notify_upstream_destroy = true;
                                    break;
                                }
                                DialWaitOutcome::UpstreamAborted(r, notify) => {
                                    destroy_reason = r;
                                    notify_upstream_destroy = notify;
                                    break;
                                }
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    }

    let _ = state.destroy(destroy_reason);
    if let Ok(mut guard) = upstream_routes.lock() {
        guard.remove(&cid);
    }
    if notify_upstream_destroy {
        let _ = up_tx
            .send_timeout(Cell::destroy(cid, destroy_reason), io_timeout)
            .await;
    }
    if let Some(binding) = next_hop.take() {
        binding.link.unregister_circuit(binding.downstream_cid);
        if notify_downstream_destroy {
            let _ = binding
                .link
                .send(
                    Cell::destroy(binding.downstream_cid, destroy_reason),
                    io_timeout,
                )
                .await;
        }
    }
    debug!(
        relay_id = %runtime.config.id,
        role = ?runtime.config.role,
        circuit_id = cid.get(),
        reason = ?destroy_reason,
        "forwarding circuit terminated"
    );
}

struct PendingDownstreamGuard {
    link: Arc<OutboundLinkHandle>,
    cid: CircuitId,
    armed: bool,
}

impl Drop for PendingDownstreamGuard {
    fn drop(&mut self) {
        if self.armed {
            self.link.unregister_circuit(self.cid);
        }
    }
}

fn decode_extend_directive(
    runtime: &Arc<RelayRuntime>,
    hop_ciphers: &mut HopCipherPair,
    sealed_body: &[u8],
) -> Result<ExtendDirective, DestroyReason> {
    let pt = Zeroizing::new(
        hop_ciphers
            .forward
            .open(sealed_body)
            .map_err(|_| DestroyReason::CryptoFail)?,
    );
    let decoded = RelayHopPlaintext::decode(&pt).map_err(|_| DestroyReason::ProtocolError)?;

    let dir = match decoded {
        RelayHopPlaintext::Extend(dir) => dir,
        _ => return Err(DestroyReason::ProtocolError),
    };

    runtime.authorize_next_peer(&dir.next_hop_addr, &dir.next_hop_pub)?;
    Ok(dir)
}

async fn dial_and_create_downstream(
    runtime: &Arc<RelayRuntime>,
    dir: ExtendDirective,
) -> Result<(NextHopBinding, Vec<u8>), DestroyReason> {
    let link = runtime
        .get_or_connect_outbound(&dir.next_hop_addr, dir.next_hop_pub)
        .await?;
    let (downstream_cid, mut downstream_rx) =
        link.register_circuit(runtime.config.circuit_channel_capacity.max(1))?;

    let mut reg_guard = PendingDownstreamGuard {
        link: Arc::clone(&link),
        cid: downstream_cid,
        armed: true,
    };

    let create_cell = Cell::new(downstream_cid, Command::Create, 0, dir.handshake_msg1)
        .map_err(|_| DestroyReason::ProtocolError)?;
    if link.send(create_cell, runtime.io_timeout()).await.is_err() {
        runtime.metrics.inc_hop_handshake_failures();
        return Err(DestroyReason::PeerDisconnected);
    }

    let created = match timeout(runtime.handshake_timeout(), downstream_rx.recv()).await {
        Ok(Some(cell)) => cell,
        Ok(None) => {
            runtime.metrics.inc_hop_handshake_failures();
            return Err(DestroyReason::PeerDisconnected);
        }
        Err(_) => {
            runtime.metrics.inc_hop_handshake_failures();
            let _ = link
                .send(
                    Cell::destroy(downstream_cid, DestroyReason::HandshakeTimeout),
                    runtime.io_timeout(),
                )
                .await;
            return Err(DestroyReason::HandshakeTimeout);
        }
    };

    match created.command {
        Command::Created => {}
        Command::Destroy => {
            runtime.metrics.inc_hop_handshake_failures();
            return Err(created
                .destroy_reason()
                .unwrap_or(DestroyReason::PeerDisconnected));
        }
        _ => {
            runtime.metrics.inc_hop_handshake_failures();
            return Err(DestroyReason::ProtocolError);
        }
    }

    runtime.metrics.inc_hop_handshakes();

    reg_guard.armed = false;
    Ok((
        NextHopBinding {
            link,
            downstream_cid,
            downstream_rx,
        },
        created.body,
    ))
}

fn seal_extended_response(
    cid: CircuitId,
    hop_ciphers: &mut HopCipherPair,
    created_body: Vec<u8>,
) -> Result<Cell, DestroyReason> {
    let ext_pt = Zeroizing::new(
        RelayHopPlaintext::Extended(created_body)
            .encode()
            .map_err(|_| DestroyReason::ProtocolError)?,
    );
    let sealed_ext = hop_ciphers
        .backward
        .seal(&ext_pt)
        .map_err(|_| DestroyReason::CryptoFail)?;
    Cell::new(cid, Command::Extended, 0, sealed_ext).map_err(|_| DestroyReason::ProtocolError)
}

async fn handle_forwarding_upstream_cell(
    runtime: &Arc<RelayRuntime>,
    state: &mut CircuitState,
    hop_ciphers: &mut HopCipherPair,
    binding: &NextHopBinding,
    cell: Cell,
) -> Result<(), DestroyReason> {
    let out_cmd = match cell.command {
        Command::Extend => {
            // Only Entry relays forward Hop 3 `Extend` directives toward Middle (`state == Building`).
            if runtime.config.role != RelayRole::Entry || *state != CircuitState::Building {
                return Err(DestroyReason::ProtocolError);
            }
            Command::Extend
        }
        Command::RelayData => {
            if !state.can_forward_data() {
                return Err(DestroyReason::ProtocolError);
            }
            Command::RelayData
        }
        _ => return Err(DestroyReason::ProtocolError),
    };

    let pt = Zeroizing::new(
        hop_ciphers
            .forward
            .open(&cell.body)
            .map_err(|_| DestroyReason::CryptoFail)?,
    );
    let decoded = RelayHopPlaintext::decode(&pt).map_err(|_| DestroyReason::ProtocolError)?;
    let next_body = match decoded {
        RelayHopPlaintext::Forward(inner) => inner,
        // Entry and Middle NEVER act as Exit (`Message`) or accept double `Extend` (`Extend`).
        _ => return Err(DestroyReason::ProtocolError),
    };

    let out_cell = Cell::new(binding.downstream_cid, out_cmd, 0, next_body)
        .map_err(|_| DestroyReason::ProtocolError)?;
    binding.link.send(out_cell, runtime.io_timeout()).await
}

fn handle_forwarding_downstream_cell(
    runtime: &Arc<RelayRuntime>,
    cid: CircuitId,
    state: &mut CircuitState,
    hop_ciphers: &mut HopCipherPair,
    cell: Cell,
) -> Result<Cell, DestroyReason> {
    let out_cmd = match cell.command {
        Command::Extended => {
            // Entry completes 3-hop building as soon as Hop 3 `Extended` flows back from Middle.
            if runtime.config.role == RelayRole::Entry && *state == CircuitState::Building {
                state
                    .mark_open()
                    .map_err(|_| DestroyReason::ProtocolError)?;
            } else {
                return Err(DestroyReason::ProtocolError);
            }
            Command::Extended
        }
        Command::RelayData => {
            if !state.can_forward_data() {
                return Err(DestroyReason::ProtocolError);
            }
            Command::RelayData
        }
        _ => return Err(DestroyReason::ProtocolError),
    };

    let wrapped = hop_ciphers
        .backward
        .seal(&cell.body)
        .map_err(|_| DestroyReason::CryptoFail)?;
    Cell::new(cid, out_cmd, 0, wrapped).map_err(|_| DestroyReason::ProtocolError)
}

async fn run_exit_circuit_task(
    runtime: Arc<RelayRuntime>,
    cid: CircuitId,
    mut hop_ciphers: HopCipherPair,
    up_tx: mpsc::Sender<Cell>,
    mut up_rx: mpsc::Receiver<Cell>,
    upstream_routes: Arc<Mutex<HashMap<CircuitId, mpsc::Sender<Cell>>>>,
) {
    use private_relay_protocol::RequestErrorCode;

    let io_timeout = runtime.io_timeout();
    let dest_timeout = runtime.dest_io_timeout();
    let idle_ttl = runtime.idle_ttl();

    let mut state = CircuitState::Building;
    let _ = state.mark_open();

    let mut reassembler: Option<MessageReassembler> = None;
    let mut used_request_ids: HashSet<u32> = HashSet::new();
    let mut used_request_order: VecDeque<u32> = VecDeque::new();
    let mut active_dest_task: Option<(
        private_relay_protocol::RequestId,
        Instant,
        PendingDestResponse,
    )> = None;
    let destroy_reason;
    let mut notify_upstream_destroy = false;
    let mut shutdown_rx = runtime.shutdown_rx.clone();

    let idle_sleep = sleep(idle_ttl);
    tokio::pin!(idle_sleep);

    loop {
        if *shutdown_rx.borrow() {
            destroy_reason = DestroyReason::Normal;
            notify_upstream_destroy = true;
            break;
        }
        if let Some((active_rid, req_started, resp_rx)) = active_dest_task.as_mut() {
            let rid = *active_rid;
            let started = *req_started;
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        destroy_reason = DestroyReason::Normal;
                        notify_upstream_destroy = true;
                        break;
                    }
                }
                _ = &mut idle_sleep => {
                    destroy_reason = DestroyReason::IdleTimeout;
                    notify_upstream_destroy = true;
                    break;
                }
                res = resp_rx => {
                    active_dest_task = None;
                    runtime.metrics.observe_request_duration(started.elapsed());
                    let result = res.unwrap_or(Err(RequestErrorCode::InternalError));
                    match &result {
                        Ok(_) => runtime.metrics.inc_requests_success(),
                        Err(code) => {
                            runtime.metrics.inc_requests_failed();
                            match code {
                                RequestErrorCode::PolicyDenied => runtime.metrics.inc_ssrf_denied(),
                                RequestErrorCode::Timeout => runtime.metrics.inc_timeouts(),
                                RequestErrorCode::PayloadTooLarge => runtime.metrics.inc_payload_too_large(),
                                RequestErrorCode::ConnectFailed | RequestErrorCode::DnsFailed => {
                                    runtime.metrics.inc_destination_connect_failures();
                                }
                                _ => runtime.metrics.inc_protocol_violations(),
                            }
                        }
                    }
                    if send_exit_response(&up_tx, cid, rid, &mut hop_ciphers, result, io_timeout)
                        .await
                        .is_err()
                    {
                        destroy_reason = DestroyReason::PeerDisconnected;
                        notify_upstream_destroy = true;
                        break;
                    }
                    idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_ttl);
                }
                maybe_up = up_rx.recv() => {
                    match maybe_up {
                        Some(cell) if cell.command == Command::Destroy => {
                            destroy_reason = cell.destroy_reason().unwrap_or(DestroyReason::Normal);
                            break;
                        }
                        Some(_) => {
                            // Overlapping requests while Exit is executing are protocol violations in v0.1 (`D-01`).
                            destroy_reason = DestroyReason::ProtocolError;
                            notify_upstream_destroy = true;
                            break;
                        }
                        None => {
                            destroy_reason = DestroyReason::PeerDisconnected;
                            break;
                        }
                    }
                }
            }
        } else {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        destroy_reason = DestroyReason::Normal;
                        notify_upstream_destroy = true;
                        break;
                    }
                }
                _ = &mut idle_sleep => {
                    destroy_reason = DestroyReason::IdleTimeout;
                    notify_upstream_destroy = true;
                    break;
                }
                maybe_up = up_rx.recv() => {
                    idle_sleep.as_mut().reset(tokio::time::Instant::now() + idle_ttl);
                    match maybe_up {
                        Some(cell) => {
                            if cell.command == Command::Destroy {
                                destroy_reason = cell.destroy_reason().unwrap_or(DestroyReason::Normal);
                                break;
                            }
                            if cell.command != Command::RelayData || !state.can_forward_data() {
                                destroy_reason = DestroyReason::ProtocolError;
                                notify_upstream_destroy = true;
                                break;
                            }
                            let pt = match hop_ciphers.forward.open(&cell.body) {
                                Ok(v) => Zeroizing::new(v),
                                Err(_) => {
                                    destroy_reason = DestroyReason::CryptoFail;
                                    notify_upstream_destroy = true;
                                    break;
                                }
                            };
                            let inner_bytes = match RelayHopPlaintext::decode(&pt) {
                                Ok(RelayHopPlaintext::Message(bytes)) => Zeroizing::new(bytes),
                                _ => {
                                    destroy_reason = DestroyReason::ProtocolError;
                                    notify_upstream_destroy = true;
                                    break;
                                }
                            };
                            drop(pt);
                            let chunk = match InnerPayload::decode(&inner_bytes) {
                                Ok(c) => c,
                                Err(_) => {
                                    destroy_reason = DestroyReason::ProtocolError;
                                    notify_upstream_destroy = true;
                                    break;
                                }
                            };
                            drop(inner_bytes);
                            if chunk.flags.is_error() {
                                destroy_reason = DestroyReason::ProtocolError;
                                notify_upstream_destroy = true;
                                break;
                            }

                            let rid = chunk.request_id;
                            let reasm = match reassembler.as_mut() {
                                Some(existing) => {
                                    if existing.request_id() != rid {
                                        destroy_reason = DestroyReason::ProtocolError;
                                        notify_upstream_destroy = true;
                                        break;
                                    }
                                    existing
                                }
                                None => {
                                    if used_request_ids.contains(&rid.get()) {
                                        destroy_reason = DestroyReason::ProtocolError;
                                        notify_upstream_destroy = true;
                                        break;
                                    }
                                    reassembler.insert(MessageReassembler::for_request(rid))
                                }
                            };

                            match reasm.push(chunk) {
                                Ok(None) => {}
                                Ok(Some(ReassembledMessage::Data(raw_req))) => {
                                    let raw_req = Zeroizing::new(raw_req);
                                    reassembler = None;
                                    if used_request_order.len() >= 4096 {
                                        if let Some(oldest) = used_request_order.pop_front() {
                                            used_request_ids.remove(&oldest);
                                        }
                                    }
                                    if used_request_ids.insert(rid.get()) {
                                        used_request_order.push_back(rid.get());
                                    }

                                    match DecodedRequest::parse(&raw_req) {
                                        Ok(decoded_req) => {
                                            let (tx, rx) = oneshot::channel();
                                            let policy = runtime.dest_policy.clone();
                                            let dest_track = TaskTrackGuard::spawn_counted(&runtime);
                                            let mut sd_dest = runtime.shutdown_rx.clone();
                                            tokio::spawn(async move {
                                                let _track = dest_track;
                                                let exec_fut = execute_destination_request(
                                                    &policy,
                                                    decoded_req,
                                                    dest_timeout,
                                                );
                                                tokio::pin!(exec_fut);
                                                let outcome = tokio::select! {
                                                    _ = sd_dest.changed() => {
                                                        if *sd_dest.borrow() {
                                                            Err(RequestErrorCode::InternalError)
                                                        } else {
                                                            exec_fut.await
                                                        }
                                                    }
                                                    res = &mut exec_fut => res,
                                                };
                                                let _ = tx.send(outcome);
                                            });
                                            runtime.metrics.inc_requests();
                                            active_dest_task = Some((rid, Instant::now(), rx));
                                        }
                                        Err(e) => {
                                            let code = match e {
                                                private_relay_protocol::ProtocolError::PayloadTooLarge { .. } => {
                                                    runtime.metrics.inc_payload_too_large();
                                                    RequestErrorCode::PayloadTooLarge
                                                }
                                                _ => {
                                                    runtime.metrics.inc_protocol_violations();
                                                    RequestErrorCode::ProtocolViolation
                                                }
                                            };
                                            runtime.metrics.inc_requests_failed();
                                            if send_exit_response(&up_tx, cid, rid, &mut hop_ciphers, Err(code), io_timeout).await.is_err() {
                                                destroy_reason = DestroyReason::PeerDisconnected;
                                                notify_upstream_destroy = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                                Ok(Some(ReassembledMessage::Error(_))) => {
                                    destroy_reason = DestroyReason::ProtocolError;
                                    notify_upstream_destroy = true;
                                    break;
                                }
                                Err(_) => {
                                    destroy_reason = DestroyReason::ProtocolError;
                                    notify_upstream_destroy = true;
                                    break;
                                }
                            }
                        }
                        None => {
                            destroy_reason = DestroyReason::PeerDisconnected;
                            break;
                        }
                    }
                }
            }
        }
    }

    let _ = state.destroy(destroy_reason);
    if let Ok(mut guard) = upstream_routes.lock() {
        guard.remove(&cid);
    }
    if notify_upstream_destroy {
        let _ = up_tx
            .send_timeout(Cell::destroy(cid, destroy_reason), io_timeout)
            .await;
    }
    debug!(
        relay_id = %runtime.config.id,
        role = ?runtime.config.role,
        circuit_id = cid.get(),
        reason = ?destroy_reason,
        "exit circuit terminated"
    );
}

async fn send_exit_response(
    up_tx: &mpsc::Sender<Cell>,
    cid: CircuitId,
    rid: private_relay_protocol::RequestId,
    hop_ciphers: &mut HopCipherPair,
    result: Result<Vec<u8>, private_relay_protocol::RequestErrorCode>,
    io_timeout: Duration,
) -> Result<(), DestroyReason> {
    let chunks = match result {
        Ok(body) => {
            let body = Zeroizing::new(body);
            chunk_response(rid, &body).map_err(|_| DestroyReason::ProtocolError)?
        }
        Err(code) => vec![encode_error_payload(rid, code)],
    };

    for chunk in chunks {
        let encoded_inner =
            Zeroizing::new(chunk.encode().map_err(|_| DestroyReason::ProtocolError)?);
        let pt = Zeroizing::new(
            RelayHopPlaintext::Message(encoded_inner.to_vec())
                .encode()
                .map_err(|_| DestroyReason::ProtocolError)?,
        );
        drop(encoded_inner);
        let sealed = hop_ciphers
            .backward
            .seal(&pt)
            .map_err(|_| DestroyReason::CryptoFail)?;
        drop(pt);
        let cell = Cell::new(cid, Command::RelayData, 0, sealed)
            .map_err(|_| DestroyReason::ProtocolError)?;
        up_tx
            .send_timeout(cell, io_timeout)
            .await
            .map_err(|_| DestroyReason::PeerDisconnected)?;
    }

    Ok(())
}

async fn execute_destination_request(
    policy: &DestinationPolicy,
    req: DecodedRequest,
    dest_timeout: Duration,
) -> Result<Vec<u8>, private_relay_protocol::RequestErrorCode> {
    use private_relay_protocol::RequestErrorCode;

    let exec_future = async {
        let validated_addr = policy
            .resolve_and_validate(&req.target_host_port)
            .await
            .map_err(|err| match err {
                NetworkError::PolicyDenied(_) => RequestErrorCode::PolicyDenied,
                NetworkError::DnsResolutionFailed => RequestErrorCode::DnsFailed,
                _ => RequestErrorCode::InternalError,
            })?;

        let mut stream = TcpStream::connect(validated_addr)
            .await
            .map_err(|_| RequestErrorCode::ConnectFailed)?;

        stream
            .write_all(&req.body)
            .await
            .map_err(|_| RequestErrorCode::ConnectFailed)?;
        stream
            .flush()
            .await
            .map_err(|_| RequestErrorCode::ConnectFailed)?;
        let _ = stream.shutdown().await;

        let mut resp = Vec::with_capacity(4096);
        let mut chunk = [0u8; 16_384];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|_| RequestErrorCode::ConnectFailed)?;
            if n == 0 {
                break;
            }
            if resp.len().saturating_add(n) > MAX_MESSAGE_BYTES {
                return Err(RequestErrorCode::PayloadTooLarge);
            }
            resp.extend_from_slice(&chunk[..n]);
        }
        Ok(resp)
    };

    match timeout(dest_timeout, exec_future).await {
        Ok(res) => res,
        Err(_) => Err(RequestErrorCode::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use private_relay_network::accept_noise_link;

    #[tokio::test]
    async fn outbound_link_demuxer_evicts_full_circuit_without_breaking_sibling() {
        let kp_local = StaticKeypair::generate().unwrap();
        let kp_remote = StaticKeypair::generate().unwrap();
        let mut cfg = RelayConfig::with_generated_keypair(
            "mid-unit",
            RelayRole::Middle,
            "127.0.0.1:0",
            &kp_local,
        );
        cfg.io_timeout_ms = 80;
        let (_sd_tx, sd_rx) = watch::channel(false);
        let runtime = Arc::new(RelayRuntime {
            dest_policy: DestinationPolicy::default(),
            conn_semaphore: Arc::new(Semaphore::new(cfg.max_concurrent_connections)),
            config: cfg,
            keypair: kp_local.clone(),
            active_circuits: AtomicUsize::new(0),
            active_tasks: AtomicUsize::new(0),
            drain_notify: Notify::new(),
            per_ip_circuits: Mutex::new(HashMap::new()),
            outbound_links: AsyncMutex::new(HashMap::new()),
            dial_locks: Mutex::new(HashMap::new()),
            shutdown_rx: sd_rx,
            metrics: Arc::new(RelayMetrics::new()),
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let kp_r = kp_remote.clone();
        let peer_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            accept_noise_link(stream, &kp_r, Duration::from_secs(2))
                .await
                .unwrap()
        });

        let (lr, lw) = connect_noise_link_with_rekey(
            &addr,
            &kp_local,
            *kp_remote.public(),
            Duration::from_secs(2),
            runtime.config.link_rekey_policy(),
        )
        .await
        .unwrap();
        let (mut pr, mut pw, _) = peer_task.await.unwrap();

        let link =
            OutboundLinkHandle::spawn(Arc::clone(&runtime), (addr, *kp_remote.public()), lr, lw);

        // Register cid1 with cap=1 and prefill it so next downstream cell hits TrySendError::Full.
        let (cid1, _rx1) = link.register_circuit(1).unwrap();
        let (cid2, mut rx2) = link.register_circuit(4).unwrap();
        {
            let guard = link.routes.lock().unwrap();
            guard
                .get(&cid1)
                .unwrap()
                .try_send(Cell::new(cid1, Command::RelayData, 0, vec![1; 4]).unwrap())
                .unwrap();
        }

        // Peer sends downstream cell to full cid1, then valid cell to sibling cid2.
        pw.send_cell(
            &Cell::new(cid1, Command::RelayData, 0, vec![2; 4]).unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        pw.send_cell(
            &Cell::new(cid2, Command::RelayData, 0, vec![9; 4]).unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

        // Peer must receive DESTROY(ResourceLimit) specifically for cid1, while sibling cid2 gets its cell intact.
        let destroy_c1 = pr.recv_cell(Duration::from_secs(2)).await.unwrap();
        assert_eq!(destroy_c1.circuit_id, cid1);
        assert_eq!(destroy_c1.command, Command::Destroy);
        assert_eq!(
            destroy_c1.destroy_reason().unwrap(),
            DestroyReason::ResourceLimit
        );

        let got_c2 = rx2.recv().await.unwrap();
        assert_eq!(got_c2.circuit_id, cid2);
        assert_eq!(got_c2.body, vec![9; 4]);
        assert!(link.is_alive());
    }
}
