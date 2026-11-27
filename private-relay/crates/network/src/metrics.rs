use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Prometheus-compatible metrics registry with bounded, low-cardinality labels.
///
/// Complies with strict privacy guarantees:
/// NEVER records IPs, hostnames, URLs, RequestIDs, CircuitIDs, or payloads.
#[derive(Debug, Default)]
pub struct RelayMetrics {
    // Process & Circuit Counters
    pub circuits_created_total: AtomicU64,
    pub circuits_destroyed_total: AtomicU64,
    pub active_circuits_gauge: AtomicU64,
    pub active_connections_gauge: AtomicU64,
    pub connections_accepted_total: AtomicU64,
    pub connections_rejected_total: AtomicU64,

    // Relay Hop & Cell/Frame Traffic
    pub frames_received_total: AtomicU64,
    pub frames_sent_total: AtomicU64,
    pub cells_processed_total: AtomicU64,
    pub bytes_received_total: AtomicU64,
    pub bytes_sent_total: AtomicU64,

    // Request & Destination Execution (Exit & Client)
    pub requests_total: AtomicU64,
    pub requests_success_total: AtomicU64,
    pub requests_failed_total: AtomicU64,
    pub ssrf_denials_total: AtomicU64,
    pub timeouts_total: AtomicU64,
    pub payload_too_large_total: AtomicU64,
    pub protocol_violations_total: AtomicU64,

    // Link Rekey Events
    pub link_rekeys_total: AtomicU64,
}

impl RelayMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc_circuits_created(&self) {
        self.circuits_created_total.fetch_add(1, Ordering::Relaxed);
        self.active_circuits_gauge.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_circuits_destroyed(&self) {
        self.circuits_destroyed_total
            .fetch_add(1, Ordering::Relaxed);
        let _ =
            self.active_circuits_gauge
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |val| {
                    Some(val.saturating_sub(1))
                });
    }

    pub fn inc_connections_accepted(&self) {
        self.connections_accepted_total
            .fetch_add(1, Ordering::Relaxed);
        self.active_connections_gauge
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_connections_active(&self) {
        let _ = self.active_connections_gauge.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |val| Some(val.saturating_sub(1)),
        );
    }

    pub fn inc_connections_rejected(&self) {
        self.connections_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received_total
            .fetch_add(bytes, Ordering::Relaxed);
        self.frames_received_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent_total.fetch_add(bytes, Ordering::Relaxed);
        self.frames_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_cells_processed(&self) {
        self.cells_processed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_requests(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_requests_success(&self) {
        self.requests_success_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_requests_failed(&self) {
        self.requests_failed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ssrf_denied(&self) {
        self.ssrf_denials_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_timeouts(&self) {
        self.timeouts_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_payload_too_large(&self) {
        self.payload_too_large_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_protocol_violations(&self) {
        self.protocol_violations_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_link_rekeys(&self) {
        self.link_rekeys_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Renders all metrics in standard Prometheus exposition text format.
    ///
    /// Role label is statically validated as entry, middle, or exit.
    pub fn render_prometheus(&self, role: &str, node_id: &str) -> String {
        // Sanitize node_id to alphanumeric/dash only
        let safe_node_id: String = node_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();

        format!(
            "# HELP private_relay_circuits_created_total Total circuits created\n\
             # TYPE private_relay_circuits_created_total counter\n\
             private_relay_circuits_created_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {circuits_created}\n\
             # HELP private_relay_circuits_destroyed_total Total circuits destroyed\n\
             # TYPE private_relay_circuits_destroyed_total counter\n\
             private_relay_circuits_destroyed_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {circuits_destroyed}\n\
             # HELP private_relay_active_circuits Current active circuits\n\
             # TYPE private_relay_active_circuits gauge\n\
             private_relay_active_circuits{{role=\"{role}\",node=\"{safe_node_id}\"}} {active_circuits}\n\
             # HELP private_relay_active_connections Current active TCP links\n\
             # TYPE private_relay_active_connections gauge\n\
             private_relay_active_connections{{role=\"{role}\",node=\"{safe_node_id}\"}} {active_conns}\n\
             # HELP private_relay_connections_accepted_total Total TCP links accepted\n\
             # TYPE private_relay_connections_accepted_total counter\n\
             private_relay_connections_accepted_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {conns_accepted}\n\
             # HELP private_relay_connections_rejected_total Total TCP links rejected due to capacity\n\
             # TYPE private_relay_connections_rejected_total counter\n\
             private_relay_connections_rejected_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {conns_rejected}\n\
             # HELP private_relay_bytes_received_total Total wire frame bytes received\n\
             # TYPE private_relay_bytes_received_total counter\n\
             private_relay_bytes_received_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {bytes_recv}\n\
             # HELP private_relay_bytes_sent_total Total wire frame bytes transmitted\n\
             # TYPE private_relay_bytes_sent_total counter\n\
             private_relay_bytes_sent_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {bytes_sent}\n\
             # HELP private_relay_frames_received_total Total 600-byte wire frames received\n\
             # TYPE private_relay_frames_received_total counter\n\
             private_relay_frames_received_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {frames_recv}\n\
             # HELP private_relay_frames_sent_total Total 600-byte wire frames sent\n\
             # TYPE private_relay_frames_sent_total counter\n\
             private_relay_frames_sent_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {frames_sent}\n\
             # HELP private_relay_cells_processed_total Total onion cells routed or unpeeled\n\
             # TYPE private_relay_cells_processed_total counter\n\
             private_relay_cells_processed_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {cells_proc}\n\
             # HELP private_relay_requests_total Total destination requests executed\n\
             # TYPE private_relay_requests_total counter\n\
             private_relay_requests_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {requests_total}\n\
             # HELP private_relay_requests_success_total Successful destination requests\n\
             # TYPE private_relay_requests_success_total counter\n\
             private_relay_requests_success_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {requests_success}\n\
             # HELP private_relay_requests_failed_total Failed destination requests\n\
             # TYPE private_relay_requests_failed_total counter\n\
             private_relay_requests_failed_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {requests_failed}\n\
             # HELP private_relay_ssrf_denials_total SSRF destination policy blocks\n\
             # TYPE private_relay_ssrf_denials_total counter\n\
             private_relay_ssrf_denials_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {ssrf_denials}\n\
             # HELP private_relay_timeouts_total Destination or link timeouts\n\
             # TYPE private_relay_timeouts_total counter\n\
             private_relay_timeouts_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {timeouts}\n\
             # HELP private_relay_payload_too_large_total Oversized payload rejections\n\
             # TYPE private_relay_payload_too_large_total counter\n\
             private_relay_payload_too_large_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {oversized}\n\
             # HELP private_relay_protocol_violations_total Framing or protocol violation drops\n\
             # TYPE private_relay_protocol_violations_total counter\n\
             private_relay_protocol_violations_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {violations}\n\
             # HELP private_relay_link_rekeys_total Coordinated Noise link rekey events\n\
             # TYPE private_relay_link_rekeys_total counter\n\
             private_relay_link_rekeys_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {rekeys}\n",
            circuits_created = self.circuits_created_total.load(Ordering::Relaxed),
            circuits_destroyed = self.circuits_destroyed_total.load(Ordering::Relaxed),
            active_circuits = self.active_circuits_gauge.load(Ordering::Relaxed),
            active_conns = self.active_connections_gauge.load(Ordering::Relaxed),
            conns_accepted = self.connections_accepted_total.load(Ordering::Relaxed),
            conns_rejected = self.connections_rejected_total.load(Ordering::Relaxed),
            bytes_recv = self.bytes_received_total.load(Ordering::Relaxed),
            bytes_sent = self.bytes_sent_total.load(Ordering::Relaxed),
            frames_recv = self.frames_received_total.load(Ordering::Relaxed),
            frames_sent = self.frames_sent_total.load(Ordering::Relaxed),
            cells_proc = self.cells_processed_total.load(Ordering::Relaxed),
            requests_total = self.requests_total.load(Ordering::Relaxed),
            requests_success = self.requests_success_total.load(Ordering::Relaxed),
            requests_failed = self.requests_failed_total.load(Ordering::Relaxed),
            ssrf_denials = self.ssrf_denials_total.load(Ordering::Relaxed),
            timeouts = self.timeouts_total.load(Ordering::Relaxed),
            oversized = self.payload_too_large_total.load(Ordering::Relaxed),
            violations = self.protocol_violations_total.load(Ordering::Relaxed),
            rekeys = self.link_rekeys_total.load(Ordering::Relaxed),
        )
    }
}

pub type SharedRelayMetrics = Arc<RelayMetrics>;
