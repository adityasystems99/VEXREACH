use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const LATENCY_BUCKET_BOUNDS_SECS: [f64; 10] =
    [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];
const LATENCY_BUCKET_BOUND_LABELS: [&str; 10] = [
    "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5",
];

/// Prometheus-compatible metrics registry with strictly bounded, low-cardinality labels.
///
/// Complies with the privacy contract:
/// NEVER records IPs, hostnames, URLs, RequestIDs, CircuitIDs, keys, or payloads.
#[derive(Debug)]
pub struct RelayMetrics {
    started_at: Instant,

    // Configured Capacity Limits (for resource utilization gauges)
    pub max_circuits_limit: AtomicU64,
    pub max_connections_limit: AtomicU64,

    // Process & Circuit Counters
    pub circuits_created_total: AtomicU64,
    pub circuits_destroyed_total: AtomicU64,
    pub active_circuits_gauge: AtomicU64,
    pub active_connections_gauge: AtomicU64,
    pub connections_accepted_total: AtomicU64,
    pub connections_rejected_total: AtomicU64,
    pub hop_handshakes_total: AtomicU64,
    pub hop_handshake_failures_total: AtomicU64,

    // Relay Hop & Cell/Frame Traffic
    pub frames_received_total: AtomicU64,
    pub frames_sent_total: AtomicU64,
    pub cells_processed_total: AtomicU64,
    pub bytes_received_total: AtomicU64,
    pub bytes_sent_total: AtomicU64,

    // Request & Destination Execution (Exit)
    pub requests_total: AtomicU64,
    pub requests_success_total: AtomicU64,
    pub requests_failed_total: AtomicU64,
    pub destination_connect_failures_total: AtomicU64,
    pub ssrf_denials_total: AtomicU64,
    pub timeouts_total: AtomicU64,
    pub payload_too_large_total: AtomicU64,
    pub protocol_violations_total: AtomicU64,

    // Destination Request Latency Histogram (microseconds accumulated + cumulative buckets)
    pub request_duration_buckets: [AtomicU64; 10],
    pub request_duration_count: AtomicU64,
    pub request_duration_sum_micros: AtomicU64,

    // Link Rekey Events
    pub link_rekeys_total: AtomicU64,
}

impl Default for RelayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayMetrics {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            max_circuits_limit: AtomicU64::new(0),
            max_connections_limit: AtomicU64::new(0),
            circuits_created_total: AtomicU64::new(0),
            circuits_destroyed_total: AtomicU64::new(0),
            active_circuits_gauge: AtomicU64::new(0),
            active_connections_gauge: AtomicU64::new(0),
            connections_accepted_total: AtomicU64::new(0),
            connections_rejected_total: AtomicU64::new(0),
            hop_handshakes_total: AtomicU64::new(0),
            hop_handshake_failures_total: AtomicU64::new(0),
            frames_received_total: AtomicU64::new(0),
            frames_sent_total: AtomicU64::new(0),
            cells_processed_total: AtomicU64::new(0),
            bytes_received_total: AtomicU64::new(0),
            bytes_sent_total: AtomicU64::new(0),
            requests_total: AtomicU64::new(0),
            requests_success_total: AtomicU64::new(0),
            requests_failed_total: AtomicU64::new(0),
            destination_connect_failures_total: AtomicU64::new(0),
            ssrf_denials_total: AtomicU64::new(0),
            timeouts_total: AtomicU64::new(0),
            payload_too_large_total: AtomicU64::new(0),
            protocol_violations_total: AtomicU64::new(0),
            request_duration_buckets: Default::default(),
            request_duration_count: AtomicU64::new(0),
            request_duration_sum_micros: AtomicU64::new(0),
            link_rekeys_total: AtomicU64::new(0),
        }
    }

    pub fn set_capacity_limits(&self, max_circuits: usize, max_connections: usize) {
        self.max_circuits_limit
            .store(max_circuits as u64, Ordering::Relaxed);
        self.max_connections_limit
            .store(max_connections as u64, Ordering::Relaxed);
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

    pub fn inc_hop_handshakes(&self) {
        self.hop_handshakes_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_hop_handshake_failures(&self) {
        self.hop_handshake_failures_total
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

    pub fn inc_destination_connect_failures(&self) {
        self.destination_connect_failures_total
            .fetch_add(1, Ordering::Relaxed);
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

    pub fn observe_request_duration(&self, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        let micros = elapsed.as_micros().min(u64::MAX as u128) as u64;
        for (idx, bound) in LATENCY_BUCKET_BOUNDS_SECS.iter().enumerate() {
            if secs <= *bound {
                self.request_duration_buckets[idx].fetch_add(1, Ordering::Relaxed);
            }
        }
        self.request_duration_count.fetch_add(1, Ordering::Relaxed);
        self.request_duration_sum_micros
            .fetch_add(micros, Ordering::Relaxed);
    }

    pub fn inc_link_rekeys(&self) {
        self.link_rekeys_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Renders all metrics in standard Prometheus exposition text format (`0.0.4`).
    ///
    /// Role label is statically constrained to `entry`, `middle`, or `exit`.
    pub fn render_prometheus(&self, role: &str, node_id: &str) -> String {
        let safe_node_id: String = node_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        let uptime_secs = self.started_at.elapsed().as_secs_f64();
        let req_count = self.request_duration_count.load(Ordering::Relaxed);
        let req_sum_secs =
            (self.request_duration_sum_micros.load(Ordering::Relaxed) as f64) / 1_000_000.0;

        let mut bucket_lines = String::new();
        for (idx, label) in LATENCY_BUCKET_BOUND_LABELS.iter().enumerate() {
            let val = self.request_duration_buckets[idx].load(Ordering::Relaxed);
            bucket_lines.push_str(&format!(
                "private_relay_request_duration_seconds_bucket{{role=\"{role}\",node=\"{safe_node_id}\",le=\"{label}\"}} {val}\n"
            ));
        }
        bucket_lines.push_str(&format!(
            "private_relay_request_duration_seconds_bucket{{role=\"{role}\",node=\"{safe_node_id}\",le=\"+Inf\"}} {req_count}\n"
        ));

        format!(
            "# HELP private_relay_up Relay process readiness indicator (1 = up)\n\
             # TYPE private_relay_up gauge\n\
             private_relay_up{{role=\"{role}\",node=\"{safe_node_id}\"}} 1\n\
             # HELP private_relay_process_uptime_seconds Relay process uptime in seconds\n\
             # TYPE private_relay_process_uptime_seconds gauge\n\
             private_relay_process_uptime_seconds{{role=\"{role}\",node=\"{safe_node_id}\"}} {uptime_secs:.3}\n\
             # HELP private_relay_max_circuits Configured maximum concurrent circuits\n\
             # TYPE private_relay_max_circuits gauge\n\
             private_relay_max_circuits{{role=\"{role}\",node=\"{safe_node_id}\"}} {max_circuits}\n\
             # HELP private_relay_max_connections Configured maximum concurrent TCP links\n\
             # TYPE private_relay_max_connections gauge\n\
             private_relay_max_connections{{role=\"{role}\",node=\"{safe_node_id}\"}} {max_conns}\n\
             # HELP private_relay_circuits_created_total Total circuits created\n\
             # TYPE private_relay_circuits_created_total counter\n\
             private_relay_circuits_created_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {circuits_created}\n\
             # HELP private_relay_circuits_destroyed_total Total circuits destroyed\n\
             # TYPE private_relay_circuits_destroyed_total counter\n\
             private_relay_circuits_destroyed_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {circuits_destroyed}\n\
             # HELP private_relay_active_circuits Current active circuits\n\
             # TYPE private_relay_active_circuits gauge\n\
             private_relay_active_circuits{{role=\"{role}\",node=\"{safe_node_id}\"}} {active_circuits}\n\
             # HELP private_relay_active_connections Current active inbound TCP links\n\
             # TYPE private_relay_active_connections gauge\n\
             private_relay_active_connections{{role=\"{role}\",node=\"{safe_node_id}\"}} {active_conns}\n\
             # HELP private_relay_connections_accepted_total Total TCP links accepted\n\
             # TYPE private_relay_connections_accepted_total counter\n\
             private_relay_connections_accepted_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {conns_accepted}\n\
             # HELP private_relay_connections_rejected_total Total TCP links rejected due to capacity\n\
             # TYPE private_relay_connections_rejected_total counter\n\
             private_relay_connections_rejected_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {conns_rejected}\n\
             # HELP private_relay_hop_handshakes_total Successful Noise_NK hop handshakes\n\
             # TYPE private_relay_hop_handshakes_total counter\n\
             private_relay_hop_handshakes_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {hop_ok}\n\
             # HELP private_relay_hop_handshake_failures_total Failed Noise_NK or peer hop handshakes\n\
             # TYPE private_relay_hop_handshake_failures_total counter\n\
             private_relay_hop_handshake_failures_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {hop_fail}\n\
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
             # HELP private_relay_destination_connect_failures_total Failed outbound destination TCP or DNS operations\n\
             # TYPE private_relay_destination_connect_failures_total counter\n\
             private_relay_destination_connect_failures_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {dest_conn_fail}\n\
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
             # HELP private_relay_request_duration_seconds Destination request execution latency\n\
             # TYPE private_relay_request_duration_seconds histogram\n\
             {bucket_lines}\
             private_relay_request_duration_seconds_sum{{role=\"{role}\",node=\"{safe_node_id}\"}} {req_sum_secs:.6}\n\
             private_relay_request_duration_seconds_count{{role=\"{role}\",node=\"{safe_node_id}\"}} {req_count}\n\
             # HELP private_relay_link_rekeys_total Coordinated Noise link rekey events\n\
             # TYPE private_relay_link_rekeys_total counter\n\
             private_relay_link_rekeys_total{{role=\"{role}\",node=\"{safe_node_id}\"}} {rekeys}\n",
            max_circuits = self.max_circuits_limit.load(Ordering::Relaxed),
            max_conns = self.max_connections_limit.load(Ordering::Relaxed),
            circuits_created = self.circuits_created_total.load(Ordering::Relaxed),
            circuits_destroyed = self.circuits_destroyed_total.load(Ordering::Relaxed),
            active_circuits = self.active_circuits_gauge.load(Ordering::Relaxed),
            active_conns = self.active_connections_gauge.load(Ordering::Relaxed),
            conns_accepted = self.connections_accepted_total.load(Ordering::Relaxed),
            conns_rejected = self.connections_rejected_total.load(Ordering::Relaxed),
            hop_ok = self.hop_handshakes_total.load(Ordering::Relaxed),
            hop_fail = self.hop_handshake_failures_total.load(Ordering::Relaxed),
            bytes_recv = self.bytes_received_total.load(Ordering::Relaxed),
            bytes_sent = self.bytes_sent_total.load(Ordering::Relaxed),
            frames_recv = self.frames_received_total.load(Ordering::Relaxed),
            frames_sent = self.frames_sent_total.load(Ordering::Relaxed),
            cells_proc = self.cells_processed_total.load(Ordering::Relaxed),
            requests_total = self.requests_total.load(Ordering::Relaxed),
            requests_success = self.requests_success_total.load(Ordering::Relaxed),
            requests_failed = self.requests_failed_total.load(Ordering::Relaxed),
            dest_conn_fail = self.destination_connect_failures_total.load(Ordering::Relaxed),
            ssrf_denials = self.ssrf_denials_total.load(Ordering::Relaxed),
            timeouts = self.timeouts_total.load(Ordering::Relaxed),
            oversized = self.payload_too_large_total.load(Ordering::Relaxed),
            violations = self.protocol_violations_total.load(Ordering::Relaxed),
            rekeys = self.link_rekeys_total.load(Ordering::Relaxed),
        )
    }
}

pub type SharedRelayMetrics = Arc<RelayMetrics>;
