//! Shared CLI argument parsing, configuration validation, safe stderr logging, URL framing,
//! and process entrypoints for `relay-entry`, `relay-middle`, `relay-exit`, `relay-client`,
//! `demo-dest`, and `relay-keygen`.

use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use private_relay_client::{ClientCircuit, ClientConfig, ClientError, RelayClient};
use private_relay_crypto::StaticKeypair;
use private_relay_network::{
    connect_noise_link, encode_hex, ClientConfigFile, PeerDescriptor, RelayConfig, RelayRole,
};
use private_relay_protocol::MAX_MESSAGE_BYTES;
use private_relay_relay::RelayServer;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::field::{Field, Visit};
use tracing::span;
use tracing::{Event, Id, Level, Metadata, Subscriber};

/// Runtime verbosity filter for CLI executables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            other => Err(format!(
                "invalid log level '{other}': expected error | warn | info | debug"
            )),
        }
    }

    fn allows(self, level: &Level) -> bool {
        match self {
            Self::Error => *level <= Level::ERROR,
            Self::Warn => *level <= Level::WARN,
            Self::Info => *level <= Level::INFO,
            Self::Debug => *level <= Level::DEBUG,
        }
    }
}

struct StderrSubscriber {
    max_level: LogLevel,
}

struct SafeFieldFormatter<'a>(&'a mut String);

impl Visit for SafeFieldFormatter<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.push_str(&format!(" {}={:?}", field.name(), value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push_str(&format!(" {}={:?}", field.name(), value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.push_str(&format!(" {}={}", field.name(), value));
    }
}

impl Subscriber for StderrSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.max_level.allows(metadata.level())
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &span::Record<'_>) {}
    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        if !self.enabled(event.metadata()) {
            return;
        }
        let mut fields = String::new();
        event.record(&mut SafeFieldFormatter(&mut fields));
        eprintln!(
            "[{}] {}:{fields}",
            event.metadata().level(),
            event.metadata().target()
        );
    }

    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
}

/// Initializes clean stderr logging once, defaulting to `RUST_LOG` or `LogLevel::Info`.
pub fn init_cli_logger(level_override: Option<LogLevel>) {
    let level = level_override
        .or_else(|| {
            std::env::var("RUST_LOG")
                .ok()
                .and_then(|v| LogLevel::parse(&v).ok())
        })
        .unwrap_or(LogLevel::Info);
    let _ = tracing::subscriber::set_global_default(StderrSubscriber { max_level: level });
}

/// Parsed CLI options for any relay node (`relay-entry`, `relay-middle`, `relay-exit`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCliArgs {
    pub config_path: PathBuf,
    pub listen_override: Option<String>,
    pub log_level: Option<LogLevel>,
    pub check_only: bool,
    pub show_help: bool,
}

/// Parses arguments for `relay-entry`, `relay-middle`, or `relay-exit`.
pub fn parse_relay_args(bin_name: &str, args: &[String]) -> Result<RelayCliArgs, String> {
    let mut config_path: Option<PathBuf> = None;
    let mut listen_override: Option<String> = None;
    let mut log_level: Option<LogLevel> = None;
    let mut check_only = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                return Ok(RelayCliArgs {
                    config_path: PathBuf::new(),
                    listen_override,
                    log_level,
                    check_only,
                    show_help: true,
                });
            }
            "--config" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| format!("{bin_name}: --config requires a file path"))?;
                config_path = Some(PathBuf::from(val));
            }
            "--listen" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| format!("{bin_name}: --listen requires ip:port"))?;
                listen_override = Some(val.clone());
            }
            "--log-level" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| format!("{bin_name}: --log-level requires a value"))?;
                log_level = Some(LogLevel::parse(val)?);
            }
            "--check-only" => {
                check_only = true;
            }
            unknown => {
                return Err(format!("{bin_name}: unexpected argument '{unknown}'"));
            }
        }
        i += 1;
    }

    let config_path = config_path.ok_or_else(|| {
        format!("{bin_name}: missing required --config <path> (run with --help for usage)")
    })?;

    Ok(RelayCliArgs {
        config_path,
        listen_override,
        log_level,
        check_only,
        show_help: false,
    })
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    res = tokio::signal::ctrl_c() => {
                        if res.is_err() {
                            eprintln!("warning: Ctrl+C signal listener failed; initiating shutdown");
                        }
                    }
                    _ = sigterm.recv() => {}
                }
            }
            Err(_) => {
                if tokio::signal::ctrl_c().await.is_err() {
                    eprintln!("warning: signal listener failed; initiating shutdown");
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        if tokio::signal::ctrl_c().await.is_err() {
            eprintln!("warning: Ctrl+C signal listener failed; initiating shutdown");
        }
    }
}

/// Executes a standalone relay binary for `expected_role`, validating config and handling SIGINT/SIGTERM.
pub async fn run_relay_cli(expected_role: RelayRole, bin_name: &str, args: &[String]) -> ExitCode {
    let parsed = match parse_relay_args(bin_name, args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if parsed.show_help {
        println!(
            "Usage: {bin_name} --config <FILE> [--listen <IP:PORT>] [--log-level error|warn|info|debug] [--check-only]"
        );
        return ExitCode::SUCCESS;
    }

    init_cli_logger(parsed.log_level);

    let raw_toml = match fs::read_to_string(&parsed.config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "error: failed to read config '{}': {e}",
                parsed.config_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let mut cfg = match RelayConfig::from_toml_str(&raw_toml) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: invalid relay configuration: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(listen) = parsed.listen_override {
        cfg.listen_addr = listen;
        if let Err(e) = cfg.validate() {
            eprintln!("error: invalid --listen override: {e}");
            return ExitCode::FAILURE;
        }
    }

    if cfg.role != expected_role {
        eprintln!(
            "error: binary '{bin_name}' expects role {:?}, but config declares {:?}",
            expected_role, cfg.role
        );
        return ExitCode::FAILURE;
    }

    if parsed.check_only {
        println!(
            "CONFIG_OK id={} role={:?} listen={} peers={} max_conns={} max_circuits={} rekey_secs={} rekey_bytes={}",
            cfg.id,
            cfg.role,
            cfg.listen_addr,
            cfg.allowed_next_peers.len(),
            cfg.max_concurrent_connections,
            cfg.max_concurrent_circuits,
            cfg.link_rekey_interval_secs,
            cfg.link_rekey_bytes
        );
        return ExitCode::SUCCESS;
    }

    let cfg_id = cfg.id.clone();
    let handle = match RelayServer::start(cfg).await {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: failed to start {bin_name}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let desc = handle.peer_descriptor().clone();

    println!(
        "STATUS=READY id={cfg_id} role={:?} listen={}",
        desc.role,
        handle.local_addr()
    );

    wait_for_shutdown_signal().await;

    println!("STATUS=SHUTTING_DOWN id={cfg_id}");
    handle.shutdown().await;
    println!("STATUS=STOPPED id={cfg_id}");
    ExitCode::SUCCESS
}

/// Target specification parsed from `relay-client` flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientRequestSpec {
    Url(String),
    RawTarget { host_port: String, payload: Vec<u8> },
}

/// Parsed CLI options for `relay-client`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCliArgs {
    pub config_path: PathBuf,
    pub request: Option<ClientRequestSpec>,
    pub probe_addr: Option<String>,
    pub probe_noise_addr: Option<String>,
    pub pubkey_toml: Option<PathBuf>,
    pub probe_http_addr: Option<String>,
    pub log_level: Option<LogLevel>,
    pub check_only: bool,
    pub print_body: bool,
    pub show_help: bool,
}

/// Parses arguments for `relay-client`.
pub fn parse_client_args(args: &[String]) -> Result<ClientCliArgs, String> {
    let mut config_path: Option<PathBuf> = None;
    let mut url: Option<String> = None;
    let mut target: Option<String> = None;
    let mut data: Option<String> = None;
    let mut data_bytes: Option<usize> = None;
    let mut probe_addr: Option<String> = None;
    let mut probe_noise_addr: Option<String> = None;
    let mut pubkey_toml: Option<PathBuf> = None;
    let mut probe_http_addr: Option<String> = None;
    let mut log_level: Option<LogLevel> = None;
    let mut check_only = false;
    let mut print_body = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                return Ok(ClientCliArgs {
                    config_path: PathBuf::new(),
                    request: None,
                    probe_addr: None,
                    probe_noise_addr: None,
                    pubkey_toml: None,
                    probe_http_addr: None,
                    log_level,
                    check_only,
                    print_body,
                    show_help: true,
                });
            }
            "--probe" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "relay-client: --probe requires host:port".to_owned())?;
                probe_addr = Some(val.clone());
            }
            "--probe-noise" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "relay-client: --probe-noise requires host:port".to_owned())?;
                probe_noise_addr = Some(val.clone());
            }
            "--pubkey-toml" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "relay-client: --pubkey-toml requires path".to_owned())?;
                pubkey_toml = Some(PathBuf::from(val));
            }
            "--probe-http" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "relay-client: --probe-http requires host:port".to_owned())?;
                probe_http_addr = Some(val.clone());
            }
            "--config" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "relay-client: --config requires a file path".to_owned())?;
                config_path = Some(PathBuf::from(val));
            }
            "--url" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "relay-client: --url requires an http:// URL".to_owned())?;
                url = Some(val.clone());
            }
            "--target" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "relay-client: --target requires host:port".to_owned())?;
                target = Some(val.clone());
            }
            "--data" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "relay-client: --data requires string payload".to_owned())?;
                data = Some(val.clone());
            }
            "--data-bytes" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "relay-client: --data-bytes requires a number".to_owned())?;
                let count: usize = val
                    .parse()
                    .map_err(|_| format!("relay-client: invalid --data-bytes value '{val}'"))?;
                data_bytes = Some(count);
            }
            "--print-body" => print_body = true,
            "--check-only" => check_only = true,
            "--log-level" => {
                i += 1;
                let val = args
                    .get(i)
                    .ok_or_else(|| "relay-client: --log-level requires a value".to_owned())?;
                log_level = Some(LogLevel::parse(val)?);
            }
            unknown => {
                return Err(format!("relay-client: unexpected argument '{unknown}'"));
            }
        }
        i += 1;
    }

    let probe_mode_count = usize::from(probe_addr.is_some())
        + usize::from(probe_noise_addr.is_some())
        + usize::from(probe_http_addr.is_some());
    if probe_mode_count > 1 {
        return Err(
            "relay-client: specify at most one of --probe, --probe-noise, or --probe-http"
                .to_owned(),
        );
    }
    if pubkey_toml.is_some() && probe_noise_addr.is_none() {
        return Err("relay-client: --pubkey-toml requires --probe-noise <host:port>".to_owned());
    }

    if let Some(probe) = probe_addr {
        if config_path.is_some() || url.is_some() || target.is_some() || check_only {
            return Err(
                "relay-client: --probe cannot be combined with --config, --url, --target, or --check-only"
                    .to_owned(),
            );
        }
        return Ok(ClientCliArgs {
            config_path: PathBuf::new(),
            request: None,
            probe_addr: Some(probe),
            probe_noise_addr: None,
            pubkey_toml: None,
            probe_http_addr: None,
            log_level,
            check_only: false,
            print_body: false,
            show_help: false,
        });
    }

    if let Some(noise_addr) = probe_noise_addr {
        if config_path.is_some() || url.is_some() || target.is_some() || check_only {
            return Err(
                "relay-client: --probe-noise cannot be combined with --config, --url, --target, or --check-only"
                    .to_owned(),
            );
        }
        let pk_toml = pubkey_toml.ok_or_else(|| {
            "relay-client: --probe-noise requires --pubkey-toml <path>".to_owned()
        })?;
        return Ok(ClientCliArgs {
            config_path: PathBuf::new(),
            request: None,
            probe_addr: None,
            probe_noise_addr: Some(noise_addr),
            pubkey_toml: Some(pk_toml),
            probe_http_addr: None,
            log_level,
            check_only: false,
            print_body: false,
            show_help: false,
        });
    }

    if let Some(http_addr) = probe_http_addr {
        if config_path.is_some() || url.is_some() || target.is_some() || check_only {
            return Err(
                "relay-client: --probe-http cannot be combined with --config, --url, --target, or --check-only"
                    .to_owned(),
            );
        }
        return Ok(ClientCliArgs {
            config_path: PathBuf::new(),
            request: None,
            probe_addr: None,
            probe_noise_addr: None,
            pubkey_toml: None,
            probe_http_addr: Some(http_addr),
            log_level,
            check_only: false,
            print_body: false,
            show_help: false,
        });
    }

    let config_path = config_path.ok_or_else(|| {
        "relay-client: missing required --config <path> (run with --help for usage)".to_owned()
    })?;

    if url.is_some() && target.is_some() {
        return Err("relay-client: specify either --url OR --target, not both".to_owned());
    }
    if data.is_some() && data_bytes.is_some() {
        return Err("relay-client: specify either --data OR --data-bytes, not both".to_owned());
    }
    if url.is_some() && (data.is_some() || data_bytes.is_some()) {
        return Err(
            "relay-client: --data/--data-bytes are only supported with --target".to_owned(),
        );
    }

    let request = if let Some(u) = url {
        Some(ClientRequestSpec::Url(u))
    } else if let Some(t) = target {
        let payload = if let Some(text) = data {
            text.into_bytes()
        } else if let Some(n) = data_bytes {
            // Cap raw allocation sanity slightly above protocol 64 KiB limit so tests can test rejection safely.
            if n > MAX_MESSAGE_BYTES + 1024 {
                return Err(format!(
                    "relay-client: --data-bytes {n} exceeds CLI allocation guard ({})",
                    MAX_MESSAGE_BYTES + 1024
                ));
            }
            vec![b'X'; n]
        } else {
            Vec::new()
        };
        Some(ClientRequestSpec::RawTarget {
            host_port: t,
            payload,
        })
    } else if check_only {
        None
    } else {
        return Err("relay-client: either --url or --target is required".to_owned());
    };

    Ok(ClientCliArgs {
        config_path,
        request,
        probe_addr: None,
        probe_noise_addr: None,
        pubkey_toml: None,
        probe_http_addr: None,
        log_level,
        check_only,
        print_body,
        show_help: false,
    })
}

/// Converts `http://host[:port][/path?query]` into `(host:port, HTTP/1.1 GET bytes)` without
/// ever resolving DNS locally on the Client or allowing redirect/userinfo injection.
pub fn build_http_request_from_url(url: &str) -> Result<(String, Vec<u8>), String> {
    let trimmed = url.trim();
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("URL contains control or whitespace characters".to_owned());
    }
    let rest = if let Some(r) = trimmed.strip_prefix("http://") {
        r
    } else if trimmed.starts_with("https://") {
        return Err(
            "https:// scheme is not implemented inside relay-client v0.1 CLI; use http:// or raw --target"
                .to_owned(),
        );
    } else {
        return Err("URL must begin with http://".to_owned());
    };

    let (without_frag, _) = rest.split_once('#').unwrap_or((rest, ""));
    let (authority, path_raw) = match without_frag.find(['/', '?']) {
        Some(idx) => (&without_frag[..idx], &without_frag[idx..]),
        None => (without_frag, "/"),
    };

    if authority.is_empty() {
        return Err("URL host is empty".to_owned());
    }
    if authority.contains('@') {
        return Err("URL userinfo ('@') is rejected".to_owned());
    }

    let host_port = if authority.starts_with('[') {
        let Some(end_bracket) = authority.find(']') else {
            return Err("malformed IPv6 host in URL".to_owned());
        };
        let after = &authority[end_bracket + 1..];
        if after.is_empty() {
            format!("{authority}:80")
        } else if let Some(port_s) = after.strip_prefix(':') {
            validate_port_str(port_s)?;
            authority.to_owned()
        } else {
            return Err("malformed port after IPv6 literal".to_owned());
        }
    } else if let Some((h, port_s)) = authority.rsplit_once(':') {
        if h.contains(':') {
            return Err("unbracketed IPv6 literal in URL must use [...]".to_owned());
        }
        validate_port_str(port_s)?;
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };

    let path = if path_raw.starts_with('?') {
        format!("/{path_raw}")
    } else {
        path_raw.to_owned()
    };

    let http = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    Ok((host_port, http.into_bytes()))
}

fn validate_port_str(port_s: &str) -> Result<u16, String> {
    let p: u16 = port_s
        .parse()
        .map_err(|_| format!("invalid URL port '{port_s}'"))?;
    if p == 0 {
        return Err("URL port must be non-zero".to_owned());
    }
    Ok(p)
}

fn extract_sanitized_http_status(bytes: &[u8]) -> Option<String> {
    if !bytes.starts_with(b"HTTP/1.") {
        return None;
    }
    let line_end = bytes
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(bytes.len().min(64));
    let slice = &bytes[..line_end.min(64)];
    let status = String::from_utf8_lossy(slice)
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect::<String>();
    Some(status)
}

/// Executes `relay-client` end-to-end and prints sanitized status/byte/timing metadata.
pub async fn run_client_cli(args: &[String]) -> ExitCode {
    let parsed = match parse_client_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if parsed.show_help {
        println!(
            "Usage: relay-client (--probe <HOST:PORT> | --probe-noise <HOST:PORT> --pubkey-toml <FILE> | --probe-http <HOST:PORT> | --config <FILE> (--url <http://host:port/path> | --target <host:port> [--data <STR> | --data-bytes <N>])) [--print-body] [--check-only] [--log-level error|warn|info|debug]"
        );
        return ExitCode::SUCCESS;
    }

    if let Some(probe_addr) = parsed.probe_addr {
        match tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(&probe_addr),
        )
        .await
        {
            Ok(Ok(_)) => return ExitCode::SUCCESS,
            _ => return ExitCode::FAILURE,
        }
    }

    if let Some(noise_addr) = parsed.probe_noise_addr {
        let Some(pubkey_toml) = parsed.pubkey_toml else {
            return ExitCode::FAILURE;
        };
        return match run_noise_probe(&noise_addr, &pubkey_toml).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: relay-client noise readiness probe failed: {err}");
                ExitCode::FAILURE
            }
        };
    }

    if let Some(http_addr) = parsed.probe_http_addr {
        return match run_http_health_probe(&http_addr).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("error: relay-client http readiness probe failed: {err}");
                ExitCode::FAILURE
            }
        };
    }

    init_cli_logger(parsed.log_level);

    let raw_toml = match fs::read_to_string(&parsed.config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "error: failed to read client config '{}': {e}",
                parsed.config_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    let cfg = match ClientConfigFile::from_toml_str(&raw_toml) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: invalid client configuration: {e}");
            return ExitCode::FAILURE;
        }
    };

    let req_parts = match parsed.request.as_ref() {
        None => None,
        Some(ClientRequestSpec::Url(u)) => match build_http_request_from_url(u) {
            Ok((hp, body)) => Some((true, hp, body)),
            Err(e) => {
                eprintln!("error: invalid --url: {e}");
                return ExitCode::FAILURE;
            }
        },
        Some(ClientRequestSpec::RawTarget { host_port, payload }) => {
            Some((false, host_port.clone(), payload.clone()))
        }
    };

    if parsed.check_only {
        println!(
            "CONFIG_OK route=[{}->{},{}->{}] handshake_ms={} request_ms={}",
            cfg.entry.id,
            cfg.middle.id,
            cfg.middle.id,
            cfg.exit.id,
            cfg.handshake_timeout_ms,
            cfg.request_timeout_ms
        );
        return ExitCode::SUCCESS;
    }

    let (is_http, target_host_port, body) = req_parts.expect("validated request spec");
    let started = Instant::now();

    let mut circuit: ClientCircuit = match RelayClient::connect_three_hop_with_rekey(
        cfg.route(),
        ClientConfig::from_config_file(&cfg),
        cfg.link_rekey_policy(),
    )
    .await
    {
        Ok(c) => {
            println!("connection: OK (3-hop circuit_id={})", c.circuit_id().get());
            c
        }
        Err(e) => {
            println!("connection: FAILED ({e})");
            return ExitCode::FAILURE;
        }
    };

    let send_outcome = circuit.send_request(&target_host_port, &body).await;
    let elapsed_ms = started.elapsed().as_millis();
    let req_id_str = circuit
        .last_request_id()
        .map(|r| r.get().to_string())
        .unwrap_or_else(|| "none".to_owned());
    println!("request_id: {req_id_str}");

    let exit_code = match send_outcome {
        Ok(resp_bytes) => {
            println!("transmission: OK (request_bytes={})", body.len());
            if is_http {
                let status = extract_sanitized_http_status(&resp_bytes)
                    .unwrap_or_else(|| "non-HTTP response".to_owned());
                println!("outcome: OK (http_status=\"{status}\")");
            } else {
                println!("outcome: OK");
            }
            println!("response_bytes: {}", resp_bytes.len());
            println!("elapsed_ms: {elapsed_ms}");
            if parsed.print_body {
                if let Ok(text) = std::str::from_utf8(&resp_bytes) {
                    println!("--- BEGIN RESPONSE BODY ---\n{text}\n--- END RESPONSE BODY ---");
                } else {
                    println!(
                        "--- RESPONSE BODY IS BINARY ({} bytes) ---",
                        resp_bytes.len()
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            match &err {
                ClientError::Protocol(_) | ClientError::InvalidState(_) => {
                    println!("transmission: FAILED ({err})");
                    println!("outcome: REJECTED_LOCALLY");
                }
                ClientError::RemoteError(code) => {
                    println!("transmission: OK (request_bytes={})", body.len());
                    println!("outcome: REMOTE_ERROR({code:?}: {})", code.summary());
                }
                ClientError::CircuitDestroyed(reason) => {
                    println!("transmission: INTERRUPTED");
                    println!("outcome: CIRCUIT_DESTROYED({reason:?})");
                }
                other => {
                    println!("transmission: FAILED ({other})");
                    println!("outcome: FAILED");
                }
            }
            println!("response_bytes: 0");
            println!("elapsed_ms: {elapsed_ms}");
            ExitCode::FAILURE
        }
    };

    let _ = circuit.close().await;
    exit_code
}

/// Configuration file for the controlled local HTTP/TCP demo destination server (`demo-dest`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestServerConfig {
    pub listen_addr: String,
    #[serde(default = "default_slow_delay_ms")]
    pub slow_delay_ms: u64,
}

const fn default_slow_delay_ms() -> u64 {
    12_000
}

impl DestServerConfig {
    pub fn from_toml_str(s: &str) -> Result<Self, String> {
        let cfg: Self = toml::from_str(s).map_err(|e| format!("invalid TOML: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.listen_addr.parse::<SocketAddr>().is_err() {
            return Err("destination listen_addr must be a valid ip:port SocketAddr".to_owned());
        }
        Ok(())
    }
}

/// Runs the controlled local destination test server supporting `/health`, `/echo`, `/medium`,
/// `/max-64kib`, `/oversized`, `/slow`, `/redirect-ssrf`, and raw TCP fallback.
pub async fn run_demo_dest(args: &[String]) -> ExitCode {
    let mut config_path: Option<PathBuf> = None;
    let mut listen_override: Option<String> = None;
    let mut check_only = false;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!("Usage: demo-dest [--config <FILE>] [--listen <ip:port>] [--check-only]");
                return ExitCode::SUCCESS;
            }
            "--config" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: demo-dest: --config requires a path");
                    return ExitCode::FAILURE;
                };
                config_path = Some(PathBuf::from(v));
            }
            "--listen" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: demo-dest: --listen requires ip:port");
                    return ExitCode::FAILURE;
                };
                listen_override = Some(v.clone());
            }
            "--check-only" => check_only = true,
            unknown => {
                eprintln!("error: demo-dest: unexpected argument '{unknown}'");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let mut cfg = if let Some(path) = config_path {
        match fs::read_to_string(&path).and_then(|s| {
            DestServerConfig::from_toml_str(&s)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: invalid destination config: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        DestServerConfig {
            listen_addr: listen_override
                .clone()
                .unwrap_or_else(|| "127.0.0.1:9000".to_owned()),
            slow_delay_ms: default_slow_delay_ms(),
        }
    };

    if let Some(ov) = listen_override {
        cfg.listen_addr = ov;
    }
    if let Err(e) = cfg.validate() {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    if check_only {
        println!(
            "CONFIG_OK service=demo-dest listen={} slow_delay_ms={}",
            cfg.listen_addr, cfg.slow_delay_ms
        );
        return ExitCode::SUCCESS;
    }

    let listener = match TcpListener::bind(&cfg.listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: demo-dest failed to bind {}: {e}", cfg.listen_addr);
            return ExitCode::FAILURE;
        }
    };
    let bound = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: failed to read bound addr: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("STATUS=READY service=demo-dest listen={bound}");

    let (sd_tx, mut sd_rx) = watch::channel(false);
    let slow_ms = cfg.slow_delay_ms;
    let accept_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sd_rx.changed() => {
                    if *sd_rx.borrow() {
                        break;
                    }
                }
                res = listener.accept() => {
                    if let Ok((mut stream, _)) = res {
                        tokio::spawn(async move {
                            let mut buf = Vec::with_capacity(2048);
                            let mut tmp = [0u8; 4096];
                            loop {
                                match stream.read(&mut tmp).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if buf.len().saturating_add(n) > MAX_MESSAGE_BYTES + 1024 {
                                            break;
                                        }
                                        buf.extend_from_slice(&tmp[..n]);
                                    }
                                    Err(_) => return,
                                }
                            }

                            let resp = handle_demo_dest_bytes(&buf, slow_ms).await;
                            let _ = stream.write_all(&resp).await;
                            let _ = stream.shutdown().await;
                        });
                    }
                }
            }
        }
    });

    wait_for_shutdown_signal().await;
    println!("STATUS=SHUTTING_DOWN service=demo-dest");
    let _ = sd_tx.send(true);
    let _ = accept_task.await;
    println!("STATUS=STOPPED service=demo-dest");
    ExitCode::SUCCESS
}

async fn handle_demo_dest_bytes(req: &[u8], slow_delay_ms: u64) -> Vec<u8> {
    if let Some(first_line) = req.split(|&b| b == b'\n').next() {
        if let Ok(line_str) = std::str::from_utf8(first_line) {
            if let Some(path) = parse_http_request_path(line_str) {
                return match path {
                    "/health" => {
                        let body = "{\"status\":\"ok\",\"service\":\"private-relay-demo-dest\"}\n";
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .into_bytes()
                    }
                    "/echo" => {
                        let body = format!(
                            "{{\"status\":\"ok\",\"received_bytes\":{}}}\n",
                            req.len()
                        );
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .into_bytes()
                    }
                    "/medium" => {
                        let body = "M".repeat(12_288);
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .into_bytes()
                    }
                    "/max-64kib" => {
                        // Total wire response = exact MAX_MESSAGE_BYTES (65,536 bytes).
                        let header_prefix = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ";
                        let header_suffix = "\r\nConnection: close\r\n\r\n";
                        let approx_header = format!("{header_prefix}65536{header_suffix}").len();
                        let mut body_len = MAX_MESSAGE_BYTES - approx_header;
                        let actual_header =
                            format!("{header_prefix}{body_len}{header_suffix}");
                        body_len = MAX_MESSAGE_BYTES - actual_header.len();
                        let header = format!("{header_prefix}{body_len}{header_suffix}");
                        let mut out = Vec::with_capacity(MAX_MESSAGE_BYTES);
                        out.extend_from_slice(header.as_bytes());
                        out.resize(MAX_MESSAGE_BYTES, b'Z');
                        out
                    }
                    "/oversized" => vec![b'O'; MAX_MESSAGE_BYTES + 4096],
                    "/slow" => {
                        sleep(Duration::from_millis(slow_delay_ms)).await;
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow"
                            .to_vec()
                    }
                    "/redirect-ssrf" => b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                    _ => {
                        let body = "not found\n";
                        format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .into_bytes()
                    }
                };
            }
        }
    }

    // Raw TCP non-HTTP fallback echoes exact payload length & transformed tail safely.
    req.iter().map(|b| b ^ 0x5A).collect()
}

fn parse_http_request_path(line: &str) -> Option<&str> {
    let trimmed = line.trim_end_matches('\r');
    let mut parts = trimmed.split_whitespace();
    let method = parts.next()?;
    if !matches!(method, "GET" | "POST" | "HEAD") {
        return None;
    }
    let path_full = parts.next()?;
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    Some(path_full.split('?').next().unwrap_or(path_full))
}

async fn run_noise_probe(addr: &str, pubkey_toml: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(pubkey_toml)
        .map_err(|e| format!("failed to read {}: {e}", pubkey_toml.display()))?;
    let expected_pub = RelayConfig::read_public_key_from_toml_str(&raw)
        .map_err(|e| format!("invalid public key TOML {}: {e}", pubkey_toml.display()))?;
    let ephemeral = StaticKeypair::generate().map_err(|e| e.to_string())?;
    let (reader, writer) =
        connect_noise_link(addr, &ephemeral, expected_pub, Duration::from_secs(2))
            .await
            .map_err(|e| format!("Noise_IK handshake to {addr} failed: {e}"))?;
    drop(reader);
    drop(writer);
    Ok(())
}

async fn run_http_health_probe(addr: &str) -> Result<(), String> {
    let probe_fut = async {
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|e| format!("tcp connect to {addr} failed: {e}"))?;
        let req = format!("GET /health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("write /health request failed: {e}"))?;
        stream
            .shutdown()
            .await
            .map_err(|e| format!("half-close /health request failed: {e}"))?;
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        loop {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read /health response failed: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if String::from_utf8_lossy(&buf).contains("\"status\":\"ok\"") || buf.len() >= 2048 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buf);
        let first_line = text.lines().next().unwrap_or("").trim_end_matches('\r');
        let ok_status = first_line == "HTTP/1.1 200"
            || first_line.starts_with("HTTP/1.1 200 ")
            || first_line == "HTTP/1.0 200"
            || first_line.starts_with("HTTP/1.0 200 ");
        if !ok_status {
            return Err(format!("unexpected HTTP status line: '{first_line}'"));
        }
        let body_part = text
            .split_once("\r\n\r\n")
            .or_else(|| text.split_once("\n\n"))
            .map(|(_, b)| b)
            .unwrap_or("");
        if !body_part.contains("\"status\":\"ok\"") {
            return Err("health body missing status=ok marker".to_owned());
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(2), probe_fut)
        .await
        .map_err(|_| format!("timed out probing http://{addr}/health"))?
}

fn write_secret_key_file(path: &Path, key_hex: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create secret dir {}: {e}", parent.display()))?;
    }
    fs::write(path, format!("{key_hex}\n"))
        .map_err(|e| format!("failed to write secret file {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
    Ok(())
}

/// Safe local identity and configuration generator (`relay-keygen`).
/// Writes fresh runtime TOML configs to `--out-dir` without printing private keys to stdout.
pub fn run_keygen(args: &[String]) -> ExitCode {
    let mut out_dir = PathBuf::from("demo/generated");
    let mut entry_addr = "127.0.0.1:9101".to_owned();
    let mut middle_addr = "127.0.0.1:9102".to_owned();
    let mut exit_addr = "127.0.0.1:9103".to_owned();
    let mut entry_listen: Option<String> = None;
    let mut middle_listen: Option<String> = None;
    let mut exit_listen: Option<String> = None;
    let mut allowed_targets: Vec<String> = Vec::new();
    let mut destination_io_timeout_ms = 5_000u64;
    let mut allow_loopback_for_test = true;
    let mut allow_private_targets_for_test = false;
    let mut split_dirs = false;
    let mut key_file_path: Option<String> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!(
                    "Usage: relay-keygen [--out-dir <DIR>] [--entry-addr <HOST:PORT>] [--middle-addr <HOST:PORT>] [--exit-addr <HOST:PORT>] [--entry-listen <IP:PORT>] [--middle-listen <IP:PORT>] [--exit-listen <IP:PORT>] [--allow-target <HOST:PORT>] [--dest-timeout-ms <MS>] [--allow-private-targets-for-test] [--deny-loopback] [--split-dirs]"
                );
                return ExitCode::SUCCESS;
            }
            "--out-dir" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: relay-keygen: --out-dir requires a path");
                    return ExitCode::FAILURE;
                };
                out_dir = PathBuf::from(v);
            }
            "--entry-addr" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: relay-keygen: --entry-addr requires host:port");
                    return ExitCode::FAILURE;
                };
                entry_addr = v.clone();
            }
            "--middle-addr" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: relay-keygen: --middle-addr requires host:port");
                    return ExitCode::FAILURE;
                };
                middle_addr = v.clone();
            }
            "--exit-addr" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: relay-keygen: --exit-addr requires host:port");
                    return ExitCode::FAILURE;
                };
                exit_addr = v.clone();
            }
            "--entry-listen" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: relay-keygen: --entry-listen requires ip:port");
                    return ExitCode::FAILURE;
                };
                entry_listen = Some(v.clone());
            }
            "--middle-listen" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: relay-keygen: --middle-listen requires ip:port");
                    return ExitCode::FAILURE;
                };
                middle_listen = Some(v.clone());
            }
            "--exit-listen" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: relay-keygen: --exit-listen requires ip:port");
                    return ExitCode::FAILURE;
                };
                exit_listen = Some(v.clone());
            }
            "--allow-target" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: relay-keygen: --allow-target requires host:port");
                    return ExitCode::FAILURE;
                };
                allowed_targets.push(v.clone());
            }
            "--allow-private-targets-for-test" => allow_private_targets_for_test = true,
            "--deny-loopback" => allow_loopback_for_test = false,
            "--split-dirs" => split_dirs = true,
            "--key-file-path" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: relay-keygen: --key-file-path requires path or 'auto'");
                    return ExitCode::FAILURE;
                };
                if v.trim().is_empty() {
                    eprintln!("error: relay-keygen: --key-file-path must be non-empty");
                    return ExitCode::FAILURE;
                }
                key_file_path = Some(v.clone());
            }
            "--dest-timeout-ms" => {
                i += 1;
                let Some(v) = args.get(i) else {
                    eprintln!("error: relay-keygen: --dest-timeout-ms requires integer");
                    return ExitCode::FAILURE;
                };
                destination_io_timeout_ms = match v.parse() {
                    Ok(ms) => ms,
                    Err(_) => {
                        eprintln!("error: invalid --dest-timeout-ms '{v}'");
                        return ExitCode::FAILURE;
                    }
                };
            }
            unknown => {
                eprintln!("error: relay-keygen: unexpected argument '{unknown}'");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    if allowed_targets.is_empty() {
        allowed_targets.push("127.0.0.1:9000".to_owned());
    }

    let opts = KeygenOptions {
        entry_listen: entry_listen.unwrap_or_else(|| entry_addr.clone()),
        middle_listen: middle_listen.unwrap_or_else(|| middle_addr.clone()),
        exit_listen: exit_listen.unwrap_or_else(|| exit_addr.clone()),
        allow_loopback_for_test,
        allow_private_targets_for_test,
        split_dirs,
        key_file_path,
    };

    match generate_demo_configs_with_options(
        &out_dir,
        &entry_addr,
        &middle_addr,
        &exit_addr,
        allowed_targets,
        destination_io_timeout_ms,
        &opts,
    ) {
        Ok(()) => {
            println!("KEYGEN_OK out_dir={}", out_dir.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: relay-keygen failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Optional container/isolation layout flags for [`generate_demo_configs_with_options`].
#[derive(Debug, Clone)]
pub struct KeygenOptions {
    pub entry_listen: String,
    pub middle_listen: String,
    pub exit_listen: String,
    pub allow_loopback_for_test: bool,
    pub allow_private_targets_for_test: bool,
    pub split_dirs: bool,
    pub key_file_path: Option<String>,
}

/// Generates fresh X25519 demo identities and validated TOML configurations inside `out_dir`.
pub fn generate_demo_configs(
    out_dir: &Path,
    entry_addr: &str,
    middle_addr: &str,
    exit_addr: &str,
    allowed_targets: Vec<String>,
    destination_io_timeout_ms: u64,
) -> Result<(), String> {
    let opts = KeygenOptions {
        entry_listen: entry_addr.to_owned(),
        middle_listen: middle_addr.to_owned(),
        exit_listen: exit_addr.to_owned(),
        allow_loopback_for_test: true,
        allow_private_targets_for_test: false,
        split_dirs: false,
        key_file_path: None,
    };
    generate_demo_configs_with_options(
        out_dir,
        entry_addr,
        middle_addr,
        exit_addr,
        allowed_targets,
        destination_io_timeout_ms,
        &opts,
    )
}

/// Generates fresh X25519 demo identities supporting distinct bind addresses and split per-node directories.
pub fn generate_demo_configs_with_options(
    out_dir: &Path,
    entry_addr: &str,
    middle_addr: &str,
    exit_addr: &str,
    allowed_targets: Vec<String>,
    destination_io_timeout_ms: u64,
    opts: &KeygenOptions,
) -> Result<(), String> {
    let entry_kp = StaticKeypair::generate().map_err(|e| e.to_string())?;
    let middle_kp = StaticKeypair::generate().map_err(|e| e.to_string())?;
    let exit_kp = StaticKeypair::generate().map_err(|e| e.to_string())?;

    let exit_desc = PeerDescriptor {
        id: "demo-exit-1".to_owned(),
        role: RelayRole::Exit,
        addr: exit_addr.to_owned(),
        public_key_hex: encode_hex(exit_kp.public()),
    };
    let middle_desc = PeerDescriptor {
        id: "demo-middle-1".to_owned(),
        role: RelayRole::Middle,
        addr: middle_addr.to_owned(),
        public_key_hex: encode_hex(middle_kp.public()),
    };
    let entry_desc = PeerDescriptor {
        id: "demo-entry-1".to_owned(),
        role: RelayRole::Entry,
        addr: entry_addr.to_owned(),
        public_key_hex: encode_hex(entry_kp.public()),
    };

    let mut exit_cfg = RelayConfig::with_generated_keypair(
        "demo-exit-1",
        RelayRole::Exit,
        &opts.exit_listen,
        &exit_kp,
    );
    exit_cfg.allow_loopback_for_test = opts.allow_loopback_for_test;
    exit_cfg.allow_private_targets_for_test = opts.allow_private_targets_for_test;
    exit_cfg.allowed_targets = allowed_targets;
    exit_cfg.destination_io_timeout_ms = destination_io_timeout_ms;
    exit_cfg.validate().map_err(|e| e.to_string())?;

    let mut middle_cfg = RelayConfig::with_generated_keypair(
        "demo-middle-1",
        RelayRole::Middle,
        &opts.middle_listen,
        &middle_kp,
    );
    middle_cfg.allowed_next_peers = vec![exit_desc.clone()];
    middle_cfg.validate().map_err(|e| e.to_string())?;

    let mut entry_cfg = RelayConfig::with_generated_keypair(
        "demo-entry-1",
        RelayRole::Entry,
        &opts.entry_listen,
        &entry_kp,
    );
    entry_cfg.allowed_next_peers = vec![middle_desc.clone()];
    entry_cfg.validate().map_err(|e| e.to_string())?;

    if let Some(ref secret_spec) = opts.key_file_path {
        let (entry_dir, middle_dir, exit_dir) = if opts.split_dirs {
            (
                out_dir.join("entry"),
                out_dir.join("middle"),
                out_dir.join("exit"),
            )
        } else {
            (
                out_dir.to_path_buf(),
                out_dir.to_path_buf(),
                out_dir.to_path_buf(),
            )
        };
        let entry_key_disk = entry_dir.join("entry.key");
        let middle_key_disk = middle_dir.join("middle.key");
        let exit_key_disk = exit_dir.join("exit.key");
        write_secret_key_file(&entry_key_disk, &encode_hex(entry_kp.secret_bytes()))?;
        write_secret_key_file(&middle_key_disk, &encode_hex(middle_kp.secret_bytes()))?;
        write_secret_key_file(&exit_key_disk, &encode_hex(exit_kp.secret_bytes()))?;

        let (entry_ref, middle_ref, exit_ref) = if secret_spec == "auto" {
            (
                entry_key_disk.to_string_lossy().into_owned(),
                middle_key_disk.to_string_lossy().into_owned(),
                exit_key_disk.to_string_lossy().into_owned(),
            )
        } else {
            (
                secret_spec.clone(),
                secret_spec.clone(),
                secret_spec.clone(),
            )
        };
        entry_cfg = entry_cfg.without_inline_secret(entry_ref);
        middle_cfg = middle_cfg.without_inline_secret(middle_ref);
        exit_cfg = exit_cfg.without_inline_secret(exit_ref);
    }

    let client_cfg = ClientConfigFile {
        entry: entry_desc,
        middle: middle_desc,
        exit: exit_desc,
        handshake_timeout_ms: 5_000,
        io_timeout_ms: 5_000,
        request_timeout_ms: destination_io_timeout_ms.saturating_add(5_000),
        link_rekey_interval_secs: 3_600,
        link_rekey_bytes: 1_073_741_824,
        metrics_addr: None,
    };
    client_cfg.validate().map_err(|e| e.to_string())?;

    let (entry_dir, middle_dir, exit_dir, client_dir) = if opts.split_dirs {
        (
            out_dir.join("entry"),
            out_dir.join("middle"),
            out_dir.join("exit"),
            out_dir.join("client"),
        )
    } else {
        (
            out_dir.to_path_buf(),
            out_dir.to_path_buf(),
            out_dir.to_path_buf(),
            out_dir.to_path_buf(),
        )
    };

    for dir in [&entry_dir, &middle_dir, &exit_dir, &client_dir] {
        fs::create_dir_all(dir).map_err(|e| format!("create_dir_all: {e}"))?;
    }

    write_config_file(
        &entry_dir.join("entry.toml"),
        &entry_cfg.to_toml_string().map_err(|e| e.to_string())?,
    )?;
    write_config_file(
        &middle_dir.join("middle.toml"),
        &middle_cfg.to_toml_string().map_err(|e| e.to_string())?,
    )?;
    write_config_file(
        &exit_dir.join("exit.toml"),
        &exit_cfg.to_toml_string().map_err(|e| e.to_string())?,
    )?;
    write_config_file(
        &client_dir.join("client.toml"),
        &client_cfg.to_toml_string().map_err(|e| e.to_string())?,
    )?;

    Ok(())
}

fn write_config_file(path: &Path, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
    Ok(())
}
