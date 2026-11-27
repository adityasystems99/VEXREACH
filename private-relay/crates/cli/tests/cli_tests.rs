use std::collections::HashSet;
use std::fs::{self, File};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use private_relay_cli::{
    build_http_request_from_url, generate_demo_configs, generate_demo_configs_with_options,
    parse_client_args, parse_relay_args, KeygenOptions, LogLevel,
};

struct ChildGuard(Vec<Child>);

impl ChildGuard {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, child: Child) -> usize {
        self.0.push(child);
        self.0.len() - 1
    }

    fn kill_index(&mut self, idx: usize) {
        let _ = self.0[idx].kill();
        let _ = self.0[idx].wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn create(prefix: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "{prefix}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn free_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn wait_tcp_ready(addr: &str, timeout: Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    panic!("timed out waiting for process listening on {addr}");
}

#[test]
fn cli_arg_parsing_and_url_validation_unit_checks() {
    // Relay CLI arg parsing
    let args = vec![
        "--config".into(),
        "entry.toml".into(),
        "--listen".into(),
        "0.0.0.0:9101".into(),
        "--log-level".into(),
        "debug".into(),
        "--check-only".into(),
    ];
    let parsed_relay = parse_relay_args("relay-entry", &args).unwrap();
    assert_eq!(parsed_relay.config_path, PathBuf::from("entry.toml"));
    assert_eq!(
        parsed_relay.listen_override.as_deref(),
        Some("0.0.0.0:9101")
    );
    assert_eq!(parsed_relay.log_level, Some(LogLevel::Debug));
    assert!(parsed_relay.check_only);

    assert!(parse_relay_args("relay-entry", &[]).is_err());
    assert!(parse_relay_args("relay-entry", &["--unknown".into()]).is_err());

    // Client --probe mode parsing (no --config needed; mutually exclusive with request flags)
    let probe_args = parse_client_args(&["--probe".into(), "127.0.0.1:9101".into()]).unwrap();
    assert_eq!(probe_args.probe_addr.as_deref(), Some("127.0.0.1:9101"));
    assert!(parse_client_args(&[
        "--probe".into(),
        "127.0.0.1:9101".into(),
        "--config".into(),
        "client.toml".into()
    ])
    .is_err());

    // Client CLI arg parsing
    let cargs = vec![
        "--config".into(),
        "client.toml".into(),
        "--url".into(),
        "http://127.0.0.1:9000/health".into(),
    ];
    let parsed_cli = parse_client_args(&cargs).unwrap();
    assert_eq!(parsed_cli.config_path, PathBuf::from("client.toml"));
    assert!(!parsed_cli.print_body);

    // Mutually exclusive --url and --target rejected
    assert!(parse_client_args(&[
        "--config".into(),
        "c.toml".into(),
        "--url".into(),
        "http://a/".into(),
        "--target".into(),
        "a:80".into(),
    ])
    .is_err());

    // Excess --data-bytes guard rejected
    assert!(parse_client_args(&[
        "--config".into(),
        "c.toml".into(),
        "--target".into(),
        "a:80".into(),
        "--data-bytes".into(),
        "100000".into(),
    ])
    .is_err());

    // URL framing checks
    let (hp, raw) = build_http_request_from_url("http://127.0.0.1:9000/health?v=1").unwrap();
    assert_eq!(hp, "127.0.0.1:9000");
    let raw_s = String::from_utf8(raw).unwrap();
    assert!(raw_s.starts_with("GET /health?v=1 HTTP/1.1\r\nHost: 127.0.0.1:9000\r\n"));

    let (hp_def, _) = build_http_request_from_url("http://example.com").unwrap();
    assert_eq!(hp_def, "example.com:80");

    let (hp_v6, _) = build_http_request_from_url("http://[::1]:9000/test").unwrap();
    assert_eq!(hp_v6, "[::1]:9000");

    assert!(build_http_request_from_url("https://example.com/").is_err());
    assert!(build_http_request_from_url("http://user@127.0.0.1:9000/").is_err());
    assert!(build_http_request_from_url("http://127.0.0.1:9000/ bad").is_err());
}

#[test]
fn cli_rejects_missing_config_wrong_role_and_bad_keys() {
    let tmp = TempDirGuard::create("pr_cli_bad_cfg");
    let entry_addr = format!("127.0.0.1:{}", free_loopback_port());
    let mid_addr = format!("127.0.0.1:{}", free_loopback_port());
    let exit_addr = format!("127.0.0.1:{}", free_loopback_port());
    generate_demo_configs(
        &tmp.0,
        &entry_addr,
        &mid_addr,
        &exit_addr,
        vec!["127.0.0.1:9000".into()],
        2000,
    )
    .unwrap();

    // 1. Missing config file path fails cleanly.
    let missing = Command::new(env!("CARGO_BIN_EXE_relay-entry"))
        .arg("--config")
        .arg(tmp.0.join("does-not-exist.toml"))
        .output()
        .unwrap();
    assert!(!missing.status.success());

    // 2. Wrong role binary rejected (giving exit.toml to relay-entry).
    let wrong_role = Command::new(env!("CARGO_BIN_EXE_relay-entry"))
        .arg("--config")
        .arg(tmp.0.join("exit.toml"))
        .arg("--check-only")
        .output()
        .unwrap();
    assert!(!wrong_role.status.success());
    let err_txt = String::from_utf8_lossy(&wrong_role.stderr);
    assert!(err_txt.contains("expects role Entry"));

    // 3. Missing key material / malformed config rejected.
    let broken_toml = tmp.0.join("broken_exit.toml");
    fs::write(
        &broken_toml,
        "id = 'x'\nrole = 'exit'\nlisten_addr = '127.0.0.1:0'\n",
    )
    .unwrap();
    let missing_key = Command::new(env!("CARGO_BIN_EXE_relay-exit"))
        .arg("--config")
        .arg(&broken_toml)
        .arg("--check-only")
        .output()
        .unwrap();
    assert!(!missing_key.status.success());

    // 4. Client --check-only validates valid config cleanly.
    let cli_check = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(tmp.0.join("client.toml"))
        .arg("--check-only")
        .output()
        .unwrap();
    assert!(cli_check.status.success());
    assert!(String::from_utf8_lossy(&cli_check.stdout).contains("CONFIG_OK"));

    // 5. Split container directory generation writes isolated entry/middle/exit/client TOMLs cleanly.
    let split_dir = tmp.0.join("split");
    let opts = KeygenOptions {
        entry_listen: "0.0.0.0:9101".into(),
        middle_listen: "0.0.0.0:9102".into(),
        exit_listen: "0.0.0.0:9103".into(),
        allow_loopback_for_test: false,
        allow_private_targets_for_test: true,
        split_dirs: true,
        key_file_path: None,
    };
    generate_demo_configs_with_options(
        &split_dir,
        "relay-entry:9101",
        "relay-middle:9102",
        "relay-exit:9103",
        vec!["demo-dest:9000".into()],
        2500,
        &opts,
    )
    .unwrap();
    assert!(split_dir.join("entry/entry.toml").exists());
    assert!(split_dir.join("middle/middle.toml").exists());
    assert!(split_dir.join("exit/exit.toml").exists());
    assert!(split_dir.join("client/client.toml").exists());
    let exit_split_txt = fs::read_to_string(split_dir.join("exit/exit.toml")).unwrap();
    assert!(exit_split_txt.contains("allow_loopback_for_test = false"));
    assert!(exit_split_txt.contains("allow_private_targets_for_test = true"));
}

#[test]
fn multi_process_os_three_hop_demo_and_failure_scenarios() {
    let tmp = TempDirGuard::create("pr_multi_proc");
    let dest_port = free_loopback_port();
    let entry_port = free_loopback_port();
    let mid_port = free_loopback_port();
    let exit_port = free_loopback_port();
    let closed_port = free_loopback_port();

    let dest_addr = format!("127.0.0.1:{dest_port}");
    let entry_addr = format!("127.0.0.1:{entry_port}");
    let mid_addr = format!("127.0.0.1:{mid_port}");
    let exit_addr = format!("127.0.0.1:{exit_port}");
    let closed_addr = format!("127.0.0.1:{closed_port}");

    // Allow both live destination port AND an unlisted vs closed port check.
    let keygen = Command::new(env!("CARGO_BIN_EXE_relay-keygen"))
        .arg("--out-dir")
        .arg(&tmp.0)
        .arg("--entry-addr")
        .arg(&entry_addr)
        .arg("--middle-addr")
        .arg(&mid_addr)
        .arg("--exit-addr")
        .arg(&exit_addr)
        .arg("--allow-target")
        .arg(&dest_addr)
        .arg("--allow-target")
        .arg(&closed_addr)
        .arg("--dest-timeout-ms")
        .arg("3500")
        .output()
        .unwrap();
    assert!(
        keygen.status.success(),
        "relay-keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );

    let dest_cfg = tmp.0.join("dest.toml");
    fs::write(
        &dest_cfg,
        format!("listen_addr = \"{dest_addr}\"\nslow_delay_ms = 5500\n"),
    )
    .unwrap();

    let mut children = ChildGuard::new();

    // 1. Spawn controlled destination server process.
    let dest_child = Command::new(env!("CARGO_BIN_EXE_demo-dest"))
        .arg("--config")
        .arg(&dest_cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let dest_pid = dest_child.id();
    children.push(dest_child);
    wait_tcp_ready(&dest_addr, Duration::from_secs(5));

    // 2. Spawn Exit Relay OS process with redirected stdout/stderr logs.
    let exit_out_path = tmp.0.join("exit.out.log");
    let exit_err_path = tmp.0.join("exit.err.log");
    let exit_child = Command::new(env!("CARGO_BIN_EXE_relay-exit"))
        .arg("--config")
        .arg(tmp.0.join("exit.toml"))
        .arg("--log-level")
        .arg("debug")
        .stdout(Stdio::from(File::create(&exit_out_path).unwrap()))
        .stderr(Stdio::from(File::create(&exit_err_path).unwrap()))
        .spawn()
        .unwrap();
    let exit_pid = exit_child.id();
    children.push(exit_child);
    wait_tcp_ready(&exit_addr, Duration::from_secs(5));

    // 3. Spawn Middle Relay OS process with redirected stdout/stderr logs.
    let middle_out_path = tmp.0.join("middle.out.log");
    let middle_err_path = tmp.0.join("middle.err.log");
    let mid_child = Command::new(env!("CARGO_BIN_EXE_relay-middle"))
        .arg("--config")
        .arg(tmp.0.join("middle.toml"))
        .arg("--log-level")
        .arg("debug")
        .stdout(Stdio::from(File::create(&middle_out_path).unwrap()))
        .stderr(Stdio::from(File::create(&middle_err_path).unwrap()))
        .spawn()
        .unwrap();
    let middle_pid = mid_child.id();
    let mid_idx = children.push(mid_child);
    wait_tcp_ready(&mid_addr, Duration::from_secs(5));

    // 4. Spawn Entry Relay OS process with redirected stdout/stderr logs.
    let entry_out_path = tmp.0.join("entry.out.log");
    let entry_err_path = tmp.0.join("entry.err.log");
    let entry_child = Command::new(env!("CARGO_BIN_EXE_relay-entry"))
        .arg("--config")
        .arg(tmp.0.join("entry.toml"))
        .arg("--log-level")
        .arg("debug")
        .stdout(Stdio::from(File::create(&entry_out_path).unwrap()))
        .stderr(Stdio::from(File::create(&entry_err_path).unwrap()))
        .spawn()
        .unwrap();
    let entry_pid = entry_child.id();
    children.push(entry_child);
    wait_tcp_ready(&entry_addr, Duration::from_secs(5));

    let unique_pids: HashSet<u32> = [dest_pid, exit_pid, middle_pid, entry_pid]
        .into_iter()
        .collect();
    assert_eq!(unique_pids.len(), 4);

    let client_cfg = tmp.0.join("client.toml");

    // Case A: Small HTTP /health via separate OS client process (also checks no raw body leaked by default).
    let out_health = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--url")
        .arg(format!("http://{dest_addr}/health"))
        .output()
        .unwrap();
    let health_stdout = String::from_utf8_lossy(&out_health.stdout);
    assert!(
        out_health.status.success(),
        "health failed: {health_stdout}"
    );
    assert!(health_stdout.contains("connection: OK"));
    assert!(health_stdout.contains("outcome: OK (http_status=\"HTTP/1.1 200 OK\")"));
    assert!(!health_stdout.contains("private-relay-demo-dest"));

    // Case B: Empty (0B) raw request.
    let out_empty = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--target")
        .arg(&dest_addr)
        .arg("--data-bytes")
        .arg("0")
        .output()
        .unwrap();
    assert!(out_empty.status.success());
    assert!(String::from_utf8_lossy(&out_empty.stdout).contains("response_bytes: 0"));

    // Case C: Multi-chunk /medium + exact 65,536-byte boundary.
    let out_max = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--url")
        .arg(format!("http://{dest_addr}/max-64kib"))
        .output()
        .unwrap();
    let max_stdout = String::from_utf8_lossy(&out_max.stdout);
    assert!(out_max.status.success(), "max-64kib failed: {max_stdout}");
    assert!(max_stdout.contains("response_bytes: 65536"));

    let out_raw_max = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--target")
        .arg(&dest_addr)
        .arg("--data-bytes")
        .arg("65536")
        .output()
        .unwrap();
    assert!(out_raw_max.status.success());
    assert!(String::from_utf8_lossy(&out_raw_max.stdout).contains("response_bytes: 65536"));

    // Case D: Redirect 302 to 169.254.169.254 is returned safely and never followed.
    let out_redir = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--url")
        .arg(format!("http://{dest_addr}/redirect-ssrf"))
        .output()
        .unwrap();
    assert!(out_redir.status.success());
    assert!(String::from_utf8_lossy(&out_redir.stdout).contains("302 Found"));

    // Case E: Oversized request (65,537B) rejected locally.
    let out_big_req = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--target")
        .arg(&dest_addr)
        .arg("--data-bytes")
        .arg("65537")
        .output()
        .unwrap();
    assert!(!out_big_req.status.success());
    assert!(String::from_utf8_lossy(&out_big_req.stdout).contains("REJECTED_LOCALLY"));

    // Case F: Oversized destination response blocked at Exit (/oversized).
    let out_big_resp = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--url")
        .arg(format!("http://{dest_addr}/oversized"))
        .output()
        .unwrap();
    assert!(!out_big_resp.status.success());
    assert!(String::from_utf8_lossy(&out_big_resp.stdout).contains("PayloadTooLarge"));

    // Case G: Slow destination triggers Exit Timeout.
    let out_slow = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--url")
        .arg(format!("http://{dest_addr}/slow"))
        .output()
        .unwrap();
    assert!(!out_slow.status.success());
    assert!(String::from_utf8_lossy(&out_slow.stdout).contains("Timeout"));

    // Case H: Unlisted SSRF / closed destination failures.
    let out_denied = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--url")
        .arg("http://127.0.0.1:9/health")
        .output()
        .unwrap();
    assert!(!out_denied.status.success());
    assert!(String::from_utf8_lossy(&out_denied.stdout).contains("PolicyDenied"));

    let out_closed = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--url")
        .arg(format!("http://{closed_addr}/health"))
        .output()
        .unwrap();
    assert!(!out_closed.status.success());
    assert!(String::from_utf8_lossy(&out_closed.stdout).contains("ConnectFailed"));

    // Case I: Relay unavailable after killing Middle OS process cleanly triggers client failure.
    children.kill_index(mid_idx);
    let out_mid_dead = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .arg("--config")
        .arg(&client_cfg)
        .arg("--url")
        .arg(format!("http://{dest_addr}/health"))
        .output()
        .unwrap();
    assert!(!out_mid_dead.status.success());

    // Stop child relay/destination processes and flush handles before verifying log evidence.
    drop(children);

    let entry_out = fs::read_to_string(&entry_out_path).unwrap();
    let middle_out = fs::read_to_string(&middle_out_path).unwrap();
    let exit_out = fs::read_to_string(&exit_out_path).unwrap();
    assert!(entry_out.contains("STATUS=READY id=demo-entry-1 role=Entry"));
    assert!(middle_out.contains("STATUS=READY id=demo-middle-1 role=Middle"));
    assert!(exit_out.contains("STATUS=READY id=demo-exit-1 role=Exit"));

    let entry_err = fs::read_to_string(&entry_err_path).unwrap();
    let middle_err = fs::read_to_string(&middle_err_path).unwrap();
    let exit_err = fs::read_to_string(&exit_err_path).unwrap();

    for (label, log) in [
        ("entry", &entry_err),
        ("middle", &middle_err),
        ("exit", &exit_err),
    ] {
        assert!(
            log.contains("relay node started"),
            "{label} missing startup log: {log}"
        );
        assert!(
            log.contains("circuit hop established"),
            "{label} missing circuit hop log: {log}"
        );
        assert!(
            !log.contains("127.0.0.1")
                && !log.contains("/health")
                && !log.contains("private-relay-demo-dest"),
            "{label} log leaked sensitive IP/path/payload: {log}"
        );
    }

    // Verify no relay private/public keys leaked into any relay log file.
    for cfg_name in ["entry.toml", "middle.toml", "exit.toml"] {
        let raw_cfg = fs::read_to_string(tmp.0.join(cfg_name)).unwrap();
        for line in raw_cfg.lines() {
            if let Some((_, rhs)) = line.split_once("key_hex = ") {
                let key_hex = rhs.trim().trim_matches('"');
                assert!(key_hex.len() == 64);
                for log in [&entry_err, &middle_err, &exit_err] {
                    assert!(
                        !log.contains(key_hex),
                        "key hex leaked into relay stderr log"
                    );
                }
            }
        }
    }
}

#[test]
fn cli_probe_mode_validation_rejects_ambiguous_flags() {
    let p_noise = parse_client_args(&[
        "--probe-noise".into(),
        "127.0.0.1:9101".into(),
        "--pubkey-toml".into(),
        "entry.toml".into(),
    ])
    .unwrap();
    assert_eq!(p_noise.probe_noise_addr.as_deref(), Some("127.0.0.1:9101"));
    assert_eq!(p_noise.pubkey_toml, Some(PathBuf::from("entry.toml")));

    assert!(parse_client_args(&["--probe-noise".into(), "127.0.0.1:9101".into()]).is_err());
    assert!(parse_client_args(&["--pubkey-toml".into(), "entry.toml".into()]).is_err());

    let p_http = parse_client_args(&["--probe-http".into(), "127.0.0.1:9000".into()]).unwrap();
    assert_eq!(p_http.probe_http_addr.as_deref(), Some("127.0.0.1:9000"));

    assert!(parse_client_args(&[
        "--probe-http".into(),
        "127.0.0.1:9000".into(),
        "--config".into(),
        "client.toml".into()
    ])
    .is_err());
    assert!(parse_client_args(&[
        "--probe".into(),
        "127.0.0.1:9101".into(),
        "--probe-http".into(),
        "127.0.0.1:9000".into()
    ])
    .is_err());
}

#[test]
fn cli_readiness_probes_and_secret_file_separation_e2e() {
    let tmp = TempDirGuard::create("pr_cli_probes_sep");
    let entry_addr = format!("127.0.0.1:{}", free_loopback_port());
    let middle_addr = format!("127.0.0.1:{}", free_loopback_port());
    let exit_addr = format!("127.0.0.1:{}", free_loopback_port());
    let dest_addr = format!("127.0.0.1:{}", free_loopback_port());
    let closed_addr = format!("127.0.0.1:{}", free_loopback_port());
    let out_dir = tmp.0.join("split_secrets");

    let keygen_out = Command::new(env!("CARGO_BIN_EXE_relay-keygen"))
        .args([
            "--out-dir",
            out_dir.to_str().unwrap(),
            "--entry-addr",
            &entry_addr,
            "--middle-addr",
            &middle_addr,
            "--exit-addr",
            &exit_addr,
            "--allow-target",
            &dest_addr,
            "--split-dirs",
            "--key-file-path",
            "auto",
        ])
        .output()
        .unwrap();
    assert!(
        keygen_out.status.success(),
        "relay-keygen failed: {}",
        String::from_utf8_lossy(&keygen_out.stderr)
    );

    for (dir_name, cfg_name, key_name) in [
        ("entry", "entry.toml", "entry.key"),
        ("middle", "middle.toml", "middle.key"),
        ("exit", "exit.toml", "exit.key"),
    ] {
        let toml_txt = fs::read_to_string(out_dir.join(dir_name).join(cfg_name)).unwrap();
        assert!(!toml_txt.contains("private_key_hex"));
        assert!(toml_txt.contains("private_key_file"));
        assert!(toml_txt.contains("public_key_hex"));
        let key_txt = fs::read_to_string(out_dir.join(dir_name).join(key_name)).unwrap();
        assert_eq!(key_txt.trim().len(), 64);
        assert!(!toml_txt.contains(key_txt.trim()));
    }

    let mut children = ChildGuard::new();
    children.push(
        Command::new(env!("CARGO_BIN_EXE_demo-dest"))
            .args(["--listen", &dest_addr])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    children.push(
        Command::new(env!("CARGO_BIN_EXE_relay-exit"))
            .args(["--config", out_dir.join("exit/exit.toml").to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    children.push(
        Command::new(env!("CARGO_BIN_EXE_relay-middle"))
            .args([
                "--config",
                out_dir.join("middle/middle.toml").to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    children.push(
        Command::new(env!("CARGO_BIN_EXE_relay-entry"))
            .args([
                "--config",
                out_dir.join("entry/entry.toml").to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    wait_tcp_ready(&dest_addr, Duration::from_secs(5));
    wait_tcp_ready(&exit_addr, Duration::from_secs(5));
    wait_tcp_ready(&middle_addr, Duration::from_secs(5));
    wait_tcp_ready(&entry_addr, Duration::from_secs(5));

    // HTTP /health readiness probe succeeds on destination and fails on closed port.
    let http_ok = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .args(["--probe-http", &dest_addr])
        .output()
        .unwrap();
    assert!(
        http_ok.status.success(),
        "http probe failed: {}",
        String::from_utf8_lossy(&http_ok.stderr)
    );
    let http_fail = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .args(["--probe-http", &closed_addr])
        .output()
        .unwrap();
    assert!(!http_fail.status.success());

    // Noise_IK readiness probe succeeds against matching relay identity and fails on wrong pubkey.
    for (addr, toml_rel) in [
        (&entry_addr, "entry/entry.toml"),
        (&middle_addr, "middle/middle.toml"),
        (&exit_addr, "exit/exit.toml"),
    ] {
        let probe_ok = Command::new(env!("CARGO_BIN_EXE_relay-client"))
            .args([
                "--probe-noise",
                addr,
                "--pubkey-toml",
                out_dir.join(toml_rel).to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            probe_ok.status.success(),
            "noise probe failed for {toml_rel}: {}",
            String::from_utf8_lossy(&probe_ok.stderr)
        );
    }

    let wrong_identity = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .args([
            "--probe-noise",
            &entry_addr,
            "--pubkey-toml",
            out_dir.join("exit/exit.toml").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!wrong_identity.status.success());

    // Full 3-hop request traverses secret-separated relays cleanly.
    let req_out = Command::new(env!("CARGO_BIN_EXE_relay-client"))
        .args([
            "--config",
            out_dir.join("client/client.toml").to_str().unwrap(),
            "--url",
            &format!("http://{dest_addr}/health"),
            "--print-body",
        ])
        .output()
        .unwrap();
    assert!(
        req_out.status.success(),
        "3-hop request through secret-separated relays failed: {}",
        String::from_utf8_lossy(&req_out.stderr)
    );
    assert!(String::from_utf8_lossy(&req_out.stdout).contains("private-relay-demo-dest"));
}
