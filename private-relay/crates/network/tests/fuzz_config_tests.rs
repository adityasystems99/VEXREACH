use std::fs;
use std::net::IpAddr;

use private_relay_crypto::StaticKeypair;
use private_relay_network::{
    decode_hex_32, decode_hex_32_zeroizing, encode_hex, ClientConfigFile, DestinationPolicy,
    RelayConfig, RelayRole, MAX_CONFIG_TOML_BYTES,
};

#[test]
fn fuzz_regression_toml_parse_errors_never_leak_inline_private_key() {
    let kp = StaticKeypair::generate().unwrap();
    let secret_canary = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let malformed_toml = format!(
        "id = \"entry-canary\"\nrole = \"entry\"\nlisten_addr = \"127.0.0.1:9101\"\npublic_key_hex = \"{}\"\nprivate_key_hex = \"{}\"\n[invalid_unclosed\n",
        encode_hex(kp.public()),
        secret_canary
    );
    let err = RelayConfig::from_toml_str(&malformed_toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        !msg.contains(secret_canary),
        "TOML parse error leaked secret material: {msg}"
    );

    // Adversarial malformed TOML variants: unclosed quote around secret, bad escape, integer type mismatch,
    // secret placed on broken key/comment lines, and missing fields.
    let pk_hex = encode_hex(kp.public());
    let adversarial_canaries = [
        format!("private_key_hex = \"{secret_canary}\nbroken"),
        format!("private_key_hex = \"{secret_canary}\\z\""),
        format!("private_key_hex = {secret_canary}"),
        format!("id = \"e\"\nrole = \"entry\"\nlisten_addr = \"127.0.0.1:9101\"\npublic_key_hex = \"{pk_hex}\"\nprivate_key_hex = 12345 # {secret_canary}"),
        format!("[{secret_canary}\nprivate_key_hex = \"{secret_canary}\""),
    ];
    for case in &adversarial_canaries {
        let e1 = RelayConfig::from_toml_str(case).unwrap_err().to_string();
        assert!(
            !e1.contains(secret_canary),
            "Adversarial TOML RelayConfig error leaked secret canary: {e1}"
        );
        if let Err(e2) = RelayConfig::read_public_key_from_toml_str(case) {
            assert!(
                !e2.to_string().contains(secret_canary),
                "Adversarial TOML read_public_key error leaked secret canary: {e2}"
            );
        }
        let e3 = ClientConfigFile::from_toml_str(case)
            .unwrap_err()
            .to_string();
        assert!(
            !e3.contains(secret_canary),
            "Adversarial TOML ClientConfigFile error leaked secret canary: {e3}"
        );
    }

    // Same guarantee for read_public_key_from_toml_str and ClientConfigFile on base malformed TOML.
    let pk_err = RelayConfig::read_public_key_from_toml_str(&malformed_toml).unwrap_err();
    assert!(!pk_err.to_string().contains(secret_canary));
    let cli_err = ClientConfigFile::from_toml_str(&malformed_toml).unwrap_err();
    assert!(!cli_err.to_string().contains(secret_canary));

    // Oversized configuration (> MAX_CONFIG_TOML_BYTES) is rejected cleanly before TOML parser allocation.
    let oversized_toml = " ".repeat(MAX_CONFIG_TOML_BYTES + 1);
    assert!(RelayConfig::from_toml_str(&oversized_toml).is_err());
    assert!(RelayConfig::read_public_key_from_toml_str(&oversized_toml).is_err());
    assert!(ClientConfigFile::from_toml_str(&oversized_toml).is_err());

    // Zeroizing decode helper returns exact 32-byte key and without_inline_secret zeroes secret copy.
    let z = decode_hex_32_zeroizing(secret_canary).unwrap();
    assert_eq!(z.len(), 32);
    let mut cfg = RelayConfig::with_generated_keypair("z", RelayRole::Exit, "127.0.0.1:9103", &kp);
    let stripped = cfg.without_inline_secret("/run/secrets/private_key_hex");
    assert!(stripped.private_key_hex.is_empty());
    assert_eq!(
        stripped.private_key_file.as_deref(),
        Some("/run/secrets/private_key_hex")
    );
    cfg.scrub_private_key();
    assert!(cfg.private_key_hex.is_empty());
}

#[test]
fn fuzz_property_config_secret_file_and_ssrf_boundaries() {
    let dir = std::env::temp_dir().join(format!("pr_fuzz_cfg_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let kp = StaticKeypair::generate().unwrap();
    let base_cfg =
        RelayConfig::with_generated_keypair("fuzz-exit", RelayRole::Exit, "127.0.0.1:9103", &kp);

    // 1. Secret file pointing to directory instead of regular file fails cleanly.
    let dir_secret_cfg = base_cfg.without_inline_secret(dir.to_string_lossy().into_owned());
    assert!(RelayConfig::from_toml_str(&dir_secret_cfg.to_toml_string().unwrap()).is_err());

    // 2. Secret file > 256 bytes rejected cleanly.
    let oversized_key_path = dir.join("oversized.key");
    fs::write(&oversized_key_path, "a".repeat(300)).unwrap();
    let big_secret_cfg =
        base_cfg.without_inline_secret(oversized_key_path.to_string_lossy().into_owned());
    assert!(RelayConfig::from_toml_str(&big_secret_cfg.to_toml_string().unwrap()).is_err());

    // 3. Valid 64-hex key file with trailing newline succeeds, and scrub + Debug hide secret.
    let valid_key_path = dir.join("valid.key");
    fs::write(
        &valid_key_path,
        format!("{}\n", encode_hex(kp.secret_bytes())),
    )
    .unwrap();
    let mut file_cfg = RelayConfig::from_toml_str(
        &base_cfg
            .without_inline_secret(valid_key_path.to_string_lossy().into_owned())
            .to_toml_string()
            .unwrap(),
    )
    .unwrap();
    let dbg_str = format!("{file_cfg:?}");
    assert!(!dbg_str.contains(&encode_hex(kp.secret_bytes())));
    file_cfg.scrub_private_key();
    assert!(file_cfg.private_key_hex.is_empty());

    // 4. Randomized malformed hex keys never panic and always return Err.
    for len in [0usize, 1, 63, 65, 128] {
        assert!(decode_hex_32(&"a".repeat(len)).is_err());
    }
    assert!(decode_hex_32(&format!("{}z", "0".repeat(63))).is_err());

    // 5. Fuzz-derived malformed SSRF targets & IPv4/IPv6 bypass patterns rejected cleanly.
    let policy = DestinationPolicy::default();
    for weird in [
        "",
        "127.0.0.1",
        "127.0.0.1:0",
        "localhost\0:80",
        "example.com:80\r\n",
        "[fe80::1%25eth0]:80",
        "[::1]:0",
        &format!("{}:80", "a".repeat(260)),
    ] {
        assert!(
            futures_lite_or_tokio_deny(&policy, weird),
            "expected SSRF policy rejection for '{weird}'"
        );
    }

    // All-zero, multicast, documentation, NAT64, IPv4-mapped metadata always denied.
    for ip_str in [
        "0.0.0.0",
        "100.127.255.254",
        "198.18.0.1",
        "192.0.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:169.254.169.254",
        "::ffff:10.0.0.1",
        "3fff::1",
        "fe80::dead:beef",
        "ff02::1",
    ] {
        let ip: IpAddr = ip_str.parse().unwrap();
        assert!(
            policy.validate_ip(ip).is_err(),
            "expected validate_ip denial for {ip_str}"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

fn futures_lite_or_tokio_deny(policy: &DestinationPolicy, target: &str) -> bool {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(policy.resolve_and_validate(target)).is_err()
}
