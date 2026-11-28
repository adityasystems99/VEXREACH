#![no_main]

use libfuzzer_sys::fuzz_target;
use private_relay_cli::DestServerConfig;
use private_relay_network::{decode_hex_32, ClientConfigFile, RelayConfig};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = RelayConfig::from_toml_str(&s);
    let _ = RelayConfig::read_public_key_from_toml_str(&s);
    let _ = ClientConfigFile::from_toml_str(&s);
    let _ = DestServerConfig::from_toml_str(&s);
    let _ = decode_hex_32(&s);
});
