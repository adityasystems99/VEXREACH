#![no_main]

use libfuzzer_sys::fuzz_target;
use private_relay_cli::{
    build_http_request_from_url, parse_http_health_response, parse_http_request_path,
    parse_sanitized_http_status,
};

fuzz_target!(|data: &[u8]| {
    if let Some(status) = parse_sanitized_http_status(data) {
        assert!(!status.chars().any(|c| c.is_control()));
    }
    let _ = parse_http_health_response(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_http_request_path(s);
        let _ = build_http_request_from_url(s);
    }
});
