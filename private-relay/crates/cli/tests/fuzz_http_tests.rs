use private_relay_cli::{
    build_http_request_from_url, parse_http_health_response, parse_http_request_path,
    parse_sanitized_http_status, DestServerConfig,
};

#[test]
fn fuzz_http_response_parser_and_url_invariants() {
    // 1. Control-character stripping and length bounding on status lines.
    let dirty = b"HTTP/1.1 200 OK\x1b[31mFAKE\x00\x07\r\nContent-Length: 0\r\n\r\n";
    let status = parse_sanitized_http_status(dirty).unwrap();
    assert!(!status.chars().any(|c| c.is_control()));
    assert!(status.starts_with("HTTP/1.1 200 OK"));

    let huge = vec![b'A'; 4096];
    assert!(parse_sanitized_http_status(&huge).is_none());
    let huge_http = [b"HTTP/1.1 200 ".as_slice(), &huge].concat();
    assert!(parse_sanitized_http_status(&huge_http).unwrap().len() <= 64);

    // 2. HTTP /health probe response validator cases (arbitrary/malformed inputs must never panic).
    assert!(parse_http_health_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}"
    )
    .is_ok());
    assert!(parse_http_health_response(b"HTTP/1.0 200\n\n{\"status\":\"ok\"}").is_ok());

    for bad in [
        b"".as_slice(),
        b"\xFF\xFE\x00\x01".as_slice(),
        b"HTTP/1.1 2000 Fake\r\n\r\n{\"status\":\"ok\"}".as_slice(),
        b"HTTP/1.1 500 Internal\r\n\r\n{\"status\":\"ok\"}".as_slice(),
        b"HTTP/1.1 200 OK\r\n{\"status\":\"ok\"}".as_slice(),
        b"HTTP/1.1 200 OK\r\n\r\n{\"status\":\"bad\"}".as_slice(),
    ] {
        assert!(parse_http_health_response(bad).is_err());
    }

    // 3. Request path & URL sanitizer edge cases.
    assert_eq!(
        parse_http_request_path("GET /abc?x=1 HTTP/1.1\r"),
        Some("/abc")
    );
    assert_eq!(parse_http_request_path("DELETE /abc HTTP/1.1"), None);
    assert_eq!(parse_http_request_path("GET /abc HTTP/2.0"), None);
    assert!(build_http_request_from_url("http://example.com/ok").is_ok());
    assert!(build_http_request_from_url("http://example.com\nHost: evil").is_err());
    assert!(DestServerConfig::from_toml_str("listen_addr = 'bad'").is_err());
    assert!(DestServerConfig::from_toml_str(&" ".repeat(600 * 1024)).is_err());
    assert!(private_relay_cli::parse_client_args(&[
        "--config".into(),
        "c.toml".into(),
        "--target".into(),
        "example.com:80".into(),
        "--data-bytes".into(),
        usize::MAX.to_string(),
    ])
    .is_err());
}
