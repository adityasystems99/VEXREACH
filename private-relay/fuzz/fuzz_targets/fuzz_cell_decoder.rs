#![no_main]

use libfuzzer_sys::fuzz_target;
use private_relay_protocol::{Cell, DecodedRequest, RelayHopPlaintext};

fuzz_target!(|data: &[u8]| {
    if let Ok(cell) = Cell::decode(data) {
        let re = cell.encode().expect("decoded cell must always re-encode");
        assert_eq!(re, data);
    }
    if let Ok(hop_pt) = RelayHopPlaintext::decode(data) {
        let _ = hop_pt.encode().expect("decoded hop plaintext must re-encode");
    }
    let _ = DecodedRequest::parse(data);
});
