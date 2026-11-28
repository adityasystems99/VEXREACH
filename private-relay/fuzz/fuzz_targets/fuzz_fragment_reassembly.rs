#![no_main]

use libfuzzer_sys::fuzz_target;
use private_relay_protocol::{InnerFlags, InnerPayload, MessageReassembler, RequestId};

fuzz_target!(|data: &[u8]| {
    let rid = RequestId::new(1).unwrap();
    let mut reasm = MessageReassembler::for_request(rid);
    if let Ok(chunk) = InnerPayload::decode(data) {
        let _ = reasm.push(chunk);
    }
    if data.len() >= 8 {
        let mut raw_reasm = MessageReassembler::for_response(rid);
        let raw_chunk = InnerPayload {
            request_id: rid,
            chunk_index: u16::from_be_bytes([data[4], data[5]]),
            chunk_count: u16::from_be_bytes([data[6], data[7]]),
            flags: InnerFlags::from_u8(data[3] & 0x07).unwrap(),
            fragment: data[8..].to_vec(),
        };
        let _ = raw_reasm.push(raw_chunk);
    }
});
