#![no_main]

use libfuzzer_sys::fuzz_target;
use private_relay_protocol::{decode_wire_record, LinkFrame, OuterFramePlaintext};

fuzz_target!(|data: &[u8]| {
    let _ = decode_wire_record(data);
    if let Ok(frame) = OuterFramePlaintext::unpack_link_frame(data) {
        if let LinkFrame::Cell(cell) = frame {
            let _ = cell.encode().expect("unpacked cell must re-encode");
        }
    }
});
