#![no_main]

use libfuzzer_sys::fuzz_target;
use private_relay_crypto::{
    HopHandshakeInitiator, HopHandshakeResponder, LinkInitiator, LinkResponder, StaticKeypair,
};

fuzz_target!(|data: &[u8]| {
    let Ok(client_kp) = StaticKeypair::generate() else {
        return;
    };
    let Ok(relay_kp) = StaticKeypair::generate() else {
        return;
    };
    if let Ok(resp) = LinkResponder::new(&relay_kp) {
        let _ = resp.process_msg1_and_finish(data);
    }
    if let Ok(init) = LinkInitiator::new(&client_kp, *relay_kp.public()) {
        let _ = init.finish_with_msg2(data);
    }
    if let Ok(resp) = HopHandshakeResponder::new(1, &relay_kp) {
        let _ = resp.process_msg1_and_finish(data);
    }
    if let Ok(init) = HopHandshakeInitiator::new(2, *relay_kp.public()) {
        let _ = init.finish_with_msg2(data);
    }
});
