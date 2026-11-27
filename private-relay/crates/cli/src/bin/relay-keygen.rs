use std::process::ExitCode;

use private_relay_cli::run_keygen;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run_keygen(&args)
}
