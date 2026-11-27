use std::process::ExitCode;

use private_relay_cli::run_relay_cli;
use private_relay_network::RelayRole;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run_relay_cli(RelayRole::Middle, "relay-middle", &args).await
}
