use std::process::ExitCode;

use private_relay_cli::run_client_cli;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run_client_cli(&args).await
}
