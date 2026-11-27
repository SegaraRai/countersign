use std::process::ExitCode;

use clap::Parser as _;
use countersign_ask::{Cli, EXIT_ERROR, exit_code_for_state, run};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli).await {
        Ok(resp) => {
            if let Ok(json) = serde_json::to_string_pretty(&resp) {
                println!("{json}");
            }
            ExitCode::from(exit_code_for_state(&resp.state))
        }
        Err(e) => {
            eprintln!("countersign-ask: {e}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}
