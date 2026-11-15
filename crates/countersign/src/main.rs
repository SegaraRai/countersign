use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use countersign::{CliError, Command, Context, execute, keygen};
use countersign_core::Store;
use countersign_store_sqlite::SqliteStore;
use countersignd::config::Config;

#[derive(Debug, Parser)]
#[command(version, about = "Administer countersign on the daemon's host")]
struct Cli {
    /// Configuration file (the daemon's).
    #[arg(long, short, env = "COUNTERSIGN_CONFIG", default_value = "/etc/countersign/config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("countersign: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    if let Command::Keygen { path, format, force } = &cli.command {
        return keygen(path, *format, *force);
    }
    let config = Config::load(&cli.config).map_err(|e| CliError::Usage(e.to_string()))?;
    let path = &config.store.path;
    if !path.exists() {
        return Err(CliError::Usage(format!("no database at {} (has countersignd run?)", path.display())));
    }
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&format!("sqlite://{}", path.display())).await?);
    let backends = countersignd::build_backends(&config).map_err(|e| CliError::Usage(e.to_string()))?;
    let ctx = Context { config, store, backends };
    let mut out = std::io::stdout().lock();
    execute(cli.command, ctx, &mut out).await
}
