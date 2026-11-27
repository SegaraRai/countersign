use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;

use countersign::{CliError, Command, Context, execute, host_key, keygen, signing_key, vapid_key};
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
    // These need no configuration or database.
    match &cli.command {
        Command::Keygen { path, format, force } => return keygen(path, *format, *force),
        Command::HostKey { path, force } => {
            println!("{}", host_key(path, *force)?);
            return Ok(());
        }
        Command::SigningKey { path, public, force } => {
            println!("{}", signing_key(path, *public, *force)?);
            return Ok(());
        }
        Command::VapidKey { path, public, force } => {
            println!("{}", vapid_key(path, *public, *force)?);
            return Ok(());
        }
        _ => {}
    }
    let config = Config::load(&cli.config).map_err(|e| CliError::Usage(e.to_string()))?;
    let path = &config.store.path;
    if !path.exists() {
        return Err(CliError::Usage(format!("no database at {} (has countersignd run?)", path.display())));
    }
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(&format!("sqlite://{}", path.display())).await?);
    let backends = countersignd::build_backends(&config, &store).map_err(|e| CliError::Usage(e.to_string()))?;
    let ctx = Context { config, store, backends };
    let mut out = std::io::stdout().lock();
    execute(cli.command, ctx, &mut out).await
}
