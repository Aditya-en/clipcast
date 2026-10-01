//! Command line interface.

use clap::{Parser, Subcommand};

use crate::config::Config;

#[derive(Parser, Debug)]
#[command(
    name = "clipcast",
    version,
    about = "LAN clipboard sync daemon (plain text, encrypted UDP broadcast)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print diagnostics: session, backend, interfaces, key, device_id.
    Doctor,
    // Keygen and Run are added in a later milestone.
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
}

pub fn dispatch(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Doctor => {
            let (cfg, path) = Config::load_default()?;
            print!("{}", crate::doctor::report(&cfg, &path));
            Ok(())
        }
    }
}

/// Initialize tracing to stderr. `RUST_LOG` is respected; default level is
/// `info` (use `RUST_LOG=debug` for packet-level detail).
pub fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("clipcast=info,info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
