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
    /// Create the shared key file (refuses to overwrite without --force).
    Keygen {
        /// Overwrite an existing key file.
        #[arg(long)]
        force: bool,
    },
    /// Run the sync daemon in the foreground.
    Run {
        /// Log clipboard content (debugging only; never use in production).
        #[arg(long)]
        log_content: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error(transparent)]
    Key(#[from] crate::keys::KeyError),
    #[error(transparent)]
    Keygen(#[from] crate::keys::KeygenError),
    #[error(transparent)]
    DeviceId(#[from] crate::keys::DeviceIdError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("cannot determine the home directory")]
    NoHome,
}

pub fn dispatch(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Doctor => {
            let (cfg, path) = Config::load_default()?;
            print!("{}", crate::doctor::report(&cfg, &path));
            Ok(())
        }
        Command::Keygen { force } => keygen(force),
        Command::Run { log_content } => run_daemon(log_content),
    }
}

fn keygen(force: bool) -> Result<(), CliError> {
    let path = crate::paths::key_file().ok_or(CliError::NoHome)?;
    // The key material goes to the file only; never print it.
    crate::keys::generate_key_file(&path, force)?;
    println!("key written: {}", path.display());
    println!();
    println!("Every device on the LAN must use this same key. Copy the file");
    println!("securely, e.g.:");
    println!();
    println!("  scp {} other-host:{}", path.display(), path.display());
    println!();
    println!("Anyone holding this key can read and inject clipboard content.");
    Ok(())
}

fn run_daemon(log_content: bool) -> Result<(), CliError> {
    use crate::clipboard::{self, BackendPlan, DataControlSupport, plan_backend};
    use crate::engine::{Engine, EngineConfig};
    use crate::net::UdpTransport;

    let (cfg, config_path) = Config::load_default()?;
    tracing::debug!(path = %config_path.display(), "loaded config");

    let key_path = crate::paths::key_file().ok_or(CliError::NoHome)?;
    let key = crate::keys::read_key(&key_path)?;
    let device_id_path = crate::paths::device_id_file().ok_or(CliError::NoHome)?;
    let device_id = crate::keys::load_or_create_device_id(&device_id_path)?;

    let session = clipboard::detect_session();
    let data_control = if session == clipboard::Session::Wayland {
        clipboard::probe_data_control()
    } else {
        DataControlSupport::NotApplicable
    };
    let (plan, note) = plan_backend(cfg.backend, session, &data_control);
    if let Some(note) = &note {
        tracing::warn!("{note}");
    }
    let backend = match plan.create(&cfg) {
        Ok(backend) => backend,
        Err(e) if plan != BackendPlan::Polling => {
            tracing::warn!("{plan} backend unavailable ({e}); falling back to polling");
            BackendPlan::Polling.create(&cfg)?
        }
        Err(e) => return Err(e.into()),
    };
    tracing::info!(backend = %plan, port = cfg.port, "clipboard backend selected");

    let transport = UdpTransport::new(
        cfg.port,
        cfg.interface_allow.clone(),
        cfg.interface_deny.clone(),
    )?;

    let inline_max = cfg.effective_inline_max_bytes();
    let engine_cfg = EngineConfig {
        key,
        device_id,
        max_text_bytes: inline_max,
        inline_max_bytes: inline_max,
        max_transfer_bytes: cfg.max_transfer_bytes,
        tcp_port: cfg.tcp_port,
        transfer_ttl: std::time::Duration::from_secs(cfg.transfer_ttl_secs),
        fetch_timeout: std::time::Duration::from_secs(cfg.fetch_timeout_secs),
        skip_sensitive: cfg.skip_sensitive,
        log_content,
        ..EngineConfig::default()
    };
    let engine = Engine::new(backend, transport, engine_cfg);

    // TCP side channel for large text, for the daemon's lifetime. If the
    // port is taken (e.g. a second instance on one machine), inline sync
    // keeps working; only serving large transfers is unavailable here.
    match crate::tcp_server::bind_listener(cfg.tcp_port) {
        Ok(listener) => {
            tracing::info!(port = cfg.tcp_port, "TCP transfer listener bound");
            crate::tcp_server::spawn_server(
                listener,
                key,
                engine.transfer_store(),
                crate::tcp_server::IDLE_TIMEOUT,
                std::time::Duration::from_secs(cfg.fetch_timeout_secs),
            );
        }
        Err(e) => {
            tracing::warn!(
                "TCP listener on port {} unavailable ({e}); large-text serving disabled, inline sync continues",
                cfg.tcp_port
            );
        }
    }

    tracing::info!("clipcast started; press Ctrl-C to stop");
    engine.run();
    tracing::info!("clipcast stopped");
    Ok(())
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
