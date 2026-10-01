use std::process::ExitCode;

use clap::Parser;

use clipcast::cli::{Cli, dispatch, init_tracing};

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("clipcast: {e}");
            ExitCode::FAILURE
        }
    }
}
