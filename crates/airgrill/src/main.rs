mod app;
mod cli;
mod daemon;
mod mixed;
mod state;
mod tcp;
mod udp;

use clap::Parser;

#[tokio::main]
async fn main() {
    let cli = cli::Cli::parse();
    if let Err(e) = app::dispatch(cli).await {
        eprintln!("airgrill: {e:#}");
        std::process::exit(1);
    }
}
