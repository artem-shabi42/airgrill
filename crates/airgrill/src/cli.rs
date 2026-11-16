use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "airgrill",
    about = "Domain-routed proxy client: direct / DPI desync / VLESS proxy",
    version
)]
pub struct Cli {
    /// Path to the TOML configuration.
    #[arg(
        short,
        long,
        global = true,
        env = "AIRGRILL_CONFIG",
        default_value = "/etc/airgrill/config.toml"
    )]
    pub config: PathBuf,

    /// Increase log verbosity (repeatable).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Run the daemon.
    Run(RunArgs),
    /// Validate the configuration and print a summary.
    Check,
    /// Explain how a domain or IP would be routed.
    Route { target: String },
    /// Manage the nftables / policy-routing rules.
    Rules(RulesArgs),
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Print the generated nftables rules and exit.
    #[arg(long)]
    pub dry_run: bool,
    /// Do not touch nftables; assume the rules are already installed.
    #[arg(long)]
    pub no_rules: bool,
    /// Disable the DPI desync engine (connections still go direct).
    #[arg(long)]
    pub no_dpi: bool,
    /// Disable the userspace UDP TUN.
    #[arg(long)]
    pub no_tun: bool,
    /// Disable the DNS proxy.
    #[arg(long)]
    pub no_dns: bool,
    /// Start even if another policy-routing VPN/TUN is active.  This can break
    /// that VPN (airgrill would intercept its own upstream traffic).
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub cmd: RulesCmd,
}

#[derive(Debug, Subcommand)]
pub enum RulesCmd {
    /// Print the generated nftables script.
    Print,
    /// Install nftables and TPROXY policy-routing rules.
    Install {
        #[arg(long, default_value = "nft")]
        nft: String,
    },
    /// Remove the nftables table and policy-routing rules.
    Remove {
        #[arg(long, default_value = "nft")]
        nft: String,
    },
}
