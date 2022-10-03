use clap::{Parser, Subcommand};

// HAR file analyzer
#[derive(Parser, Debug)]
#[command(author, version, about, propagate_version = true)]
pub struct Cli {
    /// Subcommands
    #[command(subcommand)]
    pub command: Command,

    /// Verbose output
    #[arg(long)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Analysis har file to get domain list with additional information
    #[command(visible_alias = "a")]
    Analysis(AnalysisArg),
}

#[derive(clap::Args, Debug)]
pub struct AnalysisArg {
    /// har file
    #[arg(short='f', long, value_hint=clap::ValueHint::FilePath, default_value = "./har.har")]
    pub har: String,

    /// dns server, default use system
    #[arg(short, long)]
    pub dns: Option<String>,

    /// Verbose log
    #[arg(long)]
    pub verbose: bool,
}
