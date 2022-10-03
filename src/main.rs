use clap::Parser;
use har_analyzer::analysis;
use log::warn;
use tabled::{Style, Table};

mod cli;
mod logger;

fn main() {
    let cli = cli::Cli::parse();

    // init logger
    logger::init(&cli);

    match cli.command {
        cli::Command::Analysis(arg) => {
            let result = analysis::analysis(&arg.har, arg.dns);
            match result {
                Ok(records) => {
                    let data = records.iter().map(|v| v.to_tabled()).collect::<Vec<_>>();
                    let mut table = Table::new(&data);
                    table.with(Style::psql());
                    println!("{}", table);
                }
                Err(err) => {
                    warn!("{:?}", err);
                }
            }
        }
    }
}
