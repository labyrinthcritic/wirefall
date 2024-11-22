mod config;
mod nft;

use std::path::PathBuf;

use colored::Colorize;
use config::Config;

const DEFAULT_CONFIG_PATH: &str = "/etc/wirefall/wirefall.toml";

fn main() {
    let success = run();
    if !success {
        std::process::exit(1);
    }
}

fn run() -> bool {
    let cli = <Cli as clap::Parser>::parse();

    let mut context = nftables::Context::new()
        .ok_or("could not create context".to_string())
        .unwrap();

    match cli.command {
        Command::Apply { path } => {
            if let Some(config) = get_config(path) {
                let actions = nft::actions(&config);
                let payload = nft::payload(actions);
                let json = serde_json::to_string(&payload).unwrap();

                match context.run_command(&json, false) {
                    Ok(_) => {
                        eprintln!(
                            " {}",
                            "Applied netfilter configuration.".bright_green().bold()
                        );
                        return true;
                    }
                    Err(e) => {
                        report_nftables_error(&e);
                    }
                }
            }
        }
        Command::Inspect { path } => {
            if let Some(config) = get_config(path) {
                let actions = nft::actions(&config);
                let payload = nft::payload(actions);
                let json = serde_json::to_string_pretty(&payload).unwrap();

                println!("\n{json}\n");
                return true;
            }
        }
    }

    false
}

fn get_config(path: Option<PathBuf>) -> Option<Config> {
    let config_path = path.unwrap_or(PathBuf::from(DEFAULT_CONFIG_PATH));
    let Ok(config) = std::fs::read_to_string(config_path) else {
        eprintln!(
            "{} no configuration was found.",
            " error:".bright_red().bold()
        );
        eprintln!(
            " provide one or write to the default path at {}",
            DEFAULT_CONFIG_PATH
        );
        return None;
    };

    match toml::from_str::<Config>(&config) {
        Ok(config) => Some(config),
        Err(e) => {
            report_parse_error(&e);
            None
        }
    }
}

fn report_parse_error(error: &toml::de::Error) {
    eprintln!(
        " {} failed to parse config{}: {:?}",
        "error:".bright_red().bold(),
        error
            .span()
            .map(|range| format!(" at {range:?}"))
            .unwrap_or("".to_string()),
        error.message(),
    );
}

fn report_nftables_error(error: &str) {
    eprintln!("{}", " nftables raised an error:".bright_red().bold(),);
    for line in error.trim().split('\n') {
        let line = line.trim();
        if !line.is_empty() {
            eprintln!("   {line}");
        }
    }
}

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Apply a configuration.
    Apply { path: Option<PathBuf> },
    /// Display the ruleset of a configuration.
    Inspect { path: Option<PathBuf> },
}
