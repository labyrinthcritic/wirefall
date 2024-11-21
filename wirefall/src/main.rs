mod config;
mod nft;

use std::path::PathBuf;

use colored::Colorize;
use config::Config;

fn main() {
    let cli = <Cli as clap::Parser>::parse();

    match cli.command {
        Command::Apply { config, verbose } => {
            let config_path = config.unwrap_or(PathBuf::from("/etc/wirefall/default.toml"));
            let Ok(config_contents) = std::fs::read_to_string(config_path) else {
                eprintln!(
                    "{} no configuration was found.",
                    " error:".bright_red().bold()
                );
                eprintln!(
                    " provide one or write to the default path at /etc/wirefall/default.toml"
                );
                return;
            };

            match toml::from_str::<Config>(&config_contents) {
                Ok(config) => {
                    let value = nft::construct_json(&config);
                    let json = serde_json::to_string_pretty(&value).unwrap();

                    if verbose {
                        println!("payload for libnftables-json:");
                        println!("{json}");
                    }

                    match run(&json) {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("{}", " nftables raised an error:".bright_red().bold(),);
                            for line in e.trim().split('\n') {
                                let line = line.trim();
                                if !line.is_empty() {
                                    eprintln!("   {line}");
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        " {} failed to parse config{}: {:?}",
                        "error:".bright_red().bold(),
                        e.span()
                            .map(|range| format!(" at {range:?}"))
                            .unwrap_or("".to_string()),
                        e.message(),
                    );
                }
            }
        }
    }
}

fn run(json: &str) -> Result<(), String> {
    let mut context = nftables::Context::new().ok_or("could not create context".to_string())?;
    let output = context.run_command(json)?;
    let output = output.trim();
    if !output.is_empty() {
        println!("output: {output}");
    }
    Ok(())
}

#[derive(clap::Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    Apply {
        config: Option<PathBuf>,
        #[arg(short, long)]
        verbose: bool,
    },
}
