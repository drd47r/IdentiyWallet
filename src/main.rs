pub mod cli;
pub mod keystore;
pub mod wallet;

use clap::Parser;
use cli::Cli;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();
    if let Err(err) = cli::run(cli).await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
