use client::{
    calculate_password_hash,
    client::{AuthZKPClient, ChaumPedersenAuthClient},
};
use log::info;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    // user registration
    Register {
        // user name
        #[arg(short, long)]
        name: String,
        // user password
        #[arg(short, long)]
        password: String,
    },
    // user authentication
    Login {
        // user name
        #[arg(short, long)]
        name: String,
        // user password
        #[arg(short, long)]
        password: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    info!("Connecting to server... ");
    let mut client = ChaumPedersenAuthClient::new("https://server:5001").await?;

    match cli.command {
        Commands::Register { name, password } => {
            info!("Registering user with name: {name} ...");
            let secret = calculate_password_hash(password);
            client.register_user(&name, &secret).await?;
        }
        Commands::Login { name, password } => {
            info!("User {name} logging in ...");
            let secret = calculate_password_hash(password);
            let session_id = client.authenticate_user(&name, &secret).await?;
            info!("User has successfully authenticated, with session_id = {session_id}");
        }
    }

    Ok(())
}
