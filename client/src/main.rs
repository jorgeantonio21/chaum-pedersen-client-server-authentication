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
    dotenv::dotenv().expect("Failed to load .env variables");

    let cli = Cli::parse();
    let server_addr = std::env::var("CLIENT_DEST_SERVER_ADDR")
        .expect("Failed to retrieve `CLIENT_DEST_SERVER_ADDR` .env variable");

    info!("Connecting to server at address {server_addr}... ");
    let mut client = ChaumPedersenAuthClient::new(server_addr).await?;

    match cli.command {
        Commands::Register { name, password } => {
            info!("Registering user with name: {name} ...");
            let secret = calculate_password_hash(password);
            client.register_user(&name, &secret).await?;
            println!("User registered successfully !")
        }
        Commands::Login { name, password } => {
            info!("User {name} logging in ...");
            let secret = calculate_password_hash(password);
            let session_id = client.authenticate_user(&name, &secret).await?;
            println!(
                "User is successfully authenticated, with session_id = {}",
                session_id
            );
        }
    }

    Ok(())
}
