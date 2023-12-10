use client::client_auth::{
    auth_client::AuthClient, AuthenticationChallengeRequest, RegisterRequest,
};
use log::info;

use clap::{Parser, Subcommand};
use tonic::Request;

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
    let mut client = AuthClient::connect("https://localhost:5001").await?;

    match cli.command {
        Commands::Register { name, password } => {
            info!("Registering user with name: {name} ...");
            client
                .register(Request::new(RegisterRequest {
                    user: name,
                    y1: 0,
                    y2: 1,
                }))
                .await?;
        }
        Commands::Login { name, password } => {
            info!("User {name} logging in ...");

            client
                .create_authentication_challenge(Request::new(AuthenticationChallengeRequest {
                    user: name,
                    r1: 0,
                    r2: 1,
                }))
                .await?;
        }
    }

    Ok(())
}
