use log::info;
use server::{server::PedersenChaumAuthServer, server_auth::auth_server::AuthServer};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    dotenv::dotenv().expect("Failed to load .env variables");
    let server_addr = std::env::var("SERVER_ADDR")
        .expect("Failed to retrieve `SERVER_ADDR` .env variable")
        .parse()?;

    let service = PedersenChaumAuthServer::new();

    info!("Starting server at address: {server_addr} ...");

    Server::builder()
        .add_service(AuthServer::new(service))
        .serve(server_addr)
        .await?;

    Ok(())
}
