use client::client_auth::{auth_client::AuthClient, RegisterRequest};
use log::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let mut client = AuthClient::connect("https://localhost:5001").await?;

    let request = tonic::Request::new(RegisterRequest {
        user: String::from("I"),
        y1: 0,
        y2: 1,
    });

    let response = client.register(request).await?;

    info!(
        "Request successfully processed with response: {:?}",
        response
    );

    Ok(())
}
