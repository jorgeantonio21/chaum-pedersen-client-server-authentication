use server::{server::PedersenChaumAuthServer, server_auth::auth_server::AuthServer};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let addr = "127.0.0.1:5001".parse()?;
    let service = PedersenChaumAuthServer::new();

    Server::builder()
        .add_service(AuthServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
