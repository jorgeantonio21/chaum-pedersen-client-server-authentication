pub mod handlers;
pub mod server;

pub mod server_auth {
    tonic::include_proto!("zkp_auth");
}
