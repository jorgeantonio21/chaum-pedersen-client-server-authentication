pub mod server;
pub mod state;
pub mod types;

pub mod server_auth {
    tonic::include_proto!("zkp_auth");
}
