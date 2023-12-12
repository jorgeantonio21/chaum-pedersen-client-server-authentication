pub mod server;
pub mod state;
#[cfg(test)]
pub mod tests;
pub mod types;

pub mod server_auth {
    tonic::include_proto!("zkp_auth");
}
