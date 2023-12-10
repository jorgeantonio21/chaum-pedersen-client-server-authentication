use crate::server_auth::{
    auth_server::Auth, AuthenticationAnswerRequest, AuthenticationAnswerResponse,
    AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest,
    RegisterResponse,
};
use log::info;
use tonic::{Request, Response, Status};

pub struct PedersenChaumAuthServer {
    user_auth_data: Vec<usize>,
}

impl PedersenChaumAuthServer {
    pub fn new() -> Self {
        Self {
            user_auth_data: vec![],
        }
    }
}

#[tonic::async_trait]
impl Auth for PedersenChaumAuthServer {
    async fn register(
        &self,
        register_request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        info!("Got a new registration request: {:?}", register_request);
        let RegisterRequest { user, y1, y2 } = register_request.into_inner();
        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        auth_challenge_request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeResponse>, Status> {
        info!(
            "Got a new create authentication challenge request: {:?}",
            auth_challenge_request
        );
        let AuthenticationChallengeRequest { user, r1, r2 } = auth_challenge_request.into_inner();
        let response = AuthenticationChallengeResponse {
            auth_id: String::from("TODO"),
            c: 0,
        };
        Ok(Response::new(response))
    }

    async fn verify_authentication(
        &self,
        auth_answer_request: Request<AuthenticationAnswerRequest>,
    ) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        info!(
            "Got a new verify authentication request: {:?}",
            auth_answer_request
        );
        let AuthenticationAnswerRequest { auth_id, s } = auth_answer_request.into_inner();
        let response = AuthenticationAnswerResponse {
            session_id: String::from("TODO"),
        };
        Ok(Response::new(response))
    }
}
