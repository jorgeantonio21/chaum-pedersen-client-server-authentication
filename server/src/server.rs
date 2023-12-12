use crate::{
    server_auth::{
        auth_server::Auth, AuthenticationAnswerRequest, AuthenticationAnswerResponse,
        AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest,
        RegisterResponse,
    },
    state::PedersenChaumAuthServerState,
};
use chaum_pedersen::chaum_pedersen::{ChaumPedersen, ChaumPedersenInterface};
use log::info;
use num_bigint::BigInt;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct PedersenChaumAuthServer {
    cp_zkp_protocol: ChaumPedersen,
    state: RwLock<PedersenChaumAuthServerState>,
}

impl PedersenChaumAuthServer {
    pub fn new() -> Self {
        Self {
            cp_zkp_protocol: ChaumPedersen::default(),
            state: RwLock::new(PedersenChaumAuthServerState::new()),
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
        let y1_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &y1);
        let y2_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &y2);
        {
            let mut state_lock = self.state.write().await;
            state_lock.register_user(user, y1_bigint, y2_bigint);
        }
        info!("User successfully registered");
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

        let r1_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &r1);
        let r2_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &r2);
        let c = self.cp_zkp_protocol.generate_random();
        let auth_id = Uuid::new_v4().to_string();

        {
            let mut state_lock = self.state.write().await;
            state_lock.create_authentication_challenge(
                user,
                auth_id.clone(),
                r1_bigint,
                r2_bigint,
                c.clone(),
            )?;
        }

        info!("Successfully created a new authentication challenge for user");
        Ok(Response::new(AuthenticationChallengeResponse {
            auth_id: auth_id,
            c: c.to_bytes_be().1,
        }))
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
        let s_bigint = BigInt::from_bytes_be(num_bigint::Sign::Plus, &s);

        let user_name = {
            let state_read_lock = self.state.read().await;
            let challenge = state_read_lock.challenges.get(&auth_id).ok_or(Status::aborted(
                "Failed to retrieve user challenge data, user must submit an authentication request",
            ))?;
            let user = state_read_lock
                .users
                .get(&challenge.user_id)
                .ok_or(Status::aborted(
                    "Failed to retrieve user data, user must register first",
                ))?;
            self.cp_zkp_protocol
                .verify(
                    &user.y1,
                    &user.y2,
                    &challenge.r1,
                    &challenge.r2,
                    &s_bigint,
                    &challenge.c,
                )
                .map_err(|e| Status::unauthenticated(e.to_string()))?;

            user.id.clone()
        };

        let session_id = Uuid::new_v4().to_string();
        {
            let mut state_lock = self.state.write().await;
            state_lock.create_session(user_name, session_id.clone())?;
        }

        let response = AuthenticationAnswerResponse { session_id };
        Ok(Response::new(response))
    }
}
