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

/// Represents a server for handling authentication using the Chaum-Pedersen Zero-Knowledge Proof (ZKP) protocol.
///
/// This server structure contains the necessary components to manage and execute the Chaum-Pedersen protocol for user authentication. It holds an instance of the Chaum-Pedersen protocol and maintains the server's state.
pub struct PedersenChaumAuthServer {
    /// An instance of the `ChaumPedersen` struct
    cp_zkp_protocol: ChaumPedersen,
    /// A thread-safe, read-write lock (`RwLock`) guarding the state of the `PedersenChaumAuthServer`
    pub(crate) state: RwLock<PedersenChaumAuthServerState>,
}

impl PedersenChaumAuthServer {
    pub fn new() -> Self {
        Self {
            cp_zkp_protocol: ChaumPedersen::default(),
            state: RwLock::new(PedersenChaumAuthServerState::new()),
        }
    }
}

impl Default for PedersenChaumAuthServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl Auth for PedersenChaumAuthServer {
    /// Handles user registration requests for the authentication server.
    ///
    /// This asynchronous function processes registration requests for new users.
    /// It extracts user data from the request, converts it into the required format,
    /// and updates the server's state with the new user's information.
    ///
    /// # Arguments
    ///
    /// * `register_request`: A `Request<RegisterRequest>` object containing the registration data.
    ///
    /// # Returns
    ///
    /// A `Result` type that, on success, contains a `Response<RegisterResponse>`.
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

    /// Creates an authentication challenge for a user.
    ///
    /// This asynchronous function generates a new authentication challenge as part of the Chaum-Pedersen authentication process. It processes the request, generates a random challenge, and stores the challenge information in the server's state.
    ///
    /// # Arguments
    ///
    /// * `auth_challenge_request`: A `Request<AuthenticationChallengeRequest>` object containing the challenge request data.
    ///
    /// # Returns
    ///
    /// A `Result` type that, on success, contains a `Response<AuthenticationChallengeResponse>`. The `AuthenticationChallengeResponse` includes an authentication ID and the generated challenge.
    ///
    /// On failure, it returns a `Status` indicating the error encountered during the challenge creation process.
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
            auth_id,
            c: c.to_bytes_be().1,
        }))
    }

    /// Verifies an authentication response from a user.
    ///
    /// This asynchronous function checks the validity of a user's response to an authentication challenge as part of the Chaum-Pedersen authentication process. It validates the response and, upon successful verification, creates a new session for the user.
    ///
    /// # Arguments
    ///
    /// * `auth_answer_request`: A `Request<AuthenticationAnswerRequest>` object containing the authentication answer data.
    ///
    /// # Returns
    ///
    /// A `Result` type that, on success, contains a `Response<AuthenticationAnswerResponse>`.
    ///
    /// On failure, it returns a `Status` indicating the error encountered during the challenge creation process.
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
