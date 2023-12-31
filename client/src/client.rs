use chaum_pedersen::chaum_pedersen::{ChaumPedersen, ChaumPedersenInterface};
use log::info;
use num_bigint::BigInt;
use tonic::{async_trait, transport::Channel, Request};

use crate::client_auth::{
    auth_client::AuthClient, AuthenticationAnswerRequest, AuthenticationChallengeRequest,
    RegisterRequest,
};

/// Trait definition for the asynchronous interface of a client handling authentication
/// using Chaum-Pedersen ZK protocol.
#[async_trait]
pub trait AuthZKPClient {
    /// Makes a user registration request to the server.
    ///
    /// # Arguments
    /// * `user`: A string slice representing the username.
    /// * `x`: A `BigInt` representing the user's secret, currently as a `Blake3` 32-byte hash (in big-endian format).
    ///
    /// # Returns
    /// A `Result` indicating the success or failure of the registration process.
    ///
    /// # Errors
    /// Returns an error if the registration process fails.
    async fn register_user(
        &mut self,
        user: &str,
        x: &BigInt,
    ) -> Result<(), Box<dyn std::error::Error>>;

    /// Authenticates a user.
    ///
    /// # Arguments
    /// * `user`: A string slice representing the username.
    /// * `x`: A `BigInt` representing the user's secret, currently as a `Blake3` 32-byte hash (in big-endian format).
    ///
    /// # Returns
    /// A `Result` containing a string (e.g., a token) upon successful authentication, or an error.
    ///
    /// # Errors
    /// Returns an error if the authentication process fails.
    async fn authenticate_user(
        &mut self,
        user: &str,
        x: &BigInt,
    ) -> Result<String, Box<dyn std::error::Error>>;
}

/// A client for handling user authentication using the Chaum-Pedersen ZKP protocol.
pub struct ChaumPedersenAuthClient {
    /// The Chaum-Pedersen protocol instance.
    cp_zkp_protocol: ChaumPedersen,
    /// An authentication client.
    client: AuthClient<Channel>,
}

impl ChaumPedersenAuthClient {
    pub async fn new<T: ToString>(destination: T) -> Result<Self, Box<dyn std::error::Error>> {
        let client = AuthClient::connect(destination.to_string()).await?;
        Ok(Self {
            cp_zkp_protocol: ChaumPedersen::default(),
            client,
        })
    }
}

#[async_trait]
impl AuthZKPClient for ChaumPedersenAuthClient {
    async fn register_user(
        &mut self,
        user: &str,
        x: &BigInt,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let exponents = self.cp_zkp_protocol.commit(x);
        let (y1, y2) = (
            exponents.get_first_exponent(),
            exponents.get_second_exponent(),
        );
        let register_request = RegisterRequest {
            user: user.to_string(),
            y1: y1.to_bytes_be().1,
            y2: y2.to_bytes_be().1,
        };

        self.client.register(Request::new(register_request)).await?;
        Ok(())
    }

    async fn authenticate_user(
        &mut self,
        user: &str,
        x: &BigInt,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let k = self.cp_zkp_protocol.generate_random();
        let commitment = self.cp_zkp_protocol.commit(&k);
        let (r1, r2) = (
            commitment.get_first_exponent(),
            commitment.get_second_exponent(),
        );

        let auth_challenge_request = AuthenticationChallengeRequest {
            user: user.to_string(),
            r1: r1.to_bytes_be().1,
            r2: r2.to_bytes_be().1,
        };
        let auth_challenge_response = self
            .client
            .create_authentication_challenge(Request::new(auth_challenge_request))
            .await?;

        info!("Successfully submitted a authentication challenge request to server");

        let auth_challenge = auth_challenge_response.into_inner();
        let c = BigInt::from_bytes_be(num_bigint::Sign::Plus, &auth_challenge.c);
        let s = self.cp_zkp_protocol.solve_challenge(x, &k, &c);

        let auth_answer_request = AuthenticationAnswerRequest {
            auth_id: auth_challenge.auth_id,
            s: s.to_bytes_be().1,
        };
        let auth_answer_response = self
            .client
            .verify_authentication(Request::new(auth_answer_request))
            .await?
            .into_inner();

        Ok(auth_answer_response.session_id)
    }
}
