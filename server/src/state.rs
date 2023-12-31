use std::collections::HashMap;

use num_bigint::BigInt;
use tonic::Status;

use crate::types::{Challenge, Session, User};

pub type UserId = String;
pub type ChallengeId = String;
pub type SessionId = String;

/// Represents the state of a Pedersen-Chaum authentication server.
///
/// This struct maintains the state of the authentication server, including registered users,
/// active challenges, and ongoing sessions. It uses hash maps for efficient retrieval and management
/// of these entities.
pub struct PedersenChaumAuthServerState {
    pub(crate) users: HashMap<UserId, User>,
    pub(crate) challenges: HashMap<ChallengeId, Challenge>,
    pub(crate) sessions: HashMap<SessionId, Session>,
}

impl PedersenChaumAuthServerState {
    pub(crate) fn new() -> Self {
        Self {
            users: HashMap::new(),
            challenges: HashMap::new(),
            sessions: HashMap::new(),
        }
    }
}

impl PedersenChaumAuthServerState {
    /// Registers a new user in the server state.
    ///
    /// This function adds a new user to the `PedersenChaumAuthServerState`. It takes the user's name and their cryptographic components (`y1` and `y2`), and stores them as part of the user's information.
    ///
    /// # Arguments
    ///
    /// * `user_name`: A `String` representing the unique name of the user. This serves as the user's identifier.
    /// * `y1`: A `BigInt` representing the first cryptographic component associated with the user.
    /// * `y2`: A `BigInt` representing the second cryptographic component associated with the user.
    pub(crate) fn register_user(&mut self, user_name: String, y1: BigInt, y2: BigInt) {
        self.users.insert(
            user_name.clone(),
            User {
                id: user_name,
                y1,
                y2,
                auth_id: None,
                session_id: None,
            },
        );
    }

    /// Creates an authentication challenge for a registered user.
    ///
    /// This method adds a new challenge for a user in the `PedersenChaumAuthServerState`. It associates a user with an authentication challenge, identified by an authentication ID, and stores the challenge's cryptographic components.
    ///
    /// # Arguments
    ///
    /// * `user_name`: A `String` representing the name of the user. This should correspond to a user that is already registered in the server state.
    /// * `auth_id`: A `String` representing a unique identifier for the authentication challenge.
    /// * `r1`: A `BigInt` representing the first cryptographic component of the challenge.
    /// * `r2`: A `BigInt` representing the second cryptographic component of the challenge.
    /// * `c`: A `BigInt` representing the challenge value.
    ///
    /// # Returns
    ///
    /// Returns a `Result` type:
    /// - `Ok(())` if the challenge was successfully created.
    /// - `Err(Status)` if the user is not registered, with an appropriate error message.
    pub(crate) fn create_authentication_challenge(
        &mut self,
        user_name: String,
        auth_id: String,
        r1: BigInt,
        r2: BigInt,
        c: BigInt,
    ) -> Result<(), Status> {
        if let Some(user_data) = self.users.get_mut(&user_name) {
            if let Some(ref user_auth_id) = user_data.auth_id {
                // if the user has already authenticated, we delete the associated challenge
                self.challenges.remove(user_auth_id);
            }
            user_data.auth_id = Some(auth_id.clone());
            self.challenges.insert(
                auth_id.clone(),
                Challenge {
                    id: auth_id,
                    c,
                    r1,
                    r2,
                    user_id: user_name,
                },
            );
        } else {
            return Err(Status::unauthenticated(
                "Failed to retrieve user data, user must register first",
            ));
        }
        Ok(())
    }

    /// Creates a session for a registered user.
    ///
    /// This method establishes a new session for a user who has successfully completed authentication. It updates the user's session information in the server state and adds a new session record.
    ///
    /// # Arguments
    ///
    /// * `user_name`: A `String` representing the name of the user. This should correspond to a user that is already registered and authenticated in the server state.
    /// * `session_id`: A `String` representing a unique identifier for the new session.
    ///
    /// # Returns
    ///
    /// Returns a `Result` type:
    /// - `Ok(())` if the session was successfully created.
    /// - `Err(Status)` if the user is not registered, with an appropriate error message.
    pub(crate) fn create_session(
        &mut self,
        user_name: String,
        session_id: String,
    ) -> Result<(), Status> {
        if let Some(user) = self.users.get_mut(&user_name) {
            user.session_id = Some(session_id.clone());
            self.sessions.insert(
                session_id.clone(),
                Session {
                    id: session_id,
                    user_id: user_name,
                },
            );
        } else {
            return Err(Status::unauthenticated(
                "Failed to retrieve user data, user must register first",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_register_user() {
        let user_name = "user_name".to_string();
        let y1 = BigInt::from_str("1_000_000_000").unwrap();
        let y2 = BigInt::from_str("2_000_000_000").unwrap();

        let mut state = PedersenChaumAuthServerState::new();
        state.register_user(user_name.clone(), y1.clone(), y2.clone());

        let should_be_users = HashMap::from_iter([(
            user_name.clone(),
            User {
                id: user_name,
                y1,
                y2,
                auth_id: None,
                session_id: None,
            },
        )]);
        assert_eq!(state.users, should_be_users);

        assert_eq!(state.challenges, HashMap::new());
        assert_eq!(state.sessions, HashMap::new());
    }

    #[test]
    fn test_create_authentication_challenge() {
        let user_name = "user_name".to_string();
        let y1 = BigInt::from_str("1_000_000_000").unwrap();
        let y2 = BigInt::from_str("2_000_000_000").unwrap();

        let auth_id = "f2m38m2kcj9d-s823".to_string();
        let r1 = BigInt::from_str("1_000").unwrap();
        let r2 = BigInt::from_str("2_000").unwrap();
        let c = BigInt::from_str("10_000").unwrap();

        let mut state = PedersenChaumAuthServerState::new();
        state.register_user(user_name.clone(), y1.clone(), y2.clone());

        state
            .create_authentication_challenge(
                user_name.clone(),
                auth_id.clone(),
                r1.clone(),
                r2.clone(),
                c.clone(),
            )
            .expect("Failed to create authentication");

        let should_be_challenges = HashMap::from_iter([(
            auth_id.clone(),
            Challenge {
                id: auth_id.clone(),
                c,
                r1,
                r2,
                user_id: user_name.clone(),
            },
        )]);
        assert_eq!(state.challenges, should_be_challenges);

        assert_eq!(state.users.get(&user_name).unwrap().auth_id, Some(auth_id));
        assert_eq!(state.sessions, HashMap::new());
    }

    #[test]
    fn test_create_authentication_challenge_when_auth_id_exists() {
        let user_name = "user_name".to_string();
        let y1 = BigInt::from_str("1_000_000_000").unwrap();
        let y2 = BigInt::from_str("2_000_000_000").unwrap();

        let auth_id = "f2m38m2kcj9d-s823".to_string();
        let r1 = BigInt::from_str("1_000").unwrap();
        let r2 = BigInt::from_str("2_000").unwrap();
        let c = BigInt::from_str("10_000").unwrap();

        let mut state = PedersenChaumAuthServerState::new();
        state.register_user(user_name.clone(), y1.clone(), y2.clone());

        state
            .create_authentication_challenge(
                user_name.clone(),
                auth_id,
                r1.clone(),
                r2.clone(),
                c.clone(),
            )
            .expect("Failed to create authentication");

        // re-authenticate to test if the the new authentication token is updated
        let new_auth_id = "2sdiofa9013".to_string();
        state
            .create_authentication_challenge(
                user_name.clone(),
                new_auth_id.clone(),
                r1.clone(),
                r2.clone(),
                c.clone(),
            )
            .expect("Failed to create authentication");

        let should_be_challenges = HashMap::from_iter([(
            new_auth_id.clone(),
            Challenge {
                id: new_auth_id.clone(),
                c,
                r1,
                r2,
                user_id: user_name.clone(),
            },
        )]);
        assert_eq!(state.challenges, should_be_challenges);

        assert_eq!(
            state.users.get(&user_name).unwrap().auth_id,
            Some(new_auth_id)
        );
        assert_eq!(state.sessions, HashMap::new());
    }

    #[test]
    fn test_create_authentication_challenge_fails_if_user_unregistered() {
        let user_name = "user_name".to_string();

        let auth_id = "f2m38m2kcj9d-s823".to_string();
        let r1 = BigInt::from_str("1_000").unwrap();
        let r2 = BigInt::from_str("2_000").unwrap();
        let c = BigInt::from_str("10_000").unwrap();

        let mut state = PedersenChaumAuthServerState::new();

        // user hasn't registered yet
        assert!(state
            .create_authentication_challenge(
                user_name.clone(),
                auth_id,
                r1.clone(),
                r2.clone(),
                c.clone(),
            )
            .unwrap_err()
            .to_string()
            .contains("Failed to retrieve user data, user must register first"));
    }

    #[test]
    fn test_create_session() {
        let user_name = "user_name".to_string();
        let y1 = BigInt::from_str("1_000_000_000").unwrap();
        let y2 = BigInt::from_str("2_000_000_000").unwrap();

        let session_id = "sdfa837djf".to_string();

        let mut state = PedersenChaumAuthServerState::new();
        state.register_user(user_name.clone(), y1.clone(), y2.clone());

        state
            .create_session(user_name.clone(), session_id.clone())
            .expect("Failed to create sesssion");

        assert_eq!(
            state.users.get(&user_name).unwrap().session_id,
            Some(session_id.clone())
        );
        assert_eq!(state.challenges, HashMap::new());

        let should_be_sessions = HashMap::from_iter([(
            session_id.clone(),
            Session {
                id: session_id,
                user_id: user_name,
            },
        )]);
        assert_eq!(state.sessions, should_be_sessions)
    }

    #[test]
    fn test_create_session_fails_if_user_unregistered() {
        let user_name = "user_name".to_string();
        let session_id = "sdfa837djf".to_string();

        let mut state = PedersenChaumAuthServerState::new();

        assert!(state
            .create_session(user_name.clone(), session_id.clone())
            .unwrap_err()
            .to_string()
            .contains("Failed to retrieve user data, user must register first"));
    }
}
