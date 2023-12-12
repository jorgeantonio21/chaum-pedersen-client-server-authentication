use std::collections::HashMap;

use num_bigint::BigInt;
use tonic::Status;

use crate::types::{Challenge, Session, User};

pub type UserId = String;
pub type ChallengeId = String;
pub type SessionId = String;

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

    pub(crate) fn register_user(&mut self, user_name: String, y1: BigInt, y2: BigInt) {
        self.users.insert(
            user_name.clone(),
            User {
                id: user_name,
                y1: y1,
                y2: y2,
                auth_id: None,
                session_id: None,
            },
        );
    }

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
