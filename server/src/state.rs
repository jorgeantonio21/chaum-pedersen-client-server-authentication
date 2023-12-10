use std::collections::HashMap;

use num_bigint::BigInt;

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
    ) {
        if let Some(user_data) = self.users.get(&user_name) {
            if let Some(ref user_auth_id) = user_data.auth_id {
                // if the user has already authenticated, we delete the associated challenge
                self.challenges.remove(user_auth_id);
            }
        }

        self.users
            .entry(user_name.clone())
            .and_modify(|entry| entry.auth_id = Some(auth_id.clone()));
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
    }

    pub(crate) fn create_session(&mut self, user_name: String, session_id: String) {
        // we have previously checked that we have user data available
        self.users.get_mut(&user_name).unwrap().session_id = Some(session_id.clone());
        self.sessions.insert(
            session_id.clone(),
            Session {
                id: session_id,
                user_id: user_name,
            },
        );
    }
}
