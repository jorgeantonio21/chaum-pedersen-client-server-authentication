use crate::{
    server::PedersenChaumAuthServer,
    server_auth::{
        auth_server::Auth, AuthenticationAnswerRequest, AuthenticationAnswerResponse,
        AuthenticationChallengeRequest, AuthenticationChallengeResponse, RegisterRequest,
        RegisterResponse,
    },
    types::{Challenge, Session, User},
};
use chaum_pedersen::chaum_pedersen::{
    ChaumPedersen, ChaumPedersenInterface,
};
use num_bigint::BigInt;
use std::{collections::HashMap, str::FromStr};
use tonic::Request;

#[tokio::test]
async fn test_register_user() {
    let user = "hello, world";
    let y1 = BigInt::from_str("1_000_000").unwrap();
    let y2 = BigInt::from_str("1_000_000").unwrap();

    let server = PedersenChaumAuthServer::new();

    let register_request = RegisterRequest {
        user: user.to_string(),
        y1: y1.to_bytes_be().1,
        y2: y2.to_bytes_be().1,
    };

    let result = server.register(Request::new(register_request)).await;
    assert!(result.is_ok());

    let response = result.unwrap().into_inner();
    assert_eq!(response, RegisterResponse {});

    let should_be_users = HashMap::from_iter([(
        user.to_string(),
        User {
            id: user.to_string(),
            y1,
            y2,
            auth_id: None,
            session_id: None,
        },
    )]);
    assert_eq!(server.state.read().await.users, should_be_users);
    assert_eq!(server.state.read().await.challenges, HashMap::new());
    assert_eq!(server.state.read().await.sessions, HashMap::new());
}

#[tokio::test]
async fn test_create_authentication_challenge() {
    let user = "hello, world";
    let y1 = BigInt::from_str("1_000_000").unwrap();
    let y2 = BigInt::from_str("1_000_000").unwrap();

    let r1 = BigInt::from_str("1").unwrap();
    let r2 = BigInt::from_str("2").unwrap();

    let server = PedersenChaumAuthServer::new();

    let register_request = RegisterRequest {
        user: user.to_string(),
        y1: y1.to_bytes_be().1,
        y2: y2.to_bytes_be().1,
    };

    server
        .register(Request::new(register_request))
        .await
        .unwrap();

    let auth_challenge_request = AuthenticationChallengeRequest {
        user: user.to_string(),
        r1: r1.to_bytes_be().1,
        r2: r2.to_bytes_be().1,
    };

    let result = server
        .create_authentication_challenge(Request::new(auth_challenge_request))
        .await;
    assert!(result.is_ok());

    let response = result.unwrap().into_inner();

    println!("response auth id = {}", response.auth_id);
    println!("response c = {:?}", response.c);

    assert_eq!(response.c.len(), 32);

    let should_be_users = HashMap::from_iter([(
        user.to_string(),
        User {
            id: user.to_string(),
            y1,
            y2,
            auth_id: Some(response.auth_id.clone()),
            session_id: None,
        },
    )]);
    assert_eq!(server.state.read().await.users, should_be_users);

    let should_be_challenges = HashMap::from_iter([(
        response.auth_id.clone(),
        Challenge {
            id: response.auth_id.clone(),
            r1,
            r2,
            c: BigInt::from_bytes_be(num_bigint::Sign::Plus, &response.c.clone()),
            user_id: user.to_string(),
        },
    )]);
    assert_eq!(server.state.read().await.challenges, should_be_challenges);
    assert_eq!(server.state.read().await.sessions, HashMap::new());
}

#[tokio::test]
async fn test_create_authentication_challenge_fails_if_user_unregistered() {
    let user = "hello, world";

    let r1 = BigInt::from_str("1").unwrap();
    let r2 = BigInt::from_str("2").unwrap();

    let server = PedersenChaumAuthServer::new();

    let auth_challenge_request = AuthenticationChallengeRequest {
        user: user.to_string(),
        r1: r1.to_bytes_be().1,
        r2: r2.to_bytes_be().1,
    };

    let result = server
        .create_authentication_challenge(Request::new(auth_challenge_request))
        .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Failed to retrieve user data, user must register first"));
}

#[tokio::test]
async fn test_verify_authentication() {
    let user = "hello, world";
    let cp = ChaumPedersen::default();

    let TestChaumPedersenClientValues {
        client_secret,
        y1,
        y2,
        k,
        r1,
        r2,
    } = get_client_chaum_pedersen_values();

    let server = PedersenChaumAuthServer::new();

    let register_request = RegisterRequest {
        user: user.to_string(),
        y1: y1.to_bytes_be().1,
        y2: y2.to_bytes_be().1,
    };

    server
        .register(Request::new(register_request))
        .await
        .unwrap();

    let auth_challenge_request = AuthenticationChallengeRequest {
        user: user.to_string(),
        r1: r1.to_bytes_be().1,
        r2: r2.to_bytes_be().1,
    };

    let response = server
        .create_authentication_challenge(Request::new(auth_challenge_request))
        .await
        .unwrap();

    let AuthenticationChallengeResponse { auth_id, c } = response.into_inner();
    let c = BigInt::from_bytes_be(num_bigint::Sign::Plus, &c);

    let s = get_solution_to_challenge(&cp, client_secret, k, c.clone());

    let auth_answer_request = AuthenticationAnswerRequest {
        auth_id: auth_id.clone(),
        s: s.to_bytes_be().1,
    };

    let result = server
        .verify_authentication(Request::new(auth_answer_request))
        .await;
    assert!(result.is_ok());

    let AuthenticationAnswerResponse { session_id } = result.unwrap().into_inner();

    let should_be_users = HashMap::from_iter([(
        user.to_string(),
        User {
            id: user.to_string(),
            y1,
            y2,
            auth_id: Some(auth_id.clone()),
            session_id: Some(session_id.clone()),
        },
    )]);
    assert_eq!(server.state.read().await.users, should_be_users);

    let should_be_challenges = HashMap::from_iter([(
        auth_id.clone(),
        Challenge {
            id: auth_id,
            r1,
            r2,
            c,
            user_id: user.to_string(),
        },
    )]);
    assert_eq!(server.state.read().await.challenges, should_be_challenges);

    let should_be_session = HashMap::from_iter([(
        session_id.clone(),
        Session {
            id: session_id,
            user_id: user.to_string(),
        },
    )]);
    assert_eq!(server.state.read().await.sessions, should_be_session);
}

struct TestChaumPedersenClientValues {
    client_secret: BigInt,
    y1: BigInt,
    y2: BigInt,
    k: BigInt,
    r1: BigInt,
    r2: BigInt,
}

fn get_client_chaum_pedersen_values() -> TestChaumPedersenClientValues {
    let cp = ChaumPedersen::default();

    let client_secret = cp.generate_random();
    let client_secret_commitment = cp.commit(&client_secret);
    let (y1, y2) = (
        client_secret_commitment.get_first_exponent(),
        client_secret_commitment.get_second_exponent(),
    );

    let k = cp.generate_random();
    let commitment = cp.commit(&k);
    let (r1, r2) = (
        commitment.get_first_exponent().clone(),
        commitment.get_second_exponent().clone(),
    );

    TestChaumPedersenClientValues {
        client_secret,
        y1: y1.clone(),
        y2: y2.clone(),
        k,
        r1,
        r2,
    }
}

fn get_solution_to_challenge(
    cp: &ChaumPedersen,
    client_secret: BigInt,
    k: BigInt,
    challenge: BigInt,
) -> BigInt {
    cp.solve_challenge(&client_secret, &k, &challenge)
}
