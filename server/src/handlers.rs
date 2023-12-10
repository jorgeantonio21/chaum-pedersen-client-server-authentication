use axum::{extract::State, Json};

use crate::{
    server::AppState,
    server_auth::{
        AuthenticationAnswerRequest, AuthenticationAnswerResponse, AuthenticationChallengeRequest,
        AuthenticationChallengeResponse, RegisterRequest, RegisterResponse,
    },
};

pub(crate) async fn handle_register(
    State(state): State<Vec<usize>>,
    Json(register_request): Json<RegisterRequest>,
) -> Json<RegisterResponse> {
    // let RegisterRequest { user, y1, y2 } = register_request;
    // Json(Ok(RegisterResponse {}))
    Json(String::from("Hello"))
}

pub(crate) async fn handle_authentication_challenge(
    State(state): State<Vec<usize>>,
    Json(auth_challenge_request): Json<AuthenticationChallengeRequest>,
) -> Json<AuthenticationChallengeResponse> {
    let AuthenticationChallengeRequest { user, r1, r2 } = auth_challenge_request;
    let auth_id = String::from("TODO: add me");
    let c = 0;
    Json(AuthenticationChallengeResponse { auth_id, c })
}

pub(crate) async fn handle_authentication_answer(
    State(state): State<Vec<usize>>,
    Json(auth_answer_request): Json<AuthenticationAnswerRequest>,
) -> Json<AuthenticationAnswerResponse> {
    let AuthenticationAnswerRequest { auth_id, s } = auth_answer_request;
    let session_id = String::from("TODO: add me");
    Json(AuthenticationAnswerResponse { session_id })
}
