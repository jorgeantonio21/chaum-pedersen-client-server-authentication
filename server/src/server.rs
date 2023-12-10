use crate::handlers::{
    handle_authentication_answer, handle_authentication_challenge, handle_register,
};
use axum::{extract::FromRef, routing::post, Router};

#[derive(Clone, FromRef)]
pub(crate) struct AppState {
    pub(crate) state: Vec<usize>,
}

pub fn routes(state: Vec<usize>) -> Router {
    let app_state = AppState { state };
    Router::new()
        .route("/", post(handle_register))
        .route("/register", post(handle_register))
        .route(
            "/authentication_challenge",
            post(handle_authentication_challenge),
        )
        .route("authentication_answer", post(handle_authentication_answer))
        .with_state(app_state)
}
