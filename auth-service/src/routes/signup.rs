use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{app_state::AppState, domain::user};

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> impl IntoResponse {
    let user = user::User::new(request.email, request.password, request.requires_2fa);
    let mut user_store = state.user_store.write().await;
    let add_user_result = user_store.add_user(user).unwrap();
    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });
    (StatusCode::CREATED, response)
}
#[derive(Serialize, Debug, PartialEq, Deserialize)]
pub struct SignupResponse {
    pub message: String,
}
#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
