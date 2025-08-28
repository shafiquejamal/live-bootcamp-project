use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, UserStoreError, user},
};

const MIN_PASSWORD_LENGTH: usize = 8;

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email;
    if !email.contains("@") {
        return Err(AuthAPIError::InvalidCredentials);
    }
    let password = request.password;
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(AuthAPIError::InvalidCredentials);
    }
    let user = user::User::new(email, password, request.requires_2fa);
    let mut user_store = state.user_store.write().await;
    if let Err(UserStoreError::UserAlreadyExists) = user_store.add_user(user).await {
        return Err(AuthAPIError::UserAlreadyExists);
    }
    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });
    Ok((StatusCode::CREATED, response))
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
