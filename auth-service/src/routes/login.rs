use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;

use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, user},
};

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        _ => return Err(AuthAPIError::InvalidCredentials),
    };
    let password = match Password::parse(request.password) {
        Ok(password) => password,
        _ => return Err(AuthAPIError::InvalidCredentials),
    };

    let mut user_store = state.user_store.read().await;
    match user_store.validate_user(&email, &password).await {
        Ok(()) => Ok(StatusCode::OK.into_response()),
        _ => Err(AuthAPIError::IncorrectCredentials),
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
