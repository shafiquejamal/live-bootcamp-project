use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;

use crate::{app_state::AppState, domain::AuthAPIError, utils::validate_token};

pub async fn verify_token(
    State(state): State<AppState>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<StatusCode, AuthAPIError> {
    let token = request.token;

    let token_not_valid = validate_token(&token).await.is_err();
    if token_not_valid {
        return Err(AuthAPIError::InvalidToken);
    }
    let banned_token_store = state.banned_token_store.read().await;
    match banned_token_store.contains_token(&token).await {
        Ok(contains_banned_token) => {
            if contains_banned_token {
                Err(AuthAPIError::InvalidToken)
            } else {
                Ok(StatusCode::OK)
            }
        }
        _ => Ok(StatusCode::OK),
    }
}

#[derive(Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}
