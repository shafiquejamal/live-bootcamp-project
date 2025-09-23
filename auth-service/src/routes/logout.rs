use axum::{extract::State, http::StatusCode, response::IntoResponse};
use axum_extra::extract::{CookieJar, cookie};

use crate::{
    app_state::AppState,
    domain::AuthAPIError,
    utils::{JWT_COOKIE_NAME, validate_token},
};

#[tracing::instrument(name = "logout", skip_all)]
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    // Retrieve JWT cookie from the `CookieJar`
    // Return AuthAPIError::MissingToken is the cookie is not found
    let cookie = match jar.get(JWT_COOKIE_NAME) {
        Some(cookie) => cookie,
        _ => return (jar, Err(AuthAPIError::MissingToken)),
    };

    let token = cookie.value().to_owned();

    // TODO: Validate JWT token by calling `validate_token` from the auth service.
    // If the token is valid you can ignore the returned claims for now.
    // Return AuthAPIError::InvalidToken is validation fails.
    if validate_token(&token, state.banned_token_store.clone())
        .await
        .is_err()
    {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    let jar = jar.remove(cookie::Cookie::from(JWT_COOKIE_NAME));
    let mut banned_token_store = state.banned_token_store.write().await;
    match banned_token_store.add_token(token).await {
        Ok(()) => (jar, Ok(StatusCode::OK)),
        Err(e) => (jar, Err(AuthAPIError::UnexpectedError(e.into()))),
    }
}
