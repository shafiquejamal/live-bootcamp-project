use std::env::set_var;

use axum::{http::StatusCode, response::IntoResponse};
use axum_extra::extract::{CookieJar, cookie};

use crate::{
    domain::AuthAPIError,
    utils::{JWT_COOKIE_NAME, validate_token},
};

pub async fn logout(jar: CookieJar) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
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
    if validate_token(&token).await.is_err() {
        return (jar, Err(AuthAPIError::InvalidToken));
    }

    let jar = jar.remove(cookie::Cookie::from(JWT_COOKIE_NAME));
    (jar, Ok(StatusCode::OK))
}
