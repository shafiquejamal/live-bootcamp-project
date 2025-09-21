// use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
// use axum_extra::extract::CookieJar;
// use serde::{Deserialize, Serialize};
//
// use crate::{
//     app_state::AppState,
//     domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
//     utils::generate_auth_cookie,
// };
//
// pub async fn verify_2fa(
//     jar: CookieJar,
//     State(state): State<AppState>, // New!
//     Json(request): Json<Verify2FARequest>,
// ) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
//     let email = match Email::parse(request.email) {
//         // Validate the email in `request`
//         Ok(email) => email,
//         Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
//     };
//
//     let login_attempt_id = match LoginAttemptId::parse(request.login_attempt_id) {
//         Ok(login_attempt_id) => login_attempt_id,
//         Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
//     }; // Validate the login attempt ID in `request`
//
//     let two_fa_code = match TwoFACode::parse(request.two_fa_code) {
//         Ok(two_fa_code) => two_fa_code,
//         Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
//     };
//
//     // New!
//     let mut two_fa_code_store = state.two_fa_code_store.write().await;
//
//     // Call `two_fa_code_store.get_code`. If the call fails
//     // return a `AuthAPIError::IncorrectCredentials`.
//     let (stored_login_attempt_id, stored_two_fa_cde) =
//         match two_fa_code_store.get_code(&email).await {
//             Ok(code_tuple) => code_tuple,
//             Err(_) => {
//                 return (jar, Err(AuthAPIError::IncorrectCredentials));
//             }
//         };
//
//     // TODO: Validate that the `login_attempt_id` and `two_fa_code`
//     // in the request body matches values in the `code_tuple`.
//     // If not, return a `AuthAPIError::IncorrectCredentials`.
//     if two_fa_code == stored_two_fa_cde && login_attempt_id == stored_login_attempt_id {
//         let auth_cookie = match generate_auth_cookie(&email) {
//             Ok(cookie) => cookie,
//             Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
//         };
//
//         match two_fa_code_store.remove_code(&email).await {
//             Ok(()) => {}
//             Err(_) => return (jar, Err(AuthAPIError::UnexpectedError)),
//         }
//         let updated_jar = jar.add(auth_cookie);
//         (updated_jar, Ok(StatusCode::OK.into_response()))
//     } else {
//         (jar, Err(AuthAPIError::IncorrectCredentials))
//     }
// }
//
// #[derive(Debug, Serialize, Deserialize)]
// pub struct Verify2FARequest {
//     email: String,
//     #[serde(rename = "loginAttemptId")]
//     pub login_attempt_id: String,
//     #[serde(rename = "2FACode")]
//     pub two_fa_code: String,
// }
