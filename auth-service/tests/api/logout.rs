use auth_service::utils::JWT_COOKIE_NAME;
use reqwest::Url;
use secrecy::Secret;

use crate::helpers::TestApp;
use crate::helpers::get_random_email;

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let mut app = TestApp::new().await;
    let response = app.post_logout().await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "failed for input: {:?}",
        "missing cookie"
    );
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let mut app = TestApp::new().await;

    // add invalid cookie
    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;
    assert_eq!(
        response.status().as_u16(),
        401,
        "failed for input: {:?}",
        "missing cookie"
    );
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let signup_request_body = serde_json::json!({
        "email": random_email,
        "password": "longenough",
        "requires2FA": false,
    });
    app.post_signup(&signup_request_body).await;

    let login_request_body = serde_json::json!({
        "email": random_email,
        "password": "longenough",
    });
    let login_response = app.post_login(&login_request_body).await;
    let token = login_response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect(format!("Cookie with name '{}' not found", JWT_COOKIE_NAME).as_str());
    let token = token.value();

    app.cookie_jar.add_cookie_str(
        &format!(
            "{}={}; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME, token
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);
    let contains_token = app
        .banned_token_store
        .read()
        .await
        .contains_token(&Secret::new(token.to_owned()))
        .await
        .expect("Could not check whether token is banned.");
    assert!(contains_token);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();
    let signup_request_body = serde_json::json!({
        "email": random_email,
        "password": "longenough",
        "requires2FA": false,
    });
    app.post_signup(&signup_request_body).await;

    let login_request_body = serde_json::json!({
        "email": random_email,
        "password": "longenough",
    });
    let login_response = app.post_login(&login_request_body).await;
    let token = login_response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect(format!("Cookie with name '{}' not found", JWT_COOKIE_NAME).as_str());
    let token = token.value();

    app.cookie_jar.add_cookie_str(
        &format!(
            "{}={}; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME, token
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    app.post_logout().await;
    let response = app.post_logout().await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "failed for input: {:?}",
        "double loggout"
    );
    app.clean_up().await;
}
