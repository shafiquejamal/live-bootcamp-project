use auth_service::{domain::Email, routes::TwoFactorAuthResponse, utils::JWT_COOKIE_NAME};
use secrecy::Secret;

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let mut app = TestApp::new().await;
    let input_missing_email = serde_json::json!({
        "password": "some-password-here",
    });
    let input_missing_password = serde_json::json!( {
        "email": "spammer@some_domain.com",
    });
    let test_cases = vec![input_missing_email, input_missing_password];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message.
    let mut app = TestApp::new().await;
    let invalid_email = serde_json::json!({
        "email": "invalidemail",
        "password": "password123",
    });
    let invalid_password = serde_json::json!({
        "email": "some@mydomain.com",
        "password": "0",
    });
    let test_cases = vec![invalid_email, invalid_password];
    for test_case in test_cases.iter() {
        let response = app.post_login(&test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "failed for input: {:?}",
            test_case
        );
    }
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.
    let mut app = TestApp::new().await;
    let initial_credentials = serde_json::json!({
        "email": "coder@tester.com",
        "password": "password123",
    });
    app.post_signup(&initial_credentials).await;

    let incorrect_credentials = serde_json::json!({
        "email": "coder@tester.com",
        "password": "wrong-password",
    });

    let response = app.post_login(&incorrect_credentials).await;
    assert_eq!(
        response.status().as_u16(),
        401,
        "failed for input: {:?}",
        incorrect_credentials
    );
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let mut app = TestApp::new().await;

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;
    assert_eq!(
        response
            .json::<TwoFactorAuthResponse>()
            .await
            .expect("Could not deserialize response body to TwoFactorAuthResponse")
            .message,
        "2FA required".to_owned()
    );
    let response = app.post_login(&login_body).await;
    assert_eq!(response.status().as_u16(), 206);

    let random_email = Email::parse(Secret::new(random_email)).unwrap();
    let retrieved_value = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&random_email)
        .await;
    assert!(retrieved_value.is_ok());
    app.clean_up().await;
}
