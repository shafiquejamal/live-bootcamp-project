use auth_service::{domain::Email, routes::TwoFactorAuthResponse};
use secrecy::{ExposeSecret, Secret};

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let mut app = TestApp::new().await;
    let invalid_inputs = vec![
        serde_json::json!({
        "loginAttemptId": "string",
        "2FACode": "string"
          }),
        serde_json::json!({
        "email": "user@example.com",
        "2FACode": "string"
          }),
        serde_json::json!({
        "email": "user@example.com",
        "loginAttemptId": "string",
          }),
    ];
    for test_case in invalid_inputs.iter() {
        let response = app.post_verify_2fa(&test_case).await;
        assert_eq!(response.status().as_u16(), 422);
    }
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let mut app = TestApp::new().await;
    let test_cases = vec![
        serde_json::json!({
            "email": "not-an-email-address",
            "loginAttemptId": "1dd67e3b-94e5-46e5-aa10-31f9c7f037e5",
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": "a@b.com",
            "loginAttemptId": "3b-94e5-46e5-aa10-31f9c7f037e5",
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": "a@b.com",
            "loginAttemptId": "1dd67e3b-94e5-46e5-aa10-31f9c7f037e5",
            "2FACode": "2short"
        }),
    ];
    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(&test_case).await;
        assert_eq!(response.status().as_u16(), 400);
    }
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let mut app = TestApp::new().await;
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail.

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
    let old_login_attempt_id = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse")
        .login_attempt_id;
    let email = Email::parse(Secret::new(random_email)).unwrap();
    let (login_attempt_id, old_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&email)
        .await
        .unwrap();
    assert_eq!(
        old_login_attempt_id,
        login_attempt_id.as_ref().expose_secret().to_string()
    );

    let _response2 = app.post_login(&login_body).await;
    let _message2 = _response2
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    let test_case = serde_json::json!({
        "email": "a@b.com",
        "loginAttemptId": "1dd67e3b-94e5-46e5-aa10-31f9c7f037e5",
        "2FACode": old_code.as_ref().expose_secret().to_string(),
    });
    let response = app.post_verify_2fa(&test_case).await;
    assert_eq!(response.status().as_u16(), 401);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    // Make sure to assert the auth cookie gets set
    let mut app = TestApp::new().await;
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail.

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email.clone(),
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;
    let login_attempt_id_returned_from_login = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse")
        .login_attempt_id;
    let email = Email::parse(Secret::new(random_email.clone())).unwrap();
    let (login_attempt_id_from_store, two_fa_code_from_store) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&email)
        .await
        .unwrap();
    assert_eq!(
        login_attempt_id_returned_from_login,
        login_attempt_id_from_store
            .as_ref()
            .expose_secret()
            .to_string()
    );

    let test_case = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id_returned_from_login,
        "2FACode": two_fa_code_from_store.as_ref().expose_secret().to_string(),
    });
    let response = app.post_verify_2fa(&test_case).await;
    assert_eq!(response.status().as_u16(), 200);
    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    // Make sure to assert the auth cookie gets set
    let mut app = TestApp::new().await;
    // Call login twice. Then, attempt to call verify-fa with the 2FA code from the first login requet. This should fail.

    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email.clone(),
        "password": "password123",
    });

    let response = app.post_login(&login_body).await;
    let login_attempt_id_returned_from_login = response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse")
        .login_attempt_id;
    let email = Email::parse(Secret::new(random_email.clone())).unwrap();
    let (login_attempt_id_from_store, two_fa_code_from_store) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&email)
        .await
        .unwrap();
    assert_eq!(
        login_attempt_id_returned_from_login,
        login_attempt_id_from_store
            .as_ref()
            .expose_secret()
            .to_string()
    );

    let test_case = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id_returned_from_login,
        "2FACode": two_fa_code_from_store.as_ref().expose_secret().to_string(),
    });
    let response = app.post_verify_2fa(&test_case).await;
    assert_eq!(response.status().as_u16(), 200);
    let response_2 = app.post_verify_2fa(&test_case).await;
    assert_eq!(response_2.status().as_u16(), 401);
    app.clean_up().await;
}
