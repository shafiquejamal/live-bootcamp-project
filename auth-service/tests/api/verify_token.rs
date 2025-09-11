use auth_service::utils::constants::JWT_COOKIE_NAME;

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;

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
    let valid_token_input = serde_json::json!({
        "token": token
    });

    let response = app.post_verify_token(&valid_token_input).await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "failed for input: {:?}",
        valid_token_input
    );
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;
    let invalid_token = serde_json::json!({
        "token": "bar"
    });

    let response = app.post_verify_token(&invalid_token).await;
    assert_eq!(
        response.status().as_u16(),
        401,
        "failed for input: {:?}",
        invalid_token
    );
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;
    let input_missing = serde_json::json!({});
    let irrelevant_input = serde_json::json!({
        "foo": "bar"
    });
    let test_cases = vec![input_missing, irrelevant_input];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_401_if_banned_token() {
    let app = TestApp::new().await;

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

    let logout_response = app.post_logout().await;
    assert_eq!(logout_response.status().as_u16(), 200,);

    let banned_token_input = serde_json::json!({
        "token": token
    });

    let response = app.post_verify_token(&banned_token_input).await;
    assert_eq!(
        response.status().as_u16(),
        401,
        "failed for input: {:?}",
        banned_token_input
    );
}
