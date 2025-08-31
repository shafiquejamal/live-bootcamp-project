use auth_service::routes::LoginRequest;

use crate::helpers::{TestApp, get_random_email};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;
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
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // Call the log-in route with invalid credentials and assert that a
    // 400 HTTP status code is returned along with the appropriate error message.
    let app = TestApp::new().await;
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
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    // Call the log-in route with incorrect credentials and assert
    // that a 401 HTTP status code is returned along with the appropriate error message.
    let app = TestApp::new().await;
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
}
