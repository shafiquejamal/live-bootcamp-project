use auth_service::ErrorResponse;
use auth_service::routes::SignupResponse;

use crate::helpers::TestApp;

#[tokio::test]
async fn signup_should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = crate::helpers::get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({"email": random_email, "requires2FA": false}),
        serde_json::json!({"email": random_email, "password": false}),
        serde_json::json!({"email": random_email, "password": "foo"}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;
    let valid_input = serde_json::json!({
        "email": "some@mydomain.com",
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&valid_input).await;
    assert_eq!(response.status().as_u16(), 201);

    let expected_response = SignupResponse {
        message: "User created successfully!".to_owned(),
    };

    // Assert that we are getting the correct response body!
    assert_eq!(
        response
            .json::<SignupResponse>()
            .await
            .expect("Could not deserialize response body to UserBody"),
        expected_response
    );
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    // The signup route should return a 400 HTTP status code if an invalid input is sent.
    // The input is considered invalid if:
    // - The email is empty or does not contain '@'
    // - The password is less than 8 characters

    // Create an array of invalid inputs. Then, iterate through the array and
    // make HTTP calls to the signup route. Assert a 400 HTTP status code is returned.
    let app = TestApp::new().await;
    let invalid_email_address = serde_json::json!({
        "email": "some_mydomain.com",
        "password": "password123",
        "requires2FA": true
    });
    let invalid_password = serde_json::json!({
        "email": "some@mydomain.com",
        "password": "word123",
        "requires2FA": true
    });
    let invalid_inputs = vec![invalid_email_address, invalid_password];

    for input in invalid_inputs.iter() {
        let response_invalid_email = app.post_signup(input).await;
        assert_eq!(
            response_invalid_email.status().as_u16(),
            400,
            "Failed for input:{:?}",
            input
        );
        assert_eq!(
            response_invalid_email
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to UserBody")
                .error,
            "Invalid credentials".to_owned(),
        );
    }
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    // Call the signup route twice. The second request should fail with a 409 HTTP status code
    let app = TestApp::new().await;
    let valid_input = serde_json::json!({
        "email": "some@mydomain.com",
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&valid_input).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_signup(&valid_input).await;
    assert_eq!(response.status().as_u16(), 409);
    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    )
}
