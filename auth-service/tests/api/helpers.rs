use std::sync::Arc;

use auth_service::Application;
use serde_json::json;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct TestApp {
    pub address: String,
    pub http_client: reqwest::Client,
}

impl TestApp {
    pub async fn new() -> Self {
        let user_store = auth_service::services::HashmapUserStore::new();
        let app_state = auth_service::app_state::AppState::new(Arc::new(RwLock::new(user_store)));
        let app = Application::build(app_state, "127.0.0.1:0")
            .await
            .expect("Failed to build app");

        let address = format!("http://{}", app.address.clone());

        // Run the auth service in a separate async task
        // to avoid blocking the main test thread.
        #[allow(clippy::let_underscore_future)]
        let _ = tokio::spawn(app.run());

        let http_client = reqwest::Client::new(); // Create a Reqwest http client instance

        // Create new `TestApp` instance and return it
        TestApp {
            address,
            http_client,
        }
    }

    pub async fn get_root(&self) -> reqwest::Response {
        self.http_client
            .get(&format!("{}/", &self.address))
            .send()
            .await
            .expect("Failed to execute request.")
    }

    // TODO: Implement helper functions for all other routes (signup, login, logout, verify-2fa, and verify-token)
    // Done
    pub async fn post_signup<Body>(&self, body: &Body) -> reqwest::Response
    where
        Body: serde::Serialize,
    {
        self.http_client
            .post(&format!("{}/signup", &self.address))
            .json(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_login(&self) -> reqwest::Response {
        let body = r#"{"email:": "some-email", "password": "some-password""#;
        self.http_client
            .post(&format!("{}/login", &self.address))
            .body(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_logout(&self) -> reqwest::Response {
        self.http_client
            .post(&format!("{}/logout", &self.address))
            .header("jwt", "foo")
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_2fa(&self) -> reqwest::Response {
        let body = r#"{"email:": "some-email", "loginAttemptId": "foo", "2FACode": "bar" "#;
        self.http_client
            .post(&format!("{}/verify-2fa", &self.address))
            .body(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }

    pub async fn post_verify_token(&self) -> reqwest::Response {
        let body = r#"{"token:": "some-token""#;
        self.http_client
            .post(&format!("{}/verify-token", &self.address))
            .body(body)
            .send()
            .await
            .expect("Failed to execute request.")
    }
}

pub fn get_random_email() -> String {
    format!("{}@example.com", Uuid::new_v4())
}
