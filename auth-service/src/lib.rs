use app_state::AppState;
use domain::AuthAPIError;
use serde::{Deserialize, Serialize};
use std::error::Error;

use axum::{
    Json, Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get_service,
    routing::post,
    serve::Serve,
};
use tokio::net::TcpListener;
use tower_http::services::ServeDir;

pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;

#[derive(Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AuthAPIError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthAPIError::UserAlreadyExists => (StatusCode::CONFLICT, "User already exists"),
            AuthAPIError::InvalidCredentials => (StatusCode::BAD_REQUEST, "Invalid credentials"),
            AuthAPIError::UnexpectedError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Unexpected error")
            }
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}

pub struct Application {
    server: Serve<TcpListener, Router, Router>,
    // address is exposed as a public field
    // so we have access to it in tests.
    pub address: String,
}

impl Application {
    pub async fn build(app_state: AppState, address: &str) -> Result<Self, Box<dyn Error>> {
        // Move the Router definition from `main.rs` to here.
        // Also, remove the `hello` route.
        // We don't need it at this point!
        // DONE
        let router = Router::new()
            .route("/", get_service(ServeDir::new("assets")))
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify-token", post(routes::verify_token))
            .route("/verify-2fa", post(routes::verify_2fa))
            .with_state(app_state);

        let listener = tokio::net::TcpListener::bind(address).await?;
        let address = listener.local_addr()?.to_string();
        let server = axum::serve(listener, router);

        // Create a new Application instance and return it
        // DONE
        Ok(Application { server, address })
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        println!("listening on {}", &self.address);
        self.server.await
    }
}
