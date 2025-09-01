use app_state::AppState;
use axum::{
    Json, Router,
    http::Method,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get_service,
    routing::post,
    serve::Serve,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use domain::AuthAPIError;
use serde::{Deserialize, Serialize};
use std::error::Error;
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, services::ServeDir};

pub mod app_state;
pub mod domain;
pub mod routes;
pub mod services;
pub mod utils;

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
            AuthAPIError::IncorrectCredentials => {
                (StatusCode::UNAUTHORIZED, "Incorrect credentials")
            }
            AuthAPIError::MissingToken => (StatusCode::BAD_REQUEST, "JTW is missing"),
            AuthAPIError::InvalidToken => (StatusCode::UNAUTHORIZED, "JWT is invalid"),
        };
        let body = Json(ErrorResponse {
            error: error_message.to_string(),
        });
        (status, body).into_response()
    }
}

pub struct Application {
    server: Serve<Router, Router>,
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
        let allowed_origins = [
            "http://localhost:8000".parse()?,
            // TODO: Replace [YOUR_DROPLET_IP] with your Droplet IP address
            "http://165.227.82.210:8000".parse()?,
        ];

        let cors = CorsLayer::new()
            // Allow GET and POST requests
            .allow_methods([Method::GET, Method::POST])
            // Allow cookies to be included in requests
            .allow_credentials(true)
            .allow_origin(allowed_origins);
        let router = Router::new()
            .nest_service("/", ServeDir::new("assets"))
            .route("/signup", post(routes::signup))
            .route("/login", post(routes::login))
            .route("/logout", post(routes::logout))
            .route("/verify-token", post(routes::verify_token))
            .route("/verify-2fa", post(routes::verify_2fa))
            .with_state(app_state)
            .layer(cors);

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
