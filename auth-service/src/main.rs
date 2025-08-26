use std::sync::Arc;

use auth_service::Application;
use axum::{Router, response::Html, routing::get};
use tokio::sync::RwLock;
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let user_store = auth_service::services::HashmapUserStore::new();
    let app_state = auth_service::app_state::AppState::new(Arc::new(RwLock::new(user_store)));
    let app = Application::build(app_state, "0.0.0.0:3000")
        .await
        .expect("Failed to build app");
    app.run().await.expect("Failed to run app");
}
