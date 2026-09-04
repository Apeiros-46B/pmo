mod model;
mod routes;
mod config;

use anyhow::Result;
use axum::{Router, extract::State, routing::get};

use crate::model::{AppState, init_state};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let state = init_state().await?;
    let app = Router::new()
        .route("/pepper", get(pepper))
        .route("/alphabet", get(alphabet))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    _ = axum::serve(listener, app).await;

    Ok(())
}

async fn pepper(State(s): State<AppState>) -> String {
    return s.secrets.media_pepper.iter()
        .flat_map(|b| b.escape_ascii())
        .map(|e| e.to_string())
        .collect::<String>();
}

async fn alphabet(State(s): State<AppState>) -> String {
    return s.secrets.sqids_alphabet.clone()
}
