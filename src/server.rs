use axum::{
    Router,
    extract::{Json, Path, State},
    http::StatusCode,
    routing::{get, post},
};
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info};

use crate::{
    mock_network::{MockNetwork, create_user_update_request, wait_for_query_response},
    network::{Message, Network, UserQueryRequest, UserUpdateRequest},
    utils::parse_public_key,
};

pub struct ServerState {
    admin: MockNetwork,
}

async fn update_node(
    State(state): State<Arc<ServerState>>,
    Path(node): Path<usize>,
    Json(payload): Json<UserUpdateRequest>,
) -> Result<(), StatusCode> {
    info!(
        "Server: Update request for node {}: {}",
        node, payload.update
    );
    let (request, signature) = create_user_update_request(
        node,
        payload.nonce,
        &payload.update,
        parse_public_key(&payload.user_public_key).map_err(|e| {
            error!("Invalid public key: {}", e);
            StatusCode::BAD_REQUEST
        })?,
    )
    .map_err(|e| {
        error!("Failed to create user update request: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    state
        .admin
        .send(
            node,
            Message::AdminUserRequestArrived { request, signature },
        )
        .await
        .map_err(|e| {
            error!("Failed to send update to node {}: {}", node, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(())
}

async fn query_node(
    State(state): State<Arc<ServerState>>,
    Path(node): Path<usize>,
    Json(payload): Json<UserQueryRequest>,
) -> Result<Json<String>, StatusCode> {
    info!("Server: Querying node {} with request {:?}", node, payload);
    let user_public_key = parse_public_key(&payload.user_public_key).map_err(|e| {
        error!("Invalid public key: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    state
        .admin
        .send(node, Message::AdminQueryStateRequest { user_public_key })
        .await
        .map_err(|e| {
            error!("Failed to send query to node {}: {}", node, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    wait_for_query_response(&state.admin, user_public_key)
        .await
        .map_err(|e| {
            error!("Failed to receive query response: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
        .and_then(|dna_opt| dna_opt.map(|dna| Json(dna)).ok_or(StatusCode::NOT_FOUND))
}

pub async fn server_start(admin: MockNetwork) -> anyhow::Result<()> {
    let state = Arc::new(ServerState { admin });
    let app = Router::new()
        .route("/api/{node}/update", post(update_node))
        .route("/api/{node}/query", get(query_node))
        .with_state(state.clone());

    // Set server address from environment variable or default to localhost:3000
    let host = std::env::var("HOST").unwrap_or("127.0.0.1".to_string());
    let port: u16 = std::env::var("PORT")
        .unwrap_or("3000".to_string())
        .parse()?;
    let addr = format!("{}:{}", host, port).parse::<SocketAddr>()?;
    info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();

    state.admin.broadcast(Message::AdminQuit).await.unwrap();
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    info!("Signal received, starting graceful shutdown");
}
