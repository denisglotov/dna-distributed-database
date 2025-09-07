use axum::{
    Router,
    extract::{Json, Path, State},
    http::StatusCode,
    routing::post,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::timeout;
use tracing::{error, info};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    config::Config,
    mock_network::{MockNetwork, create_user_update_request, wait_for_query_response},
    network::{Message, Network, UserQueryRequest, UserUpdateRequest},
    utils::{parse_public_key, stringify_public_key},
};

pub struct ServerState {
    admin: MockNetwork,
    users: Vec<String>,
    nodes_len: usize,
}

#[utoipa::path(
    post,
    path = "/api/{node}/update",
    request_body = UserUpdateRequest,
    params(
        ("node" = usize, Path, description = "Node number to send the update to"),
    ),
    responses(
        (status = 200, description = "Request accepted"),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    )
)]
async fn update_node(
    State(state): State<Arc<ServerState>>,
    Path(node): Path<usize>,
    Json(payload): Json<UserUpdateRequest>,
) -> Result<(), StatusCode> {
    info!(
        "Server: Update request for node {}: {}",
        node, payload.update
    );
    if node >= state.nodes_len {
        error!("Invalid node index: {}", node);
        return Err(StatusCode::BAD_REQUEST);
    }
    let user_public_key = parse_public_key(&payload.user_public_key).map_err(|e| {
        error!("Invalid public key: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    let user = state
        .users
        .iter()
        .position(|pk| pk == &payload.user_public_key)
        .ok_or_else(|| {
            error!("Unknown user public key: {}", payload.user_public_key);
            StatusCode::BAD_REQUEST
        })?;
    let (request, signature) =
        create_user_update_request(user, payload.nonce, &payload.update, user_public_key).map_err(
            |e| {
                error!("Failed to create user update request: {}", e);
                StatusCode::BAD_REQUEST
            },
        )?;
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

#[utoipa::path(
    post,
    path = "/api/{node}/query",
    request_body = UserQueryRequest,
    params(
        ("node" = usize, Path, description = "Node number to query"),
    ),
    responses(
        (status = 200, description = "Query result", body = String),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error"),
    )
)]
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
    if node >= state.nodes_len {
        error!("Invalid node index: {}", node);
        return Err(StatusCode::BAD_REQUEST);
    }
    state
        .admin
        .send(node, Message::AdminQueryStateRequest { user_public_key })
        .await
        .map_err(|e| {
            error!("Failed to send query to node {}: {}", node, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    timeout(
        Duration::from_secs(1),
        wait_for_query_response(&state.admin, user_public_key),
    )
    .await
    .map_err(|e| {
        error!("Failed to receive query response: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })
    .and_then(|res| {
        res.map_err(|e| {
            error!("Failed to receive query response: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
    })
    .map(|dna_opt| {
        let dna = dna_opt.unwrap_or_else(|| "No data".to_string());
        Json(dna)
    })
}

/// API documentation
#[derive(OpenApi)]
#[openapi(
    paths(update_node, query_node),
    components(schemas(UserUpdateRequest, UserQueryRequest)),
    tags(
        (name = "dna", description = "DNA database operations")
    )
)]
struct ApiDoc;

pub async fn server_start(admin: MockNetwork, config: &Config) -> anyhow::Result<()> {
    let users = config.users.iter().map(stringify_public_key).collect();
    let state = Arc::new(ServerState {
        admin,
        users,
        nodes_len: config.nodes.len(),
    });
    let app = Router::new()
        .route("/api/{node}/update", post(update_node))
        .route("/api/{node}/query", post(query_node))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-doc/openapi.json", ApiDoc::openapi()))
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
