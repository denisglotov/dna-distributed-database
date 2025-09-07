mod config;
mod mock_network;
mod network;
mod node;
mod server;
mod utils;

use crate::{
    config::load_config, mock_network::create_nodes_network, server::server_start,
    utils::stringify_public_key,
};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = load_config("config/config.yaml")?;
    info!(
        "Loaded config for {} nodes and {} users",
        config.nodes.len(),
        config.users.len()
    );

    let (tasks, admin) = create_nodes_network(&config).await?;

    let users = config
        .users
        .iter()
        .map(|u| stringify_public_key(u))
        .collect();
    server_start(admin, users).await?;

    for t in tasks {
        let _ = t.await;
    }

    info!("All nodes shut down");
    Ok(())
}
