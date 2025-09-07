mod config;
mod mock_network;
mod network;
mod node;
mod server;
mod utils;

use crate::{config::load_config, mock_network::create_nodes_network, server::server_start};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Load configuration
    let config = load_config("config/config.yaml")?;
    info!(
        "Loaded config for {} nodes and {} users",
        config.nodes.len(),
        config.users.len()
    );

    // Create the network of nodes and admin interface
    let (tasks, admin) = create_nodes_network(&config).await?;

    // Start the server
    server_start(admin, &config).await?;

    // Wait for all tasks to complete
    for t in tasks {
        let _ = t.await;
    }

    info!("All nodes shut down");
    Ok(())
}
