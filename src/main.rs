pub mod config;
mod mock_network;
pub mod network;
mod node;
pub mod utils;

use crate::{
    config::{load_config, load_private_key},
    mock_network::MockNetwork,
    network::{Message, Network},
    node::Node,
};
use tokio::task;
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

    let mut peer_txs = Vec::new();
    let mut peer_rxs = Vec::new();
    for _ in 0..config.nodes.len() {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        peer_txs.push(tx);
        peer_rxs.push(Some(rx));
    }

    let mut tasks = Vec::new();
    for i in 0..config.nodes.len() {
        let net = MockNetwork::new(i, peer_txs.clone(), peer_rxs[i].take());
        let private_key_path = format!("config/config-node-{}-sk.hex", i);
        let private_key = load_private_key(&private_key_path)?;
        let node = Node::new(private_key, config.clone(), i);
        tasks.push(task::spawn(async move { node.run(&net).await }));
    }

    let admin = MockNetwork::new(usize::MAX, peer_txs.clone(), None);

    admin.broadcast(Message::Quit).await?;

    for t in tasks {
        let _ = t.await;
    }

    info!("All nodes shut down");
    Ok(())
}
