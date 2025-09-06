pub mod config;
mod mock_network;
pub mod network;
mod node;
pub mod utils;

use crate::{
    config::{load_config, load_private_key},
    mock_network::MockNetwork,
    network::{Message, Network, UserUpdateRequest},
    node::Node,
    utils::{hash_message, sign_message},
};
use blst::min_pk::Signature;
use tokio::task;
use tracing::{debug, info};

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
    for (i, peer) in peer_rxs.iter_mut().enumerate() {
        let net = MockNetwork::new(i, peer_txs.clone(), peer.take());
        let private_key_path = format!("config/config-node-{}-sk.hex", i);
        let private_key = load_private_key(&private_key_path)?;
        let node = Node::new(private_key, config.clone(), i);
        tasks.push(task::spawn(async move { node.run(&net).await }));
    }

    let admin = MockNetwork::new(usize::MAX, peer_txs.clone(), None);

    let (request, signature) = create_user_update_request(0, 0, "ABCDDCBA", &config)?;
    admin
        .send(0, Message::DebugUserRequestArrived { request, signature })
        .await?;

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let (request, signature) = create_user_update_request(0, 1, "AAAA", &config)?;
    admin
        .send(1, Message::DebugUserRequestArrived { request, signature })
        .await?;

    // Let the nodes run for a while
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    debug!("Broadcasting shutdown signal to all nodes...");
    admin.broadcast(Message::DebugQuit).await?;
    for t in tasks {
        let _ = t.await;
    }

    info!("All nodes shut down");
    Ok(())
}

fn create_user_update_request(
    user_index: usize,
    nonce: u64,
    update: &str,
    config: &config::Config,
) -> anyhow::Result<(UserUpdateRequest, Signature)> {
    let request = network::UserUpdateRequest {
        user_public_key: hex::encode(config.users[user_index].to_bytes()),
        nonce,
        update: update.to_string(),
    };
    let serialized_request = serde_json::to_string(&request)?;
    let hash = hash_message(&serialized_request);
    let signature = sign_message(
        &load_private_key(format!("config/config-user-{}-sk.hex", user_index).as_str())?,
        hash,
    );
    Ok((request, signature))
}
