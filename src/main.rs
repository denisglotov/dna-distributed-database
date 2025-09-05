pub mod config;
mod mock_network;
pub mod network;

use crate::config::load_config;
use crate::mock_network::MockNetwork;
use crate::network::{Message, Network};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = load_config("config.yaml")?;
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

    let mut nodes = Vec::new();
    for i in 0..config.nodes.len() {
        nodes.push(MockNetwork::new(
            i,
            peer_txs.clone(),
            peer_rxs[i].take().unwrap(),
        ));
    }

    // Node 0 sends a message to Node 100
    nodes[0]
        .send(
            1,
            Message::UserUpdate {
                from: 0,
                request: network::UserUpdateRequest {
                    user_public_key: "pubkey0".to_string(),
                    nonce: 1,
                    update: "Update from Node 0".to_string(),
                    signature: "signature0".to_string(),
                },
            },
        )
        .await
        .unwrap();
    nodes[0]
        .broadcast(Message::UserUpdate {
            from: 0,
            request: network::UserUpdateRequest {
                user_public_key: "pubkey0".to_string(),
                nonce: 2,
                update: "Broadcast from Node 0".to_string(),
                signature: "signature0".to_string(),
            },
        })
        .await
        .unwrap();
    // Node 1 receives the message
    if let Some((peer_id, msg)) = nodes[1].receive().await {
        println!("Node 1 received from Node {}: {:?}", peer_id, msg);
    }
    if let Some((peer_id, msg)) = nodes[1].receive().await {
        println!("Node 1 received from Node {}: {:?}", peer_id, msg);
    }
    // Node 2 receives the broadcast message
    if let Some((peer_id, msg)) = nodes[2].receive().await {
        println!("Node 2 received from Node {}: {:?}", peer_id, msg);
    }
    Ok(())
}
