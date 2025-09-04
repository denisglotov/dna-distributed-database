mod mock_network;
mod network;
use crate::mock_network::MockNetwork;
use crate::network::Network;

#[tokio::main]
async fn main() {
    // Example usage of mock_network
    let (tx0, rx0) = tokio::sync::mpsc::channel(100);
    let (tx1, rx1) = tokio::sync::mpsc::channel(100);
    let (tx2, rx2) = tokio::sync::mpsc::channel(100);
    let peers = vec![tx0, tx1, tx2];
    let node0 = MockNetwork::new(0, peers.clone(), rx0);
    let node1 = MockNetwork::new(1, peers.clone(), rx1);
    let node2 = MockNetwork::new(2, peers.clone(), rx2);

    // Node 0 sends a message to Node 100
    node0
        .send(1, "Hello from Node 0".to_string())
        .await
        .unwrap();
    node0
        .broadcast("Broadcast from Node 0".to_string())
        .await
        .unwrap();
    // Node 1 receives the message
    if let Some((peer_id, msg)) = node1.receive().await {
        println!("Node 1 received from Node {}: {}", peer_id, msg);
    }
    if let Some((peer_id, msg)) = node1.receive().await {
        println!("Node 1 received from Node {}: {}", peer_id, msg);
    }
    // Node 2 receives the broadcast message
    if let Some((peer_id, msg)) = node2.receive().await {
        println!("Node 2 received from Node {}: {}", peer_id, msg);
    }
}
