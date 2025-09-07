use std::sync::Arc;

use async_trait::async_trait;
use tokio::{
    sync::{Mutex, mpsc},
    task::{self, JoinHandle},
};

use crate::{
    config::{Config, load_private_key},
    network::{Message, Network, PeerId},
    node::Node,
};

type MockNetworkPacket = (PeerId, Message);

pub struct MockNetwork {
    peer_id: PeerId,
    txs: Vec<mpsc::Sender<MockNetworkPacket>>, // send to peers
    rx: Option<Arc<Mutex<mpsc::Receiver<MockNetworkPacket>>>>, // receive from peers
}

impl MockNetwork {
    pub fn new(
        peer_id: PeerId,
        txs: Vec<mpsc::Sender<MockNetworkPacket>>,
        rx: Option<mpsc::Receiver<MockNetworkPacket>>,
    ) -> Self {
        Self {
            peer_id,
            txs,
            rx: rx.map(|rx| Arc::new(Mutex::new(rx))),
        }
    }
}

#[async_trait]
impl Network for MockNetwork {
    async fn send(&self, peer_id: PeerId, msg: Message) -> anyhow::Result<()> {
        self.txs[peer_id]
            .send((self.peer_id, msg))
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    }

    async fn broadcast(&self, msg: Message) -> anyhow::Result<()> {
        for tx in &self.txs {
            let _ = tx.send((self.peer_id, msg.clone())).await;
        }
        Ok(())
    }

    async fn receive(&self) -> Option<MockNetworkPacket> {
        if let Some(rx) = &self.rx {
            let mut rx = rx.lock().await;
            rx.recv().await
        } else {
            None
        }
    }
}

pub async fn create_nodes_network(
    config: &Config,
) -> anyhow::Result<(Vec<JoinHandle<()>>, MockNetwork)> {
    let mut peer_txs = Vec::new();
    let mut peer_rxs = Vec::new();
    for _ in 0..config.nodes.len() + 1 {
        let (tx, rx) = tokio::sync::mpsc::channel(100);
        peer_txs.push(tx);
        peer_rxs.push(Some(rx));
    }

    let admin_index = config.nodes.len();
    let admin = MockNetwork::new(admin_index, peer_txs.clone(), peer_rxs.pop().unwrap());

    let mut tasks = Vec::new();
    for (i, peer) in peer_rxs.iter_mut().enumerate() {
        let net = MockNetwork::new(i, peer_txs.clone(), peer.take());
        let private_key_path = format!("config/config-node-{}-sk.hex", i);
        let private_key = load_private_key(&private_key_path)?;
        let node = Node::new(private_key, config.clone(), i);
        tasks.push(task::spawn(async move { node.run(&net).await }));
    }
    Ok((tasks, admin))
}

#[cfg(test)]
mod tests {
    use blst::min_pk::Signature;

    use crate::{
        config::load_config,
        network::{self, Dna, UserUpdateRequest},
        utils::{hash_message, sign_message},
    };

    use super::*;

    fn sign_request(serialized: &str, node_index: usize) -> anyhow::Result<Signature> {
        let hash = hash_message(serialized);
        let private_key_path = format!("config/config-user-{}-sk.hex", node_index);
        let private_key = load_private_key(&private_key_path)?;
        Ok(sign_message(&private_key, hash))
    }

    async fn wait_for_query_response(
        admin: &MockNetwork,
        user_public_key: blst::min_pk::PublicKey,
    ) -> anyhow::Result<Option<Dna>> {
        loop {
            if let Some((_, msg)) = admin.receive().await {
                if let Message::AdminQueryStateResponse {
                    user_public_key: pk,
                    dna,
                } = msg
                {
                    if pk == user_public_key {
                        return Ok(dna);
                    }
                }
            } else {
                return Err(anyhow::anyhow!("No response received"));
            }
        }
    }

    fn create_user_update_request(
        user_index: usize,
        nonce: u64,
        update: &str,
        config: &Config,
    ) -> anyhow::Result<(UserUpdateRequest, Signature)> {
        let request = network::UserUpdateRequest {
            user_public_key: hex::encode(config.users[user_index].to_bytes()),
            nonce,
            update: update.to_string(),
        };
        let serialized_request = serde_json::to_string(&request)?;
        let signature = sign_request(&serialized_request, user_index)?;
        Ok((request, signature))
    }

    #[tokio::test]
    async fn test_mock_network() -> anyhow::Result<()> {
        tracing_subscriber::fmt::init();

        let config = load_config("config/config.yaml")?;
        let (tasks, admin) = create_nodes_network(&config).await?;

        // User #0 sends an update to node #0
        let (request, signature) = create_user_update_request(0, 0, "ABCDDCBA", &config)?;
        admin
            .send(0, Message::AdminUserRequestArrived { request, signature })
            .await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Check that the update was applied at node #1
        admin
            .send(
                1,
                Message::AdminQueryStateRequest {
                    user_public_key: config.users[0],
                },
            )
            .await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert_eq!(
            wait_for_query_response(&admin, config.users[0]).await?,
            Some("ABCDDCBA".to_string())
        );

        // User #0 sends another update to node #1
        let (request, signature) = create_user_update_request(0, 1, "AAAA", &config)?;
        admin
            .send(1, Message::AdminUserRequestArrived { request, signature })
            .await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Check that the update was applied at node #2
        admin
            .send(
                2,
                Message::AdminQueryStateRequest {
                    user_public_key: config.users[0],
                },
            )
            .await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        assert_eq!(
            wait_for_query_response(&admin, config.users[0]).await?,
            Some("AAAA".to_string())
        );

        // Shut down all nodes
        admin.broadcast(Message::AdminQuit).await?;
        for t in tasks {
            let _ = t.await;
        }

        Ok(())
    }
}
