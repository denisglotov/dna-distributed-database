use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{Mutex, mpsc};

use crate::network::{Message, Network, PeerId};

pub struct MockNetwork {
    peer_id: PeerId,
    txs: Vec<mpsc::Sender<(PeerId, Message)>>, // send to peers
    rx: Option<Arc<Mutex<mpsc::Receiver<(PeerId, Message)>>>>, // receive from peers
}

impl MockNetwork {
    pub fn new(
        peer_id: PeerId,
        txs: Vec<mpsc::Sender<(PeerId, Message)>>,
        rx: Option<mpsc::Receiver<(PeerId, Message)>>,
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
        for (i, tx) in self.txs.iter().enumerate() {
            if i != self.peer_id {
                let _ = tx.send((self.peer_id, msg.clone())).await;
            }
        }
        Ok(())
    }

    async fn receive(&self) -> Option<(PeerId, Message)> {
        if let Some(rx) = &self.rx {
            let mut rx = rx.lock().await;
            rx.recv().await
        } else {
            None
        }
    }
}
