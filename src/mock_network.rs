use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{Mutex, mpsc};

use crate::network::{Message, Network, NetworkError, PeerId};

pub struct MockNetwork {
    peer_id: PeerId,
    txs: Vec<mpsc::Sender<(PeerId, Message)>>, // send to peers
    rx: Arc<Mutex<mpsc::Receiver<(PeerId, Message)>>>, // receive from peers
}

impl MockNetwork {
    pub fn new(
        peer_id: PeerId,
        txs: Vec<mpsc::Sender<(PeerId, Message)>>,
        rx: mpsc::Receiver<(PeerId, Message)>,
    ) -> Self {
        Self {
            peer_id,
            txs,
            rx: Arc::new(Mutex::new(rx)),
        }
    }
}

#[async_trait]
impl Network for MockNetwork {
    async fn send(&self, peer_id: PeerId, msg: Message) -> Result<(), NetworkError> {
        self.txs[peer_id]
            .send((self.peer_id, msg))
            .await
            .map_err(|_| NetworkError::SendFailed)
    }

    async fn broadcast(&self, msg: Message) -> Result<(), NetworkError> {
        for (i, tx) in self.txs.iter().enumerate() {
            if i != self.peer_id {
                let _ = tx.send((self.peer_id, msg.clone())).await;
            }
        }
        Ok(())
    }

    async fn receive(&self) -> Option<(PeerId, Message)> {
        let mut rx = self.rx.lock().await;
        rx.recv().await
    }
}
