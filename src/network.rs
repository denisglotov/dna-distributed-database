use async_trait::async_trait;
use blst::min_pk::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

pub type PeerId = usize; // later libp2p::PeerId

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUpdateRequest {
    pub user_public_key: String,
    pub nonce: u64,
    pub update: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    UserUpdate {
        from: PeerId,
        request: UserUpdateRequest,
    },
    Ack {
        from: PeerId,
        request_hash: Vec<u8>,
        signature: Signature,
    },
    Certificate {
        request_hash: Vec<u8>,
        participants: Vec<PublicKey>,
        signature: Signature,
    },
}

#[derive(Debug)]
pub enum NetworkError {
    SendFailed,
}

#[async_trait]
pub trait Network {
    async fn send(&self, peer_id: PeerId, msg: Message) -> Result<(), NetworkError>;
    async fn broadcast(&self, msg: Message) -> Result<(), NetworkError>;
    async fn receive(&self) -> Option<(PeerId, Message)>;
}
