use async_trait::async_trait;
use blst::min_pk::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

pub type PeerId = usize; // later libp2p::PeerId
pub type Nonce = u64;
pub type Dna = String; // user data

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUpdateRequest {
    pub user_public_key: String,
    pub nonce: Nonce,
    pub update: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    UserUpdate {
        request: UserUpdateRequest,
    },
    Ack {
        request_hash: Vec<u8>,
        signature: Signature,
    },
    Certificate {
        request_hash: Vec<u8>,
        participants: Vec<PublicKey>,
        signature: Signature,
    },
    Quit,
}

#[async_trait]
pub trait Network: Send + Sync {
    async fn send(&self, peer_id: PeerId, msg: Message) -> anyhow::Result<()>;
    async fn broadcast(&self, msg: Message) -> anyhow::Result<()>;
    async fn receive(&self) -> Option<(PeerId, Message)>;
}
