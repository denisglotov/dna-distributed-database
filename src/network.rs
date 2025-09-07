use async_trait::async_trait;
use blst::min_pk::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::utils::Hash;

pub type PeerId = usize; // later libp2p::PeerId
pub type Nonce = u64;
pub type Dna = String; // user data

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserUpdateRequest {
    pub user_public_key: String,
    pub nonce: Nonce,
    pub update: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserQueryRequest {
    pub user_public_key: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    UserUpdate {
        request: UserUpdateRequest,
        signature: Signature,
    },
    Ack {
        request_hash: Hash,
        signature: Signature,
    },
    Certificate {
        request_hash: Hash,
        participants: Vec<PublicKey>,
        signature: Signature,
    },
    AdminUserRequestArrived {
        request: UserUpdateRequest,
        signature: Signature,
    },
    AdminQueryStateRequest {
        user_public_key: PublicKey,
    },
    AdminQueryStateResponse {
        user_public_key: PublicKey,
        dna: Option<Dna>,
    },
    AdminQuit,
}

#[async_trait]
pub trait Network: Send + Sync {
    async fn send(&self, peer_id: PeerId, msg: Message) -> anyhow::Result<()>;
    async fn broadcast(&self, msg: Message) -> anyhow::Result<()>;
    async fn receive(&self) -> Option<(PeerId, Message)>;
}
