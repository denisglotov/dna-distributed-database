use async_trait::async_trait;

pub type PeerId = usize; // later libp2p::PeerId
pub type Message = String;

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
