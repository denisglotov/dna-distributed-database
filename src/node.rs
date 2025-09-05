use blst::min_pk::{PublicKey, SecretKey, Signature};
use dashmap::{DashMap, Entry};
use tracing::{debug, info, warn};

use crate::{
    config::{Config, DST},
    network::{Dna, Message, Network, Nonce},
    utils::hash_message,
};

pub struct Node {
    memo: DashMap<String, (Nonce, Dna)>, // user_public_key -> (nonce, dna)
    private_key: SecretKey,
    config: Config,
    index: usize,
}

impl Node {
    pub fn new(private_key: SecretKey, config: Config, index: usize) -> Self {
        let pk = private_key.sk_to_pk();
        assert_eq!(
            pk, config.nodes[index],
            "Private key does not match public key in config"
        );
        Self {
            memo: DashMap::new(),
            private_key,
            config,
            index,
        }
    }

    pub async fn run(&self, net: &dyn Network) {
        let node_index = self.index;
        info!(node_index, "Node started");
        loop {
            if let Some((peer_id, msg)) = net.receive().await {
                match msg {
                    Message::UserUpdate { request } => {
                        // Verify signature
                        let user_pk_bytes = hex::decode(&request.user_public_key).unwrap();
                        let user_pk = PublicKey::from_bytes(&user_pk_bytes).unwrap();
                        let sig_bytes = hex::decode(&request.signature).unwrap();
                        let signature = Signature::from_bytes(&sig_bytes).unwrap();
                        let serialized = serde_json::to_string(&request).unwrap();
                        let hash = hash_message(&serialized);
                        if signature.verify(true, &hash, DST, &[], &user_pk, true)
                            != blst::BLST_ERROR::BLST_SUCCESS
                        {
                            warn!("Invalid signature from user {}", request.user_public_key);
                            continue;
                        }

                        // Check nonce
                        let entry = self.memo.entry(request.user_public_key.clone());
                        match entry {
                            Entry::Occupied(ref e) => {
                                if request.nonce != e.get().0 {
                                    warn!(
                                        "Replay attack detected for user {} (expected nonce {}, got {})",
                                        request.user_public_key,
                                        e.get().0,
                                        request.nonce
                                    );
                                    continue;
                                }
                            }
                            Entry::Vacant(_) => {
                                if request.nonce != 0 {
                                    warn!(
                                        "Replay attack detected for new user {} (expected nonce 0, got {})",
                                        request.user_public_key, request.nonce
                                    );
                                    continue;
                                }
                            }
                        }

                        // Update memo
                        entry.insert((request.nonce, request.update.clone()));

                        // Send Ack
                        let ack_msg = Message::Ack {
                            request_hash: hash.clone(),
                            signature: self.private_key.sign(&hash, DST, &[]),
                        };
                        net.send(peer_id, ack_msg).await.unwrap();
                    }

                    Message::Ack {
                        request_hash,
                        signature,
                    } => {
                        debug!(node_index, "Received Ack from {}", peer_id);
                        // Broadcast Certificate if enough Acks (omitted for brevity)
                    }

                    Message::Certificate {
                        request_hash,
                        participants,
                        signature,
                    } => {
                        debug!(node_index, "Received Certify message from {}", peer_id);
                        // Handle Certify (omitted for brevity)
                    }

                    Message::Quit => {
                        debug!(node_index, "Received Quit message from {}", peer_id);
                        break;
                    }
                }
            }
        }
        info!(node_index, "Node shutting down");
    }
}
