use std::collections::HashSet;

use anyhow::anyhow;
use blst::min_pk::{PublicKey, SecretKey, Signature};
use dashmap::{DashMap, Entry};
use tracing::{debug, info, warn};

use crate::{
    config::{Config, node_threshold},
    network::{Dna, Message, Network, Nonce, UserUpdateRequest},
    utils::{
        Hash, aggregate_signatures, hash_message, sign_message, verify_aggregated_signature,
        verify_signature,
    },
};

pub struct Node {
    db: DashMap<String, (Nonce, Dna)>, // user_public_key -> (nonce, dna)
    pending: DashMap<Hash, UserUpdateRequest>, // request_hash -> request, TODO: cleanup
    votes: DashMap<Hash, HashSet<(String, String)>>, // request_hash -> {(node_pk, signature)}
    nodes_set: HashSet<String>,        // set of node public keys in hex
    nodes: Vec<PublicKey>,             // list of node public keys
    users: HashSet<String>,            // set of user public keys
    private_key: SecretKey,            // node's private key
    index: usize,                      // node index in config
}

impl Node {
    pub fn new(private_key: SecretKey, config: Config, index: usize) -> Self {
        let pk = private_key.sk_to_pk();
        assert_eq!(
            pk, config.nodes[index],
            "Private key does not match public key in config"
        );
        let users: HashSet<String> = config
            .users
            .iter()
            .map(|pk| hex::encode(pk.to_bytes()))
            .collect();
        let nodes_set: HashSet<String> = config
            .nodes
            .iter()
            .map(|pk| hex::encode(pk.to_bytes()))
            .collect();
        Self {
            db: DashMap::new(),
            pending: DashMap::new(),
            votes: DashMap::new(),
            nodes_set,
            nodes: config.nodes,
            users,
            private_key,
            index,
        }
    }

    pub async fn run(&self, net: &dyn Network) {
        let node_index = self.index;
        info!(node_index, "Node started");
        loop {
            if let Some((peer_id, msg)) = net.receive().await {
                match msg {
                    Message::UserUpdate { request, signature } => {
                        debug!(node_index, "Received UserUpdate from {}", peer_id);
                        if !self.users.contains(&request.user_public_key) {
                            warn!(node_index, "Unknown user {}", request.user_public_key);
                            continue;
                        }
                        if peer_id >= self.nodes.len() {
                            warn!(node_index, "Invalid peer_id {}", peer_id);
                            continue;
                        }

                        // Verify signature
                        let (user_pk, hash) = match parse_user_request(&request) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!(
                                    node_index,
                                    "Failed to parse user request {:?}: {}", request, e
                                );
                                continue;
                            }
                        };
                        if !verify_signature(&user_pk, hash, signature) {
                            warn!(
                                node_index,
                                "Invalid signature from user {}", request.user_public_key
                            );
                            continue;
                        }

                        // Check nonce
                        let db_entry = self.db.entry(request.user_public_key.clone());
                        match db_entry {
                            Entry::Occupied(ref e) => {
                                if request.nonce != e.get().0 {
                                    warn!(
                                        node_index,
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
                                        node_index,
                                        "Replay attack detected for new user {} (expected nonce 0, got {})",
                                        request.user_public_key,
                                        request.nonce
                                    );
                                    continue;
                                }
                            }
                        }

                        // Update pending requests
                        self.pending.insert(hash, request);

                        // Send Ack
                        let ack_msg = Message::Ack {
                            request_hash: hash,
                            signature: sign_message(&self.private_key, hash),
                        };
                        net.send(peer_id, ack_msg).await.unwrap();
                    }

                    Message::Ack {
                        request_hash,
                        signature,
                    } => {
                        debug!(node_index, "Received Ack from {}", peer_id);
                        if self.pending.get(&request_hash).is_none() {
                            warn!(node_index, "Ack for unknown request");
                            continue;
                        };

                        // Verify Ack Signature
                        if peer_id >= self.nodes.len() {
                            warn!(node_index, "Invalid peer_id {}", peer_id);
                            continue;
                        }
                        if !verify_signature(&self.nodes[peer_id], request_hash, signature) {
                            warn!(node_index, "Invalid Ack signature from {}", peer_id);
                            continue;
                        }

                        // Record vote
                        let Entry::Occupied(mut votes_entry) = self.votes.entry(request_hash)
                        else {
                            debug!(node_index, "Voting closed for request");
                            continue;
                        };

                        let vote_set = votes_entry.get_mut();
                        vote_set.insert((
                            hex::encode(self.nodes[peer_id].to_bytes()),
                            hex::encode(signature.to_bytes()),
                        ));

                        // Broadcast Certificate if enough Acks
                        if vote_set.len() >= node_threshold(self.nodes.len()) {
                            let participant_pks: Vec<PublicKey> = vote_set
                                .iter()
                                .map(|(pk_hex, _)| {
                                    let pk_bytes = hex::decode(pk_hex).unwrap();
                                    PublicKey::from_bytes(&pk_bytes).unwrap()
                                })
                                .collect();
                            let sigs: Vec<Signature> = vote_set
                                .iter()
                                .map(|(_, sig_hex)| {
                                    let sig_bytes = hex::decode(sig_hex).unwrap();
                                    Signature::from_bytes(&sig_bytes).unwrap()
                                })
                                .collect();
                            let sigs: Vec<&Signature> = sigs.iter().collect();
                            let aggregated_sig = aggregate_signatures(&sigs).unwrap();

                            debug!(
                                node_index,
                                "Broadcasting Certificate for request with {}",
                                vote_set.len(),
                            );
                            let cert_msg = Message::Certificate {
                                request_hash,
                                participants: participant_pks,
                                signature: aggregated_sig,
                            };
                            net.broadcast(cert_msg).await.unwrap();

                            // Close the voting
                            votes_entry.remove();
                        }
                    }

                    Message::Certificate {
                        request_hash,
                        participants,
                        signature,
                    } => {
                        debug!(node_index, "Received Certificate from {}", peer_id);
                        if peer_id >= self.nodes.len() {
                            warn!(node_index, "Invalid peer_id {}", peer_id);
                            continue;
                        }

                        let Some(request) = self.pending.get(&request_hash) else {
                            warn!(node_index, "Certificate for unknown request");
                            continue;
                        };

                        // Verify participants
                        let participant_set: HashSet<String> = participants
                            .iter()
                            .map(|pk| hex::encode(pk.to_bytes()))
                            .collect();
                        if participant_set.len() < node_threshold(self.nodes.len()) {
                            warn!(
                                node_index,
                                "Not enough participants in Certificate: got {}, need {}",
                                participant_set.len(),
                                node_threshold(self.nodes.len())
                            );
                            continue;
                        }
                        if !participant_set.is_subset(&self.nodes_set) {
                            warn!(node_index, "Unknown participant in Certificate");
                            continue;
                        }

                        // Verify aggregated Signature
                        let participants: Vec<&PublicKey> = participants.iter().collect();
                        if !verify_aggregated_signature(&participants, request_hash, &signature) {
                            warn!(node_index, "Invalid aggregated signature from");
                            continue;
                        }

                        // Double check the nonce
                        let db_entry = self.db.entry(request.user_public_key.clone());
                        match db_entry {
                            Entry::Occupied(ref e) => {
                                if request.nonce != e.get().0 {
                                    warn!(
                                        node_index,
                                        "Nonce obsolete {} (expected nonce {}, got {})",
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
                                        node_index,
                                        "Nonce obsolete {} (expected nonce 0, got {})",
                                        request.user_public_key,
                                        request.nonce
                                    );
                                    continue;
                                }
                            }
                        }

                        // Apply the Update
                        db_entry.insert((request.nonce + 1, request.update.clone()));
                        info!(
                            node_index,
                            "Applied update for user {}: nonce {}, dna {}",
                            request.user_public_key,
                            request.nonce,
                            request.update
                        );
                    }

                    Message::AdminUserRequestArrived { request, signature } => {
                        debug!(node_index, "Received DebugUserRequest from {}", peer_id);
                        if !self.users.contains(&request.user_public_key) {
                            warn!(node_index, "Unknown user {}", request.user_public_key);
                            continue;
                        }
                        // if peer_id >= self.nodes.len() {
                        //     warn!(node_index, "Invalid peer_id {}", peer_id);
                        //     continue;
                        // }

                        // Verify Signature
                        let (user_pk, hash) = match parse_user_request(&request) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!(
                                    node_index,
                                    "Failed to parse user request {:?}: {}", request, e
                                );
                                continue;
                            }
                        };
                        if !verify_signature(&user_pk, hash, signature) {
                            warn!(
                                node_index,
                                "Invalid signature from user {}", request.user_public_key
                            );
                            continue;
                        }

                        // Begin the voting process
                        self.pending.insert(hash, request.clone());
                        self.votes.insert(hash, HashSet::new());

                        // Broadcast the request to all nodes
                        let user_update_msg = Message::UserUpdate { request, signature };
                        net.broadcast(user_update_msg).await.unwrap();
                    }

                    Message::AdminQueryStateRequest { user_public_key } => {
                        debug!(node_index, "Received QueryStateRequest from {}", peer_id);
                        if peer_id != self.nodes.len() {
                            warn!(node_index, "QueryStateRequest only allowed from admin");
                            continue;
                        }
                        let dna = self
                            .db
                            .get(&hex::encode(user_public_key.to_bytes()))
                            .map(|entry| entry.value().1.clone());
                        let response_msg = Message::AdminQueryStateResponse {
                            user_public_key,
                            dna,
                        };
                        net.send(peer_id, response_msg).await.unwrap();
                    }

                    Message::AdminQueryStateResponse { .. } => {
                        // Nodes do not expect to receive this message
                    }

                    Message::AdminQuit => {
                        debug!(node_index, "Received Quit message from {}", peer_id);
                        break;
                    }
                }
            }
        }
        info!(node_index, "Node shutting down");
    }
}

pub fn parse_user_request(request: &UserUpdateRequest) -> anyhow::Result<(PublicKey, Hash)> {
    let pk_bytes = hex::decode(&request.user_public_key)
        .map_err(|e| anyhow!("invalid hex in user_public_key: {}", e))?;
    let pk = PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| anyhow!("invalid public key bytes: {:?}", e))?;

    let serialized = serde_json::to_string(&request).unwrap();
    let hash = hash_message(&serialized);

    Ok((pk, hash))
}
