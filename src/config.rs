use anyhow::anyhow;
use blst::min_pk::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct RawConfig {
    pub nodes: Vec<String>, // list of node public keys in hex
    pub users: Vec<String>, // list of user public keys in key_hex
}

#[derive(Clone, Debug)]
pub struct Config {
    pub nodes: Vec<PublicKey>, // list of node public keys
    pub users: Vec<PublicKey>, // list of user public keys
}

pub fn load_config(file_path: &str) -> anyhow::Result<Config> {
    let config_str = std::fs::read_to_string(file_path)
        .map_err(|e| anyhow!("Failed to read config file: {}", e))?;
    let raw: RawConfig = serde_yaml::from_str(&config_str)
        .map_err(|e| anyhow!("Failed to parse config file: {}", e))?;
    Ok(Config {
        nodes: raw
            .nodes
            .iter()
            .map(|pk_hex| parse_hex_key(pk_hex))
            .collect::<anyhow::Result<Vec<PublicKey>>>()?,
        users: raw
            .users
            .iter()
            .map(|pk_hex| parse_hex_key(pk_hex))
            .collect::<anyhow::Result<Vec<PublicKey>>>()?,
    })
}

fn parse_hex_key(hex_str: &str) -> anyhow::Result<PublicKey> {
    let key_bytes =
        hex::decode(hex_str).map_err(|e| anyhow!("Failed to decode hex public key: {}", e))?;
    PublicKey::from_bytes(&key_bytes).map_err(|_| anyhow!("Invalid public key bytes"))
}

pub fn load_private_key(file_path: &str) -> anyhow::Result<SecretKey> {
    let key_hex = std::fs::read_to_string(file_path)
        .map_err(|e| anyhow!("Failed to read private key file: {}", e))?;
    let key_bytes = hex::decode(key_hex.trim())
        .map_err(|e| anyhow!("Failed to decode hex private key: {}", e))?;
    SecretKey::from_bytes(&key_bytes).map_err(|_| anyhow!("Invalid private key bytes"))
}
