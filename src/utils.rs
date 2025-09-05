use anyhow::anyhow;
use blst::min_pk::{PublicKey, SecretKey};
use rand::RngCore;
use sha3::{Digest, Keccak256};

pub fn hash_message(message: &str) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(message.as_bytes());
    hasher.finalize().to_vec()
}

pub fn gen_key(
    ikm: Option<String>,
    key_info: Option<String>,
) -> anyhow::Result<(SecretKey, PublicKey)> {
    let ikm_bytes: Vec<u8> = if let Some(hex_str) = ikm {
        let bytes = hex::decode(hex_str).map_err(|e| anyhow!("invalid hex for ikm: {}", e))?;
        assert!(
            bytes.len() >= 32,
            "IKM must be at least 32 bytes, got {}",
            bytes.len()
        );
        bytes
    } else {
        let mut buf = [0u8; 32];
        rand::rng().fill_bytes(&mut buf);
        buf.to_vec()
    };

    let key_info_bytes = key_info.map(|s| s.as_bytes().to_vec()).unwrap_or_default();

    // Secret/public key (min_pk scheme)
    let sk = SecretKey::key_gen(&ikm_bytes, &key_info_bytes)
        .map_err(|e| anyhow!("failed to generate secret key: {:?}", e))?;
    let pk: PublicKey = sk.sk_to_pk();

    Ok((sk, pk))
}
