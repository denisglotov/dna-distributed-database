use anyhow::anyhow;
use blst::min_pk::{PublicKey, SecretKey, Signature};
use blst::{BLST_ERROR, min_pk::AggregateSignature};
use rand::RngCore;
use sha3::{Digest, Keccak256};

pub type Hash = [u8; 32];

// For BLS signatures, the domain separation tag.
// DST per IETF BLS; use the canonical DST for G2 (min_pk).
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

// For BLS signatures, the augmentation string.
const AUG: &[u8] = &[]; // no augmentation

pub fn hash_message(message: &str) -> Hash {
    let mut hasher = Keccak256::new();
    hasher.update(message.as_bytes());
    hasher.finalize().into()
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

pub fn sign_message(sk: &SecretKey, hash: Hash) -> Signature {
    sk.sign(&hash, DST, AUG)
}

pub fn verify_signature(pk: &PublicKey, message: &str, signature: Signature) -> bool {
    let hash = hash_message(message);
    let result = signature.verify(true, &hash, DST, AUG, pk, true);
    result == blst::BLST_ERROR::BLST_SUCCESS
}

pub fn aggregate_signatures(sigs: &[&Signature]) -> anyhow::Result<Signature> {
    let agg = AggregateSignature::aggregate(sigs, true)
        .map_err(|e| anyhow!("failed to aggregate signatures: {:?}", e))?;
    Ok(agg.to_signature())
}

pub fn verify_aggregated_signature(pks: &[&PublicKey], hash: Hash, signature: &Signature) -> bool {
    // Fast verify for same-message aggregation
    let result = signature.fast_aggregate_verify(true, &hash, DST, pks);
    result == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_and_verify_same_message() -> anyhow::Result<()> {
        let n = 5usize;
        let mut sks = Vec::with_capacity(n);
        let mut pks = Vec::with_capacity(n);

        // Generate deterministic/random keypairs for test
        for _ in 0..n {
            let (sk, pk) = gen_key(None, None).expect("key generation failed");
            sks.push(sk);
            pks.push(pk);
        }

        let hash = hash_message("hello distributed dna");
        let sigs: Vec<_> = sks.iter().map(|sk| sign_message(sk, hash)).collect();

        let sigs: Vec<&Signature> = sigs.iter().collect();
        let agg = aggregate_signatures(&sigs)?;

        let pks: Vec<&PublicKey> = pks.iter().collect();
        assert!(verify_aggregated_signature(&pks, hash, &agg));

        Ok(())
    }

    #[test]
    fn sign_and_verify() -> anyhow::Result<()> {
        let (sk, pk) = gen_key(None, None).expect("key generation failed");
        let msg = "hello distributed dna";
        let sig = sign_message(&sk, hash_message(msg));

        let res = verify_signature(&pk, msg, sig);
        assert!(res, "correct signature verification failed");

        let bad_msg = "hello altered message";
        let res = verify_signature(&pk, bad_msg, sig);
        assert!(!res, "incorrect signature verification passed");

        Ok(())
    }
}
