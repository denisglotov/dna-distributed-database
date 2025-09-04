use blst::min_pk::{PublicKey, SecretKey};
use clap::{Parser, Subcommand};
use rand::RngCore;

/// CLI definition
#[derive(Parser)]
#[command(name = "dna-keys")]
#[command(about = "CLI for generating BLS (min_pk) keypairs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new private/public keypair
    Gen {
        /// Optional key info (context string for key derivation)
        #[arg(long)]
        key_info: Option<String>,

        /// Optional IKM (input keying material) as hex string (>=32 bytes)
        #[arg(long)]
        ikm: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Gen { key_info, ikm } => {
            let ikm_bytes: Vec<u8> = if let Some(hex_str) = ikm {
                let bytes = hex::decode(hex_str).expect("invalid hex for --ikm");
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

            let key_info_bytes = key_info.map(|s| s.into_bytes()).unwrap_or_default();

            // Secret/public key (min_pk scheme)
            let sk = SecretKey::key_gen(&ikm_bytes, &key_info_bytes)
                .expect("failed to generate secret key");
            let pk: PublicKey = sk.sk_to_pk();

            let sk_hex = hex::encode(sk.to_bytes());
            let pk_hex = hex::encode(pk.to_bytes());

            println!("Private key (hex): {sk_hex}");
            println!("Public  key (hex): {pk_hex}");
        }
    }
}

#[cfg(test)]
mod agg_tests {
    use blst::BLST_ERROR;
    use blst::min_pk::{AggregateSignature, PublicKey, SecretKey};
    use rand::RngCore;

    #[test]
    fn aggregate_and_verify_same_message() {
        // DST per IETF BLS; use the canonical DST for G2 (min_pk).
        // (You can pick a different DST for your app, but be consistent.)
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

        let n = 5usize;
        let mut sks = Vec::with_capacity(n);
        let mut pks = Vec::with_capacity(n);

        // Generate deterministic/random keypairs for test
        for _ in 0..n {
            let mut ikm = [0u8; 32];
            rand::rng().fill_bytes(&mut ikm);

            let sk = SecretKey::key_gen(&ikm, &[]).expect("key_gen failed");
            let pk = sk.sk_to_pk();
            sks.push(sk);
            pks.push(pk);
        }

        let msg: &[u8] = b"hello distributed dna";

        // Each secret key signs the same message
        let sigs: Vec<_> = sks.iter().map(|sk| sk.sign(msg, dst, &[])).collect();

        // Build slice of &Signature for aggregation
        let sig_refs: Vec<&_> = sigs.iter().collect();

        // Aggregate all signatures into an AggregateSignature
        let agg = AggregateSignature::aggregate(&sig_refs, true).expect("aggregation failed");

        // Convert to a Signature (serializable / verifiable)
        let agg_sig = agg.to_signature();

        // Prepare public key refs for verification
        let pk_refs: Vec<&PublicKey> = pks.iter().collect();

        // Fast verify for same-message aggregation
        let res = agg_sig.fast_aggregate_verify(true, msg, dst, &pk_refs);

        assert_eq!(
            res,
            BLST_ERROR::BLST_SUCCESS,
            "aggregate verification failed"
        );
    }
}
