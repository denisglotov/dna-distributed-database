use blst::min_pk::SecretKey;
use clap::{Parser, Subcommand};
use dna_distributed_database::{config::RawConfig, utils::gen_key};

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
    GenConfig {
        /// Path to config file
        #[arg(long)]
        config_prefix: Option<String>,
        /// Number of nodes
        #[arg(long)]
        nodes: usize,
        /// Number of users
        #[arg(long)]
        users: usize,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Gen { key_info, ikm } => {
            let (sk, pk) = gen_key(ikm, key_info)?;
            let sk_hex = hex::encode(sk.to_bytes());
            let pk_hex = hex::encode(pk.to_bytes());

            println!("Private key (hex): {sk_hex}");
            println!("Public  key (hex): {pk_hex}");
        }
        Commands::GenConfig {
            config_prefix,
            nodes,
            users,
        } => {
            use std::fs::File;
            use std::io::Write;

            let config_prefix = config_prefix.unwrap_or_else(|| "config".to_string());
            let mut node_keys = Vec::with_capacity(nodes);
            for i in 0..nodes {
                let (sk, pk) = gen_key(None, Some(format!("node-{i}")))?;
                write_secret_key(&sk, &(config_prefix.clone() + &format!("-node-{i}-sk.hex")));
                node_keys.push(hex::encode(pk.to_bytes()));
            }

            let mut user_keys = Vec::with_capacity(users);
            for i in 0..users {
                let (sk, pk) = gen_key(None, Some(format!("user-{i}")))?;
                write_secret_key(&sk, &(config_prefix.clone() + &format!("-user-{i}-sk.hex")));
                user_keys.push(hex::encode(pk.to_bytes()));
            }

            let raw = RawConfig {
                nodes: node_keys,
                users: user_keys,
            };

            let yaml_str = serde_yaml::to_string(&raw)?;

            let config_path = config_prefix + ".yaml";
            let mut file = File::create(&config_path)?;
            file.write_all(yaml_str.as_bytes())?;
            println!("Config written to {}", config_path);
        }
    }
    Ok(())
}

fn write_secret_key(sk: &SecretKey, path: &str) {
    use std::fs::File;
    use std::io::Write;

    let sk_hex = hex::encode(sk.to_bytes());
    let mut file = File::create(path).expect("failed to create secret key file");
    file.write_all(sk_hex.as_bytes())
        .expect("failed to write secret key file");
    println!("Secret key written to {}", path);
}
