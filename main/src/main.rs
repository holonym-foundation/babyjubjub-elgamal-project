
use clap::{Subcommand, Args, Parser};
use std::env;
// use issuer::Issuer;
use babyjubjub_rs::{Fr, PrivateKey, ElGamalEncryption, B8, new_key};
use num_bigint::BigInt;

/// BabyJubJub ElGamal
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypts a point to a public key
    Encrypt(Encrypt),
    /// Decrypts a point given the private key in the envrionment variable "ELGAMAL_PRIVKEY_HOLONYM"
    Decrypt(Decrypt),
}

#[derive(Args)]
struct Encrypt {
    /// x-coord of message
    #[arg(long)]
    mx: String,
    /// y-coord of message
    #[arg(long)]
    my: String,
    /// x-coord of public key
    #[arg(long)]
    pubkeyx: String,
    /// y-coord of message
    #[arg(long)]
    pubkeyy: String,
}
#[derive(Args)]
struct Decrypt {
    /// x-coord of message
    #[arg(long)]
    mx: String,
    /// y-coord of message
    #[arg(long)]
    my: String,
    /// x-coord of public key
    #[arg(long)]
    pubkeyx: String,
    /// y-coord of public key
    #[arg(long)]
    pubkeyy: String,
}


fn main() {
    let p = match env::var("ELGAMAL_PRIVKEY_HOLONYM") {
        Ok(privkey) => privkey,
        Err(error) => {
            panic!("ELGAMAL_PRIVKEY_HOLONYM does not exist. It should be a 32-byte hex string such as 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef but random")
        }
    };
    let private_key = PrivateKey::import(
        hex::decode(p).unwrap(),
    ).unwrap();

    let cli = Cli::parse();
    let res = match &cli.command {
        Commands::Encrypt(e) => Err("not implemented"),
        Commands::Decrypt(d) => Ok(format!("decrypting {}", d.pubkeyx))
    };    

    println!("result {:?}", res.unwrap());
}