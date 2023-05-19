
use clap::{Subcommand, Args, Parser};
use ff::PrimeField;
use num_bigint::{RandBigInt, ToBigInt};
use std::env;
use babyjubjub_rs::{encrypt_elgamal, Fr, PrivateKey, ElGamalEncryption, Point, Q, ToDecimalString};

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
    pkx: String,
    /// y-coord of message
    #[arg(long)]
    pky: String,
}
#[derive(Args)]
struct Decrypt {
    /// x-coord of c1 (public nonce)
    #[arg(long)]
    c1x: String,
    /// y-coord of c1 (public nonce)
    #[arg(long)]
    c1y: String,
    /// x-coord of c2 (shared secret added to message)
    #[arg(long)]
    c2x: String,
    /// y-coord of c2 (shared secret added to message)
    #[arg(long)]
    c2y: String,
}

fn main() {
    let ds = Point::from_xy_strings("69".to_string(), "70".to_string());
    println!("ds {:?}", ds.x.to_dec_string());
    let p = match env::var("ELGAMAL_PRIVKEY_HOLONYM") {
        Ok(privkey) => privkey,
        Err(_) => {
            panic!("ELGAMAL_PRIVKEY_HOLONYM does not exist. It should be a 32-byte hex string such as 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef but random")
        }
    };
    let private_key = PrivateKey::import(
        hex::decode(p).unwrap(),
    ).unwrap();


    // let nonce = rand::thread_rng().gen_bigint_range(&0.to_bigint().unwrap() , &Q);
    // let some_point = B8.mul_scalar(&BigInt::from_u8(0x69).unwrap());
    // let my_pub = private_key.public();
    // println!("{:?}\n\n encrypted for {:?}\n\n with nonce {:?}\n\n is {:?}\n\n",
    //     some_point, my_pub, nonce, encrypt_elgamal(&my_pub, &nonce, &some_point)
    // );
    let cli = Cli::parse();
    let _ = match &cli.command {
        Commands::Encrypt(e) => println!("{:?}", encrypt_elgamal(
            &Point {
                x: Fr::from_str(&e.pkx).unwrap(),
                y: Fr::from_str(&e.pky).unwrap()
            },

            &rand::thread_rng().gen_bigint_range(&0.to_bigint().unwrap() , &Q), 
            &Point {
                x: Fr::from_str(&e.mx).unwrap(),
                y: Fr::from_str(&e.my).unwrap()
            }
        )),
        Commands::Decrypt(d) => println!("{:?}", private_key.decrypt_elgamal(ElGamalEncryption {
            c1: Point { 
                x: Fr::from_str(&d.c1x).unwrap(),
                y: Fr::from_str(&d.c1y).unwrap(),
            },
            c2: Point {
                x: Fr::from_str(&d.c2x).unwrap(),
                y: Fr::from_str(&d.c2y).unwrap()
            }
        }))
    };    

    
}