use rand::random;
extern crate serde;
use serde::{Serialize, Deserialize};
use babyjubjub_rs::{Point, ToDecimalString, ElGamalEncryption, encrypt_elgamal, PrivateKey};
use babyjubjub_elgamal::{Node, KeygenHelper, calculate_pubkey};
use std::env;

use crate::sealing::{get_seal_key_for_label, recover_seal_key, Seal};
mod sealing;
mod customtls;



// First argument should be empty if new private key is to be generated. Otherwise, it should be the seal of the private key to be used, as a JSON representation of the Seal object
fn main() {
    // use hyper::{Client, Uri};

    // let client = Client::new();

    // let res = client
    //     .get(Uri::from_static("http://httpbin.org/ip"));

    // 
    // println!("WOW, HERE IS THE EXTERNAL FUNCTION {}", customtls::https_get());
    let args: Vec<String> = env::args().collect();
    // Seal key:
    let key: [u8; 16];
    let seal: Seal;
    let label: &[u8; 16] = b"Holonym zkEscrow";
    match args.len() {
        0 => {
            println!("A Seal wasn't supplied as the first argument - creating new private key. To use a sealed private key, provide a JSON string representing the Seal as the first argument");
            (key, seal) = get_seal_key_for_label(*label);
            println!("Generated new private key. If you'd like to use it later, save this JSON object and supply it as the first argument to this script: \n{:?}", serde_json::to_string(&seal).unwrap())
        }
        // arg 0 is "enclave" if any arguments is supplied, and will not exist otherwise. So there cannot be just 1 arg, since "enclave" will be an additional argument
        2 => {
            println!("Attempting to decrypt from {}", args[1]);
            seal = match serde_json::from_str(&args[1]) {
                Ok(s) => s,
                Err(e) => panic!("Failed to deserialize. Error: {}",e)
            };
            key = match recover_seal_key(seal) {
                Ok(k) => k,
                Err(e) => panic!("Failed to decrypt. Error: {:?}", e)
            };
            println!("Successfully recovered key");
            
        }
        _ => panic!("Please supply exactly 0 or 1 arguments. Supplied {:?} as arguments", args)
    }
    // Create seed for random polynomial (16 bytes is enough randomness; the rest can all be zeros)
    let mut padded = key.to_vec();
    padded.append(&mut [0 as u8; 16].to_vec());
    // let p = PrivateKey::import(padded).unwrap();
    let idx = 1; // get idx from cli
    let node = Node::init_from_seed(&padded, idx, 2, 2);  
    println!("This nodes' public key : {:?}", node.pubkey_share()); 
    println!("Note ^ this public key will be different if the enclave measurements do not match the measurements before. I.e., if the code has changed.");
}



/*  To do: 
    * note it doesn't matter whether it's communicated via tls for mvp, we know code is running in the enclave
    1. generate random seed for polynomial
    2. incorporate this as a workspace 
*/