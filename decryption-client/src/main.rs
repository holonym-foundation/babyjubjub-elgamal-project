use std::{env::{args, self}, vec, str::FromStr};
use ethers_signers::{Signer, Wallet, LocalWallet};
use babyjubjub_rs::{Point, ElGamalEncryption, ToDecimalString, Fr, FrBigIntConversion};
use decryptor_node::DecryptionRequest;
use serde::{Deserialize, Serialize};
use num_bigint::BigInt;
use ethers_core::types::Signature;
use tokio::task::spawn_blocking;
#[derive(Serialize, Deserialize)]
pub struct PrfRequest {
    #[serde(rename = "API_KEY")]
    api_key: String,
    #[serde(rename = "prfIn")]
    prf_in: String
}
#[tokio::main]
async fn main() {
    // Uncomment:
        // let json_ciphertext = args().nth(1).unwrap();
        // let ciphertext: ElGamalEncryption = serde_json::from_str(&json_ciphertext).unwrap(); 
    let api_key = env::var("ZK_ESCROW_AUTHORITY_API_KEY").expect("Expected ZK_ESCROW_AUTHORITY_API_KEY in the environment");
    // Just decrypt from nodes 1 and 2 for now:
    let nodes_to_decrypt_from: Vec<u32> = vec![1, 2];
    let decryption_reqs = nodes_to_decrypt_from.iter().map(|node_number| {
        // uncomment: make_signed_decryptreq(&ciphertext, node_number, &nodes_to_decrypt_from)
    });
    let client = reqwest::blocking::Client::new();
    let req = PrfRequest {
        api_key: api_key,
        prf_in: "69".to_string() //ciphertext.c1.x.to_dec_string()
    };
    let prf = client.post("https://prf.zkda.network/authority")
    .json(&req)
    .send()
    .unwrap()
    .text()
    .unwrap();
    println!("response: {:?}", prf);
    let sini = BigInt::from_str("69").unwrap();
    let result = make_signed_decryptreq(
        &ElGamalEncryption {
            c1: Point { x: Fr::from_bigint(&sini), y: Fr::from_bigint(&sini) },
            c2: Point { x: Fr::from_bigint(&sini), y: Fr::from_bigint(&sini) }
        }, 
    &1u32, 
    &vec![1u32, 2u32]
    ).await;
    // println!(" Signed Decryption Request: {:?}", result);
}

async fn make_signed_decryptreq(/*private_key: */ciphertext: &ElGamalEncryption, for_node: &u32, nodes_to_decrypt_from: &Vec<u32>) -> DecryptionRequest{
    let c1x = ciphertext.c1.x.to_dec_string();
    let msg = format!("{}:{}", for_node, c1x);
    let private_key = env::var("ZK_ESCROW_AUTHORITY_PRIVATE_KEY").expect("Expected ZK_ESCROW_AUTHORITY_PRIVATE_KEY in the environment");
    
    // let sig = Signature {r: 69.into(), s: 69.into(), v: 69};
    let wallet = private_key.parse::<LocalWallet>().unwrap();
    let sig = spawn_blocking(move ||{
        let res = wallet.sign_message(&msg);
        res
    }).await.unwrap().await.unwrap();
    DecryptionRequest {
        c1: ciphertext.c1.clone(),
        nodes_to_decrypt_from: nodes_to_decrypt_from.clone(),
        sig: sig
    }
}

// fn get_prf(prf_in: String) -> String {
