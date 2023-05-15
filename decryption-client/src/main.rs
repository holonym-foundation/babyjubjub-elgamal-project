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
    let one_two_three: BigInt = BigInt::from_str("123").unwrap();

    // Uncomment:
        // let json_ciphertext = args().nth(1).unwrap();
        // let ciphertext: ElGamalEncryption = serde_json::from_str(&json_ciphertext).unwrap(); 
    let ciphertext = ElGamalEncryption {
        c1: Point { x: Fr::from_bigint(&one_two_three), y: Fr::from_bigint(&one_two_three) },
        c2: Point { x: Fr::from_bigint(&one_two_three), y: Fr::from_bigint(&one_two_three) }
    };
    let api_key = env::var("ZK_ESCROW_AUTHORITY_API_KEY").expect("Expected ZK_ESCROW_AUTHORITY_API_KEY in the environment");
    // Just decrypt from nodes 1 and 2 for now:
    let nodes_to_decrypt_from: &[u32] = &[1,2]; //Vec<u32> = vec![1, 2];

    // let decryption_reqs = nodes_to_decrypt_from.iter().map(
        for n in nodes_to_decrypt_from {
            let ciphertext_ = ciphertext.clone(); // seems silly and there's likely better way to do this so ciphertext can be moved into each iteration's closure
            spawn_blocking(move || {
            make_signed_decryptreq(
                &ciphertext_,
                &n, 
                &nodes_to_decrypt_from.to_vec()
        )
    }).await.unwrap();
        }

    let client = reqwest::Client::new();
    let req = PrfRequest {
        api_key: api_key,
        prf_in: "69".to_string() //ciphertext.c1.x.to_dec_string()
    };
    let prf = spawn_blocking(move ||{
        client.post("https://prf.zkda.network/authority")
        .json(&req)
        .send()
    })
    .await.unwrap()
    .await.unwrap()
    .text()
    .await.unwrap();
    println!("response: {:?}", prf);
    
}

#[tokio::main]
async fn make_signed_decryptreq(/*private_key: */ciphertext: &ElGamalEncryption, for_node: &u32, nodes_to_decrypt_from: &Vec<u32>) -> DecryptionRequest{
    let c1x = ciphertext.c1.x.to_dec_string();
    let msg = format!("{}:{}", for_node, c1x);
    let private_key = env::var("ZK_ESCROW_AUTHORITY_PRIVATE_KEY").expect("Expected ZK_ESCROW_AUTHORITY_PRIVATE_KEY in the environment");
    
    // let sig = Signature {r: 69.into(), s: 69.into(), v: 69};
    let wallet = private_key.parse::<LocalWallet>().unwrap();
    let sig = wallet.sign_message(&msg).await.unwrap();
    // let sig = spawn_blocking(move ||{
    //     let res = wallet.sign_message(&msg);
    //     res
    // }).await.unwrap().await.unwrap();
    DecryptionRequest {
        c1: ciphertext.c1.clone(),
        nodes_to_decrypt_from: nodes_to_decrypt_from.clone(),
        sig: sig
    }
}

// fn get_prf(prf_in: String) -> String {
