use std::env::{args, self};

use babyjubjub_rs::{Point, ElGamalEncryption, ToDecimalString};
use decryptor_node::DecryptionRequest;
use ethers::types::Signature;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub struct PrfRequest {
    #[serde(rename = "API_KEY")]
    api_key: String,
    #[serde(rename = "prfIn")]
    prf_in: String
}
// #[derive(Serialize, Deserialize)]
// pub struct PrfResponse {
//     #[serde::rename = "prfOut"]
//     prf_out: String
// }

fn main() {
    // Uncomment:
        // let json_ciphertext = args().nth(1).unwrap();
        // let ciphertext: ElGamalEncryption = serde_json::from_str(&json_ciphertext).unwrap(); 
        // let private_key = env::var("ZK_ESCROW_AUTHORITY_PRIVATE_KEY").expect("Expected ZK_ESCROW_AUTHORITY_PRIVATE_KEY in the environment");
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
    // .json::<PrfResponse>().unwrap();
    //     .json::<PrfResponse>()?;
    // println!("PRF output: {}", prf.prfOut);

}

fn make_signed_decryptreq(/*private_key: */ciphertext: &ElGamalEncryption, for_node: &u32, nodes_to_decrypt_from: &Vec<u32>) -> DecryptionRequest{
    let c1x = ciphertext.c1.x.to_dec_string();
    let msg = format!("{}:{}", for_node, c1x);
    let sig = Signature {r: 69.into(), s: 69.into(), v: 69};
    DecryptionRequest {
        c1: ciphertext.c1.clone(),
        nodes_to_decrypt_from: nodes_to_decrypt_from.clone(),
        sig: Signature { r: sig.r, s: sig.s, v: sig.v }
    }
}

// fn get_prf(prf_in: String) -> String {
