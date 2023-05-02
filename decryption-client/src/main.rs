use std::env::{args, self};

use babyjubjub_rs::{Point, ElGamalEncryption, ToDecimalString};
use decryptor_node::DecryptionRequest;
use ethers::types::Signature;

// pub struct PrfRequest {
//     api_key: String,
//     prf_in: String
// }

fn main() {
    let json_ciphertext = args().nth(1).unwrap();
    let ciphertext: ElGamalEncryption = serde_json::from_str(&json_ciphertext).unwrap(); 
    let private_key: Result<String, env::VarError> = env::var("ZK_ESCROW_AUTHORITY_PRIVATE_KEY");
    let api_key = env::var("ZK_ESCROW_AUTHORITY_PRIVATE_KEY");
    // Just decrypt from nodes 1 and 2 for now:
    let nodes_to_decrypt_from: Vec<u32> = vec![1, 2];
    let decryption_reqs = nodes_to_decrypt_from.iter().map(|node_number| {
        make_signed_decryptreq(&ciphertext, node_number, &nodes_to_decrypt_from)
    });

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
