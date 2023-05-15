use ethers::contract::abigen;
use ethers::prelude::*;
use ethers_core::types::{Signature, SignatureError};
use std::{sync::Arc, env};
use ethers::signers::{LocalWallet, Signer};

const ADDRESS: &'static str = "0x3A3b5aEF636D2131dd7Ab8413f104c338E723357";

#[tokio::main]
pub async fn has_access(c1x: &[u8; 32]) -> bool {
    println!("has_access to {:?} ?", c1x);
    let rpc_url = env::var("ZK_ESCROW_RPC_URL").expect("ZK_ESCROW_RPC_URL must be set");
    let provider = Provider::<Http>::try_from(rpc_url).unwrap();

    abigen!(SimpleAccessControl, r#"./SimpleAccessControl.json"#);
    let client = Arc::new(provider);
    let address = ADDRESS.parse::<Address>().unwrap();
    let the_sac = SimpleAccessControl::new(address, Arc::clone(&client));
    the_sac.has_access(c1x.into()).await.unwrap()
}

// Current authorization scheme: signed message from auditor address showing that it requests partial decryption of a certain point from a certain node.
// The point, C1, is represented by its x-coordinate, C1x, which is a 32-byte array.
// The node number says who the signature is for (preventing replay attacks)
// The ECDSA is of the message "node_number:C1x". 
// It is represented by signature over secp256k1, represented by the (r, s, v) tuple 
pub fn request_is_authorized(my_node_number: u32, c1x: String, sig: Signature/*r: &[u8; 32], s: &[u8; 32], v: u64*/) -> Result<(), SignatureError> {
    // let sig: Signature = Signature { r: r.into(), s: s.into(), v: v.into() };
    let msg = format!("{}:{}", my_node_number, c1x);
    let adr = ADDRESS.parse::<Address>().unwrap();
    sig.verify(msg, adr)
}