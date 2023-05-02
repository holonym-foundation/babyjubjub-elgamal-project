use babyjubjub_rs::Point;
use serde::{Serialize, Deserialize};
use ethers::types::{Signature, SignatureError};

#[derive(Serialize,Deserialize)]
pub struct DecryptionRequest {
    pub c1: Point,
    pub nodes_to_decrypt_from: Vec<u32>,
    pub sig: Signature,
}