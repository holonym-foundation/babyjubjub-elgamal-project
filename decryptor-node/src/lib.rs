use babyjubjub_rs::Point;
use ethers_core::types::Signature;
use serde::{Serialize, Deserialize};

#[derive(Debug,Serialize,Deserialize)]
pub struct DecryptionRequest {
    pub c1: Point,
    pub nodes_to_decrypt_from: Vec<u32>,
    pub sig: Signature,
}