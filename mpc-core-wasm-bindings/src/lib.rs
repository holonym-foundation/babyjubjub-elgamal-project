use babyjubjub_elgamal::Node;
use babyjubjub_rs::{PrivateKey, Point};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Encryptor { }
#[wasm_bindgen]
pub struct Decryptor {
    node: Node,
}

impl Encryptor {
    // TODO
}

impl Decryptor {
    pub fn from_32_byte_hex_key(hex_key: String, idx: usize, threshold_nodes: usize, total_nodes: usize) -> Decryptor {
        // let private_key = PrivateKey::import(
        //     hex::decode(hex_key).unwrap(),
        // ).unwrap();
        Decryptor {
            node : Node::init_from_seed(
                &hex::decode(hex_key).unwrap(), 
                idx,
                threshold_nodes, 
                total_nodes
            )
        }
        
    }
    pub fn decrypt(&self, c1: Point) -> Point {
        self.node.partial_decrypt(&c1)
    }
}
    