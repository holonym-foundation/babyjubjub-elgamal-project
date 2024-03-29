/* NOTE: i was not aware wasm_bindgen had such robust support for structs when making this. Hence, everything is pretty functional! 
   TODO: utilize that feature to have a nicer interface with structs. Unless perhaps this can lend to easier formal verification? But there's some non-functoinal stuff behind the scenes -- probably not!
 */
use std::{str::FromStr};

use wasm_bindgen::prelude::*;
use num_bigint::BigInt;
use babyjubjub_rs::{Point, ToDecimalString, ElGamalEncryption, encrypt_elgamal, PrivateKey};

use babyjubjub_elgamal::{self, Node, KeygenHelper, decrypt, calculate_pubkey};
extern crate console_error_panic_hook;
use std::panic;

// Note: no constant-time gaurantees


#[wasm_bindgen]
pub fn enableErrors() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}

#[wasm_bindgen]
pub fn msgToPoint(m: String) -> JsValue {
    let m_big = BigInt::from_str(&m).unwrap();
    let p = Point::from_msg_vartime(&m_big);
    serde_wasm_bindgen::to_value(&p).unwrap()
    // serde_json::to_string(&p).unwrap()
}

#[wasm_bindgen]
pub fn pointToMsg(point: JsValue) -> JsValue {
    let p: Point = serde_wasm_bindgen::from_value(point).unwrap();
    let m = p.to_msg().to_dec_string();
    serde_wasm_bindgen::to_value(&m).unwrap()
    // Point::from_xy_strings(x, y).to_msg().to_dec_string()
}

#[wasm_bindgen]
pub fn encryptPoint(msg: JsValue, pubkey: JsValue, nonce: String) -> JsValue {
    let m: Point = serde_wasm_bindgen::from_value(msg).unwrap();
    let p: Point = serde_wasm_bindgen::from_value(pubkey).unwrap();
    // let msg = Point::from_xy_strings(msg_x, msg_y);
    // let pk = Point::from_xy_strings(pub_x, pub_y);
    let nonce_big: BigInt = BigInt::from_str(&nonce).unwrap();
    let e = encrypt_elgamal(&p, &nonce_big, &m);
    serde_wasm_bindgen::to_value(&e).unwrap()
    // serde_json::to_string(&e).unwrap()
}

// #[wasm_bindgen]
// pub fn decryptShare(node: JsValue, msgPoint: JsValue) -> JsValue {
//     let n: Node = serde_wasm_bindgen::from_value(node).unwrap();
//     let m: Point = serde_wasm_bindgen::from_value(msgPoint).unwrap();
//     let d: Point = n.partial_decrypt(&m);
//     serde_wasm_bindgen::to_value(&d).unwrap()
// }

#[wasm_bindgen]
pub fn finalDecrypt(encryptedMsg: JsValue, decryptShares: JsValue, numSharesNeeded: usize) -> JsValue {
    let e: ElGamalEncryption = serde_wasm_bindgen::from_value(encryptedMsg).unwrap();
    let s: Vec<Point> = serde_wasm_bindgen::from_value(decryptShares).unwrap();
    let d = babyjubjub_elgamal::decrypt(e, s, numSharesNeeded as u64);
    serde_wasm_bindgen::to_value(&d).unwrap()
}


// These two functions can be deleted; they're just for some experimationt
#[wasm_bindgen]
pub fn random_node() -> JsValue {
    // return some random node to see how it looks in JS
    let n = Node::init_rnd(1, 3, 5);
    serde_wasm_bindgen::to_value(&n).unwrap()
}

#[wasm_bindgen]
pub fn node_from_seed(seed: &[u8]) -> JsValue {
    // return some random node to see how it looks in JS
    let as_vec = seed.to_vec();
    let n = Node::init_from_seed(&as_vec, 1, 3, 5);
    serde_wasm_bindgen::to_value(&n).unwrap()
}

#[wasm_bindgen]
pub fn read_node(node: JsValue) -> JsValue {
    let n: Node = serde_wasm_bindgen::from_value(node).unwrap();
    serde_wasm_bindgen::to_value(&n).unwrap()
}

// Gets the keygen result from a seed. This returns the keygen polynomial's evaluation at 2. This should be given to the auditor, at node 2
// * and should not be shared with anyone else *
#[wasm_bindgen]
pub fn litKeygen(seed: &[u8]) -> JsValue {
    let as_vec = seed.to_vec();
    let n = Node::init_from_seed(&as_vec, 1, 2, 2);
    let keygen_evals_for_nodes = n.keygen_step1(2);
    serde_wasm_bindgen::to_value(&keygen_evals_for_nodes[1]).unwrap()
}

// Gets the keygen result from a seed. This returns the keygen polynomial's evaluation at 1 must be given to the lit protocol, at node 1
// * and should not be shared with anyone else *
#[wasm_bindgen]
pub fn auditorKeygen(seed: &[u8]) -> JsValue {
    let as_vec = seed.to_vec();
    let n = Node::init_from_seed(&as_vec, 2, 2, 2);
    let keygen_evals_for_nodes = n.keygen_step1(2);
    serde_wasm_bindgen::to_value(&keygen_evals_for_nodes[0]).unwrap()
}


// This is what the Lit Protocol PKP doeswhenever called : 
// 1. instantiates a node based on some deterministic but secret seed Lit protocol will provide
// 2. sets the keygen polynomial based on this party's the other party's keygen result
// 3. partially decrypts a msg
#[wasm_bindgen]
pub fn litDecrypt(seed: &[u8], auditorKeygenEvalAt1: JsValue, encryptedC1: JsValue) -> JsValue {
    let as_vec = seed.to_vec();
    let mut n = Node::init_from_seed(&as_vec, 1, 2, 2);
    let k: KeygenHelper = serde_wasm_bindgen::from_value(auditorKeygenEvalAt1).unwrap();
    let e: Point = serde_wasm_bindgen::from_value(encryptedC1).unwrap();

    let my_keygen_result = &n.keygen_step1(2)[0];
    n.set_keyshare(&vec![&my_keygen_result,&k]);

    let result = n.partial_decrypt(&e);
    serde_wasm_bindgen::to_value(&result).unwrap()
}

// This is what the Auditor doeswhenever called : 
// 1. instantiates a node based on some secret key seed
// 2. sets the keygen polynomial based on this party and the other party's keygen result
// 3. fully decrypts a message
#[wasm_bindgen]
pub fn auditorDecrypt(seed: &[u8], litKeygenEvalAt2: JsValue, encrypted: JsValue, litPartialDecryption: JsValue) -> JsValue {
    let as_vec = seed.to_vec();
    let mut n = Node::init_from_seed(&as_vec, 2, 2, 2);
    let k: KeygenHelper = serde_wasm_bindgen::from_value(litKeygenEvalAt2).unwrap();
    let e: ElGamalEncryption = serde_wasm_bindgen::from_value(encrypted).unwrap();
    let d1: Point = serde_wasm_bindgen::from_value(litPartialDecryption).unwrap();

    let my_keygen_result = &n.keygen_step1(2)[1];
    n.set_keyshare(&vec![&my_keygen_result,&k]);

    let d2 = n.partial_decrypt(&e.c1);

    let decrypted = decrypt(e, vec![d1,d2], 2);
    serde_wasm_bindgen::to_value(&decrypted).unwrap()
}

#[wasm_bindgen]
pub fn auditorPubkeyShare(seed: &[u8], litKeygenEvalAt2: JsValue) -> JsValue {
    let as_vec = seed.to_vec();
    let mut n = Node::init_from_seed(&as_vec, 2, 2, 2);
    let k: KeygenHelper = serde_wasm_bindgen::from_value(litKeygenEvalAt2).unwrap();

    let my_keygen_result = &n.keygen_step1(2)[1];
    n.set_keyshare(&vec![&my_keygen_result,&k]);

    let pks = n.pubkey_share();
    serde_wasm_bindgen::to_value(&pks).unwrap()
}
#[wasm_bindgen]
pub fn litPubkeyShare(seed: &[u8], auditorKeygenEvalAt1: JsValue) -> JsValue {
    let as_vec = seed.to_vec();
    let mut n = Node::init_from_seed(&as_vec, 1, 2, 2);
    let k: KeygenHelper = serde_wasm_bindgen::from_value(auditorKeygenEvalAt1).unwrap();
    
    let my_keygen_result = &n.keygen_step1(2)[0];
    n.set_keyshare(&vec![&my_keygen_result,&k]);

    let pubkey = n.pubkey_share();
    serde_wasm_bindgen::to_value(&pubkey).unwrap()
}

#[wasm_bindgen]
pub fn sharedPubkey(pubkeyShares: JsValue) -> JsValue {
    let s: Vec<Point> = serde_wasm_bindgen::from_value(pubkeyShares).unwrap();
    let result = calculate_pubkey(s).unwrap();
    serde_wasm_bindgen::to_value(&result).unwrap()
}

/* For standard, nonthreshold ElGamal: */

// #[wasm_bindgen]
// pub fn standardDecryptPoint(privkey: String, c1x: String, c1y: String, c2x: String, c2y: String) -> String {
//     let prv = PrivateKey::import(
//         hex::decode(privkey)
//         .unwrap(),
//     ).unwrap();
//     let c1 = Point::from_xy_strings(c1x, c1y);
//     let c2 = Point::from_xy_strings(c2x, c2y);
//     let e = ElGamalEncryption {
//         c1: c1,
//         c2: c2
//     };
//     let d = prv.decrypt_elgamal(e);
//     serde_json::to_string(&d).unwrap()
// }

// #[wasm_bindgen]
// pub fn standardPubkey(privkey: String) -> String {
//     let prv = PrivateKey::import(
//         hex::decode(privkey)
//         .unwrap(),
//     ).unwrap();

//     serde_json::to_string(&prv.public()).unwrap()

// }