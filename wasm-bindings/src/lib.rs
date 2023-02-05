use std::str::FromStr;

use wasm_bindgen::prelude::*;
use num_bigint::BigInt;
use babyjubjub_rs::{Fr, Point, ElGamalEncryption, encrypt_elgamal};
extern crate console_error_panic_hook;

// Note: no constant-time gaurantees

#[wasm_bindgen]
pub fn msg_to_point(m: String) -> String {
    let m_big = BigInt::from_str(&m).unwrap();
    let p = Point::from_msg_vartime(&m_big);
    serde_json::to_string(&p).unwrap()
}

#[wasm_bindgen]
pub fn point_to_msg(x: String, y: String) -> String {
    Point::from_xy_strings(x, y).to_msg().to_string()
}

#[wasm_bindgen]
pub fn encrypt_point(msg_x: String, msg_y: String, pub_x: String, pub_y: String, nonce: String) -> String {
    let msg = Point::from_xy_strings(msg_x, msg_y);
    let pk = Point::from_xy_strings(pub_x, pub_y);
    let nonce_big: BigInt = BigInt::from_str(&nonce).unwrap();
    let e = encrypt_elgamal(&pk, &nonce_big, &msg);
    "hey".to_string()// serde_json::to_string(e)
}

// #[wasm_bindgen]
// pub fn decrypt_to_point() -> String {

// }
