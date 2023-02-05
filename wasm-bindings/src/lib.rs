use std::str::FromStr;

use wasm_bindgen::prelude::*;
use num_bigint::BigInt;
use babyjubjub_rs::{Point, ToDecimalString, ElGamalEncryption, encrypt_elgamal, PrivateKey};

extern crate console_error_panic_hook;
use std::panic;

// Note: no constant-time gaurantees


#[wasm_bindgen]
pub fn enable_errors() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}

#[wasm_bindgen]
pub fn msg_to_point(m: String) -> String {
    let m_big = BigInt::from_str(&m).unwrap();
    let p = Point::from_msg_vartime(&m_big);
    serde_json::to_string(&p).unwrap()
}

#[wasm_bindgen]
pub fn point_to_msg(x: String, y: String) -> String {
    Point::from_xy_strings(x, y).to_msg().to_dec_string()
}

#[wasm_bindgen]
pub fn encrypt_point(msg_x: String, msg_y: String, pub_x: String, pub_y: String, nonce: String) -> String {
    let msg = Point::from_xy_strings(msg_x, msg_y);
    let pk = Point::from_xy_strings(pub_x, pub_y);
    let nonce_big: BigInt = BigInt::from_str(&nonce).unwrap();
    let e = encrypt_elgamal(&pk, &nonce_big, &msg);
    serde_json::to_string(&e).unwrap()
}

#[wasm_bindgen]
pub fn decrypt_to_point(privkey: String, c1x: String, c1y: String, c2x: String, c2y: String) -> String {
    let prv = PrivateKey::import(
        hex::decode(privkey)
        .unwrap(),
    ).unwrap();
    let c1 = Point::from_xy_strings(c1x, c1y);
    let c2 = Point::from_xy_strings(c2x, c2y);
    let e = ElGamalEncryption {
        c1: c1,
        c2: c2
    };
    let d = prv.decrypt_elgamal(e);
    serde_json::to_string(&d).unwrap()
}