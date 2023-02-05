use wasm_bindgen::prelude::*;
use babyjubjub_rs::{PrivateKey, };
extern crate console_error_panic_hook;
use std::panic;

#[wasm_bindgen]
pub fn encrypt_point() -> ElGamalEncryption {

}

#[wasm_bindgen]
pub fn decrypt_point() -> Point {

}
#[wasm_bindgen]
pub fn msg_to_point() -> Point {

}

#[wasm_bindgen]
pub fn point_to_msg() -> BigInt {

}