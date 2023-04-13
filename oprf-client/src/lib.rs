use std::{panic, str::FromStr};

use babyjubjub_rs::{Point, SUBORDER, B8, Fr, ToDecimalString};
use ff::{PrimeField, Field};
use num_bigint::{BigInt, Sign, RandBigInt};
use serde::{Serialize, Deserialize};
// JS Client
use wasm_bindgen::prelude::*;
use blake2::{Blake2b512, Digest};

#[wasm_bindgen]
pub fn enable_errors() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
}

#[wasm_bindgen]
pub struct Client {}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Step1Result {
    masked: Point,
    unmasker_keepthissecret: String,
}

pub fn hash(input: Vec<u8>) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    hasher.update(input);
    hasher.finalize().to_vec().try_into().unwrap()
}

#[wasm_bindgen]
impl Client {
    pub fn step1(plaintext: &str) -> JsValue {
        let pt_vec = plaintext.as_bytes().to_vec();
        let hashed = BigInt::from_bytes_be(Sign::Plus, &hash(pt_vec));

        let rnd_bi = rand::thread_rng().gen_bigint_range(&BigInt::from_str("0").unwrap() , &SUBORDER);
        let rnd_fr = Fr::from_str(&rnd_bi.to_string()).unwrap();
        let rnd_fr_inv = rnd_fr.inverse().unwrap();
        let rnd_point = B8.mul_scalar(&rnd_bi);


        let result = Step1Result {
            masked: rnd_point.mul_scalar(&hashed),
            unmasker_keepthissecret: rnd_fr_inv.to_dec_string(),
        };
        serde_wasm_bindgen::to_value(&result).unwrap()
    }

    pub fn step2(unmasker: String, point: JsValue) -> Vec<u8> {
        let p: Point = serde_wasm_bindgen::from_value(point).unwrap();
        let unmasker_bi = BigInt::from_str(unmasker.as_str()).unwrap();
        let unmasked = p.mul_scalar(&unmasker_bi);
        let (_, unmasked_bytes) = BigInt::from_str(&unmasked.x.to_dec_string()).unwrap().to_bytes_be();
        hash(unmasked_bytes.to_vec()).to_vec()
    }
}