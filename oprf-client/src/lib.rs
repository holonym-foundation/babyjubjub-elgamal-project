use std::{panic, str::FromStr};

use babyjubjub_rs::{Point, SUBORDER, B8, Fr, ToDecimalString, Fl};
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

pub fn step1(plaintext: &str) -> Step1Result {
    let pt_vec = plaintext.as_bytes().to_vec();
        let hashed = BigInt::from_bytes_be(Sign::Plus, &hash(pt_vec));

        let rnd_bi = rand::thread_rng().gen_bigint_range(&BigInt::from_str("0").unwrap() , &SUBORDER);
        let rnd_fl = Fl::from_str(&rnd_bi.to_string()).unwrap();
        let rnd_fl_inv = rnd_fl.inverse().unwrap();
        let rnd_point = B8.mul_scalar(&rnd_bi);

        Step1Result {
            masked: rnd_point.mul_scalar(&hashed),
            unmasker_keepthissecret: rnd_fl_inv.to_dec_string(),
        }
}

pub fn step2(unmasker: String, server_response: Point) -> Vec<u8> {
    let unmasker_bi = BigInt::from_str(unmasker.as_str()).unwrap();
        let unmasked = server_response.mul_scalar(&unmasker_bi);
        let (_, unmasked_bytes) = BigInt::from_str(&unmasked.x.to_dec_string()).unwrap().to_bytes_be();
        hash(unmasked_bytes.to_vec()).to_vec()
}


#[wasm_bindgen]
impl Client {
    pub fn step1(plaintext: &str) -> JsValue {
        serde_wasm_bindgen::to_value(&step1(plaintext)).unwrap()
    }

    pub fn step2(unmasker: String, point: JsValue) -> Vec<u8> {
        let p: Point = serde_wasm_bindgen::from_value(point).unwrap();
        step2(unmasker, p)
    }
}




#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use babyjubjub_rs::Point;
    use num_bigint::BigInt;

    use crate::{step1, step2};

    // Simulates a server by multiplying the point by a private key
    // Note it does not perform security checks on the input before multiplying it by its private key
    fn mock_server(masked: Point, privkey: BigInt) -> Point {
        masked.mul_scalar(&privkey)
    }

    fn mock_interaction(input: &str) -> Vec<u8> {
        let masked_and_mask = step1(input);
        let server_response = mock_server(masked_and_mask.masked, BigInt::from_str("69").unwrap());
        step2(masked_and_mask.unmasker_keepthissecret, server_response)
    }

    #[test]
    fn test_determinism() {
        // Makes sure same input gives same output. This seems to be essentially all we need to test client-side unless i'm missing something.
        assert_eq!(mock_interaction("abc"), mock_interaction("abc"));
    }
}