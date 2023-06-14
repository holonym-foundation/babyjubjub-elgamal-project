use std::panic;
use std::{error, fmt, str::FromStr};

use babyjubjub_rs::{Point, SUBORDER, ToDecimalString, Fl, DLEQProof};
use ff::{PrimeField, Field};
use num_bigint::{BigInt, RandBigInt};
use serde::{Serialize, Deserialize};

// JS Client
use wasm_bindgen::prelude::*;
use blake2::{Blake2b512, Digest};

type Result<T> = std::result::Result<T, JsError>;

#[derive(Serialize, Deserialize, Debug)]
pub enum Error {
    InvalidInput(String),
    FailedToVerifyProof(String),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::FailedToVerifyProof(ref s) => write!(f, "FailedToVerifyProof: {}", s),
            Error::InvalidInput(ref s) => write!(f, "InvalidInput: {}", s),
        }
    }
}
impl error::Error for Error {}
// impl Into<JsError> for Error {
//     fn into(self) -> JsValue {
//         JsValue::from_str(self.to_string().as_str())
//     }
// }

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

pub fn hash(input: Vec<u8>) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

pub fn hash_to_curve(plaintext: &str) -> std::result::Result<Point, Error> {
    Point::hash_to_curve_bls(plaintext.as_bytes())
    .ok_or(Error::InvalidInput(plaintext.to_string()).into())
}

pub fn step1(plaintext: &str) -> std::result::Result<Step1Result, Error> {
        let hashed = &hash_to_curve(plaintext)?;

        let rnd_bi = rand::thread_rng().gen_bigint_range(&BigInt::from_str("0").unwrap(), &SUBORDER);
        let rnd_fl = Fl::from_str(&rnd_bi.to_string()).unwrap();
        let rnd_fl_inv = rnd_fl.inverse().unwrap();

       Ok(Step1Result {
            masked: hashed.mul_scalar(&rnd_bi),
            unmasker_keepthissecret: rnd_fl_inv.to_dec_string(),
        })
}

pub fn step2(unmasker: String, server_response: DLEQProof) -> std::result::Result<Vec<u8>, Error> {
    if !server_response.verify() { return Err(Error::FailedToVerifyProof("failed to verify VOPRF ZKP".to_string()).into()); }
    let unmasker_bi = BigInt::from_str(unmasker.as_str()).map_err(|e|Error::InvalidInput(e.to_string()))?;
        let unmasked = server_response.xB.mul_scalar(&unmasker_bi);
        let (_, unmasked_bytes) = BigInt::from_str(&unmasked.x.to_dec_string())
            .map_err(|e|Error::InvalidInput(e.to_string()))?
            .to_bytes_be();
        Ok(hash(unmasked_bytes).to_vec())
}


#[wasm_bindgen]
impl Client {
    pub fn step1(plaintext: &str) -> Result<JsValue> {
            step1(plaintext)
            .map(|o|serde_wasm_bindgen::to_value(&o).unwrap())
            .map_err(|e|e.into())
    }

    pub fn step2(unmasker: String, response: JsValue) -> Result<Vec<u8>> {
        let res: DLEQProof = serde_wasm_bindgen::from_value(response).map_err(|e|Error::InvalidInput(e.to_string()))?;
        step2(unmasker, res)
            .map(|o|o.into())
            .map_err(|e|e.into())
    }
}




#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use babyjubjub_rs::{Point, B8, DLEQProof, Fl, FrBigIntConversion};
    use num_bigint::BigInt;
    use super::Result;
    use crate::{step1, step2, Error};

    // Simulates a server by multiplying the point by a private key
    // Note it does not perform security checks on the input before multiplying it by its private key
    // We trust that its response's xA is the correct public key
    fn mock_server(masked: &Point, privkey: Fl) -> std::result::Result<DLEQProof, Error> {
        DLEQProof::new(privkey, B8.clone(), masked.clone())
        
        .map_err(|e|Error::InvalidInput(e.to_string()).into())
    }

    fn mock_interaction(input: &str) -> std::result::Result<Vec<u8>, Error> {
        let masked_and_mask = step1(input)?;
        let privkey = &BigInt::from_str("69").unwrap();
        let proof = mock_server(&masked_and_mask.masked, Fl::from_bigint(&privkey))?;
        step2(masked_and_mask.unmasker_keepthissecret, proof)
    }

    #[test]
    fn test_determinism() {
        println!("Determinism test {:?}", mock_interaction("abc").unwrap());
        // Makes sure same input gives same output. This seems to be essentially all we need to test client-side unless i'm missing something.
        assert_eq!(mock_interaction("abc").unwrap(), mock_interaction("abc").unwrap());
    }
    // TODO: test distribution of outputs is random
}