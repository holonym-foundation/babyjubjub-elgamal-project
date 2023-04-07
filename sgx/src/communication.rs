use ff::*;
use babyjubjub_rs::{Point, Fr, FrBigIntConversion, B8, SUBORDER};
use libaes::Cipher;
use rand::{Rng, thread_rng};
use num_bigint::BigInt;
use sha2::{Sha256, Digest};
use blake2::{Blake2b512};
use num_bigint::Sign::Plus;
extern crate serde;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AES128EncryptionFromECDHSecret {
    from: Point,
    iv: [u8; 16],
    ciphertext: Vec<u8>
}
pub struct Comms {
    // Should be a random element in Fl field (l is order of BabyJubJub subgroup)
    privkey: BigInt,
}

impl Comms {
    pub fn pubkey(&self) -> Point {
        B8.mul_scalar(&self.privkey)
    }
    // returns an AES128 128-bit secret key derived from ECDH over BabyJubJub subgroup
    pub fn get_shared_secret(&self, with_pubkey: Point) -> [u8; 16] {
        // Check pubkey is part of subgroup
        assert!(with_pubkey.on_curve(), "Public key isn't on the curve");
        assert!(with_pubkey.in_subgroup(), "Public key isn't in the subgroup");

        // Get AES key from ECDH
        let dh_secret = with_pubkey.mul_scalar(&self.privkey).x;
        let (_, dh_secret_bytes) = dh_secret.to_bigint().to_bytes_le();
        let mut hasher = Sha256::new();
        hasher.update(dh_secret_bytes);
        let key_full = hasher.finalize();

        key_full[0..16].try_into().unwrap()
    }

    pub fn encrypt_to(&self, to_pubkey: Point, msg: &[u8]) -> AES128EncryptionFromECDHSecret {
        // Generate random initialization vector
        let mut rng = thread_rng();
        let mut iv = [0u8; 16];
        rng.fill(&mut iv[..]);

        // Encrypt
        let key = self.get_shared_secret(to_pubkey);
        let cipher = Cipher::new_128(&key);
        AES128EncryptionFromECDHSecret {
            from: self.pubkey(),
            iv: iv,
            ciphertext: cipher.cbc_encrypt(&iv, msg)
        }
        
    }

    pub fn decrypt(&self, encryption: AES128EncryptionFromECDHSecret) -> Vec<u8> {
        let key = self.get_shared_secret(encryption.from);
        let cipher = Cipher::new_128(&key);
        cipher.cbc_decrypt(&encryption.iv, &encryption.ciphertext)
        
    }
    // Convenience method to be used with SGX sealing. We can just hash it; it's strong enough
    pub fn from_16byte_key(short_key: [u8; 16]) -> Comms {
        let mut h = Blake2b512::new();
        h.update(short_key);
        let key = h.finalize();
        let sub_order = SUBORDER.clone();
        Comms { privkey: {BigInt::from_bytes_be(Plus, &key) % sub_order }}
        
        
    }

}

#[cfg(test)]
mod tests {
    use crate::communication::*;
    use babyjubjub_rs::B8;
    // use babyjubjub_rs::{Point,Fr};
    use ff::PrimeField;
    use std::{str::FromStr, env};
    #[test] fn init() {
        env::set_var("RUST_BACKTRACE", "1");
    }
    #[test]
    fn encrypt_decrypt() {
        let comm1 = Comms {
            privkey: BigInt::from_str("123456789").unwrap()
        };
        let comm2 = Comms {
            privkey: BigInt::from_str("987654321234567898765432123456789").unwrap()
        };

        let msgs: Vec<String> = vec![
            "gm comm2".to_string(),
            "Heyyyyyyy comm2 hows it goin i got a looooooooooooong message for you if you can decrypt it ;)".to_string()
        ];

        msgs.iter().for_each(|m| {
            let encrypted = comm1.encrypt_to(comm2.pubkey(), m.as_bytes());
            let decrypted = comm2.decrypt(encrypted);
            assert_eq!(*m, String::from_utf8(decrypted).unwrap());
        });
    

        // let encrypted_longmsg = comm1.encrypt_to(comm2.pubkey(), b"Heyyyyyyy comm2 hows it goin");
        // let decrypted_longms = comm2.decrypt(encrypted);
        // println!("Decrypting..., {:?}", decrypted);
        
    }
}