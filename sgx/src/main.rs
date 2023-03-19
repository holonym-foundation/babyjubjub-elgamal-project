use sgx_isa::{Attributes, Miscselect, ErrorCode, Keyname, Keypolicy, Keyrequest, Report};
use rand::random;
extern crate serde;
use serde::{Serialize, Deserialize};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};
use generic_array::{GenericArray, ArrayLength};
use babyjubjub_rs::{Point, ToDecimalString, ElGamalEncryption, encrypt_elgamal, PrivateKey};
// use babyjubjub_elgamal::{Node, KeygenHelper, decrypt, calculate_pubkey};

// For key sealing
#[derive(Debug, Serialize, Deserialize)]
pub struct Seal {
    label: [u8; 16],
    seal_data: SealData
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SealData {
    rand: [u8; 16],
    isvsvn: u16,
    cpusvn: [u8; 16],
    /* Commenting out so don't have to work with serialization and deserialization of these unusual structs */
    // // Record attributes and miscselect so that we can verify that
    // // we can derive the correct wrapping key, but the actual input
    // // to the derivation is CPU enclave state + SW-specified masks.
    // attributes: Attributes, //Serializable,
    // miscselect: Miscselect //Serializable,
}

fn egetkey(label: [u8; 16], seal_data: &SealData) -> Result<[u8; 16], ErrorCode> {
    // Key ID is combined from fixed label and random data
    let mut keyid = [0; 32];
    let (label_dst, rand_dst) = keyid.split_at_mut(16);
    label_dst.copy_from_slice(&label);
    rand_dst.copy_from_slice(&seal_data.rand);
    Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRENCLAVE, //MRENCLAVE restricts key reading to only Enclaves with the same measurements. MRSIGNER resistricts to encalves by the same signer: https://www.intel.com/content/www/us/en/developer/articles/technical/introduction-to-intel-sgx-sealing.html
        isvsvn: seal_data.isvsvn,
        cpusvn: seal_data.cpusvn,
        attributemask: [!0; 2],
        keyid: keyid,
        miscmask: !0,
            ..Default::default()
    }.egetkey()
}

pub fn get_seal_key_for_label(label: [u8; 16]) -> ([u8; 16], SealData) {
    let report = Report::for_self();

    let seal_data = SealData {
        rand: random(),
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        // attributes: report.attributes,
        // miscselect: report.miscselect
    };
    // Return the key and data to to store alongside the label
    (egetkey(label, &seal_data).unwrap(), seal_data)
}

pub fn recover_seal_key(s: Seal) -> Result<[u8; 16], ErrorCode> {
    // let report = Report::for_self();

    // if report.attributes != seal_data.attributes 
    // || report.miscselect != seal_data.miscselect
    // {
    //     return Err(ErrorCode::InvalidAttribute)
    // }
    egetkey(s.label, &s.seal_data)
}

fn main() {
    let r: [u8; 32] = random();
    let p = PrivateKey::import(r.to_vec()).unwrap();
    // let cipher = Aes256Gcm::new(&GenericArray::from_slice(&r));
    // let nonce_slice = b"nonce to encrypt private key with sealing key";
    // let nonce = Nonce::from_slice(nonce_slice);
    println!("heyyyyyy, {:?}", p.public());


    use crypto::aes_gcm::AesGcm;
    use crypto::aead::{AeadDecryptor, AeadEncryptor};
    let key_size = crypto::aes::KeySize::KeySize128;
    let key: [u8; 16] = random();
    let iv: [u8; 16] = random();
    let additional_data = [0 as u8; 16];
    let plaintext = [69 as u8; 32];
    let enc_cipher = AesGcm::new(key_size, &key, &iv, &additional_data);
    let out = [0 as u8; 16];
    let out_tag = [0 as u8; 16];
    let ciphertext = cipher.encrypt(&plaintext, &mut out[..],&mut out_tag[..]);
    
    let dec_cipher = AesGcm::new(key_size, &key, &iv, &additional_data);

    // use aes_gcm_siv::{
    //     aead::{Aead, KeyInit, OsRng},
    //     Aes256GcmSiv, Nonce // Or `Aes128GcmSiv`
    // };

    // let cipher = Aes256GcmSiv::new(&key);
    // let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
    // let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref()).unwrap();
    // let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    // assert_eq!(&plaintext, b"plaintext message");    
}

#[cfg(test)]
mod tests {
    use crate::get_seal_key_for_label;
    use crate::recover_seal_key;
    use crate::Seal;
    #[test]
    fn seal_unseal() {
        // 1. create key & serialize its seal
        // Some label for the key
        let label: [u8; 16] = [69; 16];
        let (key, seal_data) = get_seal_key_for_label(label);
        let seal = Seal {
            label: label,
            seal_data: seal_data
        };
        let ser_seal: String = serde_json::to_string(&seal).unwrap();
        
        // 2. Deserialize and recover key
        let de_seal: Seal = serde_json::from_str(&ser_seal).unwrap();
        let recovered = recover_seal_key(de_seal).unwrap();

        // 3. Assert key was recovered correctly
        assert_eq!(key, recovered);
    }
}

/*  To do: 
    * note it doesn't matter whether it's communicated via tls for mvp, we know code is running in the enclave
    1. generate random seed for polynomial
    2. incorporate this as a workspace 
*/