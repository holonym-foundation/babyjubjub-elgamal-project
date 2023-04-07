extern crate serde;
use babyjubjub_elgamal::Node;
use clap::{Parser, Subcommand};
// use colored::Colorize;
use crate::sealing::{get_seal_key_for_label, recover_seal_key, Seal};
mod sealing;
mod communication;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, value_name = "NODE_IDX")] 
    idx: usize,
    #[arg(short, long, value_name = "P2P_SECRET_KEY_SEAL")] 
    comms: Option<String>,
    #[arg(short, long, value_name = "SECRET_KEYGEN_SEAL")] 
    keygenseal: Option<String>,
    #[arg(short, long, value_name = "THEIR_KEYGEN_ENCRYPTED_TO_ME")]
    theirkeygen: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
    
    
}
#[derive(Subcommand)]
enum Commands {
    Keygen {
        /// Who to evaluate the keygen for (idx)
        #[arg(long, value_name = "EVAL_FOR_IDX")] 
        evalforidx: usize,
        /// Who to encrypt the keygen for (comm pubkey JSON {x: "x coordinate", y: "y coordinate"})
        #[arg(long, value_name = "EVAL_FOR_IDX")] 
        evalforpubkey: String,
        /// My keygen, sealed
        #[arg(short, long, value_name = "SECRET_KEYGEN_SEAL")] 
        keygenseal: Option<String>,
        /// Their keygen, encrypted to me
        #[arg(short, long, value_name = "THEIR_KEYGEN_ENCRYPTED_TO_ME")]
        theirkeygen: Option<String>,
        /// My communication key, sealed
        #[arg(short, long, value_name = "P2P_SECRET_KEY_SEAL")] 
        comms: Option<String>,
    },

    PartialDecrypt {
        /// JSON ElGamalEncryption
        #[arg(short, long, value_name = "CIPHERTEXT")]
        ciphertext: String
    }
}

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");
    // use hyper::{Client, Uri};

    // let client = Client::new();

    // let res = client
    //     .get(Uri::from_static("http://httpbin.org/ip"));

    // 
    // println!("WOW, HERE IS THE EXTERNAL FUNCTION {}", customtls::https_get());
    // let args: Vec<String> = env::args().collect();
    
    // Seal key:
    let key_keygen: [u8; 16];
    let seal_keygen: Seal;
    let label_keygen: &[u8; 16] = b"secretshare seal";

    let key_comms: [u8; 16];
    let seal_comms: Seal;
    let label_comms: &[u8; 16] = b"com privkey seal";

    let args = Args::parse();

    // Reconstruct node from keygen seal
    if let Some(s) = args.keygenseal {
        seal_keygen = match serde_json::from_str(&s) {
                        Ok(deser) => deser,
                        Err(e) => panic!("Failed to deserialize keygen seal. Error: {}",e)
                    };
        key_keygen = match recover_seal_key(seal_keygen) {
            Ok(k) => k,
            Err(e) => panic!("Failed to decrypt keygen seal. Error: {:?}", e)
        };
        println!("Successfully recovered keygen from seal");
    } else {
        println!("A keygen Seal wasn't supplied- creating new keygen. To use a sealed private key, provide a JSON string representing the Seal to this script using the --keygenseal flag");
        (key_keygen, seal_keygen) = get_seal_key_for_label(*label_keygen);
        println!("\x1b[93mGenerated new keygen. If you'd like to use it later, save this JSON object and supply it to this script using the --keygenseal flag: \n{:?}\x1b[0m", serde_json::to_string(&seal_keygen).unwrap())
    }

    // Create the Node struct from the keygen share
    // Create seed for random polynomial (16 bytes is enough randomness; the rest can all be zeros)
    let mut padded = key_keygen.to_vec();
    padded.append(&mut [0 as u8; 16].to_vec());
    // let p = PrivateKey::import(padded).unwrap();
    let node = Node::init_from_seed(&padded, args.idx, 2, 2);  
    println!("This nodes' public keygen is : {:?}", node.pubkey_share()); 
    println!("Note ^ this public keygen will be different if the enclave measurements do not match the measurements before. I.e., if the code has changed.");

    // Reconstruct Comms from communication key seal
    if let Some(s) = args.comms {
        seal_comms = match serde_json::from_str(&s) {
                        Ok(deser) => deser,
                        Err(e) => panic!("Failed to deserialize communication key seal. Error: {}",e)
                    };
        key_comms = match recover_seal_key(seal_comms) {
            Ok(k) => k,
            Err(e) => panic!("Failed to decrypt communication key seal. Error: {:?}", e)
        };
        println!("Successfully recovered communication private key from seal");
    } else {
        println!("A communication key Seal wasn't supplied - creating new communication private key. To use a sealed private key, provide a JSON string representing the Seal using the --coms flag");
        (key_comms, seal_comms) = get_seal_key_for_label(*label_comms);
        println!("\x1b[93mGenerated new communication secret key. If you'd like to use it later, save this JSON object and supply it to this script using the --comms flag: {:?}\x1b[0m", 
        serde_json::to_string(&seal_comms).unwrap())
    }
    

    
    // Command-specific actions
    match args.command {
        Some(Commands::Keygen { evalforidx, evalforpubkey, keygenseal, theirkeygen, comms }) => {
            println!("For node {}: {}", evalforidx, 69/*, node.keygen_for(evalforidx)*/); //TODO: encrypt too
        }
        _ => {}
    }
     
}



/*  To do: 
    * note it doesn't matter whether it's communicated via tls for mvp, we know code is running in the enclave
    1. generate random seed for polynomial
    2. incorporate this as a workspace 
*/