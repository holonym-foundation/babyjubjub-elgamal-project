use std::{env, str::FromStr};

use access::has_access;
use babyjubjub_elgamal::{Node, KeygenHelper};
use babyjubjub_rs::{Point, ToDecimalString};
use num_bigint::BigInt;
use rocket::{State, serde::json::Json, response::status::BadRequest};
use serde::{Serialize, Deserialize};
use dotenv::dotenv;

#[macro_use] 
extern crate rocket;

mod access;


const THRESHOLD_NODES: usize = 2;
const TOTAL_NODES: usize = 2;

#[derive(Serialize,Deserialize)]
pub struct DecryptionRequest {
    pub c1: Point,
    pub nodes_to_decrypt_from: Vec<u32>,
    // pub auth: String,
}

#[get("/")]
fn do_nothing() -> &'static str { "GM" }

#[post("/decrypt", format = "json", data = "<decrypt_request>")]
async fn index(node: &State<Node>, decrypt_request: Json<DecryptionRequest>) -> Result<String, BadRequest<&'static str>> {
    // Check it is safe to proceed, i.e. point is on the curve and in subgroup
    if !decrypt_request.c1.on_curve() {
        return Err(BadRequest(Some("Not on curve")));
    }

    // Note: in_subgroup just checks that order of the point is the order of the subgroup
    if !decrypt_request.c1.in_subgroup() {
        return Err(BadRequest(Some("Not in subgroup")));
    }

    // See if the point (as represented by c1x) should be decrypted
    let c1x = decrypt_request.c1.x.to_dec_string();
    let (_, c1x_bytes) = BigInt::from_str(&c1x).unwrap().to_bytes_be();


    // Asynchronous call to has_access on the c1x_bytes
    let mut ha = tokio::task::spawn_blocking(move || {
        has_access(&c1x_bytes.as_slice().try_into().unwrap())
    }).await.expect("failed to query the blockchain for access to data");
    println!("has access xyz {}", ha);

    if !ha {
        return Err(BadRequest(Some("No access")));
    }

    let result = node.partial_decrypt(&decrypt_request.c1, &decrypt_request.nodes_to_decrypt_from); 
    Ok(serde_json::to_string(&result).unwrap())
}


#[launch]
fn rocket() -> _ {
    dotenv().ok();
    
    // Get the node's private key seed key env var
    let privkey: String = env::var("ZK_ESCROW_SECRET_SEED")
        .expect("ZK_ESCROW_SECRET_SEED must be an environment variable. It should be a random 32-byte hex string from a secure random number generator.");
    
    let my_node_number: usize = env::var("ZK_ESCROW_NODE_NUMBER")
        .expect("ZK_ESCROW_NODE_NUMBER must be an environment variable. It should be an integer between 1 and the total number of nodes.")
        .parse()
        .unwrap();

    let mut node: Node = Node::init_from_seed(
        &hex::decode(privkey).unwrap(), 
        my_node_number,
        THRESHOLD_NODES,
        TOTAL_NODES, 
    );

    // If keygen step one has not been done, do it now
    match env::var("ZK_ESCROW_KEYGENS4ME") {
        Ok(s) => { 
            let keygen_helpers: Vec<KeygenHelper> = serde_json::from_str(&s.replace("\\", "")).unwrap(); 
            let as_pointers: Vec<&KeygenHelper> = keygen_helpers.iter().collect();
            node.set_keyshare(&as_pointers);
        },
        Err(e) => {
            let keygen = node.keygen_step1(TOTAL_NODES);
            panic!("Keygen step 1 has not been done yet. Please perform keygen on all nodes by exchanging the shares meant for them. Then store an array of the KeygenHelpers for your node in JSON format as the env var ZK_ESCROW_KEYGENS4ME. Then you may run this again. My KeygenHelpers for the other nodes are: {:?}", serde_json::to_string(&keygen).unwrap());
        }
    }

    rocket::build()
    .manage(node)
    .mount("/", routes![index, do_nothing])
}
