use std::env::{self, VarError};
use access::has_access;
use babyjubjub_elgamal::{Node, KeygenHelper};
use babyjubjub_rs::Point;
use rocket::{State, serde::json::Json, response::status::BadRequest};
use rocket::{Request, Response, fairing::{Fairing, Info, Kind}, http::{Header, Status}};
use serde::{Serialize, Deserialize};

#[macro_use] 
extern crate rocket;

mod access;


const ALLOW_ORIGINS: [&'static str; 2] = ["https://example.com", "http://localhost:3000"];
const THRESHOLD_NODES: usize = 2;
const TOTAL_NODES: usize = 2;

// pub struct Cors;
#[derive(Serialize,Deserialize)]
pub struct DecryptionRequest {
    pub c1: Point,
    pub nodes_to_decrypt_from: Vec<u32>,
}

// #[rocket::async_trait]
// impl Fairing for Cors {
//     fn info(&self) -> Info {
//         Info {
//             name: "Fairing to add the CORS headers",
//             kind: Kind::Response
//         }
//     }
//     async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
//         let _origin = _request.headers().get_one("origin").unwrap();
//         let origin = if ALLOW_ORIGINS.contains(&_origin) { _origin } else { "null" };

//         response.set_status(Status::new(200));
        
//         response.set_header(Header::new("Access-Control-Allow-Origin", origin));
//         response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET"));
//         response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
//         response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));

//     }
// }
// this route is solely so that a TLS connection can be started early before any user action and automatically cached by both parties. This avoids the handshake latency overhead when the user requests the OPRF
#[get("/")]
fn do_nothing() -> &'static str { "GM" }

#[post("/decrypt", format = "json", data = "<decrypt_request>")]
fn index(node: &State<Node>, decrypt_request: Json<DecryptionRequest>) -> Result<String, BadRequest<&'static str>> {
    // Check it is safe to proceed, i.e. point is on the curve and in subgroup
    if !decrypt_request.c1.on_curve() {
        return Err(BadRequest(Some("Not on curve")));
    }

    // Note: in_subgroup just checks that order of the point is the order of the subgroup
    if !decrypt_request.c1.in_subgroup() {
        return Err(BadRequest(Some("Not in subgroup")));
    }

    let result = node.partial_decrypt(&decrypt_request.c1, &decrypt_request.nodes_to_decrypt_from); 
    Ok(serde_json::to_string(&result).unwrap())
    // format!("Hello, world! my private key is {}. you want me to multiply it by {:?}", privkey, point)
}


#[launch]
fn rocket() -> _ {
    println!("has access {}", has_access(123));
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
    match env::var("ZK_ESCROW_KEYGEN_EVALUATIONS_FOR_MY_NODE") {
        Ok(s) => { 
            let keygen_helpers: Vec<KeygenHelper> = serde_json::from_str(&s.replace("\\", "")).unwrap(); 
            let as_pointers: Vec<&KeygenHelper> = keygen_helpers.iter().collect();
            node.set_keyshare(&as_pointers);
        },
        Err(e) => {
            let deleteme = node.keygen_step1(TOTAL_NODES);
            let deleteme2 = serde_json::to_string(&deleteme).unwrap();
            let deleteme3: Vec<KeygenHelper> = serde_json::from_str(&deleteme2).unwrap();
            println!("abc {:?} !!!!!! {:?}", deleteme, deleteme3);
            let keygen = node.keygen_step1(TOTAL_NODES);
            panic!("Keygen step 1 has not been done yet. Please perform keygen on all nodes by exchanging the shares meant for them. Then store an array of the KeygenHelpers for your node in JSON format as the env var ZK_ESCROW_KEYGEN_EVALUATIONS_FOR_MY_NODE. Then you may run this again. My KeygenHelpers for the other nodes are: {:?}", serde_json::to_string(&keygen).unwrap());
        }
    }

    rocket::build()
    .manage(node)
    // .attach(Cors)
    .mount("/", routes![index, do_nothing])
}
