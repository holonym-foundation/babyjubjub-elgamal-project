use std::env;
use babyjubjub_elgamal::Node;
use babyjubjub_rs::Point;
use rocket::{State, serde::json::Json, response::status::BadRequest};
use rocket::{Request, Response, fairing::{Fairing, Info, Kind}, http::{Header, Status}};

#[macro_use] extern crate rocket;

pub struct Cors;

const ALLOW_ORIGINS: [&'static str; 2] = ["https://example.com", "http://localhost:3000"];
const THRESHOLD_NODES: usize = 2;
const TOTAL_NODES: usize = 2;

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "Fairing to add the CORS headers",
            kind: Kind::Response
        }
    }
    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        let _origin = _request.headers().get_one("origin").unwrap();
        let origin = if ALLOW_ORIGINS.contains(&_origin) { _origin } else { "null" };

        response.set_status(Status::new(200));
        
        response.set_header(Header::new("Access-Control-Allow-Origin", origin));
        response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));

    }
}
// this route is solely so that a TLS connection can be started early before any user action and automatically cached by both parties. This avoids the handshake latency overhead when the user requests the OPRF
#[get("/")]
fn do_nothing() -> &'static str { "GM" }

#[post("/decrypt", format = "json", data = "<point>")]
fn index(node: &State<Node>, point: Json<Point>) -> Result<String, BadRequest<&'static str>> {
    // Check it is safe to proceed, i.e. point is on the curve and in subgroup
    if !point.on_curve() {
        return Err(BadRequest(Some("Not on curve")));
    }

    // Note: in_subgroup just checks that order of the point is the order of the subgroup
    if !point.in_subgroup() {
        return Err(BadRequest(Some("Not in subgroup")));
    }

    let result = node.partial_decrypt(&point); 
    Ok(serde_json::to_string(&result).unwrap())
    // format!("Hello, world! my private key is {}. you want me to multiply it by {:?}", privkey, point)
}

#[launch]
fn rocket() -> _ {
    // Get the node's private key seed key env var
    let privkey: String = env::var("ZK_ESCROW_SECRET_SEED")
        .expect("ZK_ESCROW_SECRET_SEED must be an environment variable. It should be a random 32-byte hex string from a secure random number generator.");
    
    let my_node_number: usize = env::var("ZK_ESCROW_NODE_NUMBER")
        .expect("ZK_ESCROW_NODE_NUMBER must be an environment variable. It should be an integer between 1 and the total number of nodes.")
        .parse()
        .unwrap();

    let node: Node = Node::init_from_seed(
        &hex::decode(privkey).unwrap(), 
        my_node_number,
        THRESHOLD_NODES,
        TOTAL_NODES, 
    );
    rocket::build()
    .manage(node)
    .attach(Cors)
    .mount("/", routes![index, do_nothing])
}
