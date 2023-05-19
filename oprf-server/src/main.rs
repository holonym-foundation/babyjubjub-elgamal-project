use std::{env, collections::HashSet, str::FromStr};

use babyjubjub_rs::{Point};
use num_bigint::{BigInt};
use rocket::{State, serde::json::Json, response::status::BadRequest};
use rocket::{Request, Response, fairing::{Fairing, Info, Kind}, http::{Header, Status}};

// use rocket_contrib::json::Json;use std::env;
#[macro_use] extern crate rocket;

pub struct Cors;
const ALLOW_ORIGINS: [&'static str; 5] = ["https://silkwallet.net", "https://silksecure.net","http://localhost:3000", "http://localhost:3001", "https://silk-delta.vercel.app"];

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
        
        response.set_header(Header::new("Access-Control-Allow-Origin", origin)); //CHANGE THIS TO ONLY SAFE SITES
        response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));

    }
}
// this route is solely so that a TLS connection can be started early before any user action and automatically cached by both parties. This avoids the handshake latency overhead when the user requests the OPRF
#[get("/")]
fn do_nothing() -> &'static str { "GM" }

#[post("/oprf", format = "json", data = "<point>")]
fn index(privkey: &State<BigInt>, point: Json<Point>) -> Result<String, BadRequest<&'static str>> {
    // Check it is safe to proceed, i.e. point is on the curve and in subgroup
    if !point.on_curve() {
        return Err(BadRequest(Some("Not on curve")));
    }

    // Note: in_subgroup just checks that order of the point is the order of the subgroup
    if !point.in_subgroup() {
        return Err(BadRequest(Some("Not in subgroup")));
    }

    let result = point.mul_scalar(&privkey);
    Ok(serde_json::to_string(&result).unwrap())
    // format!("Hello, world! my private key is {}. you want me to multiply it by {:?}", privkey, point)
}

#[launch]
fn rocket() -> _ {
    // Setup CORS
    // let allowed_origins = AllowedOrigins::some_exact(&["https://silkwallet.net", "http://localhost:3000", "http://127.0.0.1:3000"]);
    // let cors = rocket_cors::CorsOptions {
    //     allowed_origins,
    //     allowed_methods: HashSet::from_iter(
    //         vec![Method::from_str("POST").unwrap(), Method::from_str("GET").unwrap()]
    //         .iter().cloned()
    //     ),
    //     allowed_headers: AllowedHeaders::some(&["*"]),
    //     // allow_credentials: true,
    //     ..Default::default()
    // }
    // .to_cors().unwrap();

    // Get the private key env var
    let privkey: BigInt = env::var("OPRF_KEY")
        .expect("OPRF_KEY must be an environment variable. It should be a decimal string representing a random integer between 0 and the order of the curve's subgroup.")
        .parse::<BigInt>()
        .unwrap();
    rocket::build()
    .manage(privkey)
    .attach(Cors)
    .mount("/", routes![index, do_nothing])
}
