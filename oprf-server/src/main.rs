use std::{env, collections::HashSet, str::FromStr};

use babyjubjub_rs::{Point};
use num_bigint::{BigInt};
use rocket::{State, serde::json::Json, response::status::BadRequest};
use rocket_cors::{Method, AllowedHeaders, AllowedOrigins};

// use rocket_contrib::json::Json;use std::env;
#[macro_use] extern crate rocket;

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
    let allowed_origins = AllowedOrigins::some_exact(&["https://silkwallet.net", "http://localhost:3000", "http://127.0.0.1:3000"]);
    let cors = rocket_cors::CorsOptions {
        allowed_origins,
        allowed_methods: HashSet::from_iter(
            vec![Method::from_str("POST").unwrap(), Method::from_str("GET").unwrap()]
            .iter().cloned()
        ),
        allowed_headers: AllowedHeaders::some(&["*"]),
        // allow_credentials: true,
        ..Default::default()
    }
    .to_cors().unwrap();

    // Get the private key env var
    let privkey: BigInt = env::var("OPRF_KEY")
        .expect("OPRF_KEY must be an environment variable. It should be a decimal string representing a random integer between 0 and the order of the curve's subgroup.")
        .parse::<BigInt>()
        .unwrap();
    rocket::build()
    .manage(privkey)
    .mount("/", routes![index, do_nothing])
    // .attach(cors)
}
