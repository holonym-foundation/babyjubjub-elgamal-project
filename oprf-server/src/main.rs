use std::{env};

use babyjubjub_rs::{Point};
use num_bigint::{BigInt};
use rocket::{State, serde::json::Json, response::status::BadRequest};

// use rocket_contrib::json::Json;use std::env;
#[macro_use] extern crate rocket;

// this route is solely so that a TLS connection can be started early before any user action and automatically cached by both parties. This avoids the handshake latency overhead when the user requests the OPRF
#[get("/ping")]
fn do_nothing() -> &'static str { "" }

#[post("/", format = "json", data = "<point>")]
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
    // Get the private key env var
    let privkey: BigInt = env::var("OPRF_KEY")
        .expect("OPRF_KEY must be an environment variable. It should be a decimal string representing a random integer between 0 and the order of the curve's subgroup.")
        .parse::<BigInt>()
        .unwrap();
    rocket::build().manage(privkey).mount("/", routes![index, do_nothing])
}
