use std::env;

use babyjubjub_rs::Point;
use num_bigint::BigInt;
use rocket::{State, serde::json::Json};
// use rocket_contrib::json::Json;use std::env;
#[macro_use] extern crate rocket;



// should be POST
// #[get("/<x>/<y>")]
#[post("/", format = "json", data = "<point>")]
fn index(privkey: &State<BigInt>, point: Json<Point>) -> String {
    format!("Hello, world! my private key is {}. you want me to multiply it by {:?}", privkey, point)
}

#[launch]
fn rocket() -> _ {
    // Get the private key env var
    let privkey: BigInt = env::var("OPRF_KEY")
        .expect("OPRF_KEY must be an environment variable. It should be a decimal string representing a random integer between 0 and the order of the curve's subgroup.")
        .parse::<BigInt>()
        .unwrap();
    rocket::build().manage(privkey).mount("/", routes![index])
}
