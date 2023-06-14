use std::env;
use babyjubjub_rs::{Point, DLEQProof, B8, Fl, FrBigIntConversion};
use num_bigint::{BigInt};
use ratelimit::{get_redis_client, rate_limit, RateLimit};
use rocket::{State, serde::json::Json, response::status::BadRequest, time::Instant};
use serde::{Serialize, Deserialize};

mod ratelimit;
mod cors;

#[macro_use] extern crate rocket;

#[derive(Serialize, Deserialize)]
pub struct VOPRFOutput {
    pub result: Point,
    pub proof: DLEQProof,
}

pub struct Keys {
    pub privkey: BigInt,
    pub priv_fl: Fl,
    pub pubkey: Point,
}

// this route is solely so that a TLS connection can be started early before any user action and automatically cached by both parties. This avoids the handshake latency overhead when the user requests the OPRF
#[get("/ping")]
fn good_morn() -> &'static str { "GM" }

// this route is solely so that a TLS connection can be started early before any user action and automatically cached by both parties. This avoids the handshake latency overhead when the user requests the OPRF
#[get("/example-point")]
fn example_point_maker() -> Json<Point> { Json(B8.mul_scalar(&BigInt::from_slice(num_bigint::Sign::Plus, &[123,45,67,89]))) }

// TODO: not have to recalculate the pubkey every time
#[get("/pub")]
fn get_pubkey(keys: &State<Keys>) -> Json<Point> {
    Json(keys.pubkey.clone())
}

/// This gives a `DLEQProof` that the OPRF was computed correctly. The output of the OPRF is the `DLEQProof`'s `xB`.
#[post("/voprf", format = "json", data = "<point>")]
fn index(keys: &State<Keys>, _r: RateLimit, point: Json<Point>) -> Result<Json<DLEQProof>, BadRequest<&'static str>> {
    // let now = Instant::now();
    // Check it is safe to proceed, i.e. point is on the curve and in subgroup
    if !point.on_curve() {
        return Err(BadRequest(Some("Not on curve")));
    }

    // Note: in_subgroup just checks that order of the point is the order of the subgroup
    if !point.in_subgroup() {
        return Err(BadRequest(Some("Not in subgroup")));
    }

    let proof = DLEQProof::new(keys.priv_fl.clone(), B8.clone(), point.into_inner())
        .map_err(|e|BadRequest(Some("Error computing zk dleq proof")))?;
    // println!("Time to compute proof: {}s\n", now.elapsed().as_seconds_f32());
    Ok(Json(proof))
}

#[launch]
fn rocket() -> _ {
    // Get the private key env var
    let privkey: BigInt = env::var("OPRF_KEY")
        .expect("OPRF_KEY must be an environment variable. It should be a decimal string representing a random integer between 0 and the order of the curve's subgroup.")
        .parse::<BigInt>()
        .unwrap();
    let priv_fl = Fl::from_bigint(&privkey);
    let pubkey = B8.mul_scalar(&privkey);

    let rlredis = get_redis_client().unwrap();

    rocket::build()
    .manage(Keys {
        privkey,
        priv_fl,
        pubkey,
    })
    .manage(rlredis)
    .attach(cors::Cors)
    .mount("/", routes![index, good_morn, get_pubkey, example_point_maker])
    .register("/", catchers![rate_limit])
}
